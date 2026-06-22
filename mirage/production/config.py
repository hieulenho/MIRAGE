"""Production profile validation and startup safety checks."""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from mirage.production.schema import (
    EnvironmentProfile,
    EventTransportBackend,
    ProductionConfig,
    StorageBackend,
    ValidationFinding,
    ValidationReport,
)


MANDATORY_FALSE = (
    "production_execution_enabled",
    "high_risk_automation_enabled",
)

MANDATORY_TRUE = (
    "formal_verification_required",
    "governance_gate_required",
    "action_mask_required",
    "safety_gate_required",
)


def _finding(code: str, message: str) -> ValidationFinding:
    return ValidationFinding(code=code, message=message)


def validate_production_config(
    raw_config: dict[str, Any],
    *,
    strict_startup: bool = False,
) -> ValidationReport:
    """Validate MIRAGE production-hardening settings.

    The report is always produced for CLI/API use.  `load_config` calls this
    function and raises only when findings are unsafe for the active profile or
    when strict startup is requested.
    """
    findings: list[ValidationFinding] = []
    try:
        production = ProductionConfig.model_validate(raw_config.get("production", {}))
    except ValidationError as exc:
        return ValidationReport(
            valid=False,
            profile=EnvironmentProfile.SHADOW,
            findings=[
                _finding(
                    "production_schema_invalid",
                    f"production config schema is invalid: {exc.errors()[0]['msg']}",
                )
            ],
        )

    general = raw_config.get("general", {})
    if general.get("operating_mode", "shadow") != "shadow":
        findings.append(
            _finding(
                "general_shadow_required",
                "general.operating_mode must remain shadow for Milestone 10 defaults",
            )
        )
    for key in MANDATORY_FALSE:
        if bool(getattr(production, key)):
            findings.append(_finding(key, f"production.{key} must default to false"))
    for key in MANDATORY_TRUE:
        if not bool(getattr(production, key)):
            findings.append(_finding(key, f"production.{key} must be true"))

    low_risk = set(production.allowed_automatic_action_types)
    prohibited = set(production.prohibited_action_types)
    overlap = low_risk.intersection(prohibited)
    if overlap:
        findings.append(
            _finding(
                "action_allowlist_overlap",
                f"actions cannot be both allowed and prohibited: {sorted(overlap)}",
            )
        )

    if production.profile == EnvironmentProfile.PRODUCTION or strict_startup:
        _validate_strict_production(raw_config, production, findings)

    return ValidationReport(
        valid=not findings,
        profile=production.profile,
        findings=findings,
    )


def enforce_production_startup(raw_config: dict[str, Any]) -> None:
    """Raise when active production settings are unsafe."""
    report = validate_production_config(raw_config)
    if report.findings and report.profile == EnvironmentProfile.PRODUCTION:
        details = "; ".join(f"{finding.code}: {finding.message}" for finding in report.findings)
        raise ValueError(f"Unsafe production startup rejected: {details}")


def _validate_strict_production(
    raw_config: dict[str, Any],
    production: ProductionConfig,
    findings: list[ValidationFinding],
) -> None:
    profile_config = production.profiles.get(EnvironmentProfile.PRODUCTION.value)
    if profile_config is None:
        findings.append(_finding("missing_production_profile", "production profile is required"))
        return

    if not production.auth.enabled or not profile_config.authentication_required:
        findings.append(_finding("auth_required", "authentication must be enabled in production"))
    if production.auth.default_credentials_allowed:
        findings.append(_finding("default_credentials", "default credentials are prohibited"))
    if not production.tls.enabled or not profile_config.tls_required:
        findings.append(_finding("tls_required", "TLS must be enabled in production"))
    if production.tls.insecure_skip_verify or not production.tls.verify_hostname:
        findings.append(_finding("tls_verification", "TLS certificate verification cannot be disabled"))
    if not production.auth.service_identity_required:
        findings.append(_finding("service_identity", "service identities are required"))

    if production.storage.backend != StorageBackend.POSTGRES:
        findings.append(_finding("storage_backend", "production requires PostgreSQL-compatible storage"))
    if not production.storage.postgres_dsn:
        findings.append(_finding("storage_unavailable", "production storage DSN is required"))
    if production.event_transport.backend != EventTransportBackend.KAFKA_COMPATIBLE:
        findings.append(_finding("event_transport", "production requires a durable broker adapter"))
    if not production.event_transport.broker_url:
        findings.append(_finding("broker_unavailable", "production event broker URL is required"))
    if not production.audit.path:
        findings.append(_finding("audit_storage", "audit storage path is required"))
    if not production.audit.fail_closed_for_execution:
        findings.append(_finding("audit_fail_closed", "audit failure must block sensitive execution"))

    if bool(raw_config.get("governance", {}).get("bypass_enabled", False)):
        findings.append(_finding("governance_bypass", "governance cannot be bypassed"))
    if bool(raw_config.get("execution", {}).get("safety_gate_bypass", False)):
        findings.append(_finding("safety_gate_bypass", "Safety Gate cannot be bypassed"))
    if bool(raw_config.get("execution", {}).get("enforcement_enabled", False)):
        findings.append(_finding("legacy_enforcement", "legacy enforcement flag cannot be enabled"))
    if production.production_execution_enabled and not raw_config.get("pilot", {}).get("pilot_scopes"):
        findings.append(_finding("pilot_scope_required", "execution requires an approved pilot scope"))
    if not production.protected_assets and not raw_config.get("execution", {}).get("protected_asset_ids"):
        findings.append(_finding("protected_assets", "protected assets must be configured"))

    if production.production_execution_enabled:
        enabled_actions = set(production.allowed_automatic_action_types)
        rollback_actions = set(production.rollback_configured_actions)
        missing = sorted(enabled_actions.difference(rollback_actions))
        if missing:
            findings.append(
                _finding(
                    "rollback_required",
                    f"rollback is not configured for enabled actions: {missing}",
                )
            )

