"""Controlled multi-site federation services for Milestone 11."""

from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timezone
from typing import Any

from mirage.config import load_config
from mirage.execution.audit import sanitize_payload
from mirage.execution.utils import deterministic_id
from mirage.milestone11.schema import (
    FederationDecision,
    FederationPolicyValidationRequest,
    FederationRouteValidationRequest,
    FederationStatus,
    FederationTransferRequest,
    SiteHealthStatus,
    SiteRegistration,
)


DEFAULT_ALLOWED_DATA_CLASSES = {
    "SUMMARY_INCIDENT",
    "PSEUDONYMIZED_ENTITY_DATA",
    "ASSURANCE_EVIDENCE_METADATA",
    "SLO_STATUS",
    "CAPACITY_SUMMARY",
    "READINESS_SUMMARY",
}

DEFAULT_DENIED_FIELD_MARKERS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "raw_event",
    "raw_payload",
    "command_line",
    "cookie",
    "authorization",
}

PSEUDONYMIZE_MARKERS = {
    "entity_id",
    "asset_id",
    "identity_id",
    "hostname",
    "host",
    "username",
    "user",
    "ip",
}


class SiteRegistry:
    """In-memory site registry with deterministic local defaults."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config if config is not None else load_config()
        sites_config = self.config.get("sites", {})
        local_config = sites_config.get("local", {})
        self.local_site_id = str(local_config.get("site_id", "site-local"))
        self.sites: dict[str, SiteRegistration] = {}
        self.register(
            SiteRegistration(
                site_id=self.local_site_id,
                tenant_id=str(local_config.get("tenant_id", "default")),
                display_name=str(local_config.get("display_name", "Local MIRAGE Site")),
                data_residency_zone=str(local_config.get("data_residency_zone", "local")),
                policy_version=str(local_config.get("policy_version", "federation-policy-v1")),
                endpoint=str(local_config.get("endpoint", "")),
                public_identity=str(local_config.get("public_identity", "local-site-identity")),
                allow_central_governance=bool(local_config.get("allow_central_governance", False)),
            )
        )
        for raw in sites_config.get("registered", []):
            self.register(SiteRegistration.model_validate(raw))

    def register(self, site: SiteRegistration) -> SiteRegistration:
        """Register or replace a site."""
        self.sites[site.site_id] = site
        return site

    def get(self, site_id: str) -> SiteRegistration:
        """Return one site or raise."""
        if site_id not in self.sites:
            raise KeyError(site_id)
        return self.sites[site_id]

    def list_sites(self) -> list[SiteRegistration]:
        """Return all registered sites sorted by site ID."""
        return [self.sites[key] for key in sorted(self.sites)]

    def mark_health(self, site_id: str, health: SiteHealthStatus) -> SiteRegistration:
        """Update one site's health."""
        site = self.get(site_id).model_copy(
            update={"health_status": health, "last_seen_at": datetime.now(timezone.utc)}
        )
        self.sites[site_id] = site
        return site

    def health(self, site_id: str) -> dict[str, Any]:
        """Public-safe site health."""
        site = self.get(site_id)
        return {
            "site_id": site.site_id,
            "tenant_id": site.tenant_id,
            "health_status": site.health_status.value,
            "data_residency_zone": site.data_residency_zone,
            "policy_version": site.policy_version,
            "last_seen_at": site.last_seen_at.isoformat(),
        }


class FederationPolicyEngine:
    """Deny-by-default federation policy engine."""

    def __init__(
        self,
        registry: SiteRegistry | None = None,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.config = config if config is not None else load_config()
        self.registry = registry or SiteRegistry(self.config)
        federation_config = self.config.get("federation", {})
        self.mode = str(federation_config.get("mode", "disabled"))
        self.allowed_data_classes = set(
            federation_config.get(
                "allowed_data_classes",
                sorted(DEFAULT_ALLOWED_DATA_CLASSES),
            )
        )
        self.denied_field_markers = {
            str(item).lower()
            for item in federation_config.get(
                "denied_field_markers",
                sorted(DEFAULT_DENIED_FIELD_MARKERS),
            )
        }
        self.pseudonymization_required = bool(
            federation_config.get("pseudonymization_required", True)
        )
        self.encrypted_transport_required = bool(
            federation_config.get("encrypted_transport_required", True)
        )
        self.max_queue_messages = int(federation_config.get("max_queue_messages", 1000))
        self.residency_routes: dict[str, list[str]] = {
            str(zone): [str(item) for item in destinations]
            for zone, destinations in federation_config.get("residency_routes", {"local": ["local"]}).items()
        }
        self._seen_message_ids: set[str] = set()
        self._outage_queue: list[FederationDecision] = []

    def validate_policy(
        self,
        policy: FederationPolicyValidationRequest,
    ) -> dict[str, Any]:
        """Validate proposed policy settings without activating them."""
        findings: list[str] = []
        denied = {item.lower() for item in policy.denied_fields}
        if not policy.encrypted_transport_required:
            findings.append("encrypted transport is mandatory")
        if not policy.pseudonymization_required:
            findings.append("pseudonymization is mandatory")
        missing_denies = sorted(DEFAULT_DENIED_FIELD_MARKERS.difference(denied))
        if missing_denies:
            findings.append("denied field markers missing: " + ", ".join(missing_denies[:10]))
        prohibited_classes = [
            item
            for item in policy.allowed_data_classes
            if item.upper() in {"RAW_CREDENTIALS", "RAW_EVENT_PAYLOAD", "SECRETS"}
        ]
        if prohibited_classes:
            findings.append("prohibited data classes allowed: " + ", ".join(prohibited_classes))
        return {
            "valid": not findings,
            "findings": findings,
            "allowed_data_classes": sorted(policy.allowed_data_classes),
        }

    def validate_route(
        self,
        request: FederationRouteValidationRequest,
    ) -> FederationDecision:
        """Validate a route without transferring data."""
        transfer = FederationTransferRequest(
            message_id=deterministic_id(
                "route",
                request.source_site_id,
                request.destination_site_id,
                request.data_class,
                request.tenant_id,
            ),
            source_site_id=request.source_site_id,
            destination_site_id=request.destination_site_id,
            tenant_id=request.tenant_id,
            data_class=request.data_class,
            payload={},
        )
        return self.validate_transfer(transfer, record_duplicate=False)

    def validate_transfer(
        self,
        request: FederationTransferRequest,
        *,
        record_duplicate: bool = True,
    ) -> FederationDecision:
        """Validate and sanitize one federation transfer."""
        try:
            source = self.registry.get(request.source_site_id)
            destination = self.registry.get(request.destination_site_id)
        except KeyError as exc:
            return self._deny(request, f"unknown site: {exc.args[0]}")

        if self.mode not in {"enabled", "local_only"}:
            return self._deny(request, "federation mode is disabled")
        if record_duplicate and request.message_id in self._seen_message_ids:
            return self._deny(request, "duplicate federation message")
        if request.tenant_id != source.tenant_id or request.tenant_id != destination.tenant_id:
            return self._deny(request, "cross-tenant federation is denied")
        if request.data_class not in self.allowed_data_classes:
            return self._deny(request, f"data class is not allowlisted: {request.data_class}")
        if source.health_status in {SiteHealthStatus.DISCONNECTED, SiteHealthStatus.SUSPENDED}:
            return self._deny(request, f"source site is {source.health_status.value}")
        if destination.health_status in {SiteHealthStatus.DISCONNECTED, SiteHealthStatus.SUSPENDED}:
            decision = self._deny(request, f"destination site is {destination.health_status.value}")
            self._queue_during_outage(decision)
            return decision
        if source.policy_version != destination.policy_version:
            return self._deny(request, "policy-version divergence requires most restrictive behavior")
        if not self._residency_route_allowed(source, destination):
            return self._deny(request, "residency-policy route is not allowlisted")
        denied_fields = _find_denied_fields(request.payload, self.denied_field_markers)
        if denied_fields:
            return self._deny(
                request,
                "payload contains prohibited fields",
                denied_fields=denied_fields,
            )

        sanitized, pseudonymized = self._sanitize_payload(request.payload, source.site_id)
        if record_duplicate:
            self._seen_message_ids.add(request.message_id)
        return FederationDecision(
            message_id=request.message_id,
            allowed=True,
            reason="allowed by federation policy",
            data_class=request.data_class,
            source_site_id=request.source_site_id,
            destination_site_id=request.destination_site_id,
            sanitized_payload=sanitized,
            pseudonymized_fields=pseudonymized,
        )

    def status(self) -> FederationStatus:
        """Return public-safe federation status."""
        disconnected = [
            site.site_id
            for site in self.registry.list_sites()
            if site.health_status != SiteHealthStatus.HEALTHY
        ]
        health = SiteHealthStatus.HEALTHY if not disconnected else SiteHealthStatus.DEGRADED
        warnings = []
        if self.mode not in {"enabled", "local_only"}:
            warnings.append("federation disabled by default")
        return FederationStatus(
            local_site_id=self.registry.local_site_id,
            mode=self.mode,
            health=health,
            registered_sites=len(self.registry.sites),
            disconnected_sites=disconnected,
            queued_messages=len(self._outage_queue),
            warnings=warnings,
        )

    def correlations(self, summaries: list[dict[str, Any]]) -> dict[str, Any]:
        """Correlate already-approved summary records without raw cross-site execution."""
        sanitized = [sanitize_payload(summary) for summary in summaries]
        incident_keys: dict[str, set[str]] = {}
        for summary in sanitized:
            key = str(summary.get("incident_family") or summary.get("tactic") or "unknown")
            site = str(summary.get("site_id") or "unknown")
            incident_keys.setdefault(key, set()).add(site)
        correlated = [
            {
                "correlation_id": deterministic_id("federated_correlation", key, ",".join(sorted(sites))),
                "incident_family": key,
                "sites": sorted(sites),
                "confidence": round(min(0.95, 0.45 + 0.15 * len(sites)), 3),
                "uncertainty": round(max(0.05, 0.55 - 0.1 * len(sites)), 3),
                "direct_cross_site_execution": False,
            }
            for key, sites in sorted(incident_keys.items())
            if len(sites) > 1
        ]
        return {"correlations": correlated, "input_summaries": len(sanitized)}

    def _sanitize_payload(self, payload: dict[str, Any], source_site_id: str) -> tuple[dict[str, Any], list[str]]:
        sanitized = copy.deepcopy(sanitize_payload(payload))
        pseudonymized: list[str] = []

        def visit(value: Any, path: str = "") -> Any:
            if isinstance(value, dict):
                output = {}
                for key, item in value.items():
                    child_path = f"{path}.{key}" if path else str(key)
                    if self.pseudonymization_required and _should_pseudonymize(str(key)):
                        output[key] = _pseudonymize(item, source_site_id)
                        pseudonymized.append(child_path)
                    else:
                        output[key] = visit(item, child_path)
                return output
            if isinstance(value, list):
                return [visit(item, f"{path}[]") for item in value]
            return value

        return visit(sanitized), sorted(set(pseudonymized))

    def _residency_route_allowed(
        self,
        source: SiteRegistration,
        destination: SiteRegistration,
    ) -> bool:
        allowed = self.residency_routes.get(source.data_residency_zone, [])
        return destination.data_residency_zone in allowed

    def _queue_during_outage(self, decision: FederationDecision) -> None:
        if len(self._outage_queue) >= self.max_queue_messages:
            self._outage_queue.pop(0)
        self._outage_queue.append(decision)

    def _deny(
        self,
        request: FederationTransferRequest,
        reason: str,
        *,
        denied_fields: list[str] | None = None,
    ) -> FederationDecision:
        return FederationDecision(
            message_id=request.message_id,
            allowed=False,
            reason=reason,
            data_class=request.data_class,
            source_site_id=request.source_site_id,
            destination_site_id=request.destination_site_id,
            denied_fields=denied_fields or [],
        )


class FederationService:
    """High-level API facade for site and federation endpoints."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config if config is not None else load_config()
        self.registry = SiteRegistry(self.config)
        self.policy_engine = FederationPolicyEngine(self.registry, self.config)

    def list_sites(self) -> dict[str, Any]:
        return {"sites": [site.model_dump(mode="json") for site in self.registry.list_sites()]}

    def get_site(self, site_id: str) -> dict[str, Any]:
        return self.registry.get(site_id).model_dump(mode="json")

    def validate_site(self, site_id: str) -> dict[str, Any]:
        site = self.registry.get(site_id)
        findings = []
        if self.policy_engine.encrypted_transport_required and site.endpoint.startswith("http://"):
            findings.append("unencrypted endpoint")
        if site.health_status == SiteHealthStatus.SUSPENDED:
            findings.append("site is suspended")
        return {
            "site_id": site_id,
            "valid": not findings,
            "findings": findings,
            "policy_version": site.policy_version,
        }

    def site_health(self, site_id: str) -> dict[str, Any]:
        return self.registry.health(site_id)

    def site_slo(self, site_id: str) -> dict[str, Any]:
        site = self.registry.get(site_id)
        return {
            "site_id": site.site_id,
            "availability": 1.0 if site.health_status == SiteHealthStatus.HEALTHY else 0.0,
            "federation_health": site.health_status.value,
            "policy_version": site.policy_version,
        }

    def federation_status(self) -> dict[str, Any]:
        return self.policy_engine.status().model_dump(mode="json")

    def policies(self) -> dict[str, Any]:
        return {
            "mode": self.policy_engine.mode,
            "allowed_data_classes": sorted(self.policy_engine.allowed_data_classes),
            "denied_field_markers": sorted(self.policy_engine.denied_field_markers),
            "residency_routes": self.policy_engine.residency_routes,
            "pseudonymization_required": self.policy_engine.pseudonymization_required,
            "encrypted_transport_required": self.policy_engine.encrypted_transport_required,
        }

    def validate_policy(
        self,
        policy: FederationPolicyValidationRequest,
    ) -> dict[str, Any]:
        return self.policy_engine.validate_policy(policy)

    def validate_route(
        self,
        route: FederationRouteValidationRequest,
    ) -> dict[str, Any]:
        return self.policy_engine.validate_route(route).model_dump(mode="json")

    def validate_transfer(
        self,
        transfer: FederationTransferRequest,
    ) -> dict[str, Any]:
        return self.policy_engine.validate_transfer(transfer).model_dump(mode="json")

    def correlations(self, summaries: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        return self.policy_engine.correlations(summaries or [])


def _find_denied_fields(
    value: Any,
    denied_markers: set[str],
    path: str = "",
) -> list[str]:
    findings: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            lowered = str(key).lower()
            if any(marker in lowered for marker in denied_markers):
                findings.append(child_path)
            findings.extend(_find_denied_fields(item, denied_markers, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_find_denied_fields(item, denied_markers, f"{path}[{index}]"))
    return sorted(set(findings))


def _should_pseudonymize(key: str) -> bool:
    lowered = key.lower()
    return any(marker == lowered or lowered.endswith("_" + marker) or marker in lowered for marker in PSEUDONYMIZE_MARKERS)


def _pseudonymize(value: Any, site_id: str) -> Any:
    if isinstance(value, list):
        return [_pseudonymize(item, site_id) for item in value]
    if isinstance(value, dict):
        return {key: _pseudonymize(item, site_id) for key, item in value.items()}
    digest = hashlib.sha256(f"{site_id}:{value}".encode("utf-8")).hexdigest()[:16]
    return f"pseudonym:{digest}"
