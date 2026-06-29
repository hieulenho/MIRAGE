"""Typed public schemas for Milestone 11 operational maturity controls."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


class StrictModel(BaseModel):
    """Base model that rejects accidental extra fields."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ImplementationStatus(str, Enum):
    """Repository-truth implementation statuses."""

    IMPLEMENTED = "IMPLEMENTED"
    PARTIAL = "PARTIAL"
    MOCK_ONLY = "MOCK_ONLY"
    TEST_ONLY = "TEST_ONLY"
    DOCUMENTED_ONLY = "DOCUMENTED_ONLY"
    STUB = "STUB"
    DEPRECATED = "DEPRECATED"
    BROKEN = "BROKEN"
    NOT_FOUND = "NOT_FOUND"


class AdapterClassification(str, Enum):
    """Execution/federation adapter maturity classes."""

    PRODUCTION_CAPABLE = "PRODUCTION_CAPABLE"
    PILOT_ONLY = "PILOT_ONLY"
    LAB_ONLY = "LAB_ONLY"
    MOCK_ONLY = "MOCK_ONLY"
    STUB = "STUB"


class CapabilityInventoryItem(StrictModel):
    """One evidence-backed capability record."""

    capability_id: str
    capability_name: str
    milestone_origin: str
    architecture_layer: str
    implementation_status: ImplementationStatus
    description: str
    source_files: list[str] = Field(default_factory=list)
    public_interfaces: list[str] = Field(default_factory=list)
    storage_dependencies: list[str] = Field(default_factory=list)
    event_dependencies: list[str] = Field(default_factory=list)
    security_dependencies: list[str] = Field(default_factory=list)
    model_dependencies: list[str] = Field(default_factory=list)
    configuration_keys: list[str] = Field(default_factory=list)
    tests: list[str] = Field(default_factory=list)
    api_routes: list[str] = Field(default_factory=list)
    cli_commands: list[str] = Field(default_factory=list)
    deployment_resources: list[str] = Field(default_factory=list)
    runtime_verification_result: str = "not_run_by_inventory_scanner"
    limitations: list[str] = Field(default_factory=list)
    known_risks: list[str] = Field(default_factory=list)
    recommended_next_action: str = "collect more runtime evidence"


class InventoryTotals(StrictModel):
    """Counts by implementation status."""

    by_status: dict[str, int] = Field(default_factory=dict)
    capability_count: int = 0
    source_file_count: int = 0
    test_file_count: int = 0
    api_route_count: int = 0
    cli_command_count: int = 0


class SystemInventory(StrictModel):
    """Machine-readable verified repository inventory."""

    inventory_version: str = "milestone11.v1"
    generated_at: str
    repository_root: str
    safety_defaults: dict[str, Any]
    totals: InventoryTotals
    capabilities: list[CapabilityInventoryItem]
    api_routes: list[dict[str, Any]] = Field(default_factory=list)
    cli_commands: list[dict[str, Any]] = Field(default_factory=list)
    schemas: list[dict[str, Any]] = Field(default_factory=list)
    configuration: list[dict[str, Any]] = Field(default_factory=list)
    security_controls: list[dict[str, Any]] = Field(default_factory=list)
    model_and_policy_artifacts: list[dict[str, Any]] = Field(default_factory=list)
    deployment_resources: list[dict[str, Any]] = Field(default_factory=list)
    test_inventory: list[dict[str, Any]] = Field(default_factory=list)
    known_gaps: list[dict[str, Any]] = Field(default_factory=list)
    system_summary_diagram: str = ""

    def capability(self, capability_id: str) -> CapabilityInventoryItem:
        """Return one capability by ID."""
        for item in self.capabilities:
            if item.capability_id == capability_id:
                return item
        raise KeyError(capability_id)


class SiteHealthStatus(str, Enum):
    """Site health used by the federation control plane."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DISCONNECTED = "disconnected"
    SUSPENDED = "suspended"


class SiteRegistration(StrictModel):
    """Registered local or remote MIRAGE site."""

    site_id: str = Field(min_length=1, max_length=120)
    tenant_id: str = Field(default="default", min_length=1, max_length=120)
    display_name: str = ""
    data_residency_zone: str = "local"
    policy_version: str = "federation-policy-v1"
    endpoint: str = ""
    public_identity: str = Field(default="", max_length=500)
    health_status: SiteHealthStatus = SiteHealthStatus.HEALTHY
    allow_central_governance: bool = False
    last_seen_at: datetime = Field(default_factory=utc_now)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("endpoint")
    @classmethod
    def _endpoint_must_not_disable_tls(cls, value: str) -> str:
        if value and value.startswith("http://"):
            raise ValueError("federation endpoints must use encrypted transport")
        return value


class FederationTransferRequest(StrictModel):
    """Request to validate and sanitize one cross-site transfer."""

    message_id: str = Field(min_length=1, max_length=200)
    source_site_id: str = Field(min_length=1)
    destination_site_id: str = Field(min_length=1)
    tenant_id: str = Field(default="default", min_length=1)
    data_class: str = Field(min_length=1, max_length=120)
    payload: dict[str, Any] = Field(default_factory=dict)
    policy_version: str = "federation-policy-v1"


class FederationDecision(StrictModel):
    """Federation policy decision with sanitized output."""

    message_id: str
    allowed: bool
    reason: str
    data_class: str
    source_site_id: str
    destination_site_id: str
    sanitized_payload: dict[str, Any] = Field(default_factory=dict)
    denied_fields: list[str] = Field(default_factory=list)
    pseudonymized_fields: list[str] = Field(default_factory=list)
    audit_required: bool = True


class FederationRouteValidationRequest(StrictModel):
    """Validate a data class between two sites."""

    source_site_id: str
    destination_site_id: str
    data_class: str
    tenant_id: str = "default"


class FederationPolicyValidationRequest(StrictModel):
    """Validate proposed federation policy settings."""

    allowed_data_classes: list[str] = Field(default_factory=list)
    denied_fields: list[str] = Field(default_factory=list)
    residency_routes: dict[str, list[str]] = Field(default_factory=dict)
    encrypted_transport_required: bool = True
    pseudonymization_required: bool = True


class FederationStatus(StrictModel):
    """Public-safe federation status."""

    local_site_id: str
    mode: str
    health: SiteHealthStatus
    registered_sites: int
    disconnected_sites: list[str] = Field(default_factory=list)
    queued_messages: int = 0
    last_policy_version: str = "federation-policy-v1"
    warnings: list[str] = Field(default_factory=list)


class AssuranceSeverity(str, Enum):
    """Assurance finding severity."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AssuranceCheckResult(StrictModel):
    """Result from one continuous assurance check."""

    check_id: str
    name: str
    passed: bool
    severity: AssuranceSeverity = AssuranceSeverity.ERROR
    evidence_refs: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""


class AssuranceBundle(StrictModel):
    """Hash-verifiable assurance evidence bundle."""

    bundle_id: str
    created_at: datetime = Field(default_factory=utc_now)
    checks: list[AssuranceCheckResult]
    evidence_hashes: dict[str, str] = Field(default_factory=dict)
    bundle_hash: str
    deployment_reduction_required: bool = False
    readiness_blocked: bool = False


class ValidationJobStatus(str, Enum):
    """Validation job lifecycle."""

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ValidationJob(StrictModel):
    """Deterministic soak or chaos job result."""

    job_id: str
    job_type: Literal["soak", "chaos"]
    status: ValidationJobStatus
    profile: str
    started_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None
    metrics: dict[str, Any] = Field(default_factory=dict)
    findings: list[str] = Field(default_factory=list)
    safe_to_continue_shadow: bool = True


class SoakValidationRequest(StrictModel):
    """API request for a bounded synthetic soak run."""

    duration: str = "5m"
    profile: str = "ci"


class ChaosValidationRequest(StrictModel):
    """API request for one deterministic chaos scenario."""

    experiment: str
    environment: str = "staging"


class SLOReport(StrictModel):
    """SLO and error-budget report."""

    report_id: str
    period_seconds: int
    sli_values: dict[str, float] = Field(default_factory=dict)
    targets: dict[str, float] = Field(default_factory=dict)
    compliance: dict[str, bool] = Field(default_factory=dict)
    error_budget_remaining: dict[str, float] = Field(default_factory=dict)
    exhausted_budgets: list[str] = Field(default_factory=list)
    release_blocked: bool = False


class CapacityReport(StrictModel):
    """Measured and projected capacity report."""

    report_id: str
    measured: dict[str, float] = Field(default_factory=dict)
    projected: dict[str, float] = Field(default_factory=dict)
    thresholds: dict[str, float] = Field(default_factory=dict)
    saturation: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class MaturityReport(StrictModel):
    """Evidence-backed operational maturity report."""

    report_id: str
    overall_score: float = Field(ge=0.0, le=1.0)
    category_scores: dict[str, float] = Field(default_factory=dict)
    evidence: dict[str, list[str]] = Field(default_factory=dict)
    blockers: list[str] = Field(default_factory=list)
    recommended_remediation: list[str] = Field(default_factory=list)


class ReadinessVerdict(str, Enum):
    """Deployment Readiness Board verdicts."""

    SUSTAINED_LIMITED_DEPLOYMENT = "SUSTAINED_LIMITED_DEPLOYMENT"
    RETURN_TO_SHADOW_MODE = "RETURN_TO_SHADOW_MODE"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class ReadinessEvaluationRequest(StrictModel):
    """Request for a readiness decision."""

    target_deployment_level: str = "SHADOW_ONLY"
    require_recent_assurance: bool = True
    require_soak_success: bool = True
    require_chaos_success: bool = False


class ReadinessDecision(StrictModel):
    """Deterministic operational readiness decision."""

    decision_id: str
    verdict: ReadinessVerdict
    target_deployment_level: str
    maturity_score: float = Field(ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)
    required_remediation: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)

    @model_validator(mode="after")
    def _no_auto_promotion_without_evidence(self) -> "ReadinessDecision":
        if (
            self.target_deployment_level != "SHADOW_ONLY"
            and self.verdict == ReadinessVerdict.SUSTAINED_LIMITED_DEPLOYMENT
            and self.maturity_score < 0.8
        ):
            raise ValueError("limited deployment requires maturity score >= 0.8")
        return self
