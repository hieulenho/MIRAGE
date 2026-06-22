"""Pydantic models for formal safety verification."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from mirage.domain.schemas import (
    ActionMask,
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionPlan,
    ExecutionRecord,
    SafetyDecision,
    TwinSnapshot,
)


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def canonical_hash(value: Any) -> str:
    """Return a stable SHA-256 hash for JSON-serializable content."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class StrictVerificationModel(BaseModel):
    """Strict verification schema base."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class InvariantCategory(str, Enum):
    REACHABILITY = "REACHABILITY"
    PROTECTED_ASSET = "PROTECTED_ASSET"
    MANAGEMENT_CHANNEL = "MANAGEMENT_CHANNEL"
    BLAST_RADIUS = "BLAST_RADIUS"
    ROLLBACK = "ROLLBACK"
    REVERSIBILITY = "REVERSIBILITY"
    TEMPORAL = "TEMPORAL"
    RESOURCE_BUDGET = "RESOURCE_BUDGET"
    IDENTITY = "IDENTITY"
    DATA_PROTECTION = "DATA_PROTECTION"
    DECISION_PROVENANCE = "DECISION_PROVENANCE"
    APPROVAL = "APPROVAL"
    PILOT_SCOPE = "PILOT_SCOPE"


class VerificationSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ViolationResponse(str, Enum):
    WARN = "WARN"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    REJECT = "REJECT"
    ROLLBACK = "ROLLBACK"
    SUSPEND = "SUSPEND"


class VerificationResult(str, Enum):
    PROVEN = "PROVEN"
    VIOLATED = "VIOLATED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class FormalVerificationVerdict(str, Enum):
    VERIFIED = "VERIFIED"
    VERIFIED_WITH_WARNINGS = "VERIFIED_WITH_WARNINGS"
    REQUIRES_APPROVAL = "REQUIRES_APPROVAL"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class SafetyInvariant(StrictVerificationModel):
    """Versioned formal safety invariant."""

    invariant_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    category: InvariantCategory
    severity: VerificationSeverity
    enabled: bool = True
    formal_expression: str = Field(min_length=1)
    human_readable_expression: str = Field(min_length=1)
    required_inputs: list[str] = Field(default_factory=list)
    applicable_action_types: list[str] = Field(default_factory=list)
    applicable_environments: list[str] = Field(default_factory=list)
    violation_response: ViolationResponse
    policy_version: str = "formal-safety-v1"
    provenance: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at", "updated_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class VerificationFinding(StrictVerificationModel):
    """One invariant verification result."""

    finding_id: str = Field(min_length=1)
    invariant_id: str = Field(min_length=1)
    result: VerificationResult
    severity: VerificationSeverity
    affected_entities: list[str] = Field(default_factory=list)
    affected_relationships: list[str] = Field(default_factory=list)
    counterexample: list[str] = Field(default_factory=list)
    explanation: str
    verifier_name: str
    verifier_version: str
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class BlastRadiusEstimate(StrictVerificationModel):
    """Conservative blast-radius estimate."""

    directly_affected_entities: list[str] = Field(default_factory=list)
    indirectly_affected_entities: list[str] = Field(default_factory=list)
    protected_entities_affected: list[str] = Field(default_factory=list)
    business_services_affected: list[str] = Field(default_factory=list)
    affected_identities: list[str] = Field(default_factory=list)
    affected_flows: list[str] = Field(default_factory=list)
    affected_subnets: list[str] = Field(default_factory=list)
    uncertainty: float = Field(default=0.0, ge=0.0, le=1.0)
    missing_dependency_warnings: list[str] = Field(default_factory=list)
    limit_violations: list[str] = Field(default_factory=list)


class SolverResult(StrictVerificationModel):
    """Constraint solver result."""

    status: Literal["SAT", "UNSAT", "UNKNOWN"]
    violated_constraints: list[str] = Field(default_factory=list)
    model: dict[str, Any] = Field(default_factory=dict)
    counterexample: dict[str, Any] = Field(default_factory=dict)
    solver_duration_ms: float = Field(default=0.0, ge=0.0)
    timeout: bool = False


class FormalVerificationContext(StrictVerificationModel):
    """All bounded facts used by formal safety verifiers."""

    action: CandidateDefenseAction
    action_mask: ActionMask
    safety_decision: SafetyDecision | None = None
    execution_plan: ExecutionPlan
    twin_snapshot: TwinSnapshot
    belief_snapshot: BeliefSnapshot | None = None
    active_execution_records: list[ExecutionRecord] = Field(default_factory=list)
    pilot_scope: dict[str, Any] = Field(default_factory=dict)
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    dependency_graph: dict[str, list[str]] = Field(default_factory=dict)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    selected_policy_id: str = ""
    selected_policy_version: str = ""
    model_uncertainty: float = Field(default=0.0, ge=0.0, le=1.0)
    ood_warnings: list[str] = Field(default_factory=list)
    policy_disagreements: list[str] = Field(default_factory=list)
    kill_switch_active: bool = False
    reference_time: datetime = Field(default_factory=utc_now)
    assumptions: list[str] = Field(default_factory=list)

    @field_validator("reference_time")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reference_time must be timezone-aware")
        return value.astimezone(timezone.utc)

    @property
    def plan_hash(self) -> str:
        """Stable hash of the execution plan."""
        return canonical_hash(self.execution_plan)


class FormalVerificationReport(StrictVerificationModel):
    """Aggregate formal verification report."""

    report_id: str = Field(min_length=1)
    execution_plan_id: str
    source_action_id: str
    twin_version: str
    graph_version: str
    belief_version: str
    analysis_id: str | None = None
    model_versions: dict[str, str] = Field(default_factory=dict)
    policy_versions: dict[str, str] = Field(default_factory=dict)
    safety_policy_version: str = ""
    invariants_evaluated: list[str] = Field(default_factory=list)
    findings: list[VerificationFinding] = Field(default_factory=list)
    proven_count: int = Field(ge=0)
    violated_count: int = Field(ge=0)
    unknown_count: int = Field(ge=0)
    overall_verdict: FormalVerificationVerdict
    counterexamples: list[list[str]] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    verifier_versions: dict[str, str] = Field(default_factory=dict)
    verification_duration_ms: float = Field(default=0.0, ge=0.0)
    report_hash: str
    generated_at: datetime = Field(default_factory=utc_now)

    @field_validator("generated_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("generated_at must be timezone-aware")
        return value.astimezone(timezone.utc)
