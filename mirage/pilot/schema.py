"""Controlled pilot schemas."""

from __future__ import annotations

from datetime import datetime, time, timezone
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictPilotModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RolloutLevel(str, Enum):
    LEVEL_0_SHADOW = "LEVEL_0_SHADOW"
    LEVEL_1_LAB = "LEVEL_1_LAB"
    LEVEL_2_READ_ONLY = "LEVEL_2_READ_ONLY"
    LEVEL_3_LOW_RISK_DECEPTION = "LEVEL_3_LOW_RISK_DECEPTION"
    LEVEL_4_LIMITED_CONTROL = "LEVEL_4_LIMITED_CONTROL"


class CanaryOutcome(str, Enum):
    EXPAND = "EXPAND"
    HOLD = "HOLD"
    ROLLBACK = "ROLLBACK"
    REQUIRE_ANALYST = "REQUIRE_ANALYST"


class RuntimeMonitorStatus(str, Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    SUSPENDED = "SUSPENDED"


class PilotFinalOutcome(str, Enum):
    PREPARED = "PREPARED"
    VERIFIED = "VERIFIED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    CANARY_HELD = "CANARY_HELD"
    CANARY_EXPANDED = "CANARY_EXPANDED"
    ROLLED_BACK = "ROLLED_BACK"
    REJECTED = "REJECTED"
    SHADOW_ONLY = "SHADOW_ONLY"


class PilotScope(StrictPilotModel):
    scope_id: str = Field(min_length=1)
    environment: str = "lab"
    tenant_or_lab_id: str = "mirage-lab"
    allowed_asset_ids: list[str] = Field(default_factory=list)
    allowed_asset_tags: list[str] = Field(default_factory=list)
    allowed_subnets: list[str] = Field(default_factory=list)
    allowed_action_types: list[str] = Field(default_factory=list)
    excluded_protected_assets: list[str] = Field(default_factory=list)
    maximum_affected_entities: int = Field(default=5, ge=0)
    maximum_ttl_seconds: int = Field(default=3600, ge=1)
    maximum_concurrent_actions: int = Field(default=1, ge=0)
    execution_window_start: time | None = None
    execution_window_end: time | None = None
    required_approvals: list[str] = Field(default_factory=list)
    management_channels: list[str] = Field(default_factory=lambda: ["soc-control-plane"])
    rollback_channels: list[str] = Field(default_factory=lambda: ["rollback-controller"])
    owner: str = "security-engineering"
    expiry: datetime | None = None
    rollout_level: RolloutLevel = RolloutLevel.LEVEL_0_SHADOW
    enabled: bool = True

    @field_validator("expiry")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expiry must be timezone-aware")
        return value.astimezone(timezone.utc)


class PilotPreparationResult(StrictPilotModel):
    preparation_id: str
    execution_plan_id: str
    pilot_scope_id: str
    plan_hash: str
    allowed_to_continue: bool
    blocked_reasons: list[str] = Field(default_factory=list)
    required_approvals: list[str] = Field(default_factory=list)


class PilotApproval(StrictPilotModel):
    approval_id: str
    execution_plan_id: str
    plan_hash: str
    approver: str
    approver_role: str
    decision: str = "APPROVED"
    environment: str
    expires_at: datetime
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("expires_at", "timestamp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class CanaryDecision(StrictPilotModel):
    execution_id: str
    outcome: CanaryOutcome
    checks: dict[str, bool] = Field(default_factory=dict)
    reasons: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)


class RuntimeMonitoringResult(StrictPilotModel):
    pilot_execution_id: str
    status: RuntimeMonitorStatus
    metrics: dict[str, float] = Field(default_factory=dict)
    rollback_triggers: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=utc_now)


class PilotExecutionRecord(StrictPilotModel):
    pilot_execution_id: str
    verification_report_id: str = ""
    governance_decision_id: str = ""
    pilot_scope_id: str
    execution_plan_id: str
    canary_result: CanaryDecision | None = None
    runtime_monitoring_results: list[RuntimeMonitoringResult] = Field(default_factory=list)
    rollback_status: str = "not_started"
    final_outcome: PilotFinalOutcome = PilotFinalOutcome.PREPARED
    business_impact_observations: list[str] = Field(default_factory=list)
    security_impact_observations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    audit_references: list[str] = Field(default_factory=list)


class PilotMetrics(StrictPilotModel):
    successful_canaries: int = 0
    held_canaries: int = 0
    rollback_count: int = 0
    rollback_success_count: int = 0
    unexpected_scope_expansion_count: int = 0
    management_channel_failure_count: int = 0
    business_impact_threshold_violations: int = 0
    kill_switch_activations: int = 0
