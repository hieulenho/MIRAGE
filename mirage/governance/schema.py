"""Governance schemas for controlled pilot artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictGovernanceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ArtifactType(str, Enum):
    GNN_MODEL = "GNN_MODEL"
    BC_POLICY = "BC_POLICY"
    OFFLINE_RL_POLICY = "OFFLINE_RL_POLICY"
    MARL_BLUE_POLICY = "MARL_BLUE_POLICY"
    RED_POLICY = "RED_POLICY"
    REWARD_MODEL = "REWARD_MODEL"
    FEATURE_SCHEMA = "FEATURE_SCHEMA"
    ACTION_SCHEMA = "ACTION_SCHEMA"
    SAFETY_POLICY = "SAFETY_POLICY"
    PILOT_SCOPE = "PILOT_SCOPE"
    VERIFIER = "VERIFIER"


class GovernanceStatus(str, Enum):
    DRAFT = "DRAFT"
    TRAINING = "TRAINING"
    VALIDATED = "VALIDATED"
    SHADOW = "SHADOW"
    PILOT_CANDIDATE = "PILOT_CANDIDATE"
    PILOT_APPROVED = "PILOT_APPROVED"
    SUSPENDED = "SUSPENDED"
    REJECTED = "REJECTED"
    ARCHIVED = "ARCHIVED"


class GovernanceVerdict(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    SUSPENDED = "SUSPENDED"


class GovernedArtifact(StrictGovernanceModel):
    artifact_id: str = Field(min_length=1)
    artifact_type: ArtifactType
    version: str = Field(min_length=1)
    artifact_hash: str = Field(min_length=1)
    configuration_hash: str = ""
    dataset_manifest_hash: str = ""
    feature_schema_hash: str = ""
    action_schema_hash: str = ""
    code_version: str = ""
    verification_report_hash: str = ""
    parent_version: str = ""
    training_dataset: str = ""
    configuration: dict[str, Any] = Field(default_factory=dict)
    evaluation_results: dict[str, float] = Field(default_factory=dict)
    worst_case_metrics: dict[str, float] = Field(default_factory=dict)
    ood_results: dict[str, float] = Field(default_factory=dict)
    safety_results: dict[str, Any] = Field(default_factory=dict)
    approval_status: GovernanceStatus = GovernanceStatus.DRAFT
    owner: str = "mirage-governance"
    created_at: datetime = Field(default_factory=utc_now)
    review_at: datetime | None = None
    expires_at: datetime | None = None
    status: GovernanceStatus = GovernanceStatus.DRAFT

    @field_validator("created_at", "review_at", "expires_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class EvidenceBundle(StrictGovernanceModel):
    test_results: dict[str, bool] = Field(default_factory=dict)
    metrics: dict[str, float] = Field(default_factory=dict)
    documents: dict[str, str] = Field(default_factory=dict)
    model_card_complete: bool = False
    policy_card_complete: bool = False
    formal_verification_passed: bool = False
    masked_action_violations: int = 0
    hard_safety_violations: int = 0
    approvals: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class GovernanceDecision(StrictGovernanceModel):
    decision_id: str = Field(min_length=1)
    artifact_type: ArtifactType
    artifact_id: str
    artifact_version: str
    proposed_status: GovernanceStatus
    governance_verdict: GovernanceVerdict
    required_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    approvers: list[str] = Field(default_factory=list)
    approvals: list[str] = Field(default_factory=list)
    rejection_reasons: list[str] = Field(default_factory=list)
    release_gate_results: dict[str, bool] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utc_now)

    @field_validator("timestamp")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("timestamp must be timezone-aware")
        return value.astimezone(timezone.utc)


class ModelCard(StrictGovernanceModel):
    artifact_id: str
    version: str
    intended_use: str
    prohibited_use: str
    architecture: str
    training_sources: list[str]
    dataset_limitations: list[str]
    feature_schema: str
    evaluation_results: dict[str, float]
    worst_case_results: dict[str, float]
    calibration: dict[str, float] = Field(default_factory=dict)
    ood_behavior: str
    uncertainty_method: str
    known_failure_modes: list[str]
    safety_dependencies: list[str]
    fallback_behavior: str
    approval_history: list[str] = Field(default_factory=list)

    def is_complete(self) -> bool:
        return all([
            self.intended_use,
            self.prohibited_use,
            self.architecture,
            self.training_sources,
            self.feature_schema,
            self.ood_behavior,
            self.uncertainty_method,
            self.safety_dependencies,
            self.fallback_behavior,
        ])


class PolicyCard(StrictGovernanceModel):
    artifact_id: str
    version: str
    policy_purpose: str
    action_vocabulary: list[str]
    required_candidate_generator: str
    mask_requirements: list[str]
    safety_gate_dependency: str
    formal_verification_requirements: list[str]
    pilot_scope: str
    approval_rules: list[str]
    rollback_requirements: list[str]
    fallback_chain: list[str]
    known_limitations: list[str]
    promotion_evidence: list[str]

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        validate_assignment=True,
    )

    def is_complete(self) -> bool:
        return all([
            self.policy_purpose,
            self.action_vocabulary,
            self.required_candidate_generator,
            self.mask_requirements,
            self.safety_gate_dependency,
            self.formal_verification_requirements,
            self.pilot_scope,
            self.approval_rules,
            self.rollback_requirements,
            self.fallback_chain,
            self.promotion_evidence,
        ])


class PolicyEvaluationResult(StrictGovernanceModel):
    policy_id: str
    policy_version: str
    allowed: bool
    deny_reasons: list[str] = Field(default_factory=list)
    required_approvals: list[str] = Field(default_factory=list)
    policy_hash: str
    policy_version_id: str = "policy-as-code-v1"
    evaluated_at: datetime = Field(default_factory=utc_now)


class GovernanceAuditRecord(StrictGovernanceModel):
    audit_id: str
    event_type: str
    actor: str
    role: str
    artifact_or_execution_id: str = ""
    before_state: dict[str, Any] = Field(default_factory=dict)
    after_state: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    timestamp: datetime = Field(default_factory=utc_now)
    hashes: dict[str, str] = Field(default_factory=dict)
    related_evidence: list[str] = Field(default_factory=list)
    previous_record_hash: str = ""
    record_hash: str
