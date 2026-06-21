"""Pydantic schemas for MIRAGE Milestone 7 offline RL."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mirage.domain.schemas import SafetyDecision, SafetyVerdict, require_aware


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictRLModel(BaseModel):
    """Strict base model for RL artifacts."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        protected_namespaces=(),
    )


class BlueTeamTactic(str, Enum):
    OBSERVE = "OBSERVE"
    DECEIVE = "DECEIVE"
    DELAY = "DELAY"
    LIMITED_CONTAIN = "LIMITED_CONTAIN"
    ESCALATE = "ESCALATE"
    NO_OP = "NO_OP"


class RLTrajectorySource(str, Enum):
    SIMULATOR = "simulator"
    ROBUST_PLANNER = "robust_planner"
    HEURISTIC_POLICY = "heuristic_policy"
    RANDOM_SAFE_POLICY = "random_safe_policy"
    DOCKER_LAB = "docker_lab"
    SHADOW_MODE = "shadow_mode"
    ANALYST_REVIEWED = "analyst_reviewed"
    SYNTHETIC_FIXTURE = "synthetic_fixture"


class RLDatasetSplit(str, Enum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    UNSEEN_TOPOLOGY = "unseen_topology"
    UNSEEN_ATTACK_SEQUENCE = "unseen_attack_sequence"
    UNSEEN_ACTION_COMBINATION = "unseen_action_combination"
    STALE_OR_INCOMPLETE_TWIN = "stale_or_incomplete_twin"
    NOISY_BELIEF = "noisy_belief"
    GNN_UNAVAILABLE = "gnn_unavailable"
    OOD_TYPES = "ood_types"
    ATTACKER_STRATEGY_SHIFT = "attacker_strategy_shift"
    ANALYST_REVIEWED = "analyst_reviewed"


class PolicyStatus(str, Enum):
    TRAINING = "TRAINING"
    VALIDATED = "VALIDATED"
    SHADOW = "SHADOW"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    REJECTED = "REJECTED"
    ARCHIVED = "ARCHIVED"


class RLOperatingMode(str, Enum):
    ROBUST_ONLY = "robust_only"
    BC_SHADOW = "bc_shadow"
    RL_SHADOW = "rl_shadow"
    RL_ROBUST_HYBRID = "rl_robust_hybrid"


class RLFeatureSchema(StrictRLModel):
    """Versioned deterministic feature layout for RL state/action encoders."""

    schema_version: str = "rl_state_v1"
    state_feature_names: list[str] = Field(default_factory=list)
    action_feature_names: list[str] = Field(default_factory=list)
    tactic_vocabulary: list[str] = Field(
        default_factory=lambda: [tactic.value for tactic in BlueTeamTactic]
    )
    action_schema_version: str = "rl_action_v1"
    missing_value_sentinel: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    def schema_hash(self) -> str:
        payload = json.dumps(
            {
                "schema_version": self.schema_version,
                "state_feature_names": self.state_feature_names,
                "action_feature_names": self.action_feature_names,
                "tactic_vocabulary": self.tactic_vocabulary,
                "action_schema_version": self.action_schema_version,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()[:16]

    def is_compatible(self, other: "RLFeatureSchema") -> bool:
        return (
            self.schema_version == other.schema_version
            and self.action_schema_version == other.action_schema_version
            and self.state_feature_names == other.state_feature_names
            and self.action_feature_names == other.action_feature_names
        )


class RLStateReference(StrictRLModel):
    state_id: str = Field(min_length=1)
    twin_version: str
    graph_version: str
    belief_version: str
    analysis_id: str
    gnn_model_version: str | None = None
    feature_schema_version: str
    timestamp: datetime
    operating_mode: str = RLOperatingMode.RL_SHADOW.value
    provenance_refs: dict[str, str] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class CandidateActionFeature(StrictRLModel):
    action_id: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    tactic_category: BlueTeamTactic
    expected_risk_reduction: float = Field(ge=0.0, le=1.0)
    information_gain: float = Field(ge=0.0, le=1.0)
    path_coverage: float = Field(ge=0.0, le=1.0)
    operational_cost: float = Field(ge=0.0)
    deployment_cost: float = Field(ge=0.0)
    business_risk: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    reversibility: float = Field(ge=0.0, le=1.0)
    ttl_seconds: int | None = Field(default=None, ge=1)
    risk_tier: str
    approval_required: bool
    affected_critical_assets: int = Field(default=0, ge=0)
    affected_paths: int = Field(default=0, ge=0)
    safety_gate_verdict: str = SafetyVerdict.REQUIRE_APPROVAL.value
    action_mask_status: str = "allowed"
    encoded_feature_vector: list[float] = Field(default_factory=list)
    feature_mask: list[float] = Field(default_factory=list)
    ood_warnings: list[str] = Field(default_factory=list)


class EncodedRLState(StrictRLModel):
    state_reference: RLStateReference
    feature_schema: RLFeatureSchema
    feature_vector: list[float] = Field(default_factory=list)
    feature_mask: list[float] = Field(default_factory=list)
    candidate_action_features: list[CandidateActionFeature] = Field(default_factory=list)
    allowed_action_ids: list[str] = Field(default_factory=list)
    masked_action_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RewardBreakdown(StrictRLModel):
    asset_protection_reward: float = 0.0
    interception_reward: float = 0.0
    attacker_delay_reward: float = 0.0
    information_gain_reward: float = 0.0
    risk_reduction_reward: float = 0.0
    safe_deception_reward: float = 0.0
    analyst_acceptance_reward: float = 0.0
    asset_loss_penalty: float = 0.0
    business_impact_penalty: float = 0.0
    operational_cost_penalty: float = 0.0
    false_positive_penalty: float = 0.0
    unnecessary_action_penalty: float = 0.0
    policy_instability_penalty: float = 0.0
    irreversible_action_penalty: float = 0.0
    stale_recommendation_penalty: float = 0.0
    analyst_rejection_penalty: float = 0.0
    hard_constraint_violations: list[str] = Field(default_factory=list)
    scalar_reward: float = 0.0
    clipped: bool = False

    def components(self) -> dict[str, float]:
        return {
            key: float(value)
            for key, value in self.model_dump().items()
            if key not in {"hard_constraint_violations", "scalar_reward", "clipped"}
            and isinstance(value, (int, float))
        }


class RLTransition(StrictRLModel):
    episode_id: str = Field(min_length=1)
    step_index: int = Field(ge=0)
    state_reference: RLStateReference
    state_feature_vector: list[float] = Field(default_factory=list)
    state_feature_mask: list[float] = Field(default_factory=list)
    candidate_action_features: list[CandidateActionFeature] = Field(default_factory=list)
    allowed_action_ids: list[str] = Field(default_factory=list)
    masked_action_ids: list[str] = Field(default_factory=list)
    selected_action_id: str
    selected_high_level_tactic: BlueTeamTactic
    behavior_policy_source: str
    behavior_policy_probability: float | None = Field(default=None, ge=0.0, le=1.0)
    reward_components: RewardBreakdown
    scalar_reward: float
    hard_constraint_violations: list[str] = Field(default_factory=list)
    next_state_reference: RLStateReference | None = None
    next_state_feature_vector: list[float] | None = None
    terminal: bool = False
    termination_reason: str = ""
    safety_verdict: str = SafetyVerdict.REQUIRE_APPROVAL.value
    execution_or_shadow_outcome: dict[str, Any] = Field(default_factory=dict)
    uncertainty: float = Field(default=0.0, ge=0.0, le=1.0)
    provenance: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    @model_validator(mode="after")
    def _selected_action_visible(self) -> "RLTransition":
        candidate_ids = {item.action_id for item in self.candidate_action_features}
        if self.selected_action_id != "__NO_OP__" and self.selected_action_id not in candidate_ids:
            raise ValueError("selected_action_id must be present in candidate_action_features")
        return self


class RLTrajectory(StrictRLModel):
    trajectory_id: str = Field(min_length=1)
    scenario_id: str
    topology_id: str
    source_type: RLTrajectorySource
    policy_source: str
    transitions: list[RLTransition] = Field(default_factory=list)
    total_return: float = 0.0
    total_business_cost: float = Field(default=0.0, ge=0.0)
    total_asset_loss: float = Field(default=0.0, ge=0.0)
    interception_result: str = "unknown"
    safety_violation_count: int = Field(default=0, ge=0)
    dataset_split: RLDatasetSplit = RLDatasetSplit.TRAIN
    labels: dict[str, Any] = Field(default_factory=dict)
    provenance: dict[str, str] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _ordered_steps(self) -> "RLTrajectory":
        steps = [transition.step_index for transition in self.transitions]
        if steps != sorted(steps):
            raise ValueError("transitions must be ordered by step_index")
        return self


class OfflineRLDatasetManifest(StrictRLModel):
    dataset_id: str = Field(min_length=1)
    dataset_version: str = "v1"
    feature_schema_version: str
    action_schema_version: str
    graph_schema_version: str = "unknown"
    gnn_model_versions: list[str] = Field(default_factory=list)
    trajectory_count: int = Field(ge=0)
    transition_count: int = Field(ge=0)
    source_distributions: dict[str, int] = Field(default_factory=dict)
    tactic_distributions: dict[str, int] = Field(default_factory=dict)
    action_distributions: dict[str, int] = Field(default_factory=dict)
    reward_statistics: dict[str, float] = Field(default_factory=dict)
    safety_statistics: dict[str, float] = Field(default_factory=dict)
    split_manifest: dict[str, list[str]] = Field(default_factory=dict)
    dataset_hash: str
    creation_timestamp: datetime
    warnings: list[str] = Field(default_factory=list)

    @field_validator("creation_timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class ActionScore(StrictRLModel):
    action_id: str
    tactic: BlueTeamTactic
    score: float
    probability: float = Field(ge=0.0, le=1.0)
    support_score: float = Field(default=1.0, ge=0.0, le=1.0)
    masked: bool = False
    reasons: list[str] = Field(default_factory=list)


class PolicyInferenceResult(StrictRLModel):
    policy_id: str
    policy_version: str
    state_id: str
    selected_high_level_tactic: BlueTeamTactic
    selected_action_id: str
    ranked_action_scores: list[ActionScore] = Field(default_factory=list)
    action_mask_applied: bool = True
    policy_confidence: float = Field(ge=0.0, le=1.0)
    policy_uncertainty: float = Field(ge=0.0, le=1.0)
    ood_warnings: list[str] = Field(default_factory=list)
    fallback_used: bool = False
    fallback_reason: str = ""
    robust_planner_comparison: dict[str, Any] = Field(default_factory=dict)
    safety_gate_result: SafetyDecision | None = None
    inference_time_ms: float = Field(default=0.0, ge=0.0)
    explanation: str = ""


class PolicyHealth(StrictRLModel):
    status: str = "no_policy"
    policy_id: str = ""
    policy_version: str = ""
    operating_mode: str = RLOperatingMode.RL_SHADOW.value
    feature_schema_version: str = ""
    action_schema_version: str = ""
    total_inferences: int = 0
    fallback_count: int = 0
    ood_warning_count: int = 0
    last_inference_time_ms: float = 0.0
    warnings: list[str] = Field(default_factory=list)


class TrainingMetrics(StrictRLModel):
    step: int = 0
    loss: float = 0.0
    policy_loss: float = 0.0
    q_loss: float = 0.0
    value_loss: float = 0.0
    entropy: float = 0.0
    mean_reward: float = 0.0
    support_penalty: float = 0.0
    warnings: list[str] = Field(default_factory=list)


class PolicyMetadata(StrictRLModel):
    policy_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    algorithm: str
    architecture: str
    feature_schema_version: str
    action_schema_version: str
    dataset_id: str = ""
    dataset_hash: str = ""
    reward_model_version: str = ""
    split_manifest: dict[str, list[str]] = Field(default_factory=dict)
    hyperparameters: dict[str, Any] = Field(default_factory=dict)
    training_seeds: list[int] = Field(default_factory=list)
    baseline_metrics: dict[str, float] = Field(default_factory=dict)
    offline_evaluation_metrics: dict[str, float] = Field(default_factory=dict)
    simulator_evaluation_metrics: dict[str, float] = Field(default_factory=dict)
    worst_case_metrics: dict[str, float] = Field(default_factory=dict)
    ood_thresholds: dict[str, float] = Field(default_factory=dict)
    status: PolicyStatus = PolicyStatus.TRAINING
    model_path: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    notes: str = ""

    @field_validator("created_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

