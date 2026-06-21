"""Strict schemas for the MIRAGE Milestone 8 MARL cyber range."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from mirage.domain.schemas import ActionMask, CandidateDefenseAction


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def clamp01(value: float) -> float:
    """Clamp a numeric value into [0, 1]."""
    return max(0.0, min(1.0, float(value)))


class StrictMARLModel(BaseModel):
    """Base model that rejects accidental extra fields."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class RangeIsolationConfig(StrictMARLModel):
    """Safety switches required before any MARL range component runs."""

    cyber_range_only: bool = True
    red_agent_external_network: bool = False
    production_connectivity: bool = False
    real_exploitation_enabled: bool = False
    blue_execution_mode: Literal["shadow"] = "shadow"
    training_api_enabled: bool = False
    registry_path: str = "models/marl_policy_registry.json"
    scenario_path: str = "artifacts/marl_scenarios"
    checkpoint_path: str = "models/marl_self_play"
    max_steps: int = Field(default=12, ge=1, le=200)
    max_scenarios_per_job: int = Field(default=20, ge=1, le=200)
    default_episodes: int = Field(default=6, ge=1, le=200)
    random_seed: int = 42
    opponent_profiles: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _must_be_isolated(self) -> "RangeIsolationConfig":
        violations = self.violations()
        if violations:
            raise ValueError(
                "MARL cyber range isolation failed: " + ", ".join(violations)
            )
        return self

    def violations(self) -> list[str]:
        """Return isolation violations without side effects."""
        issues: list[str] = []
        if not self.cyber_range_only:
            issues.append("cyber_range_only must be true")
        if self.red_agent_external_network:
            issues.append("red_agent_external_network must be false")
        if self.production_connectivity:
            issues.append("production_connectivity must be false")
        if self.real_exploitation_enabled:
            issues.append("real_exploitation_enabled must be false")
        if self.blue_execution_mode != "shadow":
            issues.append("blue_execution_mode must be shadow")
        return issues

    def assert_safe(self) -> None:
        """Raise when the range is not fully isolated."""
        violations = self.violations()
        if violations:
            raise RuntimeError(
                "MARL cyber range isolation failed: " + ", ".join(violations)
            )


class RedActionCategory(str, Enum):
    """Allowlisted abstract red-team actions."""

    RECON = "RECON"
    DISCOVER_NEIGHBOR = "DISCOVER_NEIGHBOR"
    INSPECT_SERVICE = "INSPECT_SERVICE"
    USE_SIMULATED_CREDENTIAL = "USE_SIMULATED_CREDENTIAL"
    MOVE_ALONG_EDGE = "MOVE_ALONG_EDGE"
    CHANGE_TARGET = "CHANGE_TARGET"
    REDUCE_NOISE = "REDUCE_NOISE"
    INCREASE_SPEED = "INCREASE_SPEED"
    INTERACT_WITH_RESOURCE = "INTERACT_WITH_RESOURCE"
    COLLECT_SYNTHETIC_OBJECTIVE = "COLLECT_SYNTHETIC_OBJECTIVE"
    WAIT = "WAIT"
    TERMINATE = "TERMINATE"


class BlueActionKind(str, Enum):
    """Synthetic defensive effects used only inside the cyber range."""

    OBSERVE = "OBSERVE"
    DECEIVE = "DECEIVE"
    DELAY = "DELAY"
    LIMITED_CONTAIN = "LIMITED_CONTAIN"
    ESCALATE = "ESCALATE"
    NO_OP = "NO_OP"


class RangeNode(StrictMARLModel):
    """Synthetic graph node for MARL training."""

    node_id: str = Field(min_length=1)
    visible_label: str = Field(min_length=1)
    asset_type: str = "workstation"
    value: float = Field(default=0.1, ge=0.0, le=1.0)
    exposure: float = Field(default=0.1, ge=0.0, le=1.0)
    services: list[str] = Field(default_factory=list)
    is_entry: bool = False
    is_objective: bool = False
    is_decoy: bool = False
    protected: bool = False
    credential_hint: bool = False
    tags: list[str] = Field(default_factory=list)

    @field_validator("services", "tags")
    @classmethod
    def _dedupe(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})


class RangeEdge(StrictMARLModel):
    """Synthetic movement edge for MARL training."""

    edge_id: str = Field(min_length=1)
    source: str = Field(min_length=1)
    target: str = Field(min_length=1)
    relation: str = "connects_to"
    difficulty: float = Field(default=0.4, ge=0.0, le=1.0)
    noise: float = Field(default=0.1, ge=0.0, le=1.0)
    credential_required: bool = False
    tags: list[str] = Field(default_factory=list)

    @field_validator("tags")
    @classmethod
    def _dedupe(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})


class RangeScenario(StrictMARLModel):
    """Versioned synthetic scenario used by the cyber range."""

    scenario_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    nodes: list[RangeNode]
    edges: list[RangeEdge]
    entry_node_ids: list[str]
    objective_node_ids: list[str]
    max_steps: int = Field(default=12, ge=1, le=200)
    blue_budget: float = Field(default=5.0, ge=0.0)
    random_seed: int = 42
    tags: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_graph(self) -> "RangeScenario":
        node_ids = {node.node_id for node in self.nodes}
        if not node_ids:
            raise ValueError("scenario must contain at least one node")
        for node_id in self.entry_node_ids + self.objective_node_ids:
            if node_id not in node_ids:
                raise ValueError(f"scenario references unknown node: {node_id}")
        edge_ids: set[str] = set()
        for edge in self.edges:
            if edge.edge_id in edge_ids:
                raise ValueError(f"duplicate edge_id: {edge.edge_id}")
            edge_ids.add(edge.edge_id)
            if edge.source not in node_ids or edge.target not in node_ids:
                raise ValueError(f"edge {edge.edge_id} references unknown node")
        return self

    def node_map(self) -> dict[str, RangeNode]:
        return {node.node_id: node for node in self.nodes}

    def edge_map(self) -> dict[str, RangeEdge]:
        return {edge.edge_id: edge for edge in self.edges}

    def outgoing_edges(self, node_id: str) -> list[RangeEdge]:
        return [edge for edge in self.edges if edge.source == node_id]


class RedAction(StrictMARLModel):
    """One abstract red action. It never contains executable instructions."""

    action_id: str = Field(min_length=1)
    category: RedActionCategory
    source_node_id: str | None = None
    target_node_id: str | None = None
    edge_id: str | None = None
    credential_id: str | None = None
    cost: float = Field(default=0.1, ge=0.0)
    noise: float = Field(default=0.05, ge=0.0, le=1.0)
    success_probability: float = Field(default=1.0, ge=0.0, le=1.0)
    description: str = Field(default="", max_length=240)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _reject_executable_language(self) -> "RedAction":
        text = " ".join(
            str(value).lower()
            for value in [
                self.action_id,
                self.description,
                *self.metadata.keys(),
                *self.metadata.values(),
            ]
        )
        forbidden = [
            "command",
            "payload",
            "shell",
            "powershell",
            "cmd.exe",
            "socket",
            "http://",
            "https://",
            "metasploit",
            "msfconsole",
            "nmap",
            "curl ",
            "wget ",
            "external_network",
            "production",
        ]
        hits = [term for term in forbidden if term in text]
        if hits:
            raise ValueError(
                "red action contains non-range executable terminology: "
                + ", ".join(hits)
            )
        return self


class RedActionMask(StrictMARLModel):
    """Mask for abstract red actions."""

    valid_action_ids: list[str] = Field(default_factory=list)
    blocked_action_ids: list[str] = Field(default_factory=list)
    reasons: dict[str, list[str]] = Field(default_factory=dict)

    def allowed(self, action_id: str) -> bool:
        return action_id in set(self.valid_action_ids)


class RedObservation(StrictMARLModel):
    """Partial red observation without protected ground truth."""

    observation_id: str
    scenario_id: str
    step_index: int = Field(ge=0)
    current_node_id: str
    visible_nodes: list[dict[str, Any]] = Field(default_factory=list)
    visible_edges: list[dict[str, Any]] = Field(default_factory=list)
    discovered_node_ids: list[str] = Field(default_factory=list)
    discovered_edge_ids: list[str] = Field(default_factory=list)
    known_credentials: list[str] = Field(default_factory=list)
    remaining_steps: int = Field(ge=0)
    noise_level: float = Field(ge=0.0, le=1.0)
    defender_pressure: float = Field(ge=0.0, le=1.0)
    recent_blue_actions: list[str] = Field(default_factory=list)


class BlueObservation(StrictMARLModel):
    """Blue observation with synthetic telemetry and candidate actions."""

    observation_id: str
    scenario_id: str
    step_index: int = Field(ge=0)
    suspected_red_node_ids: list[str] = Field(default_factory=list)
    detection_confidence: float = Field(ge=0.0, le=1.0)
    protected_assets_at_risk: list[str] = Field(default_factory=list)
    candidate_actions: list[CandidateDefenseAction] = Field(default_factory=list)
    action_masks: dict[str, ActionMask] = Field(default_factory=dict)
    telemetry_events: list[dict[str, Any]] = Field(default_factory=list)
    budget_remaining: float = Field(ge=0.0)
    warnings: list[str] = Field(default_factory=list)


class MultiAgentObservation(StrictMARLModel):
    """Joint observation returned by reset and step."""

    red: RedObservation
    blue: BlueObservation


class RangeState(StrictMARLModel):
    """Mutable cyber-range state, serializable for replay."""

    scenario_id: str
    step_index: int = Field(default=0, ge=0)
    red_position: str
    target_objective_id: str
    discovered_node_ids: list[str] = Field(default_factory=list)
    discovered_edge_ids: list[str] = Field(default_factory=list)
    compromised_node_ids: list[str] = Field(default_factory=list)
    known_credentials: list[str] = Field(default_factory=list)
    active_decoys: list[str] = Field(default_factory=list)
    contained_nodes: list[str] = Field(default_factory=list)
    hardened_edges: list[str] = Field(default_factory=list)
    detection_score: float = Field(default=0.0, ge=0.0, le=1.0)
    noise_level: float = Field(default=0.0, ge=0.0, le=1.0)
    blue_budget_remaining: float = Field(default=0.0, ge=0.0)
    terminal: bool = False
    terminal_reason: str = ""
    rng_seed: int = 42
    last_events: list[dict[str, Any]] = Field(default_factory=list)
    history: list[dict[str, Any]] = Field(default_factory=list)


class MultiAgentRewardBreakdown(StrictMARLModel):
    """Auditable red/blue reward components."""

    red_progress: float = 0.0
    red_objective: float = 0.0
    red_stealth: float = 0.0
    red_noise_penalty: float = 0.0
    red_invalid_action_penalty: float = 0.0
    blue_asset_protection: float = 0.0
    blue_detection: float = 0.0
    blue_deception: float = 0.0
    blue_delay: float = 0.0
    blue_cost_penalty: float = 0.0
    blue_invalid_action_penalty: float = 0.0
    hard_constraint_violations: list[str] = Field(default_factory=list)

    @property
    def red_total(self) -> float:
        return round(
            self.red_progress
            + self.red_objective
            + self.red_stealth
            - self.red_noise_penalty
            - self.red_invalid_action_penalty,
            6,
        )

    @property
    def blue_total(self) -> float:
        total = (
            self.blue_asset_protection
            + self.blue_detection
            + self.blue_deception
            + self.blue_delay
            - self.blue_cost_penalty
            - self.blue_invalid_action_penalty
        )
        if self.hard_constraint_violations:
            total = min(0.0, total) - 1.0
        return round(total, 6)


class MultiAgentStepResult(StrictMARLModel):
    """Result of one simultaneous red/blue range step."""

    observation: MultiAgentObservation
    state: RangeState
    red_action: RedAction | None = None
    blue_action_id: str
    reward: MultiAgentRewardBreakdown
    red_reward: float
    blue_reward: float
    terminal: bool
    info: dict[str, Any] = Field(default_factory=dict)


class MARLTrajectoryStep(StrictMARLModel):
    """Serializable replay step for MARL trajectories."""

    step_index: int = Field(ge=0)
    red_observation: RedObservation
    blue_observation: BlueObservation
    red_action_id: str
    blue_action_id: str
    red_reward: float
    blue_reward: float
    terminal: bool
    info: dict[str, Any] = Field(default_factory=dict)


class MARLTrajectory(StrictMARLModel):
    """One self-play trajectory."""

    trajectory_id: str
    scenario_id: str
    red_policy_id: str
    blue_policy_id: str
    steps: list[MARLTrajectoryStep] = Field(default_factory=list)
    total_red_return: float = 0.0
    total_blue_return: float = 0.0
    terminal_reason: str = ""
    created_at: datetime = Field(default_factory=utc_now)

    @field_validator("created_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)


class OpponentMetadata(StrictMARLModel):
    """Registry metadata for an opponent policy."""

    opponent_id: str
    role: Literal["red", "blue"]
    policy_type: str
    version: str = "v1"
    rating: float = 1000.0
    scenario_tags: list[str] = Field(default_factory=list)
    exploitability_score: float = 0.0
    created_at: datetime = Field(default_factory=utc_now)


class MARLPolicyStatus(str, Enum):
    TRAINING = "training"
    VALIDATED = "validated"
    SHADOW = "shadow"
    REVIEW_REQUIRED = "review_required"
    REJECTED = "rejected"
    ARCHIVED = "archived"


class MARLPolicyMetadata(StrictMARLModel):
    """File-backed registry metadata for MARL policies."""

    policy_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    role: Literal["red", "blue"]
    algorithm: str
    architecture: str
    scenario_ids: list[str] = Field(default_factory=list)
    training_steps: int = Field(default=0, ge=0)
    random_seed: int = 42
    baseline_metrics: dict[str, float] = Field(default_factory=dict)
    robustness_metrics: dict[str, float] = Field(default_factory=dict)
    exploitability_metrics: dict[str, float] = Field(default_factory=dict)
    status: MARLPolicyStatus = MARLPolicyStatus.TRAINING
    model_path: str = ""
    safety: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utc_now)
    notes: str = ""


class RangeHealth(StrictMARLModel):
    """Health payload for API/CLI range checks."""

    status: str
    isolation: RangeIsolationConfig
    training_api_enabled: bool = False
    policy_count: int = 0
    scenario_count: int = 0
    warnings: list[str] = Field(default_factory=list)


class TrainingSummary(StrictMARLModel):
    """Compact output from self-play training."""

    job_id: str
    algorithm: str
    episodes: int = Field(ge=0)
    trajectories: int = Field(ge=0)
    mean_red_return: float = 0.0
    mean_blue_return: float = 0.0
    terminal_reasons: dict[str, int] = Field(default_factory=dict)
    policy_metadata: MARLPolicyMetadata | None = None
    warnings: list[str] = Field(default_factory=list)


class ExploitabilityReport(StrictMARLModel):
    """Approximate best-response evaluation report."""

    evaluated_policy_id: str
    scenario_count: int
    best_response_policy_id: str
    approximate_exploitability: float = Field(ge=0.0)
    per_opponent_return: dict[str, float] = Field(default_factory=dict)
    note: str = (
        "Approximate graph-simulator best response only; not production evidence."
    )


class PolicyRobustnessReport(StrictMARLModel):
    """Cross-scenario policy robustness report."""

    policy_id: str
    scenario_count: int
    opponent_count: int
    mean_blue_return: float
    worst_case_blue_return: float
    per_scenario_return: dict[str, float] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
