"""Canonical security-event and digital-twin schemas for MIRAGE."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def require_aware(value: datetime) -> datetime:
    """Require timezone-aware datetimes and normalize them to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


class StrictModel(BaseModel):
    """Base model that rejects accidental duplicate concepts as extra fields."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class SecurityEvent(StrictModel):
    """Canonical security event used by ingestion, replay, API, and twin."""

    event_id: str = Field(min_length=1)
    event_time: datetime
    ingest_time: datetime
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    asset_id: str | None = None
    user_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    process_name: str | None = None
    command_line: str | None = None
    credential_id: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_event_ref: str | None = None

    @field_validator("event_id", "source", "event_type")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("value must not be empty")
        return cleaned

    @field_validator("event_time", "ingest_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class Asset(StrictModel):
    """Canonical asset registry record."""

    asset_id: str = Field(min_length=1)
    hostname: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    asset_type: str = "unknown"
    operating_system: str | None = None
    environment: str | None = None
    subnet: str | None = None
    business_criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    owner: str | None = None
    first_seen: datetime
    last_seen: datetime
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    data_sources: list[str] = Field(default_factory=list)
    active: bool = True
    aliases: list[str] = Field(default_factory=list)
    is_decoy: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    @model_validator(mode="after")
    def _validate_seen_order(self) -> "Asset":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class Identity(StrictModel):
    """Canonical identity registry record."""

    identity_id: str = Field(min_length=1)
    username: str | None = None
    domain: str | None = None
    identity_type: str = "user"
    privilege_level: str = "unknown"
    groups: list[str] = Field(default_factory=list)
    associated_assets: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    data_sources: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    @model_validator(mode="after")
    def _validate_seen_order(self) -> "Identity":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class Relationship(StrictModel):
    """Relationship between two canonical or derived twin entities."""

    relationship_id: str = Field(min_length=1)
    source_entity_id: str = Field(min_length=1)
    target_entity_id: str = Field(min_length=1)
    relationship_type: str = Field(min_length=1)
    protocol: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    privilege_requirement: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    expiry_time: datetime | None = None
    source_event_ids: list[str] = Field(default_factory=list)
    active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen", "expiry_time")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None

    @model_validator(mode="after")
    def _validate_seen_order(self) -> "Relationship":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class TwinSnapshot(StrictModel):
    """Serializable point-in-time Digital Twin state."""

    twin_version: int = Field(ge=0)
    timestamp: datetime
    assets: dict[str, Asset] = Field(default_factory=dict)
    identities: dict[str, Identity] = Field(default_factory=dict)
    relationships: dict[str, Relationship] = Field(default_factory=dict)
    graph_metadata: dict[str, Any] = Field(default_factory=dict)
    source_position: str | None = None
    coverage_score: float = Field(default=0.0, ge=0.0, le=1.0)
    freshness_score: float = Field(default=0.0, ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class TwinUpdateResult(StrictModel):
    """Result of applying one event to the Digital Twin."""

    event_id: str
    event_type: str
    duplicate: bool = False
    assets_created: list[str] = Field(default_factory=list)
    assets_updated: list[str] = Field(default_factory=list)
    identities_created: list[str] = Field(default_factory=list)
    identities_updated: list[str] = Field(default_factory=list)
    relationships_created: list[str] = Field(default_factory=list)
    relationships_updated: list[str] = Field(default_factory=list)
    expired_relationships: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    twin_version: int


class TwinUpdateSummary(StrictModel):
    """Aggregate result for a batch replay or ingestion call."""

    processed: int = 0
    duplicates: int = 0
    invalid_events: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    identities_created: int = 0
    identities_updated: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    expired_relationships: int = 0
    final_twin_version: int = 0
    warnings: list[str] = Field(default_factory=list)


EventOrdering = Literal["event_time", "file"]


class AttackStageName(str, Enum):
    """Stable contextual-detection stage names."""

    NORMAL = "normal"
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


STAGE_NAMES_V1 = [stage.value for stage in AttackStageName]
FeatureScalar = bool | int | float | str


class TimelineEvent(StrictModel):
    """Canonical event entry stored in one or more entity timelines."""

    event_id: str = Field(min_length=1)
    event_time: datetime
    entity_ids: list[str] = Field(default_factory=list)
    event_type: str = Field(min_length=1)
    source: str = Field(min_length=1)
    technique_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    feature_values: dict[str, FeatureScalar] = Field(default_factory=dict)
    raw_event_ref: str | None = None

    @field_validator("event_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    @field_validator("entity_ids", "technique_ids")
    @classmethod
    def _dedupe_strings(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})


class TimelineUpdateResult(StrictModel):
    """Result of adding one event to timeline storage."""

    event_id: str
    duplicate: bool = False
    entity_ids: list[str] = Field(default_factory=list)
    timelines_updated: int = 0
    expired_events: int = 0
    warnings: list[str] = Field(default_factory=list)


class TimelineSnapshot(StrictModel):
    """Serializable in-memory timeline snapshot."""

    timestamp: datetime
    retention_seconds: int = Field(ge=1)
    events: dict[str, TimelineEvent] = Field(default_factory=dict)
    timeline_index: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class FeatureRecord(StrictModel):
    """Explainable named feature value."""

    name: str = Field(min_length=1)
    value: FeatureScalar
    window_seconds: int | None = Field(default=None, ge=1)
    source_event_ids: list[str] = Field(default_factory=list)
    explanation: str

    @field_validator("source_event_ids")
    @classmethod
    def _dedupe_event_ids(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})


class Evidence(StrictModel):
    """Explainable evidence item produced by rules or correlation."""

    evidence_id: str = Field(min_length=1)
    event_ids: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    rule_id: str | None = None
    description: str
    stage_hints: list[str] = Field(default_factory=list)
    score: float = Field(ge=-1.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen", "expires_at")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None

    @field_validator("event_ids", "entity_ids", "stage_hints")
    @classmethod
    def _dedupe_strings(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})

    @model_validator(mode="after")
    def _validate_seen_order(self) -> "Evidence":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class StageScore(StrictModel):
    """Score and probability for one attack stage."""

    stage: str
    raw_score: float
    probability: float = Field(ge=0.0, le=1.0)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    last_updated: datetime

    @field_validator("stage")
    @classmethod
    def _valid_stage(cls, value: str) -> str:
        if value not in STAGE_NAMES_V1:
            raise ValueError(f"Unsupported stage: {value}")
        return value

    @field_validator("last_updated")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class EntityBelief(StrictModel):
    """Probabilistic belief for one entity."""

    entity_id: str = Field(min_length=1)
    entity_type: str
    compromise_probability: float = Field(ge=0.0, le=1.0)
    stage_distribution: dict[str, float]
    most_likely_stage: str
    uncertainty: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    candidate_attacker_location_probability: float = Field(ge=0.0, le=1.0)
    first_suspicious_time: datetime | None = None
    last_updated: datetime
    belief_version: int = Field(ge=0)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("first_suspicious_time", "last_updated")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None

    @field_validator("evidence_ids")
    @classmethod
    def _dedupe_evidence(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})

    @model_validator(mode="after")
    def _validate_stage_distribution(self) -> "EntityBelief":
        if self.most_likely_stage not in STAGE_NAMES_V1:
            raise ValueError("most_likely_stage is not supported")
        for stage, probability in self.stage_distribution.items():
            if stage not in STAGE_NAMES_V1:
                raise ValueError(f"Unsupported stage: {stage}")
            if probability < 0 or probability > 1:
                raise ValueError("stage probabilities must be in [0, 1]")
        total = sum(self.stage_distribution.values())
        if abs(total - 1.0) > 1e-6:
            raise ValueError("stage probabilities must sum to 1")
        return self


class IncidentBelief(StrictModel):
    """Belief over a related set of suspicious entities."""

    incident_id: str = Field(min_length=1)
    entity_beliefs: dict[str, EntityBelief] = Field(default_factory=dict)
    probable_attack_paths: list[list[str]] = Field(default_factory=list)
    probable_entry_points: list[str] = Field(default_factory=list)
    probable_targets: list[str] = Field(default_factory=list)
    overall_stage_distribution: dict[str, float]
    overall_confidence: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(ge=0.0, le=1.0)
    evidence_ids: list[str] = Field(default_factory=list)
    created_at: datetime
    last_updated: datetime

    @field_validator("created_at", "last_updated")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class RuleMatch(StrictModel):
    """Detection rule match before conversion into durable evidence."""

    match_id: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    rule_name: str
    event_ids: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)
    stage_hints: list[str] = Field(default_factory=list)
    score: float = Field(ge=-1.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: str = "medium"
    description: str
    feature_names: list[str] = Field(default_factory=list)
    suppresses: bool = False
    expires_at: datetime | None = None
    technique_ids: list[str] = Field(default_factory=list)

    @field_validator("expires_at")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None


class CorrelationRecord(StrictModel):
    """Temporal sequence correlation across related entity timelines."""

    correlation_id: str = Field(min_length=1)
    related_event_ids: list[str] = Field(default_factory=list)
    related_entity_ids: list[str] = Field(default_factory=list)
    ordered_timeline: list[str] = Field(default_factory=list)
    inferred_stage_progression: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0)
    explanation: str
    first_seen: datetime
    last_seen: datetime

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class StageEstimationResult(StrictModel):
    """Attack-stage estimate with score breakdown."""

    entity_id: str
    stage_scores: dict[str, StageScore]
    stage_distribution: dict[str, float]
    most_likely_stage: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)
    uncertainty: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    score_breakdown: dict[str, float] = Field(default_factory=dict)
    reference_time: datetime

    @field_validator("reference_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class BeliefSnapshot(StrictModel):
    """Serializable contextual-belief state."""

    belief_version: int = Field(ge=0)
    timestamp: datetime
    entity_beliefs: dict[str, EntityBelief] = Field(default_factory=dict)
    evidence: dict[str, Evidence] = Field(default_factory=dict)
    correlations: dict[str, CorrelationRecord] = Field(default_factory=dict)
    attacker_location_distribution: dict[str, float] = Field(
        default_factory=lambda: {"unknown": 1.0}
    )
    warnings: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class BeliefUpdateResult(StrictModel):
    """Result of processing one event through the belief layer."""

    event_id: str
    entity_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    correlation_ids: list[str] = Field(default_factory=list)
    updated_beliefs: dict[str, EntityBelief] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    belief_version: int


class DetectionPipelineResult(StrictModel):
    """Structured audit result for one processed event."""

    event_id: str
    duplicate: bool = False
    entity_ids: list[str] = Field(default_factory=list)
    timeline_updated: bool = False
    twin_update: dict[str, Any] = Field(default_factory=dict)
    feature_values: dict[str, FeatureScalar] = Field(default_factory=dict)
    matched_rule_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    correlation_ids: list[str] = Field(default_factory=list)
    updated_beliefs: dict[str, EntityBelief] = Field(default_factory=dict)
    old_compromise_probabilities: dict[str, float] = Field(default_factory=dict)
    new_compromise_probabilities: dict[str, float] = Field(default_factory=dict)
    old_most_likely_stages: dict[str, str] = Field(default_factory=dict)
    new_most_likely_stages: dict[str, str] = Field(default_factory=dict)
    uncertainty_by_entity: dict[str, float] = Field(default_factory=dict)
    graph_risk_updated: bool = False
    warnings: list[str] = Field(default_factory=list)
    belief_version: int


class DetectionPipelineSummary(StrictModel):
    """Aggregate contextual-detection processing summary."""

    processed: int = 0
    duplicates: int = 0
    invalid_events: int = 0
    rule_matches: int = 0
    correlations_created: int = 0
    suspicious_entities: int = 0
    highest_compromise_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    most_likely_attack_stage: str = AttackStageName.NORMAL.value
    deception_interactions: int = 0
    final_belief_version: int = 0
    warnings: list[str] = Field(default_factory=list)


class PathType(str, Enum):
    """Supported attack-path discovery strategy labels."""

    SHORTEST_TO_CRITICAL_ASSET = "shortest_to_critical_asset"
    HIGHEST_SUCCESS_PROBABILITY = "highest_success_probability"
    HIGHEST_RISK = "highest_risk"
    CREDENTIAL_DRIVEN = "credential_driven"
    RECENTLY_OBSERVED = "recently_observed"
    DECOY_PATH = "decoy_path"
    UNPROTECTED_PATH = "unprotected_path"
    HIGH_BLAST_RADIUS = "high_blast_radius"


class RiskTier(str, Enum):
    """Candidate defense action risk tiers."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AutomationLevel(str, Enum):
    """Automation policy for generated candidate actions."""

    AUTOMATIC = "automatic"
    AUTOMATIC_WITH_MONITORING = "automatic_with_monitoring"
    RECOMMEND_ONLY = "recommend_only"
    HUMAN_APPROVAL_REQUIRED = "human_approval_required"
    PROHIBITED = "prohibited"


class SeedEntity(StrictModel):
    """Entity selected as an attack-analysis seed."""

    entity_id: str = Field(min_length=1)
    entity_type: str
    seed_reason: str = Field(min_length=1)
    compromise_probability: float = Field(ge=0.0, le=1.0)
    attacker_location_probability: float = Field(ge=0.0, le=1.0)
    belief_confidence: float = Field(ge=0.0, le=1.0)
    belief_uncertainty: float = Field(ge=0.0, le=1.0)
    most_likely_stage: str
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    priority_score: float = Field(ge=0.0, le=1.0)
    selected_at: datetime

    @field_validator("supporting_evidence_ids")
    @classmethod
    def _dedupe_evidence(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})

    @field_validator("selected_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class LocalSubgraphRequest(StrictModel):
    """Request parameters for bounded local operational subgraph extraction."""

    seed_entity_ids: list[str] = Field(default_factory=list)
    max_hops: int = Field(default=2, ge=0, le=10)
    max_nodes: int = Field(default=80, ge=1)
    max_edges: int = Field(default=160, ge=0)
    reference_time: datetime
    relationship_types: list[str] | None = None
    minimum_edge_confidence: float = Field(default=0.1, ge=0.0, le=1.0)
    include_decoys: bool = True
    include_credentials: bool = True
    include_identities: bool = True
    include_subnets: bool = False
    include_critical_assets: bool = True
    criticality_threshold: float = Field(default=0.8, ge=0.0, le=1.0)
    freshness_threshold: float | None = Field(default=None, ge=0.0)

    @field_validator("seed_entity_ids", "relationship_types")
    @classmethod
    def _dedupe_strings(cls, values: list[str] | None) -> list[str] | None:
        if values is None:
            return None
        return sorted({value for value in values if value})

    @field_validator("reference_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class LocalSubgraphNode(StrictModel):
    """Node in a local operational subgraph."""

    node_id: str = Field(min_length=1)
    entity_type: str
    label: str
    asset_type: str = "unknown"
    business_criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    is_seed: bool = False
    is_decoy: bool = False
    is_critical: bool = False
    is_protected: bool = False
    compromise_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    attacker_location_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    source: str = "twin"
    attributes: dict[str, Any] = Field(default_factory=dict)


class LocalSubgraphEdge(StrictModel):
    """Edge in a local operational subgraph."""

    edge_id: str = Field(min_length=1)
    source_entity_id: str = Field(min_length=1)
    target_entity_id: str = Field(min_length=1)
    relationship_type: str = Field(min_length=1)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None = None
    directly_observed: bool = True
    inferred: bool = False
    protected_edge: bool = False
    source_event_ids: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen", "expires_at")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None

    @field_validator("source_event_ids")
    @classmethod
    def _dedupe_events(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})


class LocalOperationalSubgraph(StrictModel):
    """Bounded local operational graph used for attack-path analysis."""

    subgraph_id: str = Field(min_length=1)
    graph_version: str
    twin_version: str
    belief_version: int | str
    created_at: datetime
    reference_time: datetime
    seed_entities: list[SeedEntity] = Field(default_factory=list)
    nodes: list[LocalSubgraphNode] = Field(default_factory=list)
    edges: list[LocalSubgraphEdge] = Field(default_factory=list)
    critical_asset_ids: list[str] = Field(default_factory=list)
    decoy_ids: list[str] = Field(default_factory=list)
    boundary_entity_ids: list[str] = Field(default_factory=list)
    unknown_boundary_count: int = Field(default=0, ge=0)
    coverage_score: float = Field(default=0.0, ge=0.0, le=1.0)
    freshness_score: float = Field(default=0.0, ge=0.0, le=1.0)
    truncated: bool = False
    truncation_reasons: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("created_at", "reference_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class AttackPath(StrictModel):
    """Candidate attack path through a local operational subgraph."""

    path_id: str = Field(min_length=1)
    source_entity_id: str = Field(min_length=1)
    target_entity_id: str = Field(min_length=1)
    node_ids: list[str] = Field(min_length=1)
    edge_ids: list[str] = Field(default_factory=list)
    path_length: int = Field(ge=0)
    path_type: str
    success_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    target_criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    stage_compatibility: float = Field(default=0.5, ge=0.0, le=1.0)
    credential_feasibility: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_recency: float = Field(default=0.5, ge=0.0, le=1.0)
    relationship_confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    decoy_engagement_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    uncertainty: float = Field(default=0.5, ge=0.0, le=1.0)
    required_credentials: list[str] = Field(default_factory=list)
    required_techniques: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    directly_observed_edge_ids: list[str] = Field(default_factory=list)
    inferred_edge_ids: list[str] = Field(default_factory=list)
    contains_decoy: bool = False
    reaches_protected_asset: bool = False
    explanation: str
    score_breakdown: dict[str, float] = Field(default_factory=dict)

    @field_validator(
        "node_ids",
        "edge_ids",
        "required_credentials",
        "required_techniques",
        "supporting_evidence_ids",
        "directly_observed_edge_ids",
        "inferred_edge_ids",
    )
    @classmethod
    def _dedupe_ordered_strings(cls, values: list[str]) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for value in values:
            if value and value not in seen:
                ordered.append(value)
                seen.add(value)
        return ordered


class AttackPathAnalysis(StrictModel):
    """Aggregate attack-path analysis for a local subgraph."""

    analysis_id: str = Field(min_length=1)
    subgraph_id: str
    reference_time: datetime
    paths: list[AttackPath] = Field(default_factory=list)
    top_risk_path_ids: list[str] = Field(default_factory=list)
    critical_assets_at_risk: list[str] = Field(default_factory=list)
    candidate_deception_positions: list[str] = Field(default_factory=list)
    uncovered_attack_surfaces: list[str] = Field(default_factory=list)
    analysis_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    analysis_uncertainty: float = Field(default=1.0, ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("reference_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class DeceptionPosition(StrictModel):
    """Recommended non-executing deception placement opportunity."""

    position_id: str = Field(min_length=1)
    entity_id: str | None = None
    edge_id: str | None = None
    affected_path_ids: list[str] = Field(default_factory=list)
    estimated_interception_coverage: float = Field(ge=0.0, le=1.0)
    estimated_deployment_cost: float = Field(ge=0.0)
    realism_requirements: list[str] = Field(default_factory=list)
    current_decoy_coverage: float = Field(default=0.0, ge=0.0, le=1.0)
    operational_constraints: list[str] = Field(default_factory=list)
    explanation: str


class CandidateDefenseAction(StrictModel):
    """Generated defensive action candidate; does not execute anything."""

    action_id: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    target_entity_ids: list[str] = Field(default_factory=list)
    affected_path_ids: list[str] = Field(default_factory=list)
    affected_edge_ids: list[str] = Field(default_factory=list)
    expected_risk_reduction: float = Field(ge=0.0, le=1.0)
    expected_information_gain: float = Field(ge=0.0, le=1.0)
    operational_cost: float = Field(ge=0.0)
    business_risk: float = Field(ge=0.0, le=1.0)
    deployment_cost: float = Field(ge=0.0)
    confidence: float = Field(ge=0.0, le=1.0)
    uncertainty: float = Field(ge=0.0, le=1.0)
    risk_tier: str
    automation_level: str
    requires_approval: bool
    rollback_supported: bool
    rollback_plan: str | None = None
    ttl_seconds: int | None = Field(default=None, ge=1)
    preconditions: list[str] = Field(default_factory=list)
    postconditions: list[str] = Field(default_factory=list)
    constraints: list[str] = Field(default_factory=list)
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    reason: str
    generated_at: datetime
    score_breakdown: dict[str, float] = Field(default_factory=dict)

    @field_validator("generated_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    @field_validator(
        "target_entity_ids",
        "affected_path_ids",
        "affected_edge_ids",
        "preconditions",
        "postconditions",
        "constraints",
        "supporting_evidence_ids",
    )
    @classmethod
    def _dedupe_strings(cls, values: list[str]) -> list[str]:
        return sorted({value for value in values if value})

    @field_validator("risk_tier")
    @classmethod
    def _valid_risk_tier(cls, value: str) -> str:
        if value not in {tier.value for tier in RiskTier}:
            raise ValueError(f"Unsupported risk tier: {value}")
        return value

    @field_validator("automation_level")
    @classmethod
    def _valid_automation(cls, value: str) -> str:
        if value not in {level.value for level in AutomationLevel}:
            raise ValueError(f"Unsupported automation level: {value}")
        return value


class ActionConstraintResult(StrictModel):
    """Constraint evaluation result for one candidate action."""

    action_id: str = Field(min_length=1)
    allowed: bool
    requires_approval: bool
    risk_tier: str
    violated_constraints: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    allowed_scope: list[str] = Field(default_factory=list)
    maximum_ttl_seconds: int | None = Field(default=None, ge=1)
    adjusted_business_risk: float = Field(ge=0.0, le=1.0)
    adjusted_confidence: float = Field(ge=0.0, le=1.0)
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class ActionMask(StrictModel):
    """Executable mask for one candidate action."""

    action_id: str = Field(min_length=1)
    allowed: bool
    mask_reasons: list[str] = Field(default_factory=list)
    required_conditions: list[str] = Field(default_factory=list)
    approval_required: bool
    effective_risk_tier: str
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None


class CandidateActionSet(StrictModel):
    """Generated, constrained, masked, and ranked action candidates."""

    action_set_id: str = Field(min_length=1)
    analysis_id: str
    subgraph_id: str
    reference_time: datetime
    actions: list[CandidateDefenseAction] = Field(default_factory=list)
    masks: dict[str, ActionMask] = Field(default_factory=dict)
    allowed_action_ids: list[str] = Field(default_factory=list)
    blocked_action_ids: list[str] = Field(default_factory=list)
    recommended_action_ids: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("reference_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class AttackAnalysisResult(StrictModel):
    """Full Milestone 3 attack analysis pipeline output."""

    analysis_id: str = Field(min_length=1)
    reference_time: datetime
    twin_version: str
    graph_version: str
    belief_version: int | str
    selected_seeds: list[SeedEntity] = Field(default_factory=list)
    subgraph: LocalOperationalSubgraph
    path_analysis: AttackPathAnalysis
    deception_positions: list[DeceptionPosition] = Field(default_factory=list)
    candidate_action_set: CandidateActionSet
    constraint_results: dict[str, ActionConstraintResult] = Field(default_factory=dict)
    timing_ms: dict[str, float] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("reference_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class RobustDecisionInput(StrictModel):
    """Compatibility adapter payload for later robust-decision consumption."""

    action_set_id: str
    analysis_id: str
    available_action_ids: list[str] = Field(default_factory=list)
    action_masks: dict[str, ActionMask] = Field(default_factory=dict)
    expected_utilities: dict[str, float] = Field(default_factory=dict)
    pessimistic_factors: dict[str, float] = Field(default_factory=dict)
    operational_costs: dict[str, float] = Field(default_factory=dict)
    business_risks: dict[str, float] = Field(default_factory=dict)
    uncertainties: dict[str, float] = Field(default_factory=dict)
    affected_attack_paths: dict[str, list[str]] = Field(default_factory=dict)
    budget_requirements: dict[str, float] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class SafetyVerdict(str, Enum):
    """Milestone 4 safety verdicts for candidate execution."""

    ALLOW = "ALLOW"
    ALLOW_WITH_MONITORING = "ALLOW_WITH_MONITORING"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class ExecutionState(str, Enum):
    """Explicit execution state-machine states."""

    PROPOSED = "PROPOSED"
    VALIDATED = "VALIDATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    PREPARED = "PREPARED"
    CANARY_RUNNING = "CANARY_RUNNING"
    EXECUTING = "EXECUTING"
    VERIFYING = "VERIFYING"
    SUCCEEDED = "SUCCEEDED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLED_BACK = "ROLLED_BACK"
    CANCELLED = "CANCELLED"
    DENIED = "DENIED"


class ApprovalDecision(str, Enum):
    """Human approval decision labels."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class SafetyDecision(StrictModel):
    """Safety Gate V1 decision for one candidate action."""

    action_id: str = Field(min_length=1)
    verdict: SafetyVerdict
    risk_tier: str
    confidence: float = Field(ge=0.0, le=1.0)
    business_risk: float = Field(ge=0.0, le=1.0)
    blast_radius_estimate: int = Field(ge=0)
    twin_freshness: float = Field(ge=0.0, le=1.0)
    graph_coverage: float = Field(ge=0.0, le=1.0)
    violated_policies: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    required_approvals: list[str] = Field(default_factory=list)
    allowed_scope: list[str] = Field(default_factory=list)
    maximum_ttl_seconds: int | None = Field(default=None, ge=1)
    rollback_required: bool = True
    reasons: list[str] = Field(default_factory=list)
    policy_version: str
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class ExecutionPlan(StrictModel):
    """Deterministic lab execution plan for one safe candidate action."""

    plan_id: str = Field(min_length=1)
    source_action_id: str = Field(min_length=1)
    action_type: str = Field(min_length=1)
    targets: list[str] = Field(default_factory=list)
    adapter_type: str = Field(min_length=1)
    requested_scope: list[str] = Field(default_factory=list)
    allowed_scope: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    preconditions: list[str] = Field(default_factory=list)
    canary_steps: list[str] = Field(default_factory=list)
    execution_steps: list[str] = Field(default_factory=list)
    verification_checks: list[str] = Field(default_factory=list)
    postconditions: list[str] = Field(default_factory=list)
    rollback_steps: list[str] = Field(default_factory=list)
    ttl_seconds: int | None = Field(default=None, ge=1)
    timeout_seconds: int = Field(default=300, ge=1)
    retry_policy: dict[str, int] = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=1)
    required_approvals: list[str] = Field(default_factory=list)
    twin_version: str
    graph_version: str
    belief_version: str
    analysis_id: str | None = None
    policy_version: str
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class AdapterCallResult(StrictModel):
    """Typed result returned by a mock/lab enforcement adapter."""

    adapter_type: str
    operation: str
    success: bool
    idempotency_key: str
    changed_resources: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class HealthCheckResult(StrictModel):
    """Verification or health-check result for an execution plan."""

    check_name: str
    success: bool
    details: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class StateTransitionRecord(StrictModel):
    """One deterministic state transition in an execution record."""

    from_state: ExecutionState | None = None
    to_state: ExecutionState
    reason: str
    timestamp: datetime

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class ExecutionRecord(StrictModel):
    """Auditable state for one execution workflow."""

    execution_id: str = Field(min_length=1)
    plan_id: str = Field(min_length=1)
    current_state: ExecutionState
    state_history: list[StateTransitionRecord] = Field(default_factory=list)
    adapter_results: list[AdapterCallResult] = Field(default_factory=list)
    health_check_results: list[HealthCheckResult] = Field(default_factory=list)
    canary_result: AdapterCallResult | None = None
    rollback_result: AdapterCallResult | None = None
    created_at: datetime
    updated_at: datetime
    expires_at: datetime | None = None
    actor: str = "mirage-policy"
    warnings: list[str] = Field(default_factory=list)
    failure_reason: str | None = None
    audit_references: list[str] = Field(default_factory=list)

    @field_validator("created_at", "updated_at", "expires_at")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None


class ApprovalRecord(StrictModel):
    """Human approval record for an execution."""

    approval_id: str = Field(min_length=1)
    execution_id: str = Field(min_length=1)
    approver: str = Field(min_length=1)
    decision: ApprovalDecision
    reason: str = ""
    timestamp: datetime
    expiry: datetime

    @field_validator("timestamp", "expiry")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class KillSwitchState(StrictModel):
    """Global/per-action/per-environment automation kill-switch state."""

    global_enabled: bool = False
    action_type_blocks: dict[str, bool] = Field(default_factory=dict)
    environment_blocks: dict[str, bool] = Field(default_factory=dict)
    updated_by: str = "system"
    reason: str = ""
    updated_at: datetime

    @field_validator("updated_at")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class AuditEvent(StrictModel):
    """Append-only sanitized audit event."""

    audit_id: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    timestamp: datetime
    actor: str = "mirage"
    execution_id: str | None = None
    plan_id: str | None = None
    action_id: str | None = None
    policy_version: str | None = None
    twin_version: str | None = None
    graph_version: str | None = None
    belief_version: str | None = None
    analysis_id: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)
