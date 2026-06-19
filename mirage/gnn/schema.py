"""GNN schema definitions for MIRAGE Milestone 6.

All new GNN-specific Pydantic models live here.  Existing domain schemas
(TwinSnapshot, BeliefSnapshot, LocalOperationalSubgraph, etc.) are NOT
duplicated — they are imported from mirage.domain.schemas wherever needed.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# ---------------------------------------------------------------------------
# Feature schema — versioned, deterministic ordering
# ---------------------------------------------------------------------------

NODE_FEATURE_NAMES_V1: list[str] = [
    # Entity type (one-hot index; 0 = unknown)
    "entity_type_idx",
    # Belief features
    "compromise_probability",
    "attacker_location_probability",
    "belief_confidence",
    "belief_uncertainty",
    # Stage distribution (14 stages)
    "stage_normal",
    "stage_reconnaissance",
    "stage_initial_access",
    "stage_execution",
    "stage_persistence",
    "stage_privilege_escalation",
    "stage_defense_evasion",
    "stage_credential_access",
    "stage_discovery",
    "stage_lateral_movement",
    "stage_collection",
    "stage_command_and_control",
    "stage_exfiltration",
    "stage_impact",
    # Asset meta
    "business_criticality",
    "is_protected",
    "is_decoy",
    "is_seed",
    "is_critical",
    # Privilege
    "privilege_level_idx",
    # Vulnerability (placeholders; 0 when no vuln data)
    "vulnerability_count",
    "max_vulnerability_severity",
    # Evidence counts
    "evidence_count",
    "direct_evidence_count",
    "inferred_evidence_count",
    # Temporal
    "last_seen_recency",      # 0..1, 1=fresh
    "source_diversity",       # count of distinct evidence sources / 10
    "twin_confidence",
    "twin_freshness",
    # Graph topology (computed during dataset build)
    "in_degree",
    "out_degree",
    "weighted_in_degree",
    "weighted_out_degree",
    # Structural distances (normalised to 0..1; -1 encodes "unreachable")
    "dist_to_critical_asset",
    "dist_to_active_decoy",
]

EDGE_FEATURE_NAMES_V1: list[str] = [
    "relationship_type_idx",
    "confidence",
    "is_directly_observed",
    "is_inferred",
    "is_recent",              # last_seen within 1 hour
    "protocol_category_idx",
    "is_authentication_related",
    "credential_required",
    "privilege_requirement_idx",
    "movement_likelihood",    # heuristic 0..1
    "evidence_count",
    "is_stale",               # last_seen > 24 h
    "is_active",
    "is_protected_path",
    "existing_control",       # has source_event_ids == True
    "is_decoy_path",
]

NODE_ENTITY_TYPES_V1: list[str] = [
    "unknown",
    "asset",
    "host",
    "identity",
    "credential",
    "service",
    "process",
    "database",
    "subnet",
    "domain",
    "vulnerability",
    "decoy",
    "business_service",
    "application",
    "enterprise",
]

EDGE_RELATIONSHIP_TYPES_V1: list[str] = [
    "unknown",
    "communicates_with",
    "authenticated_to",
    "runs_on",
    "member_of",
    "has_privilege",
    "uses_credential",
    "uses_credential_on",
    "depends_on",
    "contains_vulnerability",
    "can_connect_to",
    "connects_to",
    "observed_lateral_movement",
    "protected_by",
    "deployed_as_decoy",
    "belongs_to_subnet",
    "belongs_to_domain",
    "asset_supports_application",
    "application_supports_business_service",
    "belongs_to_enterprise",
    "interacted_with_decoy",
    "accessed_file_on",
]

PRIVILEGE_LEVELS_V1: list[str] = [
    "unknown",
    "none",
    "standard",
    "elevated",
    "admin",
    "system",
    "protected",
]

PROTOCOL_CATEGORIES_V1: list[str] = [
    "unknown",
    "smb",
    "rdp",
    "ssh",
    "http",
    "https",
    "dns",
    "ldap",
    "kerberos",
    "other",
]


class GraphFeatureSchema(_StrictModel):
    """Versioned, deterministic feature schema for the GNN pipeline."""

    schema_version: str = "v1"
    node_feature_names: list[str] = Field(default_factory=lambda: list(NODE_FEATURE_NAMES_V1))
    edge_feature_names: list[str] = Field(default_factory=lambda: list(EDGE_FEATURE_NAMES_V1))
    node_entity_types: list[str] = Field(default_factory=lambda: list(NODE_ENTITY_TYPES_V1))
    edge_relationship_types: list[str] = Field(
        default_factory=lambda: list(EDGE_RELATIONSHIP_TYPES_V1)
    )
    privilege_levels: list[str] = Field(default_factory=lambda: list(PRIVILEGE_LEVELS_V1))
    protocol_categories: list[str] = Field(default_factory=lambda: list(PROTOCOL_CATEGORIES_V1))
    node_feature_dim: int = Field(default=len(NODE_FEATURE_NAMES_V1))
    edge_feature_dim: int = Field(default=len(EDGE_FEATURE_NAMES_V1))
    missing_value_sentinel: float = 0.0
    created_at: datetime = Field(default_factory=_utc_now)

    def schema_hash(self) -> str:
        payload = json.dumps(
            {
                "schema_version": self.schema_version,
                "node_feature_names": self.node_feature_names,
                "edge_feature_names": self.edge_feature_names,
                "node_entity_types": self.node_entity_types,
                "edge_relationship_types": self.edge_relationship_types,
            },
            sort_keys=True,
        ).encode()
        return hashlib.sha256(payload).hexdigest()[:16]

    def is_compatible(self, other: "GraphFeatureSchema") -> bool:
        """Return True if *other* is compatible with this schema."""
        return (
            self.schema_version == other.schema_version
            and self.node_feature_names == other.node_feature_names
            and self.edge_feature_names == other.edge_feature_names
        )


# ---------------------------------------------------------------------------
# Labels for multi-task learning
# ---------------------------------------------------------------------------

class NodeLabel(_StrictModel):
    """Ground-truth label for node-compromise task (Task A)."""

    node_id: str
    is_compromised: bool
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: str = "unknown"   # synthetic / confirmed / analyst_accepted / simulator


class EdgeLabel(_StrictModel):
    """Ground-truth label for edge lateral-movement task (Task B)."""

    edge_id: str
    is_lateral_movement: bool
    confidence: float = Field(ge=0.0, le=1.0)
    provenance: str = "unknown"


class GraphLabel(_StrictModel):
    """Ground-truth label for subgraph reachability task (Task C)."""

    is_high_risk: bool
    risk_level: float = Field(ge=0.0, le=1.0)
    provenance: str = "unknown"


class GraphSampleLabels(_StrictModel):
    """Labels for all tasks in one sample."""

    node_labels: dict[str, NodeLabel] = Field(default_factory=dict)
    edge_labels: dict[str, EdgeLabel] = Field(default_factory=dict)
    graph_label: GraphLabel | None = None
    label_source: str = "unknown"
    label_timestamp: datetime | None = None


# ---------------------------------------------------------------------------
# Graph sample — serializable unit of data
# ---------------------------------------------------------------------------

class SplitType(str, Enum):
    TRAIN = "train"
    VALIDATION = "validation"
    TEST = "test"
    UNSEEN = "unseen"


class GraphSample(_StrictModel):
    """Serializable GNN input sample produced by GraphDatasetBuilder."""

    sample_id: str = Field(min_length=1)
    # Version provenance
    twin_version: str
    graph_version: str
    belief_version: str
    feature_schema_version: str = "v1"
    feature_schema_hash: str = ""
    # Topology
    node_ids: list[str] = Field(default_factory=list)
    node_types: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    edge_types: list[str] = Field(default_factory=list)
    # Feature matrices serialized as nested lists (float)
    node_feature_matrix: list[list[float]] = Field(default_factory=list)
    edge_feature_matrix: list[list[float]] = Field(default_factory=list)
    # COO edge index [[src...], [dst...]]
    edge_index: list[list[int]] = Field(default_factory=lambda: [[], []])
    # Hierarchy
    hierarchy_mappings: dict[str, Any] = Field(default_factory=dict)
    # Masks (1=valid, 0=missing) — same shape as feature matrices
    node_feature_mask: list[list[float]] = Field(default_factory=list)
    edge_feature_mask: list[list[float]] = Field(default_factory=list)
    # Labels
    labels: GraphSampleLabels | None = None
    # Split assignment
    split: SplitType = SplitType.TRAIN
    scenario_id: str = "unknown"
    topology_id: str = "unknown"
    # Metadata
    reference_time: datetime
    created_at: datetime = Field(default_factory=_utc_now)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("reference_time", "created_at")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return v

    @property
    def num_nodes(self) -> int:
        return len(self.node_ids)

    @property
    def num_edges(self) -> int:
        return len(self.edge_ids)


# ---------------------------------------------------------------------------
# Dataset build summary
# ---------------------------------------------------------------------------

class DatasetBuildSummary(_StrictModel):
    """Statistics returned by GraphDatasetBuilder.build_dataset()."""

    total_samples: int = Field(ge=0)
    train_samples: int = Field(ge=0)
    validation_samples: int = Field(ge=0)
    test_samples: int = Field(ge=0)
    feature_schema_version: str = "v1"
    feature_schema_hash: str = ""
    output_path: str
    manifest_path: str
    node_type_counts: dict[str, int] = Field(default_factory=dict)
    edge_type_counts: dict[str, int] = Field(default_factory=dict)
    label_counts: dict[str, int] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Split manifest
# ---------------------------------------------------------------------------

class SplitManifest(_StrictModel):
    """Stored manifest recording how dataset samples were split."""

    manifest_id: str
    feature_schema_hash: str
    split_strategy: str = "scenario_time"
    train_sample_ids: list[str] = Field(default_factory=list)
    validation_sample_ids: list[str] = Field(default_factory=list)
    test_sample_ids: list[str] = Field(default_factory=list)
    scenario_assignments: dict[str, str] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# GNN model output
# ---------------------------------------------------------------------------

class GNNOutput(_StrictModel):
    """Raw output of GNNStateEncoder.forward()."""

    # Embeddings
    node_embeddings: list[list[float]] = Field(default_factory=list)
    graph_embedding: list[float] = Field(default_factory=list)
    # Risk predictions (probabilities 0..1)
    node_risk_probabilities: list[float] = Field(default_factory=list)
    edge_movement_probabilities: list[float] = Field(default_factory=list)
    graph_risk_probability: float = Field(ge=0.0, le=1.0, default=0.0)
    # Uncertainty
    node_uncertainty: list[float] = Field(default_factory=list)
    graph_uncertainty: float = Field(ge=0.0, le=1.0, default=1.0)
    # Metadata
    embedding_dim: int = Field(ge=1, default=64)
    num_nodes: int = Field(ge=0, default=0)
    num_edges: int = Field(ge=0, default=0)


# ---------------------------------------------------------------------------
# Inference result
# ---------------------------------------------------------------------------

class OODWarning(_StrictModel):
    """One out-of-distribution warning from inference."""

    warning_type: str   # unseen_node_type / unseen_edge_type / feature_ood / etc.
    details: str
    severity: str = "medium"   # low / medium / high


class GNNInferenceResult(_StrictModel):
    """Full output of GNNInferenceService.encode_subgraph()."""

    model_version: str
    feature_schema_version: str
    subgraph_id: str
    sample_id: str
    gnn_output: GNNOutput
    node_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    ood_warnings: list[OODWarning] = Field(default_factory=list)
    uncertainty_high: bool = False
    fallback_recommended: bool = False
    fallback_reason: str = ""
    inference_time_ms: float = Field(ge=0.0, default=0.0)
    inferred_at: datetime = Field(default_factory=_utc_now)


# ---------------------------------------------------------------------------
# Model metadata and registry
# ---------------------------------------------------------------------------

class ModelStatus(str, Enum):
    TRAINING = "TRAINING"
    VALIDATED = "VALIDATED"
    SHADOW = "SHADOW"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    ARCHIVED = "ARCHIVED"


class ModelMetadata(_StrictModel):
    """Registry entry for one trained GNN model."""

    model_id: str = Field(min_length=1)
    model_version: str = Field(min_length=1)
    architecture: str = "graphsage_v1"
    training_timestamp: datetime
    dataset_hash: str
    feature_schema_version: str
    feature_schema_hash: str
    split_manifest_id: str = ""
    training_config: dict[str, Any] = Field(default_factory=dict)
    evaluation_metrics: dict[str, float] = Field(default_factory=dict)
    compatible_schema_versions: list[str] = Field(default_factory=list)
    supported_node_types: list[str] = Field(default_factory=list)
    supported_edge_types: list[str] = Field(default_factory=list)
    status: ModelStatus = ModelStatus.TRAINING
    model_path: str = ""
    notes: str = ""

    @field_validator("training_timestamp")
    @classmethod
    def _aware(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return v


# ---------------------------------------------------------------------------
# Model health
# ---------------------------------------------------------------------------

class ModelHealth(_StrictModel):
    """Health status for GNNInferenceService."""

    status: str = "no_model"   # ok / degraded / no_model
    model_version: str = ""
    feature_schema_version: str = ""
    model_path: str = ""
    last_inference_time_ms: float = 0.0
    total_inferences: int = 0
    ood_warning_count: int = 0
    high_uncertainty_count: int = 0
    operating_mode: str = "heuristic_only"
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Hybrid path risk scoring
# ---------------------------------------------------------------------------

class GNNOperatingMode(str, Enum):
    HEURISTIC_ONLY = "heuristic_only"
    GNN_SHADOW = "gnn_shadow"
    HYBRID_RECOMMENDATION = "hybrid_recommendation"


class HybridPathRisk(_StrictModel):
    """Explainable hybrid path-risk score combining heuristic and GNN."""

    path_id: str
    heuristic_risk: float = Field(ge=0.0, le=1.0)
    gnn_edge_risk: float | None = None
    hybrid_risk: float = Field(ge=0.0, le=1.0)
    heuristic_weight: float = Field(ge=0.0, le=1.0)
    gnn_weight: float = Field(ge=0.0, le=1.0)
    operating_mode: GNNOperatingMode = GNNOperatingMode.GNN_SHADOW
    gnn_contribution: float = Field(ge=0.0, le=1.0, default=0.0)
    heuristic_contribution: float = Field(ge=0.0, le=1.0, default=0.0)
    uncertainty_high: bool = False
    ood_warning: bool = False
    fallback_active: bool = False
    explanation: str = ""


# ---------------------------------------------------------------------------
# GNN-extended robust decision input fields
# ---------------------------------------------------------------------------

class GNNDecisionFeatures(_StrictModel):
    """Optional GNN features to be attached to RobustDecisionInput."""

    subgraph_embedding: list[float] = Field(default_factory=list)
    node_risk_by_entity_id: dict[str, float] = Field(default_factory=dict)
    edge_movement_by_edge_id: dict[str, float] = Field(default_factory=dict)
    graph_risk: float = Field(ge=0.0, le=1.0, default=0.0)
    graph_uncertainty: float = Field(ge=0.0, le=1.0, default=1.0)
    ood_flags: list[str] = Field(default_factory=list)
    model_version: str = ""
    feature_schema_version: str = ""
