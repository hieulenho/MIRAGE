"""MIRAGE GNN — Hierarchical Graph Representation and GNN State Encoder V1.

Public re-exports kept minimal so callers do not need to import sub-modules
directly.  All GNN-specific public interfaces are available here.
"""

from __future__ import annotations

from mirage.gnn.schema import (
    DatasetBuildSummary,
    GNNInferenceResult,
    GNNOperatingMode,
    GNNOutput,
    GraphFeatureSchema,
    GraphSample,
    HybridPathRisk,
    ModelHealth,
    ModelMetadata,
    ModelStatus,
    SplitManifest,
)

__all__ = [
    "DatasetBuildSummary",
    "GNNInferenceResult",
    "GNNOperatingMode",
    "GNNOutput",
    "GraphFeatureSchema",
    "GraphSample",
    "HybridPathRisk",
    "ModelHealth",
    "ModelMetadata",
    "ModelStatus",
    "SplitManifest",
]
