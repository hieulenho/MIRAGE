from __future__ import annotations

from datetime import datetime, timezone

import pytest

from mirage.domain.schemas import AttackPath
from mirage.gnn.dataset import GraphDatasetBuilder
from mirage.gnn.hybrid_scorer import HybridPathRiskAdapter
from mirage.gnn.inference import GNNInferenceService
from mirage.gnn.registry import ModelRegistry
from mirage.gnn.scenarios import build_scenario
from mirage.gnn.schema import (
    GNNInferenceResult,
    GNNOperatingMode,
    GNNOutput,
    GraphFeatureSchema,
    ModelMetadata,
    ModelStatus,
)


def test_inference_service_falls_back_without_model_and_rejects_schema_mismatch():
    sample = GraphDatasetBuilder().build_sample(**build_scenario("benign_admin_activity"))
    service = GNNInferenceService(max_nodes=10, max_edges=10)

    result = service.encode_subgraph(sample)

    assert result.fallback_recommended is True
    assert result.fallback_reason == "no_model_loaded"
    assert result.gnn_output.num_nodes == sample.num_nodes

    incompatible = sample.model_copy(update={"feature_schema_version": "v0"})
    with pytest.raises(ValueError, match="schema version"):
        service.encode_subgraph(incompatible)


def test_model_registry_lifecycle_requires_explicit_shadow_transition(tmp_path):
    registry = ModelRegistry(str(tmp_path / "registry.json"))
    metadata = ModelMetadata(
        model_id="gnn-test",
        model_version="v1",
        training_timestamp=datetime(2026, 6, 17, 12, 0, tzinfo=timezone.utc),
        dataset_hash="abc123",
        feature_schema_version="v1",
        feature_schema_hash=GraphFeatureSchema().schema_hash(),
        compatible_schema_versions=["v1"],
        status=ModelStatus.VALIDATED,
    )

    registry.register(metadata)
    shadow = registry.transition("gnn-test", ModelStatus.SHADOW)

    assert shadow.status == ModelStatus.SHADOW
    with pytest.raises(ValueError):
        registry.transition("gnn-test", ModelStatus.TRAINING)


def test_hybrid_path_scorer_shadow_and_hybrid_modes_preserve_constraints():
    entry = build_scenario("lateral_movement_to_critical_db")
    subgraph = entry["local_subgraph"]
    belief = entry["belief_snapshot"]
    ref = entry["reference_time"]
    edge_id = subgraph.edges[0].edge_id
    path = AttackPath(
        path_id="path-test",
        source_entity_id="asset:entry_host",
        target_entity_id="asset:mid_server",
        node_ids=["asset:entry_host", "asset:mid_server"],
        edge_ids=[edge_id],
        path_length=1,
        path_type="highest_risk",
        success_probability=0.8,
        target_criticality=0.5,
        stage_compatibility=0.9,
        credential_feasibility=0.6,
        evidence_recency=0.9,
        relationship_confidence=0.8,
        uncertainty=0.1,
        directly_observed_edge_ids=[edge_id],
        explanation="test path",
    )
    protected_path = path.model_copy(
        update={
            "path_id": "protected-path",
            "target_entity_id": "asset:critical_db",
            "reaches_protected_asset": True,
        }
    )
    gnn_result = GNNInferenceResult(
        model_version="v1",
        feature_schema_version="v1",
        subgraph_id="sg",
        sample_id="sample",
        node_ids=["asset:entry_host", "asset:mid_server"],
        edge_ids=[edge_id],
        gnn_output=GNNOutput(
            node_embeddings=[[0.0] * 4, [0.0] * 4],
            graph_embedding=[0.0] * 4,
            node_risk_probabilities=[0.2, 0.3],
            edge_movement_probabilities=[0.95],
            graph_risk_probability=0.7,
            node_uncertainty=[0.0, 0.0],
            graph_uncertainty=0.0,
            embedding_dim=4,
            num_nodes=2,
            num_edges=1,
        ),
    )

    shadow_adapter = HybridPathRiskAdapter(operating_mode=GNNOperatingMode.GNN_SHADOW)
    shadow_path, shadow_risk = shadow_adapter.score_paths([path], subgraph, belief, ref, gnn_result)[0]
    assert shadow_path.risk_score == shadow_risk.heuristic_risk
    assert shadow_risk.gnn_weight == 0.0

    hybrid_adapter = HybridPathRiskAdapter(operating_mode=GNNOperatingMode.HYBRID_RECOMMENDATION)
    scored = hybrid_adapter.score_paths([path, protected_path], subgraph, belief, ref, gnn_result)
    normal_path, normal_risk = scored[0]
    constrained_path, constrained_risk = scored[1]

    assert normal_risk.gnn_weight > 0.0
    assert normal_path.risk_score == pytest.approx(normal_risk.hybrid_risk, abs=1e-6)
    assert constrained_risk.gnn_weight == 0.0
    assert constrained_path.risk_score == pytest.approx(
        constrained_risk.heuristic_risk,
        abs=1e-6,
    )
