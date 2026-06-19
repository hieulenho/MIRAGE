from __future__ import annotations

import json

from mirage.gnn.dataset import GraphDatasetBuilder
from mirage.gnn.hierarchy import HierarchicalGraphBuilder
from mirage.gnn.scenarios import SCENARIO_IDS, build_scenario
from mirage.gnn.schema import GraphFeatureSchema
from mirage.gnn.uncertainty import OODDetector


def test_feature_order_masks_and_sample_id_are_deterministic():
    schema = GraphFeatureSchema()
    entry = build_scenario("lateral_movement_to_critical_db")
    builder = GraphDatasetBuilder(schema=schema)

    sample_a = builder.build_sample(**entry)
    sample_b = builder.build_sample(**entry)

    assert sample_a.sample_id == sample_b.sample_id
    assert sample_a.model_dump(mode="json") == sample_b.model_dump(mode="json")
    assert schema.node_feature_names[0] == "entity_type_idx"
    assert schema.edge_feature_names[0] == "relationship_type_idx"
    assert len(sample_a.node_feature_matrix[0]) == schema.node_feature_dim
    assert len(sample_a.edge_feature_matrix[0]) == schema.edge_feature_dim
    assert len(sample_a.node_feature_mask) == sample_a.num_nodes
    assert len(sample_a.edge_feature_mask) == sample_a.num_edges
    assert all(isinstance(value, float) for row in sample_a.node_feature_matrix for value in row)


def test_dataset_serialization_and_split_manifest_prevent_scenario_leakage(tmp_path):
    sequence = [build_scenario(scenario_id) for scenario_id in SCENARIO_IDS]
    out_dir = tmp_path / "gnn_dataset"
    summary = GraphDatasetBuilder().build_dataset(sequence, str(out_dir))
    samples, manifest = GraphDatasetBuilder.load_dataset(str(out_dir))

    assert summary.total_samples == len(SCENARIO_IDS)
    assert summary.train_samples > 0
    assert summary.validation_samples > 0
    assert summary.test_samples > 0
    assert len(samples) == len(SCENARIO_IDS)
    assert all(node_id.startswith("node_") for sample in samples for node_id in sample.node_ids)
    assert all(edge_id.startswith("edge_") for sample in samples for edge_id in sample.edge_ids)

    assignments = manifest["split_manifest"]["scenario_assignments"]
    assert set(assignments) == set(SCENARIO_IDS)
    for sample in samples:
        assert assignments[sample.scenario_id] == sample.split.value

    manifest_payload = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_payload["summary"]["created_at"] == "2026-06-17T12:00:00Z"


def test_hierarchy_is_stable_and_has_no_dangling_aggregation_edges():
    entry = build_scenario("large_hierarchical_graph")
    subgraph = entry["local_subgraph"]
    twin = entry["twin_snapshot"]
    builder = HierarchicalGraphBuilder(twin_snapshot=twin, include_enterprise_node=True)

    hierarchy_a = builder.build(subgraph)
    hierarchy_b = builder.build(subgraph)

    assert hierarchy_a.hierarchy_mappings_dict() == hierarchy_b.hierarchy_mappings_dict()
    assert hierarchy_a.membership["subnet"]
    all_ids = set(hierarchy_a.all_node_ids)
    for edge in hierarchy_a.aggregation_edges:
        assert edge.source_node_id in all_ids
        assert edge.target_node_id in all_ids


def test_ood_detector_warns_on_unknown_types_and_low_coverage():
    entry = build_scenario("new_node_edge_type")
    sample = GraphDatasetBuilder().build_sample(**entry)
    stale = GraphDatasetBuilder().build_sample(**build_scenario("stale_incomplete_twin"))

    warnings = OODDetector().check_sample(sample)
    stale_warnings = OODDetector().check_sample(stale)

    assert any(w.warning_type == "unseen_node_type" for w in warnings)
    assert any(w.warning_type == "unseen_edge_type" for w in warnings)
    assert any(w.warning_type == "low_twin_coverage" for w in stale_warnings)
