from __future__ import annotations

import pytest

from mirage.gnn.dataset import GraphDatasetBuilder
from mirage.gnn.scenarios import build_scenario
from mirage.gnn.schema import GraphFeatureSchema, SplitType


torch = pytest.importorskip("torch")


def test_gnn_forward_dimensions_and_probability_bounds():
    from mirage.gnn.encoder import GNNStateEncoder, sample_to_tensors

    sample = GraphDatasetBuilder().build_sample(**build_scenario("overlapping_paths"))
    tensors = sample_to_tensors(sample, schema=GraphFeatureSchema())
    model = GNNStateEncoder(
        node_feature_dim=GraphFeatureSchema().node_feature_dim,
        edge_feature_dim=GraphFeatureSchema().edge_feature_dim,
        hidden_dim=16,
        out_dim=8,
        n_layers=2,
        dropout=0.0,
    )
    model.eval()

    with torch.no_grad():
        output = model(**tensors)

    assert output.num_nodes == sample.num_nodes
    assert output.num_edges == sample.num_edges
    assert len(output.node_embeddings[0]) == 8
    assert len(output.edge_movement_probabilities) == sample.num_edges
    assert all(0.0 <= p <= 1.0 for p in output.node_risk_probabilities)
    assert 0.0 <= output.graph_risk_probability <= 1.0


def test_tiny_training_pipeline_saves_metadata(tmp_path):
    from mirage.gnn.training import GNNTrainer

    entries = [
        build_scenario("lateral_movement_to_critical_db"),
        build_scenario("decoy_interaction"),
        build_scenario("overlapping_paths"),
    ]
    samples = [
        GraphDatasetBuilder().build_sample(
            **entry,
            split=SplitType.TRAIN if idx < 2 else SplitType.VALIDATION,
        )
        for idx, entry in enumerate(entries)
    ]
    trainer = GNNTrainer(
        config={
            "seed": 7,
            "hidden_dim": 16,
            "out_dim": 8,
            "n_layers": 2,
            "dropout": 0.0,
            "epochs": 2,
            "early_stopping_patience": 2,
            "learning_rate": 0.001,
        },
        output_dir=str(tmp_path / "model"),
    )

    metadata = trainer.train(samples[:2], samples[2:], model_id="tiny")

    assert metadata.model_id == "tiny"
    assert metadata.status.value == "VALIDATED"
    assert (tmp_path / "model" / "best_model.pt").exists()
    assert metadata.training_config["class_weights"]["node_pos_weight"] > 0
