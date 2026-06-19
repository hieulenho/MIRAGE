from __future__ import annotations

from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.gnn.dataset import GraphDatasetBuilder
from mirage.gnn.scenarios import build_scenario


def test_gnn_api_health_encode_and_prediction_cache(monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())
    sample = GraphDatasetBuilder().build_sample(**build_scenario("benign_admin_activity"))

    health = client.get("/api/v1/gnn/health")
    encoded = client.post(
        "/api/v1/gnn/encode",
        json={"graph_sample": sample.model_dump(mode="json")},
    )
    cached = client.get(f"/api/v1/gnn/predictions/{sample.sample_id}")
    models = client.get("/api/v1/gnn/models")

    assert health.status_code == 200
    assert health.json()["status"] == "no_model"
    assert encoded.status_code == 200
    assert encoded.json()["fallback_recommended"] is True
    assert cached.status_code == 200
    assert cached.json()["sample_id"] == sample.sample_id
    assert models.status_code == 200


def test_gnn_api_evaluate_runs_baselines_without_optional_model_deps(tmp_path, monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    dataset_path = tmp_path / "dataset"
    GraphDatasetBuilder().build_dataset(
        [
            build_scenario("lateral_movement_to_critical_db"),
            build_scenario("overlapping_paths"),
            build_scenario("large_hierarchical_graph"),
        ],
        str(dataset_path),
    )
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/gnn/evaluate",
        json={"dataset_path": str(dataset_path)},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["sample_count"] == 3
    assert "heuristic_belief" in body["results"]
    assert body["results"]["heuristic_belief"]["edge_task"]["n_samples"] > 0
