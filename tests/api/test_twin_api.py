from __future__ import annotations

from fastapi.testclient import TestClient

from mirage.api.server import create_app


def test_twin_api_ingests_event_and_reports_status(monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())
    event = {
        "event_id": "evt-api-1",
        "event_time": "2026-06-17T08:00:00Z",
        "ingest_time": "2026-06-17T08:00:01Z",
        "source": "pytest",
        "event_type": "asset_discovered",
        "asset_id": "asset:host:api-ws",
        "confidence": 0.9,
        "attributes": {"hostname": "api-ws", "asset_type": "workstation"},
    }

    response = client.post("/api/v1/events", json=event)
    assert response.status_code == 200
    assert response.json()["assets_created"] == ["asset:host:api-ws"]

    status = client.get("/api/v1/twin/status")
    assert status.status_code == 200
    assert status.json()["asset_count"] == 1

    asset = client.get("/api/v1/twin/assets/asset:host:api-ws")
    assert asset.status_code == 200
    assert asset.json()["hostname"] == "api-ws"


def test_twin_api_batch_reports_malformed_event(monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/events/batch",
        json=[
            {
                "event_id": "evt-api-good",
                "event_time": "2026-06-17T08:00:00Z",
                "ingest_time": "2026-06-17T08:00:01Z",
                "source": "pytest",
                "event_type": "asset_discovered",
                "asset_id": "asset:host:good",
                "confidence": 0.9,
            },
            "not-an-object",
        ],
    )

    assert response.status_code == 200
    body = response.json()
    assert body["processed"] == 1
    assert body["failed"] == 1


def test_twin_replay_endpoint_and_dashboard_route(monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())

    replay = client.post(
        "/api/v1/twin/replay",
        json={
            "events": [
                {
                    "event_id": "evt-replay-api",
                    "event_time": "2026-06-17T08:00:00Z",
                    "ingest_time": "2026-06-17T08:00:01Z",
                    "source": "pytest",
                    "event_type": "deception_interaction",
                    "asset_id": "asset:decoy:api",
                    "confidence": 0.95,
                    "attributes": {
                        "hostname": "api-decoy",
                        "asset_type": "decoy_db",
                        "is_decoy": True,
                    },
                }
            ]
        },
    )
    assert replay.status_code == 200
    assert replay.json()["summary"]["final_twin_version"] == 1

    dashboard = client.get("/dashboard")
    assert dashboard.status_code == 200
