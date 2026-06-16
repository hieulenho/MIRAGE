import base64

import pytest

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from mirage.api_server import create_app
from mirage.layer4_decision_engine import ActionPlan, RobustDecisionEngine
from mirage.mdp_solver import compute_composite_cost


def test_dashboard_and_static_assets_are_served():
    client = TestClient(create_app())

    root = client.get("/")
    dashboard = client.get("/dashboard")
    script = client.get("/dashboard-static/app.js")
    stylesheet = client.get("/dashboard-static/style.css")

    assert root.json()["version"] == "2.0.0"
    assert dashboard.status_code == 200
    assert "default-src 'self'" in dashboard.headers[
        "content-security-policy"
    ]
    assert "/dashboard-static/app.js" in dashboard.text
    assert "/dashboard-static/style.css" in dashboard.text
    assert script.status_code == 200
    assert stylesheet.status_code == 200


def test_api_key_protects_rest_and_websocket(monkeypatch):
    monkeypatch.setenv("MIRAGE_API_KEY", "test-secret")
    client = TestClient(create_app())

    assert client.get("/api/graph").status_code == 401
    assert client.get(
        "/api/graph",
        headers={"X-API-Key": "test-secret"},
    ).status_code == 200

    with client.websocket_connect("/ws?api_key=test-secret") as websocket:
        initial = websocket.receive_json()
        assert initial["type"] == "init"
        assert len(initial["graph"]["nodes"]) > 0

    with pytest.raises(WebSocketDisconnect) as exc:
        with client.websocket_connect("/ws") as websocket:
            websocket.receive_json()
    assert exc.value.code == 4401


def test_api_key_websocket_subprotocol_avoids_query_secret(monkeypatch):
    monkeypatch.setenv("MIRAGE_API_KEY", "test-secret")
    client = TestClient(create_app())
    encoded = base64.urlsafe_b64encode(b"test-secret").decode().rstrip("=")

    with client.websocket_connect(
        "/ws",
        subprotocols=["mirage", f"mirage-key.{encoded}"],
    ) as websocket:
        assert websocket.accepted_subprotocol == "mirage"
        assert websocket.receive_json()["type"] == "init"


def test_api_ingests_generic_and_siem_events():
    client = TestClient(create_app())

    response = client.post("/api/telemetry", json={
        "source_host": "host-a",
        "dest_host": "server-a",
        "event_type": "port_scan",
        "port": 445,
    })
    assert response.status_code == 200
    assert response.json()["total_processed"] == 1

    response = client.post("/api/ingest/splunk", json={
        "time": 2.0,
        "host": "splunk-forwarder",
        "event": {
            "source_host": "host-b",
            "dest_host": "server-b",
            "action": "smb_connect",
        },
    })
    assert response.status_code == 200
    assert response.json()["processed"] == 1
    assert client.get("/api/status").json()["total_events_processed"] == 2


def test_api_rejects_invalid_siem_port_and_unknown_belief_node():
    client = TestClient(create_app())

    invalid_port = client.post("/api/ingest/wazuh", json={
        "data": {"srcip": "host-a", "dstip": "server-a", "dstport": "bad"},
        "event_type": "smb_connect",
    })
    invalid_belief = client.post("/api/decide", json={
        "belief_override": {"9999": 1.0},
        "deploy": False,
    })

    assert invalid_port.status_code == 422
    assert invalid_belief.status_code == 400


def test_api_rejects_declared_oversized_request():
    client = TestClient(create_app())

    response = client.post(
        "/api/telemetry",
        content=b"{}",
        headers={
            "content-type": "application/json",
            "content-length": "3000000",
        },
    )

    assert response.status_code == 413


def test_real_decision_pipeline_returns_a_plan_without_deployment():
    client = TestClient(create_app())

    response = client.post(
        "/api/decide",
        json={"deploy": False, "budget_remaining": 1.5},
    )

    assert response.status_code == 200
    assert response.json()["status"] in {
        "recommended",
        "approval_required",
        "noop",
    }


def test_decision_endpoint_safety_checks_and_deploys(monkeypatch):
    app = create_app()
    state = app.state.mirage_state
    action = next(
        candidate
        for candidate in state.fabric.action_catalog
        if candidate.action_type.value == "deploy_decoy_database"
        and candidate.target_node in state.graph.decoy_sites
    )
    cost = compute_composite_cost(action, state.graph).total
    plan = ActionPlan(
        action=action,
        target_node=action.target_node,
        target_node_label=state.graph.label(action.target_node),
        optimistic_value=0.5,
        pessimistic_value=0.2,
        expected_value=0.3,
        margin_guarantee=0.1,
        risk_score=action.risk_score,
        confidence=0.9,
        required_approval=False,
        reasoning="Test low-risk deployment",
        evidence=[],
        rollback_plan=action.rollback_plan,
        monitoring_metrics=[],
        portfolio=[action],
        portfolio_cost=cost,
    )

    monkeypatch.setattr(
        RobustDecisionEngine,
        "decide",
        lambda self, **kwargs: plan,
    )

    client = TestClient(app)
    response = client.post("/api/decide", json={"deploy": True})
    assert response.status_code == 200
    assert response.json()["status"] == "deployed"
    assert client.get("/api/decoys").json()["total"] == 1

    graph = client.get("/api/graph").json()
    deployed_node = next(node for node in graph["nodes"] if node["id"] == action.target_node)
    assert deployed_node["is_decoy"] is True


def test_pending_decision_can_be_approved(monkeypatch):
    app = create_app()
    state = app.state.mirage_state
    action = next(
        candidate
        for candidate in state.fabric.action_catalog
        if candidate.action_type.value == "increase_edge_cost"
        and candidate.target_node in state.graph.true_goals
    )
    cost = compute_composite_cost(action, state.graph).total
    plan = ActionPlan(
        action=action,
        target_node=action.target_node,
        target_node_label=state.graph.label(action.target_node),
        optimistic_value=0.5,
        pessimistic_value=0.2,
        expected_value=0.3,
        margin_guarantee=0.1,
        risk_score=action.risk_score,
        confidence=0.95,
        required_approval=True,
        reasoning="Protected-path test",
        evidence=[],
        rollback_plan=action.rollback_plan,
        monitoring_metrics=[],
        portfolio=[action],
        portfolio_cost=cost,
    )
    monkeypatch.setattr(
        RobustDecisionEngine,
        "decide",
        lambda self, **kwargs: plan,
    )

    client = TestClient(app)
    pending = client.post("/api/decide", json={"deploy": True}).json()
    assert pending["status"] == "pending_approval"
    assert state.safety_gate.budget_spent == 0

    approved = client.post(
        f"/api/decisions/{pending['decision_id']}/approve",
        json={"approved_by": "soc-analyst"},
    )
    assert approved.status_code == 200
    assert approved.json()["status"] == "deployed"
    assert state.safety_gate.budget_spent == cost
