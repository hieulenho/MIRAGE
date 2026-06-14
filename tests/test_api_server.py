from fastapi.testclient import TestClient

from mirage.api_server import create_app
from mirage.layer4_decision_engine import ActionPlan, RobustDecisionEngine
from mirage.mdp_solver import compute_composite_cost


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
