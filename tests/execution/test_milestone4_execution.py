from __future__ import annotations

import json
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.config import load_config
from mirage.domain.schemas import (
    ActionMask,
    ApprovalDecision,
    Asset,
    AttackStageName,
    BeliefSnapshot,
    CandidateDefenseAction,
    EntityBelief,
    ExecutionState,
    RiskTier,
    SafetyVerdict,
    TwinSnapshot,
)
from mirage.execution.adapters import MockLabState, build_default_adapters
from mirage.execution.audit import ImmutableAuditStore
from mirage.execution_cli import main as execution_cli_main
from mirage.execution.kill_switch import KillSwitch
from mirage.execution.orchestrator import DeceptionOrchestrator
from mirage.execution.safety import SafetyGate
from mirage.execution.state_machine import ExecutionStateMachine
from mirage.execution.utils import ensure_utc
from mirage.layer6_twin.digital_twin import DigitalTwin


def now():
    return ensure_utc(None)


def stage_distribution(stage: str) -> dict[str, float]:
    values = {item.value: 0.0 for item in AttackStageName}
    values[stage] = 1.0
    return values


def twin_snapshot(
    *,
    target: str = "asset:host:app-01",
    asset_type: str = "application",
    criticality: float = 0.3,
    freshness: float = 1.0,
    coverage: float = 1.0,
) -> TwinSnapshot:
    ts = now()
    return TwinSnapshot(
        twin_version=1,
        timestamp=ts,
        assets={
            target: Asset(
                asset_id=target,
                hostname=target.split(":")[-1],
                asset_type=asset_type,
                environment="lab",
                business_criticality=criticality,
                first_seen=ts,
                last_seen=ts,
                confidence=1.0,
            )
        },
        freshness_score=freshness,
        coverage_score=coverage,
    )


def belief_snapshot(
    *,
    target: str = "asset:host:app-01",
    stage: str = "discovery",
) -> BeliefSnapshot:
    ts = now()
    belief = EntityBelief(
        entity_id=target,
        entity_type="asset",
        compromise_probability=0.7,
        stage_distribution=stage_distribution(stage),
        most_likely_stage=stage,
        uncertainty=0.1,
        confidence=0.9,
        candidate_attacker_location_probability=0.6,
        last_updated=ts,
        belief_version=1,
    )
    return BeliefSnapshot(
        belief_version=1,
        timestamp=ts,
        entity_beliefs={target: belief},
    )


def action(
    action_type: str = "deploy_decoy_database",
    *,
    target: str = "asset:host:app-01",
    tier: str = RiskTier.LOW.value,
    confidence: float = 0.9,
    approval: bool = False,
    rollback: bool = True,
    ttl: int | None = 3600,
) -> CandidateDefenseAction:
    ts = now()
    return CandidateDefenseAction(
        action_id=f"action:{action_type}:{target}",
        action_type=action_type,
        target_entity_ids=[target],
        affected_path_ids=["path:1"],
        affected_edge_ids=[],
        expected_risk_reduction=0.5,
        expected_information_gain=0.7,
        operational_cost=0.2,
        business_risk=0.1,
        deployment_cost=0.5,
        confidence=confidence,
        uncertainty=0.1,
        risk_tier=tier,
        automation_level="human_approval_required" if approval else "automatic",
        requires_approval=approval,
        rollback_supported=rollback,
        rollback_plan="remove lab change" if rollback else None,
        ttl_seconds=ttl,
        preconditions=["validated target scope"],
        postconditions=["no production enforcement executed"],
        constraints=["candidate only"],
        reason="test candidate",
        generated_at=ts,
    )


def mask(candidate: CandidateDefenseAction, *, allowed=True, approval=False) -> ActionMask:
    return ActionMask(
        action_id=candidate.action_id,
        allowed=allowed,
        approval_required=approval,
        effective_risk_tier=candidate.risk_tier,
        mask_reasons=["masked"] if not allowed else [],
        required_conditions=["human approval"] if approval else [],
    )


def safety_gate(tmp_path, kill_switch=None):
    config = load_config()["execution"]
    audit = ImmutableAuditStore(tmp_path / "audit.jsonl")
    return SafetyGate(config, audit_store=audit, kill_switch=kill_switch)


def evaluate(candidate, tmp_path, *, twin=None, belief=None, action_mask=None):
    gate = safety_gate(tmp_path)
    twin = twin or twin_snapshot()
    belief = belief or belief_snapshot()
    return gate.evaluate(
        candidate,
        action_mask or mask(candidate),
        twin,
        belief,
        [],
        belief.timestamp,
    )


def test_safety_gate_allows_observe_and_monitors_decoy(tmp_path):
    observe = action("increase_endpoint_logging")
    decoy = action("deploy_decoy_database")

    observe_decision = evaluate(
        observe,
        tmp_path,
        belief=belief_snapshot(stage="execution"),
    )
    decoy_decision = evaluate(decoy, tmp_path)

    assert observe_decision.verdict == SafetyVerdict.ALLOW
    assert decoy_decision.verdict == SafetyVerdict.ALLOW_WITH_MONITORING


def test_safety_gate_denies_masked_and_protected_containment(tmp_path):
    masked = action("increase_endpoint_logging")
    containment = action(
        "isolate_host",
        tier=RiskTier.HIGH.value,
        confidence=0.99,
    )
    protected_twin = twin_snapshot(asset_type="database", criticality=0.95)

    masked_decision = evaluate(
        masked,
        tmp_path,
        action_mask=mask(masked, allowed=False),
    )
    protected_decision = evaluate(
        containment,
        tmp_path,
        twin=protected_twin,
        belief=belief_snapshot(stage="lateral_movement"),
    )

    assert masked_decision.verdict == SafetyVerdict.DENY
    assert "action_mask_blocked" in masked_decision.violated_policies
    assert protected_decision.verdict == SafetyVerdict.DENY
    assert "protected_asset_disruptive_action" in protected_decision.violated_policies


def test_stale_twin_converts_delay_action_to_approval(tmp_path):
    candidate = action(
        "throttle_edge",
        tier=RiskTier.MEDIUM.value,
        confidence=0.9,
    )
    stale_twin = twin_snapshot(freshness=0.1, coverage=0.1)

    decision = evaluate(
        candidate,
        tmp_path,
        twin=stale_twin,
        belief=belief_snapshot(stage="lateral_movement"),
    )

    assert decision.verdict == SafetyVerdict.REQUIRE_APPROVAL
    assert "stale_twin_requires_approval" in decision.required_approvals


def test_kill_switch_blocks_automation(tmp_path):
    audit = ImmutableAuditStore(tmp_path / "audit.jsonl")
    kill = KillSwitch(audit_store=audit)
    kill.enable(actor="soc", reason="drill")
    gate = SafetyGate(load_config()["execution"], audit_store=audit, kill_switch=kill)
    candidate = action("deploy_decoy_database")

    decision = gate.evaluate(
        candidate,
        mask(candidate),
        twin_snapshot(),
        belief_snapshot(),
        [],
        now(),
    )

    assert decision.verdict == SafetyVerdict.DENY
    assert "automation_kill_switch_enabled" in decision.violated_policies


def test_state_machine_rejects_invalid_transition():
    candidate = action()
    decision = SafetyGate(load_config()["execution"]).evaluate(
        candidate,
        mask(candidate),
        twin_snapshot(),
        belief_snapshot(),
        [],
        now(),
    )
    plan = DeceptionOrchestrator(config=load_config()["execution"]).build_plan(
        candidate,
        decision,
        twin_snapshot=twin_snapshot(),
        belief_snapshot=belief_snapshot(),
    )
    record = ExecutionStateMachine().create_record(plan)

    with pytest.raises(ValueError):
        ExecutionStateMachine().transition(
            record,
            ExecutionState.SUCCEEDED,
            "skip ahead",
        )


def build_orchestrator(tmp_path, *, lab_state=None, twin=None):
    audit = ImmutableAuditStore(tmp_path / "audit.jsonl")
    lab_state = lab_state or MockLabState()
    return DeceptionOrchestrator(
        config=load_config()["execution"],
        adapters=build_default_adapters(lab_state),
        lab_state=lab_state,
        audit_store=audit,
        twin=twin,
    )


def plan_for(candidate, orchestrator):
    decision = SafetyGate(load_config()["execution"]).evaluate(
        candidate,
        mask(candidate),
        twin_snapshot(),
        belief_snapshot(),
        [],
        now(),
    )
    return orchestrator.build_plan(
        candidate,
        decision,
        twin_snapshot=twin_snapshot(),
        belief_snapshot=belief_snapshot(),
    )


def test_orchestrator_executes_decoy_idempotently_and_updates_twin(tmp_path):
    twin = DigitalTwin()
    orchestrator = build_orchestrator(tmp_path, twin=twin)
    candidate = action("deploy_decoy_database")
    plan = plan_for(candidate, orchestrator)

    record = orchestrator.execute(plan)
    repeat = orchestrator.execute(plan)

    assert record.current_state == ExecutionState.SUCCEEDED
    assert repeat.execution_id == record.execution_id
    assert len([asset for asset in twin.assets.values() if asset.is_decoy]) == 1
    assert orchestrator.audit_store.events


def test_canary_failure_triggers_rollback(tmp_path):
    lab = MockLabState(decoy_can_reach_protected=True)
    orchestrator = build_orchestrator(tmp_path, lab_state=lab)
    plan = plan_for(action("deploy_decoy_database"), orchestrator)

    record = orchestrator.execute(plan)

    assert record.current_state == ExecutionState.ROLLED_BACK
    assert record.canary_result is not None
    assert record.canary_result.success is False
    assert record.rollback_result is not None
    assert record.rollback_result.success is True


def test_adapter_failure_triggers_rollback_and_rollback_failure_is_reported(tmp_path):
    lab = MockLabState(
        failure_injections={
            "docker_decoy.execute": "adapter_execute_failed",
            "docker_decoy.rollback": "rollback_failed",
        }
    )
    orchestrator = build_orchestrator(tmp_path, lab_state=lab)
    plan = plan_for(action("deploy_decoy_database"), orchestrator)

    record = orchestrator.execute(plan)

    assert record.current_state == ExecutionState.FAILED
    assert record.rollback_result is not None
    assert record.rollback_result.success is False
    assert record.failure_reason == "rollback_failed"


def test_ttl_expiration_rolls_back_and_marks_twin_inactive(tmp_path):
    twin = DigitalTwin()
    orchestrator = build_orchestrator(tmp_path, twin=twin)
    plan = plan_for(action("deploy_decoy_database", ttl=1), orchestrator)
    record = orchestrator.execute(plan)

    expired = orchestrator.expire_due_actions(
        reference_time=record.expires_at + timedelta(seconds=1)
    )

    assert expired[0].current_state == ExecutionState.ROLLED_BACK
    assert all(not asset.active for asset in twin.assets.values())


def test_approval_required_action_waits_and_expired_approval_cannot_bypass(tmp_path):
    orchestrator = build_orchestrator(tmp_path)
    candidate = action(
        "block_egress",
        tier=RiskTier.HIGH.value,
        confidence=0.8,
    )
    safety = SafetyGate(load_config()["execution"]).evaluate(
        candidate,
        mask(candidate),
        twin_snapshot(),
        belief_snapshot(stage="exfiltration"),
        [],
        now(),
    )
    plan = orchestrator.build_plan(
        candidate,
        safety,
        twin_snapshot=twin_snapshot(),
        belief_snapshot=belief_snapshot(stage="exfiltration"),
    )

    waiting = orchestrator.execute(plan)
    approval = orchestrator.approve(
        waiting.execution_id,
        approver="soc",
        decision=ApprovalDecision.APPROVED,
        ttl_seconds=1,
    )
    approval.expiry = approval.timestamp - timedelta(seconds=1)
    still_waiting = orchestrator.execute(plan)

    assert waiting.current_state == ExecutionState.AWAITING_APPROVAL
    assert still_waiting.current_state == ExecutionState.AWAITING_APPROVAL


def test_valid_approval_allows_execution(tmp_path):
    orchestrator = build_orchestrator(tmp_path)
    candidate = action(
        "block_egress",
        tier=RiskTier.HIGH.value,
        confidence=0.8,
    )
    safety = SafetyGate(load_config()["execution"]).evaluate(
        candidate,
        mask(candidate),
        twin_snapshot(),
        belief_snapshot(stage="exfiltration"),
        [],
        now(),
    )
    plan = orchestrator.build_plan(
        candidate,
        safety,
        twin_snapshot=twin_snapshot(),
        belief_snapshot=belief_snapshot(stage="exfiltration"),
    )

    waiting = orchestrator.execute(plan)
    orchestrator.approve(waiting.execution_id, approver="soc")
    record = orchestrator.execute(plan)

    assert record.current_state == ExecutionState.SUCCEEDED


def test_audit_sanitizes_sensitive_payload(tmp_path):
    audit = ImmutableAuditStore(tmp_path / "audit.jsonl")
    event = audit.append(
        "test",
        payload={
            "command_line": "powershell SECRET_TOKEN",
            "nested": {"api_key": "secret"},
        },
    )

    assert event.payload["command_line"] == "[redacted]"
    assert event.payload["nested"]["api_key"] == "[redacted]"
    assert "SECRET_TOKEN" not in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8"
    )


def test_api_safety_execution_and_kill_switch_endpoints(monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())
    candidate = action("increase_endpoint_logging")
    payload = {
        "action": candidate.model_dump(mode="json"),
        "mask": mask(candidate).model_dump(mode="json"),
    }

    client.post(
        "/api/v1/events",
        json={
            "event_id": "evt-api-m4",
            "event_time": now().isoformat(),
            "ingest_time": now().isoformat(),
            "source": "test",
            "event_type": "asset_discovered",
            "asset_id": "asset:host:app-01",
            "confidence": 1.0,
            "attributes": {
                "hostname": "app-01",
                "asset_type": "application",
                "environment": "lab",
            },
        },
    )
    safety = client.post("/api/v1/safety/evaluate", json=payload)
    prepared = client.post("/api/v1/executions/prepare", json=payload)

    assert safety.status_code == 200
    assert prepared.status_code == 200
    execution_id = prepared.json()["execution"]["execution_id"]
    executed = client.post(
        f"/api/v1/executions/{execution_id}/execute",
        json={"actor": "test"},
    )
    assert executed.status_code == 200
    assert client.get(f"/api/v1/executions/{execution_id}").status_code == 200
    assert client.get("/api/v1/executions").json()["executions"]
    assert client.get("/api/v1/audit").json()["events"]
    enabled = client.post(
        "/api/v1/kill-switch/enable",
        json={"actor": "test", "reason": "unit"},
    )
    assert enabled.status_code == 200
    assert client.get("/api/v1/kill-switch").json()["global_enabled"] is True


def test_execution_cli_safety_execute_status_and_kill_switch(tmp_path):
    candidate = action("increase_endpoint_logging")
    action_path = tmp_path / "action.json"
    twin_path = tmp_path / "twin.json"
    belief_path = tmp_path / "belief.json"
    audit_path = tmp_path / "audit.jsonl"
    state_path = tmp_path / "state.json"
    kill_path = tmp_path / "kill.json"
    action_path.write_text(
        json.dumps(candidate.model_dump(mode="json")),
        encoding="utf-8",
    )
    twin_path.write_text(
        json.dumps(twin_snapshot().model_dump(mode="json")),
        encoding="utf-8",
    )
    belief_path.write_text(
        json.dumps(belief_snapshot(stage="execution").model_dump(mode="json")),
        encoding="utf-8",
    )

    assert execution_cli_main([
        "safety-check",
        "--action",
        str(action_path),
        "--twin",
        str(twin_path),
        "--belief",
        str(belief_path),
    ]) == 0
    assert execution_cli_main([
        "execute-plan",
        "--action",
        str(action_path),
        "--twin",
        str(twin_path),
        "--belief",
        str(belief_path),
        "--audit-out",
        str(audit_path),
        "--state-out",
        str(state_path),
        "--lab",
    ]) == 0
    state = json.loads(state_path.read_text(encoding="utf-8"))
    execution_id = next(iter(state["records"]))
    assert execution_cli_main([
        "execution-status",
        "--execution-id",
        execution_id,
        "--state-path",
        str(state_path),
    ]) == 0
    assert execution_cli_main([
        "kill-switch",
        "enable",
        "--state-path",
        str(kill_path),
        "--actor",
        "test",
        "--reason",
        "unit",
    ]) == 0
    assert json.loads(kill_path.read_text(encoding="utf-8"))["global_enabled"] is True
