from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.config import DEFAULT_CONFIG, load_config
from mirage.domain.schemas import (
    ActionMask,
    ApprovalDecision,
    Asset,
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionPlan,
    Relationship,
    SafetyDecision,
    SafetyVerdict,
    TwinSnapshot,
)
from mirage.drift.monitor import DriftMonitor
from mirage.execution.utils import deterministic_id
from mirage.governance.audit import GovernanceAuditStore
from mirage.governance.integrity import sha256_json
from mirage.governance.policy import PolicyAsCodeEngine
from mirage.governance.release import ReleaseGate
from mirage.governance.schema import (
    ArtifactType,
    EvidenceBundle,
    GovernanceStatus,
    GovernedArtifact,
)
from mirage.pilot.canary import CanaryDecisionController
from mirage.pilot.monitor import RuntimeSafetyMonitor
from mirage.pilot.scenarios import build_m9_scenarios
from mirage.pilot.schema import CanaryOutcome, RuntimeMonitorStatus
from mirage.verification.schema import (
    FormalVerificationContext,
    FormalVerificationVerdict,
    VerificationResult,
)
from mirage.verification.solver import DeterministicConstraintSolverBackend
from mirage.verification.verifier import FormalSafetyVerifier


NOW = datetime(2026, 6, 22, tzinfo=timezone.utc)


def _action(
    action_type: str = "deploy_decoy_database",
    target: str = "asset:workstation-1",
    *,
    risk_tier: str = "low",
    requires_approval: bool = False,
    ttl: int | None = 900,
    rollback: bool = True,
) -> CandidateDefenseAction:
    return CandidateDefenseAction(
        action_id=f"action:{action_type}:{target}",
        action_type=action_type,
        target_entity_ids=[target],
        expected_risk_reduction=0.2,
        expected_information_gain=0.4,
        operational_cost=0.5,
        business_risk=0.05,
        deployment_cost=0.5,
        confidence=0.9,
        uncertainty=0.1,
        risk_tier=risk_tier,
        automation_level="recommend_only",
        requires_approval=requires_approval,
        rollback_supported=rollback,
        rollback_plan="remove synthetic pilot change" if rollback else None,
        ttl_seconds=ttl,
        reason="test action",
        generated_at=NOW,
    )


def _mask(action: CandidateDefenseAction, allowed: bool = True) -> ActionMask:
    return ActionMask(
        action_id=action.action_id,
        allowed=allowed,
        mask_reasons=[] if allowed else ["masked_by_test"],
        required_conditions=[],
        approval_required=action.requires_approval,
        effective_risk_tier=action.risk_tier,
    )


def _safety(action: CandidateDefenseAction) -> SafetyDecision:
    return SafetyDecision(
        action_id=action.action_id,
        verdict=SafetyVerdict.ALLOW,
        risk_tier=action.risk_tier,
        confidence=action.confidence,
        business_risk=action.business_risk,
        blast_radius_estimate=len(action.target_entity_ids),
        twin_freshness=1.0,
        graph_coverage=1.0,
        maximum_ttl_seconds=action.ttl_seconds or 900,
        rollback_required=bool(action.rollback_plan),
        policy_version="safety-v1",
        evaluated_at=NOW,
    )


def _plan(action: CandidateDefenseAction) -> ExecutionPlan:
    return ExecutionPlan(
        plan_id=deterministic_id("plan", action.action_id),
        source_action_id=action.action_id,
        action_type=action.action_type,
        targets=action.target_entity_ids,
        adapter_type="docker_decoy" if "decoy" in action.action_type else "mock_firewall",
        requested_scope=action.target_entity_ids,
        allowed_scope=action.target_entity_ids,
        parameters={},
        preconditions=["target exists"],
        canary_steps=["check"],
        execution_steps=["apply"],
        verification_checks=["verify rollback"],
        postconditions=["record evidence"],
        rollback_steps=["rollback"] if action.rollback_plan else [],
        ttl_seconds=action.ttl_seconds,
        timeout_seconds=300,
        retry_policy={"max_attempts": 1, "rollback_max_attempts": 2},
        idempotency_key=deterministic_id("idempotency", action.action_id),
        required_approvals=["soc_analyst"] if action.requires_approval else [],
        twin_version="1",
        graph_version="test-graph",
        belief_version="1",
        analysis_id="analysis:test",
        policy_version="safety-v1",
        created_at=NOW,
    )


def _twin(*, protected_target: bool = False, decoy_path: bool = False, stale: bool = False) -> TwinSnapshot:
    target = Asset(
        asset_id="asset:workstation-1",
        asset_type="workstation",
        environment="lab",
        business_criticality=0.2,
        first_seen=NOW,
        last_seen=NOW,
        confidence=1.0,
    )
    protected = Asset(
        asset_id="asset:prod-db",
        asset_type="database",
        environment="prod",
        business_criticality=0.95,
        first_seen=NOW,
        last_seen=NOW,
        confidence=1.0,
        attributes={"protected": True},
    )
    if protected_target:
        target = target.model_copy(
            update={
                "asset_id": "asset:prod-db",
                "asset_type": "database",
                "business_criticality": 0.95,
                "attributes": {"protected": True},
            }
        )
    relationships = {}
    if decoy_path:
        relationships["rel:decoy-app"] = Relationship(
            relationship_id="rel:decoy-app",
            source_entity_id="asset:decoy-db",
            target_entity_id="asset:app-1",
            relationship_type="connects_to",
            confidence=1.0,
            first_seen=NOW,
            last_seen=NOW,
            active=True,
        )
        relationships["rel:app-db"] = Relationship(
            relationship_id="rel:app-db",
            source_entity_id="asset:app-1",
            target_entity_id="asset:prod-db",
            relationship_type="connects_to",
            confidence=0.2 if stale else 1.0,
            first_seen=NOW,
            last_seen=NOW,
            active=True,
            attributes={"stale": stale},
        )
    return TwinSnapshot(
        twin_version=1,
        timestamp=NOW,
        assets={
            target.asset_id: target,
            "asset:prod-db": protected,
            "asset:decoy-db": Asset(
                asset_id="asset:decoy-db",
                asset_type="decoy",
                environment="lab",
                business_criticality=0.0,
                first_seen=NOW,
                last_seen=NOW,
                confidence=1.0,
                is_decoy=True,
            ),
        },
        relationships=relationships,
        coverage_score=1.0,
        freshness_score=1.0,
    )


def _context(
    action: CandidateDefenseAction,
    *,
    allowed: bool = True,
    protected_target: bool = False,
    approvals: list[dict] | None = None,
    pilot_scope: dict | None = None,
    decoy_path: bool = False,
    dependency_graph: dict[str, list[str]] | None = None,
    stale_twin: bool = False,
) -> FormalVerificationContext:
    twin = _twin(protected_target=protected_target, decoy_path=decoy_path, stale=stale_twin)
    if stale_twin:
        twin = twin.model_copy(update={"freshness_score": 0.1})
    plan = _plan(action)
    return FormalVerificationContext(
        action=action,
        action_mask=_mask(action, allowed),
        safety_decision=_safety(action),
        execution_plan=plan,
        twin_snapshot=twin,
        belief_snapshot=BeliefSnapshot(belief_version=1, timestamp=NOW),
        pilot_scope=pilot_scope
        or {
            "enabled": True,
            "allowed_action_types": [action.action_type],
            "allowed_asset_ids": plan.allowed_scope,
            "excluded_protected_assets": ["asset:prod-db"],
            "maximum_affected_entities": 5,
        },
        approvals=approvals or [],
        dependency_graph=dependency_graph or {target: [] for target in plan.allowed_scope},
    )


def test_m9_config_defaults_and_fail_closed_when_pilot_execution_lacks_scope(tmp_path):
    config = load_config()
    assert config["pilot"]["operating_mode"] == "controlled_pilot"
    assert config["pilot"]["pilot_execution_enabled"] is False
    assert config["pilot"]["high_risk_automation_enabled"] is False
    assert config["verification"]["formal_verification_required"] is True

    unsafe = deepcopy(DEFAULT_CONFIG)
    unsafe["pilot"]["pilot_execution_enabled"] = True
    unsafe["pilot"]["pilot_scopes"] = []
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(unsafe), encoding="utf-8")
    with pytest.raises(ValueError, match="explicit pilot scopes"):
        load_config(path)


def test_masked_action_is_rejected_even_with_approval():
    action = _action()
    approval = {"decision": ApprovalDecision.APPROVED.value, "plan_hash": _context(action).plan_hash, "valid": True}
    context = _context(action, allowed=False, approvals=[approval])
    report = FormalSafetyVerifier().verify(context.execution_plan, context)

    assert report.overall_verdict == FormalVerificationVerdict.REJECTED
    assert any(f.invariant_id == "INV-007" and f.result == VerificationResult.VIOLATED for f in report.findings)


def test_protected_asset_automatic_modification_rejected():
    action = _action(target="asset:prod-db")
    context = _context(action, protected_target=True)
    report = FormalSafetyVerifier().verify(context.execution_plan, context)

    assert report.overall_verdict == FormalVerificationVerdict.REJECTED
    assert any(f.invariant_id == "INV-001" for f in report.findings)


def test_decoy_to_protected_reachability_returns_counterexample():
    action = _action()
    context = _context(action, decoy_path=True)
    report = FormalSafetyVerifier().verify(context.execution_plan, context)
    finding = next(f for f in report.findings if f.invariant_id == "INV-003")

    assert finding.result == VerificationResult.VIOLATED
    assert finding.counterexample == ["asset:decoy-db", "asset:app-1", "asset:prod-db"]


def test_blast_radius_and_missing_rollback_block_execution():
    action = _action(action_type="throttle_edge", risk_tier="medium", rollback=False)
    context = _context(
        action,
        dependency_graph={"asset:workstation-1": ["svc:a", "svc:b", "svc:c"]},
        pilot_scope={
            "enabled": True,
            "allowed_action_types": [action.action_type],
            "allowed_asset_ids": ["asset:workstation-1"],
            "maximum_affected_entities": 1,
        },
    )
    report = FormalSafetyVerifier().verify(context.execution_plan, context)

    assert report.overall_verdict == FormalVerificationVerdict.REJECTED
    assert any(f.invariant_id == "INV-004" for f in report.findings)
    assert any(f.invariant_id == "INV-005" for f in report.findings)


def test_solver_timeout_returns_unknown_not_proven():
    result = DeterministicConstraintSolverBackend(timeout_ms=1).check(
        {"constraints": [{"name": "safe", "fact": "x", "op": "eq", "value": 1}]},
        {"force_timeout": True, "x": 1},
    )

    assert result.status == "UNKNOWN"
    assert result.timeout is True


def test_governance_release_gate_rejects_missing_evidence_and_red_policy_pilot():
    artifact = GovernedArtifact(
        artifact_id="red:test",
        artifact_type=ArtifactType.RED_POLICY,
        version="v1",
        artifact_hash=sha256_json({"red": "test"}),
    )

    decision = ReleaseGate().evaluate(
        artifact,
        EvidenceBundle(
            test_results={"all": True},
            model_card_complete=True,
            policy_card_complete=True,
            formal_verification_passed=True,
        ),
        GovernanceStatus.PILOT_CANDIDATE,
    )

    assert decision.governance_verdict.value == "REJECTED"
    assert "red_policy_not_pilot" in decision.missing_evidence


def test_policy_as_code_denies_by_default_and_mask_block():
    action = _action()
    context = _context(action, allowed=False)
    result = PolicyAsCodeEngine({}).evaluate(action, context.execution_plan, context)

    assert result.allowed is False
    assert "action_type_not_allowed_by_policy" in result.deny_reasons
    assert "action_mask_blocked" in result.deny_reasons


def test_canary_runtime_drift_and_audit_chain_behaviors():
    hold = CanaryDecisionController().evaluate(
        "pilot:1",
        {"latency_within_threshold": False, "expected_telemetry": True},
    )
    rollback = CanaryDecisionController().evaluate(
        "pilot:2",
        {"unexpected_scope_expansion": True, "expected_telemetry": True},
    )
    runtime = RuntimeSafetyMonitor().evaluate("pilot:1", {"latency_ms": 900.0})
    drift = DriftMonitor().evaluate(model={"uncertainty": 0.9})
    audit = GovernanceAuditStore()
    audit.append("policy_change", artifact_or_execution_id="policy:1", after_state={"v": 1})
    audit.records[0] = audit.records[0].model_copy(update={"reason": "tampered"})

    assert hold.outcome == CanaryOutcome.HOLD
    assert rollback.outcome == CanaryOutcome.ROLLBACK
    assert runtime.status == RuntimeMonitorStatus.ROLLBACK_REQUIRED
    assert drift.status.value == "CRITICAL"
    assert drift.pilot_suspended is True
    assert audit.verify_chain()["valid"] is False


def test_required_scenarios_are_declared():
    scenarios = build_m9_scenarios()

    assert len(scenarios) == 15
    assert {scenario["scenario_id"] for scenario in scenarios} >= {
        "m9_safe_decoy_pilot",
        "m9_audit_chain_tampering",
        "m9_critical_model_drift",
    }


def test_m9_api_health_and_read_only_surfaces():
    client = TestClient(create_app())

    invariants = client.get("/api/v1/verification/invariants")
    scopes = client.get("/api/v1/pilot/scopes")
    drift = client.get("/api/v1/drift/status")
    audit = client.get("/api/v1/governance/audit/verify")

    assert invariants.status_code == 200
    assert len(invariants.json()["invariants"]) >= 15
    assert scopes.status_code == 200
    assert drift.status_code == 200
    assert drift.json()["shadow_mode_preserved"] is True
    assert audit.status_code == 200


def test_m9_cli_invariants_and_pilot_scopes(capsys):
    from mirage.pilot.cli import main as pilot_main
    from mirage.verification.cli import main as verify_main

    assert verify_main(["invariants"]) == 0
    assert pilot_main(["scopes"]) == 0

    output = capsys.readouterr().out
    assert "INV-001" in output
    assert "lab-low-risk" in output
