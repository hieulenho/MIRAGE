"""CLI commands for Milestone 4 safety and lab execution."""

from __future__ import annotations

import argparse
import json
from typing import Any

from mirage.config import load_config, resolve_project_path
from mirage.domain.schemas import (
    ActionMask,
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionPlan,
    ExecutionRecord,
    KillSwitchState,
    SafetyVerdict,
    TwinSnapshot,
)
from mirage.execution.audit import ImmutableAuditStore
from mirage.execution.kill_switch import KillSwitch
from mirage.execution.orchestrator import DeceptionOrchestrator
from mirage.execution.safety import SafetyGate
from mirage.execution.utils import ensure_utc


DEFAULT_STATE_PATH = "artifacts/execution_state.json"
DEFAULT_KILL_SWITCH_PATH = "artifacts/kill_switch.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MIRAGE Milestone 4 execution CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    safety = sub.add_parser("safety-check", help="Evaluate a candidate action")
    safety.add_argument("--action", required=True)
    safety.add_argument("--action-id")
    safety.add_argument("--mask")
    safety.add_argument("--twin", required=True)
    safety.add_argument("--belief", required=True)

    execute = sub.add_parser("execute-plan", help="Execute a lab-safe plan")
    execute.add_argument("--action", required=True)
    execute.add_argument("--action-id")
    execute.add_argument("--mask")
    execute.add_argument("--twin")
    execute.add_argument("--belief")
    execute.add_argument("--lab", action="store_true")
    execute.add_argument("--audit-out", default="artifacts/execution_audit.jsonl")
    execute.add_argument("--state-out", default=DEFAULT_STATE_PATH)

    status = sub.add_parser("execution-status", help="Show execution status")
    status.add_argument("--execution-id", required=True)
    status.add_argument("--state-path", default=DEFAULT_STATE_PATH)

    rollback = sub.add_parser("rollback", help="Rollback an execution")
    rollback.add_argument("--execution-id", required=True)
    rollback.add_argument("--state-path", default=DEFAULT_STATE_PATH)
    rollback.add_argument("--audit-out", default="artifacts/execution_audit.jsonl")

    kill = sub.add_parser("kill-switch", help="Manage automation kill switch")
    kill_sub = kill.add_subparsers(dest="kill_command", required=True)
    for name in ("status", "enable", "disable"):
        item = kill_sub.add_parser(name)
        item.add_argument("--state-path", default=DEFAULT_KILL_SWITCH_PATH)
        item.add_argument("--actor", default="cli")
        item.add_argument("--reason", default=name)
        item.add_argument("--action-type")
        item.add_argument("--environment")

    args = parser.parse_args(argv)
    if args.command == "safety-check":
        return _safety_check(args)
    if args.command == "execute-plan":
        return _execute_plan(args)
    if args.command == "execution-status":
        return _execution_status(args)
    if args.command == "rollback":
        return _rollback(args)
    if args.command == "kill-switch":
        return _kill_switch(args)
    return 2


def _safety_check(args) -> int:
    config = load_config()
    action, mask = _load_action_and_mask(args.action, args.action_id, args.mask)
    twin = _load_model(args.twin, TwinSnapshot)
    belief = _load_model(args.belief, BeliefSnapshot)
    gate = SafetyGate(config.get("execution", {}))
    decision = gate.evaluate(action, mask, twin, belief, [], belief.timestamp)
    _print_safety(decision.model_dump(mode="json"))
    return 0 if decision.verdict != SafetyVerdict.DENY else 1


def _execute_plan(args) -> int:
    config = load_config()
    action, mask = _load_action_and_mask(args.action, args.action_id, args.mask)
    twin = (
        _load_model(args.twin, TwinSnapshot)
        if args.twin
        else _synthetic_twin_for_action(action)
    )
    belief = (
        _load_model(args.belief, BeliefSnapshot)
        if args.belief
        else BeliefSnapshot(belief_version=0, timestamp=twin.timestamp)
    )
    audit = ImmutableAuditStore(resolve_project_path(args.audit_out))
    gate = SafetyGate(config.get("execution", {}), audit_store=audit)
    decision = gate.evaluate(action, mask, twin, belief, [], belief.timestamp)
    _print_safety(decision.model_dump(mode="json"))
    if decision.verdict == SafetyVerdict.DENY:
        print("Execution blocked by Safety Gate.")
        return 1

    orchestrator = DeceptionOrchestrator(
        config=config.get("execution", {}),
        audit_store=audit,
    )
    plan = orchestrator.build_plan(
        action,
        decision,
        twin_snapshot=twin,
        belief_snapshot=belief,
    )
    record = orchestrator.execute(plan, actor="cli")
    _save_execution_state(args.state_out, orchestrator)
    print(f"Plan ID:        {plan.plan_id}")
    print(f"Execution ID:   {record.execution_id}")
    print(f"State:          {record.current_state.value}")
    if record.canary_result:
        print(f"Canary:         {record.canary_result.success}")
    if record.health_check_results:
        print(
            "Verification:   "
            f"{all(check.success for check in record.health_check_results)}"
        )
    if record.rollback_result:
        print(f"Rollback:       {record.rollback_result.success}")
    return 0 if record.current_state.value in {"SUCCEEDED", "AWAITING_APPROVAL"} else 1


def _execution_status(args) -> int:
    state = _load_json(args.state_path)
    records = state.get("records", {})
    record = records.get(args.execution_id)
    if record is None:
        print(f"Execution not found: {args.execution_id}")
        return 1
    print(f"Execution ID: {record['execution_id']}")
    print(f"Plan ID:      {record['plan_id']}")
    print(f"State:        {record['current_state']}")
    print(f"Updated:      {record['updated_at']}")
    if record.get("failure_reason"):
        print(f"Failure:      {record['failure_reason']}")
    return 0


def _rollback(args) -> int:
    config = load_config()
    state = _load_json(args.state_path)
    audit = ImmutableAuditStore(resolve_project_path(args.audit_out))
    orchestrator = DeceptionOrchestrator(
        config=config.get("execution", {}),
        audit_store=audit,
    )
    orchestrator.plans = {
        plan_id: ExecutionPlan.model_validate(plan)
        for plan_id, plan in state.get("plans", {}).items()
    }
    orchestrator.records = {
        execution_id: ExecutionRecord.model_validate(record)
        for execution_id, record in state.get("records", {}).items()
    }
    if args.execution_id not in orchestrator.records:
        print(f"Execution not found: {args.execution_id}")
        return 1
    record = orchestrator.rollback(args.execution_id, reason="CLI rollback")
    _save_execution_state(args.state_path, orchestrator)
    print(f"Execution ID: {record.execution_id}")
    print(f"State:        {record.current_state.value}")
    print(f"Rollback:     {bool(record.rollback_result and record.rollback_result.success)}")
    return 0 if record.current_state.value == "ROLLED_BACK" else 1


def _kill_switch(args) -> int:
    state_path = resolve_project_path(args.state_path)
    kill = KillSwitch()
    if state_path.exists():
        kill.state = KillSwitchState.model_validate(_load_json(state_path))
    if args.kill_command == "enable":
        kill.enable(
            actor=args.actor,
            reason=args.reason,
            action_type=args.action_type,
            environment=args.environment,
        )
    elif args.kill_command == "disable":
        kill.disable(
            actor=args.actor,
            reason=args.reason,
            action_type=args.action_type,
            environment=args.environment,
        )
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(kill.state.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    print(json.dumps(kill.state.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


def _load_action_and_mask(
    action_path: str,
    action_id: str | None,
    mask_path: str | None,
) -> tuple[CandidateDefenseAction, ActionMask]:
    payload = _load_json(action_path)
    if "actions" in payload:
        actions = [
            CandidateDefenseAction.model_validate(item)
            for item in payload.get("actions", [])
        ]
        if not actions:
            raise ValueError("Action file contains no actions.")
        action = (
            next((item for item in actions if item.action_id == action_id), None)
            if action_id
            else actions[0]
        )
        if action is None:
            raise ValueError(f"Action ID not found: {action_id}")
        masks = payload.get("masks", {})
        raw_mask = masks.get(action.action_id)
        if raw_mask:
            return action, ActionMask.model_validate(raw_mask)
        return action, _default_mask(action)
    action = CandidateDefenseAction.model_validate(payload)
    if mask_path:
        return action, ActionMask.model_validate(_load_json(mask_path))
    return action, _default_mask(action)


def _default_mask(action: CandidateDefenseAction) -> ActionMask:
    return ActionMask(
        action_id=action.action_id,
        allowed=True,
        approval_required=action.requires_approval,
        effective_risk_tier=action.risk_tier,
        mask_reasons=["approval_required"] if action.requires_approval else [],
        required_conditions=["human approval"] if action.requires_approval else [],
    )


def _load_model(path: str, model):
    return model.model_validate(_load_json(path))


def _load_json(path: str) -> dict[str, Any]:
    return json.loads(resolve_project_path(path).read_text(encoding="utf-8"))


def _synthetic_twin_for_action(action: CandidateDefenseAction) -> TwinSnapshot:
    from mirage.domain.schemas import Asset

    now = ensure_utc(None)
    return TwinSnapshot(
        twin_version=0,
        timestamp=now,
        assets={
            target: Asset(
                asset_id=target,
                hostname=target.split(":")[-1],
                asset_type="lab_target",
                environment="lab",
                business_criticality=0.1,
                first_seen=now,
                last_seen=now,
            )
            for target in action.target_entity_ids
            if target.startswith("asset:")
        },
        coverage_score=1.0,
        freshness_score=1.0,
    )


def _save_execution_state(path: str, orchestrator: DeceptionOrchestrator) -> None:
    target = resolve_project_path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "plans": {
            plan_id: plan.model_dump(mode="json")
            for plan_id, plan in orchestrator.plans.items()
        },
        "records": {
            execution_id: record.model_dump(mode="json")
            for execution_id, record in orchestrator.records.items()
        },
        "approvals": {
            approval_id: approval.model_dump(mode="json")
            for approval_id, approval in orchestrator.approvals.items()
        },
    }
    target.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _print_safety(decision: dict[str, Any]) -> None:
    print(f"Safety verdict:       {decision['verdict']}")
    print(f"Risk tier:            {decision['risk_tier']}")
    print(f"Required approvals:   {', '.join(decision['required_approvals']) or 'none'}")
    print(f"Allowed scope:        {', '.join(decision['allowed_scope']) or 'none'}")
    if decision["violated_policies"]:
        print(f"Violated policies:    {', '.join(decision['violated_policies'])}")
    if decision["warnings"]:
        print(f"Warnings:             {', '.join(decision['warnings'])}")


if __name__ == "__main__":
    raise SystemExit(main())
