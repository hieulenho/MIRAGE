"""CLI for formal safety verification."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from mirage.config import load_config
from mirage.domain.schemas import (
    ActionMask,
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionPlan,
    SafetyDecision,
    SafetyVerdict,
    TwinSnapshot,
)
from mirage.execution.utils import ensure_utc


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _load_json(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def cmd_plan(args) -> int:
    from mirage.verification.schema import FormalVerificationContext
    from mirage.verification.verifier import FormalSafetyVerifier

    plan = ExecutionPlan.model_validate(_load_json(args.plan))
    twin = TwinSnapshot.model_validate(_load_json(args.twin))
    action = CandidateDefenseAction.model_validate(
        _load_json(args.action) if args.action else _action_from_plan(plan)
    )
    mask = ActionMask.model_validate(
        _load_json(args.mask) if args.mask else _mask_for_action(action, True)
    )
    safety = SafetyDecision.model_validate(
        _load_json(args.safety) if args.safety else _safety_for_action(action)
    )
    context = FormalVerificationContext(
        action=action,
        action_mask=mask,
        safety_decision=safety,
        execution_plan=plan,
        twin_snapshot=twin,
        belief_snapshot=BeliefSnapshot(belief_version=0, timestamp=twin.timestamp),
        pilot_scope={
            "enabled": True,
            "allowed_action_types": [action.action_type],
            "allowed_asset_ids": plan.allowed_scope or plan.targets,
            "maximum_affected_entities": args.max_affected,
            "excluded_protected_assets": args.protected_assets,
        },
        dependency_graph={target: [] for target in plan.allowed_scope or plan.targets},
    )
    report = FormalSafetyVerifier(config=load_config().get("verification", {})).verify(
        plan,
        context,
    )
    _print_json(report.model_dump(mode="json"))
    return 0 if report.overall_verdict.value.startswith("VERIFIED") else 1


def cmd_invariants(args) -> int:
    from mirage.verification.invariants import SafetySpecificationRegistry

    _print_json({
        "invariants": [
            invariant.model_dump(mode="json")
            for invariant in SafetySpecificationRegistry().list_invariants()
        ]
    })
    return 0


def cmd_audit_chain(args) -> int:
    from mirage.governance.audit import GovernanceAuditStore

    _print_json(GovernanceAuditStore(args.audit).verify_chain())
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage verify")
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--plan", required=True)
    plan.add_argument("--twin", required=True)
    plan.add_argument("--action")
    plan.add_argument("--mask")
    plan.add_argument("--safety")
    plan.add_argument("--max-affected", type=int, default=5)
    plan.add_argument("--protected-assets", nargs="*", default=[])
    sub.add_parser("invariants")
    audit = sub.add_parser("audit-chain")
    audit.add_argument("--audit", default="artifacts/governance_audit.jsonl")
    args = parser.parse_args(argv)
    if args.command == "plan":
        return cmd_plan(args)
    if args.command == "invariants":
        return cmd_invariants(args)
    if args.command == "audit-chain":
        return cmd_audit_chain(args)
    return 2


def _action_from_plan(plan: ExecutionPlan) -> dict[str, Any]:
    now = ensure_utc(plan.created_at)
    return {
        "action_id": plan.source_action_id,
        "action_type": plan.action_type,
        "target_entity_ids": plan.targets,
        "expected_risk_reduction": 0.1,
        "expected_information_gain": 0.1,
        "operational_cost": 0.1,
        "business_risk": 0.01,
        "deployment_cost": 0.1,
        "confidence": 0.9,
        "uncertainty": 0.1,
        "risk_tier": "low",
        "automation_level": "recommend_only",
        "requires_approval": bool(plan.required_approvals),
        "rollback_supported": bool(plan.rollback_steps),
        "rollback_plan": "CLI reconstructed rollback",
        "ttl_seconds": plan.ttl_seconds,
        "reason": "reconstructed for verification CLI",
        "generated_at": now.isoformat(),
    }


def _mask_for_action(action: CandidateDefenseAction, allowed: bool) -> dict[str, Any]:
    return {
        "action_id": action.action_id,
        "allowed": allowed,
        "mask_reasons": [] if allowed else ["cli_mask_block"],
        "required_conditions": [],
        "approval_required": action.requires_approval,
        "effective_risk_tier": action.risk_tier,
    }


def _safety_for_action(action: CandidateDefenseAction) -> dict[str, Any]:
    now = ensure_utc(None)
    return {
        "action_id": action.action_id,
        "verdict": SafetyVerdict.ALLOW.value,
        "risk_tier": action.risk_tier,
        "confidence": action.confidence,
        "business_risk": action.business_risk,
        "blast_radius_estimate": len(action.target_entity_ids),
        "twin_freshness": 1.0,
        "graph_coverage": 1.0,
        "maximum_ttl_seconds": action.ttl_seconds or 3600,
        "rollback_required": bool(action.rollback_plan),
        "policy_version": "safety-v1",
        "evaluated_at": now.isoformat(),
    }


if __name__ == "__main__":
    raise SystemExit(main())
