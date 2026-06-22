"""CLI for governance registry and release gates."""

from __future__ import annotations

import argparse
import json
from typing import Any

from mirage.config import load_config, resolve_project_path
from mirage.governance.registry import GovernanceRegistry
from mirage.governance.schema import EvidenceBundle, GovernanceStatus


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _registry() -> GovernanceRegistry:
    config = load_config().get("governance", {})
    return GovernanceRegistry(str(resolve_project_path(config.get("registry_path", "models/governance_registry.json"))))


def cmd_artifacts(args) -> int:
    registry = _registry()
    _print_json({
        "summary": registry.summary(),
        "artifacts": [artifact.model_dump(mode="json") for artifact in registry.list_artifacts()],
    })
    return 0


def cmd_model_card(args) -> int:
    registry = _registry()
    card = registry.model_cards.get(args.artifact_id)
    if card is None:
        _print_json({"error": "model_card_not_found", "artifact_id": args.artifact_id})
        return 1
    _print_json(card.model_dump(mode="json"))
    return 0


def cmd_policy_card(args) -> int:
    registry = _registry()
    card = registry.policy_cards.get(args.artifact_id)
    if card is None:
        _print_json({"error": "policy_card_not_found", "artifact_id": args.artifact_id})
        return 1
    _print_json(card.model_dump(mode="json"))
    return 0


def cmd_release_check(args) -> int:
    from mirage.governance.release import ReleaseGate

    registry = _registry()
    artifact = registry.get_artifact(args.artifact_id)
    if artifact is None:
        _print_json({"error": "artifact_not_found", "artifact_id": args.artifact_id})
        return 1
    evidence = EvidenceBundle(
        test_results={"provided": args.tests_pass},
        model_card_complete=args.model_card_complete,
        policy_card_complete=args.policy_card_complete,
        formal_verification_passed=args.formal_verification_passed,
        masked_action_violations=args.masked_action_violations,
        hard_safety_violations=args.hard_safety_violations,
        approvals=args.approver,
        metrics={
            "worst_case_return": args.worst_case_return,
            "unseen_topology_return": args.unseen_topology_return,
            "calibration_error": args.calibration_error,
            "latency_ms": args.latency_ms,
        },
    )
    decision = ReleaseGate(load_config().get("governance", {}).get("release_gate_thresholds", {})).evaluate(
        artifact,
        evidence,
        GovernanceStatus(args.target_status),
    )
    registry.register_decision(decision)
    _print_json(decision.model_dump(mode="json"))
    return 0 if decision.governance_verdict.value == "APPROVED" else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage governance")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("artifacts")
    model = sub.add_parser("model-card")
    model.add_argument("--artifact-id", required=True)
    policy = sub.add_parser("policy-card")
    policy.add_argument("--artifact-id", required=True)
    release = sub.add_parser("release-check")
    release.add_argument("--artifact-id", required=True)
    release.add_argument("--target-status", default="PILOT_CANDIDATE")
    release.add_argument("--tests-pass", action="store_true")
    release.add_argument("--model-card-complete", action="store_true")
    release.add_argument("--policy-card-complete", action="store_true")
    release.add_argument("--formal-verification-passed", action="store_true")
    release.add_argument("--masked-action-violations", type=int, default=0)
    release.add_argument("--hard-safety-violations", type=int, default=0)
    release.add_argument("--approver", action="append", default=[])
    release.add_argument("--worst-case-return", type=float, default=0.0)
    release.add_argument("--unseen-topology-return", type=float, default=0.0)
    release.add_argument("--calibration-error", type=float, default=0.0)
    release.add_argument("--latency-ms", type=float, default=0.0)
    args = parser.parse_args(argv)
    if args.command == "artifacts":
        return cmd_artifacts(args)
    if args.command == "model-card":
        return cmd_model_card(args)
    if args.command == "policy-card":
        return cmd_policy_card(args)
    if args.command == "release-check":
        return cmd_release_check(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
