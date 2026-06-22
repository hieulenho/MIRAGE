"""CLI for controlled pilot workflows."""

from __future__ import annotations

import argparse
import json
from typing import Any

from mirage.pilot.canary import CanaryDecisionController
from mirage.pilot.monitor import RuntimeSafetyMonitor
from mirage.pilot.scope import PilotScopeRegistry


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def cmd_scopes(args) -> int:
    registry = PilotScopeRegistry()
    _print_json({"scopes": [scope.model_dump(mode="json") for scope in registry.list_scopes()]})
    return 0


def cmd_prepare(args) -> int:
    scope = PilotScopeRegistry().get(args.scope_id)
    if scope is None:
        _print_json({"error": "scope_not_found", "scope_id": args.scope_id})
        return 1
    _print_json({
        "recommendation_id": args.recommendation_id,
        "pilot_scope": scope.model_dump(mode="json"),
        "status": "shadow_preparation_only",
        "note": "CLI prepare requires a serialized recommendation for execution-plan construction.",
    })
    return 0


def cmd_approve(args) -> int:
    _print_json({
        "execution_id": args.execution_id,
        "status": "approval_record_cli_stub",
        "approver": args.approver,
        "role": args.role,
        "note": "API/controller approval binds to exact plan hash.",
    })
    return 0


def cmd_canary(args) -> int:
    checks = {
        "target_adapter_healthy": True,
        "management_channel_healthy": not args.management_loss,
        "rollback_channel_healthy": True,
        "business_service_healthy": not args.business_unhealthy,
        "latency_within_threshold": not args.latency_violation,
        "error_rate_within_threshold": True,
        "expected_telemetry": True,
        "unexpected_scope_expansion": args.scope_expansion,
        "protected_dependency_impact": args.protected_impact,
        "twin_graph_consistent": True,
    }
    _print_json(CanaryDecisionController().evaluate(args.execution_id, checks).model_dump(mode="json"))
    return 0


def cmd_monitor(args) -> int:
    result = RuntimeSafetyMonitor().evaluate(
        args.execution_id,
        {
            "availability": args.availability,
            "latency_ms": args.latency_ms,
            "error_rate": args.error_rate,
            "health_success": args.health_success,
        },
        kill_switch_active=args.kill_switch,
        scope_expanded=args.scope_expansion,
    )
    _print_json(result.model_dump(mode="json"))
    return 0


def cmd_rollback(args) -> int:
    _print_json({"execution_id": args.execution_id, "rollback_status": "requested", "reason": args.reason})
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage pilot")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scopes")
    prep = sub.add_parser("prepare")
    prep.add_argument("--recommendation-id", required=True)
    prep.add_argument("--scope-id", default="lab-low-risk")
    approve = sub.add_parser("approve")
    approve.add_argument("--execution-id", required=True)
    approve.add_argument("--approver", default="soc-analyst")
    approve.add_argument("--role", default="soc_analyst")
    canary = sub.add_parser("canary")
    canary.add_argument("--execution-id", required=True)
    canary.add_argument("--management-loss", action="store_true")
    canary.add_argument("--business-unhealthy", action="store_true")
    canary.add_argument("--latency-violation", action="store_true")
    canary.add_argument("--scope-expansion", action="store_true")
    canary.add_argument("--protected-impact", action="store_true")
    monitor = sub.add_parser("monitor")
    monitor.add_argument("--execution-id", required=True)
    monitor.add_argument("--availability", type=float, default=1.0)
    monitor.add_argument("--latency-ms", type=float, default=100.0)
    monitor.add_argument("--error-rate", type=float, default=0.0)
    monitor.add_argument("--health-success", type=float, default=1.0)
    monitor.add_argument("--kill-switch", action="store_true")
    monitor.add_argument("--scope-expansion", action="store_true")
    rollback = sub.add_parser("rollback")
    rollback.add_argument("--execution-id", required=True)
    rollback.add_argument("--reason", required=True)
    args = parser.parse_args(argv)
    return {
        "scopes": cmd_scopes,
        "prepare": cmd_prepare,
        "approve": cmd_approve,
        "canary": cmd_canary,
        "monitor": cmd_monitor,
        "rollback": cmd_rollback,
    }[args.command](args)


if __name__ == "__main__":
    raise SystemExit(main())
