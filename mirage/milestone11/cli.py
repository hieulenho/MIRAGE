"""Command-line interface for Milestone 11."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from mirage.config import load_config
from mirage.milestone11.assurance import ContinuousAssuranceService
from mirage.milestone11.federation import FederationService
from mirage.milestone11.inventory import InventoryScanner, write_inventory_artifacts
from mirage.milestone11.readiness import OperationalMaturityService
from mirage.milestone11.schema import (
    FederationRouteValidationRequest,
    ReadinessEvaluationRequest,
)
from mirage.milestone11.validation import ValidationService


def main(argv: list[str] | None = None) -> int:
    """Run Milestone 11 commands."""
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config()
    area = args.area
    if area == "inventory":
        return _inventory(args)
    if area == "sites":
        return _sites(args, config)
    if area == "federation":
        return _federation(args, config)
    if area == "assurance":
        return _assurance(args, config)
    if area == "validation":
        return _validation(args, config)
    if area in {"slo", "capacity", "maturity", "readiness"}:
        return _operations(args, config)
    parser.error(f"unknown area: {area}")
    return 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m mirage", description="MIRAGE Milestone 11 commands")
    sub = parser.add_subparsers(dest="area", required=True)
    _add_inventory(sub.add_parser("inventory"))
    _add_sites(sub.add_parser("sites"))
    _add_federation(sub.add_parser("federation"))
    _add_assurance(sub.add_parser("assurance"))
    _add_validation(sub.add_parser("validation"))
    _add_slo(sub.add_parser("slo"))
    _add_capacity(sub.add_parser("capacity"))
    _add_maturity(sub.add_parser("maturity"))
    _add_readiness(sub.add_parser("readiness"))
    return parser


def _add_inventory(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scan")
    sub.add_parser("status")
    sub.add_parser("gaps")
    export = sub.add_parser("export")
    export.add_argument("--format", choices=["json", "yaml"], default="json")
    export.add_argument("--output", default="")


def _add_sites(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("list")
    health = sub.add_parser("health")
    health.add_argument("--site-id", default="")
    validate = sub.add_parser("validate")
    validate.add_argument("--site-id", required=True)


def _add_federation(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("policies")
    transfer = sub.add_parser("validate-transfer")
    transfer.add_argument("--source-site", required=True)
    transfer.add_argument("--destination-site", required=True)
    transfer.add_argument("--data-class", required=True)
    transfer.add_argument("--tenant-id", default="default")


def _add_assurance(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run")
    sub.add_parser("bundles")
    verify = sub.add_parser("verify-bundle")
    verify.add_argument("--bundle-id", required=True)
    sub.add_parser("checks")
    sub.add_parser("status")


def _add_validation(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    soak = sub.add_parser("soak")
    soak.add_argument("--duration", default="5m")
    soak.add_argument("--profile", default="ci")
    chaos = sub.add_parser("chaos")
    chaos.add_argument("--experiment", required=True)
    chaos.add_argument("--environment", default="staging")


def _add_slo(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    sub.add_parser("error-budget")


def _add_capacity(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("report")


def _add_maturity(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("assess")


def _add_readiness(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--target-deployment-level", default="SHADOW_ONLY")
    sub.add_parser("latest")


def _inventory(args: argparse.Namespace) -> int:
    if args.command == "scan":
        inventory = write_inventory_artifacts()
        return _print(
            {
                "generated": True,
                "capability_count": inventory.totals.capability_count,
                "status_counts": inventory.totals.by_status,
                "artifacts": [
                    "artifacts/inventory/system_inventory.json",
                    "artifacts/inventory/system_inventory.yaml",
                    "docs/inventory/",
                    "docs/milestone-11/",
                ],
            }
        )
    inventory = InventoryScanner().scan()
    if args.command == "status":
        return _print(
            {
                "verified_capabilities": inventory.totals.by_status.get("IMPLEMENTED", 0),
                "partial_and_broken_capabilities": sum(
                    inventory.totals.by_status.get(status, 0)
                    for status in ("PARTIAL", "BROKEN", "STUB", "MOCK_ONLY")
                ),
                "status_counts": inventory.totals.by_status,
                "failed_tests": "not executed by inventory status command",
            }
        )
    if args.command == "gaps":
        return _print({"gaps": inventory.known_gaps})
    if args.command == "export":
        data = inventory.model_dump(mode="json")
        text = json.dumps(data, indent=2, sort_keys=True)
        if args.format == "yaml":
            from mirage.milestone11.inventory import to_yaml

            text = to_yaml(data)
        if args.output:
            Path(args.output).write_text(text, encoding="utf-8")
            return _print({"exported": args.output, "format": args.format})
        print(text)
        return 0
    return 2


def _sites(args: argparse.Namespace, config: dict[str, Any]) -> int:
    service = FederationService(config)
    if args.command == "list":
        return _print(service.list_sites())
    if args.command == "health":
        site_id = args.site_id or service.registry.local_site_id
        return _print(service.site_health(site_id))
    if args.command == "validate":
        return _print(service.validate_site(args.site_id))
    return 2


def _federation(args: argparse.Namespace, config: dict[str, Any]) -> int:
    service = FederationService(config)
    if args.command == "status":
        return _print(service.federation_status())
    if args.command == "policies":
        return _print(service.policies())
    if args.command == "validate-transfer":
        route = FederationRouteValidationRequest(
            source_site_id=args.source_site,
            destination_site_id=args.destination_site,
            data_class=args.data_class,
            tenant_id=args.tenant_id,
        )
        return _print(service.validate_route(route))
    return 2


def _assurance(args: argparse.Namespace, config: dict[str, Any]) -> int:
    service = ContinuousAssuranceService(config)
    if args.command == "run":
        return _print(service.run().model_dump(mode="json"))
    if args.command == "bundles":
        return _print({"bundles": service.list_bundles()})
    if args.command == "verify-bundle":
        return _print(service.verify_bundle(args.bundle_id))
    if args.command == "checks":
        return _print({"checks": service.checks()})
    if args.command == "status":
        return _print(service.status())
    return 2


def _validation(args: argparse.Namespace, config: dict[str, Any]) -> int:
    service = ValidationService(config)
    if args.command == "soak":
        return _print(service.run_soak(duration=args.duration, profile=args.profile).model_dump(mode="json"))
    if args.command == "chaos":
        return _print(service.run_chaos(experiment=args.experiment, environment=args.environment).model_dump(mode="json"))
    return 2


def _operations(args: argparse.Namespace, config: dict[str, Any]) -> int:
    service = OperationalMaturityService(config)
    if args.area == "slo" and args.command == "status":
        return _print(service.slo.report().model_dump(mode="json"))
    if args.area == "slo" and args.command == "error-budget":
        service.slo.report()
        return _print(service.slo.error_budgets())
    if args.area == "capacity" and args.command == "report":
        return _print(service.capacity.report().model_dump(mode="json"))
    if args.area == "maturity" and args.command == "assess":
        return _print(service.maturity.assess().model_dump(mode="json"))
    if args.area == "readiness" and args.command == "evaluate":
        request = ReadinessEvaluationRequest(target_deployment_level=args.target_deployment_level)
        return _print(service.readiness.evaluate(request).model_dump(mode="json"))
    if args.area == "readiness" and args.command == "latest":
        latest = service.readiness.latest()
        return _print(latest.model_dump(mode="json") if latest else {"latest": None})
    return 2


def _print(payload: dict[str, Any]) -> int:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0
