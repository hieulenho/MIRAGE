"""Milestone 5 CLI for connectors, CASM, realtime Twin, and Shadow Mode."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mirage.casm.service import CASMService
from mirage.config import load_config, resolve_project_path
from mirage.connectors.fixture import build_connector
from mirage.domain.schemas import (
    AnalystDecision,
    AnalystFeedback,
    ConnectorConfig,
    DiscoveryObservation,
)
from mirage.execution.utils import deterministic_id, ensure_utc
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.realtime.twin_service import RealtimeTwinService
from mirage.shadow.controller import ShadowModeController
from mirage.streaming.coordinator import ConnectorManager
from mirage.streaming.state import JSONStateStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="MIRAGE Milestone 5 CLI")
    sub = parser.add_subparsers(dest="area", required=True)

    connectors = sub.add_parser("connectors")
    connectors_sub = connectors.add_subparsers(dest="command", required=True)
    for name in ("list", "validate", "health", "poll-once", "run"):
        item = connectors_sub.add_parser(name)
        item.add_argument("--config", help="Optional connector config JSON")

    casm = sub.add_parser("casm")
    casm_sub = casm.add_subparsers(dest="command", required=True)
    for name in ("status", "conflicts", "quality", "expire-stale"):
        item = casm_sub.add_parser(name)
        item.add_argument("--observations", help="Discovery observations JSONL")

    shadow = sub.add_parser("shadow")
    shadow_sub = shadow.add_subparsers(dest="command", required=True)
    run = shadow_sub.add_parser("run-once")
    run.add_argument("--analysis", required=False)
    recs = shadow_sub.add_parser("recommendations")
    recs.add_argument("--state", default="artifacts/shadow_recommendations.json")
    feedback = shadow_sub.add_parser("feedback")
    feedback.add_argument("--recommendation-id", required=True)
    feedback.add_argument("--decision", required=True)
    feedback.add_argument("--analyst", default="cli")
    feedback.add_argument("--state", default="artifacts/shadow_feedback.json")

    twin = sub.add_parser("twin")
    twin_sub = twin.add_subparsers(dest="command", required=True)
    twin_sub.add_parser("realtime-status")
    snapshot = twin_sub.add_parser("snapshot")
    snapshot.add_argument("--out", required=True)

    args = parser.parse_args(argv)
    if args.area == "connectors":
        return _connectors(args)
    if args.area == "casm":
        return _casm(args)
    if args.area == "shadow":
        return _shadow(args)
    if args.area == "twin":
        return _twin(args)
    return 2


def _connector_configs(path: str | None = None) -> list[ConnectorConfig]:
    config = load_config()
    definitions = config.get("connectors", {}).get("definitions", [])
    if path:
        raw = json.loads(resolve_project_path(path).read_text(encoding="utf-8-sig"))
        definitions = raw.get("connectors", raw if isinstance(raw, list) else [])
    return [ConnectorConfig.model_validate(item) for item in definitions]


def _load_casm_observations(path: str) -> list[DiscoveryObservation]:
    """Load canonical observations or simple inventory/vulnerability JSONL records."""
    observations: list[DiscoveryObservation] = []
    source_path = resolve_project_path(path)
    for index, line in enumerate(source_path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip():
            continue
        raw = json.loads(line)
        if "observation_id" in raw and "observed_entity_type" in raw:
            observations.append(DiscoveryObservation.model_validate(raw))
            continue

        vulnerability_id = raw.get("vulnerability_id") or raw.get("cve")
        ip_address = raw.get("ip") or raw.get("src_ip") or raw.get("dst_ip")
        attributes = {
            key: value
            for key, value in raw.items()
            if key
            in {
                "asset_id",
                "asset_type",
                "business_criticality",
                "environment",
                "exploitability",
                "owner",
                "severity",
            }
            and value is not None
        }
        attributes["raw_record_id"] = raw.get("record_id") or raw.get("event_id") or str(index)
        observations.append(
            DiscoveryObservation(
                observation_id=str(
                    raw.get("observation_id")
                    or raw.get("record_id")
                    or raw.get("event_id")
                    or deterministic_id("casm-observation", str(source_path), str(index))
                ),
                observed_entity_type=str(raw.get("observed_entity_type") or "asset"),
                source=str(raw.get("source") or "fixture_inventory"),
                event_time=raw.get("event_time") or raw.get("timestamp") or ensure_utc(None),
                hostname=raw.get("hostname"),
                domain=raw.get("domain"),
                ip_addresses=[str(ip_address)] if ip_address else [],
                agent_id=raw.get("agent_id"),
                cloud_instance_id=raw.get("cloud_instance_id"),
                operating_system=raw.get("operating_system"),
                services=list(raw.get("services") or []),
                ports=list(raw.get("ports") or []),
                software=list(raw.get("software") or []),
                vulnerabilities=[str(vulnerability_id)] if vulnerability_id else [],
                subnet=raw.get("subnet"),
                confidence=float(raw.get("confidence", 0.5)),
                attributes=attributes,
            )
        )
    return observations


def _connectors(args) -> int:
    configs = _connector_configs(args.config)
    if args.command == "list":
        for cfg in configs:
            print(f"{cfg.connector_id}\t{cfg.connector_type.value}\tenabled={cfg.enabled}")
        if not configs:
            print("No connectors configured.")
        return 0
    connectors = [build_connector(cfg) for cfg in configs]
    if args.command == "validate":
        for connector in connectors:
            connector.validate_config()
            print(f"{connector.config.connector_id}: valid")
        return 0
    state = JSONStateStore(resolve_project_path("artifacts/connectors_state.json"))
    service = RealtimeTwinService()
    manager = ConnectorManager(
        event_sink=service.process_event,
        state_store=state,
        allowed_lateness_seconds=int(
            load_config()["connectors"]["allowed_lateness_seconds"]
        ),
    )
    for connector in connectors:
        manager.register(connector)
    if args.command in {"poll-once", "run"}:
        manager.start_all()
        summary = manager.poll_once()
        print(json.dumps(summary.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    if args.command == "health":
        for health in manager.health_summary():
            print(json.dumps(health.model_dump(mode="json"), sort_keys=True))
        return 0
    return 2


def _casm(args) -> int:
    twin = DigitalTwin()
    service = CASMService(twin, config=load_config().get("casm", {}))
    if args.observations:
        for observation in _load_casm_observations(args.observations):
            service.apply_observation(observation)
    if args.command == "status":
        print(json.dumps(twin.health(), indent=2, sort_keys=True))
    elif args.command == "conflicts":
        print(json.dumps([c.model_dump(mode="json") for c in service.find_conflicts()], indent=2, sort_keys=True))
    elif args.command == "quality":
        print(json.dumps(service.quality_report().model_dump(mode="json"), indent=2, sort_keys=True))
    elif args.command == "expire-stale":
        print(json.dumps(service.expire_stale_entities(ensure_utc(None)).model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


def _shadow(args) -> int:
    controller = ShadowModeController(load_config().get("shadow", {}))
    if args.command == "run-once":
        print("Shadow run-once requires an analysis result; use API after analysis for full workflow.")
        return 0
    if args.command == "recommendations":
        path = resolve_project_path(args.state)
        if path.exists():
            print(path.read_text(encoding="utf-8"))
        else:
            print("[]")
        return 0
    if args.command == "feedback":
        feedback = AnalystFeedback(
            feedback_id=deterministic_id(
                "feedback",
                args.recommendation_id,
                args.analyst,
                args.decision,
            ),
            recommendation_id=args.recommendation_id,
            analyst_decision=AnalystDecision(args.decision),
            analyst_identifier=args.analyst,
            timestamp=ensure_utc(None),
        )
        path = resolve_project_path(args.state)
        path.parent.mkdir(parents=True, exist_ok=True)
        existing = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
        existing.append(feedback.model_dump(mode="json"))
        path.write_text(json.dumps(existing, indent=2, sort_keys=True), encoding="utf-8")
        controller.record_feedback(feedback)
        print(json.dumps(feedback.model_dump(mode="json"), indent=2, sort_keys=True))
        return 0
    return 2


def _twin(args) -> int:
    service = RealtimeTwinService()
    if args.command == "realtime-status":
        print(json.dumps(service.twin.health(), indent=2, sort_keys=True))
        return 0
    if args.command == "snapshot":
        out = Path(resolve_project_path(args.out))
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(service.create_consistent_snapshot().model_dump(mode="json"), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        print(f"Snapshot saved: {out}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
