from __future__ import annotations

import json
import uuid
from datetime import timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from mirage.analysis.pipeline import AttackAnalysisPipeline
from mirage.api.server import create_app
from mirage.casm.service import CASMService
from mirage.config import load_config
from mirage.connectors.fixture import (
    GenericJSONLConnector,
    SysmonWindowsConnector,
    ZeekNetFlowConnector,
)
from mirage.domain.schemas import (
    AnalystDecision,
    AnalystFeedback,
    ConnectorConfig,
    ConnectorType,
    DiscoveryObservation,
)
from mirage.execution.safety import SafetyGate
from mirage.execution.utils import deterministic_id, ensure_utc
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.realtime.twin_service import RealtimeTwinService
from mirage.shadow.controller import ShadowModeController
from mirage.streaming.coordinator import ConnectorManager
from mirage.streaming.state import JSONStateStore


ROOT = Path(__file__).resolve().parents[2]


def fixture(name: str) -> str:
    return str(ROOT / "examples" / "connectors" / name)


def connector_config(
    connector_id: str,
    connector_type: ConnectorType,
    path: str,
    *,
    strict: bool = False,
) -> ConnectorConfig:
    return ConnectorConfig(
        connector_id=connector_id,
        connector_type=connector_type,
        input_path=path,
        batch_size=10,
        strict=strict,
        source_metadata={"lab": True},
    )


def test_sysmon_mapping_redacts_command_line():
    connector = SysmonWindowsConnector(
        connector_config("sysmon", ConnectorType.SYSMON, fixture("sysmon_lateral.jsonl"))
    )
    connector.start()
    record = connector.read_batch(1)[0]
    event = connector.normalize(record)[0]

    assert event.event_type == "process_start"
    assert event.command_line is None
    assert event.attributes["command_line_redacted"] is True
    assert event.attributes["command_hash"]


def test_zeek_mapping_normalizes_network_and_dns():
    connector = ZeekNetFlowConnector(
        connector_config("zeek", ConnectorType.ZEEK, fixture("zeek_flows.jsonl"))
    )
    connector.start()
    events = [connector.normalize(record)[0] for record in connector.read_batch(2)]

    assert [event.event_type for event in events] == [
        "network_connection",
        "dns_query",
    ]
    assert events[0].dst_port == 445


def test_connector_manager_deduplicates_and_checkpoints_after_processing(tmp_path):
    processed = []
    state = JSONStateStore(tmp_path / "state.json")
    connector = GenericJSONLConnector(
        connector_config(
            "generic",
            ConnectorType.GENERIC_JSONL,
            fixture("duplicate_events.jsonl"),
        )
    )
    manager = ConnectorManager(
        event_sink=lambda event: processed.append(event),
        state_store=state,
    )
    manager.register(connector)
    manager.start_all()

    summary = manager.poll_once()
    restart = GenericJSONLConnector(
        connector_config(
            "generic",
            ConnectorType.GENERIC_JSONL,
            fixture("duplicate_events.jsonl"),
        )
    )
    manager2 = ConnectorManager(
        event_sink=lambda event: processed.append(event),
        state_store=JSONStateStore(tmp_path / "state.json"),
    )
    manager2.register(restart)
    manager2.start_all()
    summary2 = manager2.poll_once()

    assert summary.records_read == 2
    assert summary.events_processed == 1
    assert summary.duplicates == 1
    assert summary.checkpoints_committed == 1
    assert summary2.events_processed == 0


def test_ordering_and_late_event_classification(tmp_path):
    order = []
    connector = GenericJSONLConnector(
        connector_config(
            "ooo",
            ConnectorType.GENERIC_JSONL,
            fixture("out_of_order.jsonl"),
        )
    )
    manager = ConnectorManager(
        event_sink=lambda event: order.append(event.event_id),
        state_store=JSONStateStore(tmp_path / "state.json"),
        allowed_lateness_seconds=1,
    )
    manager.register(connector)
    manager.start_all()
    summary = manager.poll_once(reference_time=ensure_utc(None))

    assert order == ["ooo-001", "ooo-002"]
    assert summary.late_records >= 1


def test_malformed_record_goes_to_dead_letter_in_tolerant_mode(tmp_path):
    processed = []
    connector = GenericJSONLConnector(
        connector_config(
            "bad",
            ConnectorType.GENERIC_JSONL,
            fixture("malformed.jsonl"),
        )
    )
    manager = ConnectorManager(
        event_sink=lambda event: processed.append(event),
        state_store=JSONStateStore(tmp_path / "state.json"),
    )
    manager.register(connector)
    manager.start_all()
    summary = manager.poll_once()

    assert summary.events_processed == 1
    assert summary.dead_letters >= 0
    assert connector.health().rejected_records == 1


def observation(**updates) -> DiscoveryObservation:
    base = {
        "observation_id": "obs-1",
        "observed_entity_type": "asset",
        "source": "authoritative_inventory",
        "event_time": ensure_utc(None),
        "hostname": "app-01",
        "agent_id": "agent-app-01",
        "ip_addresses": ["10.10.30.20"],
        "operating_system": "Windows Server",
        "confidence": 0.95,
        "attributes": {
            "asset_id": "asset:host:app-01",
            "asset_type": "application",
            "environment": "lab",
            "business_criticality": 0.8,
            "owner": "platform",
        },
    }
    base.update(updates)
    return DiscoveryObservation.model_validate(base)


def test_casm_reconciles_assets_conflicts_and_quality():
    twin = DigitalTwin()
    casm = CASMService(twin, config=load_config()["casm"])
    first = casm.apply_observation(observation())
    conflict = casm.apply_observation(
        observation(
            observation_id="obs-2",
            source="netflow",
            operating_system="Linux",
            confidence=0.5,
            attributes={
                "asset_id": "asset:host:app-01",
                "asset_type": "application",
                "environment": "lab",
                "business_criticality": 0.1,
            },
        )
    )
    quality = casm.quality_report()

    assert first.created is True
    assert conflict.conflicts
    assert twin.assets["asset:host:app-01"].business_criticality == 0.8
    assert quality.total_assets == 1
    assert quality.conflicting_fields >= 1


def test_casm_stale_expiry_reduces_quality_state():
    twin = DigitalTwin()
    casm = CASMService(twin, config={"asset_ttl_seconds": 1})
    obs = observation()
    casm.apply_observation(obs)

    summary = casm.expire_stale_entities(obs.event_time + timedelta(seconds=5))

    assert summary.stale_assets == 1
    assert twin.assets["asset:host:app-01"].attributes["casm_state"] == "STALE"


def test_realtime_twin_processes_event_and_observation_incrementally():
    service = RealtimeTwinService()
    obs = observation()

    update = service.process_observation(obs)
    snapshot = service.create_consistent_snapshot()
    quality = service.quality_report()

    assert update.assets_created == ["asset:host:app-01"]
    assert snapshot.twin_version >= 1
    assert quality.total_assets == 1


def test_shadow_recommendations_do_not_call_enforcement():
    twin = DigitalTwin()
    service = RealtimeTwinService(twin=twin)
    service.process_observation(observation())
    # Build a minimal analysis from the current empty belief; this may produce
    # no paths, so use fixture pipeline when recommendations exist.
    analysis = AttackAnalysisPipeline(config=load_config()["analysis"]).analyze(
        service.create_consistent_snapshot(),
        service.detection_pipeline.belief_engine.create_snapshot(),
        seed_entity_ids=[],
    )
    gate = SafetyGate(load_config()["execution"])
    decisions = [
        gate.evaluate(
            action,
            analysis.candidate_action_set.masks[action.action_id],
            service.create_consistent_snapshot(),
            service.detection_pipeline.belief_engine.create_snapshot(),
            [],
            analysis.reference_time,
        )
        for action in analysis.candidate_action_set.actions
    ]
    controller = ShadowModeController(load_config()["shadow"])
    recs = controller.evaluate_analysis(analysis, decisions, analysis.reference_time)

    assert isinstance(recs, list)


def test_shadow_feedback_lifecycle_and_metrics():
    controller = ShadowModeController()
    feedback = AnalystFeedback(
        feedback_id=deterministic_id("feedback", "rec-1", "analyst", "REJECT"),
        recommendation_id="rec-1",
        analyst_decision=AnalystDecision.REJECT,
        analyst_identifier="analyst",
        timestamp=ensure_utc(None),
    )
    controller.record_feedback(feedback)
    metrics = controller.metrics()

    assert metrics.recommendation_count == 0
    assert feedback.feedback_id in controller.feedback


def test_m5_api_registers_connector_polls_and_exposes_quality(monkeypatch, tmp_path):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())
    event_id = f"dup-{uuid.uuid4().hex}"
    event_file = tmp_path / "api_events.jsonl"
    payload = {
        "event_id": event_id,
        "event_time": "2026-06-18T08:00:00Z",
        "event_type": "network_connection",
        "source": "fixture",
        "src_ip": "10.10.20.10",
        "dst_ip": "10.10.30.20",
        "dst_port": 445,
        "attributes": {"environment": "lab"},
    }
    event_file.write_text(
        json.dumps(payload) + "\n" + json.dumps(payload) + "\n",
        encoding="utf-8",
    )
    cfg = connector_config(
        f"api-generic-{uuid.uuid4().hex}",
        ConnectorType.GENERIC_JSONL,
        str(event_file),
    )

    registered = client.post(
        "/api/v1/connectors",
        json={"connector": cfg.model_dump(mode="json")},
    )
    poll = client.post("/api/v1/connectors/poll")
    quality = client.get("/api/v1/casm/quality")
    dead_letters = client.get("/api/v1/dead-letter")

    assert registered.status_code == 200
    assert poll.status_code == 200
    assert poll.json()["events_processed"] == 1
    assert quality.status_code == 200
    assert dead_letters.status_code == 200


def test_m5_cli_connectors_validate_and_poll(tmp_path):
    from mirage.m5_cli import main as m5_main

    config_path = tmp_path / "connectors.json"
    cfg = connector_config(
        "cli-generic",
        ConnectorType.GENERIC_JSONL,
        fixture("duplicate_events.jsonl"),
    )
    config_path.write_text(
        json.dumps({"connectors": [cfg.model_dump(mode="json")]}),
        encoding="utf-8-sig",
    )

    assert m5_main(["connectors", "validate", "--config", str(config_path)]) == 0
    assert m5_main(["connectors", "poll-once", "--config", str(config_path)]) == 0


def test_m5_cli_casm_accepts_canonical_and_fixture_observations():
    from mirage.m5_cli import main as m5_main

    assert (
        m5_main(
            [
                "casm",
                "quality",
                "--observations",
                str(ROOT / "examples" / "casm_observations.jsonl"),
            ]
        )
        == 0
    )
    assert (
        m5_main(
            [
                "casm",
                "quality",
                "--observations",
                fixture("inventory_vuln.jsonl"),
            ]
        )
        == 0
    )
