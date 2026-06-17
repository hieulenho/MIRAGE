from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.config import load_config
from mirage.detect import main as detect_main
from mirage.detection.features import FeatureExtractor
from mirage.detection.pipeline import ContextualDetectionPipeline
from mirage.detection.timeline import TimelineStore
from mirage.domain.schemas import SecurityEvent
from mirage.ingestion.jsonl_source import JSONLEventSource
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.replay import sort_events_for_replay


ROOT = Path(__file__).resolve().parents[2]
BASE_TIME = datetime(2026, 6, 17, 8, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    event_type: str = "network_connection",
    *,
    seconds: int = 0,
    asset_id: str = "asset:host:ws-test",
    user_id: str = "identity:user:alice",
    src_ip: str = "10.10.1.10",
    dst_ip: str = "10.10.1.20",
    dst_port: int | None = 445,
    **extra,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        event_time=BASE_TIME + timedelta(seconds=seconds),
        ingest_time=BASE_TIME + timedelta(seconds=seconds + 1),
        source="pytest",
        event_type=event_type,
        asset_id=asset_id,
        user_id=user_id,
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_port=dst_port,
        confidence=float(extra.pop("confidence", 0.95)),
        process_name=extra.pop("process_name", None),
        command_line=extra.pop("command_line", None),
        credential_id=extra.pop("credential_id", None),
        technique_ids=list(extra.pop("technique_ids", [])),
        attributes=dict(extra.pop("attributes", {})),
    )


def load_scenario(name: str) -> list[SecurityEvent]:
    source = JSONLEventSource(ROOT / "examples" / "events" / name)
    return sort_events_for_replay(list(source))


def run_scenario(name: str) -> ContextualDetectionPipeline:
    config = load_config()
    twin = DigitalTwin(
        relationship_ttls=config["twin"]["relationship_ttls"],
        allow_provisional_entities=True,
    )
    pipeline = ContextualDetectionPipeline(
        twin=twin,
        config=config["detection"],
    )
    for event in load_scenario(name):
        pipeline.process_event(event)
    return pipeline


def test_timeline_dedup_ordering_retention_and_snapshot_restore():
    store = TimelineStore(retention_seconds=120)
    late = make_event("evt-late", seconds=60, dst_ip="10.10.1.21")
    early = make_event("evt-early", seconds=10, dst_ip="10.10.1.22")

    assert store.add_event(late).duplicate is False
    assert store.add_event(early).duplicate is False
    assert store.add_event(early).duplicate is True

    timeline = store.get_timeline("asset:host:ws-test")
    assert [event.event_id for event in timeline] == ["evt-early", "evt-late"]
    assert "identity:user:alice" in store.all_entity_ids()

    expired = store.remove_expired_events(BASE_TIME + timedelta(seconds=150))
    assert expired == 1

    snapshot = store.create_snapshot()
    restored = TimelineStore()
    restored.load_snapshot(snapshot)
    assert restored.get_timeline("asset:host:ws-test")[0].event_id == "evt-late"


def test_feature_extraction_is_explainable_and_omits_raw_command():
    store = TimelineStore()
    event = make_event(
        "evt-script",
        "process_start",
        dst_ip=None,
        dst_port=None,
        process_name="powershell.exe",
        command_line="powershell.exe -enc SECRET_TOKEN",
    )
    store.add_event(event)
    features = FeatureExtractor().extract(event, store)

    assert features["is_script_interpreter"].value is True
    assert features["contains_encoded_command"].value is True
    payload = json.dumps(
        {name: record.model_dump(mode="json") for name, record in features.items()}
    )
    assert "SECRET_TOKEN" not in payload
    assert features["contains_encoded_command"].source_event_ids == ["evt-script"]


def test_pipeline_detects_auth_spray_and_duplicate_does_not_inflate():
    pipeline = run_scenario("contextual_auth_spray.jsonl")
    top = pipeline.belief_engine.get_top_suspected_entities(limit=1)[0]
    before = top.compromise_probability
    duplicate = load_scenario("contextual_auth_spray.jsonl")[-1]
    result = pipeline.process_event(duplicate)
    after = pipeline.belief_engine.get_top_suspected_entities(limit=1)[0]

    assert result.duplicate is True
    assert after.compromise_probability == before
    assert any(
        item.rule_id == "R004_AUTH_SPRAY"
        for item in pipeline.belief_engine.evidence.values()
    )
    assert any(
        item.rule_id == "R005_SUCCESS_AFTER_FAILURES"
        for item in pipeline.belief_engine.evidence.values()
    )


def test_benign_admin_is_suppressed_but_deception_stays_high_confidence():
    benign = run_scenario("contextual_benign_admin.jsonl")
    benign_top = benign.belief_engine.get_top_suspected_entities(limit=1)[0]
    assert benign_top.compromise_probability < 0.85
    assert any(
        item.rule_id == "R010_BENIGN_ADMIN_SUPPRESSION"
        for item in benign.belief_engine.evidence.values()
    )

    deception = run_scenario("contextual_deception.jsonl")
    deception_top = deception.belief_engine.get_top_suspected_entities(limit=1)[0]
    assert deception_top.compromise_probability >= 0.85
    assert any(
        item.rule_id == "R008_DECEPTION_INTERACTION"
        for item in deception.belief_engine.evidence.values()
    )


def test_correlation_stage_and_graph_belief_metadata_are_deterministic():
    pipeline = run_scenario("contextual_discovery_lateral.jsonl")
    snapshot_one = pipeline.belief_engine.create_snapshot().model_dump_json()
    pipeline_two = run_scenario("contextual_discovery_lateral.jsonl")
    snapshot_two = pipeline_two.belief_engine.create_snapshot().model_dump_json()

    assert snapshot_one == snapshot_two
    assert pipeline.belief_engine.correlations
    top = pipeline.belief_engine.get_top_suspected_entities(limit=1)[0]
    assert top.most_likely_stage in {"lateral_movement", "collection", "discovery"}

    graph = pipeline.twin.export_attack_graph()
    graph.apply_belief_snapshot(pipeline.belief_engine.create_snapshot())
    matched_nodes = [
        metadata
        for metadata in graph.node_metadata.values()
        if metadata.get("compromise_probability", 0) > 0
    ]
    assert matched_nodes
    assert "direct_evidence_count" in matched_nodes[0]


def test_contextual_detection_api_endpoints(monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())
    event = make_event(
        "api-detect-1",
        "deception_interaction",
        asset_id="asset:decoy:api-db",
        user_id="identity:user:mallory",
        credential_id="honey-api-token",
        attributes={"hostname": "api-db", "asset_type": "decoy_db", "is_decoy": True},
    )

    response = client.post(
        "/api/v1/detection/events",
        json=event.model_dump(mode="json"),
    )
    assert response.status_code == 200
    assert "R008_DECEPTION_INTERACTION" in response.json()["matched_rule_ids"]

    entity = client.get("/api/v1/detection/entities/asset:decoy:api-db")
    assert entity.status_code == 200
    assert entity.json()["compromise_probability"] >= 0.85

    snapshot = client.get("/api/v1/belief/snapshot")
    assert snapshot.status_code == 200
    assert snapshot.json()["belief_version"] > 0


def test_detect_cli_writes_snapshot_and_detection_audit(tmp_path):
    belief_out = tmp_path / "belief.json"
    detections_out = tmp_path / "detections.jsonl"
    code = detect_main([
        "--events",
        str(ROOT / "examples" / "events" / "contextual_deception.jsonl"),
        "--belief-out",
        str(belief_out),
        "--detections-out",
        str(detections_out),
    ])

    assert code == 0
    assert belief_out.exists()
    assert detections_out.exists()
    payload = json.loads(belief_out.read_text(encoding="utf-8"))
    assert payload["attacker_location_distribution"]["unknown"] > 0
    assert "command_line" not in detections_out.read_text(encoding="utf-8")
