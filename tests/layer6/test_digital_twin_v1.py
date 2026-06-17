from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from mirage.domain.schemas import SecurityEvent, TwinSnapshot
from mirage.ingestion.jsonl_source import JSONLEventSource
from mirage.ingestion.normalizer import EventNormalizer
from mirage.layer2_graph_engine.attack_graph import (
    MIRAGEAttackGraph,
    build_enterprise_attack_graph,
)
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.replay import replay_jsonl


def _event(
    event_id: str,
    event_type: str,
    *,
    minutes: int = 0,
    **kwargs,
) -> SecurityEvent:
    event_time = datetime(2026, 6, 17, 8, minutes, tzinfo=timezone.utc)
    payload = {
        "event_id": event_id,
        "event_time": event_time,
        "ingest_time": event_time + timedelta(seconds=1),
        "source": "pytest",
        "event_type": event_type,
        "confidence": kwargs.pop("confidence", 0.9),
        "attributes": kwargs.pop("attributes", {}),
        **kwargs,
    }
    return SecurityEvent.model_validate(payload)


def test_security_event_requires_aware_timestamps():
    with pytest.raises(ValueError, match="timezone-aware"):
        SecurityEvent.model_validate(
            {
                "event_id": "bad",
                "event_time": datetime(2026, 6, 17, 8, 0),
                "ingest_time": datetime(2026, 6, 17, 8, 0),
                "source": "pytest",
                "event_type": "asset_discovered",
                "confidence": 0.5,
            }
        )


def test_jsonl_source_tolerant_and_strict_modes(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "evt-jsonl-1",
                        "event_time": "2026-06-17T08:00:00Z",
                        "ingest_time": "2026-06-17T08:00:01Z",
                        "source": "pytest",
                        "event_type": "asset_discovered",
                        "asset_id": "asset:host:a",
                        "confidence": 0.9,
                    }
                ),
                "{not-json}",
            ]
        ),
        encoding="utf-8",
    )

    tolerant = JSONLEventSource(path, strict=False)
    assert [event.event_id for event in tolerant] == ["evt-jsonl-1"]
    assert tolerant.errors[0].line_number == 2

    with pytest.raises(ValueError, match="Invalid event"):
        list(JSONLEventSource(path, strict=True))


def test_normalizer_maps_generic_events():
    event = EventNormalizer().normalize(
        {
            "id": "evt-normalized",
            "timestamp": "2026-06-17T08:00:00Z",
            "source": "unit",
            "type": "process_create",
            "process": "powershell.exe",
            "hostname": "ws-01",
            "confidence": 0.8,
        }
    )

    assert event.event_type == "process_start"
    assert event.process_name == "powershell.exe"
    assert event.attributes["hostname"] == "ws-01"


def test_twin_resolves_assets_identities_and_deduplicates_relationships():
    twin = DigitalTwin()
    login = _event(
        "evt-login",
        "authentication_success",
        asset_id="asset:host:ws-01",
        user_id="identity:corp:alice",
        attributes={"username": "alice", "domain": "corp", "hostname": "ws-01"},
    )

    first = twin.apply_event(login)
    duplicate = twin.apply_event(login)

    assert first.assets_created == ["asset:host:ws-01"]
    assert first.identities_created == ["identity:corp:alice"]
    assert first.relationships_created
    assert duplicate.duplicate is True
    assert len(twin.relationships) == 1


def test_ambiguous_ip_resolution_warns_without_merging():
    twin = DigitalTwin()
    t0 = datetime(2026, 6, 17, 8, 0, tzinfo=timezone.utc)
    for asset_id, hostname in (("asset:a", "a"), ("asset:b", "b")):
        twin.apply_event(
            _event(
                f"evt-{hostname}",
                "asset_discovered",
                asset_id=asset_id,
                src_ip="10.0.0.5",
                attributes={"hostname": hostname},
            )
        )
    result = twin.apply_event(
        _event(
            "evt-ambiguous",
            "network_connection",
            minutes=1,
            src_ip="10.0.0.5",
            dst_ip="10.0.0.9",
        )
    )

    assert "Ambiguous asset resolution" in " ".join(result.warnings)
    assert len(twin.assets) == 3
    assert twin.last_event_time >= t0


def test_relationship_expiry_and_graph_export_preserve_decoy_marker():
    twin = DigitalTwin(relationship_ttls={"connects_to": 1})
    twin.apply_event(
        _event(
            "evt-conn",
            "network_connection",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            attributes={"src_hostname": "ws", "dst_hostname": "db"},
        )
    )
    twin.apply_event(
        _event(
            "evt-decoy",
            "deception_interaction",
            minutes=1,
            asset_id="asset:decoy:db",
            dst_ip="10.0.0.99",
            attributes={
                "hostname": "fake-db",
                "asset_type": "decoy_db",
                "is_decoy": True,
            },
        )
    )

    assert any(not relationship.active for relationship in twin.relationships.values())
    source_asset = twin.get_asset("asset:host:fs")
    if source_asset is None:
        source_asset = twin.get_asset("asset:host:ws")
    assert source_asset is not None
    assert source_asset.is_decoy is False
    graph = twin.export_attack_graph()
    assert graph.decoy_sites
    assert all(graph.get_node_info(node).get("is_decoy") for node in graph.decoy_sites)
    assert all(
        "connects_to" != action
        for actions in graph.available_actions.values()
        for action in actions
    )


def test_snapshot_round_trip_and_deterministic_replay(tmp_path):
    sample = tmp_path / "sample.jsonl"
    sample.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event_id": "evt-b",
                        "event_time": "2026-06-17T08:02:00Z",
                        "ingest_time": "2026-06-17T08:02:01Z",
                        "source": "pytest",
                        "event_type": "authentication_success",
                        "asset_id": "asset:host:ws",
                        "user_id": "identity:corp:bob",
                        "confidence": 0.9,
                        "attributes": {"username": "bob", "domain": "corp"},
                    }
                ),
                json.dumps(
                    {
                        "event_id": "evt-a",
                        "event_time": "2026-06-17T08:01:00Z",
                        "ingest_time": "2026-06-17T08:01:01Z",
                        "source": "pytest",
                        "event_type": "asset_discovered",
                        "asset_id": "asset:host:ws",
                        "confidence": 0.9,
                    }
                ),
            ]
        ),
        encoding="utf-8",
    )

    first = replay_jsonl(sample, snapshot_out=tmp_path / "one.json")
    second = replay_jsonl(sample, snapshot_out=tmp_path / "two.json")

    assert first.snapshot_path.read_text() == second.snapshot_path.read_text()
    loaded = TwinSnapshot.model_validate_json(first.snapshot_path.read_text())
    twin = DigitalTwin()
    twin.load_snapshot(loaded)
    assert twin.create_snapshot().assets.keys() == first.snapshot.assets.keys()


def test_existing_static_graph_still_builds():
    graph = build_enterprise_attack_graph()
    assert graph.true_goals
    assert graph.decoy_sites


def test_attack_graph_classmethod_from_twin_snapshot():
    twin = DigitalTwin()
    twin.apply_event(
        _event(
            "evt-goal",
            "asset_discovered",
            asset_id="asset:db",
            attributes={
                "hostname": "db",
                "asset_type": "database",
                "business_criticality": 1.0,
            },
        )
    )
    graph = MIRAGEAttackGraph.from_twin_snapshot(twin.create_snapshot())
    assert graph.true_goals
