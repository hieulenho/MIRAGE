"""Deterministic Digital Twin replay service and CLI helpers."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from mirage.config import load_config, resolve_project_path
from mirage.domain.schemas import SecurityEvent, TwinSnapshot, TwinUpdateSummary
from mirage.ingestion.jsonl_source import JSONLEventSource
from mirage.layer2_graph_engine.graph_parser import save_graph_to_json
from mirage.layer6_twin.digital_twin import DigitalTwin


@dataclass(frozen=True)
class ReplayResult:
    """Result returned by deterministic replay."""

    summary: TwinUpdateSummary
    snapshot: TwinSnapshot
    invalid_events: int
    snapshot_path: Path | None = None
    graph_path: Path | None = None


def sort_events_for_replay(
    events: list[SecurityEvent],
    *,
    preserve_file_order: bool = False,
) -> list[SecurityEvent]:
    """Return events in deterministic replay order."""
    if preserve_file_order:
        return list(events)
    return sorted(events, key=lambda event: (event.event_time, event.event_id))


def save_snapshot(snapshot: TwinSnapshot, path: str | Path) -> Path:
    """Save snapshot with deterministic key ordering."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = snapshot.model_dump(mode="json")
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output


def load_snapshot(path: str | Path) -> TwinSnapshot:
    """Load a TwinSnapshot from JSON."""
    return TwinSnapshot.model_validate_json(Path(path).read_text(encoding="utf-8"))


def replay_jsonl(
    events_path: str | Path,
    *,
    snapshot_out: str | Path | None = None,
    graph_out: str | Path | None = None,
    strict: bool = False,
    preserve_file_order: bool = False,
    twin: DigitalTwin | None = None,
) -> ReplayResult:
    """Replay JSONL events into a Digital Twin and optionally save outputs."""
    config = load_config()
    twin_config = config.get("twin", {})
    source = JSONLEventSource(events_path, strict=strict)
    events = sort_events_for_replay(
        list(source),
        preserve_file_order=preserve_file_order,
    )
    runtime_twin = twin or DigitalTwin(
        relationship_ttls=twin_config.get("relationship_ttls", {}),
        allow_provisional_entities=bool(
            twin_config.get("allow_provisional_entities", True)
        ),
    )
    summary = runtime_twin.apply_events(events)
    summary.invalid_events = len(source.errors)
    runtime_twin.source_position = f"{Path(events_path)}:{source.last_line_number}"
    snapshot = runtime_twin.create_snapshot()

    snapshot_path = None
    if snapshot_out:
        snapshot_path = save_snapshot(snapshot, snapshot_out)

    graph_path = None
    if graph_out:
        graph = runtime_twin.export_attack_graph()
        graph_path = Path(graph_out)
        graph_path.parent.mkdir(parents=True, exist_ok=True)
        save_graph_to_json(graph, str(graph_path))

    return ReplayResult(
        summary=summary,
        snapshot=snapshot,
        invalid_events=len(source.errors),
        snapshot_path=snapshot_path,
        graph_path=graph_path,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the MIRAGE replay CLI parser."""
    parser = argparse.ArgumentParser(description="Replay MIRAGE JSONL events")
    parser.add_argument(
        "--events",
        required=True,
        help="Path to JSONL events.",
    )
    parser.add_argument(
        "--snapshot-out",
        default=load_config().get("twin", {}).get(
            "snapshot_path",
            "artifacts/twin_snapshot.json",
        ),
        help="Path to write deterministic TwinSnapshot JSON.",
    )
    parser.add_argument(
        "--graph-out",
        default=None,
        help="Optional path to export MIRAGE attack graph JSON.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on first invalid JSONL line.",
    )
    parser.add_argument(
        "--preserve-file-order",
        action="store_true",
        help="Replay JSONL file order instead of event_time/event_id order.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the replay CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = replay_jsonl(
            resolve_project_path(args.events),
            snapshot_out=resolve_project_path(args.snapshot_out),
            graph_out=resolve_project_path(args.graph_out)
            if args.graph_out
            else None,
            strict=args.strict,
            preserve_file_order=args.preserve_file_order,
        )
    except (OSError, ValueError) as exc:
        print(f"Replay failed: {exc}")
        return 2

    summary = result.summary
    print("MIRAGE Digital Twin replay complete")
    print(f"  events processed:          {summary.processed}")
    print(f"  invalid events:            {summary.invalid_events}")
    print(f"  assets created/updated:    {summary.assets_created}/{summary.assets_updated}")
    print(
        "  identities created/updated: "
        f"{summary.identities_created}/{summary.identities_updated}"
    )
    print(
        "  relationships created/updated: "
        f"{summary.relationships_created}/{summary.relationships_updated}"
    )
    print(f"  expired relationships:     {summary.expired_relationships}")
    print(f"  final twin version:        {summary.final_twin_version}")
    if result.snapshot_path:
        print(f"  snapshot saved:            {result.snapshot_path}")
    if result.graph_path:
        print(f"  graph exported:            {result.graph_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

