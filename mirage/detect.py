"""Deterministic contextual detection replay CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mirage.config import load_config, resolve_project_path
from mirage.detection.pipeline import ContextualDetectionPipeline
from mirage.domain.schemas import BeliefSnapshot
from mirage.ingestion.jsonl_source import JSONLEventSource
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.replay import load_snapshot, sort_events_for_replay


def save_belief_snapshot(snapshot: BeliefSnapshot, path: str | Path) -> Path:
    """Save a deterministic contextual-belief snapshot."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = snapshot.model_dump(mode="json")
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser for contextual detection replay."""
    parser = argparse.ArgumentParser(description="Replay MIRAGE contextual detection")
    parser.add_argument("--events", required=True, help="Path to JSONL events.")
    parser.add_argument(
        "--twin-snapshot",
        default=None,
        help="Optional TwinSnapshot JSON to seed Digital Twin state.",
    )
    parser.add_argument(
        "--belief-out",
        default="artifacts/belief_snapshot.json",
        help="Path to write BeliefSnapshot JSON.",
    )
    parser.add_argument(
        "--detections-out",
        default="artifacts/detections.jsonl",
        help="Path to write per-event DetectionPipelineResult JSONL.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail on first invalid JSONL event.",
    )
    parser.add_argument(
        "--preserve-file-order",
        action="store_true",
        help="Process JSONL order instead of event_time/event_id order.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print evidence explanations without raw command lines.",
    )
    return parser


def run_detection(args: argparse.Namespace) -> tuple[ContextualDetectionPipeline, int, Path]:
    """Run contextual detection and return pipeline plus invalid count."""
    config = load_config()
    twin_config = config.get("twin", {})
    twin = DigitalTwin(
        relationship_ttls=twin_config.get("relationship_ttls", {}),
        allow_provisional_entities=bool(
            twin_config.get("allow_provisional_entities", True)
        ),
    )
    if args.twin_snapshot:
        twin.load_snapshot(load_snapshot(resolve_project_path(args.twin_snapshot)))

    pipeline = ContextualDetectionPipeline(
        twin=twin,
        attack_graph=twin.export_attack_graph(),
        config=config.get("detection", {}),
    )
    source = JSONLEventSource(
        resolve_project_path(args.events),
        strict=args.strict,
    )
    events = sort_events_for_replay(
        list(source),
        preserve_file_order=args.preserve_file_order,
    )
    detections_path = resolve_project_path(args.detections_out)
    detections_path.parent.mkdir(parents=True, exist_ok=True)
    with detections_path.open("w", encoding="utf-8") as handle:
        for event in events:
            result = pipeline.process_event(event)
            handle.write(result.model_dump_json() + "\n")
            if args.verbose and result.evidence_ids:
                print(f"{event.event_id}: {', '.join(result.matched_rule_ids)}")
                for evidence_id in result.evidence_ids:
                    evidence = pipeline.belief_engine.evidence[evidence_id]
                    print(f"  - {evidence.rule_id}: {evidence.description}")
    return pipeline, len(source.errors), detections_path


def main(argv: list[str] | None = None) -> int:
    """Run contextual detection replay CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        pipeline, invalid_events, detections_path = run_detection(args)
    except (OSError, ValueError) as exc:
        print(f"Detection replay failed: {exc}")
        return 2

    snapshot = pipeline.belief_engine.create_snapshot()
    belief_path = save_belief_snapshot(
        snapshot,
        resolve_project_path(args.belief_out),
    )
    top = pipeline.belief_engine.get_top_suspected_entities(limit=1)
    suspicious = [
        belief
        for belief in pipeline.belief_engine.get_top_suspected_entities(limit=1000)
        if belief.compromise_probability
        >= pipeline.belief_engine.compromise_threshold
    ]
    deception_interactions = sum(
        1
        for item in pipeline.belief_engine.evidence.values()
        if item.rule_id == "R008_DECEPTION_INTERACTION"
    )
    print("MIRAGE contextual detection replay complete")
    print(f"  events processed:          {pipeline.timeline_store.event_count()}")
    print(f"  rule matches:              {sum(1 for e in pipeline.belief_engine.evidence.values() if e.rule_id and e.rule_id.startswith('R'))}")
    print(f"  correlations created:      {len(pipeline.belief_engine.correlations)}")
    print(f"  suspicious entities:       {len(suspicious)}")
    highest = f"{top[0].compromise_probability:.4f}" if top else "0.0000"
    stage = top[0].most_likely_stage if top else "normal"
    print(f"  highest compromise:       {highest}")
    print(f"  most likely stage:        {stage}")
    print(f"  deception interactions:    {deception_interactions}")
    print(f"  invalid events:            {invalid_events}")
    print(f"  final belief version:      {pipeline.belief_engine.version}")
    print(f"  belief snapshot saved:     {belief_path}")
    print(f"  detections saved:          {detections_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
