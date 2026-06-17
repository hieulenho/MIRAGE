"""Synthetic-scenario evaluation for Contextual Detection V1."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable

from mirage.config import load_config
from mirage.detection.pipeline import ContextualDetectionPipeline
from mirage.ingestion.jsonl_source import JSONLEventSource
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.replay import sort_events_for_replay


def evaluate_scenarios(
    scenario_paths: Iterable[str | Path],
    labels: dict[str, dict],
) -> dict[str, float | int | str]:
    """Evaluate deterministic behavior on synthetic labeled scenarios.

    These metrics validate implementation behavior only; they are not
    production detection-accuracy claims.
    """
    config = load_config()
    detection_config = config.get("detection", {})
    rule_tp = rule_fp = rule_fn = 0
    stage_correct = 0
    stage_total = 0
    brier_sum = 0.0
    brier_count = 0
    false_positives_benign = 0
    detections_with_evidence = 0
    detections_total = 0
    correlated_events = 0
    elapsed_total = 0.0
    snapshot_fingerprints: list[str] = []

    for path_value in scenario_paths:
        path = Path(path_value)
        label = labels.get(path.stem, {})
        source = JSONLEventSource(path)
        events = sort_events_for_replay(list(source))
        twin = DigitalTwin(
            relationship_ttls=config.get("twin", {}).get("relationship_ttls", {}),
            allow_provisional_entities=True,
        )
        pipeline = ContextualDetectionPipeline(
            twin=twin,
            attack_graph=twin.export_attack_graph(),
            config=detection_config,
        )
        start = time.perf_counter()
        event_results = [pipeline.process_event(event) for event in events]
        elapsed_total += time.perf_counter() - start
        snapshot_fingerprints.append(
            pipeline.belief_engine.create_snapshot().model_dump_json()
        )

        expected_rules = set(label.get("expected_rules", []))
        observed_rules = {
            rule_id
            for result in event_results
            for rule_id in result.matched_rule_ids
        }
        rule_tp += len(expected_rules & observed_rules)
        rule_fp += len(observed_rules - expected_rules)
        rule_fn += len(expected_rules - observed_rules)

        expected_stage = label.get("expected_stage")
        top = pipeline.belief_engine.get_top_suspected_entities(limit=1)
        if expected_stage and top:
            stage_total += 1
            stage_correct += int(top[0].most_likely_stage == expected_stage)

        expected_compromised = float(label.get("expected_compromised", 0.0))
        if top:
            brier_sum += (top[0].compromise_probability - expected_compromised) ** 2
            brier_count += 1
            if label.get("benign") and top[0].compromise_probability >= 0.35:
                false_positives_benign += 1

        for result in event_results:
            if result.matched_rule_ids:
                detections_total += 1
                detections_with_evidence += int(bool(result.evidence_ids))
            correlated_events += len(result.correlation_ids)

    precision = rule_tp / max(1, rule_tp + rule_fp)
    recall = rule_tp / max(1, rule_tp + rule_fn)
    stage_accuracy = stage_correct / max(1, stage_total)
    deterministic_consistency = int(
        len(snapshot_fingerprints) == len(set(snapshot_fingerprints))
    )
    return {
        "scope": "synthetic_scenarios_only",
        "rule_precision": round(precision, 4),
        "rule_recall": round(recall, 4),
        "stage_accuracy": round(stage_accuracy, 4),
        "stage_macro_f1": round(
            2 * stage_accuracy * recall / max(1e-9, stage_accuracy + recall),
            4,
        ),
        "brier_score": round(brier_sum / max(1, brier_count), 4),
        "detection_latency_seconds": round(elapsed_total, 6),
        "false_positives_per_benign_scenario": false_positives_benign,
        "detections_with_evidence_pct": round(
            detections_with_evidence / max(1, detections_total),
            4,
        ),
        "deterministic_replay_consistency": deterministic_consistency,
        "average_correlated_events": round(
            correlated_events / max(1, len(snapshot_fingerprints)),
            4,
        ),
        "average_processing_time_per_scenario": round(
            elapsed_total / max(1, len(snapshot_fingerprints)),
            6,
        ),
    }
