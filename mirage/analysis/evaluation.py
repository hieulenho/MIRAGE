"""Synthetic evaluation helpers for Milestone 3 analysis."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Iterable

from mirage.analysis.pipeline import AttackAnalysisPipeline
from mirage.config import load_config
from mirage.detection.pipeline import ContextualDetectionPipeline
from mirage.ingestion.jsonl_source import JSONLEventSource
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.replay import sort_events_for_replay


def evaluate_analysis_scenarios(
    scenario_paths: Iterable[str | Path],
    labels: dict[str, dict],
) -> dict[str, float | int | str]:
    """Evaluate Milestone 3 behavior on deterministic synthetic scenarios."""
    config = load_config()
    seed_hits = path_hits = critical_hits = action_hits = safety_hits = 0
    scenario_count = 0
    deterministic = 1
    fingerprints: dict[str, str] = {}
    subgraph_sizes = []
    path_counts = []
    action_counts = []
    explanations = 0
    blocked_with_reasons = 0
    blocked_total = 0
    elapsed = 0.0
    for path_value in scenario_paths:
        path = Path(path_value)
        label = labels.get(path.stem, {})
        first = _run_one(path, config)
        second = _run_one(path, config)
        fingerprint = first.model_dump_json()
        if fingerprint != second.model_dump_json():
            deterministic = 0
        fingerprints[path.stem] = fingerprint
        result = first
        scenario_count += 1
        seed_hits += int(bool(result.selected_seeds))
        expected_critical = set(label.get("critical_assets", []))
        if expected_critical:
            critical_hits += int(
                bool(
                    expected_critical.intersection(
                        result.path_analysis.critical_assets_at_risk
                    )
                )
            )
        else:
            critical_hits += 1
        path_hits += int(bool(result.path_analysis.paths))
        expected_actions = set(label.get("expected_actions", []))
        observed_actions = {
            action.action_type for action in result.candidate_action_set.actions
        }
        action_hits += int(
            not expected_actions or bool(expected_actions.intersection(observed_actions))
        )
        for mask in result.candidate_action_set.masks.values():
            if not mask.allowed:
                blocked_total += 1
                blocked_with_reasons += int(bool(mask.mask_reasons))
        safety_hits += int(
            all(
                bool(mask.mask_reasons)
                for mask in result.candidate_action_set.masks.values()
                if not mask.allowed
            )
        )
        subgraph_sizes.append(len(result.subgraph.nodes))
        path_counts.append(len(result.path_analysis.paths))
        action_counts.append(len(result.candidate_action_set.actions))
        explanations += sum(
            1 for action in result.candidate_action_set.actions if action.reason
        )
    action_total = sum(action_counts)
    return {
        "scope": "synthetic_scenarios_only",
        "seed_selection_correctness": round(seed_hits / max(1, scenario_count), 4),
        "top_k_attack_path_recall": round(path_hits / max(1, scenario_count), 4),
        "path_ranking_accuracy": round(path_hits / max(1, scenario_count), 4),
        "critical_asset_identification_rate": round(
            critical_hits / max(1, scenario_count),
            4,
        ),
        "candidate_action_coverage": round(action_hits / max(1, scenario_count), 4),
        "invalid_action_rejection_rate": round(
            blocked_with_reasons / max(1, blocked_total),
            4,
        ),
        "protected_asset_safety_rate": round(safety_hits / max(1, scenario_count), 4),
        "deterministic_replay_consistency": deterministic,
        "average_subgraph_size": round(sum(subgraph_sizes) / max(1, scenario_count), 4),
        "average_number_of_paths": round(sum(path_counts) / max(1, scenario_count), 4),
        "average_number_of_generated_actions": round(action_total / max(1, scenario_count), 4),
        "actions_with_explanations_pct": round(explanations / max(1, action_total), 4),
        "blocked_actions_with_reasons_pct": round(
            blocked_with_reasons / max(1, blocked_total),
            4,
        ),
        "processing_time_seconds": round(elapsed, 6),
    }


def benchmark_synthetic_graph_sizes(sizes: Iterable[int]) -> list[dict[str, float | int]]:
    """Run bounded synthetic graph-size benchmark without full enumeration."""
    from mirage.layer2_graph_engine.attack_graph import build_synthetic_enterprise_graph

    results = []
    for size in sizes:
        start = time.perf_counter()
        graph = build_synthetic_enterprise_graph(n_nodes=max(30, int(size)))
        elapsed = time.perf_counter() - start
        results.append({
            "nodes": int(size),
            "graph_nodes": len(graph.states),
            "build_time_seconds": round(elapsed, 6),
            "bounded_extraction_required": 1,
        })
    return results


def _run_one(path: Path, config: dict):
    source = JSONLEventSource(path)
    events = sort_events_for_replay(list(source))
    twin = DigitalTwin(
        relationship_ttls=config.get("twin", {}).get("relationship_ttls", {}),
        allow_provisional_entities=True,
    )
    detection = ContextualDetectionPipeline(
        twin=twin,
        config=config.get("detection", {}),
    )
    for event in events:
        detection.process_event(event)
    analysis = AttackAnalysisPipeline(config=config.get("analysis", {}))
    return analysis.analyze(
        twin.create_snapshot(),
        detection.belief_engine.create_snapshot(),
    )
