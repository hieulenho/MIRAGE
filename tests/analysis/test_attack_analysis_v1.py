from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

from fastapi.testclient import TestClient

from mirage.analysis.evaluation import evaluate_analysis_scenarios
from mirage.analysis.pipeline import AttackAnalysisPipeline
from mirage.analysis.robust_adapter import robust_input_from_candidate_action_set
from mirage.analyze_paths import main as analyze_paths_main
from mirage.api.server import create_app
from mirage.config import load_config
from mirage.detect import save_belief_snapshot
from mirage.detection.pipeline import ContextualDetectionPipeline
from mirage.ingestion.jsonl_source import JSONLEventSource
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage.replay import save_snapshot, sort_events_for_replay


ROOT = Path(__file__).resolve().parents[2]


def run_analysis_scenario(name: str):
    config = load_config()
    twin = DigitalTwin(
        relationship_ttls=config["twin"]["relationship_ttls"],
        allow_provisional_entities=True,
    )
    detection = ContextualDetectionPipeline(
        twin=twin,
        config=config["detection"],
    )
    source = JSONLEventSource(ROOT / "examples" / "events" / name)
    for event in sort_events_for_replay(list(source)):
        detection.process_event(event)
    pipeline = AttackAnalysisPipeline(config=config["analysis"])
    return pipeline.analyze(
        twin.create_snapshot(),
        detection.belief_engine.create_snapshot(),
    ), twin, detection


def test_seed_selector_subgraph_and_path_scoring_for_critical_db():
    result, _twin, _detection = run_analysis_scenario(
        "analysis_lateral_critical_db.jsonl"
    )

    assert result.selected_seeds
    assert len(result.subgraph.nodes) <= load_config()["analysis"]["subgraph"]["max_nodes"]
    assert len(result.subgraph.edges) <= load_config()["analysis"]["subgraph"]["max_edges"]
    assert {
        seed.entity_id for seed in result.selected_seeds
    }.issubset({node.node_id for node in result.subgraph.nodes})
    assert result.path_analysis.paths
    assert result.path_analysis.critical_assets_at_risk

    top = result.path_analysis.paths[0]
    assert 0 <= top.risk_score <= 1
    assert top.reaches_protected_asset is True
    assert top.score_breakdown["target_criticality"] >= 0.8
    assert top.directly_observed_edge_ids


def test_action_generation_constraints_masks_and_ranking():
    result, _twin, _detection = run_analysis_scenario(
        "analysis_protected_asset.jsonl"
    )
    action_set = result.candidate_action_set

    assert action_set.actions
    assert action_set.recommended_action_ids
    assert set(action_set.allowed_action_ids).isdisjoint(action_set.blocked_action_ids)
    assert all(
        action_id in action_set.masks for action_id in action_set.blocked_action_ids
    )
    assert all(
        action_set.masks[action_id].mask_reasons
        for action_id in action_set.blocked_action_ids
    )
    assert any(
        mask.approval_required for mask in action_set.masks.values()
    )
    assert not any(
        action.action_id in action_set.recommended_action_ids
        for action in action_set.actions
        if not action_set.masks[action.action_id].allowed
    )


def test_disabled_candidate_action_types_are_skipped_without_crashing():
    config = deepcopy(load_config()["analysis"])
    config["candidate_actions"]["enabled_action_types"] = [
        "increase_endpoint_logging"
    ]
    _result, twin, detection = run_analysis_scenario(
        "analysis_lateral_critical_db.jsonl"
    )

    limited = AttackAnalysisPipeline(config=config).analyze(
        twin.create_snapshot(),
        detection.belief_engine.create_snapshot(),
    )

    assert limited.candidate_action_set.actions
    assert {
        action.action_type for action in limited.candidate_action_set.actions
    } == {"increase_endpoint_logging"}


def test_decoy_path_prioritizes_information_gain_actions():
    result, _twin, _detection = run_analysis_scenario(
        "analysis_decoy_interaction.jsonl"
    )

    assert any(path.contains_decoy for path in result.path_analysis.paths)
    recommended = [
        action
        for action in result.candidate_action_set.actions
        if action.action_id in result.candidate_action_set.recommended_action_ids
    ]
    assert recommended
    assert any(
        action.action_type
        in {"increase_endpoint_logging", "increase_network_telemetry", "create_soc_ticket"}
        for action in recommended
    )


def test_subgraph_limits_are_respected_and_edges_do_not_dangle():
    config = load_config()
    result, twin, detection = run_analysis_scenario(
        "analysis_lateral_critical_db.jsonl"
    )
    limited = AttackAnalysisPipeline(config=config["analysis"]).analyze(
        twin.create_snapshot(),
        detection.belief_engine.create_snapshot(),
        max_hops=1,
        max_nodes=3,
        max_paths=5,
    )

    node_ids = {node.node_id for node in limited.subgraph.nodes}
    assert len(limited.subgraph.nodes) <= 3
    assert len(limited.path_analysis.paths) <= 5
    assert {seed.entity_id for seed in limited.selected_seeds}.issubset(node_ids)
    assert all(
        edge.source_entity_id in node_ids and edge.target_entity_id in node_ids
        for edge in limited.subgraph.edges
    )
    assert result.analysis_id != ""


def test_robust_adapter_preserves_masks_and_allowed_actions():
    result, _twin, detection = run_analysis_scenario(
        "analysis_lateral_critical_db.jsonl"
    )
    adapter = robust_input_from_candidate_action_set(
        result.candidate_action_set,
        result.path_analysis,
        detection.belief_engine.create_snapshot(),
    )

    assert adapter.available_action_ids == result.candidate_action_set.allowed_action_ids
    assert set(adapter.action_masks) == set(result.candidate_action_set.masks)
    assert all(
        action_id in result.candidate_action_set.allowed_action_ids
        for action_id in adapter.expected_utilities
    )
    assert adapter.warnings


def test_analyze_paths_cli_is_deterministic(tmp_path):
    result, twin, detection = run_analysis_scenario(
        "analysis_lateral_critical_db.jsonl"
    )
    twin_path = save_snapshot(twin.create_snapshot(), tmp_path / "twin.json")
    belief_path = save_belief_snapshot(
        detection.belief_engine.create_snapshot(),
        tmp_path / "belief.json",
    )
    analysis_a = tmp_path / "analysis-a.json"
    actions_a = tmp_path / "actions-a.json"
    analysis_b = tmp_path / "analysis-b.json"
    actions_b = tmp_path / "actions-b.json"

    code_a = analyze_paths_main([
        "--twin-snapshot",
        str(twin_path),
        "--belief-snapshot",
        str(belief_path),
        "--analysis-out",
        str(analysis_a),
        "--actions-out",
        str(actions_a),
    ])
    code_b = analyze_paths_main([
        "--twin-snapshot",
        str(twin_path),
        "--belief-snapshot",
        str(belief_path),
        "--analysis-out",
        str(analysis_b),
        "--actions-out",
        str(actions_b),
    ])

    assert code_a == 0
    assert code_b == 0
    assert json.loads(analysis_a.read_text(encoding="utf-8")) == json.loads(
        analysis_b.read_text(encoding="utf-8")
    )
    assert json.loads(actions_a.read_text(encoding="utf-8")) == json.loads(
        actions_b.read_text(encoding="utf-8")
    )
    assert result.analysis_id


def test_analysis_api_endpoints(monkeypatch):
    monkeypatch.delenv("MIRAGE_API_KEY", raising=False)
    client = TestClient(create_app())
    source = JSONLEventSource(
        ROOT / "examples" / "events" / "analysis_decoy_interaction.jsonl"
    )
    events = [event.model_dump(mode="json") for event in sort_events_for_replay(list(source))]

    batch = client.post("/api/v1/detection/events/batch", json=events)
    assert batch.status_code == 200
    analysis = client.post("/api/v1/analysis/run", json={"max_hops": 3})
    assert analysis.status_code == 200
    analysis_id = analysis.json()["analysis_id"]

    assert client.get(f"/api/v1/analysis/{analysis_id}").status_code == 200
    assert client.get(f"/api/v1/analysis/{analysis_id}/subgraph").status_code == 200
    assert client.get(f"/api/v1/analysis/{analysis_id}/paths").status_code == 200
    assert client.get(f"/api/v1/analysis/{analysis_id}/actions").status_code == 200
    masks = client.get(f"/api/v1/analysis/{analysis_id}/masks")
    assert masks.status_code == 200
    assert masks.json()["masks"]


def test_analysis_evaluation_runs_on_synthetic_scenarios():
    metrics = evaluate_analysis_scenarios(
        [
            ROOT / "examples" / "events" / "analysis_lateral_critical_db.jsonl",
            ROOT / "examples" / "events" / "analysis_decoy_interaction.jsonl",
        ],
        {
            "analysis_lateral_critical_db": {
                "expected_actions": ["deploy_decoy_database", "throttle_edge"],
            },
            "analysis_decoy_interaction": {
                "expected_actions": ["increase_endpoint_logging"],
            },
        },
    )

    assert metrics["scope"] == "synthetic_scenarios_only"
    assert metrics["deterministic_replay_consistency"] == 1
    assert metrics["actions_with_explanations_pct"] == 1.0
