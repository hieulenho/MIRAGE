import json

import pytest

from mirage.layer2_graph_engine.graph_parser import load_attack_graph, save_graph_to_json
from mirage.layer2_graph_engine.attack_graph import build_runtime_graph
from mirage.layer3_deception.deception_fabric import DeceptionFabric


def test_dynamic_graph_keeps_decoy_slots_inactive():
    graph = load_attack_graph("examples/enterprise_topology.json")

    assert graph.decoy_sites
    assert graph.active_decoy_sites == []
    assert graph.transitions[0]["exploit_web"][graph.sink_state] == pytest.approx(0.25)
    for source in graph.states:
        for action in graph.available_actions.get(source, []):
            destinations = graph.transitions[source][action]
            assert not set(destinations).intersection(graph.decoy_sites)

    fabric = DeceptionFabric(graph)
    assert fabric.action_catalog
    assert all(action.target_node in graph.states for action in fabric.action_catalog)

    deploy = next(
        action
        for action in fabric.action_catalog
        if action.target_node in graph.decoy_sites
        and action.action_type.value.startswith("deploy_decoy")
    )
    runtime = build_runtime_graph(graph, actions=[deploy])
    assert runtime.active_decoy_sites == [deploy.target_node]


def test_parser_rejects_duplicate_node_ids(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(
        json.dumps({
            "nodes": [
                {"id": 1, "goal": True},
                {"id": 1},
            ],
            "edges": [],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="unique"):
        load_attack_graph(str(path))


def test_parser_preserves_weighted_start_distribution(tmp_path):
    path = tmp_path / "weighted.json"
    path.write_text(
        json.dumps({
            "nodes": [
                {"id": 0, "start_probability": 1},
                {"id": 1, "start_probability": 3},
                {"id": 2, "goal": True},
            ],
            "edges": [
                {"src": 0, "dst": 2, "action": "move", "prob": 1},
                {"src": 1, "dst": 2, "action": "move", "prob": 1},
            ],
        }),
        encoding="utf-8",
    )

    graph = load_attack_graph(str(path))

    assert graph.start_distribution == pytest.approx({0: 0.25, 1: 0.75})


def test_parser_rejects_non_finite_probability(tmp_path):
    path = tmp_path / "invalid_probability.json"
    path.write_text(
        json.dumps({
            "nodes": [
                {"id": 0, "start": True},
                {"id": 1, "goal": True},
            ],
            "edges": [
                {"src": 0, "dst": 1, "action": "move", "prob": float("nan")},
            ],
        }),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="finite"):
        load_attack_graph(str(path))


def test_save_round_trip_preserves_inactive_decoy_routes(tmp_path):
    graph = load_attack_graph("examples/enterprise_topology.json")
    output = tmp_path / "round_trip.json"

    save_graph_to_json(graph, str(output))
    restored = load_attack_graph(str(output))

    assert restored.decoy_sites == graph.decoy_sites
    assert restored.decoy_transition_templates == graph.decoy_transition_templates
    assert restored.start_distribution == pytest.approx(
        graph.start_distribution
    )
