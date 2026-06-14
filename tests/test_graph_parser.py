import json

import pytest

from mirage.graph_parser import load_attack_graph
from mirage.layer2_attack_graph import build_runtime_graph
from mirage.layer3_deception import DeceptionFabric


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
