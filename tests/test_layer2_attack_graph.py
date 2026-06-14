import pytest
from mirage.layer2_attack_graph import build_enterprise_attack_graph
from mirage.layer3_deception import DeceptionFabric

def test_build_graph_initialization():
    graph = build_enterprise_attack_graph(budget=4.0, discount=0.95, decoy_realism=0.8)
    
    # Check states
    assert len(graph.states) == 15
    assert 14 in graph.states  # Sink
    
    # Check belief state is initialized
    assert len(graph.belief_state) == 14  # Sink is excluded
    assert sum(graph.belief_state.values()) == pytest.approx(1.0)


def test_fabric_refresh_does_not_compound_edge_costs():
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    edge_action = next(
        action
        for action in fabric.action_catalog
        if action.action_type.value == "increase_edge_cost"
    )
    honey_action = next(
        action
        for action in fabric.action_catalog
        if action.action_type.value == "scatter_honey_credential"
    )

    fabric.deploy_action(edge_action)
    source, _ = edge_action.target_edge
    after_edge = {
        action: dict(distribution)
        for action, distribution in graph.transitions[source].items()
    }

    fabric.deploy_action(honey_action)
    assert graph.transitions[source] == after_edge
