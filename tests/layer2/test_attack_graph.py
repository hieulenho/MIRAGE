import pytest
from mirage.layer2_graph_engine.attack_graph import (
    build_configured_attack_graph,
    build_enterprise_attack_graph,
    build_runtime_graph,
)
from mirage.config import load_config
from mirage.layer3_deception.deception_fabric import (
    DeceptionAction,
    DeceptionActionType,
    DeceptionFabric,
)

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


def test_interception_rate_requires_attack_session_denominator():
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    action = next(
        candidate
        for candidate in fabric.action_catalog
        if candidate.action_type.value == "deploy_decoy_database"
        and candidate.target_node in graph.decoy_sites
    )
    decoy = fabric.deploy_action(action)
    fabric.record_engagement(decoy.decoy_id, "test-attacker")

    with pytest.raises(ValueError, match="total_attacks is required"):
        fabric.get_interception_rate()

    assert fabric.get_interception_rate(total_attacks=4) == pytest.approx(0.25)


def test_deploy_catalog_targets_only_real_decoy_slots():
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    deploy_actions = [
        action
        for action in fabric.action_catalog
        if action.action_type in {
            DeceptionActionType.DEPLOY_DECOY_DATABASE,
            DeceptionActionType.DEPLOY_DECOY_ROUTER,
        }
    ]

    assert deploy_actions
    assert {
        action.target_node for action in deploy_actions
    }.issubset(graph.decoy_sites)

    invalid = DeceptionAction(
        action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
        target_node=4,
    )
    with pytest.raises(ValueError, match="decoy slot"):
        build_runtime_graph(graph, actions=[invalid])


def test_fabric_rejects_deploy_action_for_wrong_decoy_asset_type():
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    invalid = DeceptionAction(
        action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
        target_node=12,
    )

    with pytest.raises(ValueError, match="cannot target asset type"):
        fabric.deploy_action(invalid)


def test_retiring_one_action_keeps_other_reward_and_engagement_history():
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    deploy = next(
        action
        for action in fabric.action_catalog
        if action.action_type
        == DeceptionActionType.DEPLOY_DECOY_DATABASE
    )
    honey = DeceptionAction(
        action_type=DeceptionActionType.SCATTER_HONEY_CREDENTIAL,
        target_node=deploy.target_node,
        reward_delta=0.5,
    )

    deployed_decoy = fabric.deploy_action(deploy)
    fabric.deploy_action(honey)
    fabric.record_engagement(deployed_decoy.decoy_id, "203.0.113.4")
    deployed_decoy.deployed_at = 0

    fabric.retire_expired_decoys()

    assert fabric.reward_interventions[
        (deploy.target_node, "end")
    ] == pytest.approx(0.15)
    assert fabric.get_interception_rate(total_attacks=1) == pytest.approx(1.0)


def test_configured_file_topology_is_used():
    config = load_config()
    config["topology"] = {
        "source": "file",
        "path": "examples/enterprise_topology.json",
        "format": "mirage",
    }

    graph = build_configured_attack_graph(config)

    assert graph.label(0) == "Internet"
    assert graph.true_goals
    assert graph.decoy_sites
