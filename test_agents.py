from mirage.attacker_agents import run_simulation
from mirage.layer2_attack_graph import (
    DB_FAKE,
    RTR_FAKE,
    build_enterprise_attack_graph,
    build_runtime_graph,
)
from mirage.layer3_deception import DeceptionFabric


ATTACKER_TYPES = [
    "random",
    "greedy",
    "shortest_path",
    "stealthy",
    "deception_aware",
    "mitre_evasion",
]


def _find_action(fabric, action_type, target_node):
    return next(
        action
        for action in fabric.action_catalog
        if action.action_type.value == action_type
        and action.target_node == target_node
    )


def test_clean_graph_has_no_reachable_decoy_slots():
    graph = build_enterprise_attack_graph()
    clean_graph = build_runtime_graph(graph, actions=[])

    for source in clean_graph.states:
        for action in clean_graph.available_actions.get(source, []):
            destinations = clean_graph.transitions[source][action]
            assert not set(destinations).intersection(clean_graph.decoy_sites)

    for attacker_type in ATTACKER_TYPES:
        result = run_simulation(
            clean_graph,
            attacker_type,
            n_episodes=30,
            seed=42,
        )
        assert result["decoy_interception_rate"] == 0.0


def test_deploy_actions_activate_only_selected_slots():
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    actions = [
        _find_action(fabric, "deploy_decoy_database", DB_FAKE),
        _find_action(fabric, "deploy_decoy_router", RTR_FAKE),
    ]
    active_graph = build_runtime_graph(graph, actions=actions)

    assert set(active_graph.active_decoy_sites) == {DB_FAKE, RTR_FAKE}
    assert any(
        set(active_graph.transitions[source][action]).intersection({DB_FAKE, RTR_FAKE})
        for source in active_graph.states
        for action in active_graph.available_actions.get(source, [])
    )


if __name__ == "__main__":
    test_clean_graph_has_no_reachable_decoy_slots()
    test_deploy_actions_activate_only_selected_slots()
    print("Attacker-agent smoke tests passed.")
