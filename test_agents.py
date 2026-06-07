import io
import sys

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

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
]


def find_action(fabric, action_type, target_node):
    return next(
        action
        for action in fabric.action_catalog
        if action.action_type.value == action_type
        and action.target_node == target_node
    )


graph = build_enterprise_attack_graph()
clean_graph = build_runtime_graph(graph, actions=[])
for slot in clean_graph.decoy_sites:
    visible = clean_graph.attacker_label(slot).lower()
    assert all(keyword not in visible for keyword in ["fake", "decoy", "honey"])

for source in clean_graph.states:
    for action in clean_graph.available_actions.get(source, []):
        destinations = clean_graph.transitions[source][action]
        assert not set(destinations).intersection(clean_graph.decoy_sites)

print("Testing all attacker types on clean no-defense graph...")
clean_results = {}
for attacker_type in ATTACKER_TYPES:
    result = run_simulation(
        clean_graph,
        attacker_type,
        n_episodes=300,
        seed=42,
    )
    clean_results[attacker_type] = result
    assert result["decoy_interception_rate"] == 0.0
    print(
        f"{attacker_type:20s}: "
        f"Hit TG={result['hit_true_goal_rate']:.1%}  "
        f"Decoy={result['decoy_interception_rate']:.1%}  "
        f"Steps={result['avg_steps_to_terminal']:.1f}"
    )

fabric = DeceptionFabric(graph)
actions = [
    find_action(fabric, "deploy_decoy_database", DB_FAKE),
    find_action(fabric, "deploy_decoy_router", RTR_FAKE),
]
active_graph = build_runtime_graph(graph, actions=actions)
reward_interventions = {
    (action.target_node, "end"): action.reward_delta
    for action in actions
}

assert set(active_graph.active_decoy_sites) == {DB_FAKE, RTR_FAKE}
assert any(
    set(active_graph.transitions[source][action]).intersection({DB_FAKE, RTR_FAKE})
    for source in active_graph.states
    for action in active_graph.available_actions.get(source, [])
)

print("\nTesting all attacker types on active deception graph...")
for attacker_type in ATTACKER_TYPES:
    result = run_simulation(
        active_graph,
        attacker_type,
        n_episodes=300,
        seed=42,
        reward_interventions=reward_interventions,
    )
    print(
        f"{attacker_type:20s}: "
        f"Hit TG={result['hit_true_goal_rate']:.1%}  "
        f"Decoy={result['decoy_interception_rate']:.1%}  "
        f"Steps={result['avg_steps_to_terminal']:.1f}"
    )
