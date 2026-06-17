import pytest

from mirage.shared.attacker_agents import RandomAttacker, run_simulation
from mirage.layer2_graph_engine.attack_graph import build_enterprise_attack_graph


def test_attacker_samples_configured_start_distribution():
    graph = build_enterprise_attack_graph()
    graph.start_distribution = {0: 0.0, 1: 1.0}

    attacker = RandomAttacker(graph, seed=7)

    assert attacker.current_state == 1
    attacker.reset()
    assert attacker.current_state == 1


def test_attacker_rejects_unknown_belief_state_and_empty_run():
    graph = build_enterprise_attack_graph()
    attacker = RandomAttacker(graph, seed=7)

    with pytest.raises(ValueError, match="unknown state"):
        attacker.reset({9999: 1.0})

    with pytest.raises(ValueError, match="n_episodes"):
        run_simulation(graph, "random", n_episodes=0)
