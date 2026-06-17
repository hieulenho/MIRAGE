import pytest

from mirage.layer2_graph_engine.attack_graph import build_enterprise_attack_graph
from mirage.shared.models.mdp_model import (
    AttackGraphMDP,
    InterventionSite,
    _parse_sa_key,
)
from mirage.shared.models.robust_reward import solve_max_margin_reward_design


def _build_tiny_reward_design_mdp() -> AttackGraphMDP:
    return AttackGraphMDP(
        name="tiny_reward_design",
        states=[0, 1, 2, 3],
        actions=["to_goal", "to_decoy", "end", "noop"],
        available_actions={
            0: ["to_goal", "to_decoy"],
            1: ["end"],
            2: ["end"],
            3: ["noop"],
        },
        transitions={
            0: {
                "to_goal": {2: 1.0},
                "to_decoy": {1: 1.0},
            },
            1: {"end": {3: 1.0}},
            2: {"end": {3: 1.0}},
            3: {"noop": {3: 1.0}},
        },
        start_distribution={0: 1.0},
        discount=0.9,
        budget=2.0,
        defender_reward={(1, "end"): 1.0, (2, "end"): -1.0},
        attacker_reward={(1, "end"): 0.0, (2, "end"): 1.0},
        interventions=[
            InterventionSite(name="decoy_reward", state=1, action="end")
        ],
        true_goals=[2],
        decoy_sites=[1],
        sink_state=3,
    )


def test_reward_design_changes_attacker_best_response_within_budget():
    mdp = _build_tiny_reward_design_mdp()
    result = solve_max_margin_reward_design(mdp)

    assert result.solver_status == "EXHAUSTIVE_CANDIDATES"
    assert result.x_ip == {"decoy_reward": pytest.approx(2.0)}
    assert sum(result.x_ip.values()) <= mdp.budget
    assert result.c_star > 0
    assert result.objective_evaluations == 2


def test_portable_model_round_trip_and_key_parser():
    graph = build_enterprise_attack_graph()
    portable = AttackGraphMDP.from_dict(graph.to_mdp_dict())
    converted = portable.to_mirage_graph()

    assert converted.states == graph.states
    assert converted.transitions == graph.transitions
    assert converted.sink_state == graph.sink_state
    assert _parse_sa_key("11|end") == (11, "end")


def test_live_graph_adapter_restores_potential_decoy_routes_for_design():
    graph = build_enterprise_attack_graph()
    portable = AttackGraphMDP.from_mirage_graph(graph)

    assert not graph.active_decoy_sites
    assert any(
        decoy in distribution
        for actions in portable.transitions.values()
        for distribution in actions.values()
        for decoy in graph.decoy_sites
    )


def test_portable_model_rejects_invalid_transition_distribution():
    mdp = _build_tiny_reward_design_mdp()
    mdp.transitions[0]["to_goal"] = {2: 0.5}

    with pytest.raises(ValueError, match="must sum to 1"):
        mdp.validate()
