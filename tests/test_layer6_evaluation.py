from mirage.graph_parser import load_attack_graph
from mirage.layer6_evaluation import MIRAGEEvaluator


def test_dynamic_graph_benchmark_inputs_reference_valid_nodes(tmp_path):
    graph = load_attack_graph("examples/enterprise_topology.json")
    evaluator = MIRAGEEvaluator(
        graph,
        n_episodes=1,
        results_dir=str(tmp_path),
    )

    belief = evaluator.benchmark_b_belief()
    assert set(belief).issubset(graph.states)
    assert graph.sink_state not in belief
    assert abs(sum(belief.values()) - 1.0) < 1e-9

    for method in ("random_deception", "static_honeypot", "greedy_top_k"):
        _, _, _, actions = evaluator._get_reward_interventions_for_method(
            method,
            start_distribution=belief,
        )
        assert all(action.target_node in graph.states for action in actions)
