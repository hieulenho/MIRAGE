"""
MIRAGE — Main Entry Point
=========================
Multi-stage Intelligent Robust Adaptive Graph-based Engagement
Version 1: Research Simulator

Usage:
  python run_mirage.py                    # Chạy demo đầy đủ end-to-end
  python run_mirage.py --mode demo        # Demo end-to-end nhanh
  python run_mirage.py --mode benchmark   # Benchmark đầy đủ 6 phương pháp
  python run_mirage.py --mode benchmark_a # Benchmark A: Entry-point attack (Internet → DB)
  python run_mirage.py --mode benchmark_b # Benchmark B: Belief-conditioned response (mid-network)
  python run_mirage.py --mode multi_seed  # Multi-seed Benchmark A+B với confidence intervals
  python run_mirage.py --mode step1       # Bước 1: MVP (Layer 2+4)
  python run_mirage.py --mode step2       # Bước 2: Đắp thịt (Layer 3+6+Attackers)
  python run_mirage.py --mode step3       # Bước 3: Gắn mắt phanh (Layer 1+5)
  python run_mirage.py --mode ablation    # Ablation study
  python run_mirage.py --mode graph       # Hiển thị thông tin đồ thị
"""

from __future__ import annotations

import argparse
import os
import sys
import io
import time

# Fix Windows console encoding for Unicode output
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ('utf-8', 'utf8'):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

# Thêm thư mục MIRAGE vào path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

BANNER = r"""
╔═══════════════════════════════════════════════════════════════════╗
║   ███╗   ███╗██╗██████╗  █████╗  ██████╗ ███████╗               ║
║   ████╗ ████║██║██╔══██╗██╔══██╗██╔════╝ ██╔════╝               ║
║   ██╔████╔██║██║██████╔╝███████║██║  ███╗█████╗                 ║
║   ██║╚██╔╝██║██║██╔══██╗██╔══██║██║   ██║██╔══╝                 ║
║   ██║ ╚═╝ ██║██║██║  ██║██║  ██║╚██████╔╝███████╗               ║
║   ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝               ║
║                                                                   ║
║   Multi-stage Intelligent Robust Adaptive Graph-based Engagement  ║
║   Version 1.0 — Research Simulator                                ║
║   Based on: Robust Reward Design for Attack Graph MDP             ║
╚═══════════════════════════════════════════════════════════════════╝
"""


def run_step1_mvp():
    """
    Bước 1: Khung xương MVP
    Mục tiêu: Layer 2 (Attack Graph) + Layer 4 (Decision Engine)
    AI tự chọn node nào để đặt Fake Database.
    """
    print("\n" + "─" * 70)
    print("BƯỚC 1: Khung xương MVP (Layer 2 + Layer 4)")
    print("─" * 70)

    from mirage.layer2_attack_graph import build_enterprise_attack_graph, print_graph_summary
    from mirage.layer3_deception import DeceptionFabric
    from mirage.layer4_decision_engine import RobustDecisionEngine

    # Layer 2: Xây dựng đồ thị
    print("\n[Layer 2] Xây dựng Enterprise Attack Graph (15 nodes)...")
    graph = build_enterprise_attack_graph()
    print_graph_summary(graph)

    # Layer 3: Khởi tạo Deception Fabric
    fabric = DeceptionFabric(graph)

    # Layer 4: Decision Engine
    print("\n[Layer 4] Khởi tạo Robust Decision Engine...")
    engine = RobustDecisionEngine(
        graph, fabric,
        n_attacker_samples=100,
        use_robust_milp=False,
    )

    # Belief state: attacker có thể ở Workstation Finance (node 4)
    belief_state = {
        4: 0.45,   # WS_Finance — most likely
        3: 0.25,   # WS_Engineering
        5: 0.15,   # WS_IT
        1: 0.10,   # WebServer DMZ
        0: 0.05,   # Internet
    }

    print("\n[Layer 4] Evaluating deception options...")
    print(f"  Current belief: Attacker likely at Node 4 (WS_Finance) — {belief_state[4]:.0%}")

    plan = engine.decide(
        belief_state=belief_state,
        stage_context={"stage": "Lateral Movement", "confidence": 0.75},
        budget_remaining=4.0,
    )

    if plan:
        print(plan)
        print("\n✅ Bước 1 HOÀN THÀNH: AI đã quyết định đặt decoy tại Node",
              plan.target_node, f"({plan.target_node_label})")
        print(f"   Pessimistic Value: {plan.pessimistic_value:+.4f}")
        print(f"   Reasoning: {plan.reasoning[:150]}...")
    else:
        print("⚠️  Không có action nào được chọn.")

    return plan


def run_step2_full_layers():
    """
    Bước 2: Đắp thịt — Layer 3 đầy đủ + Attacker Agents + Layer 6
    """
    print("\n" + "─" * 70)
    print("BƯỚC 2: Đắp thịt — Layer 3 + Attackers + Evaluation")
    print("─" * 70)

    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer3_deception import DeceptionFabric, DeceptionActionType
    from mirage.attacker_agents import run_simulation

    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)

    # --- Demo Layer 3: Triển khai nhiều loại deception ---
    print("\n[Layer 3] Triển khai Deception Fabric...")
    catalog = fabric.get_available_actions(budget_remaining=5.0)

    # Chọn mỗi loại action một cái
    deployed = []
    for action_type in [
        DeceptionActionType.DEPLOY_DECOY_DATABASE,
        DeceptionActionType.DEPLOY_DECOY_ROUTER,
        DeceptionActionType.SCATTER_HONEY_CREDENTIAL,
        DeceptionActionType.INCREASE_EDGE_COST,
    ]:
        action = next((a for a in catalog if a.action_type == action_type), None)
        if action:
            decoy = fabric.deploy_action(action)
            deployed.append(decoy)

    print(f"\n  → {len(deployed)} decoys deployed")
    print(fabric.summary())

    # --- Demo 4 loại Attacker Agents ---
    print("\n[Attackers] Simulating 4 attacker types (100 episodes each)...")
    print("-" * 70)

    # Tạo reward interventions từ fabric
    reward_interventions = dict(fabric.reward_interventions)

    for atype in ["random", "greedy", "shortest_path", "stealthy", "deception_aware"]:
        result = run_simulation(
            graph, atype,
            n_episodes=100,
            reward_interventions=reward_interventions,
            seed=42,
        )
        print(f"  {result['attacker_type']:20s}: "
              f"Hit True Goal={result['hit_true_goal_rate']:.1%}  |  "
              f"Decoy Hit={result['decoy_interception_rate']:.1%}  |  "
              f"Avg Steps={result['avg_steps_to_terminal']:.1f}")

    # --- Layer 6: Quick Benchmark ---
    print("\n[Layer 6] Running benchmark (3 methods for speed)...")
    from mirage.layer6_evaluation import MIRAGEEvaluator
    evaluator = MIRAGEEvaluator(graph, n_episodes=150, seed=42)

    # Chạy 3 phương pháp để demo nhanh; _get_reward_interventions_for_method
    # trả về tuple (interventions_dict, edge_edits_list) — phải unpack đúng.
    for method in ["no_defense", "static_honeypot", "robust_mirage"]:
        interventions, edge_edits = evaluator._get_reward_interventions_for_method(method)
        result = evaluator._compute_metrics_for_method(
            method, interventions, edge_cost_edits=edge_edits
        )
        evaluator.results[method] = result

    print("\nQuick Comparison (3 methods):")
    print(f"  {'Method':25s} | {'Intercept%':>12s} | {'Pess.Val':>12s}")
    print("  " + "-" * 60)
    for method in ["no_defense", "static_honeypot", "robust_mirage"]:
        if method in evaluator.results:
            r = evaluator.results[method]
            flag = " ← MIRAGE" if method == "robust_mirage" else ""
            print(f"  {method:25s} | {r.interception_rate:>11.1%} | {r.pessimistic_value:+11.4f}{flag}")

    print("\n✅ Bước 2 HOÀN THÀNH")


def run_step3_safety():
    """
    Bước 3: Gắn Mắt và Phanh — Layer 1 + Layer 5
    """
    print("\n" + "─" * 70)
    print("BƯỚC 3: Gắn Mắt và Phanh — Layer 1 + Layer 5")
    print("─" * 70)

    from mirage.layer1_attack_modeling import (
        AttackStageClassifier, simulate_attack_telemetry
    )
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer3_deception import DeceptionFabric, DeceptionAction, DeceptionActionType
    from mirage.layer5_safe_control import SafetyGate, RiskLevel, create_safety_gate
    from mirage.layer2_attack_graph import DB_FAKE, DB_REAL, RTR_FAKE

    graph = build_enterprise_attack_graph()

    # --- Layer 1: Attack Stage Classification ---
    print("\n[Layer 1] Processing telemetry events...")
    classifier = AttackStageClassifier()
    events = simulate_attack_telemetry("lateral_movement")
    print(f"  Processing {len(events)} events from 'lateral_movement' scenario...")
    for event in events:
        classifier.process_event(event)
    print(classifier.summary())

    # Honey trap scenario
    print("\n  Processing 'honey_trap' scenario...")
    classifier2 = AttackStageClassifier()
    for event in simulate_attack_telemetry("honey_trap"):
        classifier2.process_event(event)
    print(classifier2.summary())

    # --- Layer 5: Safety Gate Tests ---
    print("\n[Layer 5] Testing Safety Gate with different risk levels...")
    gate = create_safety_gate("results", budget_limit=5.0)

    # Tạo mock plans với risk levels khác nhau
    class MockAction:
        def __init__(self, atype, node, risk, impact, cost):
            self.action_type = atype
            self.target_node = node
            self.risk_score = risk
            self.business_impact = impact
            self.cost = cost
            self.rollback_plan = "Automated rollback"

    class MockPlan:
        def __init__(self, action, node, label, pess, conf):
            self.action = action
            self.target_node = node
            self.target_node_label = label
            self.pessimistic_value = pess
            self.confidence = conf
            self.reasoning = f"Deploy {action.action_type.value} at {label}"

    print("\n  Test 1: LOW risk — Fake DB at decoy node")
    act1 = MockAction(DeceptionActionType.DEPLOY_DECOY_DATABASE, DB_FAKE, 0.1, 0.02, 1.5)
    plan1 = MockPlan(act1, DB_FAKE, "DB_FAKE_Backup", 0.35, 0.80)
    allowed1, decision1 = gate.check_action_plan(plan1, graph)
    print(decision1)

    print("\n  Test 2: MEDIUM risk — Honey Credential at Workstation Finance")
    act2 = MockAction(DeceptionActionType.SCATTER_HONEY_CREDENTIAL, 4, 0.35, 0.08, 0.8)
    plan2 = MockPlan(act2, 4, "Workstation_Finance", 0.15, 0.65)
    allowed2, decision2 = gate.check_action_plan(plan2, graph)
    print(decision2)

    print("\n  Test 3: HIGH risk — Action near Real DB (protected node)")
    act3 = MockAction(DeceptionActionType.DEPLOY_DECOY_DATABASE, DB_REAL, 0.6, 0.25, 2.0)
    plan3 = MockPlan(act3, DB_REAL, "DB_REAL_Finance", -0.5, 0.55)
    allowed3, decision3 = gate.check_action_plan(plan3, graph)
    print(decision3)

    print("\n  Test 4: FAIL-SAFE mode activation")
    gate.enter_fail_safe("Anomaly detected in telemetry — confidence too low")
    act4 = MockAction(DeceptionActionType.DEPLOY_DECOY_ROUTER, RTR_FAKE, 0.1, 0.02, 1.2)
    plan4 = MockPlan(act4, RTR_FAKE, "Router_FAKE_Gateway", 0.25, 0.75)
    allowed4, decision4 = gate.check_action_plan(plan4, graph)
    print(decision4)
    gate.exit_fail_safe("SOC_Admin_001")

    print("\n")
    print(gate.get_audit_summary())
    print("\n✅ Bước 3 HOÀN THÀNH")


def run_full_demo():
    """Chạy demo đầy đủ end-to-end."""
    print("\n" + "─" * 70)
    print("MIRAGE END-TO-END DEMO")
    print("─" * 70)

    from mirage.layer1_attack_modeling import AttackStageClassifier, simulate_attack_telemetry
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer3_deception import DeceptionFabric
    from mirage.layer4_decision_engine import RobustDecisionEngine
    from mirage.layer5_safe_control import create_safety_gate, make_safety_filter
    from mirage.layer6_evaluation import MIRAGEEvaluator

    print("\n📡 [Layer 1] Processing real-time telemetry...")
    classifier = AttackStageClassifier()
    events = simulate_attack_telemetry("lateral_movement")
    for event in events:
        est = classifier.process_event(event)

    # Lấy stage estimate
    estimates = classifier.get_all_estimates()
    dominant_host = list(estimates.keys())[0] if estimates else None
    stage_ctx = {}
    if dominant_host:
        est = estimates[dominant_host]
        from mirage.layer1_attack_modeling import STAGE_NAMES
        stage_ctx = {
            "stage": STAGE_NAMES[est.dominant_stage],
            "confidence": est.confidence,
        }
        print(f"  → Detected: [{stage_ctx['stage']}] "
              f"({stage_ctx['confidence']:.1%} confidence)")
        print(f"  → Evidence: {est.evidence[-2] if est.evidence else 'None'}")

    print("\n🗺️  [Layer 2] Building Enterprise Attack Graph...")
    graph = build_enterprise_attack_graph()

    # Cập nhật belief state dựa trên telemetry
    belief_state = {4: 0.40, 3: 0.25, 6: 0.15, 5: 0.12, 1: 0.08}
    graph.update_belief({4: 0.8, 3: 0.4, 6: 0.3})
    print(f"  → Belief updated: WS_Finance (Node 4) has {graph.belief_state.get(4, 0):.1%} probability")

    print("\n🎭 [Layer 3] Initializing Deception Fabric...")
    fabric = DeceptionFabric(graph)

    print("\n🔐 [Layer 5] Setting up Safety Gate...")
    gate = create_safety_gate("results", budget_limit=5.0)
    safety_filter = make_safety_filter(gate, graph)

    print("\n🤖 [Layer 4] Running Robust Decision Engine...")
    engine = RobustDecisionEngine(
        graph, fabric,
        n_attacker_samples=150,
        use_robust_milp=False,
    )

    plan = engine.decide(
        belief_state=belief_state,
        stage_context=stage_ctx,
        budget_remaining=4.0,
        safety_filter=safety_filter,
    )

    if plan:
        print(plan)
        # Deploy toàn bộ portfolio (không chỉ primary action)
        deployed_decoys = []
        for action in plan.portfolio:
            decoy = fabric.deploy_action(action)
            deployed_decoys.append(decoy)
        print(f"\n🚀 [Layer 3] {len(deployed_decoys)} portfolio actions deployed: "
              + ", ".join(d.decoy_id for d in deployed_decoys))

    print("\n📊 [Layer 6] Running Quick Evaluation...")
    evaluator = MIRAGEEvaluator(graph, n_episodes=200, seed=42)
    evaluator.run_full_benchmark(verbose=False)
    evaluator.print_comparison_table()
    evaluator.plot_results(save=True)

    print("\n" + "─" * 70)
    print("✅ MIRAGE End-to-End Demo COMPLETE")
    print("─" * 70)


def run_full_benchmark():
    """Chạy benchmark đầy đủ với tất cả 6 phương pháp."""
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer6_evaluation import MIRAGEEvaluator

    graph = build_enterprise_attack_graph()
    evaluator = MIRAGEEvaluator(graph, n_episodes=500, seed=42, results_dir="results")

    print("\n[Benchmark] Running full 6-method comparison...")
    evaluator.run_full_benchmark(verbose=True)

    print("\n[Benchmark] Results:")
    evaluator.print_comparison_table()
    evaluator.per_attacker_breakdown()

    print("\n[Benchmark] Running Ablation Study...")
    evaluator.run_ablation_study()

    evaluator.save_results_json()
    evaluator.plot_results(save=True)

    print("\n✅ Full benchmark complete!")


def run_benchmark_a():
    """Chạy Benchmark A: Attacker bắt đầu từ Internet/Entry Point."""
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer6_evaluation import MIRAGEEvaluator

    graph = build_enterprise_attack_graph()
    evaluator = MIRAGEEvaluator(graph, n_episodes=500, seed=42, results_dir="results")

    print("\n[Benchmark A] Entry-point attack — Attacker starts at Internet (Node 0)")
    evaluator.run_benchmark_a(verbose=True)

    print("\n[Benchmark A] Results:")
    evaluator.print_comparison_table()
    evaluator.per_attacker_breakdown()
    evaluator.save_results_json(filename="benchmark_a_results.json")
    evaluator.plot_results(save=True)

    print("\n✅ Benchmark A complete!")


def run_benchmark_b():
    """Chạy Benchmark B: Attacker đã bị nghi ở mid-network (post-intrusion)."""
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer6_evaluation import MIRAGEEvaluator

    graph = build_enterprise_attack_graph()
    evaluator = MIRAGEEvaluator(graph, n_episodes=500, seed=42, results_dir="results")

    print("\n[Benchmark B] Belief-conditioned response")
    print("  Belief: WS_Finance(35%), SMB(25%), SVC_Cred(20%), Admin_Cred(10%), WS_Eng(10%)")
    evaluator.run_benchmark_b(verbose=True)

    print("\n[Benchmark B] Results:")
    evaluator.print_comparison_table()
    evaluator.per_attacker_breakdown()
    evaluator.save_results_json(filename="benchmark_b_results.json")
    evaluator.plot_results(save=True)

    print("\n✅ Benchmark B complete!")


def run_multi_seed():
    """Chạy Multi-Seed Benchmark để lấy mean ± std."""
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer6_evaluation import MIRAGEEvaluator

    graph = build_enterprise_attack_graph()
    evaluator = MIRAGEEvaluator(graph, n_episodes=300, seed=42, results_dir="results")

    print("\n[Multi-Seed] Running Benchmark A across 10 seeds...")
    aggregated_a = evaluator.run_multi_seed_benchmark(
        seeds=list(range(10)),
        n_episodes=500,
        benchmark_type="a",
        verbose=True,
    )

    print("\n[Multi-Seed] Running Benchmark B across 10 seeds...")
    aggregated_b = evaluator.run_multi_seed_benchmark(
        seeds=list(range(10)),
        n_episodes=500,
        benchmark_type="b",
        verbose=True,
    )

    print("\n✅ Multi-seed benchmark complete! Results saved to results/")


def show_graph_info():
    """Hiển thị thông tin đồ thị."""
    from mirage.layer2_attack_graph import build_enterprise_attack_graph, print_graph_summary
    graph = build_enterprise_attack_graph()
    print_graph_summary(graph)


def main():
    parser = argparse.ArgumentParser(
        description="MIRAGE — Research Simulator v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--mode",
        choices=[
            "demo", "benchmark", "benchmark_a", "benchmark_b",
            "multi_seed", "step1", "step2", "step3", "ablation", "graph",
        ],
        default="demo",
        help="Chế độ chạy",
    )
    args = parser.parse_args()

    print(BANNER)
    print(f"Mode: {args.mode.upper()}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")

    os.makedirs("results", exist_ok=True)

    if args.mode == "demo":
        run_full_demo()
    elif args.mode == "step1":
        run_step1_mvp()
    elif args.mode == "step2":
        run_step2_full_layers()
    elif args.mode == "step3":
        run_step3_safety()
    elif args.mode == "benchmark":
        run_full_benchmark()
    elif args.mode == "benchmark_a":
        run_benchmark_a()
    elif args.mode == "benchmark_b":
        run_benchmark_b()
    elif args.mode == "multi_seed":
        run_multi_seed()
    elif args.mode == "ablation":
        from mirage.layer2_attack_graph import build_enterprise_attack_graph
        from mirage.layer6_evaluation import MIRAGEEvaluator
        graph = build_enterprise_attack_graph()
        evaluator = MIRAGEEvaluator(graph, n_episodes=300, seed=42)
        evaluator.run_ablation_study()
    elif args.mode == "graph":
        show_graph_info()


if __name__ == "__main__":
    main()
