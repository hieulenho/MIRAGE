"""
MIRAGE - Layer 6: Evaluation, Benchmarks & Visualization
=========================================================
Đo lường và so sánh hiệu quả của MIRAGE với các baseline.

6 phương pháp so sánh:
  1. no_defense        — Không có deception nào
  2. random_deception  — Đặt decoy ngẫu nhiên
  3. static_honeypot   — Honeypot cố định (kinh nghiệm)
  4. greedy_top_k      — Đặt decoy ở node có value cao nhất
  5. standard_rl       — Tối ưu expected value (criterion="expected") dùng cùng engine
  6. robust_mirage     — MIRAGE: tối ưu cost-aware robust objective

Benchmark A: Attacker bắt đầu từ Internet/Entry — đo năng lực phòng thủ tổng thể.
Benchmark B: Attacker đã bị nghi ở vị trí giữa mạng — đo năng lực phản ứng theo telemetry.

Metrics đo lường:
  - interception_rate     : Tỷ lệ attacker bị dẫn vào decoy
  - time_to_compromise    : Số bước trung bình đến True Goal
  - false_positive_cost   : Chi phí rủi ro vận hành
  - pessimistic_value     : Worst-case defender value (ROBUST metric chính)
  - optimistic_value      : Best-case defender value
  - robustness_gap        : optimistic - pessimistic (nhỏ hơn = robust hơn)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import random
import time
import os
import json
import csv


@dataclass
class MethodResult:
    """Kết quả đánh giá cho một phương pháp."""
    method_name: str
    interception_rate: float          # Cao hơn = tốt hơn (attacker vào decoy)
    hit_true_goal_rate: float         # Thấp hơn = tốt hơn (attacker không đến DB)
    time_to_compromise: float         # Cao hơn = tốt hơn (kéo dài thời gian)
    false_positive_cost: float        # Thấp hơn = tốt hơn (ít ảnh hưởng user)
    pessimistic_value: float          # Cao hơn = tốt hơn (ROBUST metric)
    optimistic_value: float           # Reference
    robustness_gap: float             # optimistic - pessimistic (nhỏ hơn = tốt hơn)
    total_cost: float                 # Chi phí triển khai
    security_loss: float = 0.0
    portfolio_actions: List[str] = field(default_factory=list)
    per_attacker_type: Dict[str, float] = field(default_factory=dict)
    cost_model: Dict = field(default_factory=dict)
    runtime_seconds: float = 0.0

    def to_row(self) -> List:
        """Chuyển sang dòng bảng."""
        return [
            self.method_name,
            f"{self.interception_rate:.1%}",
            f"{self.hit_true_goal_rate:.1%}",
            f"{self.time_to_compromise:.1f}",
            f"{self.false_positive_cost:.3f}",
            f"{self.pessimistic_value:+.4f}",
            f"{self.optimistic_value:+.4f}",
            f"{self.robustness_gap:.4f}",
            f"{self.total_cost:.1f}",
        ]


class MIRAGEEvaluator:
    """
    Lớp 6: Framework đánh giá toàn diện MIRAGE.
    
    Tự động chạy benchmark, tính metrics, vẽ biểu đồ và xuất bảng so sánh.
    """

    METHODS = [
        "no_defense",
        "random_deception",
        "static_honeypot",
        "greedy_top_k",
        "standard_rl",
        "robust_mirage",
    ]

    # Six attacker profiles, including deception-aware and MITRE evasion.
    ATTACKER_TYPES = [
        "random",
        "greedy",
        "shortest_path",
        "stealthy",
        "deception_aware",
        "mitre_evasion",
    ]

    # Belief state cố định cho Benchmark B (mid-network intrusion scenario)
    BENCHMARK_B_BELIEF = {
        4: 0.35,   # WS_Finance — most likely (lateral movement hướng vào finance)
        6: 0.25,   # SMB_FileShare
        9: 0.20,   # ServiceAcct_Credential
        8: 0.10,   # Admin_Credential
        3: 0.10,   # WS_Engineering
    }

    def __init__(
        self,
        graph,
        n_episodes: int = 300,
        max_steps: int = 30,
        seed: int = 42,
        results_dir: str = "results",
    ):
        self.graph = graph
        self.n_episodes = n_episodes
        self.max_steps = max_steps
        self.seed = seed
        self.results_dir = results_dir
        os.makedirs(results_dir, exist_ok=True)
        self.results: Dict[str, MethodResult] = {}

    def _build_clean_graph_no_defense(self):
        """
        Tạo bản sao graph loại bỏ hoàn toàn xác suất chuyển đến decoy nodes.

        Mục đích: baseline no_defense phải phản ánh đúng kịch bản không có
        deception nào được deploy — tức là decoy nodes về mặt vật lý không
        tồn tại, attacker không có đường structural nào dẫn đến chúng.

        Cách làm: với mỗi transition có xác suất đến decoy node, lấy phần
        xác suất đó và phân phối lại theo tỷ lệ sang các real neighbors còn lại.
        Nếu không còn real neighbor nào thì redirect về Sink.
        """
        from mirage.layer2_attack_graph import build_runtime_graph
        return build_runtime_graph(self.graph, actions=[])

    def _empty_cost_model(self) -> Dict:
        return {
            "total": 0.0,
            "false_positive_cost": 0.0,
            "action_count": 0,
            "per_action": [],
        }

    def _cost_model_for_actions(self, actions: List) -> Dict:
        from mirage.mdp_solver import compute_portfolio_cost

        if not actions:
            return self._empty_cost_model()
        return compute_portfolio_cost(actions, self.graph)

    def _catalog_action(self, action_type: str, target_node: int):
        from mirage.layer3_deception import DeceptionFabric

        fabric = DeceptionFabric(self.graph)
        for action in fabric.action_catalog:
            if action.action_type.value == action_type and action.target_node == target_node:
                return action
        for action in fabric.action_catalog:
            if action.target_node == target_node:
                return action
        return None

    def _effects_for_actions(self, actions: List) -> Tuple[Dict, List[Tuple[int, int, float]]]:
        from mirage.layer3_deception import DeceptionActionType

        rewards: Dict = {}
        edge_edits: List[Tuple[int, int, float]] = []
        for action in actions:
            if action.action_type in {
                DeceptionActionType.DEPLOY_DECOY_DATABASE,
                DeceptionActionType.DEPLOY_DECOY_ROUTER,
            }:
                key = (action.target_node, "end")
                rewards[key] = rewards.get(key, 0.0) + action.reward_delta
            elif action.action_type == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
                cred_key = (action.target_node, "cred_dump")
                end_key = (action.target_node, "end")
                rewards[cred_key] = rewards.get(cred_key, 0.0) + action.reward_delta * 0.5
                rewards[end_key] = rewards.get(end_key, 0.0) + action.reward_delta * 0.3
            elif action.action_type == DeceptionActionType.INCREASE_EDGE_COST:
                if action.target_edge:
                    edge_edits.append(
                        (
                            action.target_edge[0],
                            action.target_edge[1],
                            action.edge_cost_delta,
                        )
                    )
        return rewards, edge_edits

    def _get_reward_interventions_for_method(
        self,
        method: str,
        start_distribution=None,
    ) -> Tuple[Dict[Tuple, float], List[Tuple[int, int, float]], Dict, List]:
        """
        Tạo reward interventions theo phương pháp.

        Args:
            start_distribution: Nếu có (Benchmark B), pass vào engine để
                                 optimize_portfolio() dùng belief state —
                                 giúp so sánh standard_rl vs robust_mirage công bằng
                                 vì cả hai đều optimize dưới cùng belief.
        """
        from mirage.layer2_attack_graph import DB_FAKE, RTR_FAKE, WS_FIN, SMB_SHARE, SVC_CRED
        rng = random.Random(self.seed)

        if method == "no_defense":
            return {}, [], self._empty_cost_model(), []

        elif method == "random_deception":
            # Đặt decoy ngẫu nhiên
            possible_nodes = [DB_FAKE, RTR_FAKE, WS_FIN, SMB_SHARE, SVC_CRED]
            chosen = rng.choice(possible_nodes)
            action = (
                self._catalog_action("deploy_decoy_database", chosen)
                or self._catalog_action("scatter_honey_credential", chosen)
                or self._catalog_action("deploy_decoy_router", chosen)
            )
            actions = [action] if action else []
            rewards, edge_edits = self._effects_for_actions(actions)
            return rewards, edge_edits, self._cost_model_for_actions(actions), actions

        elif method == "static_honeypot":
            actions = [
                a for a in [
                    self._catalog_action("deploy_decoy_database", DB_FAKE),
                    self._catalog_action("deploy_decoy_router", RTR_FAKE),
                ] if a
            ]
            rewards, edge_edits = self._effects_for_actions(actions)
            return rewards, edge_edits, self._cost_model_for_actions(actions), actions

        elif method == "greedy_top_k":
            actions = [
                a for a in [
                    self._catalog_action("deploy_decoy_database", DB_FAKE),
                    self._catalog_action("scatter_honey_credential", SVC_CRED),
                ] if a
            ]
            rewards, edge_edits = self._effects_for_actions(actions)
            return rewards, edge_edits, self._cost_model_for_actions(actions), actions

        elif method == "standard_rl":
            # Standard RL: dùng CÙNG engine, tối ưu EXPECTED value (criterion="expected").
            # Khi Benchmark B: truyền belief_state để optimize dưới belief điều kiện
            # → so sánh với robust_mirage trở nên công bằng (same engine, same belief).
            from mirage.layer3_deception import DeceptionFabric
            from mirage.layer4_decision_engine import RobustDecisionEngine

            fabric = DeceptionFabric(self.graph)
            engine = RobustDecisionEngine(
                self.graph, fabric,
                n_attacker_samples=max(100, self.n_episodes // 3),
                use_robust_milp=False,
                seed=self.seed,
            )
            portfolio, portfolio_result = engine.optimize_portfolio(
                budget=self.graph.budget,
                criterion="expected",          # <-- Maximize AVERAGE value
                belief_state=start_distribution, # <-- Same belief as robust_mirage
            )
            return (
                portfolio_result.get("combined_interventions", {}),
                portfolio_result.get("edge_cost_edits", []),
                portfolio_result.get("cost_breakdown", self._empty_cost_model()),
                portfolio,
            )

        elif method == "robust_mirage":
            # Robust MIRAGE: cùng engine, tối ưu cost-aware robust objective.
            # Khi Benchmark B: truyền belief_state để optimize dưới belief điều kiện.
            from mirage.layer3_deception import DeceptionFabric
            from mirage.layer4_decision_engine import RobustDecisionEngine

            fabric = DeceptionFabric(self.graph)
            engine = RobustDecisionEngine(
                self.graph, fabric,
                n_attacker_samples=max(100, self.n_episodes // 3),
                use_robust_milp=False,
                seed=self.seed,
            )
            portfolio, portfolio_result = engine.optimize_portfolio(
                budget=self.graph.budget,
                criterion="cost_aware_robust",
                belief_state=start_distribution, # <-- Same belief as standard_rl
                min_actions=1,
            )
            return (
                portfolio_result.get("combined_interventions", {}),
                portfolio_result.get("edge_cost_edits", []),
                portfolio_result.get("cost_breakdown", self._empty_cost_model()),
                portfolio,
            )

        return {}, [], self._empty_cost_model(), []

    def _compute_metrics_for_method(
        self,
        method: str,
        reward_interventions: Dict,
        edge_cost_edits: List[Tuple[int, int, float]],
        actions: Optional[List] = None,
        cost_model: Optional[Dict] = None,
        start_distribution: Optional[Dict[int, float]] = None,
    ) -> MethodResult:
        """Tính tất cả metrics cho một phương pháp."""
        from mirage.attacker_agents import run_simulation
        from mirage.layer2_attack_graph import build_runtime_graph

        t0 = time.time()
        per_attacker: Dict[str, float] = {}
        interception_rates = []
        hit_rates = []
        avg_steps_list = []
        all_defender_values = []

        eps_per_type = max(50, self.n_episodes // len(self.ATTACKER_TYPES))

        graph_copy = build_runtime_graph(
            self.graph,
            actions=actions or [],
            edge_cost_edits=edge_cost_edits,
        )

        for atype in self.ATTACKER_TYPES:
            result = run_simulation(
                graph_copy, atype,
                n_episodes=eps_per_type,
                reward_interventions=reward_interventions,
                seed=self.seed,
                max_steps=self.max_steps,
                start_distribution=start_distribution,
            )
            interception_rates.append(result["decoy_interception_rate"])
            hit_rates.append(result["hit_true_goal_rate"])
            avg_steps_list.append(result["avg_steps_to_terminal"])

            # Tính defender value
            d_val = (
                result["decoy_interception_rate"] * 1.0
                - result["hit_true_goal_rate"] * 2.0
                + (result["avg_steps_to_terminal"] / self.max_steps) * 0.2
            )
            all_defender_values.append(d_val)
            per_attacker[atype] = d_val

        # Tổng hợp metrics
        interception_rate = sum(interception_rates) / len(interception_rates)
        hit_true_goal_rate = sum(hit_rates) / len(hit_rates)
        time_to_compromise = sum(avg_steps_list) / len(avg_steps_list)
        asset_value = max(
            (
                float(self.graph.node_metadata.get(goal, {}).get("value", 1.0) or 1.0)
                for goal in self.graph.true_goals
            ),
            default=1.0,
        )
        security_loss = hit_true_goal_rate * asset_value

        # Operational cost comes from the same composite model used by Layer 4.
        if cost_model is None:
            cost_model = self._empty_cost_model()
        false_positive_cost = float(cost_model.get("false_positive_cost", 0.0))

        # Pessimistic = min defender value (worst-case attacker)
        pessimistic_value = min(all_defender_values)
        # Optimistic = max defender value (best-case)
        optimistic_value = max(all_defender_values)
        robustness_gap = optimistic_value - pessimistic_value

        # Chi phí tổng
        total_cost = float(cost_model.get("total", 0.0))

        runtime = time.time() - t0

        return MethodResult(
            method_name=method,
            interception_rate=interception_rate,
            hit_true_goal_rate=hit_true_goal_rate,
            time_to_compromise=time_to_compromise,
            false_positive_cost=false_positive_cost,
            pessimistic_value=pessimistic_value,
            optimistic_value=optimistic_value,
            robustness_gap=robustness_gap,
            total_cost=total_cost,
            security_loss=security_loss,
            portfolio_actions=[action.action_id for action in (actions or [])],
            per_attacker_type=per_attacker,
            cost_model=cost_model,
            runtime_seconds=runtime,
        )

    def run_full_benchmark(
        self,
        verbose: bool = True,
        start_distribution: Optional[Dict[int, float]] = None,
        benchmark_label: str = "A",
    ) -> Dict[str, MethodResult]:
        """
        Chạy benchmark đầy đủ cho tất cả 6 phương pháp.

        Args:
            start_distribution: Nếu có, attacker bắt đầu từ phân phối này (Benchmark B).
                                 Nếu None, bắt đầu từ Internet entry point (Benchmark A).
            benchmark_label: "A" hoặc "B" — dùng để label output.
        """
        if verbose:
            print("=" * 70)
            if benchmark_label == "B":
                print("MIRAGE Layer 6 — Benchmark B (Belief-Conditioned Response)")
                print("  Attacker starts at mid-network position (post-intrusion)")
            else:
                print("MIRAGE Layer 6 — Benchmark A (Entry-Point Attack)")
                print("  Attacker starts at Internet/Entry (Node 0)")
            print(f"  Episodes per method: {self.n_episodes}")
            print(f"  Attacker types: {self.ATTACKER_TYPES}")
            print("=" * 70)

        for method in self.METHODS:
            method_started = time.time()
            if verbose:
                print(f"\n[{method}] Running...")
            # Truyền start_distribution vào _get_reward_interventions_for_method
            # để standard_rl và robust_mirage đều optimize dưới cùng belief (Benchmark B).
            interventions, edge_edits, cost_model, actions = self._get_reward_interventions_for_method(
                method, start_distribution=start_distribution
            )
            result = self._compute_metrics_for_method(
                method, interventions,
                edge_cost_edits=edge_edits,
                actions=actions,
                cost_model=cost_model,
                start_distribution=start_distribution,
            )
            result.runtime_seconds = time.time() - method_started
            self.results[method] = result
            if verbose:
                print(f"  Interception Rate: {result.interception_rate:.1%}")
                print(f"  True Goal Hit:     {result.hit_true_goal_rate:.1%}")
                print(f"  Security Loss:     {result.security_loss:.4f}")
                print(f"  False-Positive:    {result.false_positive_cost:.4f}")
                print(f"  Pessimistic Val:   {result.pessimistic_value:+.4f}")
                print(f"  Robustness Gap:    {result.robustness_gap:.4f}")

        return self.results

    def run_benchmark_a(self, verbose: bool = True) -> Dict[str, MethodResult]:
        """
        Benchmark A — Entry-point attack.

        Attacker luôn bắt đầu từ Internet (Node 0).
        Đo năng lực phòng thủ tổng thể từ ngoài vào.
        Không có prior knowledge về vị trí attacker.
        """
        self.results = {}  # Reset
        return self.run_full_benchmark(
            verbose=verbose,
            start_distribution=None,
            benchmark_label="A",
        )

    def run_benchmark_b(self, verbose: bool = True) -> Dict[str, MethodResult]:
        """
        Benchmark B — Belief-conditioned response.

        Attacker đã bị nghi ở vị trí giữa mạng nội bộ (post-intrusion).
        Belief state: WS_Finance, SMB, ServiceAcct Cred, Admin Cred, WS_Eng.

        Đo năng lực phản ứng của defender khi đã có telemetry.
        Đây là kịch bản realistic nhất cho MIRAGE.
        """
        self.results = {}  # Reset
        return self.run_full_benchmark(
            verbose=verbose,
            start_distribution=self.BENCHMARK_B_BELIEF,
            benchmark_label="B",
        )

    def run_scaling_benchmark(
        self,
        node_sizes: Optional[List[int]] = None,
        max_candidates: int = 30,
        n_attacker_samples: int = 60,
        verbose: bool = True,
    ) -> Dict[int, Dict]:
        """
        Measure optimizer scaling on synthetic 100/500/1000-node graphs.

        This benchmark focuses on tractability: catalog size, pruned candidate
        count, selected portfolio size, cost, robust value, and runtime.
        """
        from mirage.layer2_attack_graph import build_synthetic_enterprise_graph
        from mirage.layer3_deception import DeceptionFabric
        from mirage.layer4_decision_engine import RobustDecisionEngine
        from mirage.mdp_solver import prune_action_space, rank_action_candidates

        if node_sizes is None:
            node_sizes = [100, 500, 1000]

        results: Dict[int, Dict] = {}
        if verbose:
            print("\n" + "=" * 70)
            print("MIRAGE Scaling Benchmark -- candidate pruning on large graphs")
            print("=" * 70)
            print(
                f"  {'Nodes':>7s} | {'Catalog':>7s} | {'Pruned':>7s} | "
                f"{'Ranked':>7s} | {'Portfolio':>9s} | {'Cost':>7s} | {'Runtime':>8s}"
            )
            print("  " + "-" * 68)

        for n_nodes in node_sizes:
            scale_candidate_limit = min(
                max_candidates,
                16 if n_nodes <= 100 else 10 if n_nodes <= 500 else 6,
            )
            scale_attacker_samples = max(
                12,
                int(n_attacker_samples * (100.0 / n_nodes) ** 0.5),
            )
            graph = build_synthetic_enterprise_graph(
                n_nodes=n_nodes,
                budget=12.0,
                seed=self.seed,
            )
            belief_nodes = [
                s for s, meta in graph.node_metadata.items()
                if meta.get("layer") in {"internal", "services", "credentials"}
                and s != graph.sink_state
            ][:8]
            belief = {
                node: 1.0 / max(1, len(belief_nodes))
                for node in belief_nodes
            } or graph.start_distribution

            t0 = time.time()
            fabric = DeceptionFabric(graph, max_actions_per_type=50)
            catalog_size = len(fabric.action_catalog)
            available = fabric.get_available_actions(graph.budget)
            focus = set(prune_action_space(
                graph,
                belief,
                top_k_states=min(80, max(20, int(n_nodes ** 0.5) * 2)),
            ))
            pruned = [
                action for action in available
                if (
                    action.target_node in focus
                    or (
                        action.target_edge
                        and (action.target_edge[0] in focus or action.target_edge[1] in focus)
                    )
                )
            ]
            ranked = rank_action_candidates(
                pruned,
                graph,
                belief_state=belief,
                limit=scale_candidate_limit,
            )

            engine = RobustDecisionEngine(
                graph,
                fabric,
                n_attacker_samples=scale_attacker_samples,
                use_robust_milp=False,
                seed=self.seed,
                approximate_mode=True,
            )
            portfolio, result = engine.optimize_portfolio(
                budget=graph.budget,
                belief_state=belief,
                criterion="cost_aware_robust",
                max_candidates=scale_candidate_limit,
                min_actions=1,
                max_portfolio_size=3,
            )
            runtime = time.time() - t0

            row = {
                "nodes": n_nodes,
                "catalog_actions": catalog_size,
                "budget_feasible_actions": len(available),
                "pruned_actions": len(pruned),
                "ranked_actions": len(ranked),
                "attacker_samples": scale_attacker_samples,
                "approximate_mode": True,
                "portfolio_size": len(portfolio),
                "portfolio_cost": result.get("total_cost", 0.0),
                "false_positive_cost": result.get("false_positive_cost", 0.0),
                "pessimistic_value": result.get("pessimistic_value", 0.0),
                "selection_value": result.get("selection_value", 0.0),
                "runtime_seconds": runtime,
            }
            results[n_nodes] = row

            if verbose:
                print(
                    f"  {n_nodes:7d} | {catalog_size:7d} | {len(pruned):7d} | "
                    f"{len(ranked):7d} | {len(portfolio):9d} | "
                    f"{row['portfolio_cost']:7.2f} | {runtime:7.2f}s"
                )

        out_path = os.path.join(self.results_dir, "scaling_benchmark_results.json")
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            if verbose:
                print(f"\nScaling results saved to: {out_path}")
        except Exception as e:
            print(f"Could not save scaling results: {e}")

        return results

    def print_comparison_table(self) -> None:
        """In bảng so sánh chuẩn."""
        if not self.results:
            print("No results yet. Run run_full_benchmark() first.")
            return

        HEADERS = [
            "Method", "Intercept%", "Hit_TG%", "Avg_Steps",
            "FP_Cost", "Pess.Val", "Opt.Val", "Gap", "Cost"
        ]

        COL_WIDTHS = [22, 12, 10, 12, 10, 12, 12, 10, 8]

        def fmt_row(cols):
            return "│ " + " │ ".join(
                str(c).ljust(w) for c, w in zip(cols, COL_WIDTHS)
            ) + " │"

        def sep_row():
            return "├─" + "─┼─".join("─" * w for w in COL_WIDTHS) + "─┤"

        top_row = "┌─" + "─┬─".join("─" * w for w in COL_WIDTHS) + "─┐"
        bot_row = "└─" + "─┴─".join("─" * w for w in COL_WIDTHS) + "─┘"

        print()
        print("MIRAGE BENCHMARK COMPARISON TABLE")
        print("=" * 80)
        print(top_row)
        print(fmt_row(HEADERS))
        print(sep_row())

        for method in self.METHODS:
            if method not in self.results:
                continue
            r = self.results[method]
            row = r.to_row()

            # Highlight MIRAGE
            if method == "robust_mirage":
                row[0] = ">>> " + row[0]

            print(fmt_row(row))

        print(bot_row)
        print()
        print("Metrics:")
        print("  Intercept%  : % attacker bị dẫn vào decoy (cao hơn = tốt hơn) ↑")
        print("  Hit_TG%     : % attacker đến True Goal (thấp hơn = tốt hơn) ↓")
        print("  Avg_Steps   : Thời gian trung bình đến kết thúc (cao hơn = tốt hơn) ↑")
        print("  FP_Cost     : Chi phí false positive (thấp hơn = tốt hơn) ↓")
        print("  Pess.Val    : Pessimistic defender value (cao hơn = robust hơn) ↑ ★")
        print("  Gap         : Opt - Pess gap (nhỏ hơn = robust hơn) ↓")

    def per_attacker_breakdown(self) -> None:
        """Hiển thị breakdown theo từng loại attacker."""
        if not self.results:
            return

        print("\n" + "=" * 80)
        print("PER-ATTACKER BREAKDOWN — Pessimistic Defender Value")
        print("=" * 80)

        # Header
        header = ["Method"] + [f"{a[:10]:>12s}" for a in self.ATTACKER_TYPES] + ["PESS (min)"]
        print(" | ".join(f"{h:>20s}" if i == 0 else h for i, h in enumerate(header)))
        print("-" * 80)

        for method in self.METHODS:
            if method not in self.results:
                continue
            r = self.results[method]
            vals = [r.per_attacker_type.get(a, 0.0) for a in self.ATTACKER_TYPES]
            row = [f"{'>>> ' + method if method == 'robust_mirage' else method:>20s}"] + \
                  [f"{v:+10.4f}" + "  " for v in vals] + \
                  [f"{r.pessimistic_value:+10.4f}"]
            print(" | ".join(row))

    def plot_results(self, save: bool = True) -> None:
        """Vẽ biểu đồ so sánh."""
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            import matplotlib.patches as mpatches
            import numpy as np
        except ImportError:
            print("matplotlib not available. Skipping plots.")
            return

        if not self.results:
            print("No results to plot.")
            return

        methods = [m for m in self.METHODS if m in self.results]
        colors = {
            "no_defense":       "#e74c3c",
            "random_deception": "#e67e22",
            "static_honeypot":  "#f39c12",
            "greedy_top_k":     "#2ecc71",
            "standard_rl":      "#3498db",
            "robust_mirage":    "#9b59b6",
        }

        fig, axes = plt.subplots(2, 3, figsize=(18, 11))
        fig.suptitle("MIRAGE v1 Research Simulator — Benchmark Results",
                     fontsize=16, fontweight="bold", y=0.98)
        fig.patch.set_facecolor("#1a1a2e")
        for ax in axes.flat:
            ax.set_facecolor("#16213e")
            ax.tick_params(colors="white")
            ax.xaxis.label.set_color("white")
            ax.yaxis.label.set_color("white")
            ax.title.set_color("white")
            for spine in ax.spines.values():
                spine.set_edgecolor("#444")

        method_labels = [
            m.replace("_", "\n") for m in methods
        ]
        clrs = [colors[m] for m in methods]

        # ----- Plot 1: Interception Rate -----
        ax = axes[0, 0]
        vals = [self.results[m].interception_rate for m in methods]
        bars = ax.bar(method_labels, vals, color=clrs, alpha=0.85, edgecolor="#333")
        ax.set_title("Interception Rate ↑", fontsize=12, fontweight="bold")
        ax.set_ylabel("Rate", color="white")
        ax.set_ylim(0, 1.1)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                    f"{v:.1%}", ha="center", va="bottom", fontsize=9, color="white")
        ax.axhline(y=vals[-1], color="#9b59b6", linestyle="--", alpha=0.5, label="MIRAGE")

        # ----- Plot 2: Hit True Goal Rate -----
        ax = axes[0, 1]
        vals = [self.results[m].hit_true_goal_rate for m in methods]
        bars = ax.bar(method_labels, vals, color=clrs, alpha=0.85, edgecolor="#333")
        ax.set_title("Hit True Goal Rate ↓ (Lower = Better)", fontsize=12, fontweight="bold")
        ax.set_ylabel("Rate", color="white")
        ax.set_ylim(0, 1.1)
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                    f"{v:.1%}", ha="center", va="bottom", fontsize=9, color="white")

        # ----- Plot 3: Pessimistic Value -----
        ax = axes[0, 2]
        vals = [self.results[m].pessimistic_value for m in methods]
        bars = ax.bar(method_labels, vals, color=clrs, alpha=0.85, edgecolor="#333")
        ax.set_title("Pessimistic Value ↑ (Robust Metric) ★", fontsize=12, fontweight="bold")
        ax.set_ylabel("Value", color="white")
        ax.axhline(y=0, color="gray", linestyle="-", alpha=0.5)
        for bar, v in zip(bars, vals):
            ypos = bar.get_height() + 0.01 if v >= 0 else bar.get_height() - 0.05
            ax.text(bar.get_x() + bar.get_width()/2, ypos,
                    f"{v:+.4f}", ha="center", va="bottom", fontsize=8, color="white")

        # ----- Plot 4: Per-Attacker Pessimistic Value (Grouped Bar) -----
        ax = axes[1, 0]
        n_att = len(self.ATTACKER_TYPES)
        n_meth = len(methods)
        x = np.arange(n_att)
        width = 0.8 / n_meth
        att_colors = ["#e74c3c", "#3498db", "#2ecc71", "#9b59b6",
                      "#f39c12", "#1abc9c"]

        for i, method in enumerate(methods):
            vals_att = [self.results[method].per_attacker_type.get(a, 0) for a in self.ATTACKER_TYPES]
            offset = (i - n_meth/2 + 0.5) * width
            bars = ax.bar(x + offset, vals_att, width * 0.9,
                         label=method.replace("_", " "),
                         color=att_colors[i % len(att_colors)], alpha=0.85)

        ax.set_title("Defender Value by Attacker Type", fontsize=12, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels([a.replace("_", "\n") for a in self.ATTACKER_TYPES], fontsize=9, color="white")
        ax.axhline(y=0, color="gray", linestyle="-", alpha=0.5)
        ax.legend(fontsize=7, facecolor="#1a1a2e", labelcolor="white")
        ax.set_ylabel("Defender Value", color="white")

        # ----- Plot 5: Robustness Gap -----
        ax = axes[1, 1]
        pess_vals = [self.results[m].pessimistic_value for m in methods]
        opt_vals = [self.results[m].optimistic_value for m in methods]
        x = np.arange(len(methods))
        ax.bar(x, opt_vals, color=clrs, alpha=0.4, label="Optimistic", edgecolor="#555")
        ax.bar(x, pess_vals, color=clrs, alpha=0.9, label="Pessimistic (Robust)", edgecolor="#555")
        ax.set_title("Optimistic vs Pessimistic Value\n(Gap = robustness risk)", fontsize=11, fontweight="bold")
        ax.set_xticks(x)
        ax.set_xticklabels(method_labels, fontsize=9, color="white")
        ax.axhline(y=0, color="gray", linestyle="-", alpha=0.5)
        ax.legend(fontsize=9, facecolor="#1a1a2e", labelcolor="white")
        ax.set_ylabel("Value", color="white")

        # ----- Plot 6: Time to Compromise -----
        ax = axes[1, 2]
        vals = [self.results[m].time_to_compromise for m in methods]
        bars = ax.bar(method_labels, vals, color=clrs, alpha=0.85, edgecolor="#333")
        ax.set_title("Avg Steps to Compromise ↑\n(Higher = Harder for Attacker)", fontsize=11, fontweight="bold")
        ax.set_ylabel("Steps", color="white")
        for bar, v in zip(bars, vals):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1,
                    f"{v:.1f}", ha="center", va="bottom", fontsize=9, color="white")

        # Legend cho colors
        legend_patches = [
            mpatches.Patch(color=colors[m], label=m.replace("_", " ").title())
            for m in methods
        ]
        fig.legend(handles=legend_patches, loc="lower center",
                  ncol=len(methods), fontsize=9,
                  facecolor="#1a1a2e", labelcolor="white",
                  bbox_to_anchor=(0.5, 0.01))

        plt.tight_layout(rect=[0, 0.05, 1, 0.96])

        if save:
            path = os.path.join(self.results_dir, "mirage_benchmark.png")
            plt.savefig(path, dpi=150, bbox_inches="tight",
                       facecolor="#1a1a2e", edgecolor="none")
            print(f"\n✅ Plot saved to: {path}")
        plt.close()

    def save_results_json(self, filename: str = "mirage_benchmark_results.json") -> None:
        """Lưu kết quả ra file JSON."""
        path = os.path.join(self.results_dir, filename)
        data = {}
        for method, result in self.results.items():
            data[method] = {
                "method_name": result.method_name,
                "interception_rate": result.interception_rate,
                "hit_true_goal_rate": result.hit_true_goal_rate,
                "time_to_compromise": result.time_to_compromise,
                "false_positive_cost": result.false_positive_cost,
                "pessimistic_value": result.pessimistic_value,
                "optimistic_value": result.optimistic_value,
                "robustness_gap": result.robustness_gap,
                "total_cost": result.total_cost,
                "security_loss": result.security_loss,
                "portfolio_actions": result.portfolio_actions,
                "cost_model": result.cost_model,
                "per_attacker_type": result.per_attacker_type,
                "runtime_seconds": result.runtime_seconds,
            }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"✅ Results saved to: {path}")

    def run_multi_seed_benchmark(
        self,
        seeds: Optional[List[int]] = None,
        n_episodes: int = 500,
        benchmark_type: str = "a",
        verbose: bool = True,
    ) -> Dict[str, Dict]:
        """
        Chạy benchmark với nhiều seed để có confidence intervals.

        Args:
            seeds: Danh sách seed (mặc định [0..4] = 5 seeds)
            n_episodes: Số episodes mỗi method mỗi seed
            benchmark_type: "a" (entry-point) hoặc "b" (belief-conditioned)
            verbose: In progress

        Returns:
            Dict: {method: {"mean": {...}, "std": {...}, "per_seed": [...]}}
        """
        import numpy as np

        if seeds is None:
            seeds = list(range(10))  # 10 seeds mặc định cho confidence intervals tốt hơn

        label = benchmark_type.upper()
        if verbose:
            print("=" * 70)
            print(f"MIRAGE Multi-Seed Benchmark {label} ({len(seeds)} seeds × {n_episodes} eps)")
            print(f"  Seeds: {seeds}")
            print(f"  Benchmark type: {'Entry-Point (A)' if benchmark_type == 'a' else 'Belief-Conditioned (B)'}")
            print("=" * 70)

        # Dữ liệu tích lũy theo method
        seed_results: Dict[str, List[Dict]] = {m: [] for m in self.METHODS}

        original_seed = self.seed
        original_n = self.n_episodes

        for i, seed in enumerate(seeds):
            if verbose:
                print(f"\n  Seed {seed} ({i+1}/{len(seeds)})...")

            # Tạo evaluator tạm thời với seed này
            self.seed = seed
            self.n_episodes = n_episodes
            self.results = {}

            if benchmark_type == "a":
                self.run_benchmark_a(verbose=False)
            else:
                self.run_benchmark_b(verbose=False)

            for method, result in self.results.items():
                seed_results[method].append({
                    "interception_rate": result.interception_rate,
                    "hit_true_goal_rate": result.hit_true_goal_rate,
                    "time_to_compromise": result.time_to_compromise,
                    "pessimistic_value": result.pessimistic_value,
                    "optimistic_value": result.optimistic_value,
                    "robustness_gap": result.robustness_gap,
                    "total_cost": result.total_cost,
                    "false_positive_cost": result.false_positive_cost,
                    "runtime_seconds": result.runtime_seconds,
                })

            if verbose:
                for m in self.METHODS:
                    r = self.results.get(m)
                    if r:
                        print(f"    {m:22s}: intercept={r.interception_rate:.1%}"
                              f"  pess={r.pessimistic_value:+.4f}"
                              f"  gap={r.robustness_gap:.4f}")

        # Restore original
        self.seed = original_seed
        self.n_episodes = original_n

        # Tính mean ± std cho mỗi method
        metrics = [
            "interception_rate", "hit_true_goal_rate", "time_to_compromise",
            "pessimistic_value", "optimistic_value", "robustness_gap",
            "total_cost", "false_positive_cost", "runtime_seconds",
        ]
        aggregated: Dict[str, Dict] = {}
        for method, runs in seed_results.items():
            if not runs:
                continue
            mean_vals = {}
            std_vals = {}
            for metric in metrics:
                vals = [r[metric] for r in runs]
                mean_vals[metric] = float(np.mean(vals))
                std_vals[metric] = float(np.std(vals))
            aggregated[method] = {
                "mean": mean_vals,
                "std": std_vals,
                "per_seed": runs,
                "n_seeds": len(runs),
            }

        # In bảng tổng hợp
        if verbose:
            print(f"\n{'='*70}")
            print(f"MULTI-SEED RESULTS — Benchmark {label} (mean ± std over {len(seeds)} seeds)")
            print(f"{'='*70}")
            print(
                f"  {'Method':22s} | {'Intercept%':>15s} | {'Pess.Val':>15s} | {'Gap':>12s}"
            )
            print("  " + "-" * 70)
            for method in self.METHODS:
                if method not in aggregated:
                    continue
                d = aggregated[method]
                ir = f"{d['mean']['interception_rate']:.1%}±{d['std']['interception_rate']:.1%}"
                pv = f"{d['mean']['pessimistic_value']:+.4f}±{d['std']['pessimistic_value']:.4f}"
                rg = f"{d['mean']['robustness_gap']:.4f}±{d['std']['robustness_gap']:.4f}"
                flag = " ← MIRAGE" if method == "robust_mirage" else ""
                flag += " ← RL" if method == "standard_rl" else ""
                print(f"  {method:22s} | {ir:>15s} | {pv:>15s} | {rg:>12s}{flag}")
                print(
                    " " * 26
                    + f"hit={d['mean']['hit_true_goal_rate']:.1%}±"
                    f"{d['std']['hit_true_goal_rate']:.1%}, "
                    + f"cost={d['mean']['total_cost']:.3f}±"
                    f"{d['std']['total_cost']:.3f}, "
                    + f"fp={d['mean']['false_positive_cost']:.3f}±"
                    f"{d['std']['false_positive_cost']:.3f}, "
                    + f"runtime={d['mean']['runtime_seconds']:.3f}±"
                    f"{d['std']['runtime_seconds']:.3f}s"
                )

        # Lưu kết quả
        out_file = f"multi_seed_benchmark_{label.lower()}_results.json"
        out_path = os.path.join(self.results_dir, out_file)
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump({
                    "benchmark_type": benchmark_type,
                    "seeds": seeds,
                    "n_episodes": n_episodes,
                    "n_attacker_types": len(self.ATTACKER_TYPES),
                    "attacker_types": self.ATTACKER_TYPES,
                    "results": aggregated,
                }, f, indent=2)
            csv_path = os.path.join(
                self.results_dir,
                f"multi_seed_benchmark_{label.lower()}_results.csv",
            )
            with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(["method", "metric", "mean", "std", "n_seeds"])
                for method, summary in aggregated.items():
                    for metric in metrics:
                        writer.writerow([
                            method,
                            metric,
                            summary["mean"][metric],
                            summary["std"][metric],
                            summary["n_seeds"],
                        ])
            if verbose:
                print(f"\n✅ Multi-seed results saved to: {out_path}")
        except Exception as e:
            print(f"⚠️  Could not save JSON: {e}")

        return aggregated

    def run_ablation_study(self) -> Dict[str, Dict]:
        from mirage.layer3_deception import DeceptionFabric
        from mirage.layer4_decision_engine import RobustDecisionEngine

        belief = dict(self.BENCHMARK_B_BELIEF)
        optimization_episodes = max(30, self.n_episodes // 5)
        evaluation_episodes = max(40, self.n_episodes // 4)
        all_types = list(self.ATTACKER_TYPES)
        without_deception_aware = [
            attacker for attacker in all_types
            if attacker != "deception_aware"
        ]

        variants = [
            {
                "name": "full_mirage",
                "criterion": "cost_aware_robust",
                "belief": belief,
                "allowed": None,
                "cost_model": True,
                "attacker_types": all_types,
            },
            {
                "name": "no_robust_objective",
                "criterion": "expected",
                "belief": belief,
                "allowed": None,
                "cost_model": True,
                "attacker_types": all_types,
            },
            {
                "name": "no_belief",
                "criterion": "cost_aware_robust",
                "belief": None,
                "allowed": None,
                "cost_model": True,
                "attacker_types": all_types,
            },
            {
                "name": "no_edge_cost",
                "criterion": "cost_aware_robust",
                "belief": belief,
                "allowed": [
                    "deploy_decoy_database",
                    "deploy_decoy_router",
                    "scatter_honey_credential",
                ],
                "cost_model": True,
                "attacker_types": all_types,
            },
            {
                "name": "no_deception_variety",
                "criterion": "cost_aware_robust",
                "belief": belief,
                "allowed": ["deploy_decoy_database"],
                "cost_model": True,
                "attacker_types": all_types,
            },
            {
                "name": "no_cost_model",
                "criterion": "cost_aware_robust",
                "belief": belief,
                "allowed": None,
                "cost_model": False,
                "attacker_types": all_types,
            },
            {
                "name": "no_deception_aware",
                "criterion": "cost_aware_robust",
                "belief": belief,
                "allowed": None,
                "cost_model": True,
                "attacker_types": without_deception_aware,
            },
        ]

        print("\n" + "=" * 100)
        print("ABLATION STUDY -- one component disabled per variant")
        print("=" * 100)
        print(
            f"{'Variant':24s} | {'Cost':>7s} | {'Pess':>9s} | "
            f"{'Gap':>8s} | Portfolio actions"
        )
        print("-" * 100)

        results: Dict[str, Dict] = {}
        for variant in variants:
            fabric = DeceptionFabric(self.graph)
            engine = RobustDecisionEngine(
                self.graph,
                fabric,
                n_attacker_samples=optimization_episodes,
                use_robust_milp=False,
                seed=self.seed,
                attacker_types=variant["attacker_types"],
                cost_model_enabled=variant["cost_model"],
            )
            portfolio, _ = engine.optimize_portfolio(
                budget=self.graph.budget,
                belief_state=variant["belief"],
                criterion=variant["criterion"],
                allowed_action_types=variant["allowed"],
                min_actions=1,
            )

            evaluation_engine = RobustDecisionEngine(
                self.graph,
                DeceptionFabric(self.graph),
                n_attacker_samples=evaluation_episodes,
                use_robust_milp=False,
                seed=self.seed,
                attacker_types=all_types,
            )
            evaluation = evaluation_engine._evaluate_portfolio(
                portfolio,
                n_eps=evaluation_episodes,
                belief_state=belief,
                criterion="pure_pessimistic",
            )
            action_ids = [action.action_id for action in portfolio]
            gap = (
                evaluation["optimistic_value"]
                - evaluation["pessimistic_value"]
            )
            row = {
                "portfolio_actions": action_ids,
                "total_cost": evaluation["total_cost"],
                "false_positive_cost": evaluation["false_positive_cost"],
                "pessimistic_value": evaluation["pessimistic_value"],
                "expected_value": evaluation["expected_value"],
                "robustness_gap": gap,
                "margin_guarantee": evaluation["margin_guarantee"],
                "seed": self.seed,
                "episodes": evaluation_episodes,
            }
            results[variant["name"]] = row
            print(
                f"{variant['name']:24s} | {row['total_cost']:7.3f} | "
                f"{row['pessimistic_value']:+9.4f} | {gap:8.4f} | "
                + (", ".join(action_ids) if action_ids else "clean/no-action")
            )

        output_path = os.path.join(self.results_dir, "ablation_results.json")
        with open(output_path, "w", encoding="utf-8") as output:
            json.dump(results, output, indent=2)
        print(f"\nAblation results saved to: {output_path}")
        return results

if __name__ == "__main__":
    from mirage.layer2_attack_graph import build_enterprise_attack_graph

    graph = build_enterprise_attack_graph()
    evaluator = MIRAGEEvaluator(graph, n_episodes=300, seed=42)

    print("Running MIRAGE Full Benchmark...")
    evaluator.run_full_benchmark(verbose=True)

    print("\n")
    evaluator.print_comparison_table()
    evaluator.per_attacker_breakdown()
    evaluator.save_results_json()

    print("\nRunning Ablation Study...")
    evaluator.run_ablation_study()

    print("\nGenerating plots...")
    evaluator.plot_results(save=True)
