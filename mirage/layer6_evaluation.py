"""
MIRAGE - Layer 6: Evaluation, Benchmarks & Visualization
=========================================================
Đo lường và so sánh hiệu quả của MIRAGE với các baseline.

6 phương pháp so sánh:
  1. no_defense        — Không có deception nào
  2. random_deception  — Đặt decoy ngẫu nhiên
  3. static_honeypot   — Honeypot cố định (kinh nghiệm)
  4. greedy_top_k      — Đặt decoy ở node có value cao nhất
  5. standard_rl       — Tối ưu optimistic value (standard RL)
  6. robust_mirage     — MIRAGE: tối ưu pessimistic/robust value

Metrics đo lường:
  - interception_rate     : Tỷ lệ attacker bị dẫn vào decoy
  - time_to_compromise    : Số bước trung bình đến True Goal
  - false_positive_cost   : Chi phí rủi ro vận hành
  - pessimistic_value     : Worst-case defender value
  - optimistic_value      : Best-case defender value
  - robustness_gap        : optimistic - pessimistic (nhỏ hơn = tốt hơn)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import random
import time
import os
import json


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
    per_attacker_type: Dict[str, float] = field(default_factory=dict)
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

    ATTACKER_TYPES = ["random", "greedy", "shortest_path", "stealthy"]

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
        import copy
        graph_copy = copy.deepcopy(self.graph)
        decoy_set = set(graph_copy.decoy_sites)

        for src in graph_copy.states:
            for action in graph_copy.available_actions.get(src, []):
                trans = graph_copy.transitions[src][action]
                decoy_prob = sum(p for ns, p in trans.items() if ns in decoy_set)
                if decoy_prob <= 0:
                    continue  # Không có decoy trong transition này

                # Giữ lại các real neighbors
                real_trans = {ns: p for ns, p in trans.items() if ns not in decoy_set}
                if real_trans:
                    # Phân phối lại decoy_prob theo tỷ lệ vào real nodes
                    total_real = sum(real_trans.values())
                    scale = (total_real + decoy_prob) / total_real
                    graph_copy.transitions[src][action] = {
                        ns: p * scale for ns, p in real_trans.items()
                    }
                else:
                    # Không còn real neighbor → redirect toàn bộ về Sink
                    graph_copy.transitions[src][action] = {
                        graph_copy.sink_state: 1.0
                    }
        return graph_copy

    def _get_reward_interventions_for_method(self, method: str) -> Dict[Tuple, float]:
        """Tạo reward interventions theo phương pháp."""
        from mirage.layer2_attack_graph import DB_FAKE, RTR_FAKE, WS_FIN, SMB_SHARE, SVC_CRED
        rng = random.Random(self.seed)

        if method == "no_defense":
            return {}

        elif method == "random_deception":
            # Đặt decoy ngẫu nhiên
            possible_nodes = [DB_FAKE, RTR_FAKE, WS_FIN, SMB_SHARE, SVC_CRED]
            chosen = rng.choice(possible_nodes)
            return {(chosen, "end"): rng.uniform(0.3, 0.9)}

        elif method == "static_honeypot":
            # Honeypot cố định tại decoy nodes đã biết
            return {
                (DB_FAKE, "end"):  0.7,
                (RTR_FAKE, "end"): 0.5,
            }

        elif method == "greedy_top_k":
            # Đặt decoy ở node có reward potential cao nhất gần True Goal
            return {
                (DB_FAKE, "end"):  0.85,  # Gần True Goal nhất
                (SVC_CRED, "end"): 0.60,  # Credential node có giá trị cao
            }

        elif method == "standard_rl":
            # Standard RL: tối ưu expected value (không quan tâm worst-case)
            # Thường đặt decoy với reward cao nhất có thể
            return {
                (DB_FAKE, "end"):  1.0,   # Maximize expected
                (RTR_FAKE, "end"): 0.8,
                (WS_FIN, "db_access"): 0.5,
            }

        elif method == "robust_mirage":
            # Gọi Layer 4 engine thật để tìm portfolio tối ưu
            # Benchmark sẽ phản ánh đúng những gì hệ thống thực sự làm
            from mirage.layer3_deception import DeceptionFabric
            from mirage.layer4_decision_engine import RobustDecisionEngine

            fabric = DeceptionFabric(self.graph)
            engine = RobustDecisionEngine(
                self.graph, fabric,
                # Dùng ít episodes hơn trong optimization phase
                # (đủ để phân biệt portfolios), evaluation phase sẽ dùng n_episodes đầy đủ
                n_attacker_samples=max(80, self.n_episodes // 6),
                use_robust_milp=False,
            )
            _, portfolio_result = engine.optimize_portfolio(budget=self.graph.budget)
            return portfolio_result.get("combined_interventions", {})

        return {}

    def _compute_metrics_for_method(
        self,
        method: str,
        reward_interventions: Dict,
    ) -> MethodResult:
        """Tính tất cả metrics cho một phương pháp."""
        from mirage.attacker_agents import run_simulation

        t0 = time.time()
        per_attacker: Dict[str, float] = {}
        interception_rates = []
        hit_rates = []
        avg_steps_list = []
        all_defender_values = []

        eps_per_type = max(50, self.n_episodes // len(self.ATTACKER_TYPES))

        import copy

        # ---- no_defense: dùng clean graph không có đường đến decoy ----
        # Đây là baseline thực sự "không phòng thủ" — decoy chưa được deploy,
        # nên không có xác suất structural nào dẫn attacker vào decoy nodes.
        if method == "no_defense":
            graph_copy = self._build_clean_graph_no_defense()
        else:
            # Các phương pháp có deception: dùng graph gốc + boost transitions
            graph_copy = copy.deepcopy(self.graph)
            # Apply interventions bằng cách tăng xác suất đi đến decoy nodes
            for (node, action), delta in reward_interventions.items():
                if node in graph_copy.decoy_sites and delta > 0:
                    # Tăng xác suất attacker đi đến decoy node
                    # (Decoy hấp dẫn hơn → attacker bị dụ nhiều hơn)
                    for src in graph_copy.states:
                        for act in graph_copy.available_actions.get(src, []):
                            if node in graph_copy.transitions[src][act]:
                                old_p = graph_copy.transitions[src][act][node]
                                # Tăng xác suất đến decoy theo strength của intervention
                                boost = min(delta * 0.15, old_p * 0.4)
                                graph_copy.transitions[src][act][node] = old_p + boost
                                # Normalize lại
                                total = sum(graph_copy.transitions[src][act].values())
                                graph_copy.transitions[src][act] = {
                                    k: v/total for k, v in graph_copy.transitions[src][act].items()
                                }

        for atype in self.ATTACKER_TYPES:
            result = run_simulation(
                graph_copy, atype,
                n_episodes=eps_per_type,
                reward_interventions=reward_interventions,
                seed=self.seed,
                max_steps=self.max_steps,
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

        # False positive cost: ước lượng dựa trên số action + chi phí vận hành
        n_actions = len([v for v in reward_interventions.values() if v > 0])
        false_positive_cost = n_actions * 0.05 + hit_true_goal_rate * 0.1

        # Pessimistic = min defender value (worst-case attacker)
        pessimistic_value = min(all_defender_values)
        # Optimistic = max defender value (best-case)
        optimistic_value = max(all_defender_values)
        robustness_gap = optimistic_value - pessimistic_value

        # Chi phí tổng
        total_cost = n_actions * 1.0  # Simplified cost model

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
            per_attacker_type=per_attacker,
            runtime_seconds=runtime,
        )

    def run_full_benchmark(self, verbose: bool = True) -> Dict[str, MethodResult]:
        """
        Chạy benchmark đầy đủ cho tất cả 6 phương pháp.
        """
        if verbose:
            print("=" * 70)
            print("MIRAGE Layer 6 — Full Benchmark")
            print(f"  Episodes per method: {self.n_episodes}")
            print(f"  Attacker types: {self.ATTACKER_TYPES}")
            print("=" * 70)

        for method in self.METHODS:
            if verbose:
                print(f"\n[{method}] Running...")
            interventions = self._get_reward_interventions_for_method(method)
            result = self._compute_metrics_for_method(method, interventions)
            self.results[method] = result
            if verbose:
                print(f"  Interception Rate: {result.interception_rate:.1%}")
                print(f"  True Goal Hit:     {result.hit_true_goal_rate:.1%}")
                print(f"  Pessimistic Val:   {result.pessimistic_value:+.4f}")
                print(f"  Robustness Gap:    {result.robustness_gap:.4f}")

        return self.results

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

        # Tìm best values cho mỗi metric
        best_intercept = max(r.interception_rate for r in self.results.values())
        best_hit = min(r.hit_true_goal_rate for r in self.results.values())
        best_steps = max(r.time_to_compromise for r in self.results.values())
        best_pess = max(r.pessimistic_value for r in self.results.values())
        best_gap = min(r.robustness_gap for r in self.results.values())

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

    def save_results_json(self) -> None:
        """Lưu kết quả ra file JSON."""
        path = os.path.join(self.results_dir, "mirage_benchmark_results.json")
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
                "per_attacker_type": result.per_attacker_type,
                "runtime_seconds": result.runtime_seconds,
            }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"✅ Results saved to: {path}")

    def run_ablation_study(self) -> None:
        """
        Ablation study: each variant ACTUALLY disables one MIRAGE component.

        Changes are made to optimize_portfolio() parameters:
          - criterion: "pessimistic" vs "expected"  -> tests robust objective
          - belief_state=None                        -> tests stage belief
          - allowed_action_types filter              -> tests action diversity / edge cost
        """
        from mirage.attacker_agents import run_simulation
        from mirage.layer3_deception import DeceptionFabric
        from mirage.layer4_decision_engine import RobustDecisionEngine

        print("\n" + "=" * 70)
        print("ABLATION STUDY -- Component Contribution Analysis")
        print("=" * 70)

        # Fixed belief state: lateral movement scenario
        ABLATION_BELIEF = {4: 0.35, 3: 0.25, 6: 0.20, 8: 0.10, 9: 0.10}

        VARIANTS = [
            {
                "name": "Full MIRAGE",
                "criterion": "pessimistic",
                "allowed_types": None,
                "use_belief": True,
                "desc": "All components active",
            },
            {
                "name": "- No Robust Objective",
                "criterion": "expected",
                "allowed_types": None,
                "use_belief": True,
                "desc": "Avg value instead of worst-case -> no robustness guarantee",
            },
            {
                "name": "- No Stage Belief",
                "criterion": "pessimistic",
                "allowed_types": None,
                "use_belief": False,
                "desc": "Simulation from entry point, ignoring attacker location",
            },
            {
                "name": "- No Deception Variety",
                "criterion": "pessimistic",
                "allowed_types": ["deploy_decoy_database"],
                "use_belief": True,
                "desc": "Only Decoy DB -> no honey cred / router / edge cost",
            },
            {
                "name": "- No Edge Cost",
                "criterion": "pessimistic",
                "allowed_types": [
                    "deploy_decoy_database",
                    "deploy_decoy_router",
                    "scatter_honey_credential",
                ],
                "use_belief": True,
                "desc": "Remove INCREASE_EDGE_COST -> reward-only deception (no transition boost from edge)",
            },
            {
                "name": "No Components",
                "criterion": "expected",
                "allowed_types": ["deploy_decoy_database"],
                "use_belief": False,
                "desc": "No robust + no belief + no variety (degenerate baseline)",
            },
        ]

        eps_opt  = max(60, self.n_episodes // 6)
        eps_eval = max(80, self.n_episodes // 4)

        print(
            f"\n{'Variant':28s} | {'Pess.Val':>10s} | {'Exp.Val':>9s}"
            f" | {'Intercept%':>11s} | {'Hit_TG%':>9s} | Portfolio"
        )
        print("-" * 100)

        SHORT = {
            "deploy_decoy_database":     "decoy_db",
            "deploy_decoy_router":       "decoy_rt",
            "scatter_honey_credential":  "honey",
            "increase_edge_cost":        "edge",
        }

        for v in VARIANTS:
            belief = ABLATION_BELIEF if v["use_belief"] else None

            fabric = DeceptionFabric(self.graph)
            engine = RobustDecisionEngine(
                self.graph, fabric,
                n_attacker_samples=eps_opt,
                use_robust_milp=False,
            )

            portfolio, _ = engine.optimize_portfolio(
                budget=self.graph.budget,
                belief_state=belief,
                criterion=v["criterion"],
                allowed_action_types=v["allowed_types"],
            )

            if portfolio:
                # Evaluate with neutral belief + pessimistic criterion for fair comparison
                eval_r = engine._evaluate_portfolio(
                    portfolio, n_eps=eps_eval,
                    belief_state=None,
                    criterion="pessimistic",
                )
                pess     = eval_r["pessimistic_value"]
                exp_val  = eval_r["expected_value"]
                combined = eval_r["combined_interventions"]

                raw_ic, raw_ht = [], []
                for atype in self.ATTACKER_TYPES:
                    res = run_simulation(
                        self.graph, atype,
                        n_episodes=max(eps_eval // 4, 20),
                        reward_interventions=combined,
                        seed=self.seed,
                    )
                    raw_ic.append(res["decoy_interception_rate"])
                    raw_ht.append(res["hit_true_goal_rate"])
                ic_pct = sum(raw_ic) / len(raw_ic)
                ht_pct = sum(raw_ht) / len(raw_ht)

                port_desc = "+".join(
                    SHORT.get(a.action_type.value, a.action_type.value[:8])
                    for a in portfolio[:3]
                )
                if len(portfolio) > 3:
                    port_desc += f"+{len(portfolio)-3}more"
            else:
                pess, exp_val, ic_pct, ht_pct, port_desc = -2.0, -2.0, 0.0, 1.0, "empty"

            flag = " <- FULL" if v["name"] == "Full MIRAGE" else ""
            print(
                f"{v['name']:28s} | {pess:+10.4f} | {exp_val:+9.4f}"
                f" | {ic_pct:>10.1%} | {ht_pct:>8.1%} | {port_desc}{flag}"
            )
            print(f"  +-- {v['desc']}")

        print()


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
