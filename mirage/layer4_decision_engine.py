"""
MIRAGE - Layer 4: Robust Portfolio / Game-Theoretic Decision Engine
=============================================================
"Bộ não" của MIRAGE — tối ưu worst-case (pessimistic) defender value
dưới nhiều biến thể attacker khác nhau.

This is not a PPO/DQN-style deep RL agent. It is a simulation-based robust
portfolio optimizer with MDP/game-theoretic value estimates inspired by the
Robust Reward Design paper.

Thuật toán:
  - Kế thừa Robust Reward Design từ codebase gốc (max-margin MILP)
  - Ánh xạ x_alloc → DeceptionAction thực tế
  - Output có cấu trúc: action plan với giải thích, risk, confidence

Workflow tại mỗi time step:
  1. Nhận belief state từ Layer 2
  2. Tính expected/pessimistic value cho mỗi action
  3. Loại action vi phạm safety (Layer 5)
  4. Chọn action tối ưu pessimistic value
  5. Gửi plan có cấu trúc xuống Layer 5
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import time

from mirage.layer2_attack_graph import MIRAGEAttackGraph
from mirage.layer3_deception import DeceptionAction, DeceptionFabric, DeceptionActionType
from mirage.mdp_solver import (
    MDPSolver,
    compute_composite_cost,
    compute_portfolio_cost,
    rank_action_candidates,
)


# ---------------------------------------------------------------------------
# Decision Plan Output
# ---------------------------------------------------------------------------

@dataclass
class ActionPlan:
    """
    Output có cấu trúc từ Decision Engine.
    Mỗi plan bao gồm:
    - action: Hành động được đề xuất (action quan trọng nhất trong portfolio)
    - portfolio: Toàn bộ tập actions được chọn (có thể nhiều action)
    - giải thích chi tiết
    - expected values (tính trên toàn portfolio)
    - risk & confidence
    - rollback plan
    """
    action: DeceptionAction
    target_node: int
    target_node_label: str

    # Giá trị kỳ vọng (tính trên TOÀN BỘ portfolio)
    optimistic_value: float
    pessimistic_value: float
    expected_value: float
    margin_guarantee: float  # c* từ Paper

    # Rủi ro & Độ tin cậy
    risk_score: float
    confidence: float
    required_approval: bool

    # Giải thích (cho SOC analysts)
    reasoning: str
    evidence: List[str]
    rollback_plan: str

    # Metrics cần theo dõi sau khi triển khai
    monitoring_metrics: List[str]

    # ---- Portfolio fields ----
    # Tập toàn bộ actions được chọn (bao gồm action chính)
    portfolio: List[DeceptionAction] = field(default_factory=list)
    portfolio_cost: float = 0.0
    false_positive_cost: float = 0.0
    cost_adjusted_value: float = 0.0
    portfolio_interventions: Dict = field(default_factory=dict)
    per_attacker_values: Dict[str, float] = field(default_factory=dict)

    # Thông tin bổ sung
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return {
            "action_type": self.action.action_type.value,
            "target_node": self.target_node,
            "target_node_label": self.target_node_label,
            "optimistic_value": round(self.optimistic_value, 4),
            "pessimistic_value": round(self.pessimistic_value, 4),
            "expected_value": round(self.expected_value, 4),
            "margin_guarantee": round(self.margin_guarantee, 4),
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 3),
            "required_approval": self.required_approval,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "rollback_plan": self.rollback_plan,
            "monitoring_metrics": self.monitoring_metrics,
            "portfolio_size": len(self.portfolio),
            "portfolio_cost": round(self.portfolio_cost, 2),
            "false_positive_cost": round(self.false_positive_cost, 3),
            "cost_adjusted_value": round(self.cost_adjusted_value, 4),
            "portfolio_actions": [a.action_id for a in self.portfolio],
        }

    def __str__(self) -> str:
        approval_str = "⚠️ REQUIRES HUMAN APPROVAL" if self.required_approval else "✅ Auto-approved"
        portfolio_lines = ""
        if self.portfolio:
            portfolio_lines = "\nPortfolio:\n" + "\n".join(
                f"  [{i+1}] {a.action_type.value:35s} -> Node {a.target_node:2d} "
                f"| base_cost={a.cost:.1f} | risk={a.risk_score:.2f}"
                for i, a in enumerate(self.portfolio)
            )
            portfolio_lines += f"\nTotal portfolio cost: {self.portfolio_cost:.1f}\n"
        per_att = ""
        if self.per_attacker_values:
            per_att = "\nPer-attacker defender values:\n" + "\n".join(
                f"  {atype:15s}: {val:+.4f}"
                for atype, val in sorted(self.per_attacker_values.items())
            )
        return (
            f"\n{'='*65}\n"
            f"🤖 MIRAGE Decision Plan (Portfolio)\n"
            f"{'='*65}\n"
            f"Primary Action: {self.action.action_type.value}\n"
            f"Target:         Node {self.target_node} — {self.target_node_label}\n"
            f"{'─'*65}"
            f"{portfolio_lines}"
            f"{per_att}\n"
            f"{'─'*65}\n"
            f"Opt. Value:  {self.optimistic_value:+.4f}  (Best case for defender)\n"
            f"Pess. Value: {self.pessimistic_value:+.4f}  (Worst case — ROBUST target)\n"
            f"Exp. Value:  {self.expected_value:+.4f}  (Average case)\n"
            f"Margin (c*): {self.margin_guarantee:+.4f}  (Provable improvement over no-defense)\n"
            f"{'─'*65}\n"
            f"Risk:        {self.risk_score:.2f} / 1.0\n"
            f"Confidence:  {self.confidence:.1%}\n"
            f"Approval:    {approval_str}\n"
            f"{'─'*65}\n"
            f"Reasoning:   {self.reasoning}\n"
            f"Evidence:\n" +
            "\n".join(f"  • {e}" for e in self.evidence) +
            f"\nRollback:    {self.rollback_plan}\n"
            f"Monitor:     {', '.join(self.monitoring_metrics)}\n"
        )


# ---------------------------------------------------------------------------
# Robust Decision Engine
# ---------------------------------------------------------------------------

class RobustDecisionEngine:
    """
    Lớp 4: Bộ não ra quyết định Robust.
    
    Tối ưu pessimistic defender value bằng cách:
    1. Đánh giá mỗi DeceptionAction qua nhiều loại attacker, kể cả MITRE evasion
    2. Chọn action có pessimistic_value cao nhất (robust to worst-case)
    3. Ánh xạ kết quả toán học → ActionPlan có thể thực thi
    """

    # Six attacker profiles shared by optimization and evaluation.
    ALL_ATTACKER_TYPES = [
        "random",
        "greedy",
        "shortest_path",
        "stealthy",
        "deception_aware",
        "mitre_evasion",
    ]

    def __init__(
        self,
        graph: MIRAGEAttackGraph,
        fabric: DeceptionFabric,
        n_attacker_samples: int = 200,
        use_robust_milp: bool = True,
        seed: int = 42,
        operational_cost_weight: float = 0.015,
        false_positive_weight: float = 0.05,
        expected_value_weight: float = 0.25,
        margin_weight: float = 0.20,
        attacker_types: Optional[List[str]] = None,
        approximate_mode: bool = False,
        cost_model_enabled: bool = True,
    ):
        self.graph = graph
        self.fabric = fabric
        self.n_attacker_samples = n_attacker_samples
        # Kept for API compatibility. The external MILP package was removed;
        # exact MDP math and robust simulation are now fully in-package.
        self.use_robust_milp = False
        self.seed = seed
        self.operational_cost_weight = operational_cost_weight
        self.false_positive_weight = false_positive_weight
        self.expected_value_weight = expected_value_weight
        self.margin_weight = margin_weight
        self.attacker_types = list(attacker_types or self.ALL_ATTACKER_TYPES)
        self.approximate_mode = approximate_mode
        self.cost_model_enabled = cost_model_enabled
        self._decision_history: List[ActionPlan] = []
        self._evaluation_cache: Dict[Tuple, Dict] = {}
        
        # Exact MDP Math Solver
        self.mdp_solver = MDPSolver(graph)

    def _run_attacker_simulation(
        self,
        action: DeceptionAction,
        n_episodes: int = 200,
    ) -> Dict[str, float]:
        """
        Chạy simulation với tất cả loại attacker để tính pessimistic value.
        Pessimistic value = defender value khi attacker chọn strategy bất lợi nhất.
        """
        from mirage.attacker_agents import run_simulation
        from mirage.layer2_attack_graph import build_runtime_graph

        # Tạo reward interventions từ action
        reward_interventions = {}
        if action.action_type in [
            DeceptionActionType.DEPLOY_DECOY_DATABASE,
            DeceptionActionType.DEPLOY_DECOY_ROUTER,
        ]:
            reward_interventions[(action.target_node, "end")] = action.reward_delta

        elif action.action_type == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
            reward_interventions[(action.target_node, "cred_dump")] = action.reward_delta * 0.5
            reward_interventions[(action.target_node, "end")] = action.reward_delta * 0.3

        # Defender value function:
        # +1 nếu attacker đến decoy, -2 nếu attacker đến true goal
        attacker_types = self.ALL_ATTACKER_TYPES
        defender_values = []
        runtime_graph = build_runtime_graph(self.graph, actions=[action])

        for atype in attacker_types:
            result = run_simulation(
                runtime_graph, atype,
                n_episodes=n_episodes // len(attacker_types),
                reward_interventions=reward_interventions,
                seed=self.seed,
            )
            # Tính defender value từ kết quả
            decoy_rate = result["decoy_interception_rate"]
            true_goal_rate = result["hit_true_goal_rate"]
            avg_steps = result["avg_steps_to_terminal"]

            # Defender value = reward khi attacker đi vào decoy - penalty khi họ đến true goal
            # Cộng thêm delay bonus (càng kéo dài thì càng tốt cho defender)
            defender_val = (
                decoy_rate * 1.0           # Reward: attacker vào decoy
                - true_goal_rate * 2.0     # Penalty: attacker đến true goal
                + (avg_steps / 30.0) * 0.2 # Bonus: kéo dài thời gian
            )
            defender_values.append(defender_val)

        return {
            "optimistic_value":  max(defender_values),
            "pessimistic_value": min(defender_values),   # Worst-case!
            "expected_value":    sum(defender_values) / len(defender_values),
            "per_attacker":      dict(zip(attacker_types, defender_values)),
            "reward_interventions": reward_interventions,
        }

    def evaluate_action(self, action: DeceptionAction) -> Dict:
        """(Legacy) Đánh giá một action đơn lẻ qua simulation."""
        return self._run_attacker_simulation(action, self.n_attacker_samples)

    # ---------------------------------------------------------------------------
    # Portfolio Optimization (mới)
    # ---------------------------------------------------------------------------

    def _action_cost(self, action: DeceptionAction) -> float:
        """Composite budget cost used by optimizer and safety accounting."""
        return compute_composite_cost(action, self.graph).total

    def _portfolio_cost_report(self, actions: List[DeceptionAction]) -> Dict[str, object]:
        """Composite portfolio cost with false-positive component."""
        return compute_portfolio_cost(actions, self.graph)

    def _merge_interventions(
        self, actions: List[DeceptionAction],
        belief_state: Optional[Dict[int, float]] = None
    ) -> Dict:
        """
        Kết hợp reward interventions từ nhiều actions thành một dict dùng cho simulation.

        Quy tắc kết hợp:
        - DEPLOY_DECOY_*: ghi nhận (node, "end") -> reward_delta (lấy max nếu trùng node)
        - SCATTER_HONEY_CREDENTIAL: ghi nhận cả (node, "cred_dump") và (node, "end")
        - INCREASE_EDGE_COST trên đường thật: ghi nhận vào edge_cost_edits để
          _evaluate_portfolio áp dụng lên graph_copy transitions.
          Không còn model bằng reward nhỏ nữa — tác động trực tiếp lên xác suất.
        """
        merged: Dict = {}
        self._edge_cost_edits: List[Tuple] = []  # [(src, dst, delta), ...]

        for action in actions:
            atype = action.action_type

            if atype in (
                DeceptionActionType.DEPLOY_DECOY_DATABASE,
                DeceptionActionType.DEPLOY_DECOY_ROUTER,
            ):
                key = (action.target_node, "end")
                # Tất cả reward cộng dồn (nhiều decoy cùng loại tại các node khác nhau)
                merged[key] = merged.get(key, 0.0) + action.reward_delta

            elif atype == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
                k_cred = (action.target_node, "cred_dump")
                k_end  = (action.target_node, "end")
                merged[k_cred] = merged.get(k_cred, 0.0) + action.reward_delta * 0.5
                merged[k_end]  = merged.get(k_end,  0.0) + action.reward_delta * 0.3

            elif atype == DeceptionActionType.INCREASE_EDGE_COST:
                # Ghi nhận cảnh cần giảm xác suất — sẽ được apply trong _evaluate_portfolio
                if action.target_edge:
                    src, dst = action.target_edge
                    self._edge_cost_edits.append((src, dst, action.edge_cost_delta))

        # Scale by occupancy measure (Robust Reward Design paper)
        return self.mdp_solver.allocate_reward_by_occupancy(
            raw_interventions=merged,
            start_distribution=belief_state
        )

    def _evaluate_portfolio(
        self,
        actions: List[DeceptionAction],
        n_eps: int = 50,
        belief_state: Optional[Dict[int, float]] = None,
        criterion: str = "cost_aware_robust",
    ) -> Dict:
        """
        Đánh giá hiệu quả của một portfolio actions.

        Deception hoạt động qua HAI kênh đồng thời:
          Channel 1 — Reward: reward_interventions thêm fake reward tại decoy nodes.
            Tác dụng: attacker dạng greedy/stealthy bị thu hút.
          Channel 2 — Transition: tăng xác suất attacker "land" tại decoy node.
            Tác dụng: ảnh hưởng ALL attacker types, kể cả shortest_path.

        Args:
            criterion: Tiêu chí chọn portfolio:
              "pessimistic" — min value (full MIRAGE, worst-case robust)
              "expected"    — avg value (standard RL, không có robust term)
              "optimistic"  — max value (best-case)
        """
        from mirage.attacker_agents import run_simulation
        from mirage.layer2_attack_graph import build_runtime_graph

        cache_key = (
            tuple(sorted(action.action_id for action in actions)),
            int(n_eps),
            tuple(sorted((belief_state or {}).items())),
            criterion,
            tuple(self.attacker_types),
            self.cost_model_enabled,
            self.approximate_mode,
        )
        if cache_key in self._evaluation_cache:
            return self._evaluation_cache[cache_key]

        combined = self._merge_interventions(actions, belief_state=belief_state)
        edge_cost_edits = getattr(self, "_edge_cost_edits", [])
        graph_copy = build_runtime_graph(
            self.graph,
            actions=actions,
            edge_cost_edits=edge_cost_edits,
        )
        clean_graph = build_runtime_graph(self.graph, actions=[])

        attacker_types = self.attacker_types
        defender_values: Dict[str, float] = {}

        for atype in attacker_types:
            result = run_simulation(
                graph_copy, atype,          # Dùng graph đã modified (cả 2 kênh)
                n_episodes=max(n_eps, 6 if self.approximate_mode else 20),
                reward_interventions=combined,  # Channel 1: reward bait
                seed=self.seed,
                start_distribution=belief_state,
            )
            d_val = (
                result["decoy_interception_rate"] * 1.0
                - result["hit_true_goal_rate"] * 2.0
                + (result["avg_steps_to_terminal"] / 30.0) * 0.2
            )
            defender_values[atype] = d_val

        # ---- Exact MDP Evaluation (Robust Reward Design Paper) ----
        # Giải bài toán bằng toán học chính xác thay vì chỉ mô phỏng
        mdp_solver = MDPSolver(graph_copy)
        mdp_baseline_graph = clean_graph
        mdp_interventions = combined
        mdp_belief = belief_state
        if len(self.graph.states) > 120:
            from mirage.mdp_solver import build_hierarchical_subgraph, prune_action_space

            focus = set(prune_action_space(
                graph_copy,
                belief_state,
                top_k_states=min(60, max(20, int(len(self.graph.states) ** 0.5))),
            ))
            for action in actions:
                focus.add(action.target_node)
                if action.target_edge:
                    focus.update(action.target_edge)
            subgraph = build_hierarchical_subgraph(graph_copy, sorted(focus))
            baseline_subgraph = build_hierarchical_subgraph(clean_graph, sorted(focus))
            mdp_solver = MDPSolver(subgraph)
            mdp_baseline_graph = baseline_subgraph
            sub_states = set(subgraph.states)
            mdp_interventions = {
                key: value
                for key, value in combined.items()
                if key[0] in sub_states
            }
            if belief_state:
                mdp_belief = {
                    s: p for s, p in belief_state.items()
                    if s in sub_states
                }
                total_belief = sum(mdp_belief.values())
                if total_belief > 0:
                    mdp_belief = {s: p / total_belief for s, p in mdp_belief.items()}
                else:
                    mdp_belief = None

        exact_results = mdp_solver.evaluate_defense_exact(
            reward_interventions=mdp_interventions,
            start_distribution=mdp_belief,
            baseline_graph=mdp_baseline_graph,
        )
        
        mdp_pess = exact_results["V_robust"]
        mdp_exp = exact_results["V_uniform"]
        mdp_opt = exact_results["V_greedy"]
        margin_guarantee = exact_results["margin_guarantee"]

        # ---- Hybrid Evaluation (60% Exact MDP, 40% Simulation) ----
        # Lấy lợi thế cả về toán học (robust guarantee) và thực tiễn (edge dynamics)
        sim_values = list(defender_values.values())
        sim_pess = min(sim_values)
        sim_opt = max(sim_values)
        sim_exp = sum(sim_values) / len(sim_values)

        hybrid_pess = 0.6 * mdp_pess + 0.4 * sim_pess
        hybrid_exp = 0.6 * mdp_exp + 0.4 * sim_exp
        hybrid_opt = 0.6 * mdp_opt + 0.4 * sim_opt

        # Tính tổng composite cost cho portfolio
        cost_report = self._portfolio_cost_report(actions)
        total_cost = float(cost_report["total"])
        fp_cost = float(cost_report["false_positive_cost"])

        criterion = {
            "pessimistic": "cost_aware_robust",
            "robust": "cost_aware_robust",
        }.get(criterion, criterion)
        cost_penalty = 0.0
        if self.cost_model_enabled:
            cost_penalty = (
                self.operational_cost_weight * total_cost
                + self.false_positive_weight * fp_cost
            )

        if criterion == "expected":
            objective_value = hybrid_exp
            selection_value = objective_value - cost_penalty
        elif criterion == "pure_pessimistic":
            objective_value = hybrid_pess
            selection_value = objective_value
        elif criterion == "optimistic":
            objective_value = hybrid_opt
            selection_value = objective_value - cost_penalty
        elif criterion == "cost_aware_robust":
            objective_value = (
                hybrid_pess
                + self.expected_value_weight * hybrid_exp
                + self.margin_weight * margin_guarantee
            )
            selection_value = objective_value - cost_penalty
        else:
            raise ValueError(
                "criterion must be one of: expected, pure_pessimistic, "
                "cost_aware_robust"
            )

        evaluation = {
            "pessimistic_value": hybrid_pess,
            "optimistic_value":  hybrid_opt,
            "expected_value":    hybrid_exp,
            "objective_value":   objective_value,
            "selection_value":   selection_value,
            "cost_penalty":      cost_penalty,
            "margin_guarantee":  margin_guarantee,
            "per_attacker":      defender_values,
            "combined_interventions": combined,
            "edge_cost_edits":   self._edge_cost_edits.copy(),
            "total_cost":        total_cost,
            "false_positive_cost": fp_cost,
            "cost_breakdown":    cost_report,
        }
        self._evaluation_cache[cache_key] = evaluation
        return evaluation

    def optimize_portfolio(
        self,
        budget: float,
        safety_filter=None,
        belief_state: Optional[Dict[int, float]] = None,
        criterion: str = "cost_aware_robust",
        allowed_action_types: Optional[List[str]] = None,
        max_candidates: Optional[int] = None,
        min_actions: int = 0,
        max_portfolio_size: Optional[int] = None,
    ):
        """
        Tìm portfolio tối ưu dưới budget constraint.

        Args:
            criterion: Tiêu chí chọn portfolio:
              "pessimistic" — maximize worst-case value (full MIRAGE robust)
              "expected"    — maximize average value (no robust term, standard RL)
              "optimistic"  — maximize best-case value
            allowed_action_types: Nếu có, chỉ cho phép các loại action này.
              Dùng cho ablation study để thử vực action catalog.
            belief_state: Phân phối xác suất attacker location từ Layer 1/2.

        Algorithms: Greedy forward + Local swap.
        """
        available = self.fabric.get_available_actions(budget)

        # Lọc theo loại action (cho ablation study)
        if allowed_action_types:
            available = [
                a for a in available
                if a.action_type.value in allowed_action_types
            ]

        # Scale-aware pruning: focus on belief/topology hotspots, then keep a
        # bounded ranked candidate set before expensive simulation.
        if len(self.graph.states) > 30:
            from mirage.mdp_solver import prune_action_space

            top_k = min(80, max(20, int(len(self.graph.states) ** 0.5) * 2))
            hotspots = set(prune_action_space(self.graph, belief_state, top_k_states=top_k))
            available = [
                a for a in available
                if (
                    a.target_node in hotspots
                    or (
                        a.target_edge
                        and (a.target_edge[0] in hotspots or a.target_edge[1] in hotspots)
                    )
                )
            ]

        if max_candidates is None:
            max_candidates = 80 if len(self.graph.states) > 250 else 60
            if len(self.graph.states) <= 30:
                max_candidates = None
        available = rank_action_candidates(
            available,
            self.graph,
            belief_state=belief_state,
            limit=max_candidates,
        )

        if not available:
            return [], self._evaluate_portfolio(
                [],
                n_eps=6 if self.approximate_mode else 20,
                belief_state=belief_state,
                criterion=criterion,
            )

        # Độ phân giải episodes: đủ để phân biệt portfolios mà không quá chậm
        # Với 5 attacker types cần nhiều episodes hơn để có signal đủ mạnh
        if self.approximate_mode:
            eps_per_eval = max(6, min(12, self.n_attacker_samples // 8))
        elif len(self.graph.states) > 120:
            eps_per_eval = max(25, min(60, self.n_attacker_samples // 4))
        else:
            eps_per_eval = max(60, self.n_attacker_samples // 2)

        print(f"\n[INFO] [Portfolio Optimizer] {len(available)} candidate actions, "
              f"budget={budget:.1f}, {eps_per_eval} eps/eval, criterion={criterion}"
              + (" | belief-conditioned" if belief_state else " | from entry point"))

        # --------------- Pha 1: Greedy forward ----------------
        portfolio: List[DeceptionAction] = []
        remaining_budget = budget
        candidates = list(available)
        current_result: Dict = self._evaluate_portfolio(
            [],
            n_eps=max(20, eps_per_eval // 2),
            belief_state=belief_state,
            criterion=criterion,
        )

        while candidates:
            if max_portfolio_size is not None and len(portfolio) >= max_portfolio_size:
                break
            best_candidate = None
            best_sel_val = float("-inf")
            best_result: Dict = {"pessimistic_value": float("-inf"),
                                  "selection_value":  float("-inf")}

            for action in candidates:
                action_cost = self._action_cost(action)
                if action_cost > remaining_budget:
                    continue
                trial_result = self._evaluate_portfolio(
                    portfolio + [action], n_eps=eps_per_eval,
                    belief_state=belief_state,
                    criterion=criterion,
                )
                if trial_result["selection_value"] > best_sel_val:
                    best_sel_val = trial_result["selection_value"]
                    best_result = trial_result
                    best_candidate = action

            if best_candidate is None:
                break

            if (
                best_result["selection_value"] > current_result["selection_value"]
                or len(portfolio) < min_actions
            ):
                portfolio.append(best_candidate)
                candidates.remove(best_candidate)
                remaining_budget -= self._action_cost(best_candidate)
                current_result = best_result
                print(f"  + Add: {best_candidate.action_type.value} @ Node {best_candidate.target_node} "
                      f"| sel={best_result['selection_value']:+.4f} "
                      f"| pess={best_result['pessimistic_value']:+.4f} "
                      f"| budget_left={remaining_budget:.1f}")
            else:
                candidates.remove(best_candidate)
                print(f"  ~ Skip: {best_candidate.action_type.value} @ Node {best_candidate.target_node} "
                      f"(sel={best_result['selection_value']:+.4f} <= current {current_result['selection_value']:+.4f})")

        # --------------- Pha 2: Local swap ----------------
        print(f"  Phase 2: Local swap on portfolio of {len(portfolio)} actions "
              f"(criterion={criterion})...")
        outside = [a for a in available if a not in portfolio]
        improved = True
        while improved:
            improved = False
            for i, in_action in enumerate(portfolio):
                for out_action in outside:
                    # Kiểm tra budget nếu hoán đổi
                    new_cost = current_result["total_cost"] \
                        - self._action_cost(in_action) + self._action_cost(out_action)
                    if new_cost > budget:
                        continue
                    trial_portfolio = portfolio[:i] + [out_action] + portfolio[i+1:]
                    trial_result = self._evaluate_portfolio(
                        trial_portfolio, n_eps=eps_per_eval,
                        belief_state=belief_state,
                        criterion=criterion,
                    )
                    if trial_result["selection_value"] > current_result["selection_value"] + 1e-4:
                        portfolio = trial_portfolio
                        outside[outside.index(out_action)] = in_action
                        current_result = trial_result
                        improved = True
                        print(f"  ~ Swap: {in_action.action_type.value} -> "
                              f"{out_action.action_type.value} @ Node {out_action.target_node} "
                              f"| pess={trial_result['pessimistic_value']:+.4f}")
                        break
                if improved:
                    break

        # Re-evaluate portfolio cuối cùng với độ chính xác cao hơn
        if portfolio:
            final_result = self._evaluate_portfolio(
                portfolio,
                n_eps=max(50, self.n_attacker_samples // 4),
                belief_state=belief_state,
                criterion=criterion,
            )
        else:
            final_result = current_result

        total_cost = float(self._portfolio_cost_report(portfolio)["total"])
        print(f"  [OK] Optimal portfolio: {len(portfolio)} actions, "
              f"cost={total_cost:.1f}/{budget:.1f}, "
              f"pess={final_result['pessimistic_value']:+.4f}, "
              f"opt={final_result['optimistic_value']:+.4f}")

        return portfolio, final_result

    def decide(
        self,
        belief_state: Dict[int, float],
        stage_context: Optional[Dict] = None,
        budget_remaining: float = 4.0,
        safety_filter=None,  # Layer 5 safety gate
    ) -> Optional[ActionPlan]:
        """
        Ra quyết định chính: chọn portfolio tối ưu theo pessimistic value.

        Upgraded từ: chọn 1 action tốt nhất
        Thành:          chọn tập action tối ưu dưới budget (portfolio optimization)

        Args:
            belief_state: Phân phối xác suất attacker location
            stage_context: Stage information từ Layer 1
            budget_remaining: Ngân sách còn lại
            safety_filter: Layer 5 function kiểm tra an toàn

        Returns:
            ActionPlan với portfolio đầy đủ, hoặc None nếu không có action an toàn
        """
        print("\n[*] [Decision Engine] Running portfolio optimization...")

        # Log belief state nếu có — cho thấy thông tin đã được dùng
        if belief_state:
            top_nodes = sorted(belief_state.items(), key=lambda x: x[1], reverse=True)[:3]
            belief_summary = ", ".join(
                f"Node{s}({self.graph.label(s)})={p:.1%}"
                for s, p in top_nodes if p > 0.01
            )
            print(f"  [>] Belief state (top nodes): {belief_summary}")

        # ---- Chạy portfolio optimizer với belief_state ----
        # belief_state được dùng làm start_distribution trong simulation:
        # mỗi episode sẽ sample vị trí bắt đầu từ phân phối này → value phản ánh
        # thực tế attacker đang ở đâu, không phải luôn từ entry point.
        portfolio, portfolio_result = self.optimize_portfolio(
            budget=budget_remaining,
            safety_filter=safety_filter,
            belief_state=belief_state,
            criterion="cost_aware_robust",
            min_actions=1,
        )

        if not portfolio:
            print("  [!] No feasible portfolio found within budget.")
            return None

        # ---- Chọn primary action (action quan trọng nhất trong portfolio) ----
        # Ƭu tiên: DEPLOY_DECOY_DATABASE > DEPLOY_DECOY_ROUTER > HONEY_CRED > EDGE_COST
        priority_order = [
            DeceptionActionType.DEPLOY_DECOY_DATABASE,
            DeceptionActionType.DEPLOY_DECOY_ROUTER,
            DeceptionActionType.SCATTER_HONEY_CREDENTIAL,
            DeceptionActionType.INCREASE_EDGE_COST,
        ]
        primary_action = portfolio[0]
        for atype in priority_order:
            match = next((a for a in portfolio if a.action_type == atype), None)
            if match:
                primary_action = match
                break

        # ---- Xây dựng evidence & reasoning ----
        evidence = self._build_evidence(belief_state, stage_context, primary_action)
        milp_result = None
        cost_report = portfolio_result.get("cost_breakdown") or self._portfolio_cost_report(portfolio)
        false_positive_cost = float(cost_report.get("false_positive_cost", 0.0))
        total_operational_cost = float(cost_report.get("total", portfolio_result.get("total_cost", 0.0)))

        needs_approval = any(
            a.risk_score > 0.3 or a.business_impact > 0.1
            for a in portfolio
        ) or portfolio_result["pessimistic_value"] < -0.5 or false_positive_cost > 0.8

        gap = portfolio_result["optimistic_value"] - portfolio_result["pessimistic_value"]
        confidence = max(0.5, 1.0 - gap * 0.5)

        plan = ActionPlan(
            action=primary_action,
            target_node=primary_action.target_node,
            target_node_label=self.graph.label(primary_action.target_node),
            optimistic_value=portfolio_result["optimistic_value"],
            pessimistic_value=portfolio_result["pessimistic_value"],
            expected_value=portfolio_result["expected_value"],
            margin_guarantee=portfolio_result.get("margin_guarantee", 0.0),
            risk_score=max(a.risk_score for a in portfolio),
            confidence=confidence,
            required_approval=needs_approval,
            reasoning=self._build_reasoning(
                primary_action, portfolio_result, belief_state, milp_result,
                portfolio_size=len(portfolio),
            ),
            evidence=evidence,
            rollback_plan=" | ".join(a.rollback_plan for a in portfolio),
            monitoring_metrics=self._build_monitoring_metrics(primary_action),
            # Portfolio fields
            portfolio=portfolio,
            portfolio_cost=total_operational_cost,
            false_positive_cost=false_positive_cost,
            cost_adjusted_value=portfolio_result.get("selection_value", 0.0),
            portfolio_interventions=portfolio_result["combined_interventions"],
            per_attacker_values=portfolio_result.get("per_attacker", {}),
        )

        # Kiểm tra safety gate (Layer 5) trên primary action
        if safety_filter is not None:
            safe, warning = safety_filter(plan)
            if not safe:
                print(f"  [BLOCKED] Portfolio blocked by Safety Gate: {warning}")
                return None

        self._decision_history.append(plan)
        print(f"  [OK] Portfolio selected: {len(portfolio)} actions "
              f"| total_cost={plan.portfolio_cost:.1f} "
              f"| Pess.Val={portfolio_result['pessimistic_value']:+.4f}")
        return plan

    def _build_evidence(
        self,
        belief_state: Dict[int, float],
        stage_context: Optional[Dict],
        action: DeceptionAction,
    ) -> List[str]:
        """Xây dựng danh sách evidence để giải thích quyết định."""
        evidence = []

        # Top likely locations
        if belief_state:
            top3 = sorted(belief_state.items(), key=lambda x: -x[1])[:3]
            locs = [f"Node {s} ({self.graph.label(s)}): {p:.1%}" for s, p in top3]
            evidence.append(f"Likely attacker locations: {', '.join(locs)}")

        # Stage context
        if stage_context:
            evidence.append(f"Detected attack stage: {stage_context.get('stage', 'Unknown')} "
                          f"(conf={stage_context.get('confidence', 0):.1%})")

        # High-risk paths crossing target node
        for i, path in enumerate(self.graph.get_high_risk_paths(), 1):
            if action.target_node in path:
                path_str = " -> ".join(self.graph.label(n) for n in path)
                evidence.append(f"Target node on high-risk Path {i}: {path_str}")

        # Node metadata
        meta = self.graph.get_node_info(action.target_node)
        if meta:
            evidence.append(
                f"Target node type: {meta.get('asset_type', 'unknown')} "
                f"| Layer: {meta.get('layer', 'unknown')} "
                f"| Value: {meta.get('value', 0):.1f}"
            )

        return evidence

    def _build_reasoning(
        self,
        action: DeceptionAction,
        result: Dict,
        belief_state: Dict[int, float],
        milp_result: Optional[Dict],
        portfolio_size: int = 1,
    ) -> str:
        """Xây dựng giải thích bằng tiếng Anh cho SOC analyst."""
        action_name = action.action_type.value.replace("_", " ").title()
        node_label = self.graph.label(action.target_node)

        reasoning = (
            f"{action_name} at {node_label} (primary action in portfolio of {portfolio_size}). "
            f"Pessimistic defender value: {result['pessimistic_value']:+.4f} "
            f"(worst-case across all attacker strategies). "
        )

        if result["pessimistic_value"] > 0:
            reasoning += "Positive pessimistic value means this action is beneficial even against adversarial attackers. "
        else:
            reasoning += "Action limits damage even in worst-case scenarios. "

        if milp_result:
            reasoning += f"MILP robust optimization confirmed with margin c*={milp_result.get('c_star', 0):.4f}. "

        # Chỉ ra attacker type nguy hiểm nhất
        per_atk = result.get("per_attacker", {})
        if per_atk:
            worst_atk = min(per_atk, key=per_atk.get)
            reasoning += f"Most dangerous attacker type: {worst_atk} (value={per_atk[worst_atk]:+.4f})."

        return reasoning

    def _build_monitoring_metrics(self, action: DeceptionAction) -> List[str]:
        """Chỉ định các metrics cần theo dõi sau khi triển khai action."""
        base = [
            f"Engagement rate at Node {action.target_node}",
            "Attacker trajectory changes",
            "False positive rate",
        ]
        if action.action_type == DeceptionActionType.DEPLOY_DECOY_DATABASE:
            base += ["SQL query volume at decoy DB", "Data exfiltration attempts to decoy"]
        elif action.action_type == DeceptionActionType.DEPLOY_DECOY_ROUTER:
            base += ["Network traffic redirected to honeynet", "ARP/routing anomalies"]
        elif action.action_type == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
            base += ["Honey credential usage events", "Login attempts with fake account"]
        elif action.action_type == DeceptionActionType.INCREASE_EDGE_COST:
            if action.target_edge:
                src, dst = action.target_edge
                base += [f"Traffic volume on {self.graph.label(src)} -> {self.graph.label(dst)}",
                         "Firewall rule trigger count"]
        return base

    def get_history(self) -> List[Dict]:
        """Lấy lịch sử quyết định."""
        return [plan.to_dict() for plan in self._decision_history]

    def print_decision_summary(self) -> None:
        """In tóm tắt các quyết định đã thực hiện."""
        print(f"\n{'='*65}")
        print(f"Decision Engine History ({len(self._decision_history)} decisions)")
        print(f"{'='*65}")
        for i, plan in enumerate(self._decision_history, 1):
            print(f"\n[Decision {i}] {plan.action.action_type.value}")
            print(f"  Target:       Node {plan.target_node} ({plan.target_node_label})")
            print(f"  Pess. Value:  {plan.pessimistic_value:+.4f}")
            print(f"  Opt. Value:   {plan.optimistic_value:+.4f}")
            print(f"  Approved:     {'Yes' if not plan.required_approval else 'Human Required'}")


if __name__ == "__main__":
    from mirage.layer2_attack_graph import build_enterprise_attack_graph
    from mirage.layer3_deception import DeceptionFabric

    print("Testing Layer 4 — Robust Decision Engine")
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    engine = RobustDecisionEngine(graph, fabric, n_attacker_samples=100, use_robust_milp=False)

    # Giả lập belief state: attacker likely ở WS_FIN (node 4)
    belief = {4: 0.45, 3: 0.25, 5: 0.15, 1: 0.10, 0: 0.05}
    stage_ctx = {"stage": "Lateral Movement", "confidence": 0.75}

    plan = engine.decide(
        belief_state=belief,
        stage_context=stage_ctx,
        budget_remaining=4.0,
    )
    if plan:
        print(plan)
