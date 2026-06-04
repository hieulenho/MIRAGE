"""
MIRAGE - Layer 4: Robust RL / Game-Theoretic Decision Engine
=============================================================
"Bộ não" của MIRAGE — tối ưu worst-case (pessimistic) defender value
dưới nhiều biến thể attacker khác nhau.

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

import sys
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import time
import json

# Thêm đường dẫn codebase cũ để dùng thuật toán Robust RL
_ROBUST_RL_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..",
    "robust_reward_design_journal_production_suite",
    "robust_reward_design_lab", "src"
)
if os.path.exists(_ROBUST_RL_PATH):
    sys.path.insert(0, os.path.abspath(_ROBUST_RL_PATH))

from mirage.layer2_attack_graph import MIRAGEAttackGraph
from mirage.layer3_deception import DeceptionAction, DeceptionFabric, DeceptionActionType


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
            "risk_score": round(self.risk_score, 3),
            "confidence": round(self.confidence, 3),
            "required_approval": self.required_approval,
            "reasoning": self.reasoning,
            "evidence": self.evidence,
            "rollback_plan": self.rollback_plan,
            "monitoring_metrics": self.monitoring_metrics,
            "portfolio_size": len(self.portfolio),
            "portfolio_cost": round(self.portfolio_cost, 2),
            "portfolio_actions": [a.action_id for a in self.portfolio],
        }

    def __str__(self) -> str:
        approval_str = "⚠️ REQUIRES HUMAN APPROVAL" if self.required_approval else "✅ Auto-approved"
        portfolio_lines = ""
        if self.portfolio:
            portfolio_lines = "\nPortfolio:\n" + "\n".join(
                f"  [{i+1}] {a.action_type.value:35s} → Node {a.target_node:2d} "
                f"| cost={a.cost:.1f} | risk={a.risk_score:.2f}"
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
    1. Đánh giá mỗi DeceptionAction qua nhiều loại attacker
    2. Chọn action có pessimistic_value cao nhất (robust to worst-case)
    3. Ánh xạ kết quả toán học → ActionPlan có thể thực thi
    """

    def __init__(
        self,
        graph: MIRAGEAttackGraph,
        fabric: DeceptionFabric,
        n_attacker_samples: int = 200,
        use_robust_milp: bool = True,
    ):
        self.graph = graph
        self.fabric = fabric
        self.n_attacker_samples = n_attacker_samples
        self.use_robust_milp = use_robust_milp
        self._decision_history: List[ActionPlan] = []

        # Thử import robust MILP solver từ codebase cũ
        self._milp_available = self._check_milp_available()

    def _check_milp_available(self) -> bool:
        """Kiểm tra xem robust MILP solver có khả dụng không."""
        try:
            import pulp
            # Thử import từ codebase cũ
            if os.path.exists(_ROBUST_RL_PATH):
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "robust_reward_design",
                    os.path.join(_ROBUST_RL_PATH, "robust_reward_design.py")
                )
                return spec is not None
        except ImportError:
            pass
        return False

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
        attacker_types = ["random", "greedy", "shortest_path", "stealthy"]
        defender_values = []

        for atype in attacker_types:
            result = run_simulation(
                self.graph, atype,
                n_episodes=n_episodes // len(attacker_types),
                reward_interventions=reward_interventions,
                seed=42,
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

    def _run_milp_optimization(self, budget: float) -> Optional[Dict]:
        """
        Chạy MILP Robust Reward Design từ codebase cũ (nếu khả dụng).
        Trả về x_alloc tối ưu.
        """
        if not self._milp_available:
            return None
        try:
            sys.path.insert(0, _ROBUST_RL_PATH)
            from mdp_model import AttackGraphMDP, InterventionSite
            from robust_reward_design import solve_max_margin_reward_design

            # Chuyển enterprise graph sang AttackGraphMDP format
            mdp_data = self.graph.to_mdp_dict()

            # Build AttackGraphMDP compatible format
            transitions_compat = {}
            for s, acts in mdp_data["transitions"].items():
                transitions_compat[int(s)] = {
                    a: {int(ns): float(p) for ns, p in nxt.items()}
                    for a, nxt in acts.items()
                }

            from mdp_model import _parse_sa_key
            attacker_reward = {_parse_sa_key(k): float(v) for k, v in mdp_data["attacker_reward"].items()}
            defender_reward = {_parse_sa_key(k): float(v) for k, v in mdp_data["defender_reward"].items()}
            interventions = [
                InterventionSite(name=it["name"], state=int(it["state"]), action=it["action"])
                for it in mdp_data["interventions"]
            ]

            mdp = AttackGraphMDP(
                name=mdp_data["name"],
                states=[int(s) for s in mdp_data["states"]],
                actions=mdp_data["actions"],
                available_actions={int(k): v for k, v in mdp_data["available_actions"].items()},
                transitions=transitions_compat,
                start_distribution={int(k): float(v) for k, v in mdp_data["start_distribution"].items()},
                discount=float(mdp_data["discount"]),
                budget=float(budget),
                true_goals=[int(s) for s in mdp_data["true_goals"]],
                decoy_sites=[int(s) for s in mdp_data["decoy_sites"]],
                sink_state=int(mdp_data["sink_state"]),
                state_labels={int(k): v for k, v in mdp_data["state_labels"].items()},
                attacker_reward=attacker_reward,
                defender_reward=defender_reward,
                interventions=interventions,
            )

            result = solve_max_margin_reward_design(mdp, solver_msg=False, time_limit_seconds=30)
            return {
                "x_ip": result.x_ip,
                "c_star": result.c_star,
                "v1_star": result.v1_star,
                "solver_status": result.solver_status,
            }
        except Exception as e:
            print(f"  [!] MILP solver error: {e}. Falling back to simulation-based method.")
            return None

    def evaluate_action(self, action: DeceptionAction) -> Dict:
        """(Legacy) Đánh giá một action đơn lẻ qua simulation."""
        return self._run_attacker_simulation(action, self.n_attacker_samples)

    # ---------------------------------------------------------------------------
    # Portfolio Optimization (mới)
    # ---------------------------------------------------------------------------

    def _merge_interventions(
        self, actions: List[DeceptionAction]
    ) -> Dict:
        """
        Kết hợp reward interventions từ nhiều actions thành một dict dùng cho simulation.

        Quy tắc kết hợp:
        - DEPLOY_DECOY_*: ghi nhận (node, "end") -> reward_delta (lấy max nếu trùng node)
        - SCATTER_HONEY_CREDENTIAL: ghi nhận cả (node, "cred_dump") và (node, "end")
        - INCREASE_EDGE_COST: không sinh reward intervention nhưng có hiệu ứng qua
          graph.increase_edge_cost đã được deploy_action xử lý; ở đây ta chỉ model
          hiệu ứng "push attacker toward decoys" bằng negative bait.
        """
        merged: Dict = {}
        for action in actions:
            atype = action.action_type

            if atype in (
                DeceptionActionType.DEPLOY_DECOY_DATABASE,
                DeceptionActionType.DEPLOY_DECOY_ROUTER,
            ):
                key = (action.target_node, "end")
                # Tất cả reward cộng dồn (nhiều decoy cùng loaại tại các node khác nhau)
                merged[key] = merged.get(key, 0.0) + action.reward_delta

            elif atype == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
                k_cred = (action.target_node, "cred_dump")
                k_end  = (action.target_node, "end")
                merged[k_cred] = merged.get(k_cred, 0.0) + action.reward_delta * 0.5
                merged[k_end]  = merged.get(k_end,  0.0) + action.reward_delta * 0.3

            elif atype == DeceptionActionType.INCREASE_EDGE_COST:
                # Model hiệu ứng của việc chặn edge: attacker có ít khả năng qua đượng đó hơn.
                # Ta không thể giảm reward tại node, nhưng có thể boost node decoy ở điểm đến
                # cùng mức độ nhỏ hơn (edge cost được apply sọn lên graph trong deploy_action;
                # ở đây ta model hiệu ứng bonus cho các decoy cửa đi lân cận).
                if action.target_edge and action.target_node in self.graph.decoy_sites:
                    k_end = (action.target_node, "end")
                    merged[k_end] = merged.get(k_end, 0.0) + action.edge_cost_delta * 0.2

        return merged

    def _evaluate_portfolio(
        self,
        actions: List[DeceptionAction],
        n_eps: int = 50,
        belief_state: Optional[Dict[int, float]] = None,
    ) -> Dict:
        """
        Đánh giá hiệu quả của một portfolio actions.

        Simulate với tất cả 4 loại attacker dùng combined reward interventions.
        Pessimistic value = min defender value across all attacker types.

        Args:
            belief_state: Nếu có, mỗi simulation episode sẽ bắt đầu từ phân phối này.
                          Điều này giúp value được tính dướng trên vị trí thực của attacker,
                          không phải luôn từ entry point.
        """
        from mirage.attacker_agents import run_simulation

        combined = self._merge_interventions(actions)
        attacker_types = ["random", "greedy", "shortest_path", "stealthy"]
        defender_values: Dict[str, float] = {}

        for atype in attacker_types:
            result = run_simulation(
                self.graph, atype,
                n_episodes=max(n_eps, 20),
                reward_interventions=combined,
                seed=42,
                start_distribution=belief_state,
            )
            d_val = (
                result["decoy_interception_rate"] * 1.0
                - result["hit_true_goal_rate"] * 2.0
                + (result["avg_steps_to_terminal"] / 30.0) * 0.2
            )
            defender_values[atype] = d_val

        total_cost = sum(a.cost for a in actions)
        values = list(defender_values.values())
        return {
            "pessimistic_value": min(values),
            "optimistic_value":  max(values),
            "expected_value":    sum(values) / len(values),
            "per_attacker":      defender_values,
            "combined_interventions": combined,
            "total_cost":        total_cost,
        }

    def optimize_portfolio(
        self,
        budget: float,
        safety_filter=None,
        belief_state: Optional[Dict[int, float]] = None,
    ):
        """
        Tìm portfolio tối ưu dưới budget constraint.
        Maximize pessimistic (worst-case) defender value.

        Args:
            belief_state: Phân phối xác suất attacker location từ Layer 1/2.
                          Nếu có, simulation sẽ bắt đầu từ đây thay vì entry point.
                          Điều này làm cho value của từng portfolio action phụ thuộc
                          vào thông tin thực về vị trí attacker — đúng theo POMDP.

        Algorithms: Greedy forward + Local swap.
        """
        available = self.fabric.get_available_actions(budget)
        if not available:
            return [], {"pessimistic_value": float("-inf"), "combined_interventions": {}}

        # Độ phân giải episodes: đủ để phân biệt portfolios mà không quá chậm
        eps_per_eval = max(40, self.n_attacker_samples // 4)

        print(f"\n\U0001f50e [Portfolio Optimizer] {len(available)} candidate actions, "
              f"budget={budget:.1f}, {eps_per_eval} eps/eval"
              + (" | belief-conditioned" if belief_state else " | from entry point"))

        # --------------- Pha 1: Greedy forward ----------------
        # Thêm actions từng bước, mỗi bước chọn action cải thiện pessimistic_value nhất.
        # Khác với stopping-at-first-improvement: ta thử TOÀN BỘ candidates ở mỗi bước.
        portfolio: List[DeceptionAction] = []
        remaining_budget = budget
        candidates = list(available)
        current_result: Dict = {
            "pessimistic_value": float("-inf"),
            "combined_interventions": {},
            "total_cost": 0.0,
        }

        while candidates:
            best_candidate = None
            best_result: Dict = {"pessimistic_value": float("-inf")}

            for action in candidates:
                if action.cost > remaining_budget:
                    continue
                trial_result = self._evaluate_portfolio(
                    portfolio + [action], n_eps=eps_per_eval,
                    belief_state=belief_state,
                )
                if trial_result["pessimistic_value"] > best_result["pessimistic_value"]:
                    best_result = trial_result
                    best_candidate = action

            if best_candidate is None:
                break  # Budget hết — không action nào fit

            # Luôn thêm action tốt nhất tìm được nếu nó cải thiện so với portfolio hiện tại
            if best_result["pessimistic_value"] > current_result["pessimistic_value"]:
                portfolio.append(best_candidate)
                candidates.remove(best_candidate)
                remaining_budget -= best_candidate.cost
                current_result = best_result
                print(f"  + Add: {best_candidate.action_type.value} @ Node {best_candidate.target_node} "
                      f"| pess={best_result['pessimistic_value']:+.4f} "
                      f"| budget_left={remaining_budget:.1f}")
            else:
                # Thêm action này không cải thiện pessimistic_value,
                # nhưng có thể action khác vẫn còn cải thiện được → tiếp tục
                candidates.remove(best_candidate)
                print(f"  ~ Skip: {best_candidate.action_type.value} @ Node {best_candidate.target_node} "
                      f"(no pess improvement: {best_result['pessimistic_value']:+.4f})")

        # --------------- Pha 2: Local swap ----------------
        print(f"  Phase 2: Local swap on portfolio of {len(portfolio)} actions...")
        outside = [a for a in available if a not in portfolio]
        improved = True
        while improved:
            improved = False
            for i, in_action in enumerate(portfolio):
                for out_action in outside:
                    # Kiểm tra budget nếu hoán đổi
                    new_cost = current_result["total_cost"] \
                        - in_action.cost + out_action.cost
                    if new_cost > budget:
                        continue
                    trial_portfolio = portfolio[:i] + [out_action] + portfolio[i+1:]
                    trial_result = self._evaluate_portfolio(
                        trial_portfolio, n_eps=eps_per_eval,
                        belief_state=belief_state,
                    )
                    if trial_result["pessimistic_value"] > current_result["pessimistic_value"] + 1e-4:
                        portfolio = trial_portfolio
                        outside[outside.index(out_action)] = in_action
                        current_result = trial_result
                        improved = True
                        print(f"  ~ Swap: {in_action.action_type.value} → "
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
            )
        else:
            final_result = current_result

        total_cost = sum(a.cost for a in portfolio)
        print(f"  ✓ Optimal portfolio: {len(portfolio)} actions, "
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
        print("\n🔬 [Decision Engine] Running portfolio optimization...")

        # Log belief state nếu có — cho thấy thông tin đã được dùng
        if belief_state:
            top_nodes = sorted(belief_state.items(), key=lambda x: x[1], reverse=True)[:3]
            belief_summary = ", ".join(
                f"Node{s}({self.graph.label(s)})={p:.1%}"
                for s, p in top_nodes if p > 0.01
            )
            print(f"  📍 Belief state (top nodes): {belief_summary}")

        # ---- Chạy portfolio optimizer với belief_state ----
        # belief_state được dùng làm start_distribution trong simulation:
        # mỗi episode sẽ sample vị trí bắt đầu từ phân phối này → value phản ánh
        # thực tế attacker đang ở đâu, không phải luôn từ entry point.
        portfolio, portfolio_result = self.optimize_portfolio(
            budget=budget_remaining,
            safety_filter=safety_filter,
            belief_state=belief_state,
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

        needs_approval = any(
            a.risk_score > 0.3 or a.business_impact > 0.1
            for a in portfolio
        ) or portfolio_result["pessimistic_value"] < -0.5

        gap = portfolio_result["optimistic_value"] - portfolio_result["pessimistic_value"]
        confidence = max(0.5, 1.0 - gap * 0.5)

        plan = ActionPlan(
            action=primary_action,
            target_node=primary_action.target_node,
            target_node_label=self.graph.label(primary_action.target_node),
            optimistic_value=portfolio_result["optimistic_value"],
            pessimistic_value=portfolio_result["pessimistic_value"],
            expected_value=portfolio_result["expected_value"],
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
            portfolio_cost=sum(a.cost for a in portfolio),
            portfolio_interventions=portfolio_result["combined_interventions"],
            per_attacker_values=portfolio_result.get("per_attacker", {}),
        )

        # Kiểm tra safety gate (Layer 5) trên primary action
        if safety_filter is not None:
            safe, warning = safety_filter(plan)
            if not safe:
                print(f"  ✗ Portfolio blocked by Safety Gate: {warning}")
                return None

        self._decision_history.append(plan)
        print(f"  ✓ Portfolio selected: {len(portfolio)} actions "
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
                path_str = " → ".join(self.graph.label(n) for n in path)
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
                base += [f"Traffic volume on {self.graph.label(src)} → {self.graph.label(dst)}",
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
