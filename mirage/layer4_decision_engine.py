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
    - action: Hành động được đề xuất
    - giải thích chi tiết
    - expected values
    - risk & confidence
    - rollback plan
    """
    action: DeceptionAction
    target_node: int
    target_node_label: str

    # Giá trị kỳ vọng
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
        }

    def __str__(self) -> str:
        approval_str = "⚠️ REQUIRES HUMAN APPROVAL" if self.required_approval else "✅ Auto-approved"
        return (
            f"\n{'='*65}\n"
            f"🤖 MIRAGE Decision Plan\n"
            f"{'='*65}\n"
            f"Action:      {self.action.action_type.value}\n"
            f"Target:      Node {self.target_node} — {self.target_node_label}\n"
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
        """Đánh giá một action qua simulation."""
        return self._run_attacker_simulation(action, self.n_attacker_samples)

    def decide(
        self,
        belief_state: Dict[int, float],
        stage_context: Optional[Dict] = None,
        budget_remaining: float = 4.0,
        safety_filter=None,  # Layer 5 safety gate
    ) -> Optional[ActionPlan]:
        """
        Ra quyết định chính: chọn action tốt nhất theo pessimistic value.
        
        Args:
            belief_state: Phân phối xác suất attacker location
            stage_context: Stage information từ Layer 1
            budget_remaining: Ngân sách còn lại
            safety_filter: Layer 5 function kiểm tra an toàn
            
        Returns:
            ActionPlan tốt nhất, hoặc None nếu không có action an toàn
        """
        print("\n🔬 [Decision Engine] Evaluating deception actions...")
        available = self.fabric.get_available_actions(budget_remaining)

        if not available:
            print("  [!] No actions available within budget.")
            return None

        # Thử MILP optimization trước
        milp_result = None
        if self.use_robust_milp:
            print("  → Running MILP Robust Optimization...")
            milp_result = self._run_milp_optimization(budget_remaining)
            if milp_result:
                print(f"  ✓ MILP solved: c*={milp_result['c_star']:.4f}, "
                      f"v1*={milp_result['v1_star']:.4f}")

        # Evaluate mỗi action qua simulation
        print(f"  → Simulating {len(available)} candidate actions "
              f"({self.n_attacker_samples} episodes each)...")

        action_results = []
        for action in available:
            result = self.evaluate_action(action)
            action_results.append((action, result))

        # Sắp xếp theo pessimistic value (ROBUST criterion)
        action_results.sort(key=lambda x: x[1]["pessimistic_value"], reverse=True)

        # Chọn action tốt nhất qua safety filter
        for action, result in action_results:
            # Xây dựng evidence từ belief state và stage context
            evidence = self._build_evidence(belief_state, stage_context, action)

            # Xác định cần human approval không
            needs_approval = (
                action.risk_score > 0.3 or
                action.business_impact > 0.1 or
                result["pessimistic_value"] < -0.5
            )

            plan = ActionPlan(
                action=action,
                target_node=action.target_node,
                target_node_label=self.graph.label(action.target_node),
                optimistic_value=result["optimistic_value"],
                pessimistic_value=result["pessimistic_value"],
                expected_value=result["expected_value"],
                risk_score=action.risk_score,
                confidence=max(0.5, 1.0 - abs(result["optimistic_value"] - result["pessimistic_value"])),
                required_approval=needs_approval,
                reasoning=self._build_reasoning(action, result, belief_state, milp_result),
                evidence=evidence,
                rollback_plan=action.rollback_plan,
                monitoring_metrics=self._build_monitoring_metrics(action),
            )

            # Kiểm tra safety gate (Layer 5)
            if safety_filter is not None:
                safe, warning = safety_filter(plan)
                if not safe:
                    print(f"  ✗ Action blocked by Safety Gate: {warning}")
                    continue

            self._decision_history.append(plan)
            print(f"  ✓ Selected: {action.action_type.value} @ Node {action.target_node} "
                  f"| Pess.Val={result['pessimistic_value']:+.4f}")
            return plan

        print("  [!] All actions blocked by safety constraints. Entering observe-only mode.")
        return None

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
    ) -> str:
        """Xây dựng giải thích bằng tiếng Anh cho SOC analyst."""
        action_name = action.action_type.value.replace("_", " ").title()
        node_label = self.graph.label(action.target_node)

        reasoning = (
            f"{action_name} at {node_label}. "
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
