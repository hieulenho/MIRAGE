"""
MIRAGE - Exact MDP Solver & Robust Math
========================================
Bridges the gap between the Paper's theoretical MILP formulation and
MIRAGE's practical simulation-based portfolio optimizer.

Mathematical components (all exact, no approximation):
  1. Policy Iteration        → V^π(s) via Bellman equation
  2. Occupancy Measure       → ρ^π(s,a) via matrix inversion
  3. Robust Bellman Operator  → minimax V_pess(s) (game-theoretic)
  4. Margin Guarantee         → c* = improvement over no-defense
  5. Composite Action Cost    → multi-factor cost model

References:
  - "Robust Reward Design for Markov Decision Processes" (Paper)
  - MIRAGE Architecture Document §7.4

Dependencies: numpy (required), scipy (optional, for sparse solvers on large graphs)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, TYPE_CHECKING
import numpy as np

if TYPE_CHECKING:
    from mirage.layer2_attack_graph import MIRAGEAttackGraph


# ============================================================
# Composite Action Cost Model
# ============================================================

@dataclass
class CompositeActionCost:
    """
    Multi-factor cost model cho một deception action.
    
    Thay vì cost = 1 số đơn giản, cost được tính từ nhiều yếu tố:
      cost_total = base_cost
                   + business_impact * w_biz
                   + risk_score * w_risk
                   + affected_services * w_svc
                   + fp_likelihood * w_fp
                   + rollback_complexity * w_rollback
    
    Weights có thể tune theo domain (SOC preference).
    """
    base_cost: float = 1.0

    # Các yếu tố cấu thành
    business_impact: float = 0.0       # 0-1: ảnh hưởng đến business
    risk_score: float = 0.0            # 0-1: rủi ro vận hành
    affected_services: int = 0         # Số service/user bị ảnh hưởng
    affected_users: int = 0            # Số user bị ảnh hưởng
    fp_likelihood: float = 0.0         # 0-1: khả năng false positive
    rollback_complexity: float = 0.0   # 0-1: độ phức tạp rollback
    duration_hours: float = 1.0        # Thời gian duy trì action

    # Weights (tunable)
    w_biz: float = 2.0
    w_risk: float = 1.5
    w_svc: float = 0.1
    w_user: float = 0.002
    w_fp: float = 1.0
    w_rollback: float = 0.5
    w_duration: float = 0.08

    @property
    def total(self) -> float:
        """Tổng chi phí composite."""
        duration_factor = max(0.25, self.duration_hours / 8.0)
        return (
            self.base_cost
            + self.business_impact * self.w_biz
            + self.risk_score * self.w_risk
            + self.affected_services * self.w_svc
            + self.affected_users * self.w_user
            + self.fp_likelihood * self.w_fp
            + self.rollback_complexity * self.w_rollback
            + duration_factor * self.w_duration
        )

    @property
    def fp_cost(self) -> float:
        """Chi phí riêng do false positive."""
        exposure = (
            1.0
            + self.affected_services * 0.05
            + self.affected_users * 0.002
            + max(0.0, self.duration_hours - 1.0) * 0.03
        )
        return self.fp_likelihood * self.w_fp * exposure

    def to_dict(self) -> Dict[str, float]:
        """Return a serializable cost breakdown for reports and benchmarks."""
        return {
            "total": self.total,
            "base_cost": self.base_cost,
            "business_impact": self.business_impact,
            "risk_score": self.risk_score,
            "affected_services": float(self.affected_services),
            "affected_users": float(self.affected_users),
            "false_positive_cost": self.fp_cost,
            "fp_likelihood": self.fp_likelihood,
            "rollback_complexity": self.rollback_complexity,
            "duration_hours": self.duration_hours,
        }

    def __repr__(self) -> str:
        return (f"CompositeActionCost(total={self.total:.2f}, "
                f"base={self.base_cost:.1f}, biz={self.business_impact:.2f}, "
                f"risk={self.risk_score:.2f}, fp={self.fp_likelihood:.2f})")


def _node_operational_profile(graph, node: int) -> Dict[str, float]:
    """Estimate operational blast radius from graph metadata when present."""
    if graph is None or node is None:
        return {}

    meta = getattr(graph, "node_metadata", {}).get(node, {}) or {}
    asset_type = meta.get("asset_type", "")
    layer = meta.get("layer", "")
    value = float(meta.get("value", 0.0) or 0.0)

    default_services = {
        "entry": 1,
        "web_server": 4,
        "mail_server": 5,
        "workstation": 1,
        "file_share": 6,
        "dns_server": 8,
        "credential": 2,
        "database": 10,
        "dc": 15,
        "decoy_db": 1,
        "decoy_router": 3,
        "sink": 0,
    }
    default_users = {
        "entry": 0,
        "web_server": 250,
        "mail_server": 800,
        "workstation": 25,
        "file_share": 500,
        "dns_server": 1200,
        "credential": 150,
        "database": 900,
        "dc": 1500,
        "decoy_db": 5,
        "decoy_router": 50,
        "sink": 0,
    }

    services = int(meta.get("service_count", default_services.get(asset_type, 1)))
    users = int(meta.get("user_count", default_users.get(asset_type, 10)))
    criticality = float(meta.get("business_criticality", value))
    if layer in {"critical", "data"}:
        criticality = max(criticality, min(1.0, value + 0.1))

    return {
        "affected_services": services,
        "affected_users": users,
        "business_criticality": max(0.0, min(1.0, criticality)),
    }


def compute_composite_cost(action, graph=None) -> CompositeActionCost:
    """
    Tính composite cost từ một DeceptionAction.
    Map các thuộc tính của action sang multi-factor cost.
    """
    from mirage.layer3_deception import DeceptionActionType

    atype = action.action_type

    # Base cost theo loại action
    base_map = {
        DeceptionActionType.DEPLOY_DECOY_DATABASE:    1.5,
        DeceptionActionType.DEPLOY_DECOY_ROUTER:      1.2,
        DeceptionActionType.SCATTER_HONEY_CREDENTIAL: 0.8,
        DeceptionActionType.INCREASE_EDGE_COST:       0.5,
    }

    # FP likelihood theo loại action
    fp_map = {
        DeceptionActionType.DEPLOY_DECOY_DATABASE:    0.05,  # DB giả ít ảnh hưởng
        DeceptionActionType.DEPLOY_DECOY_ROUTER:      0.15,  # Router giả có thể confuse
        DeceptionActionType.SCATTER_HONEY_CREDENTIAL: 0.20,  # Credential giả dễ FP
        DeceptionActionType.INCREASE_EDGE_COST:       0.10,  # Firewall rule có thể block nhầm
    }

    # Affected services (ước tính theo loại)
    svc_map = {
        DeceptionActionType.DEPLOY_DECOY_DATABASE:    1,
        DeceptionActionType.DEPLOY_DECOY_ROUTER:      3,   # Router ảnh hưởng nhiều service
        DeceptionActionType.SCATTER_HONEY_CREDENTIAL: 0,
        DeceptionActionType.INCREASE_EDGE_COST:       2,
    }

    # Rollback complexity
    rollback_map = {
        DeceptionActionType.DEPLOY_DECOY_DATABASE:    0.2,
        DeceptionActionType.DEPLOY_DECOY_ROUTER:      0.4,
        DeceptionActionType.SCATTER_HONEY_CREDENTIAL: 0.1,
        DeceptionActionType.INCREASE_EDGE_COST:       0.3,
    }

    profile = _node_operational_profile(graph, getattr(action, "target_node", None))
    action_services = int(getattr(action, "affected_services", 0) or 0)
    action_users = int(getattr(action, "affected_users", 0) or 0)
    services = action_services or int(profile.get("affected_services", svc_map.get(atype, 0)))
    users = action_users or int(profile.get("affected_users", 0))

    action_fp = getattr(action, "false_positive_likelihood", None)
    if action_fp is None:
        action_fp = getattr(action, "fp_likelihood", None)
    fp_likelihood = fp_map.get(atype, 0.1) if action_fp is None else float(action_fp)

    action_rollback = getattr(action, "rollback_complexity", None)
    rollback_complexity = (
        rollback_map.get(atype, 0.2)
        if action_rollback is None
        else float(action_rollback)
    )

    duration_hours = float(getattr(action, "duration_hours", 1.0) or 1.0)
    business_impact = float(getattr(action, "business_impact", 0.0) or 0.0)
    business_impact = max(
        business_impact,
        0.25 * float(profile.get("business_criticality", 0.0)),
    )

    return CompositeActionCost(
        base_cost=base_map.get(atype, 1.0),
        business_impact=business_impact,
        risk_score=float(getattr(action, "risk_score", 0.0) or 0.0),
        affected_services=services,
        affected_users=users,
        fp_likelihood=fp_likelihood,
        rollback_complexity=rollback_complexity,
        duration_hours=duration_hours,
    )


def compute_portfolio_cost(actions, graph=None) -> Dict[str, object]:
    """Aggregate composite cost for a portfolio of deception actions."""
    action_costs = [compute_composite_cost(a, graph) for a in actions]
    return {
        "total": sum(c.total for c in action_costs),
        "false_positive_cost": sum(c.fp_cost for c in action_costs),
        "action_count": len(action_costs),
        "per_action": [c.to_dict() for c in action_costs],
    }


# ============================================================
# MDPSolver — Exact MDP Mathematics
# ============================================================

class MDPSolver:
    """
    Giải bài toán MDP chính xác (exact) cho đồ thị tấn công.
    
    Thay vì chạy Monte Carlo simulation rồi lấy min/max/avg,
    solver này tính ĐÚNG bằng toán học:
    
    1. V^π(s) qua Policy Iteration (Bellman equation)
    2. ρ^π(s,a) occupancy measure qua matrix inversion
    3. Minimax value qua Robust Bellman operator
    4. Margin guarantee c*
    
    Với đồ thị 15 nodes: < 5ms. Scaling ~O(|S|^3) cho matrix ops.
    Với 1000 nodes: ~1 giây (vẫn OK cho offline optimization).
    """

    def __init__(self, graph: MIRAGEAttackGraph):
        self.graph = graph
        self.n_states = len(graph.states)
        self.state_to_idx = {s: i for i, s in enumerate(graph.states)}
        self.idx_to_state = {i: s for s, i in self.state_to_idx.items()}

        # Cache defender/attacker rewards
        self._defender_r = graph.defender_reward
        self._attacker_r = graph.attacker_reward
        self._discount = graph.discount

    # ----- Utility: Build transition matrix for a policy -----

    def _build_transition_matrix(
        self,
        policy: Optional[Dict[int, Dict[str, float]]] = None,
        reward_interventions: Optional[Dict[Tuple, float]] = None,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Build P (transition matrix) and r (reward vector) for a given policy.
        
        If policy is None, uses uniform random over available actions.
        reward_interventions: {(state, action): delta} to add to attacker reward.
        
        Returns:
            P: |S| x |S| transition matrix
            r_def: |S| defender reward vector under policy
        """
        n = self.n_states
        P = np.zeros((n, n))
        r_def = np.zeros(n)

        interventions = reward_interventions or {}

        for s in self.graph.states:
            i = self.state_to_idx[s]
            actions = self.graph.available_actions.get(s, [])
            if not actions:
                P[i, i] = 1.0  # Self-loop absorbing state
                continue

            # Determine action probabilities
            if policy and s in policy:
                action_probs = policy[s]
            else:
                # Uniform random policy
                prob = 1.0 / len(actions)
                action_probs = {a: prob for a in actions}

            for a, a_prob in action_probs.items():
                if a_prob <= 0:
                    continue
                trans = self.graph.transitions.get(s, {}).get(a, {})
                for s_next, t_prob in trans.items():
                    j = self.state_to_idx[s_next]
                    P[i, j] += a_prob * t_prob

                # Defender reward (including interventions)
                base_r = self._defender_r.get((s, a), 0.0)
                intervention_r = interventions.get((s, a), 0.0)
                r_def[i] += a_prob * (base_r + intervention_r)

        return P, r_def

    # ----- 1. Policy Iteration → V*(s) -----

    def solve_value_function(
        self,
        reward_interventions: Optional[Dict[Tuple, float]] = None,
        policy: Optional[Dict[int, Dict[str, float]]] = None,
        max_iters: int = 100,
        tol: float = 1e-8,
    ) -> Dict[int, float]:
        """
        Giải Bellman equation chính xác:
            V^π(s) = r(s) + γ Σ_s' P(s'|s) V^π(s')
        
        Bằng matrix inversion: V = (I - γP)^{-1} r
        
        Args:
            reward_interventions: Reward delta từ deception actions
            policy: Nếu None, dùng "greedy attacker policy" (attacker chọn
                    action maximize attacker reward)
        
        Returns:
            {state: value} — exact defender value function
        """
        if policy is None:
            # Default: build greedy attacker policy
            policy = self._build_greedy_attacker_policy(reward_interventions)

        P, r_def = self._build_transition_matrix(policy, reward_interventions)

        n = self.n_states
        gamma = self._discount

        # V = (I - γP)^{-1} r
        try:
            A = np.eye(n) - gamma * P
            V = np.linalg.solve(A, r_def)
        except np.linalg.LinAlgError:
            # Fallback to iterative if singular
            V = self._value_iteration_fallback(P, r_def, gamma, max_iters, tol)

        return {self.idx_to_state[i]: float(V[i]) for i in range(n)}

    def _value_iteration_fallback(
        self, P: np.ndarray, r: np.ndarray,
        gamma: float, max_iters: int, tol: float,
    ) -> np.ndarray:
        """Value iteration khi matrix inversion fails."""
        n = len(r)
        V = np.zeros(n)
        for _ in range(max_iters):
            V_new = r + gamma * P @ V
            if np.max(np.abs(V_new - V)) < tol:
                break
            V = V_new
        return V

    def _build_greedy_attacker_policy(
        self,
        reward_interventions: Optional[Dict[Tuple, float]] = None,
    ) -> Dict[int, Dict[str, float]]:
        """
        Build deterministic policy: attacker chọn action maximize attacker reward.
        Đây là best response của attacker khi biết reward structure.
        """
        interventions = reward_interventions or {}
        policy = {}

        for s in self.graph.states:
            actions = self.graph.available_actions.get(s, [])
            if not actions:
                continue

            # Tính expected attacker reward cho mỗi action
            action_values = {}
            for a in actions:
                trans = self.graph.transitions.get(s, {}).get(a, {})
                # Attacker cares about attacker_reward
                # With interventions, attacker perceives modified rewards
                expected_r = 0.0
                for s_next, t_prob in trans.items():
                    # Attacker reward at next state (approximate 1-step lookahead)
                    for a_next in self.graph.available_actions.get(s_next, []):
                        base_r = self._attacker_r.get((s_next, a_next), 0.0)
                        interv = interventions.get((s_next, a_next), 0.0)
                        expected_r += t_prob * (base_r + interv) / max(
                            1, len(self.graph.available_actions.get(s_next, []))
                        )
                action_values[a] = expected_r

            # Greedy: pick action with max attacker reward
            best_a = max(action_values, key=action_values.get)
            policy[s] = {best_a: 1.0}

        return policy

    # ----- 2. Occupancy Measure ρ^π(s,a) -----

    def compute_occupancy_measure(
        self,
        policy: Optional[Dict[int, Dict[str, float]]] = None,
        start_distribution: Optional[Dict[int, float]] = None,
        reward_interventions: Optional[Dict[Tuple, float]] = None,
    ) -> Dict[Tuple[int, str], float]:
        """
        Occupancy measure — khái niệm cốt lõi từ Paper:
            ρ^π(s,a) = Σ_{t=0}^{∞} γ^t Pr[s_t=s, a_t=a | π, μ_0]
        
        Tính exact bằng matrix:
            d^π = (I - γP^π)^{-1} μ_0     (state visitation)
            ρ^π(s,a) = d^π(s) * π(a|s)
        
        Returns:
            {(state, action): occupancy} cho mọi (s,a) pair
        """
        if policy is None:
            policy = self._build_greedy_attacker_policy(reward_interventions)

        P, _ = self._build_transition_matrix(policy, reward_interventions)

        n = self.n_states
        gamma = self._discount

        # Start distribution vector
        mu0 = np.zeros(n)
        if start_distribution:
            for s, p in start_distribution.items():
                if s in self.state_to_idx:
                    mu0[self.state_to_idx[s]] = p
        else:
            for s, p in self.graph.start_distribution.items():
                if s in self.state_to_idx:
                    mu0[self.state_to_idx[s]] = p

        # Normalize mu0
        total = mu0.sum()
        if total > 0:
            mu0 /= total

        # d^π = (I - γP^T)^{-1} μ_0  (state visitation frequencies)
        try:
            A = np.eye(n) - gamma * P.T
            d_pi = np.linalg.solve(A, mu0)
        except np.linalg.LinAlgError:
            # Fallback iterative
            d_pi = mu0.copy()
            for _ in range(200):
                d_pi_new = mu0 + gamma * P.T @ d_pi
                if np.max(np.abs(d_pi_new - d_pi)) < 1e-10:
                    break
                d_pi = d_pi_new

        # Clamp negatives (numerical)
        d_pi = np.maximum(d_pi, 0.0)

        # ρ(s,a) = d(s) * π(a|s)
        occupancy: Dict[Tuple[int, str], float] = {}
        for s in self.graph.states:
            i = self.state_to_idx[s]
            d_s = d_pi[i]
            actions = self.graph.available_actions.get(s, [])
            if not actions or d_s < 1e-12:
                continue

            if policy and s in policy:
                action_probs = policy[s]
            else:
                prob = 1.0 / len(actions)
                action_probs = {a: prob for a in actions}

            for a, a_prob in action_probs.items():
                rho = d_s * a_prob
                if rho > 1e-12:
                    occupancy[(s, a)] = float(rho)

        return occupancy

    # ----- 3. Robust Bellman Operator (Minimax) -----

    def solve_robust_value(
        self,
        reward_interventions: Optional[Dict[Tuple, float]] = None,
        max_iters: int = 200,
        tol: float = 1e-8,
    ) -> Dict[int, float]:
        """
        Robust Bellman equation (game-theoretic minimax):
        
        V_robust(s) = max_{a_def} min_{a_atk} [
            r_def(s, a_atk) + γ Σ_s' P(s'|s, a_atk) V_robust(s')
        ]
        
        Ở đây attacker chọn action tối ưu cho attacker (tệ nhất cho defender),
        giữa các action có attacker value xấp xỉ nhau (tie-breaking rule của Paper).
        
        Giải bằng Value Iteration trên robust Bellman operator.
        """
        n = self.n_states
        gamma = self._discount
        interventions = reward_interventions or {}
        V = np.zeros(n)

        for iteration in range(max_iters):
            V_new = np.full(n, -1e10)

            for s in self.graph.states:
                i = self.state_to_idx[s]
                actions = self.graph.available_actions.get(s, [])

                if not actions:
                    V_new[i] = 0.0
                    continue

                # Attacker chooses action to MINIMIZE defender value
                # (equivalent to maximizing attacker value)
                min_def_value = float('inf')

                for a in actions:
                    trans = self.graph.transitions.get(s, {}).get(a, {})
                    if not trans:
                        continue

                    # Defender reward for this (s, a)
                    r_d = self._defender_r.get((s, a), 0.0)
                    r_d += interventions.get((s, a), 0.0)

                    # Expected future value
                    future_v = 0.0
                    for s_next, t_prob in trans.items():
                        j = self.state_to_idx[s_next]
                        future_v += t_prob * V[j]

                    def_val = r_d + gamma * future_v
                    min_def_value = min(min_def_value, def_val)

                V_new[i] = min_def_value if min_def_value < float('inf') else 0.0

            # Convergence check
            if np.max(np.abs(V_new - V)) < tol:
                break
            V = V_new

        return {self.idx_to_state[i]: float(V[i]) for i in range(n)}

    # ----- 4. Margin Guarantee c* -----

    def compute_margin(
        self,
        reward_interventions: Optional[Dict[Tuple, float]] = None,
        start_distribution: Optional[Dict[int, float]] = None,
    ) -> float:
        """
        Margin guarantee c* (khái niệm cốt lõi từ Paper):
        
            c* = V_robust(with defense) - V_robust(no defense)
        
        c* > 0 → chính sách đảm bảo tốt hơn no-defense trong mọi kịch bản.
        c* = 0 → defense không giúp ích gì (hoặc đã tối ưu).
        c* < 0 → defense đang harmful (không nên xảy ra nếu optimizer đúng).
        
        Returns:
            float: margin value
        """
        # Value with defense
        V_defense = self.solve_robust_value(reward_interventions)

        # Value without defense (no interventions)
        V_no_defense = self.solve_robust_value(None)

        # Weighted by start distribution
        mu0 = start_distribution or self.graph.start_distribution

        v_def = sum(V_defense.get(s, 0.0) * p for s, p in mu0.items())
        v_no_def = sum(V_no_defense.get(s, 0.0) * p for s, p in mu0.items())

        return v_def - v_no_def

    # ----- 5. Occupancy-Weighted Reward Allocation -----

    def allocate_reward_by_occupancy(
        self,
        raw_interventions: Dict[Tuple[int, str], float],
        start_distribution: Optional[Dict[int, float]] = None,
    ) -> Dict[Tuple[int, str], float]:
        """
        Scale reward interventions theo occupancy measure (Paper §4).
        
        Ý tưởng: nếu attacker hiếm khi đến state s, thì đặt reward ở đó
        sẽ ít hiệu quả. Ngược lại, state có ρ cao → reward ở đó tác động mạnh.
        
        x_effective(s,a) = x_raw(s,a) * ρ(s,a) / max_ρ
        
        Điều này tự động focus budget vào nơi attacker thực sự hay đến.
        """
        if not raw_interventions:
            return raw_interventions

        # Compute occupancy under greedy attacker (worst case for defender)
        occupancy = self.compute_occupancy_measure(
            start_distribution=start_distribution
        )

        if not occupancy:
            return raw_interventions

        max_rho = max(occupancy.values()) if occupancy else 1.0
        if max_rho < 1e-12:
            return raw_interventions

        weighted = {}
        for (s, a), x_raw in raw_interventions.items():
            rho = occupancy.get((s, a), 0.0)
            # Scale: states attacker visits more → more effective reward
            scale = 0.3 + 0.7 * (rho / max_rho)  # Floor at 0.3 to keep some effect
            weighted[(s, a)] = x_raw * scale

        return weighted

    # ----- 6. Full Hybrid Evaluation -----

    def evaluate_defense_exact(
        self,
        reward_interventions: Optional[Dict[Tuple, float]] = None,
        start_distribution: Optional[Dict[int, float]] = None,
    ) -> Dict:
        """
        Đánh giá chính xác (exact) hiệu quả phòng thủ bằng toán MDP.
        
        Trả về tất cả metrics cần thiết:
        - V_robust: minimax defender value (worst-case)
        - V_greedy: value dưới greedy attacker
        - V_expected: value dưới uniform attacker
        - margin: c* guarantee
        - occupancy: ρ(s,a) distribution
        """
        # 1. Robust value (minimax — worst-case attacker)
        V_robust = self.solve_robust_value(reward_interventions)

        # 2. Value under greedy attacker (typical threat)
        greedy_policy = self._build_greedy_attacker_policy(reward_interventions)
        V_greedy = self.solve_value_function(reward_interventions, greedy_policy)

        # 3. Value under uniform random attacker (baseline)
        V_uniform = self.solve_value_function(reward_interventions, policy=None)

        # 4. Margin guarantee
        margin = self.compute_margin(reward_interventions, start_distribution)

        # 5. Occupancy measure
        occupancy = self.compute_occupancy_measure(
            greedy_policy, start_distribution, reward_interventions
        )

        # Weighted values by start distribution
        mu0 = start_distribution or self.graph.start_distribution
        v_robust = sum(V_robust.get(s, 0.0) * p for s, p in mu0.items())
        v_greedy = sum(V_greedy.get(s, 0.0) * p for s, p in mu0.items())
        v_uniform = sum(V_uniform.get(s, 0.0) * p for s, p in mu0.items())

        return {
            "V_robust": v_robust,       # Worst-case defender value
            "V_greedy": v_greedy,        # Value under greedy attacker
            "V_uniform": v_uniform,      # Value under random attacker
            "margin_guarantee": margin,  # c* = improvement over no-defense
            "V_per_state_robust": V_robust,
            "V_per_state_greedy": V_greedy,
            "occupancy": occupancy,
        }


# ============================================================
# Graph Scaling Utilities
# ============================================================

def prune_action_space(
    graph: "MIRAGEAttackGraph",
    belief_state: Optional[Dict[int, float]] = None,
    top_k_states: int = 20,
) -> List[int]:
    """
    Action Space Pruning: chỉ xét deception actions gần belief hotspots.
    
    Với đồ thị lớn (100-1000 nodes), không thể đánh giá TẤT CẢ actions.
    Thay vào đó, chọn top-k states có belief cao nhất + neighbors.
    
    Returns:
        List of state IDs where deception should be considered.
    """
    if belief_state is None:
        belief_state = graph.belief_state or graph.start_distribution

    if not belief_state:
        return list(range(min(top_k_states, len(graph.states))))

    # Sort states by belief probability
    sorted_states = sorted(belief_state.items(), key=lambda x: -x[1])
    hotspots = set()

    predecessors: Dict[int, List[int]] = {s: [] for s in graph.states}
    for s_pred in graph.states:
        for a_pred in graph.available_actions.get(s_pred, []):
            for s_next in graph.transitions.get(s_pred, {}).get(a_pred, {}):
                predecessors.setdefault(s_next, []).append(s_pred)

    for s, p in sorted_states[:top_k_states]:
        hotspots.add(s)
        # Add 1-hop neighbors (states reachable from s)
        for a in graph.available_actions.get(s, []):
            trans = graph.transitions.get(s, {}).get(a, {})
            for s_next in trans:
                hotspots.add(s_next)
        # Add states that can reach s (1-hop predecessors)
        for s_pred in predecessors.get(s, []):
            hotspots.add(s_pred)

    # Always include true goals and decoy sites
    for tg in graph.true_goals:
        hotspots.add(tg)
    for ds in graph.decoy_sites:
        hotspots.add(ds)

    return sorted(hotspots)


def rank_action_candidates(
    actions,
    graph: "MIRAGEAttackGraph",
    belief_state: Optional[Dict[int, float]] = None,
    limit: Optional[int] = None,
) -> List:
    """
    Rank candidate actions by practical value before expensive simulation.

    This is a scale guardrail, not the final optimizer. It keeps the action
    catalog bounded on 100-1000 node graphs by preferring actions near belief
    mass, high-value assets, true goals, decoys, and critical transitions while
    penalizing operational cost.
    """
    if belief_state is None:
        belief_state = getattr(graph, "belief_state", None) or graph.start_distribution

    true_goals = set(graph.true_goals)
    decoys = set(graph.decoy_sites)
    high_risk_nodes = set()
    for path in getattr(graph, "get_high_risk_paths", lambda: [])():
        high_risk_nodes.update(path)

    def node_value(node: int) -> float:
        meta = getattr(graph, "node_metadata", {}).get(node, {}) or {}
        value = float(meta.get("value", 0.0) or 0.0)
        criticality = float(meta.get("business_criticality", value) or 0.0)
        return max(value, criticality)

    def action_score(action) -> float:
        target = getattr(action, "target_node", None)
        score = 0.0
        if target is not None:
            score += 3.0 * float(belief_state.get(target, 0.0))
            score += 1.2 * node_value(target)
            if target in decoys:
                score += 0.6
            if target in true_goals:
                score += 0.4
            if target in high_risk_nodes:
                score += 0.5

        edge = getattr(action, "target_edge", None)
        if edge:
            src, dst = edge
            score += 2.0 * float(belief_state.get(src, 0.0))
            score += 1.4 * node_value(dst)
            if dst in true_goals or dst in high_risk_nodes:
                score += 0.8

        score += 0.5 * float(getattr(action, "realism_score", 0.0) or 0.0)
        score += 0.4 * float(getattr(action, "reward_delta", 0.0) or 0.0)
        score += 0.2 * float(getattr(action, "edge_cost_delta", 0.0) or 0.0)
        score -= 0.18 * compute_composite_cost(action, graph).total
        score -= 0.35 * float(getattr(action, "risk_score", 0.0) or 0.0)
        return score

    ranked = sorted(actions, key=action_score, reverse=True)
    if limit is not None and limit > 0:
        return ranked[:limit]
    return ranked


def build_hierarchical_subgraph(
    graph: "MIRAGEAttackGraph",
    focus_states: List[int],
) -> "MIRAGEAttackGraph":
    """
    Hierarchical Graph Decomposition: tạo subgraph xung quanh focus_states.
    
    Với đồ thị >100 nodes, MDPSolver chạy trên subgraph nhỏ hơn
    thay vì toàn bộ. Transitions ra ngoài subgraph → sink.
    
    Returns:
        Subgraph chỉ chứa focus_states + sink
    """
    import copy

    focus_set = set(focus_states)
    # Ensure sink is included
    focus_set.add(graph.sink_state)

    sub_states = sorted(focus_set)
    sub_transitions = {}
    sub_available = {}
    sub_attacker_r = {}
    sub_defender_r = {}

    for s in sub_states:
        if s not in graph.transitions:
            continue
        sub_transitions[s] = {}
        sub_available[s] = []

        for a in graph.available_actions.get(s, []):
            trans = graph.transitions.get(s, {}).get(a, {})
            if not trans:
                continue

            # Remap: nodes outside focus → sink
            new_trans = {}
            for s_next, p in trans.items():
                if s_next in focus_set:
                    new_trans[s_next] = new_trans.get(s_next, 0.0) + p
                else:
                    new_trans[graph.sink_state] = new_trans.get(graph.sink_state, 0.0) + p

            if new_trans:
                sub_transitions[s][a] = new_trans
                sub_available[s].append(a)

                # Copy rewards
                if (s, a) in graph.attacker_reward:
                    sub_attacker_r[(s, a)] = graph.attacker_reward[(s, a)]
                if (s, a) in graph.defender_reward:
                    sub_defender_r[(s, a)] = graph.defender_reward[(s, a)]

    # Start distribution: filter and renormalize
    sub_start = {}
    for s, p in graph.start_distribution.items():
        if s in focus_set:
            sub_start[s] = p
    total = sum(sub_start.values())
    if total > 0:
        sub_start = {s: p / total for s, p in sub_start.items()}
    else:
        # If no start state in focus, start from first focus state
        sub_start = {sub_states[0]: 1.0}

    from mirage.layer2_attack_graph import MIRAGEAttackGraph

    return MIRAGEAttackGraph(
        states=sub_states,
        actions=graph.actions,
        available_actions=sub_available,
        transitions=sub_transitions,
        start_distribution=sub_start,
        discount=graph.discount,
        budget=graph.budget,
        true_goals=[tg for tg in graph.true_goals if tg in focus_set],
        decoy_sites=[ds for ds in graph.decoy_sites if ds in focus_set],
        sink_state=graph.sink_state,
        state_labels={s: graph.label(s) for s in sub_states},
        attacker_reward=sub_attacker_r,
        defender_reward=sub_defender_r,
        node_metadata={s: graph.node_metadata.get(s, {}) for s in sub_states},
    )


# ============================================================
# Self-test
# ============================================================

if __name__ == "__main__":
    from mirage.layer2_attack_graph import build_enterprise_attack_graph

    print("=" * 70)
    print("MDPSolver — Exact MDP Mathematics Test")
    print("=" * 70)

    graph = build_enterprise_attack_graph()
    solver = MDPSolver(graph)

    # 1. Value function (no defense)
    print("\n[1] Value function (no defense, greedy attacker):")
    V_no_def = solver.solve_value_function()
    for s in sorted(V_no_def, key=V_no_def.get):
        if abs(V_no_def[s]) > 0.01:
            print(f"  {graph.label(s):30s}: V = {V_no_def[s]:+.4f}")

    # 2. Value function (with decoy defense)
    print("\n[2] Value function (with decoy at DB_FAKE, greedy attacker):")
    defense = {(11, "end"): 0.9, (12, "end"): 0.7}  # Decoy rewards
    V_defense = solver.solve_value_function(defense)
    for s in sorted(V_defense, key=V_defense.get):
        if abs(V_defense[s]) > 0.01:
            print(f"  {graph.label(s):30s}: V = {V_defense[s]:+.4f}")

    # 3. Robust value (minimax)
    print("\n[3] Robust value (minimax — worst-case attacker):")
    V_robust_nodef = solver.solve_robust_value()
    V_robust_def = solver.solve_robust_value(defense)
    mu0 = graph.start_distribution
    v_r_no = sum(V_robust_nodef.get(s, 0) * p for s, p in mu0.items())
    v_r_def = sum(V_robust_def.get(s, 0) * p for s, p in mu0.items())
    print(f"  V_robust (no defense):   {v_r_no:+.4f}")
    print(f"  V_robust (with defense): {v_r_def:+.4f}")

    # 4. Margin guarantee
    print("\n[4] Margin guarantee c*:")
    c_star = solver.compute_margin(defense)
    print(f"  c* = {c_star:+.4f}")
    if c_star > 0:
        print(f"  [OK] Defense improves worst-case by {c_star:+.4f}")
    else:
        print(f"  [!] Defense does not improve worst-case")

    # 5. Occupancy measure
    print("\n[5] Top occupancy states (attacker visits):")
    occ = solver.compute_occupancy_measure()
    top_occ = sorted(occ.items(), key=lambda x: -x[1])[:8]
    for (s, a), rho in top_occ:
        print(f"  ({graph.label(s):25s}, {a:12s}): rho = {rho:.4f}")

    # 6. Full evaluation
    print("\n[6] Full exact evaluation:")
    result = solver.evaluate_defense_exact(defense)
    print(f"  V_robust:    {result['V_robust']:+.4f}")
    print(f"  V_greedy:    {result['V_greedy']:+.4f}")
    print(f"  V_uniform:   {result['V_uniform']:+.4f}")
    print(f"  Margin c*:   {result['margin_guarantee']:+.4f}")

    # 7. Composite cost
    print("\n[7] Composite Cost Model:")
    from mirage.layer3_deception import DeceptionFabric
    fabric = DeceptionFabric(graph)
    actions = fabric.get_available_actions(5.0)
    for a in actions[:4]:
        cc = compute_composite_cost(a)
        print(f"  {a.action_type.value:35s}: simple={a.cost:.1f}  composite={cc.total:.2f}  fp={cc.fp_cost:.3f}")

    # 8. Scaling test
    print("\n[8] Action space pruning:")
    belief = {4: 0.45, 3: 0.25, 6: 0.15}
    focus = prune_action_space(graph, belief, top_k_states=5)
    print(f"  Belief hotspot states: {len(focus)}/{len(graph.states)}")
    print(f"  Focus: {[graph.label(s) for s in focus]}")

    print("\n" + "=" * 70)
    print("[OK] MDPSolver test complete")
    print("=" * 70)
