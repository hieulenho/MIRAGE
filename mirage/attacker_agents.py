"""
MIRAGE - Attacker Agents (5 loại)
====================================
Giả lập các tác nhân tấn công với chiến thuật khác nhau,
dùng để test tính robustness của policy phòng thủ.

Agent types:
  1. RandomAttacker    — Di chuyển ngẫu nhiên
  2. GreedyAttacker    — Chọn node có reward cao nhất tức thì
  3. ShortestPathAttacker — Luôn tìm đường ngắn nhất đến True Goal
  4. StealthyAttacker  — Né decoy, chọn đường ít bị phát hiện nhất
  5. DeceptionAwareAttacker — Biết nghi ngờ decoy dựa trên giá trị node
                              và bất thường trong reward structure

Các agent được dùng trong:
  - Lớp 4: Training robust policy (worst-case attacker)
  - Lớp 6: Benchmark/evaluation
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import random
import heapq
import math
from abc import ABC, abstractmethod


@dataclass
class AttackerStep:
    """Một bước của attacker trong quá trình tấn công."""
    state: int
    action: str
    next_state: int
    reward: float
    is_terminal: bool
    attacker_type: str


class BaseAttacker(ABC):
    """Base class cho tất cả attacker agents."""

    def __init__(self, graph, seed: int = 42):
        self.graph = graph
        self.rng = random.Random(seed)
        self.current_state: int = list(graph.start_distribution.keys())[0]
        self.trajectory: List[AttackerStep] = []
        self.total_reward: float = 0.0
        self.steps_taken: int = 0

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def choose_action(self, state: int, reward_interventions: Dict[Tuple[int, str], float] = None) -> str:
        """Chọn action tại state hiện tại."""
        pass

    def get_effective_reward(
        self,
        state: int,
        action: str,
        reward_interventions: Dict[Tuple[int, str], float] = None,
    ) -> float:
        """Tính reward hiệu quả sau khi áp dụng reward interventions."""
        base = self.graph.attacker_reward.get((state, action), 0.0)
        delta = 0.0
        if reward_interventions:
            delta = reward_interventions.get((state, action), 0.0)
        return base + delta

    def step(self, reward_interventions: Dict[Tuple[int, str], float] = None) -> AttackerStep:
        """Thực hiện một bước tấn công."""
        state = self.current_state
        action = self.choose_action(state, reward_interventions)

        # Sample next state
        trans = self.graph.transitions[state][action]
        states_list = list(trans.keys())
        probs = [trans[s] for s in states_list]
        next_state = self.rng.choices(states_list, weights=probs, k=1)[0]

        reward = self.get_effective_reward(state, action, reward_interventions)
        self.total_reward += reward * (self.graph.discount ** self.steps_taken)

        is_terminal = (next_state == self.graph.sink_state)
        step = AttackerStep(
            state=state,
            action=action,
            next_state=next_state,
            reward=reward,
            is_terminal=is_terminal,
            attacker_type=self.name,
        )
        self.trajectory.append(step)
        self.current_state = next_state
        self.steps_taken += 1
        return step

    def run_episode(
        self,
        max_steps: int = 30,
        reward_interventions: Dict[Tuple[int, str], float] = None,
        start_distribution: Dict[int, float] = None,
    ) -> Tuple[bool, bool, int]:
        """
        Chạy một tập tấn công đến khi kết thúc hoặc hết bước.

        Args:
            start_distribution: Nếu có, sample vị trí bắt đầu từ belief state này.

        Returns:
            (hit_true_goal, hit_decoy, steps)
        """
        self.reset(start_distribution=start_distribution)
        for _ in range(max_steps):
            step = self.step(reward_interventions)
            if step.is_terminal:
                # Kiểm tra kết thúc tại đâu
                hit_true = step.state in self.graph.true_goals
                hit_decoy = self.graph.is_decoy(step.state)
                return hit_true, hit_decoy, self.steps_taken
        return False, False, self.steps_taken

    def reset(self, start_distribution: Dict[int, float] = None) -> None:
        """
        Reset về trạng thái ban đầu.

        Args:
            start_distribution: Nếu được cung cấp, sample vị trí khởi đầu từ phân phối này
                                 (tức là belief state từ Layer 1/2).
                                 Nếu None, dùng graph.start_distribution (entry point mặc định).
        """
        if start_distribution:
            # Lọc bỏ sink state và normalize
            sink = self.graph.sink_state
            filtered = {s: p for s, p in start_distribution.items()
                        if s != sink and p > 0.0}
            if filtered:
                total = sum(filtered.values())
                states_list = list(filtered.keys())
                weights = [filtered[s] / total for s in states_list]
                self.current_state = self.rng.choices(states_list, weights=weights, k=1)[0]
            else:
                # Fallback nếu tất cả bị lọc
                self.current_state = list(self.graph.start_distribution.keys())[0]
        else:
            self.current_state = list(self.graph.start_distribution.keys())[0]
        self.trajectory = []
        self.total_reward = 0.0
        self.steps_taken = 0

    def summary(self) -> str:
        """Tóm tắt trajectory."""
        path = []
        for step in self.trajectory:
            path.append(self.graph.label(step.state))
        if self.trajectory:
            path.append(self.graph.label(self.trajectory[-1].next_state))
        return " → ".join(path)


# ============================================================
# ATTACKER 1: RANDOM
# ============================================================

class RandomAttacker(BaseAttacker):
    """
    Attacker di chuyển ngẫu nhiên — baseline đơn giản nhất.
    Không có chiến lược, chọn action ngẫu nhiên đều nhau.
    """

    def choose_action(
        self,
        state: int,
        reward_interventions: Dict[Tuple[int, str], float] = None,
    ) -> str:
        actions = self.graph.available_actions[state]
        return self.rng.choice(actions)


# ============================================================
# ATTACKER 2: GREEDY
# ============================================================

class GreedyAttacker(BaseAttacker):
    """
    Attacker tham lam — luôn chọn action có reward cao nhất tức thì.
    Không nhìn xa, chỉ tối ưu bước hiện tại.
    Dễ bị dụ vào decoy nếu reward decoy đủ hấp dẫn.
    """

    def choose_action(
        self,
        state: int,
        reward_interventions: Dict[Tuple[int, str], float] = None,
    ) -> str:
        actions = self.graph.available_actions[state]
        if len(actions) == 1:
            return actions[0]

        # Tính expected reward cho mỗi action (1 bước nhìn trước)
        best_action = actions[0]
        best_value = -float("inf")

        for action in actions:
            # Tính expected immediate reward
            trans = self.graph.transitions[state][action]
            exp_reward = 0.0
            for next_s, prob in trans.items():
                r = self.get_effective_reward(next_s, "end", reward_interventions)
                # Cũng tính reward cho action "end" từ next state
                if "end" in self.graph.available_actions.get(next_s, []):
                    exp_reward += prob * r
                # Reward trực tiếp tại action
                direct_r = self.get_effective_reward(state, action, reward_interventions)
                exp_reward += prob * direct_r * 0.3  # Discount nhẹ

            if exp_reward > best_value:
                best_value = exp_reward
                best_action = action

        return best_action


# ============================================================
# ATTACKER 3: SHORTEST PATH
# ============================================================

class ShortestPathAttacker(BaseAttacker):
    """
    Attacker tìm đường ngắn nhất đến True Goal.
    Dùng Dijkstra/BFS trên đồ thị, không bị dụ bởi reward cao của decoy
    trừ khi decoy reward > 0 (bị reward intervention dẫn dụ).
    
    Đây là "rational" attacker — nguy hiểm nhất nếu không có deception.
    """

    def __init__(self, graph, seed: int = 42):
        super().__init__(graph, seed)
        self._path_cache: Dict[int, List[int]] = {}  # state → next state on shortest path
        self._precompute_shortest_paths()

    def _precompute_shortest_paths(self) -> None:
        """Precompute shortest paths từ mọi state đến True Goal dùng Dijkstra."""
        target = self.graph.true_goals[0]

        # Dijkstra ngược (từ target về các node)
        # dist[s] = xác suất tối đa đến target trong 1 hop
        INF = float("inf")

        # Forward BFS với negative log prob để convert sang shortest path
        dist = {s: INF for s in self.graph.states}
        dist[target] = 0.0
        # prev[s] = (prev_state, action) để reconstruct path
        prev: Dict[int, Tuple[int, str]] = {}

        # BFS với priority queue
        pq = [(0.0, target)]

        # Xây dựng reverse graph
        reverse_graph: Dict[int, List[Tuple[int, str, float]]] = {s: [] for s in self.graph.states}
        for s in self.graph.states:
            for action in self.graph.available_actions.get(s, []):
                trans = self.graph.transitions[s][action]
                for ns, prob in trans.items():
                    if prob > 0:
                        reverse_graph[ns].append((s, action, prob))

        while pq:
            d, s = heapq.heappop(pq)
            if d > dist[s]:
                continue
            for prev_s, action, prob in reverse_graph[s]:
                # Cost = negative log probability (shorter path = higher prob)
                edge_cost = -math.log(max(prob, 1e-9))
                new_dist = dist[s] + edge_cost
                if new_dist < dist[prev_s]:
                    dist[prev_s] = new_dist
                    prev[prev_s] = (s, action)
                    heapq.heappush(pq, (new_dist, prev_s))

        # Lưu next step trên đường ngắn nhất
        self._next_on_path: Dict[int, Tuple[str, int]] = {}  # state → (action, next_state)
        for s in self.graph.states:
            if s in prev:
                ns, action = prev[s]
                self._next_on_path[s] = (action, ns)

    def choose_action(
        self,
        state: int,
        reward_interventions: Dict[Tuple[int, str], float] = None,
    ) -> str:
        actions = self.graph.available_actions[state]
        if len(actions) == 1:
            return actions[0]

        # Kiểm tra xem có reward intervention nào đủ hấp dẫn không
        if reward_interventions:
            best_bait = None
            best_bait_value = 0.5  # Ngưỡng bị dụ dỗ
            for action in actions:
                bait_reward = reward_interventions.get((state, action), 0.0)
                if bait_reward > best_bait_value:
                    # Tính xem đường đến bait có ngắn hơn đường đến True Goal không
                    trans = self.graph.transitions[state][action]
                    for ns, prob in trans.items():
                        ns_bait_r = reward_interventions.get((ns, "end"), 0.0)
                        if ns_bait_r > best_bait_value and prob > 0.4:
                            best_bait = action
                            best_bait_value = ns_bait_r

            # ShortestPath attacker chỉ bị dụ 30% thời gian (không hoàn hảo)
            if best_bait and self.rng.random() < 0.3:
                return best_bait

        # Nếu không bị dụ, đi theo đường ngắn nhất
        if state in self._next_on_path:
            optimal_action, _ = self._next_on_path[state]
            if optimal_action in actions:
                return optimal_action

        # Fallback: greedy
        return self.rng.choice(actions)


# ============================================================
# ATTACKER 4: STEALTHY
# ============================================================

class StealthyAttacker(BaseAttacker):
    """
    Attacker ẩn mình — tránh các node có khả năng là decoy cao.
    Chiến lược: đi chậm hơn nhưng an toàn hơn; né các node có realism thấp.
    
    Đây là kẻ tấn công khó đánh lừa nhất — test giới hạn của deception.
    """

    def __init__(self, graph, seed: int = 42, suspicion_threshold: float = 0.5):
        super().__init__(graph, seed)
        # Threshold: nếu suspicion > threshold thì né node đó
        self.suspicion_threshold = suspicion_threshold
        # Suspicion score mỗi node (0=tin tưởng, 1=nghi ngờ là decoy)
        self._node_suspicion: Dict[int, float] = self._init_suspicion()

    def _init_suspicion(self) -> Dict[int, float]:
        """
        Khởi tạo suspicion scores dựa trên heuristics topological thuần túy.

        KHÔNG đọc is_real hay asset_type từ node_metadata — đó là ground truth
        mà attacker không có quyền biết trước khi deception được deploy.

        Heuristic: node có rất ít outgoing action (dead-end) thì có khả năng
        là endpoint (sink, decoy, hoặc terminal asset). Attacker cẩn thận sẽ
        hơi nghi ngờ những node này, nhưng không chắc.
        """
        suspicion = {}
        sink = self.graph.sink_state
        for s in self.graph.states:
            if s == sink:
                # Sink đã biết là terminal — không đi vào đây
                suspicion[s] = 0.95
            else:
                n_actions = len(self.graph.available_actions.get(s, []))
                if n_actions <= 1:
                    # Dead-end node: chỉ có action "end" hoặc "noop"
                    # Có thể là decoy hoặc true goal — attacker không biết chắc
                    suspicion[s] = 0.25
                else:
                    # Node có nhiều lựa chọn → ít nghi ngờ
                    suspicion[s] = 0.05
        return suspicion

    def update_suspicion(self, node: int, delta: float) -> None:
        """Cập nhật suspicion khi có bằng chứng mới."""
        current = self._node_suspicion.get(node, 0.1)
        self._node_suspicion[node] = min(1.0, max(0.0, current + delta))

    def _estimate_suspicion_from_rewards(
        self,
        state: int,
        action: str,
        reward_interventions: Dict[Tuple[int, str], float],
    ) -> float:
        """
        Ước tính mức độ "giả tạo" dựa trên reward bất thường.
        Reward quá cao hoặc quá thấp đều đáng ngờ.
        """
        trans = self.graph.transitions[state][action]
        max_suspicion = 0.0
        for ns, prob in trans.items():
            base_s = self._node_suspicion.get(ns, 0.1)
            # Nếu reward intervention tại ns quá cao → suspicious
            if reward_interventions:
                bait = reward_interventions.get((ns, "end"), 0.0)
                if bait > 0.6:  # Reward quá hấp dẫn → nghi ngờ là bẫy
                    bait_suspicion = min(1.0, bait * 0.7)
                    max_suspicion = max(max_suspicion, bait_suspicion * prob)
            max_suspicion = max(max_suspicion, base_s * prob)
        return max_suspicion

    def choose_action(
        self,
        state: int,
        reward_interventions: Dict[Tuple[int, str], float] = None,
    ) -> str:
        actions = self.graph.available_actions[state]
        if len(actions) == 1:
            return actions[0]

        if reward_interventions is None:
            reward_interventions = {}

        # Tính score cho mỗi action: reward cao nhưng suspicion thấp
        action_scores = []
        for action in actions:
            # Reward kỳ vọng
            trans = self.graph.transitions[state][action]
            exp_reward = 0.0
            for ns, prob in trans.items():
                r_base = self.graph.attacker_reward.get((ns, "end"), 0.0)
                exp_reward += prob * r_base  # Chỉ dùng base reward, bỏ qua bait

            # Suspicion penalty
            suspicion = self._estimate_suspicion_from_rewards(state, action, reward_interventions)
            if suspicion > self.suspicion_threshold:
                # Né hành động này với xác suất cao
                action_scores.append(-1.0 * suspicion)
            else:
                # Thưởng cho đường ít nguy hiểm + có reward
                action_scores.append(exp_reward - suspicion * 0.5)

        # Chọn action có score cao nhất (với softmax nhỏ)
        tau = 0.3  # Temperature
        max_score = max(action_scores)
        weights = [math.exp((s - max_score) / tau) for s in action_scores]
        chosen = self.rng.choices(actions, weights=weights, k=1)[0]

        # Cập nhật suspicion cho các node bị né
        for i, action in enumerate(actions):
            if action_scores[i] < 0:
                trans = self.graph.transitions[state][action]
                for ns in trans:
                    self.update_suspicion(ns, 0.05)  # Tăng suspicion khi né

        return chosen


# ============================================================
# ATTACKER 5: DECEPTION AWARE
# ============================================================

class DeceptionAwareAttacker(BaseAttacker):
    """
    Attacker thông minh nhất — biết nghi ngờ decoy dựa trên nhiều tín hiệu
    kết hợp: node value, topology structure, và reward anomaly.

    Chiến lược nâng cao so with StealthyAttacker:
      1. Node value heuristic: node với attacker_reward = 0.0 tại "end"
         nhưng lại là terminal (dead-end) → rất có thể là decoy
      2. Label-based suspicion: node label chứa "FAKE", "Backup", "Gateway"
         → attacker đọc được banner và nghi ngờ
      3. Reward anomaly: reward intervention cao bất thường (> threshold)
         → cảnh báo đây là bẫy, xác suất né cao hơn Stealthy
      4. Episode-level learning: tích lũy suspicion trong episode

    Kết quả:
      - Khó bị dụ hơn StealthyAttacker (~60-70% thời gian né được decoy)
      - Nhưng không immune: nếu realism_score cao (decoy trông như thật)
        → vẫn bị lừa khoảng 30-40% trường hợp
      - Đây là "hard test" cho MIRAGE: nếu pessimistic value vẫn tốt
        trước attacker này → luận điểm robust mạnh hơn nhiều
    """

    # Từ khóa trong label gây nghi ngờ (attacker đọc network banner)
    SUSPICIOUS_LABEL_KEYWORDS = ["fake", "backup", "gateway", "decoy", "honey"]

    def __init__(
        self,
        graph,
        seed: int = 42,
        suspicion_threshold: float = 0.45,       # Thấp hơn Stealthy → nghi ngờ sớm hơn
        reward_anomaly_threshold: float = 0.55,  # Reward intervention nào > này là bẫy
        label_awareness: bool = True,            # Có đọc label để nghi ngờ không
    ):
        super().__init__(graph, seed)
        self.suspicion_threshold = suspicion_threshold
        self.reward_anomaly_threshold = reward_anomaly_threshold
        self.label_awareness = label_awareness

        # Cache suspicion scores (cập nhật động trong episode)
        self._base_suspicion: Dict[int, float] = self._compute_base_suspicion()
        self._episode_suspicion: Dict[int, float] = {}  # Reset mỗi episode

    def _compute_base_suspicion(self) -> Dict[int, float]:
        """
        Tính base suspicion cho mỗi node dựa trên:
          1. Structural: dead-end topology
          2. Value: attacker reward = 0.0 tại terminal node
          3. Label: keyword trong tên node (nếu label_awareness=True)

        Đây là prior knowledge attacker có trước khi bắt đầu tấn công.
        """
        suspicion: Dict[int, float] = {}
        sink = self.graph.sink_state

        for s in self.graph.states:
            if s == sink:
                suspicion[s] = 1.0  # Sink hoàn toàn vô dụng
                continue

            score = 0.0

            # --- Heuristic 1: Dead-end topology ---
            n_actions = len(self.graph.available_actions.get(s, []))
            if n_actions <= 1:
                score += 0.30  # Terminal node → có thể là decoy hoặc true goal

            metadata = self.graph.get_node_info(s)
            realism = float(metadata.get("realism_score", 1.0) or 1.0)
            behavioral_signal = float(metadata.get("behavioral_signal", 0.0) or 0.0)
            score += max(0.0, 1.0 - realism) * 0.35
            score += min(1.0, behavioral_signal) * 0.35

            # --- Heuristic 2: attacker-visible label/banner matching ---
            if self.label_awareness:
                label = self.graph.attacker_label(s).lower()
                banner = str(metadata.get("service_banner", "")).lower()
                for kw in self.SUSPICIOUS_LABEL_KEYWORDS:
                    if kw in label or kw in banner:
                        score += 0.35
                        break

            suspicion[s] = min(1.0, score)

        return suspicion

    def reset(self, start_distribution: Dict[int, float] = None) -> None:
        """Reset episode-level suspicion mỗi khi bắt đầu episode mới."""
        super().reset(start_distribution=start_distribution)
        # Khởi tạo episode suspicion từ base suspicion
        self._episode_suspicion = dict(self._base_suspicion)

    def _get_current_suspicion(self, node: int) -> float:
        """Lấy suspicion hiện tại (base + episode updates)."""
        return self._episode_suspicion.get(node, self._base_suspicion.get(node, 0.05))

    def _update_suspicion(self, node: int, delta: float) -> None:
        """Cập nhật suspicion trong episode (không ảnh hưởng base)."""
        current = self._get_current_suspicion(node)
        self._episode_suspicion[node] = min(1.0, max(0.0, current + delta))

    def _estimate_action_danger(
        self,
        state: int,
        action: str,
        reward_interventions: Optional[Dict[Tuple[int, str], float]],
    ) -> Tuple[float, float]:
        """
        Ước tính (expected_value, danger_score) cho một action.

        expected_value: giá trị kỳ vọng theo base attacker reward (không tính bait)
        danger_score: mức độ nguy hiểm / nghi ngờ là bẫy

        Returns: (expected_value, danger_score)
        """
        trans = self.graph.transitions[state][action]
        exp_value = 0.0
        max_danger = 0.0

        for ns, prob in trans.items():
            # Giá trị base (không bị ảnh hưởng bởi bait)
            base_reward = self.graph.attacker_reward.get((ns, "end"), 0.0)
            exp_value += prob * base_reward

            # Tính danger từ nhiều nguồn
            node_suspicion = self._get_current_suspicion(ns)
            danger = node_suspicion

            # Reward anomaly detection: bait quá cao so với base reward → bẫy
            if reward_interventions:
                bait = reward_interventions.get((ns, "end"), 0.0)
                if bait > self.reward_anomaly_threshold:
                    # Reward bất thường cao → nghi ngờ mạnh
                    anomaly_danger = min(1.0, (bait - self.reward_anomaly_threshold) * 2.0 + 0.4)
                    danger = max(danger, anomaly_danger)

            max_danger = max(max_danger, danger * prob)

        return exp_value, max_danger

    def choose_action(
        self,
        state: int,
        reward_interventions: Dict[Tuple[int, str], float] = None,
    ) -> str:
        actions = self.graph.available_actions[state]
        if len(actions) == 1:
            return actions[0]

        # Tính (value, danger) cho mỗi action
        action_evals: List[Tuple[str, float, float]] = []
        for action in actions:
            val, danger = self._estimate_action_danger(state, action, reward_interventions)
            action_evals.append((action, val, danger))

        # Lọc: nếu action nguy hiểm (danger > threshold) → giảm điểm mạnh
        action_scores = []
        for action, val, danger in action_evals:
            if danger > self.suspicion_threshold:
                # Né mạnh: score âm, tỷ lệ thuận với mức nghi ngờ
                score = -danger * 2.0
            else:
                # Score = value - penalty nhỏ cho mức nghi ngờ
                score = val - danger * 0.3
            action_scores.append(score)

        # Dùng softmax với temperature thấp hơn Stealthy → quyết đoán hơn
        tau = 0.25  # Temperature thấp = quyết đoán hơn Stealthy (0.3)
        max_score = max(action_scores)
        weights = [math.exp((s - max_score) / tau) for s in action_scores]
        chosen = self.rng.choices(actions, weights=weights, k=1)[0]

        # Cập nhật suspicion cho các node bị né (reinforcement của prior)
        for i, (action, val, danger) in enumerate(action_evals):
            if action_scores[i] < 0:
                trans = self.graph.transitions[state][action]
                for ns in trans:
                    self._update_suspicion(ns, 0.08)  # Mạnh hơn Stealthy (0.05)

        return chosen


# ============================================================
# AGENT FACTORY
# ============================================================

def create_attacker(attacker_type: str, graph, seed: int = 42) -> BaseAttacker:
    """Factory function tạo attacker theo loại."""
    if attacker_type == "mitre_evasion":
        from mirage.attacker_mitre import MITREEvasionAttacker

        return MITREEvasionAttacker(graph, seed=seed)

    types = {
        "random":           RandomAttacker,
        "greedy":           GreedyAttacker,
        "shortest_path":    ShortestPathAttacker,
        "stealthy":         StealthyAttacker,
        "deception_aware":  DeceptionAwareAttacker,
    }
    if attacker_type not in types:
        choices = list(types.keys()) + ["mitre_evasion"]
        raise ValueError(f"Unknown attacker type: {attacker_type}. Choose from {choices}")
    return types[attacker_type](graph, seed=seed)


def run_simulation(
    graph,
    attacker_type: str,
    n_episodes: int = 100,
    reward_interventions: Dict[Tuple[int, str], float] = None,
    seed: int = 42,
    max_steps: int = 30,
    start_distribution: Dict[int, float] = None,
) -> Dict:
    """
    Chạy simulation với một loại attacker trong nhiều episode.

    Args:
        start_distribution: Nếu được cung cấp, mỗi episode sẽ sample vị trí khởi đầu
                             từ phân phối này thay vì luôn bắt đầu từ entry point.
                             Đây là cách inject belief state (từ Layer 1/2) vào simulation.

    Returns:
        Dict với các metrics: hit_rate, interception_rate, avg_steps, etc.
    """
    attacker = create_attacker(attacker_type, graph, seed=seed)
    hits_true_goal = 0
    hits_decoy = 0
    total_steps = 0
    total_reward = 0.0

    for ep in range(n_episodes):
        hit_true, hit_decoy, steps = attacker.run_episode(
            max_steps=max_steps,
            reward_interventions=reward_interventions,
            start_distribution=start_distribution,
        )
        if hit_true:
            hits_true_goal += 1
        if hit_decoy:
            hits_decoy += 1
        total_steps += steps
        total_reward += attacker.total_reward

    return {
        "attacker_type": attacker_type,
        "n_episodes": n_episodes,
        "hit_true_goal_rate": hits_true_goal / n_episodes,
        "decoy_interception_rate": hits_decoy / n_episodes,
        "avg_steps_to_terminal": total_steps / n_episodes,
        "avg_discounted_reward": total_reward / n_episodes,
    }


if __name__ == "__main__":
    from mirage.layer2_attack_graph import build_enterprise_attack_graph

    graph = build_enterprise_attack_graph()

    print("Testing all attacker types (no defense)...")
    print("=" * 70)
    for atype in [
        "random", "greedy", "shortest_path", "stealthy",
        "deception_aware", "mitre_evasion",
    ]:
        result = run_simulation(graph, atype, n_episodes=200, seed=42)
        print(f"\n{result['attacker_type']:20s}:")
        print(f"  True Goal Hit Rate:      {result['hit_true_goal_rate']:.1%}")
        print(f"  Decoy Interception Rate: {result['decoy_interception_rate']:.1%}")
        print(f"  Avg Steps to Terminal:   {result['avg_steps_to_terminal']:.1f}")
        print(f"  Avg Discounted Reward:   {result['avg_discounted_reward']:.4f}")

    print("\nTesting with deception (fake DB reward=0.9 planted)...")
    print("=" * 70)
    from mirage.layer2_attack_graph import build_runtime_graph, DB_FAKE
    from mirage.layer3_deception import DeceptionFabric

    fabric = DeceptionFabric(graph)
    deploy = next(
        action for action in fabric.action_catalog
        if action.action_type.value == "deploy_decoy_database"
        and action.target_node == DB_FAKE
    )
    active_graph = build_runtime_graph(graph, actions=[deploy])
    fake_interventions = {(DB_FAKE, "end"): deploy.reward_delta}
    for atype in [
        "random", "greedy", "shortest_path", "stealthy",
        "deception_aware", "mitre_evasion",
    ]:
        result = run_simulation(active_graph, atype, n_episodes=200,
                                reward_interventions=fake_interventions, seed=42)
        print(f"\n{result['attacker_type']:20s} (with deception):")
        print(f"  True Goal Hit Rate:      {result['hit_true_goal_rate']:.1%}")
        print(f"  Decoy Interception Rate: {result['decoy_interception_rate']:.1%}")
