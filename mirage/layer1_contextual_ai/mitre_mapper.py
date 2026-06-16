"""
MIRAGE - MITRE ATT&CK Evasion Extension for DeceptionAwareAttacker
=====================================================================
Bổ sung các kỹ thuật evasion từ MITRE ATT&CK vào DeceptionAwareAttacker
để tạo ra kẻ tấn công khó phát hiện và khó đánh lừa hơn.

Các kỹ thuật được mô hình hóa:
  T1027  — Obfuscated Files or Information (làm rối tín hiệu telemetry)
  T1562  — Impair Defenses (giảm hiệu quả honey credential / decoy detection)
  T1070  — Indicator Removal (xóa dấu vết sau khi tương tác với decoy)
  T1036  — Masquerading (giả vờ là traffic hợp lệ, né honeypot filter)
  LOLBin — Living off the Land (dùng công cụ hệ thống, né signature detection)

Mỗi kỹ thuật ảnh hưởng đến:
  - Suspicion threshold (giảm mức độ bị phát hiện bởi rule-based/HMM)
  - Reward anomaly detection (né phát hiện bait reward quá cao)
  - Episode learning (giới hạn khả năng học của HMM từ attacker này)

Cách dùng:
  from mirage.layer1_contextual_ai.mitre_mapper import MITREEvasionAttacker
  agent = MITREEvasionAttacker(graph, techniques=["T1027", "T1562", "LOLBin"])
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from mirage.shared.attacker_agents import DeceptionAwareAttacker


# ---------------------------------------------------------------------------
# Evasion Technique Definitions
# ---------------------------------------------------------------------------

@dataclass
class EvasionTechnique:
    """Mô hình hóa một kỹ thuật evasion MITRE ATT&CK."""
    technique_id: str
    name: str
    description: str
    # Tác động tới các tham số attacker
    suspicion_threshold_delta: float = 0.0   # Tăng ngưỡng → khó bị nhận ra là attacker
    reward_anomaly_delta: float = 0.0         # Tăng ngưỡng → ít bị dụ bởi bait reward
    noise_prob: float = 0.0                   # Xác suất thêm nhiễu vào action selection
    label_blind: bool = False                  # True → bỏ qua label-based suspicion
    evasion_success_prob: float = 0.8         # Xác suất kỹ thuật thành công mỗi bước


MITRE_TECHNIQUES: Dict[str, EvasionTechnique] = {
    "T1027": EvasionTechnique(
        technique_id="T1027",
        name="Obfuscated Files or Information",
        description=(
            "Attacker obfuscates actions to blend into normal traffic. "
            "Reduces behavioral signal visibility: decoy interactions look like "
            "routine access, reducing rule-based suspicion scoring."
        ),
        suspicion_threshold_delta=+0.10,   # Harder to detect
        reward_anomaly_delta=+0.05,        # Slight improvement in bait detection
        noise_prob=0.10,                   # 10% chance of adding noise step
        evasion_success_prob=0.85,
    ),
    "T1562": EvasionTechnique(
        technique_id="T1562",
        name="Impair Defenses",
        description=(
            "Attacker disables or degrades defensive tools before moving laterally. "
            "Honey credentials generate fewer alerts; decoy engagement signals "
            "are suppressed by 40%."
        ),
        suspicion_threshold_delta=+0.12,
        reward_anomaly_delta=+0.15,        # Better at detecting unrealistic bait
        noise_prob=0.05,
        evasion_success_prob=0.80,
    ),
    "T1070": EvasionTechnique(
        technique_id="T1070",
        name="Indicator Removal",
        description=(
            "Attacker clears logs and artefacts after decoy interactions. "
            "Episode-level suspicion update is weakened — attacker 'forgets' less "
            "from bad experiences."
        ),
        suspicion_threshold_delta=+0.05,
        reward_anomaly_delta=0.0,
        noise_prob=0.0,
        evasion_success_prob=0.90,
    ),
    "T1036": EvasionTechnique(
        technique_id="T1036",
        name="Masquerading",
        description=(
            "Attacker uses legitimate names/banners to bypass label-based detection. "
            "Disables keyword-based suspicion (SUSPICIOUS_LABEL_KEYWORDS) in "
            "DeceptionAwareAttacker."
        ),
        label_blind=True,
        suspicion_threshold_delta=+0.08,
        reward_anomaly_delta=0.0,
        noise_prob=0.0,
        evasion_success_prob=0.75,
    ),
    "LOLBin": EvasionTechnique(
        technique_id="LOLBin",
        name="Living off the Land Binaries",
        description=(
            "Attacker uses built-in system tools (certutil, wmic, powershell). "
            "Makes lateral movement appear as benign admin activity. "
            "Reduces suspicion score for all internal nodes."
        ),
        suspicion_threshold_delta=+0.15,
        reward_anomaly_delta=+0.08,
        noise_prob=0.08,
        evasion_success_prob=0.82,
    ),
}


# ---------------------------------------------------------------------------
# MITRE Evasion Attacker
# ---------------------------------------------------------------------------

class MITREEvasionAttacker(DeceptionAwareAttacker):
    """
    DeceptionAwareAttacker nâng cao với các kỹ thuật evasion MITRE ATT&CK.

    Inherits tất cả logic của DeceptionAwareAttacker và thêm:
    1. Evasion modifier: điều chỉnh suspicion_threshold và reward_anomaly_threshold
       dựa trên danh sách kỹ thuật active
    2. Noise injection: đôi khi chọn suboptimal action để blend vào traffic bình thường
    3. Label blindness: kỹ thuật T1036 làm cho attacker bỏ qua label-based detection
    4. Suspicion decay: T1070 làm cho episode_suspicion giảm dần thay vì chỉ tăng
    """

    def __init__(
        self,
        graph,
        seed: int = 42,
        techniques: Optional[List[str]] = None,
        base_suspicion_threshold: float = 0.45,
        base_reward_anomaly_threshold: float = 0.55,
    ):
        """
        Args:
            graph: MIRAGEAttackGraph
            seed: Random seed
            techniques: List of technique IDs to enable.
                        Default: ["T1027", "T1562", "T1036", "LOLBin"]
            base_suspicion_threshold: Base threshold before evasion modifiers
            base_reward_anomaly_threshold: Base reward anomaly threshold
        """
        # Resolve techniques
        active_ids = techniques if techniques is not None else ["T1027", "T1562", "T1036", "LOLBin"]
        self.active_techniques: Dict[str, EvasionTechnique] = {}
        for tid in active_ids:
            if tid in MITRE_TECHNIQUES:
                self.active_techniques[tid] = MITRE_TECHNIQUES[tid]
            else:
                import warnings
                warnings.warn(
                    f"Unknown MITRE technique '{tid}', skipping.",
                    stacklevel=2,
                )

        # Compute effective thresholds from cumulative evasion effects
        susp_delta = sum(t.suspicion_threshold_delta for t in self.active_techniques.values())
        anomaly_delta = sum(t.reward_anomaly_delta for t in self.active_techniques.values())
        label_blind = any(t.label_blind for t in self.active_techniques.values())

        # Overall noise probability (bounded at 0.30)
        self._noise_prob = min(0.30, sum(t.noise_prob for t in self.active_techniques.values()))

        # T1070 Indicator Removal: suspicion updates are weaker (decay coefficient)
        self._suspicion_decay = 0.5 if "T1070" in self.active_techniques else 1.0

        effective_susp_thresh  = min(0.95, base_suspicion_threshold + susp_delta)
        effective_anomaly_thresh = min(0.95, base_reward_anomaly_threshold + anomaly_delta)

        super().__init__(
            graph=graph,
            seed=seed,
            suspicion_threshold=effective_susp_thresh,
            reward_anomaly_threshold=effective_anomaly_thresh,
            label_awareness=not label_blind,
        )

        self._evasion_rng = random.Random(seed + 1337)

    @property
    def name(self) -> str:
        tids = "+".join(sorted(self.active_techniques.keys()))
        return f"MITREEvasion({tids})"

    def _update_suspicion(self, node: int, delta: float) -> None:
        """
        Override: T1070 causes weaker suspicion updates.
        Attacker 'clears artefacts' so learns less from bad experiences.
        """
        super()._update_suspicion(node, delta * self._suspicion_decay)

    def choose_action(
        self,
        state: int,
        reward_interventions: Dict[Tuple[int, str], float] = None,
    ) -> str:
        actions = self.graph.available_actions[state]
        if len(actions) == 1:
            return actions[0]

        # Noise injection: with noise_prob, pick a random suboptimal action
        # to simulate "masquerade as normal traffic"
        if self._noise_prob > 0 and self._evasion_rng.random() < self._noise_prob:
            # Choose uniformly but avoid "end" if other options exist
            non_terminal = [a for a in actions if a not in ("end", "noop")]
            pool = non_terminal or actions
            return self._evasion_rng.choice(pool)

        # Otherwise, use DeceptionAwareAttacker's sophisticated logic
        return super().choose_action(state, reward_interventions)

    def technique_summary(self) -> str:
        """Print a summary of active evasion techniques."""
        lines = [
            "=" * 65,
            f"MITRE ATT&CK Evasion Profile ({len(self.active_techniques)} techniques active)",
            "=" * 65,
            f"  Effective suspicion_threshold:  {self.suspicion_threshold:.2f}",
            f"  Effective anomaly_threshold:    {self.reward_anomaly_threshold:.2f}",
            f"  Noise injection probability:    {self._noise_prob:.0%}",
            f"  Suspicion decay (T1070):        {self._suspicion_decay:.1f}x",
            "",
            "Active Techniques:",
        ]
        for tid, tech in self.active_techniques.items():
            lines.append(f"  [{tid}] {tech.name}")
            lines.append(f"         {tech.description[:80]}...")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Factory: extend create_attacker to include MITRE agent
# ---------------------------------------------------------------------------

def create_mitre_attacker(
    graph,
    seed: int = 42,
    techniques: Optional[List[str]] = None,
) -> MITREEvasionAttacker:
    """
    Create a MITREEvasionAttacker with the specified techniques.

    Args:
        graph: MIRAGEAttackGraph
        seed: Random seed
        techniques: List of technique IDs. Defaults to ["T1027", "T1562", "T1036", "LOLBin"]

    Returns:
        MITREEvasionAttacker
    """
    return MITREEvasionAttacker(graph, seed=seed, techniques=techniques)


def run_mitre_simulation(
    graph,
    techniques: Optional[List[str]] = None,
    n_episodes: int = 100,
    reward_interventions=None,
    seed: int = 42,
    max_steps: int = 30,
    start_distribution: Optional[Dict[int, float]] = None,
) -> Dict:
    """
    Run a simulation with MITREEvasionAttacker and return results.

    Signature matches run_simulation() in attacker_agents.py for
    drop-in compatibility.
    """
    if n_episodes < 1:
        raise ValueError("n_episodes must be at least 1")
    if max_steps < 1:
        raise ValueError("max_steps must be at least 1")
    attacker = create_mitre_attacker(graph, seed=seed, techniques=techniques)
    hits_true_goal = 0
    hits_decoy = 0
    total_steps = 0
    total_reward = 0.0

    for _ in range(n_episodes):
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
        "attacker_type": attacker.name,
        "techniques": list(attacker.active_techniques.keys()),
        "n_episodes": n_episodes,
        "hit_true_goal_rate": hits_true_goal / n_episodes,
        "decoy_interception_rate": hits_decoy / n_episodes,
        "avg_steps_to_terminal": total_steps / n_episodes,
        "avg_discounted_reward": total_reward / n_episodes,
    }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from mirage.layer2_graph_engine.attack_graph import build_enterprise_attack_graph

    graph = build_enterprise_attack_graph()

    print("Testing MITREEvasionAttacker vs standard DeceptionAwareAttacker")
    print("=" * 70)

    # Baseline: standard DeceptionAwareAttacker
    from mirage.shared.attacker_agents import run_simulation
    baseline = run_simulation(graph, "deception_aware", n_episodes=200, seed=42)
    print("\nBaseline DeceptionAwareAttacker:")
    print(f"  True Goal Hit Rate:      {baseline['hit_true_goal_rate']:.1%}")
    print(f"  Decoy Interception Rate: {baseline['decoy_interception_rate']:.1%}")
    print(f"  Avg Steps:               {baseline['avg_steps_to_terminal']:.1f}")

    # All techniques
    all_tech = run_mitre_simulation(graph, techniques=None, n_episodes=200, seed=42)
    print("\nMITREEvasionAttacker (all 4 techniques):")
    print(f"  True Goal Hit Rate:      {all_tech['hit_true_goal_rate']:.1%}")
    print(f"  Decoy Interception Rate: {all_tech['decoy_interception_rate']:.1%}")
    print(f"  Avg Steps:               {all_tech['avg_steps_to_terminal']:.1f}")

    # With deception active
    from mirage.layer2_graph_engine.attack_graph import DB_FAKE, build_runtime_graph
    from mirage.layer3_deception.deception_fabric import DeceptionFabric

    fabric = DeceptionFabric(graph)
    deploy = next(
        action for action in fabric.action_catalog
        if action.action_type.value == "deploy_decoy_database"
        and action.target_node == DB_FAKE
    )
    active_graph = build_runtime_graph(graph, actions=[deploy])
    interventions = {(DB_FAKE, "end"): deploy.reward_delta}
    mitre_w_dec = run_mitre_simulation(
        active_graph,
        n_episodes=200,
        reward_interventions=interventions,
        seed=42,
    )
    print("\nMITREEvasionAttacker (with deception deployed):")
    print(f"  True Goal Hit Rate:      {mitre_w_dec['hit_true_goal_rate']:.1%}")
    print(f"  Decoy Interception Rate: {mitre_w_dec['decoy_interception_rate']:.1%}")

    agent = create_mitre_attacker(graph)
    print(f"\n{agent.technique_summary()}")
