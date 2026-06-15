"""
MIRAGE - Layer 1: HMM-based Telemetry Classifier
==================================================
Thay thế rule-based IF/ELSE bằng Hidden Markov Model (HMM) để phân loại
giai đoạn tấn công từ chuỗi sự kiện telemetry theo thời gian.

Kiến trúc HMM:
  - Hidden States:  8 giai đoạn MITRE ATT&CK (Unknown → Exfiltration)
  - Observations:   11 loại sự kiện telemetry (port_scan, login_attempt, ...)
  - Parameters:     A (transition matrix), B (emission matrix), π (initial state)

Thuật toán:
  1. Forward Algorithm  → P(observations | HMM) = belief state chuẩn xác hơn IF/ELSE
  2. Viterbi Algorithm  → Đường giai đoạn khả dĩ nhất (để debug/explain)
  3. Baum-Welch (stub)  → Có thể train trên log thật sau này

Cách dùng:
  from mirage.layer1_hmm import HMMTelemetryClassifier, TelemetryEvent
  clf = HMMTelemetryClassifier()
  for event in events:
      belief = clf.update(event)
  print(clf.get_stage_distribution())

So sánh với Rule-based (layer1_attack_modeling.py):
  Rule-based: nhanh hơn, giải thích tốt hơn, nhưng miss các sequence pattern
  HMM:        chính xác hơn trên chuỗi dài, có thể detect multi-stage sequences

Cả hai đều chạy song song trong MIRAGE; HMM làm "second opinion" cho rule-based.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# Reuse stage definitions from layer1
from mirage.layer1_attack_modeling import AttackStage, STAGE_NAMES, TelemetryEvent


# ---------------------------------------------------------------------------
# HMM parameters (hand-tuned based on MITRE ATT&CK kill chain)
# These can be replaced by learned parameters via Baum-Welch
# ---------------------------------------------------------------------------

# Observation types (event_type values)
OBSERVATION_TYPES = [
    "port_scan",           # O0
    "login_attempt",       # O1
    "login_failure",       # O2 (login_attempt with success=False)
    "smb_connect",         # O3
    "rdp_connect",         # O4
    "dns_query",           # O5
    "file_access",         # O6
    "data_transfer",       # O7
    "credential_use",      # O8
    "external_connect",    # O9
    "honey_credential_use",# O10
    "decoy_touch",         # O11
    "other",               # O12
]
OBS_INDEX = {o: i for i, o in enumerate(OBSERVATION_TYPES)}
N_OBS = len(OBSERVATION_TYPES)

# Stages
STAGES = [
    AttackStage.UNKNOWN,
    AttackStage.RECON,
    AttackStage.INITIAL_ACCESS,
    AttackStage.DISCOVERY,
    AttackStage.LATERAL_MOVEMENT,
    AttackStage.CREDENTIAL_ACCESS,
    AttackStage.COLLECTION,
    AttackStage.EXFILTRATION,
]
N_STATES = len(STAGES)
STAGE_IDX = {s: i for i, s in enumerate(STAGES)}


def _row_normalize(matrix: List[List[float]]) -> List[List[float]]:
    """Normalize each row of a matrix to sum to 1."""
    result = []
    for row in matrix:
        total = sum(row)
        if total <= 0:
            result.append([1.0 / len(row)] * len(row))
        else:
            result.append([v / total for v in row])
    return result


# ---- Initial state distribution π ----
# Attacker always starts at Unknown or Recon
_INITIAL_PROBS = [
    0.40,  # Unknown
    0.50,  # Recon
    0.08,  # Initial Access
    0.02,  # Discovery
    0.00,  # Lateral Movement
    0.00,  # Credential Access
    0.00,  # Collection
    0.00,  # Exfiltration
]

# ---- Transition matrix A[i][j] = P(stage_j | stage_i) ----
# Kill chain is mostly progressive (unknown→recon→access→...) but can stay or skip
_TRANSITION_RAW = [
    # From Unknown:
    [0.20, 0.50, 0.20, 0.08, 0.01, 0.01, 0.00, 0.00],
    # From Recon:
    [0.05, 0.35, 0.40, 0.15, 0.04, 0.01, 0.00, 0.00],
    # From Initial Access:
    [0.02, 0.05, 0.25, 0.40, 0.18, 0.07, 0.02, 0.01],
    # From Discovery:
    [0.01, 0.02, 0.05, 0.30, 0.40, 0.15, 0.05, 0.02],
    # From Lateral Movement:
    [0.00, 0.01, 0.02, 0.10, 0.35, 0.35, 0.12, 0.05],
    # From Credential Access:
    [0.00, 0.00, 0.02, 0.05, 0.15, 0.35, 0.30, 0.13],
    # From Collection:
    [0.00, 0.00, 0.00, 0.02, 0.05, 0.10, 0.40, 0.43],
    # From Exfiltration:
    [0.00, 0.00, 0.00, 0.00, 0.02, 0.03, 0.10, 0.85],
]

# ---- Emission matrix B[state][obs] = P(obs | stage) ----
_EMISSION_RAW = [
    # Unknown: any event possible, roughly uniform
    [0.15, 0.10, 0.08, 0.08, 0.05, 0.10, 0.08, 0.05, 0.08, 0.05, 0.05, 0.05, 0.08],
    # Recon: port_scan, dns_query dominant
    [0.30, 0.10, 0.08, 0.05, 0.03, 0.25, 0.05, 0.02, 0.03, 0.03, 0.02, 0.02, 0.02],
    # Initial Access: login_attempt/failure, port_scan
    [0.15, 0.25, 0.25, 0.05, 0.08, 0.05, 0.03, 0.02, 0.03, 0.03, 0.04, 0.01, 0.01],
    # Discovery: smb, rdp, dns, file_access
    [0.10, 0.05, 0.05, 0.20, 0.12, 0.15, 0.15, 0.02, 0.05, 0.03, 0.02, 0.04, 0.02],
    # Lateral Movement: smb, rdp, credential_use strong
    [0.05, 0.05, 0.05, 0.22, 0.20, 0.05, 0.10, 0.05, 0.15, 0.03, 0.02, 0.02, 0.01],
    # Credential Access: credential_use, login, honey_credential dominant
    [0.05, 0.12, 0.10, 0.08, 0.05, 0.03, 0.05, 0.03, 0.30, 0.03, 0.12, 0.02, 0.02],
    # Collection: file_access, data_transfer dominant
    [0.03, 0.03, 0.02, 0.05, 0.03, 0.03, 0.35, 0.30, 0.08, 0.03, 0.02, 0.01, 0.02],
    # Exfiltration: external_connect, data_transfer dominant
    [0.02, 0.02, 0.02, 0.02, 0.02, 0.02, 0.10, 0.30, 0.05, 0.35, 0.03, 0.01, 0.02],
]

# Normalize
_INITIAL_PROBS_NORM = [v / sum(_INITIAL_PROBS) for v in _INITIAL_PROBS]
_TRANSITION = _row_normalize(_TRANSITION_RAW)
_EMISSION = _row_normalize(_EMISSION_RAW)


def _map_event_to_obs_idx(event: TelemetryEvent) -> int:
    """Map a TelemetryEvent to an observation index for the HMM."""
    etype = event.event_type.lower()
    if etype == "login_attempt" and not event.success:
        return OBS_INDEX["login_failure"]
    return OBS_INDEX.get(etype, OBS_INDEX["other"])


# ---------------------------------------------------------------------------
# HMM Classifier
# ---------------------------------------------------------------------------

@dataclass
class HMMBeliefState:
    """Current belief state output from the HMM Forward algorithm."""
    host: str
    stage_distribution: Dict[AttackStage, float]
    dominant_stage: AttackStage
    confidence: float
    n_events_processed: int
    log_likelihood: float  # log P(observations so far)

    def __str__(self) -> str:
        top3 = sorted(self.stage_distribution.items(), key=lambda x: -x[1])[:3]
        lines = [
            f"Host: {self.host}",
            f"  Dominant Stage: [{STAGE_NAMES[self.dominant_stage]}] ({self.confidence:.1%})",
            f"  Events processed: {self.n_events_processed}",
            f"  Log-Likelihood: {self.log_likelihood:.4f}",
            "  Stage Distribution (Top 3):",
        ]
        for stage, prob in top3:
            if prob > 0.01:
                lines.append(f"    {STAGE_NAMES[stage]:22s}: {prob:.2%}")
        return "\n".join(lines)


class HMMTelemetryClassifier:
    """
    HMM-based attack stage classifier.

    Uses the Forward Algorithm to maintain an exact belief state over
    attack stages given the observed telemetry sequence.

    Each host maintains an independent alpha vector (forward variable).
    When a new event arrives, the HMM updates the belief via:

        alpha_t(j) = B[j][obs_t] * Σ_i alpha_{t-1}(i) * A[i][j]

    The normalized alpha vector IS the stage probability distribution.
    """

    def __init__(
        self,
        transition: Optional[List[List[float]]] = None,
        emission: Optional[List[List[float]]] = None,
        initial: Optional[List[float]] = None,
        max_tracked_hosts: int = 10000,
    ):
        """
        Args:
            transition: N_STATES×N_STATES transition matrix (or None to use defaults)
            emission:   N_STATES×N_OBS emission matrix (or None to use defaults)
            initial:    N_STATES initial state distribution (or None to use defaults)
        """
        self._A = transition if transition is not None else _TRANSITION
        self._B = emission if emission is not None else _EMISSION
        self._pi = initial if initial is not None else _INITIAL_PROBS_NORM
        if max_tracked_hosts < 1:
            raise ValueError("max_tracked_hosts must be at least 1")
        self.max_tracked_hosts = int(max_tracked_hosts)
        self._validate_parameters()

        # Per-host forward variables: alpha[host] = List[float] of length N_STATES
        self._alpha: Dict[str, List[float]] = {}
        self._event_counts: Dict[str, int] = {}
        self._log_likelihoods: Dict[str, float] = {}
        self._last_belief: Dict[str, HMMBeliefState] = {}
        self._last_seen: Dict[str, int] = {}
        self._sequence = 0

    def _validate_parameters(self) -> None:
        if len(self._A) != N_STATES or any(
            len(row) != N_STATES for row in self._A
        ):
            raise ValueError(
                f"transition must have shape {N_STATES}x{N_STATES}"
            )
        if len(self._B) != N_STATES or any(
            len(row) != N_OBS for row in self._B
        ):
            raise ValueError(
                f"emission must have shape {N_STATES}x{N_OBS}"
            )
        if len(self._pi) != N_STATES:
            raise ValueError(f"initial must contain {N_STATES} probabilities")
        for name, rows in (
            ("transition", self._A),
            ("emission", self._B),
            ("initial", [self._pi]),
        ):
            for row in rows:
                if any(
                    not math.isfinite(float(value)) or value < 0
                    for value in row
                ):
                    raise ValueError(
                        f"{name} probabilities must be finite and non-negative"
                    )
                if abs(sum(row) - 1.0) > 1e-6:
                    raise ValueError(
                        f"Each {name} probability row must sum to 1"
                    )

    def _init_host(self, host: str) -> None:
        """Initialize forward variable for a new host."""
        self._alpha[host] = list(self._pi)
        self._event_counts[host] = 0
        self._log_likelihoods[host] = 0.0

    def update(self, event: TelemetryEvent) -> HMMBeliefState:
        """
        Process a single telemetry event and update the belief state.

        Returns the updated HMMBeliefState for the event's source host.
        """
        host = event.source_host
        if host not in self._alpha:
            if len(self._alpha) >= self.max_tracked_hosts:
                oldest = min(self._last_seen, key=self._last_seen.get)
                self.reset_host(oldest)
            self._init_host(host)
        self._sequence += 1
        self._last_seen[host] = self._sequence

        obs_idx = _map_event_to_obs_idx(event)
        alpha = self._alpha[host]

        # Forward update: alpha_t(j) = B[j][o_t] * sum_i(alpha_{t-1}(i) * A[i][j])
        new_alpha = [0.0] * N_STATES
        for j in range(N_STATES):
            transition_sum = sum(alpha[i] * self._A[i][j] for i in range(N_STATES))
            new_alpha[j] = self._B[j][obs_idx] * transition_sum

        # Scaling to prevent underflow
        scale = sum(new_alpha)
        if scale > 1e-300:
            new_alpha = [v / scale for v in new_alpha]
            self._log_likelihoods[host] += math.log(scale)
        else:
            # Numerical underflow — reinitialize with observation
            new_alpha = [self._B[j][obs_idx] for j in range(N_STATES)]
            sc2 = sum(new_alpha)
            new_alpha = [v / sc2 if sc2 > 0 else 1.0 / N_STATES for v in new_alpha]

        self._alpha[host] = new_alpha
        self._event_counts[host] += 1

        # Convert to stage distribution dict
        stage_dist = {STAGES[i]: new_alpha[i] for i in range(N_STATES)}
        dominant = max(stage_dist, key=stage_dist.get)

        belief = HMMBeliefState(
            host=host,
            stage_distribution=stage_dist,
            dominant_stage=dominant,
            confidence=stage_dist[dominant],
            n_events_processed=self._event_counts[host],
            log_likelihood=self._log_likelihoods[host],
        )
        self._last_belief[host] = belief
        return belief

    def get_belief(self, host: str) -> Optional[HMMBeliefState]:
        """Get the current belief state for a host."""
        return self._last_belief.get(host)

    def get_all_beliefs(self) -> Dict[str, HMMBeliefState]:
        """Get beliefs for all tracked hosts."""
        return dict(self._last_belief)

    def get_stage_distribution(self, host: str) -> Dict[AttackStage, float]:
        """Get the current stage probability distribution for a host."""
        belief = self._last_belief.get(host)
        if belief is None:
            return {s: 1.0 / N_STATES for s in STAGES}
        return belief.stage_distribution

    def get_graph_belief_update(self, host: str, graph) -> Dict[int, float]:
        """
        Convert HMM stage distribution to a graph node belief update.

        Maps attack stages to likely node regions in the attack graph:
          Recon          → Entry/DMZ nodes
          Initial Access → DMZ nodes
          Discovery      → Internal/Services nodes
          Lateral Move   → Internal/Credential nodes
          Credential     → Credential nodes
          Collection     → Data/Critical nodes
          Exfiltration   → External/Sink nodes

        Returns:
            Dict mapping node_id → updated belief weight (unnormalized)
        """
        stage_dist = self.get_stage_distribution(host)

        STAGE_LAYER_WEIGHTS = {
            AttackStage.UNKNOWN:           {"external": 0.4, "dmz": 0.3, "internal": 0.2, "services": 0.05, "credentials": 0.03, "critical": 0.01, "data": 0.01},
            AttackStage.RECON:             {"external": 0.5, "dmz": 0.4, "internal": 0.05, "services": 0.03, "credentials": 0.01, "critical": 0.005, "data": 0.005},
            AttackStage.INITIAL_ACCESS:    {"external": 0.1, "dmz": 0.6, "internal": 0.2, "services": 0.05, "credentials": 0.02, "critical": 0.01, "data": 0.02},
            AttackStage.DISCOVERY:         {"external": 0.02, "dmz": 0.1, "internal": 0.5, "services": 0.3, "credentials": 0.05, "critical": 0.01, "data": 0.02},
            AttackStage.LATERAL_MOVEMENT:  {"external": 0.01, "dmz": 0.05, "internal": 0.35, "services": 0.3, "credentials": 0.2, "critical": 0.06, "data": 0.03},
            AttackStage.CREDENTIAL_ACCESS: {"external": 0.01, "dmz": 0.02, "internal": 0.15, "services": 0.15, "credentials": 0.55, "critical": 0.08, "data": 0.04},
            AttackStage.COLLECTION:        {"external": 0.01, "dmz": 0.01, "internal": 0.05, "services": 0.05, "credentials": 0.1, "critical": 0.3, "data": 0.48},
            AttackStage.EXFILTRATION:      {"external": 0.4, "dmz": 0.05, "internal": 0.05, "services": 0.05, "credentials": 0.05, "critical": 0.1, "data": 0.3},
        }

        # Accumulate per-node weights
        node_weights: Dict[int, float] = {}
        for state in graph.states:
            if state == graph.sink_state:
                continue
            meta = graph.node_metadata.get(state, {})
            layer = meta.get("layer", "internal")
            weight = 0.0
            for stage, stage_prob in stage_dist.items():
                layer_w = STAGE_LAYER_WEIGHTS.get(stage, {}).get(layer, 0.01)
                weight += stage_prob * layer_w
            node_weights[state] = max(0.0, weight)

        # Normalize
        total = sum(node_weights.values())
        if total > 0:
            node_weights = {s: v / total for s, v in node_weights.items()}

        return node_weights

    def reset_host(self, host: str) -> None:
        """Reset all state for a host."""
        self._alpha.pop(host, None)
        self._event_counts.pop(host, None)
        self._log_likelihoods.pop(host, None)
        self._last_belief.pop(host, None)
        self._last_seen.pop(host, None)

    def viterbi(self, events: List[TelemetryEvent], host: str = "viterbi_host") -> List[AttackStage]:
        """
        Viterbi decoding: find the most likely sequence of attack stages.

        Useful for explaining the detected attack path to SOC analysts.

        Args:
            events: Sequence of telemetry events for one host.

        Returns:
            List of AttackStage — one per event, most likely sequence.
        """
        if not events:
            return []

        T = len(events)
        # delta[t][i] = max prob of ending in state i at time t
        delta = [[0.0] * N_STATES for _ in range(T)]
        psi = [[0] * N_STATES for _ in range(T)]  # backpointer

        # Initialize
        obs_0 = _map_event_to_obs_idx(events[0])
        for i in range(N_STATES):
            delta[0][i] = self._pi[i] * self._B[i][obs_0]
        # Scale
        sc = sum(delta[0])
        if sc > 0:
            delta[0] = [v / sc for v in delta[0]]

        # Recursion
        for t in range(1, T):
            obs_t = _map_event_to_obs_idx(events[t])
            sc = 0.0
            for j in range(N_STATES):
                best_val = -1.0
                best_i = 0
                for i in range(N_STATES):
                    val = delta[t - 1][i] * self._A[i][j]
                    if val > best_val:
                        best_val = val
                        best_i = i
                delta[t][j] = self._B[j][obs_t] * best_val
                psi[t][j] = best_i
                sc += delta[t][j]
            if sc > 0:
                delta[t] = [v / sc for v in delta[t]]

        # Backtrack
        path = [0] * T
        path[T - 1] = max(range(N_STATES), key=lambda i: delta[T - 1][i])
        for t in range(T - 2, -1, -1):
            path[t] = psi[t + 1][path[t + 1]]

        return [STAGES[i] for i in path]

    def summary(self) -> str:
        lines = ["=" * 60, "MIRAGE Layer 1 HMM — Belief State Summary", "=" * 60]
        for belief in self._last_belief.values():
            lines.append(str(belief))
            lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Ensemble: Rule-based + HMM combined
# ---------------------------------------------------------------------------

class EnsembleTelemetryClassifier:
    """
    Kết hợp Rule-based Classifier (Layer 1 gốc) với HMM Classifier.

    Output = weighted average của 2 phương pháp:
      α * HMM_distribution + (1 - α) * rule_distribution

    Lợi thế:
      - Rule-based: nhạy với các event đơn lẻ bất thường (honey credential)
      - HMM: chính xác hơn trên chuỗi dài, phát hiện multi-stage sequence
    """

    def __init__(
        self,
        hmm_weight: float = 0.6,
        event_history_limit: int = 1000,
        max_tracked_hosts: int = 10000,
    ):
        from mirage.layer1_attack_modeling import AttackStageClassifier
        self.rule_clf = AttackStageClassifier(
            event_history_limit=event_history_limit,
            max_tracked_hosts=max_tracked_hosts,
        )
        self.hmm_clf = HMMTelemetryClassifier(
            max_tracked_hosts=max_tracked_hosts,
        )
        self.hmm_weight = max(0.0, min(1.0, hmm_weight))
        self._last_ensemble: Dict[str, Dict[AttackStage, float]] = {}

    def process_event(self, event: TelemetryEvent) -> Dict[AttackStage, float]:
        """
        Process one event and return ensemble stage distribution.
        """
        # Rule-based
        rule_est = self.rule_clf.process_event(event)
        rule_dist = rule_est.stage_distribution

        # HMM
        hmm_belief = self.hmm_clf.update(event)
        hmm_dist = hmm_belief.stage_distribution

        # Weighted combination
        alpha = self.hmm_weight
        combined: Dict[AttackStage, float] = {}
        all_stages = set(rule_dist) | set(hmm_dist)
        for s in all_stages:
            combined[s] = alpha * hmm_dist.get(s, 0.0) + (1 - alpha) * rule_dist.get(s, 0.0)

        # Normalize
        total = sum(combined.values())
        if total > 0:
            combined = {s: v / total for s, v in combined.items()}

        self._last_ensemble[event.source_host] = combined
        return combined

    def get_dominant_stage(self, host: str) -> Tuple[AttackStage, float]:
        dist = self._last_ensemble.get(host, {})
        if not dist:
            return AttackStage.UNKNOWN, 0.0
        dominant = max(dist, key=dist.get)
        return dominant, dist[dominant]

    def get_graph_belief_update(self, host: str, graph) -> Dict[int, float]:
        """Delegate to HMM for graph belief update (more spatially-aware)."""
        return self.hmm_clf.get_graph_belief_update(host, graph)


# ---------------------------------------------------------------------------
# Quick demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    from mirage.layer1_attack_modeling import simulate_attack_telemetry

    print("=" * 60)
    print("HMM Telemetry Classifier — Demo")
    print("=" * 60)

    for scenario in ["lateral_movement", "exfiltration", "honey_trap"]:
        print(f"\n--- Scenario: {scenario} ---")
        events = simulate_attack_telemetry(scenario)

        hmm = HMMTelemetryClassifier()
        belief = None
        for ev in events:
            belief = hmm.update(ev)
        if belief:
            print(belief)

        # Viterbi path
        path = hmm.viterbi(events, host="viterbi")
        stage_names = [STAGE_NAMES[s] for s in path]
        print(f"  Viterbi path: {' -> '.join(stage_names)}")

    print("\n--- Ensemble (HMM + Rule-based) ---")
    ens = EnsembleTelemetryClassifier(hmm_weight=0.6)
    events = simulate_attack_telemetry("lateral_movement")
    for ev in events:
        dist = ens.process_event(ev)
    stage, conf = ens.get_dominant_stage("attacker_pc")
    print(f"  Ensemble dominant stage: [{STAGE_NAMES[stage]}] ({conf:.1%})")
