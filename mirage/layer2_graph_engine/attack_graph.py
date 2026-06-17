"""
MIRAGE - Layer 2: Enterprise Attack Graph / POMDP Core
======================================================
Đồ thị tấn công doanh nghiệp 15 node mô phỏng đầy đủ các giai đoạn:
Recon → Initial Access → Discovery → Lateral Movement → Collection → Exfiltration

Cấu trúc mạng:
  [INTERNET]
      ↓
  [DMZ] Web Server, Mail Server
      ↓
  [Workstations] WS1, WS2, WS3
      ↓
  [Internal Services] SMB Share, DNS Server
      ↓
  [Credentials] Admin Account, Service Account
      ↓
  [Domain Controller]
      ↓
  [Data Layer] DB_REAL (True Goal) | DB_FAKE_1, ROUTER_FAKE (Decoy Slots)
      ↓
  [SINK]

Chú thích:
  - Nodes 0-9: Tài sản thật (real assets)
  - Nodes 10: DB_REAL = True Goal
  - Nodes 11-12: Decoy slots (chờ Lớp 3 điền vào)
  - Node 13: Domain Controller (high-value target)
  - Node 14: Sink/Terminal
"""

from __future__ import annotations

import random
import copy
import math

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from mirage.config import load_config, resolve_project_path

# ---------------------------------------------------------------------------
# Node definitions — Enterprise Network Topology
# ---------------------------------------------------------------------------

NODE_DEFINITIONS = {
    # ---- ENTRY POINT ----
    0:  {"label": "Internet/Entry",       "layer": "external",   "asset_type": "entry",       "is_real": True,  "value": 0.0},
    # ---- DMZ ----
    1:  {"label": "WebServer_DMZ",         "layer": "dmz",        "asset_type": "web_server",  "is_real": True,  "value": 0.2},
    2:  {"label": "MailServer_DMZ",        "layer": "dmz",        "asset_type": "mail_server", "is_real": True,  "value": 0.2},
    # ---- WORKSTATIONS ----
    3:  {"label": "Workstation_Eng",       "layer": "internal",   "asset_type": "workstation", "is_real": True,  "value": 0.3},
    4:  {"label": "Workstation_Finance",   "layer": "internal",   "asset_type": "workstation", "is_real": True,  "value": 0.4},
    5:  {"label": "Workstation_IT",        "layer": "internal",   "asset_type": "workstation", "is_real": True,  "value": 0.3},
    # ---- INTERNAL SERVICES ----
    6:  {"label": "SMB_FileShare",         "layer": "services",   "asset_type": "file_share",  "is_real": True,  "value": 0.4},
    7:  {"label": "DNS_Internal",          "layer": "services",   "asset_type": "dns_server",  "is_real": True,  "value": 0.3},
    # ---- CREDENTIALS ----
    8:  {"label": "Admin_Credential",      "layer": "credentials","asset_type": "credential",  "is_real": True,  "value": 0.7},
    9:  {"label": "ServiceAcct_Credential","layer": "credentials","asset_type": "credential",  "is_real": True,  "value": 0.5},
    # ---- TRUE GOAL ----
    10: {"label": "DB_REAL_Finance",       "layer": "data",       "asset_type": "database",    "is_real": True,  "value": 1.0},  # TRUE GOAL
    # ---- DECOY SLOTS ----
    11: {"label": "DB_FAKE_Backup",        "layer": "data",       "asset_type": "decoy_db",    "is_real": False, "value": 0.0},  # Decoy DB
    12: {"label": "Router_FAKE_Gateway",   "layer": "services",   "asset_type": "decoy_router","is_real": False, "value": 0.0},  # Decoy Router
    # ---- DOMAIN CONTROLLER ----
    13: {"label": "DomainController",      "layer": "critical",   "asset_type": "dc",          "is_real": True,  "value": 0.9},
    # ---- SINK ----
    14: {"label": "Sink",                  "layer": "sink",       "asset_type": "sink",        "is_real": True,  "value": 0.0},
}

for _node_id, _metadata in NODE_DEFINITIONS.items():
    _internal = _metadata["label"]
    _metadata["internal_label"] = _internal
    _metadata["attacker_visible_label"] = {
        11: "FinanceDB_Replica",
        12: "CoreService_Gateway",
    }.get(_node_id, _internal)
    _metadata["service_banner"] = _metadata["attacker_visible_label"]
    _metadata["realism_score"] = 0.8 if _node_id in {11, 12} else 1.0

# Node IDs
INTERNET   = 0
WEB_DMZ    = 1
MAIL_DMZ   = 2
WS_ENG     = 3
WS_FIN     = 4
WS_IT      = 5
SMB_SHARE  = 6
DNS_INT    = 7
ADMIN_CRED = 8
SVC_CRED   = 9
DB_REAL    = 10   # TRUE GOAL
DB_FAKE    = 11   # Decoy Slot 1
RTR_FAKE   = 12   # Decoy Slot 2
DC_NODE    = 13   # Domain Controller
SINK       = 14

TRUE_GOAL   = DB_REAL
DECOY_SITES = [DB_FAKE, RTR_FAKE]

# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------

ACTIONS = [
    "exploit_web",       # Tấn công web server
    "phish_email",       # Phishing qua email
    "smb_move",          # Di chuyển qua SMB
    "rdp_move",          # Di chuyển qua RDP
    "cred_dump",         # Đánh cắp credential
    "dns_recon",         # Thăm dò qua DNS
    "db_access",         # Truy cập database
    "dc_attack",         # Tấn công Domain Controller
    "end",               # Terminal action (arrive at destination)
    "noop",              # No operation (sink)
]

# ---------------------------------------------------------------------------
# Enterprise Attack Graph Construction
# ---------------------------------------------------------------------------

@dataclass
class MIRAGEAttackGraph:
    """
    Đồ thị tấn công dùng chung cho topology dựng sẵn và topology động.
    
    Tương thích với ``mirage.utils.mdp_model.AttackGraphMDP``.
    Bổ sung thêm: node metadata, belief state, edge cost.
    """
    states: List[int]
    actions: List[str]
    available_actions: Dict[int, List[str]]
    transitions: Dict[int, Dict[str, Dict[int, float]]]
    start_distribution: Dict[int, float]
    discount: float
    budget: float
    true_goals: List[int]
    decoy_sites: List[int]
    sink_state: int
    state_labels: Dict[int, str]
    attacker_reward: Dict[Tuple[int, str], float]
    defender_reward: Dict[Tuple[int, str], float]
    node_metadata: Dict[int, Dict] = field(default_factory=dict)
    edge_costs: Dict[Tuple[int, int], float] = field(default_factory=dict)  # (src, dst) → cost
    belief_state: Dict[int, float] = field(default_factory=dict)  # P(attacker at node s)
    active_decoy_sites: List[int] = field(default_factory=list)
    decoy_transition_templates: Dict[Tuple[int, str], Dict[int, float]] = field(default_factory=dict)

    @classmethod
    def from_twin_snapshot(cls, snapshot) -> "MIRAGEAttackGraph":
        """Build a MIRAGE attack graph from a Digital Twin snapshot."""
        from mirage.layer6_twin.graph_adapter import (
            attack_graph_from_twin_snapshot,
        )

        return attack_graph_from_twin_snapshot(snapshot)

    @property
    def name(self) -> str:
        return "mirage_enterprise_graph_v2"

    def label(self, state: int) -> str:
        return self.state_labels.get(state, str(state))

    def get_node_info(self, state: int) -> Dict:
        return self.node_metadata.get(state, {})

    def attacker_label(self, state: int) -> str:
        meta = self.node_metadata.get(state, {})
        return meta.get("attacker_visible_label", meta.get("label", self.label(state)))

    def is_decoy(self, state: int) -> bool:
        return state in self.active_decoy_sites

    def is_true_goal(self, state: int) -> bool:
        return state in self.true_goals

    def get_high_risk_paths(self) -> List[List[int]]:
        """Return up to three simple entry-to-goal paths for explanations."""
        goals = set(self.true_goals)
        starts = [
            state
            for state, probability in sorted(
                self.start_distribution.items(),
                key=lambda item: (-item[1], item[0]),
            )
            if probability > 0
        ]
        if not starts or not goals:
            return []

        adjacency: Dict[int, List[Tuple[int, float]]] = {}
        for source in self.states:
            destinations: Dict[int, float] = {}
            for action, distribution in self.transitions.get(source, {}).items():
                if action in {"end", "noop"}:
                    continue
                for destination, probability in distribution.items():
                    if destination == self.sink_state or probability <= 0:
                        continue
                    destinations[destination] = max(
                        destinations.get(destination, 0.0),
                        float(probability),
                    )
            adjacency[source] = sorted(
                destinations.items(),
                key=lambda item: (-item[1], item[0]),
            )

        max_depth = min(max(2, len(self.states)), 20)
        queue: List[List[int]] = [[start] for start in starts]
        paths: List[List[int]] = []
        while queue and len(paths) < 3:
            path = queue.pop(0)
            current = path[-1]
            if current in goals:
                paths.append(path)
                continue
            if len(path) >= max_depth:
                continue
            for destination, _ in adjacency.get(current, []):
                if destination not in path:
                    queue.append(path + [destination])
        return paths

    def update_belief(self, observation: Dict[int, float]) -> None:
        """
        Cập nhật belief state (Bayesian update đơn giản).
        observation: dict {node: likelihood} dựa trên telemetry.
        """
        if not self.belief_state:
            # Khởi tạo uniform
            n = len(self.states) - 1  # Loại sink
            if n <= 0:
                raise ValueError("Attack graph must contain a non-sink state")
            self.belief_state = {s: 1.0/n for s in self.states if s != self.sink_state}

        # Bayes update: b'(s) ∝ P(obs|s) * b(s)
        new_belief = {}
        for s in self.belief_state:
            likelihood = float(observation.get(s, 0.1))
            if not math.isfinite(likelihood) or likelihood < 0:
                raise ValueError(
                    "Belief likelihoods must be finite and non-negative"
                )
            new_belief[s] = self.belief_state[s] * likelihood

        total = sum(new_belief.values())
        if total > 0:
            self.belief_state = {s: v / total for s, v in new_belief.items()}

    def increase_edge_cost(self, src: int, dst: int, cost_delta: float) -> None:
        """Tăng chi phí di chuyển trên một edge cụ thể (Deception action)."""
        key = (src, dst)
        self.edge_costs[key] = self.edge_costs.get(key, 0.0) + cost_delta

        # Cập nhật transition probabilities: tăng cost → giảm xác suất đi theo đường đó
        if src in self.transitions:
            for action, trans in self.transitions[src].items():
                if dst in trans and len(trans) > 1:
                    # Giảm xác suất đến dst, tăng các nút khác
                    penalty = min(cost_delta * 0.05, trans[dst] * 0.3)  # Tối đa giảm 30%
                    trans[dst] = max(0.1, trans[dst] - penalty)
                    # Normalize lại
                    total = sum(trans.values())
                    self.transitions[src][action] = {k: v/total for k, v in trans.items()}

    def to_mdp_dict(self) -> Dict:
        """
        Chuyển sang format tương thích với AttackGraphMDP nội bộ.
        """
        return {
            "name": self.name,
            "states": self.states,
            "actions": self.actions,
            "available_actions": {str(k): v for k, v in self.available_actions.items()},
            "transitions": {
                str(s): {a: {str(ns): p for ns, p in nxt.items()} for a, nxt in acts.items()}
                for s, acts in self.transitions.items()
            },
            "start_distribution": {str(k): float(v) for k, v in self.start_distribution.items()},
            "discount": self.discount,
            "budget": self.budget,
            "true_goals": self.true_goals,
            "decoy_sites": self.decoy_sites,
            "sink_state": self.sink_state,
            "state_labels": {str(k): v for k, v in self.state_labels.items()},
            "attacker_reward": {f"{s}|{a}": float(v) for (s, a), v in self.attacker_reward.items()},
            "defender_reward": {f"{s}|{a}": float(v) for (s, a), v in self.defender_reward.items()},
            "interventions": [
                {"name": f"decoy_{d}", "state": d, "action": "end"}
                for d in self.decoy_sites
            ],
        }


def _normalize_distribution(
    distribution: Dict[int, float],
    sink_state: int,
) -> Dict[int, float]:
    positive = {}
    for state, raw_probability in distribution.items():
        probability = float(raw_probability)
        if not math.isfinite(probability) or probability < 0:
            raise ValueError(
                "Transition probabilities must be finite and non-negative"
            )
        if probability > 0:
            positive[state] = probability
    total = sum(positive.values())
    if total <= 0:
        return {sink_state: 1.0}
    return {state: prob / total for state, prob in positive.items()}


def initialize_decoy_slots(graph: MIRAGEAttackGraph) -> MIRAGEAttackGraph:
    """
    Store incoming decoy routes as templates and return a clean live graph.

    ``decoy_sites`` are potential slots. A slot is not reachable and is not a
    decoy outcome until a matching deploy action activates it.
    """
    potential = set(graph.decoy_sites)
    graph.active_decoy_sites = []
    graph.decoy_transition_templates = {}

    for src in graph.states:
        for action in graph.available_actions.get(src, []):
            distribution = graph.transitions.get(src, {}).get(action, {})
            if not distribution or not any(dst in potential for dst in distribution):
                continue
            graph.decoy_transition_templates[(src, action)] = copy.deepcopy(distribution)
            clean = {
                dst: prob
                for dst, prob in distribution.items()
                if dst not in potential
            }
            graph.transitions[src][action] = _normalize_distribution(
                clean,
                graph.sink_state,
            )
    return graph


def build_runtime_graph(
    graph: MIRAGEAttackGraph,
    actions: Optional[List[object]] = None,
    edge_cost_edits: Optional[List[Tuple[int, int, float]]] = None,
) -> MIRAGEAttackGraph:
    """
    Build the graph shared by simulation and exact MDP evaluation.

    Deploy actions activate decoy slots. Edge-cost actions alter transition
    probabilities. Reward interventions are deliberately excluded because
    they only change the attacker's perceived reward.
    """
    runtime = copy.deepcopy(graph)
    actions = list(actions or [])
    deploy_types = {"deploy_decoy_database", "deploy_decoy_router"}

    active = set()
    inferred_edge_edits: List[Tuple[int, int, float]] = []
    action_by_node: Dict[int, object] = {}
    for action in actions:
        action_type = getattr(getattr(action, "action_type", None), "value", "")
        if action_type in deploy_types:
            node = int(action.target_node)
            if node not in runtime.decoy_sites:
                raise ValueError(
                    f"Deploy action target {node} is not a configured decoy slot"
                )
            active.add(node)
            action_by_node[node] = action
        target_edge = getattr(action, "target_edge", None)
        edge_delta = float(getattr(action, "edge_cost_delta", 0.0) or 0.0)
        if action_type == "increase_edge_cost" and target_edge and edge_delta > 0:
            inferred_edge_edits.append((target_edge[0], target_edge[1], edge_delta))

    runtime.active_decoy_sites = sorted(active)
    inactive_slots = set(runtime.decoy_sites) - active

    for (src, action), template in runtime.decoy_transition_templates.items():
        if src not in runtime.transitions or action not in runtime.transitions[src]:
            continue
        enabled = {
            dst: prob
            for dst, prob in template.items()
            if dst not in inactive_slots
        }
        runtime.transitions[src][action] = _normalize_distribution(
            enabled,
            runtime.sink_state,
        )

    for node in active:
        metadata = runtime.node_metadata.setdefault(node, {})
        deploy_action = action_by_node.get(node)
        realism = float(getattr(deploy_action, "realism_score", 0.8) or 0.8)
        metadata["realism_score"] = realism
        metadata["behavioral_signal"] = max(0.0, 1.0 - realism)
        metadata.setdefault(
            "service_banner",
            metadata.get("attacker_visible_label", runtime.label(node)),
        )
        runtime.defender_reward[(node, "end")] = max(
            1.0,
            runtime.defender_reward.get((node, "end"), 0.0),
        )

    all_edge_edits = list(edge_cost_edits or inferred_edge_edits)
    for src, dst, delta in all_edge_edits:
        if src not in runtime.transitions:
            continue
        runtime.edge_costs[(src, dst)] = runtime.edge_costs.get((src, dst), 0.0) + delta
        for action in runtime.available_actions.get(src, []):
            distribution = runtime.transitions[src].get(action, {})
            if dst not in distribution or distribution[dst] <= 0:
                continue
            old_probability = distribution[dst]
            reduction = min(old_probability * 0.65, max(0.0, delta) * 0.12)
            if reduction <= 0:
                continue
            updated = dict(distribution)
            updated[dst] = max(0.0, old_probability - reduction)
            updated[runtime.sink_state] = (
                updated.get(runtime.sink_state, 0.0) + reduction
            )
            runtime.transitions[src][action] = _normalize_distribution(
                updated,
                runtime.sink_state,
            )

    return runtime


def apply_runtime_graph_in_place(
    graph: MIRAGEAttackGraph,
    actions: Optional[List[object]] = None,
    edge_cost_edits: Optional[List[Tuple[int, int, float]]] = None,
) -> MIRAGEAttackGraph:
    runtime = build_runtime_graph(graph, actions=actions, edge_cost_edits=edge_cost_edits)
    graph.transitions = runtime.transitions
    graph.active_decoy_sites = runtime.active_decoy_sites
    graph.edge_costs = runtime.edge_costs
    graph.node_metadata = runtime.node_metadata
    graph.defender_reward = runtime.defender_reward
    return graph


def build_enterprise_attack_graph(
    budget: Optional[float] = None,
    discount: Optional[float] = None,
    decoy_realism: Optional[float] = None,
) -> MIRAGEAttackGraph:
    """
    Xây dựng đồ thị tấn công doanh nghiệp 15 node.
    
    Args:
        budget: Ngân sách can thiệp (reward manipulation)
        discount: Hệ số chiết khấu
        decoy_realism: Mức độ "hấp dẫn" của decoy nodes (0-1)
    
    Returns:
        MIRAGEAttackGraph hoàn chỉnh
    """
    config = load_config()
    if budget is None:
        budget = config.get("general", {}).get("budget_limit", 4.0)
    if discount is None:
        discount = config.get("general", {}).get("discount_factor", 0.95)
    if decoy_realism is None:
        decoy_realism = config.get("layer2", {}).get("decoy_realism", 0.8)
    budget = float(budget)
    discount = float(discount)
    decoy_realism = float(decoy_realism)
    if not math.isfinite(budget) or budget < 0:
        raise ValueError("budget must be finite and non-negative")
    if not math.isfinite(discount) or not 0 <= discount < 1:
        raise ValueError("discount must satisfy 0 <= discount < 1")
    if not math.isfinite(decoy_realism) or not 0 <= decoy_realism <= 1:
        raise ValueError("decoy_realism must satisfy 0 <= value <= 1")

    states = list(range(15))

    # ---- AVAILABLE ACTIONS PER STATE ----
    available_actions: Dict[int, List[str]] = {
        # Entry: có thể tấn công web hoặc phishing email
        INTERNET:   ["exploit_web", "phish_email", "dns_recon"],
        # DMZ: từ web có thể SMB move hoặc recon
        WEB_DMZ:    ["smb_move", "rdp_move", "dns_recon", "end"],
        MAIL_DMZ:   ["smb_move", "rdp_move", "dns_recon", "end"],
        # Workstations: cred dump hoặc lateral move
        WS_ENG:     ["cred_dump", "smb_move", "rdp_move", "end"],
        WS_FIN:     ["cred_dump", "smb_move", "db_access", "end"],
        WS_IT:      ["cred_dump", "smb_move", "dc_attack", "end"],
        # Internal services
        SMB_SHARE:  ["cred_dump", "smb_move", "end"],
        DNS_INT:    ["dns_recon", "rdp_move", "end"],
        # Credentials: pivot sang DB hoặc DC
        ADMIN_CRED: ["dc_attack", "db_access", "end"],
        SVC_CRED:   ["db_access", "smb_move", "end"],
        # Terminal nodes
        DB_REAL:    ["end"],
        DB_FAKE:    ["end"],
        RTR_FAKE:   ["end"],
        DC_NODE:    ["db_access", "end"],
        SINK:       ["noop"],
    }

    # ---- TRANSITIONS ----
    # Mỗi action có phân phối xác suất chuyển sang nodes tiếp theo
    transitions: Dict[int, Dict[str, Dict[int, float]]] = {}

    # INTERNET (Node 0) → DMZ
    transitions[INTERNET] = {
        "exploit_web":  {WEB_DMZ: 0.75, MAIL_DMZ: 0.15, DNS_INT: 0.10},
        "phish_email":  {MAIL_DMZ: 0.70, WS_ENG: 0.20, WS_FIN: 0.10},
        "dns_recon":    {DNS_INT: 0.80, INTERNET: 0.20},  # Có thể stay
    }

    # WEB_DMZ (Node 1) → Internal
    transitions[WEB_DMZ] = {
        "smb_move":  {SMB_SHARE: 0.60, WS_FIN: 0.20, WS_ENG: 0.15, RTR_FAKE: 0.05},
        "rdp_move":  {WS_FIN: 0.50, WS_IT: 0.30, WS_ENG: 0.20},
        "dns_recon": {DNS_INT: 0.70, RTR_FAKE: 0.20, WS_ENG: 0.10},
        "end":       {SINK: 1.0},
    }

    # MAIL_DMZ (Node 2) → Internal
    transitions[MAIL_DMZ] = {
        "smb_move":  {SMB_SHARE: 0.55, WS_ENG: 0.25, WS_FIN: 0.20},
        "rdp_move":  {WS_ENG: 0.45, WS_FIN: 0.35, WS_IT: 0.20},
        "dns_recon": {DNS_INT: 0.70, WS_ENG: 0.20, RTR_FAKE: 0.10},
        "end":       {SINK: 1.0},
    }

    # WS_ENG (Node 3) → Services / Credentials
    transitions[WS_ENG] = {
        "cred_dump": {SVC_CRED: 0.50, ADMIN_CRED: 0.30, SMB_SHARE: 0.20},
        "smb_move":  {SMB_SHARE: 0.60, WS_FIN: 0.25, DB_FAKE: 0.15},  # DB_FAKE là decoy!
        "rdp_move":  {WS_IT: 0.55, WS_FIN: 0.35, DC_NODE: 0.10},
        "end":       {SINK: 1.0},
    }

    # WS_FIN (Node 4) — High value! → DB / Credentials
    transitions[WS_FIN] = {
        "cred_dump": {ADMIN_CRED: 0.55, SVC_CRED: 0.35, SMB_SHARE: 0.10},
        "smb_move":  {SMB_SHARE: 0.40, DB_FAKE: 0.35, DB_REAL: 0.25},  # Đường đến DB (cả thật lẫn giả)
        "db_access": {DB_REAL: 0.60, DB_FAKE: 0.40},                    # Trực tiếp tấn công DB
        "end":       {SINK: 1.0},
    }

    # WS_IT (Node 5) → DC / Credentials
    transitions[WS_IT] = {
        "cred_dump": {ADMIN_CRED: 0.60, SVC_CRED: 0.30, WS_FIN: 0.10},
        "smb_move":  {SMB_SHARE: 0.50, WS_FIN: 0.30, RTR_FAKE: 0.20},  # RTR_FAKE là decoy!
        "dc_attack": {DC_NODE: 0.70, ADMIN_CRED: 0.30},
        "end":       {SINK: 1.0},
    }

    # SMB_SHARE (Node 6) → Credentials / DB
    transitions[SMB_SHARE] = {
        "cred_dump": {SVC_CRED: 0.55, ADMIN_CRED: 0.35, DB_FAKE: 0.10},
        "smb_move":  {WS_FIN: 0.40, DB_FAKE: 0.35, DB_REAL: 0.25},
        "end":       {SINK: 1.0},
    }

    # DNS_INT (Node 7) → Various
    transitions[DNS_INT] = {
        "dns_recon": {SMB_SHARE: 0.40, RTR_FAKE: 0.30, WS_FIN: 0.30},
        "rdp_move":  {WS_IT: 0.50, DC_NODE: 0.30, WS_FIN: 0.20},
        "end":       {SINK: 1.0},
    }

    # ADMIN_CRED (Node 8) — Very high value → DC / DB Direct
    transitions[ADMIN_CRED] = {
        "dc_attack": {DC_NODE: 0.85, DB_REAL: 0.15},
        "db_access": {DB_REAL: 0.70, DB_FAKE: 0.30},
        "end":       {SINK: 1.0},
    }

    # SVC_CRED (Node 9) → DB access
    transitions[SVC_CRED] = {
        "db_access": {DB_REAL: 0.55, DB_FAKE: 0.45},  # Có cả DB thật và giả
        "smb_move":  {SMB_SHARE: 0.60, DB_FAKE: 0.40},
        "end":       {SINK: 1.0},
    }

    # DB_REAL (Node 10) — TRUE GOAL → Sink
    transitions[DB_REAL] = {
        "end": {SINK: 1.0},
    }

    # DB_FAKE (Node 11) — DECOY SLOT 1 → Sink
    transitions[DB_FAKE] = {
        "end": {SINK: 1.0},
    }

    # RTR_FAKE (Node 12) — DECOY SLOT 2 → Sink
    transitions[RTR_FAKE] = {
        "end": {SINK: 1.0},
    }

    # DOMAIN CONTROLLER (Node 13) → DB / Full access
    transitions[DC_NODE] = {
        "db_access": {DB_REAL: 0.90, DB_FAKE: 0.10},  # DC → DB rất chắc chắn
        "end":       {SINK: 1.0},
    }

    # SINK (Node 14)
    transitions[SINK] = {
        "noop": {SINK: 1.0},
    }

    # ---- REWARDS ----
    # Attacker reward: cao khi đến True Goal, 0 tại Decoy
    attacker_reward: Dict[Tuple[int, str], float] = {
        (DB_REAL, "end"):   1.0,   # Thành công! Đánh cắp DB thật
        (DC_NODE, "end"):   0.8,   # Domain Controller cũng có giá trị
        (DB_FAKE, "end"):   0.0,   # Decoy — không có giá trị
        (RTR_FAKE, "end"):  0.0,   # Decoy
        (ADMIN_CRED, "end"): 0.5,  # Chiếm được admin cred
    }

    # Defender reward: cao khi attacker vào Decoy, thấp khi attacker đến True Goal
    defender_reward: Dict[Tuple[int, str], float] = {
        (DB_FAKE, "end"):   1.0,    # Attacker vào bẫy! Defender thắng
        (RTR_FAKE, "end"):  0.8,    # Attacker vào bẫy router
        (DB_REAL, "end"):  -2.0,    # Attacker lấy được DB thật — Defender thua nặng
        (DC_NODE, "end"):  -1.5,    # DC bị chiếm — Defender thua
        (ADMIN_CRED, "end"): -0.7,  # Admin cred bị lộ — trung bình
    }

    # ---- STATE LABELS ----
    node_metadata = copy.deepcopy(NODE_DEFINITIONS)
    for slot in DECOY_SITES:
        node_metadata[slot]["realism_score"] = decoy_realism
        node_metadata[slot]["behavioral_signal"] = max(0.0, 1.0 - decoy_realism)
    state_labels = {k: v["label"] for k, v in node_metadata.items()}

    # ---- BUILD GRAPH ----
    graph = MIRAGEAttackGraph(
        states=states,
        actions=ACTIONS,
        available_actions=available_actions,
        transitions=transitions,
        start_distribution={INTERNET: 1.0},
        discount=discount,
        budget=budget,
        true_goals=[TRUE_GOAL],
        decoy_sites=DECOY_SITES,
        sink_state=SINK,
        state_labels=state_labels,
        attacker_reward=attacker_reward,
        defender_reward=defender_reward,
        node_metadata=node_metadata,
    )

    # Khởi tạo belief state uniform
    initialize_decoy_slots(graph)
    n_active = len(states) - 1
    graph.belief_state = {s: 1.0/n_active for s in states if s != SINK}

    return graph


def build_synthetic_enterprise_graph(
    n_nodes: int = 100,
    budget: Optional[float] = None,
    discount: Optional[float] = None,
    seed: int = 42,
    decoy_fraction: float = 0.03,
) -> MIRAGEAttackGraph:
    """
    Build a scalable synthetic enterprise attack graph.

    This is intentionally metadata-rich so the decision engine can test
    100/500/1000-node behavior without exploding the action catalog.
    """
    config = load_config()
    if budget is None:
        budget = config.get("general", {}).get("budget_limit", 12.0)
    if discount is None:
        discount = config.get("general", {}).get("discount_factor", 0.95)

    if n_nodes < 30:
        raise ValueError("n_nodes must be >= 30 for the synthetic scaling graph")
    budget = float(budget)
    discount = float(discount)
    decoy_fraction = float(decoy_fraction)
    if not math.isfinite(budget) or budget < 0:
        raise ValueError("budget must be finite and non-negative")
    if not math.isfinite(discount) or not 0 <= discount < 1:
        raise ValueError("discount must satisfy 0 <= discount < 1")
    if (
        not math.isfinite(decoy_fraction)
        or not 0 < decoy_fraction < 0.5
    ):
        raise ValueError("decoy_fraction must satisfy 0 < value < 0.5")

    rng = random.Random(seed)
    states = list(range(n_nodes))
    sink = n_nodes - 1
    true_goal = n_nodes - 2
    n_decoys = max(2, min(60, int(n_nodes * decoy_fraction)))
    decoy_sites = list(range(n_nodes - 2 - n_decoys, n_nodes - 2))

    real_nodes = [s for s in states if s not in set(decoy_sites + [sink, true_goal])]
    tier_names = ["external", "dmz", "internal", "services", "credentials", "critical", "data"]
    tier_asset = {
        "external": "entry",
        "dmz": "web_server",
        "internal": "workstation",
        "services": "file_share",
        "credentials": "credential",
        "critical": "dc",
        "data": "database",
    }

    tiers: Dict[str, List[int]] = {name: [] for name in tier_names}
    for i, node in enumerate(real_nodes):
        if node == 0:
            tier = "external"
        else:
            frac = i / max(1, len(real_nodes) - 1)
            tier = tier_names[min(len(tier_names) - 1, int(frac * len(tier_names)))]
        tiers[tier].append(node)

    state_labels: Dict[int, str] = {}
    node_metadata: Dict[int, Dict] = {}

    for tier_idx, tier in enumerate(tier_names):
        for node in tiers[tier]:
            asset_type = tier_asset[tier]
            value = min(1.0, 0.08 + tier_idx * 0.13 + rng.random() * 0.08)
            service_count = {
                "entry": 1,
                "web_server": rng.randint(2, 6),
                "workstation": 1,
                "file_share": rng.randint(4, 9),
                "credential": rng.randint(1, 4),
                "dc": rng.randint(10, 18),
                "database": rng.randint(8, 16),
            }.get(asset_type, 1)
            user_count = {
                "entry": 0,
                "web_server": rng.randint(120, 450),
                "workstation": rng.randint(5, 60),
                "file_share": rng.randint(250, 900),
                "credential": rng.randint(50, 350),
                "dc": rng.randint(700, 2200),
                "database": rng.randint(400, 1800),
            }.get(asset_type, 10)
            state_labels[node] = f"{tier.title()}_{node}"
            node_metadata[node] = {
                "label": state_labels[node],
                "layer": tier,
                "asset_type": asset_type,
                "is_real": True,
                "value": value,
                "business_criticality": min(1.0, value + rng.random() * 0.12),
                "service_count": service_count,
                "user_count": user_count,
            }

    state_labels[true_goal] = "Synthetic_DB_REAL"
    node_metadata[true_goal] = {
        "label": state_labels[true_goal],
        "layer": "data",
        "asset_type": "database",
        "is_real": True,
        "value": 1.0,
        "business_criticality": 1.0,
        "service_count": 20,
        "user_count": 2500,
    }
    for idx, node in enumerate(decoy_sites):
        asset_type = "decoy_db" if idx % 2 == 0 else "decoy_router"
        state_labels[node] = f"Synthetic_Decoy_{idx}_{node}"
        node_metadata[node] = {
            "label": state_labels[node],
            "layer": "data" if asset_type == "decoy_db" else "services",
            "asset_type": asset_type,
            "is_real": False,
            "value": 0.0,
            "business_criticality": 0.03,
            "service_count": 1 if asset_type == "decoy_db" else 3,
            "user_count": 5 if asset_type == "decoy_db" else 40,
        }
    state_labels[sink] = "Sink"
    node_metadata[sink] = {
        "label": "Sink",
        "layer": "sink",
        "asset_type": "sink",
        "is_real": True,
        "value": 0.0,
        "business_criticality": 0.0,
        "service_count": 0,
        "user_count": 0,
    }

    def action_set(asset_type: str) -> List[str]:
        if asset_type == "entry":
            return ["exploit_web", "phish_email", "dns_recon"]
        if asset_type in {"web_server", "mail_server"}:
            return ["smb_move", "rdp_move", "dns_recon", "end"]
        if asset_type == "workstation":
            return ["cred_dump", "smb_move", "rdp_move", "end"]
        if asset_type in {"file_share", "dns_server"}:
            return ["cred_dump", "smb_move", "dns_recon", "end"]
        if asset_type == "credential":
            return ["db_access", "dc_attack", "smb_move", "end"]
        if asset_type == "dc":
            return ["db_access", "end"]
        if asset_type == "database":
            return ["end"]
        if asset_type.startswith("decoy"):
            return ["end"]
        return ["smb_move", "end"]

    available_actions: Dict[int, List[str]] = {}
    transitions: Dict[int, Dict[str, Dict[int, float]]] = {}

    tier_index = {tier: idx for idx, tier in enumerate(tier_names)}
    nodes_by_tier = [tiers[t] for t in tier_names]

    def later_targets(node: int, count: int) -> List[int]:
        meta = node_metadata[node]
        current_tier = meta["layer"]
        start_idx = tier_index.get(current_tier, 0)
        pool: List[int] = []
        for idx in range(start_idx, min(len(nodes_by_tier), start_idx + 3)):
            pool.extend(nodes_by_tier[idx])
        pool = [p for p in pool if p != node]
        if start_idx >= len(tier_names) - 2 or rng.random() < 0.18:
            pool.append(true_goal)
        if rng.random() < 0.28:
            pool.extend(rng.sample(decoy_sites, k=min(len(decoy_sites), max(1, count // 2))))
        if not pool:
            pool = [true_goal]
        rng.shuffle(pool)
        return list(dict.fromkeys(pool[:count]))

    for node in states:
        meta = node_metadata[node]
        asset_type = meta["asset_type"]
        available_actions[node] = action_set(asset_type)
        transitions[node] = {}

        if node == sink:
            transitions[node]["noop"] = {sink: 1.0}
            available_actions[node] = ["noop"]
            continue
        if node == true_goal or node in decoy_sites:
            transitions[node]["end"] = {sink: 1.0}
            available_actions[node] = ["end"]
            continue

        for action in available_actions[node]:
            if action == "end":
                transitions[node][action] = {sink: 1.0}
                continue
            count = rng.randint(2, 5)
            targets = later_targets(node, count)
            weights = [rng.uniform(0.2, 1.0) for _ in targets]
            total = sum(weights)
            transitions[node][action] = {
                target: weight / total
                for target, weight in zip(targets, weights, strict=True)
            }

    # Ensure at least one clear path from entry to the true goal.
    spine = [0]
    for tier in ["dmz", "internal", "services", "credentials", "critical"]:
        if tiers[tier]:
            spine.append(tiers[tier][0])
    spine.append(true_goal)
    for src, dst in zip(spine, spine[1:], strict=True):
        action = available_actions[src][0]
        trans = transitions[src].setdefault(action, {})
        trans[dst] = max(trans.get(dst, 0.0), 0.45)
        total = sum(trans.values())
        transitions[src][action] = {k: v / total for k, v in trans.items()}

    attacker_reward: Dict[Tuple[int, str], float] = {
        (true_goal, "end"): 1.0,
    }
    defender_reward: Dict[Tuple[int, str], float] = {
        (true_goal, "end"): -2.0,
    }
    for decoy in decoy_sites:
        attacker_reward[(decoy, "end")] = 0.0
        defender_reward[(decoy, "end")] = 1.0
    for node in tiers.get("critical", [])[: max(1, len(tiers.get("critical", [])) // 12)]:
        attacker_reward[(node, "end")] = 0.8
        defender_reward[(node, "end")] = -1.4

    for node, metadata in node_metadata.items():
        internal_label = metadata.get("label", state_labels.get(node, str(node)))
        metadata["internal_label"] = internal_label
        if node in decoy_sites:
            visible = (
                f"DataReplica_{node}"
                if metadata.get("asset_type") == "decoy_db"
                else f"ServiceGateway_{node}"
            )
            metadata["realism_score"] = 0.8
        else:
            visible = internal_label
            metadata["realism_score"] = 1.0
        metadata["attacker_visible_label"] = visible
        metadata["service_banner"] = visible

    graph = MIRAGEAttackGraph(
        states=states,
        actions=ACTIONS,
        available_actions=available_actions,
        transitions=transitions,
        start_distribution={0: 1.0},
        discount=discount,
        budget=budget,
        true_goals=[true_goal],
        decoy_sites=decoy_sites,
        sink_state=sink,
        state_labels=state_labels,
        attacker_reward=attacker_reward,
        defender_reward=defender_reward,
        node_metadata=node_metadata,
    )
    initialize_decoy_slots(graph)
    n_active = len(states) - 1
    graph.belief_state = {s: 1.0 / n_active for s in states if s != sink}
    return graph


def build_configured_attack_graph(config: Optional[Dict] = None) -> MIRAGEAttackGraph:
    """Build the configured topology, falling back to the built-in graph."""
    config = config or load_config()
    topology = config.get("topology", {})
    source = str(topology.get("source", "builtin")).lower()
    if source == "builtin":
        return build_enterprise_attack_graph()
    if source != "file":
        raise ValueError("topology.source must be either 'builtin' or 'file'")

    topology_path = resolve_project_path(topology.get("path", ""))
    if not topology_path.exists():
        raise FileNotFoundError(f"Configured topology does not exist: {topology_path}")

    from mirage.layer2_graph_engine.graph_parser import load_attack_graph

    graph = load_attack_graph(
        str(topology_path),
        fmt=topology.get("format"),
        config={
            "budget": config.get("general", {}).get("budget_limit", 4.0),
            "discount": config.get("general", {}).get("discount_factor", 0.95),
            "decoy_realism": config.get("layer2", {}).get("decoy_realism", 0.8),
        },
    )
    graph.budget = float(config.get("general", {}).get("budget_limit", graph.budget))
    graph.discount = float(config.get("general", {}).get("discount_factor", graph.discount))
    return graph


def print_graph_summary(graph: MIRAGEAttackGraph) -> None:
    """In tóm tắt đồ thị tấn công."""
    print("=" * 70)
    print("MIRAGE Enterprise Attack Graph — Version 2")
    print("=" * 70)
    print(f"Total nodes: {len(graph.states)}")
    print(f"True Goal: Node {graph.true_goals[0]} ({graph.label(graph.true_goals[0])})")
    print(f"Decoy Slots: {[f'Node {d} ({graph.label(d)})' for d in graph.decoy_sites]}")
    print(f"Budget: {graph.budget}")
    print()
    print("NETWORK TOPOLOGY:")
    print("-" * 70)
    for node_id in graph.states:
        meta = graph.node_metadata.get(node_id, {})
        is_goal  = "🎯 TRUE GOAL" if graph.is_true_goal(node_id) else ""
        is_decoy = "🪤 ACTIVE DECOY" if graph.is_decoy(node_id) else ""
        is_slot = "DECOY SLOT" if node_id in graph.decoy_sites and not is_decoy else ""
        flag     = is_goal or is_decoy
        flag = flag or is_slot
        print(
            f"  Node {node_id:2d}: {graph.label(node_id):30s} "
            f"[{meta.get('layer', 'unknown'):12s}] {flag}"
        )
    print()
    print("HIGH-RISK ATTACK PATHS:")
    print("-" * 70)
    for i, path in enumerate(graph.get_high_risk_paths(), 1):
        path_str = " → ".join(f"{graph.label(n)}" for n in path)
        print(f"  Path {i}: {path_str}")
    print("=" * 70)


if __name__ == "__main__":
    graph = build_enterprise_attack_graph()
    print_graph_summary(graph)

    # Test belief update
    print("\nTesting belief update...")
    # Giả lập: attacker vừa bị phát hiện ở WS_FIN
    observation = {WS_FIN: 0.8, WS_ENG: 0.3, WS_IT: 0.2}
    graph.update_belief(observation)
    top5 = sorted(graph.belief_state.items(), key=lambda x: -x[1])[:5]
    print("Top 5 likely attacker locations:")
    for node, prob in top5:
        print(f"  {graph.label(node):30s}: {prob:.3f}")
