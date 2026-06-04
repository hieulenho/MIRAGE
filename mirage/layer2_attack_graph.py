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

import sys
import os

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import numpy as np

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
    Đồ thị tấn công mạng doanh nghiệp 15 node cho MIRAGE Version 1.
    
    Tương thích với AttackGraphMDP từ codebase cũ.
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

    @property
    def name(self) -> str:
        return "mirage_enterprise_graph_v1"

    def label(self, state: int) -> str:
        return self.state_labels.get(state, str(state))

    def get_node_info(self, state: int) -> Dict:
        return self.node_metadata.get(state, {})

    def is_decoy(self, state: int) -> bool:
        return state in self.decoy_sites

    def is_true_goal(self, state: int) -> bool:
        return state in self.true_goals

    def get_high_risk_paths(self) -> List[List[int]]:
        """Trả về các đường dẫn rủi ro cao từ entry đến True Goal."""
        return [
            [INTERNET, WEB_DMZ, WS_FIN, SVC_CRED, DB_REAL],           # Path 1: Web → Finance WS → DB
            [INTERNET, MAIL_DMZ, WS_ENG, ADMIN_CRED, DC_NODE, DB_REAL], # Path 2: Mail → Admin → DC → DB
            [INTERNET, WEB_DMZ, SMB_SHARE, SVC_CRED, DB_REAL],          # Path 3: Web → SMB → Cred → DB
        ]

    def update_belief(self, observation: Dict[int, float]) -> None:
        """
        Cập nhật belief state (Bayesian update đơn giản).
        observation: dict {node: likelihood} dựa trên telemetry.
        """
        if not self.belief_state:
            # Khởi tạo uniform
            n = len(self.states) - 1  # Loại sink
            self.belief_state = {s: 1.0/n for s in self.states if s != self.sink_state}

        # Bayes update: b'(s) ∝ P(obs|s) * b(s)
        new_belief = {}
        for s in self.belief_state:
            likelihood = observation.get(s, 0.1)  # Default likelihood thấp
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
        Chuyển sang format tương thích với AttackGraphMDP của codebase cũ.
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


def build_enterprise_attack_graph(
    budget: float = 4.0,
    discount: float = 0.95,
    decoy_realism: float = 0.8,
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
    state_labels = {k: v["label"] for k, v in NODE_DEFINITIONS.items()}

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
        node_metadata=NODE_DEFINITIONS,
    )

    # Khởi tạo belief state uniform
    n_active = len(states) - 1
    graph.belief_state = {s: 1.0/n_active for s in states if s != SINK}

    return graph


def print_graph_summary(graph: MIRAGEAttackGraph) -> None:
    """In tóm tắt đồ thị tấn công."""
    print("=" * 70)
    print("MIRAGE Enterprise Attack Graph — Version 1")
    print("=" * 70)
    print(f"Total nodes: {len(graph.states)}")
    print(f"True Goal: Node {graph.true_goals[0]} ({graph.label(graph.true_goals[0])})")
    print(f"Decoy Slots: {[f'Node {d} ({graph.label(d)})' for d in graph.decoy_sites]}")
    print(f"Budget: {graph.budget}")
    print()
    print("NETWORK TOPOLOGY:")
    print("-" * 70)
    for node_id, meta in NODE_DEFINITIONS.items():
        is_goal  = "🎯 TRUE GOAL" if graph.is_true_goal(node_id) else ""
        is_decoy = "🪤 DECOY"     if graph.is_decoy(node_id)     else ""
        flag     = is_goal or is_decoy
        print(f"  Node {node_id:2d}: {meta['label']:30s} [{meta['layer']:12s}] {flag}")
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
