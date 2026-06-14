"""
MIRAGE - Dynamic Attack Graph Parser
======================================
Parse Attack Graph từ các nguồn bên ngoài thay vì hardcode 15-node topology.

Hỗ trợ 3 định dạng đầu vào:
  1. MIRAGE Native JSON    — Định dạng tự định nghĩa (linh hoạt nhất)
  2. BloodHound JSON       — AD relationship data (nodes = principals, edges = attacks)
  3. Nmap/Nessus Generic   — Host/service scan results (nodes = hosts, edges = exploits)

Output: MIRAGEAttackGraph hoàn chỉnh, tương thích với Layer 3-6.

Example MIRAGE Native JSON format:
  {
    "nodes": [
      {"id": 0, "label": "Internet", "layer": "external", "asset_type": "entry",
       "is_real": true, "value": 0.0, "start": true},
      {"id": 1, "label": "WebServer", "layer": "dmz", "asset_type": "web_server",
       "is_real": true, "value": 0.3},
      {"id": 10, "label": "Database", "layer": "data", "asset_type": "database",
       "is_real": true, "value": 1.0, "goal": true},
      {"id": 11, "label": "FakeDB", "layer": "data", "asset_type": "decoy_db",
       "is_real": false, "value": 0.0, "decoy": true}
    ],
    "edges": [
      {"src": 0, "dst": 1, "action": "exploit_web", "prob": 0.8},
      {"src": 1, "dst": 10, "action": "db_access", "prob": 0.6}
    ],
    "config": {
      "budget": 4.0,
      "discount": 0.95,
      "decoy_realism": 0.8
    }
  }
"""

from __future__ import annotations

import json
import math
import os
from typing import Dict, List, Optional, Tuple, Any

from mirage.layer2_attack_graph import MIRAGEAttackGraph


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _normalize_dist(dist: Dict[int, float], sink: int) -> Dict[int, float]:
    """Normalize a probability distribution, routing remainder to sink."""
    positive = {}
    for state, raw_probability in dist.items():
        probability = float(raw_probability)
        if not math.isfinite(probability) or probability < 0:
            raise ValueError(
                "Transition probabilities must be finite and non-negative"
            )
        if probability > 0:
            positive[state] = probability
    total = sum(positive.values())
    if total <= 0:
        return {sink: 1.0}
    if total < 1.0 - 1e-9:
        positive[sink] = positive.get(sink, 0.0) + (1.0 - total)
        return positive
    if total > 1.0 + 1e-9:
        return {state: probability / total for state, probability in positive.items()}
    return positive


def _build_graph_from_spec(
    nodes: List[Dict],
    edges: List[Dict],
    config: Dict,
) -> MIRAGEAttackGraph:
    """
    Core builder: turn node/edge spec lists into a MIRAGEAttackGraph.

    Node spec keys (all optional unless noted):
      id (required int), label, layer, asset_type, is_real, value,
      business_criticality, start (bool), goal (bool), decoy (bool),
      sink (bool), realism_score, service_banner

    Edge spec keys:
      src (required), dst (required), action (required), prob (float, default 1.0)
      reward_delta (float, optional — attacker reward override)
    """
    budget = float(config.get("budget", 4.0))
    discount = float(config.get("discount", 0.95))
    decoy_realism = float(config.get("decoy_realism", 0.8))
    if not math.isfinite(budget) or budget < 0:
        raise ValueError("budget must be a finite non-negative number")
    if not math.isfinite(discount) or not 0 <= discount < 1:
        raise ValueError("discount must satisfy 0 <= discount < 1")
    if not math.isfinite(decoy_realism) or not 0 <= decoy_realism <= 1:
        raise ValueError("decoy_realism must satisfy 0 <= value <= 1")
    if not nodes:
        raise ValueError("At least one node is required")

    # ---- Classify nodes ----
    node_ids: List[int] = [int(n["id"]) for n in nodes]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("Node IDs must be unique.")
    node_meta: Dict[int, Dict] = {}
    state_labels: Dict[int, str] = {}
    start_nodes: List[int] = []
    goal_nodes: List[int] = []
    decoy_nodes: List[int] = []
    sink_node: Optional[int] = None

    for n in nodes:
        nid = int(n["id"])
        meta = {
            "label":                n.get("label", f"Node_{nid}"),
            "layer":                n.get("layer", "unknown"),
            "asset_type":           n.get("asset_type", "workstation"),
            "is_real":              bool(n.get("is_real", True)),
            "value":                float(n.get("value", 0.0)),
            "business_criticality": float(n.get("business_criticality", n.get("value", 0.0))),
            "service_count":        int(n.get("service_count", 1)),
            "user_count":           int(n.get("user_count", 10)),
        }
        if "realism_score" in n:
            meta["realism_score"] = float(n["realism_score"])
        if "service_banner" in n:
            meta["service_banner"] = str(n["service_banner"])

        node_meta[nid] = meta
        state_labels[nid] = meta["label"]

        start_probability = n.get("start_probability")
        if start_probability is not None:
            start_probability = float(start_probability)
            if (
                not math.isfinite(start_probability)
                or start_probability < 0
            ):
                raise ValueError(
                    f"Invalid start_probability for node {nid}"
                )
            if start_probability > 0:
                start_nodes.append(nid)
                meta["start_probability"] = start_probability
        elif n.get("start"):
            start_nodes.append(nid)
        if n.get("goal"):
            goal_nodes.append(nid)
        if n.get("decoy"):
            decoy_nodes.append(nid)
            meta["is_real"] = False
            meta["realism_score"] = decoy_realism
            meta["behavioral_signal"] = max(0.0, 1.0 - decoy_realism)
            meta["attacker_visible_label"] = n.get(
                "attacker_visible_label",
                n.get("service_banner", meta["label"]),
            )
        if n.get("sink"):
            if sink_node is not None:
                raise ValueError("Only one node may be marked as the sink.")
            sink_node = nid

    # If no explicit sink, add one automatically
    if sink_node is None:
        sink_node = max(node_ids) + 1
        node_ids.append(sink_node)
        node_meta[sink_node] = {
            "label": "Sink", "layer": "sink", "asset_type": "sink",
            "is_real": True, "value": 0.0, "business_criticality": 0.0,
            "service_count": 0, "user_count": 0,
        }
        state_labels[sink_node] = "Sink"

    # Default start / goal
    if not start_nodes:
        start_nodes = [node_ids[0]]
    if not goal_nodes:
        raise ValueError("At least one node must be marked as 'goal': true in the JSON spec.")
    if sink_node in start_nodes:
        raise ValueError("The sink node cannot be an attacker start node")
    if sink_node in goal_nodes:
        raise ValueError("The sink node cannot be a true goal")
    overlap = set(goal_nodes).intersection(decoy_nodes)
    if overlap:
        raise ValueError(
            f"Nodes cannot be both true goals and decoys: {sorted(overlap)}"
        )

    # ---- Build transitions from edges ----
    # Group edges by (src, action) → list of (dst, prob)
    edge_map: Dict[Tuple[int, str], List[Tuple[int, float]]] = {}
    attacker_reward: Dict[Tuple[int, str], float] = {}

    for e in edges:
        src = int(e["src"])
        dst = int(e["dst"])
        if src not in node_meta or dst not in node_meta:
            raise ValueError(f"Edge references unknown node: {src} -> {dst}")
        action = str(e.get("action", "move"))
        prob = float(e.get("prob", 1.0))
        if not math.isfinite(prob) or prob < 0:
            raise ValueError(
                f"Edge probability must be finite and non-negative: {src} -> {dst}"
            )
        key = (src, action)
        edge_map.setdefault(key, []).append((dst, prob))

        # Optional attacker reward at destination
        if "reward_delta" in e:
            attacker_reward[(dst, "end")] = float(e["reward_delta"])

    # Collect all unique actions per node
    available_actions: Dict[int, List[str]] = {nid: [] for nid in node_ids}
    transitions: Dict[int, Dict[str, Dict[int, float]]] = {nid: {} for nid in node_ids}

    for (src, action), dsts in edge_map.items():
        if src not in available_actions:
            continue
        if action not in available_actions[src]:
            available_actions[src].append(action)

        # Build distribution: normalise per (src, action)
        raw_dist: Dict[int, float] = {}
        for dst, prob in dsts:
            raw_dist[dst] = raw_dist.get(dst, 0.0) + prob
        transitions[src][action] = _normalize_dist(raw_dist, sink_node)

    # Every non-sink node gets an "end" action → sink
    for nid in node_ids:
        if nid == sink_node:
            continue
        if "end" not in available_actions[nid]:
            available_actions[nid].append("end")
        transitions[nid]["end"] = {sink_node: 1.0}

    # Sink gets noop
    available_actions[sink_node] = ["noop"]
    transitions[sink_node] = {"noop": {sink_node: 1.0}}

    # ---- Default rewards ----
    # Attacker reward: +1.0 at true goals, 0.0 at decoys
    for g in goal_nodes:
        attacker_reward.setdefault((g, "end"), 1.0)
    for d in decoy_nodes:
        attacker_reward.setdefault((d, "end"), 0.0)

    # Defender reward: +1.0 when attacker hits decoy, -2.0 at true goal
    defender_reward: Dict[Tuple[int, str], float] = {}
    for g in goal_nodes:
        defender_reward[(g, "end")] = -2.0
    for d in decoy_nodes:
        defender_reward[(d, "end")] = 1.0

    # ---- Build start distribution ----
    explicit_start = {
        node: float(node_meta[node].get("start_probability", 0.0))
        for node in start_nodes
        if "start_probability" in node_meta[node]
    }
    if explicit_start:
        for node in start_nodes:
            explicit_start.setdefault(node, 0.0)
        total_start = sum(explicit_start.values())
        if total_start <= 0:
            raise ValueError("start_probability values must sum to a positive number")
        start_dist = {
            node: probability / total_start
            for node, probability in explicit_start.items()
            if probability > 0
        }
    else:
        start_dist = {s: 1.0 / len(start_nodes) for s in start_nodes}

    # ---- Collect all unique actions ----
    all_actions: List[str] = sorted({
        a for acts in available_actions.values() for a in acts
    })

    # ---- Assemble graph ----
    graph = MIRAGEAttackGraph(
        states=node_ids,
        actions=all_actions,
        available_actions=available_actions,
        transitions=transitions,
        start_distribution=start_dist,
        discount=discount,
        budget=budget,
        true_goals=goal_nodes,
        decoy_sites=decoy_nodes,
        sink_state=sink_node,
        state_labels=state_labels,
        attacker_reward=attacker_reward,
        defender_reward=defender_reward,
        node_metadata=node_meta,
    )

    # Initialize belief state uniform (excluding sink)
    n_active = len(node_ids) - 1
    graph.belief_state = {s: 1.0 / n_active for s in node_ids if s != sink_node}

    from mirage.layer2_attack_graph import initialize_decoy_slots

    return initialize_decoy_slots(graph)


# ---------------------------------------------------------------------------
# Parser 1: MIRAGE Native JSON
# ---------------------------------------------------------------------------

def load_from_mirage_json(
    path: str,
    config: Optional[Dict] = None,
) -> MIRAGEAttackGraph:
    """
    Load a MIRAGEAttackGraph from a MIRAGE Native JSON file.

    The JSON must have keys: "nodes", "edges", and optionally "config".

    Args:
        path: Path to the JSON file.

    Returns:
        MIRAGEAttackGraph ready for use with Layer 3-6.

    Raises:
        FileNotFoundError, ValueError if the JSON is malformed.
    """
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    nodes = data.get("nodes", [])
    edges = data.get("edges", [])
    file_config = data.get("config", {})
    effective_config = dict(file_config)
    effective_config.update(config or {})

    if not nodes:
        raise ValueError(f"No nodes found in {path}")

    return _build_graph_from_spec(nodes, edges, effective_config)


# ---------------------------------------------------------------------------
# Parser 2: BloodHound JSON (simplified)
# ---------------------------------------------------------------------------

def load_from_bloodhound_json(path: str, config: Optional[Dict] = None) -> MIRAGEAttackGraph:
    """
    Load a MIRAGEAttackGraph from a BloodHound-style JSON export.

    BloodHound exports graph data as {"nodes": [...], "edges": [...]}.
    Each node has {"id", "label", "type"} and each edge has
    {"source", "target", "type"} describing AD relationships.

    Mapping from BloodHound types to MIRAGE concepts:
      Node types:  "User"       → credential
                   "Computer"   → workstation
                   "Group"      → credential
                   "Domain"     → dc
                   "GPO"        → workstation
    Edge types:    "MemberOf"   → smb_move (p=0.9)
                   "AdminTo"    → rdp_move (p=0.8)
                   "HasSession" → cred_dump (p=0.7)
                   "DCSync"     → dc_attack (p=0.85)
                   "CanRDP"     → rdp_move (p=0.7)
                   "Contains"   → smb_move (p=0.6)
                   *            → move (p=0.5)  # default

    Args:
        path: Path to the BloodHound JSON export.
        config: Optional config override (budget, discount, decoy_realism).

    Returns:
        MIRAGEAttackGraph
    """
    BH_TYPE_TO_ASSET = {
        "User": "credential",
        "Computer": "workstation",
        "Group": "credential",
        "Domain": "dc",
        "GPO": "workstation",
        "OU": "workstation",
    }
    BH_LAYER_MAP = {
        "credential": "credentials",
        "workstation": "internal",
        "dc": "critical",
    }
    BH_EDGE_ACTION = {
        "MemberOf":   ("smb_move",   0.90),
        "AdminTo":    ("rdp_move",   0.80),
        "HasSession": ("cred_dump",  0.70),
        "DCSync":     ("dc_attack",  0.85),
        "CanRDP":     ("rdp_move",   0.70),
        "Contains":   ("smb_move",   0.60),
        "WriteDacl":  ("cred_dump",  0.65),
        "GenericAll": ("dc_attack",  0.75),
        "Owns":       ("cred_dump",  0.70),
    }

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    bh_nodes = data.get("nodes", data.get("graph", {}).get("nodes", []))
    bh_edges = data.get("edges", data.get("graph", {}).get("edges", []))

    if not bh_nodes:
        raise ValueError(f"No BloodHound nodes found in {path}")

    # Build id mapping (BloodHound uses string IDs or object IDs)
    id_map: Dict[Any, int] = {}
    nodes: List[Dict] = []

    # Add an "Internet/Entry" node as attacker start
    nodes.append({
        "id": 0,
        "label": "Internet_Attacker",
        "layer": "external",
        "asset_type": "entry",
        "is_real": True,
        "value": 0.0,
        "start": True,
    })
    id_map["__INTERNET__"] = 0

    for i, bn in enumerate(bh_nodes, start=1):
        bh_id = bn.get("id") or bn.get("objectid") or str(i)
        ntype = bn.get("label") or bn.get("type", "Computer")
        label = bn.get("name") or bn.get("label", f"BH_{i}")
        asset_type = BH_TYPE_TO_ASSET.get(ntype, "workstation")
        layer = BH_LAYER_MAP.get(asset_type, "internal")
        value = 0.8 if asset_type == "dc" else (0.5 if asset_type == "credential" else 0.2)

        is_goal = asset_type == "dc" and "domain" in str(label).lower()

        nodes.append({
            "id": i,
            "label": str(label),
            "layer": layer,
            "asset_type": asset_type,
            "is_real": True,
            "value": value,
            "goal": is_goal,
        })
        id_map[str(bh_id)] = i

    # Mark first Domain/DC node as goal if none explicitly marked
    has_goal = any(n.get("goal") for n in nodes)
    if not has_goal:
        for n in nodes:
            if n.get("asset_type") == "dc":
                n["goal"] = True
                has_goal = True
                break
    if not has_goal:
        nodes[-1]["goal"] = True  # fallback: last node

    # Add edges from "Internet" to first non-entry nodes
    edges: List[Dict] = []
    non_entry = [n["id"] for n in nodes if n["id"] != 0][:3]
    for nid in non_entry:
        edges.append({"src": 0, "dst": nid, "action": "exploit_web", "prob": 0.6})

    for be in bh_edges:
        src_key = str(be.get("source") or be.get("startNode", ""))
        dst_key = str(be.get("target") or be.get("endNode", ""))
        rel_type = be.get("type") or be.get("label", "move")

        src_id = id_map.get(src_key)
        dst_id = id_map.get(dst_key)
        if src_id is None or dst_id is None:
            continue

        action, prob = BH_EDGE_ACTION.get(rel_type, ("move", 0.5))
        edges.append({"src": src_id, "dst": dst_id, "action": action, "prob": prob})

    cfg = config or {"budget": 4.0, "discount": 0.95, "decoy_realism": 0.8}
    return _build_graph_from_spec(nodes, edges, cfg)


# ---------------------------------------------------------------------------
# Parser 3: Nmap XML / Generic Host Scan JSON
# ---------------------------------------------------------------------------

def load_from_nmap_json(path: str, config: Optional[Dict] = None) -> MIRAGEAttackGraph:
    """
    Load a MIRAGEAttackGraph from a simplified Nmap/Nessus scan export in JSON.

    Expected format (converted from Nmap XML via e.g. python-libnmap or xmltodict):
    {
      "hosts": [
        {
          "ip": "192.168.1.10",
          "hostname": "web01",
          "ports": [{"port": 80, "service": "http"}, {"port": 443, "service": "https"}],
          "os": "Linux",
          "risk_score": 0.3
        },
        ...
      ]
    }

    MIRAGE automatically:
      - Assigns each host as a graph node
      - Creates edges based on common attack paths (web → internal, SMB chaining)
      - Estimates asset_type from open ports
      - Designates highest-value host as True Goal

    Args:
        path: Path to the Nmap JSON file.
        config: Optional config override.

    Returns:
        MIRAGEAttackGraph
    """
    PORT_ASSET_MAP = {
        80:   "web_server", 443: "web_server", 8080: "web_server", 8443: "web_server",
        25:   "mail_server", 587: "mail_server", 465: "mail_server",
        445:  "file_share",  139: "file_share",
        3389: "workstation", 22: "workstation",
        53:   "dns_server",
        1433: "database", 3306: "database", 5432: "database", 1521: "database",
        636:  "dc", 389: "dc", 88: "dc", 3268: "dc",
    }
    ASSET_VALUE = {
        "entry": 0.0, "web_server": 0.2, "mail_server": 0.2,
        "dns_server": 0.3, "workstation": 0.3, "file_share": 0.4,
        "credential": 0.5, "database": 0.9, "dc": 1.0,
    }
    ASSET_LAYER = {
        "web_server": "dmz", "mail_server": "dmz",
        "dns_server": "services", "file_share": "services",
        "workstation": "internal", "credential": "credentials",
        "database": "data", "dc": "critical",
    }

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    raw_hosts = data.get("hosts", [])
    if not raw_hosts:
        raise ValueError(f"No hosts found in Nmap JSON {path}")

    # Node 0 = attacker entry
    nodes: List[Dict] = [
        {"id": 0, "label": "Internet", "layer": "external", "asset_type": "entry",
         "is_real": True, "value": 0.0, "start": True}
    ]
    ip_to_id: Dict[str, int] = {}

    for i, host in enumerate(raw_hosts, start=1):
        ip = host.get("ip", f"host_{i}")
        hostname = host.get("hostname", ip)
        ports = [int(p.get("port", 0)) for p in host.get("ports", [])]
        risk = float(host.get("risk_score", 0.3))

        # Determine asset type from open ports
        asset_type = "workstation"
        for port in sorted(ports):
            if port in PORT_ASSET_MAP:
                candidate = PORT_ASSET_MAP[port]
                if ASSET_VALUE.get(candidate, 0) >= ASSET_VALUE.get(asset_type, 0):
                    asset_type = candidate

        value = ASSET_VALUE.get(asset_type, 0.2)
        layer = ASSET_LAYER.get(asset_type, "internal")

        nodes.append({
            "id": i,
            "label": f"{hostname}_{ip}",
            "layer": layer,
            "asset_type": asset_type,
            "is_real": True,
            "value": value,
            "business_criticality": max(value, risk),
            "service_count": len(ports),
        })
        ip_to_id[ip] = i

    # Mark highest-value real node as goal
    real_nodes = [n for n in nodes if n.get("id", 0) != 0]
    if real_nodes:
        top = max(real_nodes, key=lambda n: n.get("value", 0))
        top["goal"] = True

    # Generate edges: simple topology-aware linking
    edges: List[Dict] = []
    tier_order = ["dmz", "services", "internal", "credentials", "critical", "data"]
    tier_map: Dict[str, List[int]] = {t: [] for t in tier_order}
    tier_map["external"] = [0]

    for n in nodes:
        layer = n.get("layer", "internal")
        tier_map.setdefault(layer, []).append(n["id"])

    # Internet → DMZ
    exposed = tier_map.get("dmz", [])
    if not exposed:
        exposed = [
            node["id"]
            for node in sorted(
                real_nodes,
                key=lambda item: (-item.get("service_count", 0), item["id"]),
            )[:3]
        ]
    for nid in exposed:
        edges.append({"src": 0, "dst": nid, "action": "exploit_web", "prob": 0.75})

    # Chain through non-empty tiers so missing categories do not disconnect the graph.
    non_empty_tiers = [tier for tier in tier_order if tier_map.get(tier)]
    for i in range(len(non_empty_tiers) - 1):
        src_tier = non_empty_tiers[i]
        dst_tier = non_empty_tiers[i + 1]
        for src in tier_map.get(src_tier, []):
            for dst in tier_map.get(dst_tier, []):
                edges.append({"src": src, "dst": dst, "action": "lateral_move", "prob": 0.65})

    # SMB lateral within internal
    internal = tier_map.get("internal", [])
    for j in range(len(internal)):
        for k in range(j + 1, len(internal)):
            edges.append({"src": internal[j], "dst": internal[k], "action": "smb_move", "prob": 0.5})

    cfg = config or {"budget": 4.0, "discount": 0.95, "decoy_realism": 0.8}
    return _build_graph_from_spec(nodes, edges, cfg)


# ---------------------------------------------------------------------------
# Save helper
# ---------------------------------------------------------------------------

def save_graph_to_json(graph: MIRAGEAttackGraph, path: str) -> None:
    """
    Serialize a MIRAGEAttackGraph back to MIRAGE Native JSON format.
    Useful for saving dynamically-built or modified graphs.
    """
    nodes = []
    for nid in graph.states:
        meta = graph.node_metadata.get(nid, {})
        node = {
            "id": nid,
            "label": graph.label(nid),
            "layer": meta.get("layer", "unknown"),
            "asset_type": meta.get("asset_type", "workstation"),
            "is_real": meta.get("is_real", True),
            "value": meta.get("value", 0.0),
            "business_criticality": meta.get("business_criticality", 0.0),
            "service_count": meta.get("service_count", 1),
            "user_count": meta.get("user_count", 10),
        }
        for key in (
            "realism_score",
            "service_banner",
            "attacker_visible_label",
        ):
            if key in meta:
                node[key] = meta[key]
        if nid in graph.start_distribution:
            node["start"] = True
            node["start_probability"] = graph.start_distribution[nid]
        if nid in graph.true_goals:
            node["goal"] = True
        if nid in graph.decoy_sites:
            node["decoy"] = True
        if nid == graph.sink_state:
            node["sink"] = True
        nodes.append(node)

    edges = []
    seen = set()
    for src in graph.states:
        for action, live_distribution in graph.transitions.get(src, {}).items():
            if action in ("end", "noop"):
                continue
            dist = graph.decoy_transition_templates.get(
                (src, action),
                live_distribution,
            )
            for dst, prob in dist.items():
                key = (src, dst, action)
                if key not in seen and prob > 0:
                    seen.add(key)
                    edges.append({"src": src, "dst": dst, "action": action, "prob": round(prob, 4)})

    out = {
        "nodes": nodes,
        "edges": edges,
        "config": {
            "budget": graph.budget,
            "discount": graph.discount,
            "decoy_realism": max(
                (
                    float(
                        graph.node_metadata.get(node, {}).get(
                            "realism_score",
                            0.8,
                        )
                    )
                    for node in graph.decoy_sites
                ),
                default=0.8,
            ),
        }
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"[GraphParser] Graph saved to {path} ({len(nodes)} nodes, {len(edges)} edges)")


# ---------------------------------------------------------------------------
# Convenience auto-detect loader
# ---------------------------------------------------------------------------

def load_attack_graph(
    path: str,
    fmt: Optional[str] = None,
    config: Optional[Dict] = None,
) -> MIRAGEAttackGraph:
    """
    Auto-detect format and load a MIRAGEAttackGraph from file.

    Args:
        path: Path to the input file.
        fmt:  Force format: "mirage", "bloodhound", "nmap". If None, auto-detect.
        config: Optional config override dict.

    Returns:
        MIRAGEAttackGraph
    """
    if fmt is None:
        with open(path, "r", encoding="utf-8") as f:
            sample = json.load(f)
        if "hosts" in sample:
            fmt = "nmap"
        elif "nodes" in sample and "edges" in sample:
            first_node = sample["nodes"][0] if sample["nodes"] else {}
            # BloodHound nodes typically have "objectid" key
            if "objectid" in first_node or "startNode" in (sample.get("edges") or [{}])[0]:
                fmt = "bloodhound"
            else:
                fmt = "mirage"
        else:
            fmt = "mirage"

    if fmt == "mirage":
        return load_from_mirage_json(path, config=config)
    elif fmt == "bloodhound":
        return load_from_bloodhound_json(path, config=config)
    elif fmt == "nmap":
        return load_from_nmap_json(path, config=config)
    else:
        raise ValueError(f"Unknown format '{fmt}'. Use 'mirage', 'bloodhound', or 'nmap'.")


# ---------------------------------------------------------------------------
# Quick demo / self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    demo_json = {
        "nodes": [
            {"id": 0, "label": "Internet",      "layer": "external",     "asset_type": "entry",      "is_real": True,  "value": 0.0, "start": True},
            {"id": 1, "label": "WebServer_DMZ", "layer": "dmz",          "asset_type": "web_server", "is_real": True,  "value": 0.2},
            {"id": 2, "label": "Workstation",   "layer": "internal",     "asset_type": "workstation","is_real": True,  "value": 0.4},
            {"id": 3, "label": "ServiceCred",   "layer": "credentials",  "asset_type": "credential", "is_real": True,  "value": 0.6},
            {"id": 4, "label": "Database_REAL", "layer": "data",         "asset_type": "database",   "is_real": True,  "value": 1.0, "goal": True},
            {"id": 5, "label": "Database_FAKE", "layer": "data",         "asset_type": "decoy_db",   "is_real": False, "value": 0.0, "decoy": True},
        ],
        "edges": [
            {"src": 0, "dst": 1, "action": "exploit_web",  "prob": 0.80},
            {"src": 1, "dst": 2, "action": "smb_move",     "prob": 0.65},
            {"src": 2, "dst": 3, "action": "cred_dump",    "prob": 0.70},
            {"src": 3, "dst": 4, "action": "db_access",    "prob": 0.55},
            {"src": 3, "dst": 5, "action": "db_access",    "prob": 0.45},
        ],
        "config": {"budget": 4.0, "discount": 0.95, "decoy_realism": 0.85},
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8") as tmp:
        json.dump(demo_json, tmp)
        tmp_path = tmp.name

    graph = load_attack_graph(tmp_path, fmt="mirage")
    print(f"Loaded graph: {len(graph.states)} nodes, goals={graph.true_goals}, decoys={graph.decoy_sites}")
    print("Node labels:")
    for s in graph.states:
        print(f"  Node {s:2d}: {graph.label(s)}")

    out_path = tmp_path.replace(".json", "_out.json")
    save_graph_to_json(graph, out_path)
    os.unlink(tmp_path)
    os.unlink(out_path)
