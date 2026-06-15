"""
MIRAGE - Layer 3: Deception Fabric
====================================
Lớp tạo ra "môi trường giả có kiểm soát" cho attacker.

Defender Actions (4 loại):
  1. deploy_decoy_database    — Đặt Fake Database tại node chỉ định
  2. deploy_decoy_router      — Đặt Router giả, tăng cost di chuyển
  3. scatter_honey_credential — Rải tài khoản/credential giả
  4. increase_edge_cost       — Tăng chi phí di chuyển trên edge cụ thể

Mỗi action có:
  - risk_score: 0-1 (rủi ro vận hành)
  - realism_score: 0-1 (mức độ giống thật)
  - business_impact: 0-1 (ảnh hưởng đến hệ thống thật)
  - cost: Chi phí ngân sách (dùng trong budget constraint)

Lifecycle decoy:
  Template → Instantiate → Expose → Engage → Retire → Learning
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple
import copy
import math
import time
import uuid

from mirage.config import load_config

_CONFIG = load_config()
_DECEPTION_CONFIG = _CONFIG.get("layer3", {}).get("deception_actions", {})


class DeceptionActionType(Enum):
    """Các loại hành động deception."""
    DEPLOY_DECOY_DATABASE    = "deploy_decoy_database"
    DEPLOY_DECOY_ROUTER      = "deploy_decoy_router"
    SCATTER_HONEY_CREDENTIAL = "scatter_honey_credential"
    INCREASE_EDGE_COST       = "increase_edge_cost"


class DecoyStatus(Enum):
    """Trạng thái lifecycle của một decoy."""
    TEMPLATE     = "template"
    INSTANTIATED = "instantiated"
    EXPOSED      = "exposed"
    ENGAGED      = "engaged"    # Attacker đã chạm vào
    RETIRED      = "retired"
    LEARNED      = "learned"


@dataclass
class DeceptionAction:
    """
    Định nghĩa một hành động deception cụ thể.
    Đây là "vocabulary" của AI Defender.
    """
    action_type: DeceptionActionType
    target_node: int                    # Node được đặt decoy
    target_edge: Optional[Tuple[int, int]] = None  # Edge bị tăng cost (cho increase_edge_cost)

    # Thuộc tính kỹ thuật
    risk_score: float        = 0.0      # 0=không rủi ro, 1=rất rủi ro
    realism_score: float     = 0.8      # 0=dễ phát hiện, 1=rất giống thật
    business_impact: float   = 0.0      # 0=không ảnh hưởng, 1=ảnh hưởng lớn
    cost: float              = 1.0      # Chi phí ngân sách
    affected_services: int   = 0
    affected_users: int      = 0
    duration_hours: float    = 1.0
    rollback_complexity: Optional[float] = None
    false_positive_likelihood: Optional[float] = None

    # Metadata
    description: str         = ""
    rollback_plan: str       = "Remove deployed asset"

    # Kết quả kỳ vọng (dùng để tính reward intervention)
    reward_delta: float      = 0.0      # Delta reward gán cho (target_node, "end")
    edge_cost_delta: float   = 0.0      # Tăng bao nhiêu cost cho edge

    def __post_init__(self) -> None:
        self.target_node = int(self.target_node)
        if self.target_edge is not None:
            self.target_edge = (
                int(self.target_edge[0]),
                int(self.target_edge[1]),
            )
        for name in ("risk_score", "realism_score", "business_impact"):
            value = float(getattr(self, name))
            if not math.isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be between 0 and 1")
            setattr(self, name, value)
        for name in (
            "cost",
            "duration_hours",
            "reward_delta",
            "edge_cost_delta",
        ):
            value = float(getattr(self, name))
            if not math.isfinite(value) or value < 0:
                raise ValueError(f"{name} must be finite and non-negative")
            setattr(self, name, value)

    @property
    def action_id(self) -> str:
        if self.target_edge:
            src, dst = self.target_edge
            return f"{self.action_type.value}@edge{src}->{dst}"
        return f"{self.action_type.value}@node{self.target_node}"

    def __repr__(self) -> str:
        return (
            f"DeceptionAction({self.action_type.value}, "
            f"node={self.target_node}, risk={self.risk_score:.1f}, "
            f"realism={self.realism_score:.1f}, cost={self.cost:.1f})"
        )


@dataclass
class ActiveDecoy:
    """Một decoy đang được triển khai trên mạng."""
    decoy_id: str
    action: DeceptionAction
    status: DecoyStatus
    deployed_at: float
    engagement_count: int = 0
    last_engaged: Optional[float] = None
    attacker_ips: List[str] = field(default_factory=list)
    intelligence_gathered: List[str] = field(default_factory=list)

    def engage(self, attacker_info: str = "") -> None:
        """Ghi nhận attacker tương tác với decoy."""
        self.engagement_count += 1
        self.last_engaged = time.time()
        self.status = DecoyStatus.ENGAGED
        if attacker_info:
            self.intelligence_gathered.append(attacker_info)

    def should_retire(self, max_engagements: int = 5, max_age_seconds: float = 3600) -> bool:
        """Kiểm tra xem decoy có cần được thay thế không."""
        if max_engagements < 1:
            raise ValueError("max_engagements must be at least 1")
        if max_age_seconds < 0:
            raise ValueError("max_age_seconds cannot be negative")
        age = time.time() - self.deployed_at
        return (self.engagement_count >= max_engagements) or (age > max_age_seconds)


# ============================================================
# DECEPTION ACTION CATALOG
# ============================================================

def _operational_fields(graph, node: int, action_type: DeceptionActionType) -> Dict:
    """Build practical cost metadata for an action target."""
    meta = getattr(graph, "node_metadata", {}).get(node, {}) or {}
    asset_type = meta.get("asset_type", "")
    value = float(meta.get("value", 0.0) or 0.0)
    criticality = float(meta.get("business_criticality", value) or 0.0)

    default_services = {
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
    }
    default_users = {
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
    }

    services = int(meta.get("service_count", default_services.get(asset_type, 1)))
    users = int(meta.get("user_count", default_users.get(asset_type, 10)))

    if action_type == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
        duration = 4.0
        rollback = 0.15
        fp = 0.20
    elif action_type == DeceptionActionType.INCREASE_EDGE_COST:
        duration = 0.5
        rollback = 0.35
        fp = 0.12
    elif action_type == DeceptionActionType.DEPLOY_DECOY_ROUTER:
        duration = 8.0
        rollback = 0.45
        fp = 0.16
    else:
        duration = 8.0
        rollback = 0.25
        fp = 0.06

    return {
        "affected_services": services,
        "affected_users": users,
        "duration_hours": duration,
        "rollback_complexity": rollback,
        "false_positive_likelihood": fp,
        "business_impact": min(1.0, max(0.0, 0.05 + 0.20 * criticality)),
    }


def _top_nodes(graph, predicate, limit: int) -> List[int]:
    """Return top nodes by business value/criticality that match predicate."""
    candidates = []
    for node in graph.states:
        if node == graph.sink_state or node in graph.true_goals:
            continue
        meta = getattr(graph, "node_metadata", {}).get(node, {}) or {}
        if predicate(node, meta):
            value = float(meta.get("value", 0.0) or 0.0)
            criticality = float(meta.get("business_criticality", value) or 0.0)
            candidates.append((max(value, criticality), node))
    candidates.sort(reverse=True)
    return [node for _, node in candidates[:limit]]


def _build_generic_action_catalog(
    graph,
    max_actions_per_type: int = 40,
) -> List[DeceptionAction]:
    """
    Build a bounded action catalog for large/static or synthetic graphs.

    The 15-node demo uses the hand-tuned catalog below. Larger graphs need a
    metadata/topology driven catalog; otherwise action space grows with every
    node and edge.
    """
    actions: List[DeceptionAction] = []
    decoys = [d for d in graph.decoy_sites if d in graph.states and d != graph.sink_state]
    decoy_db_slots = [
        node for node in decoys
        if graph.node_metadata.get(node, {}).get("asset_type") == "decoy_db"
    ]
    decoy_router_slots = [
        node for node in decoys
        if graph.node_metadata.get(node, {}).get("asset_type") == "decoy_router"
    ]

    db_nodes = decoy_db_slots[:max_actions_per_type]
    cfg_db = _DECEPTION_CONFIG.get("deploy_decoy_database", {})
    for node in db_nodes:
        fields = _operational_fields(graph, node, DeceptionActionType.DEPLOY_DECOY_DATABASE)
        fields["business_impact"] = cfg_db.get(
            "business_impact",
            fields["business_impact"],
        )
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
            target_node=node,
            risk_score=cfg_db.get(
                "risk_score",
                min(0.45, 0.08 + fields["business_impact"] * 0.45),
            ),
            realism_score=cfg_db.get("realism_score", 0.82),
            cost=cfg_db.get("cost", 1.5),
            description=f"Deploy synthetic database lure near Node {node} ({graph.label(node)}).",
            rollback_plan="Stop decoy database workload and remove route/DNS exposure",
            reward_delta=cfg_db.get("reward_delta", 0.85),
            **fields,
        ))

    router_nodes = decoy_router_slots[:max_actions_per_type]
    cfg_router = _DECEPTION_CONFIG.get("deploy_decoy_router", {})
    for node in router_nodes:
        fields = _operational_fields(graph, node, DeceptionActionType.DEPLOY_DECOY_ROUTER)
        fields["business_impact"] = cfg_router.get(
            "business_impact",
            fields["business_impact"],
        )
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.DEPLOY_DECOY_ROUTER,
            target_node=node,
            risk_score=cfg_router.get(
                "risk_score",
                min(0.55, 0.12 + fields["business_impact"] * 0.50),
            ),
            realism_score=cfg_router.get("realism_score", 0.76),
            cost=cfg_router.get("cost", 1.2),
            description=f"Deploy fake routing/service waypoint near Node {node} ({graph.label(node)}).",
            rollback_plan="Remove virtual route, DNS advertisement, and monitoring hooks",
            reward_delta=cfg_router.get("reward_delta", 0.70),
            edge_cost_delta=cfg_router.get("edge_cost_delta", 0.30),
            **fields,
        ))

    cred_nodes = _top_nodes(
        graph,
        lambda _n, m: m.get("asset_type") in {"credential", "workstation", "file_share"},
        max_actions_per_type,
    )
    cfg_cred = _DECEPTION_CONFIG.get("scatter_honey_credential", {})
    for node in cred_nodes:
        fields = _operational_fields(graph, node, DeceptionActionType.SCATTER_HONEY_CREDENTIAL)
        fields["business_impact"] = cfg_cred.get(
            "business_impact",
            fields["business_impact"],
        )
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.SCATTER_HONEY_CREDENTIAL,
            target_node=node,
            risk_score=cfg_cred.get(
                "risk_score",
                min(0.35, 0.05 + fields["business_impact"] * 0.35),
            ),
            realism_score=cfg_cred.get("realism_score", 0.90),
            cost=cfg_cred.get("cost", 0.8),
            description=f"Plant honey credential material at Node {node} ({graph.label(node)}).",
            rollback_plan="Disable honey identity and remove seeded credential material",
            reward_delta=cfg_cred.get("reward_delta", 0.50),
            **fields,
        ))

    edge_candidates = []
    true_goals = set(graph.true_goals)
    for src in graph.states:
        if src == graph.sink_state:
            continue
        src_meta = getattr(graph, "node_metadata", {}).get(src, {}) or {}
        src_value = float(src_meta.get("value", 0.0) or 0.0)
        for act in graph.available_actions.get(src, []):
            for dst, prob in graph.transitions.get(src, {}).get(act, {}).items():
                if dst == graph.sink_state or dst in graph.decoy_sites or dst == src:
                    continue
                dst_meta = getattr(graph, "node_metadata", {}).get(dst, {}) or {}
                dst_value = float(dst_meta.get("value", 0.0) or 0.0)
                dst_crit = float(dst_meta.get("business_criticality", dst_value) or 0.0)
                score = prob + 0.7 * dst_value + 0.5 * dst_crit + 0.2 * src_value
                if dst in true_goals:
                    score += 1.0
                edge_candidates.append((score, src, dst))
    edge_candidates.sort(reverse=True)

    seen_edges = set()
    cfg_edge = _DECEPTION_CONFIG.get("increase_edge_cost", {})
    for _score, src, dst in edge_candidates:
        if len(seen_edges) >= max_actions_per_type:
            break
        if (src, dst) in seen_edges:
            continue
        seen_edges.add((src, dst))
        fields = _operational_fields(graph, dst, DeceptionActionType.INCREASE_EDGE_COST)
        fields["business_impact"] = cfg_edge.get(
            "business_impact",
            fields["business_impact"],
        )
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.INCREASE_EDGE_COST,
            target_node=dst,
            target_edge=(src, dst),
            risk_score=cfg_edge.get(
                "risk_score",
                min(0.45, 0.04 + fields["business_impact"] * 0.45),
            ),
            realism_score=cfg_edge.get("realism_score", 1.0),
            cost=cfg_edge.get("cost", 0.5),
            description=f"Throttle high-risk movement edge {graph.label(src)} -> {graph.label(dst)}.",
            rollback_plan="Remove throttle/MFA/firewall rule for this edge",
            reward_delta=cfg_edge.get("reward_delta", 0.0),
            edge_cost_delta=cfg_edge.get("edge_cost_delta", 0.5),
            **fields,
        ))

    return actions


def get_action_catalog(graph, max_actions_per_type: int = 40) -> List[DeceptionAction]:
    """
    Trả về danh sách đầy đủ các hành động deception khả dụng.
    Tương thích với đồ thị tấn công doanh nghiệp 15 node.
    """
    is_builtin = (
        len(graph.states) == 15
        and graph.label(10) == "DB_REAL_Finance"
        and graph.label(14) == "Sink"
    )
    if not is_builtin:
        return _build_generic_action_catalog(graph, max_actions_per_type=max_actions_per_type)

    from mirage.layer2_attack_graph import (
        DB_FAKE, RTR_FAKE, WS_FIN, WS_ENG, WS_IT,
        SMB_SHARE, SVC_CRED, ADMIN_CRED, DC_NODE, DB_REAL
    )
    actions = []

    # ---- 1. DEPLOY DECOY DATABASE ----
    cfg_db = _DECEPTION_CONFIG.get("deploy_decoy_database", {})
    decoy_db_nodes = [DB_FAKE]
    for node in decoy_db_nodes:
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
            target_node=node,
            risk_score=cfg_db.get("risk_score", 0.1),
            realism_score=cfg_db.get("realism_score", 0.85),
            business_impact=cfg_db.get("business_impact", 0.05),
            cost=cfg_db.get("cost", 1.5),
            description=(
                f"Deploy Fake Database at Node {node} ({graph.label(node)}). "
                "Contains synthetic financial records with watermarks. "
                "Triggers alert on any SQL query."
            ),
            rollback_plan="Shut down decoy DB container",
            reward_delta=cfg_db.get("reward_delta", 0.9),
        ))

    # ---- 2. DEPLOY DECOY ROUTER ----
    cfg_rtr = _DECEPTION_CONFIG.get("deploy_decoy_router", {})
    decoy_router_nodes = [RTR_FAKE]
    for node in decoy_router_nodes:
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.DEPLOY_DECOY_ROUTER,
            target_node=node,
            risk_score=cfg_rtr.get("risk_score", 0.15),
            realism_score=cfg_rtr.get("realism_score", 0.75),
            business_impact=cfg_rtr.get("business_impact", 0.08),
            cost=cfg_rtr.get("cost", 1.2),
            description=(
                f"Deploy Fake Router/Gateway at Node {node} ({graph.label(node)}). "
                "Presents realistic routing table and SNMP banners. "
                "Redirects traffic to honeynet."
            ),
            rollback_plan="Disable virtual router interface",
            reward_delta=cfg_rtr.get("reward_delta", 0.7),
            edge_cost_delta=cfg_rtr.get("edge_cost_delta", 0.3),
        ))

    # ---- 3. SCATTER HONEY CREDENTIAL ----
    cfg_cred = _DECEPTION_CONFIG.get("scatter_honey_credential", {})
    honey_cred_nodes = [WS_FIN, WS_ENG, WS_IT, SMB_SHARE, ADMIN_CRED, SVC_CRED]
    for node in honey_cred_nodes:
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.SCATTER_HONEY_CREDENTIAL,
            target_node=node,
            risk_score=cfg_cred.get("risk_score", 0.05),
            realism_score=cfg_cred.get("realism_score", 0.90),
            business_impact=cfg_cred.get("business_impact", 0.02),
            cost=cfg_cred.get("cost", 0.8),
            description=(
                f"Plant Honey Credential at Node {node} ({graph.label(node)}). "
                "Fake admin account 'svc_backup_2023' with convincing password hash. "
                "Triggers alert if credential is used anywhere."
            ),
            rollback_plan="Deactivate honey account in IAM",
            reward_delta=cfg_cred.get("reward_delta", 0.5),
        ))

    # ---- 4. INCREASE EDGE COST ----
    cfg_edge = _DECEPTION_CONFIG.get("increase_edge_cost", {})
    critical_edges = [
        (WS_FIN,    SVC_CRED),
        (SVC_CRED,  DB_REAL),
        (WS_ENG,    ADMIN_CRED),
        (ADMIN_CRED, DC_NODE),
        (DC_NODE,   DB_REAL),
        (SMB_SHARE, SVC_CRED),
    ]
    for src, dst in critical_edges:
        actions.append(DeceptionAction(
            action_type=DeceptionActionType.INCREASE_EDGE_COST,
            target_node=dst,
            target_edge=(src, dst),
            risk_score=cfg_edge.get("risk_score", 0.05),
            realism_score=cfg_edge.get("realism_score", 1.0),
            business_impact=cfg_edge.get("business_impact", 0.03),
            cost=cfg_edge.get("cost", 0.5),
            description=(
                f"Increase movement cost on critical real path: "
                f"{graph.label(src)} → {graph.label(dst)}. "
                "Configure firewall/SDN/MFA to throttle this high-risk lateral path. "
                "Reduces transition probability; redistributes toward decoys or sink."
            ),
            rollback_plan="Remove throttle rule from firewall/SDN",
            reward_delta=cfg_edge.get("reward_delta", 0.0),
            edge_cost_delta=cfg_edge.get("edge_cost_delta", 0.5),
        ))

    return actions


# ============================================================
# DECEPTION FABRIC MANAGER
# ============================================================

class DeceptionFabric:
    """
    Lớp 3: Quản lý toàn bộ hệ sinh thái deception.
    
    Nhận action từ Decision Engine (Lớp 4) và:
    1. Triển khai decoy trên đồ thị
    2. Cập nhật reward interventions
    3. Theo dõi engagement
    4. Thu thập intelligence
    """

    def __init__(
        self,
        graph,
        max_actions_per_type: Optional[int] = None,
        verbose: bool = True,
    ):
        if max_actions_per_type is None:
            max_actions_per_type = int(
                _CONFIG.get("layer3", {}).get("max_actions_per_type", 40)
            )
        self.graph = graph
        self.verbose = verbose
        self._base_graph = copy.deepcopy(graph)
        self.active_decoys: Dict[str, ActiveDecoy] = {}
        self.deployed_actions: List[DeceptionAction] = []
        self.action_catalog = get_action_catalog(graph, max_actions_per_type=max_actions_per_type)
        self.engagement_log: List[Dict] = []
        self.total_cost_spent: float = 0.0

        # Mapping: (node, action) → reward delta (dành cho Robust RL)
        self.reward_interventions: Dict[Tuple[int, str], float] = {}

    def generate_action_catalog(self) -> List[DeceptionAction]:
        """Return a copy of the configured action catalog."""
        return list(self.action_catalog)

    def get_available_actions(self, budget_remaining: float) -> List[DeceptionAction]:
        """Lọc các action khả dụng theo ngân sách."""
        from mirage.mdp_solver import compute_composite_cost
        deployed_ids = {action.action_id for action in self.deployed_actions}
        return [
            a for a in self.action_catalog
            if (
                a.action_id not in deployed_ids
                and compute_composite_cost(a, self.graph).total <= budget_remaining
            )
        ]

    def deploy_action(self, action: DeceptionAction) -> ActiveDecoy:
        """
        Triển khai một hành động deception.
        
        Returns:
            ActiveDecoy object đang được triển khai
        """
        if action.target_node not in self.graph.states:
            raise ValueError(
                f"Action target {action.target_node} is not in the graph"
            )
        if action.target_edge is not None:
            src, dst = action.target_edge
            if src not in self.graph.states or dst not in self.graph.states:
                raise ValueError(
                    f"Action edge {src}->{dst} references an unknown node"
                )
            if not any(
                dst in distribution
                for distribution in self.graph.transitions.get(src, {}).values()
            ):
                raise ValueError(
                    f"Action edge {src}->{dst} does not exist in the graph"
                )
        if any(
            deployed.action_id == action.action_id
            for deployed in self.deployed_actions
        ):
            raise ValueError(f"Action already deployed: {action.action_id}")
        if action.action_type in {
            DeceptionActionType.DEPLOY_DECOY_DATABASE,
            DeceptionActionType.DEPLOY_DECOY_ROUTER,
        } and action.target_node not in self.graph.decoy_sites:
            raise ValueError(
                f"Deploy target {action.target_node} is not a decoy slot"
            )
        if action.action_type in {
            DeceptionActionType.DEPLOY_DECOY_DATABASE,
            DeceptionActionType.DEPLOY_DECOY_ROUTER,
        }:
            expected_asset_type = {
                DeceptionActionType.DEPLOY_DECOY_DATABASE: "decoy_db",
                DeceptionActionType.DEPLOY_DECOY_ROUTER: "decoy_router",
            }[action.action_type]
            actual_asset_type = str(
                self.graph.node_metadata.get(action.target_node, {}).get(
                    "asset_type",
                    "",
                )
            )
            if (
                actual_asset_type in {"decoy_db", "decoy_router"}
                and actual_asset_type != expected_asset_type
            ):
                raise ValueError(
                    f"{action.action_type.value} cannot target asset type "
                    f"{actual_asset_type!r}"
                )

        decoy_id = str(uuid.uuid4())[:8]
        from mirage.mdp_solver import compute_composite_cost

        deployment_cost = compute_composite_cost(action, self.graph).total
        if self.total_cost_spent + deployment_cost > self.graph.budget + 1e-9:
            raise ValueError(
                "Deployment would exceed the deception fabric budget"
            )

        # Cập nhật đồ thị tùy theo loại action
        if action.action_type == DeceptionActionType.DEPLOY_DECOY_DATABASE:
            self._deploy_decoy_database(action)

        elif action.action_type == DeceptionActionType.DEPLOY_DECOY_ROUTER:
            self._deploy_decoy_router(action)

        elif action.action_type == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
            self._scatter_honey_credential(action)

        elif action.action_type == DeceptionActionType.INCREASE_EDGE_COST:
            self._increase_edge_cost(action)

        # Tạo ActiveDecoy record
        self.deployed_actions.append(action)
        try:
            self._refresh_runtime_graph()
        except Exception:
            self.deployed_actions.pop()
            self._refresh_runtime_graph()
            raise

        decoy = ActiveDecoy(
            decoy_id=decoy_id,
            action=action,
            status=DecoyStatus.EXPOSED,
            deployed_at=time.time(),
        )
        self.active_decoys[decoy_id] = decoy
        self.total_cost_spent += deployment_cost

        return decoy

    def _refresh_runtime_graph(self) -> None:
        """Rebuild deployment effects from the immutable topology baseline."""
        from mirage.layer2_attack_graph import build_runtime_graph

        runtime = build_runtime_graph(
            self._base_graph,
            actions=self.deployed_actions,
        )
        self.graph.transitions = runtime.transitions
        self.graph.active_decoy_sites = runtime.active_decoy_sites
        self.graph.edge_costs = runtime.edge_costs
        self.graph.node_metadata = runtime.node_metadata
        self.graph.defender_reward = runtime.defender_reward
        self._refresh_reward_interventions()

    def _refresh_reward_interventions(self) -> None:
        """Rebuild reward effects so overlapping actions compose safely."""
        interventions: Dict[Tuple[int, str], float] = {}
        for action in self.deployed_actions:
            if action.action_type in {
                DeceptionActionType.DEPLOY_DECOY_DATABASE,
                DeceptionActionType.DEPLOY_DECOY_ROUTER,
            }:
                key = (action.target_node, "end")
                interventions[key] = (
                    interventions.get(key, 0.0) + action.reward_delta
                )
            elif (
                action.action_type
                == DeceptionActionType.SCATTER_HONEY_CREDENTIAL
            ):
                cred_key = (action.target_node, "cred_dump")
                end_key = (action.target_node, "end")
                interventions[cred_key] = (
                    interventions.get(cred_key, 0.0)
                    + action.reward_delta * 0.5
                )
                interventions[end_key] = (
                    interventions.get(end_key, 0.0)
                    + action.reward_delta * 0.3
                )
        self.reward_interventions = interventions

    def _deploy_decoy_database(self, action: DeceptionAction) -> None:
        """Triển khai fake database — tăng reward kéo attacker vào đây."""
        node = action.target_node
        if self.verbose:
            print(f"  [Deception] Fake Database deployed at Node {node} "
                  f"({self.graph.label(node)}) | Reward bait: +{action.reward_delta:.1f}")

    def _deploy_decoy_router(self, action: DeceptionAction) -> None:
        """Triển khai fake router — vừa thu hút vừa làm chậm attacker."""
        node = action.target_node
        if self.verbose:
            print(f"  [Deception] Fake Router deployed at Node {node} "
                  f"({self.graph.label(node)}) | Edge cost +{action.edge_cost_delta:.1f}")

    def _scatter_honey_credential(self, action: DeceptionAction) -> None:
        """Rải honey credential — tăng khả năng attacker bị phát hiện khi dùng."""
        node = action.target_node
        if self.verbose:
            print(f"  [Honey] Honey Credential planted at Node {node} "
                  f"({self.graph.label(node)}) | Trigger reward: +{action.reward_delta:.1f}")

    def _increase_edge_cost(self, action: DeceptionAction) -> None:
        """Tăng cost edge — làm khó attacker trên con đường cụ thể."""
        if action.target_edge:
            src, dst = action.target_edge
            if self.verbose:
                print(f"  [Edge Cost] Edge cost increased: Node {src} -> Node {dst} "
                      f"| Delta: +{action.edge_cost_delta:.2f}")

    def record_engagement(self, decoy_id: str, attacker_info: str = "") -> Dict:
        """Ghi nhận sự kiện attacker chạm vào decoy."""
        if decoy_id not in self.active_decoys:
            return {}

        decoy = self.active_decoys[decoy_id]
        decoy.engage(attacker_info)
        if attacker_info and attacker_info not in decoy.attacker_ips:
            decoy.attacker_ips.append(attacker_info)

        log_entry = {
            "timestamp": time.time(),
            "decoy_id": decoy_id,
            "node": decoy.action.target_node,
            "node_label": self.graph.label(decoy.action.target_node),
            "action_type": decoy.action.action_type.value,
            "attacker_info": attacker_info,
            "engagement_count": decoy.engagement_count,
            "intelligence": decoy.intelligence_gathered[-1] if decoy.intelligence_gathered else "",
        }
        self.engagement_log.append(log_entry)
        return log_entry

    def retire_expired_decoys(self) -> List[str]:
        """Thu hồi các decoy đã hết hạn."""
        retired = []
        retired_actions = []
        for did, decoy in list(self.active_decoys.items()):
            if decoy.should_retire():
                decoy.status = DecoyStatus.RETIRED
                action = decoy.action
                retired_actions.append(action)
                self.active_decoys.pop(did, None)
                retired.append(did)
        if retired_actions:
            retired_ids = {id(action) for action in retired_actions}
            self.deployed_actions = [
                action
                for action in self.deployed_actions
                if id(action) not in retired_ids
            ]
            self._refresh_runtime_graph()
        return retired

    def get_interception_rate(self, total_attacks: Optional[int] = None) -> float:
        """Return decoy engagements divided by an explicit attack-session count."""
        engagements = len(self.engagement_log)
        if total_attacks is None:
            raise ValueError(
                "total_attacks is required; engagements alone cannot define "
                "an interception rate"
            )
        if total_attacks < 0:
            raise ValueError("total_attacks cannot be negative")
        if engagements > total_attacks:
            raise ValueError(
                "total_attacks cannot be smaller than recorded engagements"
            )
        if total_attacks == 0:
            return 0.0
        return engagements / total_attacks

    def summary(self) -> str:
        """In tóm tắt trạng thái Deception Fabric."""
        deploy_types = {
            DeceptionActionType.DEPLOY_DECOY_DATABASE,
            DeceptionActionType.DEPLOY_DECOY_ROUTER,
        }
        active_assets = sum(
            1
            for deployment in self.active_decoys.values()
            if deployment.action.action_type in deploy_types
        )
        lines = [
            "=" * 60,
            "MIRAGE Layer 3 — Deception Fabric Status",
            "=" * 60,
            f"Active Actions:   {len(self.active_decoys)}",
            f"Active Decoys:    {active_assets}",
            f"Total Cost Spent: {self.total_cost_spent:.1f}",
            f"Total Engagements:{len(self.engagement_log)}",
            "",
            "Active Deployments:",
        ]
        for did, decoy in self.active_decoys.items():
            lines.append(
                f"  [{did}] {decoy.action.action_type.value:30s} "
                f"-> Node {decoy.action.target_node} ({self.graph.label(decoy.action.target_node)}) "
                f"| Status: {decoy.status.value} | Engaged: {decoy.engagement_count}x"
            )
        lines.append("")
        lines.append("Reward Interventions:")
        for (node, act), delta in self.reward_interventions.items():
            lines.append(f"  Node {node} ({self.graph.label(node)}) | action={act} -> delta={delta:.2f}")
        return "\n".join(lines)


if __name__ == "__main__":
    from mirage.layer2_attack_graph import build_enterprise_attack_graph

    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)

    print("Available Deception Actions:")
    print("-" * 60)
    catalog = fabric.get_available_actions(budget_remaining=5.0)
    for i, act in enumerate(catalog[:6]):
        print(f"  [{i+1}] {act}")

    print("\nDeploying demo actions...")
    # Demo: deploy fake DB
    db_action = next(a for a in catalog if a.action_type == DeceptionActionType.DEPLOY_DECOY_DATABASE)
    fabric.deploy_action(db_action)

    # Demo: deploy honey credential
    honey_action = next(a for a in catalog if a.action_type == DeceptionActionType.SCATTER_HONEY_CREDENTIAL)
    fabric.deploy_action(honey_action)

    # Demo: increase edge cost
    cost_action = next(a for a in catalog if a.action_type == DeceptionActionType.INCREASE_EDGE_COST)
    fabric.deploy_action(cost_action)

    print()
    print(fabric.summary())
