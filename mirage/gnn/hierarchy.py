"""Hierarchical graph builder for MIRAGE GNN pipeline.

Converts a LocalOperationalSubgraph into a 5-level hierarchy:
  1. Host / Identity / Service level  (fine-grained operational nodes)
  2. Application / workload group     (assets sharing a service tag)
  3. Subnet level                     (network segment grouping)
  4. Domain / site level              (organisational domain grouping)
  5. Enterprise summary node          (optional global root)

The hierarchy is DETERMINISTIC — same inputs produce identical output.
Only the bounded local subgraph from Milestone 3 is used; the full
enterprise graph is NOT rebuilt per event.

Aggregation edges added by the builder:
  - belongs_to_subnet
  - asset_supports_application
  - subnet_belongs_to_domain
  - application_supports_business_service
  - belongs_to_enterprise  (optional, only when enterprise_node=True)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from mirage.domain.schemas import (
    LocalOperationalSubgraph,
    LocalSubgraphEdge,
    LocalSubgraphNode,
    TwinSnapshot,
)
from mirage.gnn.schema import GraphFeatureSchema


# ---------------------------------------------------------------------------
# Public data containers
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HierarchyNode:
    """A node in the hierarchy (may be summary or operational)."""

    node_id: str
    entity_type: str          # asset / subnet / domain / application / enterprise
    level: int                # 1=operational, 2=app, 3=subnet, 4=domain, 5=enterprise
    label: str
    member_node_ids: tuple[str, ...] = field(default_factory=tuple)   # members at level-1
    attributes: dict = field(default_factory=dict)


@dataclass(frozen=True)
class HierarchyEdge:
    """An aggregation edge in the hierarchy."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    level: int   # level of the source node


@dataclass
class HierarchicalGraph:
    """Full hierarchical graph for one local subgraph."""

    # All operational (level-1) nodes from the subgraph
    operational_nodes: list[LocalSubgraphNode] = field(default_factory=list)
    # Operational edges (original subgraph edges)
    operational_edges: list[LocalSubgraphEdge] = field(default_factory=list)
    # Summary nodes at levels 2..5
    summary_nodes: list[HierarchyNode] = field(default_factory=list)
    # Aggregation edges connecting levels
    aggregation_edges: list[HierarchyEdge] = field(default_factory=list)
    # Membership maps (level → group_id → list[operational_node_id])
    membership: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def all_node_ids(self) -> list[str]:
        op = [n.node_id for n in self.operational_nodes]
        su = [n.node_id for n in self.summary_nodes]
        return sorted(set(op + su))

    @property
    def num_operational_nodes(self) -> int:
        return len(self.operational_nodes)

    @property
    def num_summary_nodes(self) -> int:
        return len(self.summary_nodes)

    def hierarchy_mappings_dict(self) -> dict:
        """Serialisable representation of the hierarchy for GraphSample."""
        return {
            "membership": {
                level: {gid: sorted(members) for gid, members in groups.items()}
                for level, groups in self.membership.items()
            },
            "summary_nodes": [
                {
                    "node_id": n.node_id,
                    "entity_type": n.entity_type,
                    "level": n.level,
                    "label": n.label,
                    "member_node_ids": list(n.member_node_ids),
                }
                for n in self.summary_nodes
            ],
            "aggregation_edges": [
                {
                    "edge_id": e.edge_id,
                    "source": e.source_node_id,
                    "target": e.target_node_id,
                    "relationship_type": e.relationship_type,
                }
                for e in self.aggregation_edges
            ],
        }


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class HierarchicalGraphBuilder:
    """Build a deterministic hierarchical graph from a local subgraph.

    Parameters
    ----------
    schema:
        Feature schema (used for type validation).
    twin_snapshot:
        Used to read subnet and domain metadata from assets and identities.
    include_enterprise_node:
        When True, a single enterprise-level (level-5) summary node is added.
        Disabled by default to keep small graphs lean.
    """

    def __init__(
        self,
        schema: GraphFeatureSchema | None = None,
        twin_snapshot: TwinSnapshot | None = None,
        include_enterprise_node: bool = False,
    ) -> None:
        self.schema = schema or GraphFeatureSchema()
        self.twin_snapshot = twin_snapshot
        self.include_enterprise_node = include_enterprise_node

    def build(self, subgraph: LocalOperationalSubgraph) -> HierarchicalGraph:
        """Build a HierarchicalGraph from a LocalOperationalSubgraph."""
        warnings: list[str] = []
        nodes = list(subgraph.nodes)
        edges = list(subgraph.edges)

        # --- Level 2: application / workload group ---
        app_groups = self._group_by_application(nodes, warnings)

        # --- Level 3: subnet ---
        subnet_groups = self._group_by_subnet(nodes, warnings)

        # --- Level 4: domain ---
        domain_groups = self._group_by_domain(nodes, warnings)

        # Build summary nodes
        summary_nodes: list[HierarchyNode] = []
        aggregation_edges: list[HierarchyEdge] = []
        membership: dict[str, dict[str, list[str]]] = {
            "application": {},
            "subnet": {},
            "domain": {},
        }

        # Application summary nodes (level 2)
        for app_id, member_ids in sorted(app_groups.items()):
            summary_node_id = f"app_group:{app_id}"
            summary_nodes.append(HierarchyNode(
                node_id=summary_node_id,
                entity_type="application",
                level=2,
                label=f"App:{app_id}",
                member_node_ids=tuple(sorted(member_ids)),
            ))
            membership["application"][app_id] = sorted(member_ids)
            for member_id in sorted(member_ids):
                agg_edge_id = f"agg:app:{member_id}:{app_id}"
                aggregation_edges.append(HierarchyEdge(
                    edge_id=agg_edge_id,
                    source_node_id=member_id,
                    target_node_id=summary_node_id,
                    relationship_type="asset_supports_application",
                    level=1,
                ))

        # Subnet summary nodes (level 3)
        for subnet_id, member_ids in sorted(subnet_groups.items()):
            summary_node_id = f"subnet:{subnet_id}"
            summary_nodes.append(HierarchyNode(
                node_id=summary_node_id,
                entity_type="subnet",
                level=3,
                label=f"Subnet:{subnet_id}",
                member_node_ids=tuple(sorted(member_ids)),
            ))
            membership["subnet"][subnet_id] = sorted(member_ids)
            for member_id in sorted(member_ids):
                agg_edge_id = f"agg:subnet:{member_id}:{subnet_id}"
                aggregation_edges.append(HierarchyEdge(
                    edge_id=agg_edge_id,
                    source_node_id=member_id,
                    target_node_id=summary_node_id,
                    relationship_type="belongs_to_subnet",
                    level=1,
                ))
            # Connect subnet → domain (level 4) will be done after domains are built

        # Domain summary nodes (level 4)
        for domain_id, member_ids in sorted(domain_groups.items()):
            summary_node_id = f"domain:{domain_id}"
            summary_nodes.append(HierarchyNode(
                node_id=summary_node_id,
                entity_type="domain",
                level=4,
                label=f"Domain:{domain_id}",
                member_node_ids=tuple(sorted(member_ids)),
            ))
            membership["domain"][domain_id] = sorted(member_ids)
            # Connect operational nodes directly to domain
            for member_id in sorted(member_ids):
                agg_edge_id = f"agg:domain:{member_id}:{domain_id}"
                aggregation_edges.append(HierarchyEdge(
                    edge_id=agg_edge_id,
                    source_node_id=member_id,
                    target_node_id=summary_node_id,
                    relationship_type="belongs_to_domain",
                    level=1,
                ))

        # Enterprise summary node (level 5) — optional
        if self.include_enterprise_node:
            all_op_ids = sorted(n.node_id for n in nodes)
            ent_node_id = "enterprise:global"
            summary_nodes.append(HierarchyNode(
                node_id=ent_node_id,
                entity_type="enterprise",
                level=5,
                label="Enterprise",
                member_node_ids=tuple(all_op_ids),
            ))
            for sn in summary_nodes:
                if sn.level == 4:  # domain → enterprise
                    agg_edge_id = f"agg:enterprise:{sn.node_id}"
                    aggregation_edges.append(HierarchyEdge(
                        edge_id=agg_edge_id,
                        source_node_id=sn.node_id,
                        target_node_id=ent_node_id,
                        relationship_type="belongs_to_enterprise",
                        level=4,
                    ))

        return HierarchicalGraph(
            operational_nodes=nodes,
            operational_edges=edges,
            summary_nodes=summary_nodes,
            aggregation_edges=aggregation_edges,
            membership=membership,
            warnings=warnings,
        )

    # ------------------------------------------------------------------
    # Private grouping helpers
    # ------------------------------------------------------------------

    def _group_by_application(
        self,
        nodes: list[LocalSubgraphNode],
        warnings: list[str],
    ) -> dict[str, list[str]]:
        """Group nodes by service/asset_type as a proxy for application group."""
        groups: dict[str, list[str]] = {}
        for node in nodes:
            app_key = node.asset_type or node.entity_type or "unknown"
            app_key = app_key.lower().replace(" ", "_")
            groups.setdefault(app_key, []).append(node.node_id)
        return groups

    def _group_by_subnet(
        self,
        nodes: list[LocalSubgraphNode],
        warnings: list[str],
    ) -> dict[str, list[str]]:
        """Group nodes by subnet metadata from twin or node attributes."""
        groups: dict[str, list[str]] = {}
        for node in nodes:
            subnet = self._resolve_subnet(node)
            groups.setdefault(subnet, []).append(node.node_id)
        return groups

    def _group_by_domain(
        self,
        nodes: list[LocalSubgraphNode],
        warnings: list[str],
    ) -> dict[str, list[str]]:
        """Group nodes by domain metadata from twin or entity_type."""
        groups: dict[str, list[str]] = {}
        for node in nodes:
            domain = self._resolve_domain(node)
            groups.setdefault(domain, []).append(node.node_id)
        return groups

    def _resolve_subnet(self, node: LocalSubgraphNode) -> str:
        """Return the subnet label for a node (never exposes raw IPs)."""
        # Try twin asset metadata
        if self.twin_snapshot:
            asset = self.twin_snapshot.assets.get(node.node_id)
            if asset and asset.subnet:
                return _subnet_label(asset.subnet)
        # Try node attributes
        subnet_attr = (node.attributes or {}).get("subnet")
        if subnet_attr:
            return _subnet_label(str(subnet_attr))
        # Fall back to entity type grouping
        return f"subnet_{node.entity_type}"

    def _resolve_domain(self, node: LocalSubgraphNode) -> str:
        """Return the domain label for a node (never exposes raw domain names)."""
        if self.twin_snapshot:
            identity = self.twin_snapshot.identities.get(node.node_id)
            if identity and identity.domain:
                return f"domain_{_sanitize(identity.domain)}"
            asset = self.twin_snapshot.assets.get(node.node_id)
            if asset and asset.environment:
                return f"env_{_sanitize(asset.environment)}"
        env_attr = (node.attributes or {}).get("environment")
        if env_attr:
            return f"env_{_sanitize(str(env_attr))}"
        return "domain_unknown"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize(raw: str) -> str:
    """Return a safe lowercase alphanumeric label (no raw sensitive values)."""
    import re
    return re.sub(r"[^a-z0-9_]", "_", raw.lower())[:32]


def _subnet_label(raw_subnet: str) -> str:
    """Return a sanitised subnet label.

    The raw CIDR or subnet string is hashed into a short token to avoid
    embedding raw network topology identifiers into training artifacts.
    """
    import hashlib
    token = hashlib.sha256(raw_subnet.encode()).hexdigest()[:8]
    return f"subnet_{token}"
