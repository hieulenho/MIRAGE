"""Bounded local operational subgraph extraction."""

from __future__ import annotations

from collections import deque

from mirage.analysis.utils import (
    canonical_entity_type,
    clamp01,
    entity_label,
    mean,
    recency_score,
    stable_id,
)
from mirage.domain.schemas import (
    BeliefSnapshot,
    LocalOperationalSubgraph,
    LocalSubgraphEdge,
    LocalSubgraphNode,
    LocalSubgraphRequest,
    Relationship,
    SeedEntity,
    TwinSnapshot,
)


class LocalSubgraphExtractor:
    """Extract a bounded deterministic graph from Twin relationships."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}

    def extract(
        self,
        attack_graph,
        twin_snapshot: TwinSnapshot,
        belief_snapshot: BeliefSnapshot,
        request: LocalSubgraphRequest,
        seed_entities: list[SeedEntity] | None = None,
    ) -> LocalOperationalSubgraph:
        """Build a local subgraph around selected seeds."""
        seeds = seed_entities or []
        seed_ids = set(request.seed_entity_ids) | {seed.entity_id for seed in seeds}
        allowed_types = set(request.relationship_types or [])
        warnings: list[str] = []
        truncation_reasons: list[str] = []
        active_relationships = self._active_relationships(twin_snapshot, request)
        adjacency: dict[str, list[Relationship]] = {}
        for relationship in active_relationships:
            if allowed_types and relationship.relationship_type not in allowed_types:
                continue
            if relationship.confidence < request.minimum_edge_confidence:
                continue
            if not self._entity_allowed(relationship.source_entity_id, request):
                continue
            if not self._entity_allowed(relationship.target_entity_id, request):
                continue
            adjacency.setdefault(relationship.source_entity_id, []).append(relationship)
            adjacency.setdefault(relationship.target_entity_id, []).append(relationship)

        visited: set[str] = set(seed_ids)
        frontier = deque((seed_id, 0) for seed_id in sorted(seed_ids))
        boundary: set[str] = set()
        edge_ids: set[str] = set()
        while frontier:
            entity_id, depth = frontier.popleft()
            if depth >= request.max_hops:
                continue
            for relationship in sorted(
                adjacency.get(entity_id, []),
                key=lambda rel: (
                    -rel.confidence,
                    rel.relationship_type,
                    rel.relationship_id,
                ),
            ):
                edge_ids.add(relationship.relationship_id)
                other = (
                    relationship.target_entity_id
                    if relationship.source_entity_id == entity_id
                    else relationship.source_entity_id
                )
                if other not in visited:
                    if len(visited) < request.max_nodes:
                        visited.add(other)
                        frontier.append((other, depth + 1))
                    else:
                        boundary.add(other)

        if request.include_critical_assets:
            for asset_id, asset in sorted(twin_snapshot.assets.items()):
                if (
                    asset.business_criticality >= request.criticality_threshold
                    and not asset.is_decoy
                    and len(visited) < request.max_nodes
                ):
                    visited.add(asset_id)

        visited |= seed_ids
        if len(boundary) > 0:
            truncation_reasons.append("node_limit_reached")
        nodes = [
            self._node_from_entity(
                entity_id,
                twin_snapshot,
                belief_snapshot,
                seed_ids,
                request,
            )
            for entity_id in sorted(visited)
        ]
        node_ids = {node.node_id for node in nodes}
        edges: list[LocalSubgraphEdge] = []
        for relationship in sorted(active_relationships, key=lambda rel: rel.relationship_id):
            if relationship.relationship_id not in edge_ids:
                if (
                    relationship.source_entity_id not in node_ids
                    or relationship.target_entity_id not in node_ids
                ):
                    continue
            if (
                relationship.source_entity_id in node_ids
                and relationship.target_entity_id in node_ids
            ):
                edges.append(self._edge_from_relationship(relationship, request))
        edges.sort(
            key=lambda edge: (
                -edge.confidence,
                edge.relationship_type,
                edge.source_entity_id,
                edge.target_entity_id,
                edge.edge_id,
            )
        )
        if len(edges) > request.max_edges:
            protected = [
                edge
                for edge in edges
                if edge.source_entity_id in seed_ids or edge.target_entity_id in seed_ids
            ]
            rest = [edge for edge in edges if edge not in protected]
            edges = (protected + rest)[: request.max_edges]
            truncation_reasons.append("edge_limit_reached")
        edge_node_ids = {
            entity_id
            for edge in edges
            for entity_id in (edge.source_entity_id, edge.target_entity_id)
        }
        missing = edge_node_ids - node_ids
        if missing:
            warnings.append(f"removed dangling edge references: {sorted(missing)}")
            edges = [
                edge
                for edge in edges
                if edge.source_entity_id in node_ids and edge.target_entity_id in node_ids
            ]
        critical_assets = sorted(
            node.node_id for node in nodes if node.is_critical and not node.is_decoy
        )
        decoys = sorted(node.node_id for node in nodes if node.is_decoy)
        freshness = mean(
            [recency_score(request.reference_time, edge.last_seen, 86400) for edge in edges],
            default=twin_snapshot.freshness_score,
        )
        coverage = clamp01(
            min(twin_snapshot.coverage_score or 0.0, 1.0)
            if nodes
            else twin_snapshot.coverage_score
        )
        graph_version = getattr(attack_graph, "name", "mirage_attack_graph")
        subgraph_id = stable_id(
            "subgraph",
            [
                graph_version,
                twin_snapshot.twin_version,
                belief_snapshot.belief_version,
                *sorted(seed_ids),
                *[edge.edge_id for edge in edges],
            ],
        )
        if twin_snapshot.coverage_score < 0.25:
            warnings.append("Digital Twin coverage is low; paths may be incomplete.")
        return LocalOperationalSubgraph(
            subgraph_id=subgraph_id,
            graph_version=str(graph_version),
            twin_version=str(twin_snapshot.twin_version),
            belief_version=belief_snapshot.belief_version,
            created_at=request.reference_time,
            reference_time=request.reference_time,
            seed_entities=sorted(seeds, key=lambda seed: seed.entity_id),
            nodes=sorted(nodes, key=lambda node: node.node_id),
            edges=sorted(edges, key=lambda edge: edge.edge_id),
            critical_asset_ids=critical_assets,
            decoy_ids=decoys,
            boundary_entity_ids=sorted(boundary),
            unknown_boundary_count=len(boundary),
            coverage_score=coverage,
            freshness_score=clamp01(freshness),
            truncated=bool(truncation_reasons),
            truncation_reasons=sorted(set(truncation_reasons)),
            warnings=sorted(set(warnings + twin_snapshot.warnings)),
        )

    def _active_relationships(
        self,
        snapshot: TwinSnapshot,
        request: LocalSubgraphRequest,
    ) -> list[Relationship]:
        relationships = []
        for relationship in snapshot.relationships.values():
            if not relationship.active:
                continue
            if relationship.expiry_time is not None and relationship.expiry_time <= request.reference_time:
                continue
            if (
                request.freshness_threshold is not None
                and (request.reference_time - relationship.last_seen).total_seconds()
                > request.freshness_threshold
            ):
                continue
            relationships.append(relationship)
        return relationships

    def _entity_allowed(self, entity_id: str, request: LocalSubgraphRequest) -> bool:
        entity_type = canonical_entity_type(entity_id)
        if entity_type == "credential" and not request.include_credentials:
            return False
        if entity_type == "identity" and not request.include_identities:
            return False
        return True

    def _node_from_entity(
        self,
        entity_id: str,
        snapshot: TwinSnapshot,
        belief_snapshot: BeliefSnapshot,
        seed_ids: set[str],
        request: LocalSubgraphRequest,
    ) -> LocalSubgraphNode:
        belief = belief_snapshot.entity_beliefs.get(entity_id)
        if entity_id in snapshot.assets:
            asset = snapshot.assets[entity_id]
            critical = (
                asset.business_criticality >= request.criticality_threshold
                and not asset.is_decoy
            )
            return LocalSubgraphNode(
                node_id=entity_id,
                entity_type="asset",
                label=asset.hostname or entity_label(entity_id),
                asset_type=asset.asset_type,
                business_criticality=asset.business_criticality,
                is_seed=entity_id in seed_ids,
                is_decoy=asset.is_decoy,
                is_critical=critical,
                is_protected=critical or asset.asset_type in {"database", "dc", "domain_controller"},
                compromise_probability=belief.compromise_probability if belief else 0.0,
                attacker_location_probability=(
                    belief.candidate_attacker_location_probability if belief else 0.0
                ),
                confidence=asset.confidence,
                source="twin_asset",
                attributes={
                    "last_seen": asset.last_seen.isoformat(),
                    "environment": asset.environment,
                    "subnet": asset.subnet,
                },
            )
        if entity_id in snapshot.identities:
            identity = snapshot.identities[entity_id]
            return LocalSubgraphNode(
                node_id=entity_id,
                entity_type="identity",
                label=identity.username or entity_label(entity_id),
                asset_type=identity.identity_type,
                business_criticality=0.7 if "admin" in identity.privilege_level else 0.3,
                is_seed=entity_id in seed_ids,
                compromise_probability=belief.compromise_probability if belief else 0.0,
                attacker_location_probability=(
                    belief.candidate_attacker_location_probability if belief else 0.0
                ),
                confidence=identity.confidence,
                source="twin_identity",
                attributes={"privilege_level": identity.privilege_level},
            )
        entity_type = canonical_entity_type(entity_id)
        return LocalSubgraphNode(
            node_id=entity_id,
            entity_type=entity_type,
            label=entity_label(entity_id),
            asset_type=entity_type,
            business_criticality=0.6 if entity_type == "credential" else 0.1,
            is_seed=entity_id in seed_ids,
            is_decoy="decoy" in entity_id,
            compromise_probability=belief.compromise_probability if belief else 0.0,
            attacker_location_probability=(
                belief.candidate_attacker_location_probability if belief else 0.0
            ),
            confidence=belief.confidence if belief else 0.5,
            source="derived",
        )

    def _edge_from_relationship(
        self,
        relationship: Relationship,
        request: LocalSubgraphRequest,
    ) -> LocalSubgraphEdge:
        return LocalSubgraphEdge(
            edge_id=relationship.relationship_id,
            source_entity_id=relationship.source_entity_id,
            target_entity_id=relationship.target_entity_id,
            relationship_type=relationship.relationship_type,
            confidence=relationship.confidence,
            first_seen=relationship.first_seen,
            last_seen=relationship.last_seen,
            expires_at=relationship.expiry_time,
            directly_observed=bool(relationship.source_event_ids),
            inferred=bool(relationship.attributes.get("inferred")),
            protected_edge=relationship.privilege_requirement == "protected",
            source_event_ids=relationship.source_event_ids,
            attributes={
                "protocol": relationship.protocol,
                "port": relationship.port,
                "recency": recency_score(
                    request.reference_time,
                    relationship.last_seen,
                    86400,
                ),
            },
        )
