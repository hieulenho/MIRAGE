"""Node and edge feature extraction for the MIRAGE GNN pipeline.

Features are extracted from existing domain schemas:
  - LocalSubgraphNode  (from mirage.domain.schemas)
  - LocalSubgraphEdge  (from mirage.domain.schemas)
  - BeliefSnapshot     (from mirage.domain.schemas)
  - TwinSnapshot       (from mirage.domain.schemas)

No raw usernames, hostnames, IP addresses, command lines, or credentials
are encoded.  All categorical values use integer vocabulary indices that
support unknown values (index 0 = unknown / unseen).

Feature names and ordering are versioned via GraphFeatureSchema.
Missing values are tracked with an explicit binary mask (1=valid, 0=missing).
"""

from __future__ import annotations

import math
from datetime import datetime

from mirage.domain.schemas import (
    BeliefSnapshot,
    LocalSubgraphEdge,
    LocalSubgraphNode,
    LocalOperationalSubgraph,
    TwinSnapshot,
)
from mirage.gnn.schema import GraphFeatureSchema


def _recency(reference_time: datetime, last_seen: datetime, half_life_s: float = 3600.0) -> float:
    """Exponential recency score in [0, 1]; 1 = just seen."""
    delta = (reference_time - last_seen).total_seconds()
    if delta <= 0:
        return 1.0
    return math.exp(-delta / max(half_life_s, 1.0))


def _clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, v))


def _vocab_idx(value: str, vocab: list[str]) -> int:
    """Return index in vocab; 0 (unknown) if not found."""
    try:
        return vocab.index(value)
    except ValueError:
        return 0


class NodeFeatureExtractor:
    """Extract a fixed-length numeric feature vector from a LocalSubgraphNode.

    Parameters
    ----------
    schema:
        The versioned feature schema. Must match NODE_FEATURE_NAMES_V1.
    reference_time:
        The reference UTC datetime used for recency calculations.
    twin_snapshot:
        Digital Twin snapshot providing asset and identity metadata.
    belief_snapshot:
        Belief snapshot providing stage distributions and evidence.
    topology_stats:
        Pre-computed per-node degree and centrality values (see
        TopologyStatsComputer). If None, graph-topology features are 0.
    """

    STAGE_NAMES: list[str] = [
        "normal", "reconnaissance", "initial_access", "execution",
        "persistence", "privilege_escalation", "defense_evasion",
        "credential_access", "discovery", "lateral_movement",
        "collection", "command_and_control", "exfiltration", "impact",
    ]

    def __init__(
        self,
        schema: GraphFeatureSchema,
        reference_time: datetime,
        twin_snapshot: TwinSnapshot | None = None,
        belief_snapshot: BeliefSnapshot | None = None,
        topology_stats: dict[str, dict[str, float]] | None = None,
    ) -> None:
        self.schema = schema
        self.reference_time = reference_time
        self.twin_snapshot = twin_snapshot
        self.belief_snapshot = belief_snapshot
        self.topology_stats = topology_stats or {}
        self._feature_dim = len(schema.node_feature_names)

    def extract(
        self, node: LocalSubgraphNode
    ) -> tuple[list[float], list[float]]:
        """Return (feature_vector, mask_vector) both of length node_feature_dim."""
        features: list[float] = [0.0] * self._feature_dim
        mask: list[float] = [1.0] * self._feature_dim  # assume valid unless marked missing

        idx = {name: i for i, name in enumerate(self.schema.node_feature_names)}

        # entity_type_idx
        features[idx["entity_type_idx"]] = float(
            _vocab_idx(node.entity_type, self.schema.node_entity_types)
        )

        # Belief features
        belief = (
            self.belief_snapshot.entity_beliefs.get(node.node_id)
            if self.belief_snapshot
            else None
        )
        if belief is not None:
            features[idx["compromise_probability"]] = _clamp(belief.compromise_probability)
            features[idx["attacker_location_probability"]] = _clamp(
                belief.candidate_attacker_location_probability
            )
            features[idx["belief_confidence"]] = _clamp(belief.confidence)
            features[idx["belief_uncertainty"]] = _clamp(belief.uncertainty)
            # Stage distribution
            sd = belief.stage_distribution
            for stage in self.STAGE_NAMES:
                key = f"stage_{stage}"
                if key in idx:
                    features[idx[key]] = _clamp(sd.get(stage, 0.0))
        else:
            # Mark belief features as missing
            for key in [
                "compromise_probability", "attacker_location_probability",
                "belief_confidence", "belief_uncertainty",
            ]:
                mask[idx[key]] = 0.0
            for stage in self.STAGE_NAMES:
                key = f"stage_{stage}"
                if key in idx:
                    mask[idx[key]] = 0.0

        # Fall back to node-level probabilities when belief missing
        if belief is None:
            features[idx["compromise_probability"]] = _clamp(node.compromise_probability)
            features[idx["attacker_location_probability"]] = _clamp(
                node.attacker_location_probability
            )
            features[idx["belief_confidence"]] = _clamp(node.confidence)
            # mask remains 0 for these — they are fallbacks

        # Asset metadata
        features[idx["business_criticality"]] = _clamp(node.business_criticality)
        features[idx["is_protected"]] = 1.0 if node.is_protected else 0.0
        features[idx["is_decoy"]] = 1.0 if node.is_decoy else 0.0
        features[idx["is_seed"]] = 1.0 if node.is_seed else 0.0
        features[idx["is_critical"]] = 1.0 if node.is_critical else 0.0

        # Privilege level
        priv = node.attributes.get("privilege_level", "unknown") if node.attributes else "unknown"
        features[idx["privilege_level_idx"]] = float(
            _vocab_idx(str(priv), self.schema.privilege_levels)
        )

        # Vulnerability (not in base schema — default 0; mask=missing)
        features[idx["vulnerability_count"]] = 0.0
        features[idx["max_vulnerability_severity"]] = 0.0
        mask[idx["vulnerability_count"]] = 0.0
        mask[idx["max_vulnerability_severity"]] = 0.0

        # Evidence counts from belief
        if belief is not None:
            evidence_ids = belief.evidence_ids
            n_evidence = len(evidence_ids)
            features[idx["evidence_count"]] = float(min(n_evidence, 50)) / 50.0
            # Count direct vs inferred from snapshot evidence objects
            direct = inferred = 0
            if self.belief_snapshot:
                for eid in evidence_ids:
                    ev = self.belief_snapshot.evidence.get(eid)
                    if ev is not None:
                        if ev.score > 0:
                            direct += 1
                        else:
                            inferred += 1
            features[idx["direct_evidence_count"]] = float(min(direct, 20)) / 20.0
            features[idx["inferred_evidence_count"]] = float(min(inferred, 20)) / 20.0
        else:
            mask[idx["evidence_count"]] = 0.0
            mask[idx["direct_evidence_count"]] = 0.0
            mask[idx["inferred_evidence_count"]] = 0.0

        # Temporal: last_seen recency (from twin snapshot)
        last_seen = None
        if self.twin_snapshot:
            asset = self.twin_snapshot.assets.get(node.node_id)
            if asset:
                last_seen = asset.last_seen
                features[idx["twin_confidence"]] = _clamp(node.confidence)
                features[idx["twin_freshness"]] = _clamp(
                    self.twin_snapshot.freshness_score
                )
            else:
                identity = self.twin_snapshot.identities.get(node.node_id)
                if identity:
                    last_seen = identity.last_seen
                    features[idx["twin_confidence"]] = _clamp(node.confidence)
                    features[idx["twin_freshness"]] = _clamp(
                        self.twin_snapshot.freshness_score
                    )

        if last_seen is not None:
            features[idx["last_seen_recency"]] = _recency(self.reference_time, last_seen)
        else:
            mask[idx["last_seen_recency"]] = 0.0

        if "twin_confidence" in idx and features[idx["twin_confidence"]] == 0.0:
            features[idx["twin_confidence"]] = _clamp(node.confidence)
        if "twin_freshness" in idx and features[idx["twin_freshness"]] == 0.0:
            mask[idx["twin_freshness"]] = 0.0

        # Source diversity: number of distinct evidence sources / 10
        sources: set[str] = set()
        if self.belief_snapshot and belief is not None:
            for eid in belief.evidence_ids:
                ev = self.belief_snapshot.evidence.get(eid)
                if ev is not None:
                    for event_id in ev.event_ids:
                        sources.add(event_id[:8])
        features[idx["source_diversity"]] = _clamp(len(sources) / 10.0)

        # Graph topology features
        topo = self.topology_stats.get(node.node_id, {})
        features[idx["in_degree"]] = _clamp(topo.get("in_degree", 0.0) / 20.0)
        features[idx["out_degree"]] = _clamp(topo.get("out_degree", 0.0) / 20.0)
        features[idx["weighted_in_degree"]] = _clamp(topo.get("weighted_in_degree", 0.0))
        features[idx["weighted_out_degree"]] = _clamp(topo.get("weighted_out_degree", 0.0))

        # Structural distances (encoded as 1 - normalised_dist; -1 → 0)
        raw_dist_crit = topo.get("dist_to_critical_asset", -1.0)
        raw_dist_decoy = topo.get("dist_to_active_decoy", -1.0)
        features[idx["dist_to_critical_asset"]] = (
            _clamp(1.0 - raw_dist_crit / 10.0) if raw_dist_crit >= 0 else 0.0
        )
        features[idx["dist_to_active_decoy"]] = (
            _clamp(1.0 - raw_dist_decoy / 10.0) if raw_dist_decoy >= 0 else 0.0
        )
        if raw_dist_crit < 0:
            mask[idx["dist_to_critical_asset"]] = 0.0
        if raw_dist_decoy < 0:
            mask[idx["dist_to_active_decoy"]] = 0.0

        return features, mask


class EdgeFeatureExtractor:
    """Extract a fixed-length numeric feature vector from a LocalSubgraphEdge."""

    def __init__(
        self,
        schema: GraphFeatureSchema,
        reference_time: datetime,
    ) -> None:
        self.schema = schema
        self.reference_time = reference_time
        self._feature_dim = len(schema.edge_feature_names)

    def extract(
        self, edge: LocalSubgraphEdge
    ) -> tuple[list[float], list[float]]:
        """Return (feature_vector, mask_vector) both of length edge_feature_dim."""
        features: list[float] = [0.0] * self._feature_dim
        mask: list[float] = [1.0] * self._feature_dim

        idx = {name: i for i, name in enumerate(self.schema.edge_feature_names)}

        # Relationship type
        features[idx["relationship_type_idx"]] = float(
            _vocab_idx(edge.relationship_type, self.schema.edge_relationship_types)
        )

        # Confidence
        features[idx["confidence"]] = _clamp(edge.confidence)

        # Direct vs inferred
        features[idx["is_directly_observed"]] = 1.0 if edge.directly_observed else 0.0
        features[idx["is_inferred"]] = 1.0 if edge.inferred else 0.0

        # Recency: is_recent = last_seen within 1 hour
        age_s = (self.reference_time - edge.last_seen).total_seconds()
        features[idx["is_recent"]] = 1.0 if age_s <= 3600 else 0.0

        # Protocol category
        protocol = edge.attributes.get("protocol") if edge.attributes else None
        proto_str = str(protocol).lower() if protocol else "unknown"
        proto_cat = proto_str if proto_str in self.schema.protocol_categories else "other"
        features[idx["protocol_category_idx"]] = float(
            _vocab_idx(proto_cat, self.schema.protocol_categories)
        )

        # Semantic flags
        auth_types = {
            "authenticated_to", "uses_credential", "uses_credential_on", "has_privilege"
        }
        cred_types = {"uses_credential", "uses_credential_on"}
        features[idx["is_authentication_related"]] = (
            1.0 if edge.relationship_type in auth_types else 0.0
        )
        features[idx["credential_required"]] = (
            1.0 if edge.relationship_type in cred_types else 0.0
        )

        # Privilege requirement
        priv_req = edge.attributes.get("privilege_requirement", "unknown") if edge.attributes else "unknown"
        features[idx["privilege_requirement_idx"]] = float(
            _vocab_idx(str(priv_req), self.schema.privilege_levels)
        )
        if priv_req == "unknown":
            mask[idx["privilege_requirement_idx"]] = 0.0

        # Movement likelihood heuristic
        movement_rels = {
            "connects_to", "observed_lateral_movement", "authenticated_to",
            "uses_credential", "uses_credential_on",
        }
        features[idx["movement_likelihood"]] = (
            edge.confidence * 0.85
            if edge.relationship_type in movement_rels
            else edge.confidence * 0.25
        )

        # Evidence count (presence of source events)
        n_ev = len(edge.source_event_ids)
        features[idx["evidence_count"]] = _clamp(float(n_ev) / 20.0)

        # Stale: last_seen > 24 hours
        features[idx["is_stale"]] = 1.0 if age_s > 86400 else 0.0

        # Active: expires_at not exceeded
        features[idx["is_active"]] = 1.0
        if edge.expires_at is not None and edge.expires_at <= self.reference_time:
            features[idx["is_active"]] = 0.0

        # Protected path
        features[idx["is_protected_path"]] = 1.0 if edge.protected_edge else 0.0

        # Existing control (has observed events backing it)
        features[idx["existing_control"]] = 1.0 if edge.source_event_ids else 0.0

        # Decoy path
        features[idx["is_decoy_path"]] = 1.0 if "decoy" in edge.relationship_type else 0.0

        return features, mask


class TopologyStatsComputer:
    """Compute graph-topology statistics for all nodes in a subgraph.

    Returns a dict mapping node_id → {in_degree, out_degree,
    weighted_in_degree, weighted_out_degree, dist_to_critical_asset,
    dist_to_active_decoy}.
    """

    def compute(self, subgraph: LocalOperationalSubgraph) -> dict[str, dict[str, float]]:
        stats: dict[str, dict[str, float]] = {
            node.node_id: {
                "in_degree": 0.0,
                "out_degree": 0.0,
                "weighted_in_degree": 0.0,
                "weighted_out_degree": 0.0,
                "dist_to_critical_asset": -1.0,
                "dist_to_active_decoy": -1.0,
            }
            for node in subgraph.nodes
        }
        for edge in subgraph.edges:
            src, dst = edge.source_entity_id, edge.target_entity_id
            if src in stats:
                stats[src]["out_degree"] += 1.0
                stats[src]["weighted_out_degree"] += edge.confidence
            if dst in stats:
                stats[dst]["in_degree"] += 1.0
                stats[dst]["weighted_in_degree"] += edge.confidence

        # BFS distances from each critical asset
        for target_id in subgraph.critical_asset_ids:
            dists = self._bfs_distances(target_id, subgraph, reverse=True)
            for node_id, dist in dists.items():
                if node_id in stats:
                    cur = stats[node_id]["dist_to_critical_asset"]
                    stats[node_id]["dist_to_critical_asset"] = (
                        dist if cur < 0 else min(cur, dist)
                    )

        # BFS distances from each decoy
        for decoy_id in subgraph.decoy_ids:
            dists = self._bfs_distances(decoy_id, subgraph, reverse=True)
            for node_id, dist in dists.items():
                if node_id in stats:
                    cur = stats[node_id]["dist_to_active_decoy"]
                    stats[node_id]["dist_to_active_decoy"] = (
                        dist if cur < 0 else min(cur, dist)
                    )

        return stats

    def _bfs_distances(
        self,
        source: str,
        subgraph: LocalOperationalSubgraph,
        reverse: bool = False,
    ) -> dict[str, float]:
        """BFS hop-count distances from *source*."""
        from collections import deque

        adjacency: dict[str, list[str]] = {}
        for edge in subgraph.edges:
            src = edge.target_entity_id if reverse else edge.source_entity_id
            dst = edge.source_entity_id if reverse else edge.target_entity_id
            adjacency.setdefault(src, []).append(dst)

        distances: dict[str, float] = {source: 0.0}
        queue: deque[str] = deque([source])
        while queue:
            current = queue.popleft()
            for neighbor in adjacency.get(current, []):
                if neighbor not in distances:
                    distances[neighbor] = distances[current] + 1.0
                    queue.append(neighbor)
        return distances
