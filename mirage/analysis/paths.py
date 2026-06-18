"""Attack-path discovery and explicit risk scoring."""

from __future__ import annotations

import math
from collections import defaultdict
from datetime import datetime

from mirage.analysis.utils import clamp01, mean, recency_score, stable_id
from mirage.domain.schemas import (
    AttackPath,
    BeliefSnapshot,
    LocalOperationalSubgraph,
    LocalSubgraphEdge,
    LocalSubgraphNode,
    PathType,
)


REMOTE_RELATIONSHIPS = {
    "connects_to",
    "authenticated_to",
    "uses_credential_on",
    "interacted_with_decoy",
    "accessed_file_on",
}


class AttackPathFinder:
    """Find bounded, deduplicated attack paths in a local subgraph."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.max_path_length = int(self.config.get("maximum_path_length", 6))
        self.max_paths_per_target = int(self.config.get("maximum_paths_per_target", 3))
        self.max_total_paths = int(self.config.get("maximum_total_paths", 60))
        self.enabled = set(
            self.config.get(
                "enabled_path_types",
                [path_type.value for path_type in PathType],
            )
        )

    def find_paths(
        self,
        subgraph: LocalOperationalSubgraph,
        belief_snapshot: BeliefSnapshot,
        reference_time: datetime,
    ) -> list[AttackPath]:
        """Return deterministic candidate paths from seeds to targets."""
        nodes = {node.node_id: node for node in subgraph.nodes}
        edges = {edge.edge_id: edge for edge in subgraph.edges}
        adjacency: dict[str, list[LocalSubgraphEdge]] = defaultdict(list)
        for edge in subgraph.edges:
            adjacency[edge.source_entity_id].append(edge)
        for bucket in adjacency.values():
            bucket.sort(
                key=lambda edge: (
                    -edge.confidence,
                    edge.relationship_type,
                    edge.target_entity_id,
                    edge.edge_id,
                )
            )
        seeds = [seed.entity_id for seed in subgraph.seed_entities] or [
            node.node_id for node in subgraph.nodes if node.is_seed
        ]
        targets = sorted(
            set(subgraph.critical_asset_ids)
            | (set(subgraph.decoy_ids) if PathType.DECOY_PATH.value in self.enabled else set())
        )
        raw_paths: list[AttackPath] = []
        for seed in sorted(seeds):
            for target in targets:
                if seed == target:
                    continue
                found = self._bounded_paths(seed, target, adjacency)
                for node_ids, edge_ids in found[: self.max_paths_per_target]:
                    path_types = self._classify_path(node_ids, edge_ids, nodes, edges)
                    for path_type in sorted(path_types):
                        if path_type not in self.enabled:
                            continue
                        raw_paths.append(
                            self._build_path(
                                path_type,
                                node_ids,
                                edge_ids,
                                nodes,
                                edges,
                                belief_snapshot,
                                reference_time,
                            )
                        )
        deduped = self._dedupe(raw_paths)
        deduped.sort(
            key=lambda path: (
                -path.risk_score,
                path.path_type,
                path.source_entity_id,
                path.target_entity_id,
                path.path_id,
            )
        )
        return deduped[: self.max_total_paths]

    def _bounded_paths(
        self,
        source: str,
        target: str,
        adjacency: dict[str, list[LocalSubgraphEdge]],
    ) -> list[tuple[list[str], list[str]]]:
        results: list[tuple[list[str], list[str]]] = []
        stack = [(source, [source], [])]
        while stack and len(results) < self.max_paths_per_target * 4:
            current, node_path, edge_path = stack.pop()
            if len(edge_path) >= self.max_path_length:
                continue
            for edge in reversed(adjacency.get(current, [])):
                nxt = edge.target_entity_id
                if nxt in node_path:
                    continue
                new_nodes = node_path + [nxt]
                new_edges = edge_path + [edge.edge_id]
                if nxt == target:
                    results.append((new_nodes, new_edges))
                    continue
                stack.append((nxt, new_nodes, new_edges))
        results.sort(key=lambda item: (len(item[1]), item[0], item[1]))
        return results

    def _classify_path(
        self,
        node_ids: list[str],
        edge_ids: list[str],
        nodes: dict[str, LocalSubgraphNode],
        edges: dict[str, LocalSubgraphEdge],
    ) -> set[str]:
        path_types = {PathType.HIGHEST_SUCCESS_PROBABILITY.value}
        target = nodes[node_ids[-1]]
        if target.is_critical or target.is_protected:
            path_types.add(PathType.SHORTEST_TO_CRITICAL_ASSET.value)
            path_types.add(PathType.HIGHEST_RISK.value)
        if any(nodes[node_id].is_decoy for node_id in node_ids):
            path_types.add(PathType.DECOY_PATH.value)
        if any(
            "credential" in nodes[node_id].entity_type
            or edges[edge_id].relationship_type in {"uses_credential", "uses_credential_on"}
            for node_id in node_ids
            for edge_id in edge_ids
        ):
            path_types.add(PathType.CREDENTIAL_DRIVEN.value)
        if any(edges[edge_id].directly_observed for edge_id in edge_ids):
            path_types.add(PathType.RECENTLY_OBSERVED.value)
        if not any(nodes[node_id].is_decoy for node_id in node_ids):
            path_types.add(PathType.UNPROTECTED_PATH.value)
        if len(edge_ids) >= 3 or sum(nodes[node_id].business_criticality for node_id in node_ids) > 1.5:
            path_types.add(PathType.HIGH_BLAST_RADIUS.value)
        return path_types

    def _build_path(
        self,
        path_type: str,
        node_ids: list[str],
        edge_ids: list[str],
        nodes: dict[str, LocalSubgraphNode],
        edges: dict[str, LocalSubgraphEdge],
        belief_snapshot: BeliefSnapshot,
        reference_time: datetime,
    ) -> AttackPath:
        edge_values = [edges[edge_id] for edge_id in edge_ids]
        target = nodes[node_ids[-1]]
        source = nodes[node_ids[0]]
        relationship_confidence = mean([edge.confidence for edge in edge_values], default=0.5)
        evidence_ids = sorted(
            {
                evidence_id
                for node_id in node_ids
                if node_id in belief_snapshot.entity_beliefs
                for evidence_id in belief_snapshot.entity_beliefs[node_id].evidence_ids
            }
        )
        directly_observed = [edge.edge_id for edge in edge_values if edge.directly_observed]
        inferred = [edge.edge_id for edge in edge_values if edge.inferred]
        credential_feasibility = 0.75 if any(
            edge.relationship_type in {"uses_credential", "uses_credential_on", "authenticated_to"}
            for edge in edge_values
        ) else 0.45
        evidence_recency = mean(
            [recency_score(reference_time, edge.last_seen, 3600) for edge in edge_values],
            default=0.5,
        )
        stage_compatibility = self._stage_compatibility(
            belief_snapshot.entity_beliefs.get(source.node_id, None),
            edge_values,
        )
        success = self._success_probability(edge_values)
        contains_decoy = any(nodes[node_id].is_decoy for node_id in node_ids)
        decoy_prob = 0.8 if contains_decoy else 0.0
        path_id = stable_id("path", [path_type, *node_ids, *edge_ids])
        return AttackPath(
            path_id=path_id,
            source_entity_id=node_ids[0],
            target_entity_id=node_ids[-1],
            node_ids=node_ids,
            edge_ids=edge_ids,
            path_length=len(edge_ids),
            path_type=path_type,
            success_probability=success,
            risk_score=0.0,
            target_criticality=target.business_criticality,
            stage_compatibility=stage_compatibility,
            credential_feasibility=credential_feasibility,
            evidence_recency=evidence_recency,
            relationship_confidence=relationship_confidence,
            decoy_engagement_probability=decoy_prob,
            uncertainty=belief_snapshot.entity_beliefs.get(
                source.node_id,
                None,
            ).uncertainty
            if source.node_id in belief_snapshot.entity_beliefs
            else 0.5,
            required_credentials=[
                node_id for node_id in node_ids if node_id.startswith("credential:")
            ],
            required_techniques=self._techniques_for_edges(edge_values),
            supporting_evidence_ids=evidence_ids,
            directly_observed_edge_ids=directly_observed,
            inferred_edge_ids=inferred,
            contains_decoy=contains_decoy,
            reaches_protected_asset=target.is_protected,
            explanation=(
                f"{path_type} path from {source.label} to {target.label} "
                f"over {len(edge_ids)} relationship(s)."
            ),
        )

    def _success_probability(self, edges: list[LocalSubgraphEdge]) -> float:
        if not edges:
            return 0.0
        negative_log = 0.0
        for edge in edges:
            probability = clamp01(max(0.01, min(0.99, edge.confidence)))
            negative_log += -math.log(probability)
        return clamp01(math.exp(-negative_log / max(1, len(edges))))

    def _stage_compatibility(self, belief, edges: list[LocalSubgraphEdge]) -> float:
        if belief is None:
            return 0.5
        stage = belief.most_likely_stage
        rels = {edge.relationship_type for edge in edges}
        if stage in {"credential_access", "privilege_escalation"} and rels.intersection(
            {"uses_credential", "uses_credential_on", "authenticated_to"}
        ):
            return 0.85
        if stage == "discovery" and "connects_to" in rels:
            return 0.75
        if stage == "lateral_movement" and rels.intersection(REMOTE_RELATIONSHIPS):
            return 0.90
        if stage in {"collection", "exfiltration"}:
            return 0.80
        return 0.55

    def _techniques_for_edges(self, edges: list[LocalSubgraphEdge]) -> list[str]:
        techniques = set()
        for edge in edges:
            if edge.relationship_type == "connects_to":
                techniques.add("T1021")
            if edge.relationship_type in {"uses_credential", "uses_credential_on"}:
                techniques.add("T1555")
            if edge.relationship_type == "authenticated_to":
                techniques.add("T1078")
            if edge.relationship_type == "interacted_with_decoy":
                techniques.add("T1005")
        return sorted(techniques)

    def _dedupe(self, paths: list[AttackPath]) -> list[AttackPath]:
        retained: dict[tuple[str, ...], AttackPath] = {}
        for path in paths:
            key = tuple(path.node_ids + [path.path_type])
            if key not in retained or path.success_probability > retained[key].success_probability:
                retained[key] = path
        return list(retained.values())


class AttackPathRiskScorer:
    """Apply explicit bounded risk formula to candidate paths."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.exposure_weight = float(self.config.get("exposure_weight", 0.5))

    def score(
        self,
        path: AttackPath,
        subgraph: LocalOperationalSubgraph,
        belief_snapshot: BeliefSnapshot,
        reference_time: datetime,
    ) -> AttackPath:
        """Score one path and return an updated immutable model."""
        source_belief = belief_snapshot.entity_beliefs.get(path.source_entity_id)
        source_compromise = (
            source_belief.compromise_probability if source_belief else 0.1
        )
        source_uncertainty = source_belief.uncertainty if source_belief else 0.6
        inferred_penalty = 0.25 if path.inferred_edge_ids and not path.directly_observed_edge_ids else 0.0
        stale_penalty = 0.20 if path.evidence_recency < 0.35 else 0.0
        uncertainty_penalty = clamp01((path.uncertainty + source_uncertainty) / 2)
        exposure_factor = clamp01(0.2 + 0.1 * path.path_length)
        direct_bonus = 0.10 if path.directly_observed_edge_ids else 0.0
        credential_bonus = 0.08 if path.required_credentials else 0.0
        protected_bonus = 0.12 if path.reaches_protected_asset else 0.0
        decoy_modifier = -0.20 if path.contains_decoy else 0.0
        raw = (
            source_compromise
            * path.success_probability
            * max(0.2, path.target_criticality)
            * path.stage_compatibility
            * path.evidence_recency
            * path.relationship_confidence
            * path.credential_feasibility
            * (1.0 + exposure_factor * self.exposure_weight)
        )
        adjusted = raw + direct_bonus + credential_bonus + protected_bonus + decoy_modifier
        adjusted *= 1.0 - min(0.75, inferred_penalty + stale_penalty + uncertainty_penalty * 0.25)
        risk = clamp01(adjusted)
        breakdown = {
            "source_compromise": round(source_compromise, 6),
            "path_success": round(path.success_probability, 6),
            "target_criticality": round(path.target_criticality, 6),
            "stage_compatibility": round(path.stage_compatibility, 6),
            "evidence_recency": round(path.evidence_recency, 6),
            "relationship_confidence": round(path.relationship_confidence, 6),
            "credential_feasibility": round(path.credential_feasibility, 6),
            "exposure_factor": round(exposure_factor, 6),
            "direct_observation_bonus": round(direct_bonus, 6),
            "credential_bonus": round(credential_bonus, 6),
            "protected_asset_bonus": round(protected_bonus, 6),
            "decoy_modifier": round(decoy_modifier, 6),
            "inferred_penalty": round(inferred_penalty, 6),
            "stale_penalty": round(stale_penalty, 6),
            "uncertainty_penalty": round(uncertainty_penalty, 6),
        }
        return path.model_copy(
            update={
                "risk_score": risk,
                "uncertainty": clamp01(uncertainty_penalty),
                "score_breakdown": breakdown,
                "explanation": (
                    path.explanation
                    + f" Risk={risk:.3f}; direct edges={len(path.directly_observed_edge_ids)}, "
                    f"inferred edges={len(path.inferred_edge_ids)}."
                ),
            }
        )
