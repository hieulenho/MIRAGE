"""Entity and incident belief engine for contextual detection."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Iterable

from mirage.detection.stage_estimator import AttackStageEstimator
from mirage.detection.utils import (
    canonical_entity_type,
    clamp01,
    normalized_stage_distribution,
    stable_id,
)
from mirage.domain.schemas import (
    BeliefSnapshot,
    BeliefUpdateResult,
    CorrelationRecord,
    EntityBelief,
    Evidence,
    IncidentBelief,
    SecurityEvent,
    utc_now,
)
from mirage.layer6_twin.digital_twin import DigitalTwin


class BeliefEngine:
    """Maintain probabilistic compromise and attacker-location beliefs."""

    def __init__(
        self,
        *,
        twin: DigitalTwin | None = None,
        stage_estimator: AttackStageEstimator | None = None,
        compromise_threshold: float = 0.35,
        high_confidence_deception_threshold: float = 0.85,
        propagation_depth: int = 1,
        propagation_decay: float = 0.45,
    ) -> None:
        self.twin = twin
        self.stage_estimator = stage_estimator or AttackStageEstimator()
        self.compromise_threshold = float(compromise_threshold)
        self.high_confidence_deception_threshold = float(
            high_confidence_deception_threshold
        )
        self.propagation_depth = int(max(0, propagation_depth))
        self.propagation_decay = float(propagation_decay)
        self.evidence: dict[str, Evidence] = {}
        self.correlations: dict[str, CorrelationRecord] = {}
        self.entity_beliefs: dict[str, EntityBelief] = {}
        self.version = 0
        self.warnings: list[str] = []
        self.last_updated: datetime | None = None

    def process_event(self, event: SecurityEvent) -> BeliefUpdateResult:
        """Compatibility hook: update any already-known event entities."""
        entity_ids = []
        if event.asset_id:
            entity_ids.append(event.asset_id)
        if event.user_id:
            entity_ids.append(event.user_id)
        return BeliefUpdateResult(
            event_id=event.event_id,
            entity_ids=entity_ids,
            updated_beliefs={
                entity_id: self.update_entity(entity_id, event.event_time)
                for entity_id in entity_ids
            },
            belief_version=self.version,
        )

    def record_evidence(
        self,
        items: Iterable[Evidence],
        correlations: Iterable[CorrelationRecord] = (),
    ) -> None:
        """Insert evidence and correlations idempotently."""
        for item in items:
            self.evidence[item.evidence_id] = item
        for correlation in correlations:
            self.correlations[correlation.correlation_id] = correlation

    def update_entity(
        self,
        entity_id: str,
        reference_time: datetime,
    ) -> EntityBelief:
        """Recompute belief for one entity."""
        previous = self.entity_beliefs.get(entity_id)
        entity_evidence = self._active_evidence_for(entity_id, reference_time)
        stage_result = self.stage_estimator.estimate(
            entity_id,
            reference_time,
            entity_evidence,
            previous_belief=previous,
        )
        direct_score = sum(
            self._evidence_strength(item, reference_time)
            for item in entity_evidence
            if not item.attributes.get("inferred")
        )
        inferred_score = sum(
            self._evidence_strength(item, reference_time) * 0.5
            for item in entity_evidence
            if item.attributes.get("inferred")
        )
        suppression = sum(
            abs(self._evidence_strength(item, reference_time))
            for item in entity_evidence
            if item.attributes.get("suppression")
        )
        raw = max(0.0, direct_score + inferred_score - suppression)
        probability = 1.0 - math.exp(-raw)
        deception_observed = any(
            item.rule_id == "R008_DECEPTION_INTERACTION"
            for item in entity_evidence
        )
        if deception_observed:
            probability = max(probability, self.high_confidence_deception_threshold)
        elif suppression > 0:
            suppression_cap = self.compromise_threshold * 0.95
            probability = min(probability, suppression_cap)
        if previous is not None:
            decayed_previous = previous.compromise_probability * 0.85
            if suppression > 0 and not deception_observed:
                decayed_previous = min(
                    decayed_previous,
                    self.compromise_threshold * 0.95,
                )
            probability = max(probability, decayed_previous)
        probability = clamp01(probability)
        first_suspicious = previous.first_suspicious_time if previous else None
        if probability >= self.compromise_threshold and first_suspicious is None:
            first_suspicious = min(
                (item.first_seen for item in entity_evidence),
                default=reference_time,
            )
        confidence = clamp01(stage_result.confidence + min(0.25, raw * 0.1))
        belief = EntityBelief(
            entity_id=entity_id,
            entity_type=canonical_entity_type(entity_id),
            compromise_probability=probability,
            stage_distribution=stage_result.stage_distribution,
            most_likely_stage=stage_result.most_likely_stage,
            uncertainty=stage_result.uncertainty,
            confidence=confidence,
            evidence_ids=stage_result.supporting_evidence_ids,
            candidate_attacker_location_probability=(
                probability if entity_id.startswith("asset:") else probability * 0.3
            ),
            first_suspicious_time=first_suspicious,
            last_updated=reference_time,
            belief_version=self.version + 1,
            warnings=[],
        )
        self.entity_beliefs[entity_id] = belief
        self.version += 1
        self.last_updated = reference_time
        return belief

    def update_entities_with_propagation(
        self,
        entity_ids: Iterable[str],
        reference_time: datetime,
    ) -> dict[str, EntityBelief]:
        """Update direct entities and propagate bounded inferred risk."""
        updated = {
            entity_id: self.update_entity(entity_id, reference_time)
            for entity_id in sorted(set(entity_ids))
        }
        inferred = self._propagate(updated, reference_time)
        for entity_id in inferred:
            updated[entity_id] = self.update_entity(entity_id, reference_time)
        return updated

    def get_entity_belief(self, entity_id: str) -> EntityBelief | None:
        """Return the current belief for one entity."""
        return self.entity_beliefs.get(entity_id)

    def get_top_suspected_entities(self, limit: int = 20) -> list[EntityBelief]:
        """Return top entities by compromise probability."""
        if limit < 1:
            raise ValueError("limit must be at least 1")
        return sorted(
            self.entity_beliefs.values(),
            key=lambda belief: (
                -belief.compromise_probability,
                belief.entity_id,
            ),
        )[:limit]

    def create_incident_belief(
        self,
        seed_entity_ids: list[str],
    ) -> IncidentBelief:
        """Create an incident-level belief over related entity beliefs."""
        selected = {
            entity_id: self.entity_beliefs[entity_id]
            for entity_id in sorted(set(seed_entity_ids))
            if entity_id in self.entity_beliefs
        }
        if not selected:
            selected = {
                belief.entity_id: belief
                for belief in self.get_top_suspected_entities(limit=5)
            }
        stage_scores = {stage: 0.0 for stage in normalized_stage_distribution()}
        evidence_ids: set[str] = set()
        for belief in selected.values():
            for stage, probability in belief.stage_distribution.items():
                stage_scores[stage] += probability * belief.compromise_probability
            evidence_ids.update(belief.evidence_ids)
        overall = normalized_stage_distribution(stage_scores)
        confidence = max(
            [belief.confidence for belief in selected.values()],
            default=0.0,
        )
        now = max(
            [belief.last_updated for belief in selected.values()],
            default=utc_now(),
        )
        return IncidentBelief(
            incident_id=stable_id("incident", sorted(selected)),
            entity_beliefs=selected,
            probable_attack_paths=[sorted(selected)] if selected else [],
            probable_entry_points=[
                entity_id
                for entity_id, belief in selected.items()
                if belief.entity_type == "asset"
            ][:3],
            probable_targets=[
                entity_id
                for entity_id, belief in selected.items()
                if belief.compromise_probability >= self.compromise_threshold
            ][:3],
            overall_stage_distribution=overall,
            overall_confidence=confidence,
            uncertainty=max(
                [belief.uncertainty for belief in selected.values()],
                default=1.0,
            ),
            evidence_ids=sorted(evidence_ids),
            created_at=now,
            last_updated=now,
        )

    def create_snapshot(self) -> BeliefSnapshot:
        """Create deterministic belief snapshot."""
        timestamp = self.last_updated or utc_now()
        return BeliefSnapshot(
            belief_version=self.version,
            timestamp=timestamp,
            entity_beliefs={
                key: self.entity_beliefs[key]
                for key in sorted(self.entity_beliefs)
            },
            evidence={key: self.evidence[key] for key in sorted(self.evidence)},
            correlations={
                key: self.correlations[key]
                for key in sorted(self.correlations)
            },
            attacker_location_distribution=self.attacker_location_distribution(),
            warnings=sorted(set(self.warnings)),
        )

    def load_snapshot(self, snapshot: BeliefSnapshot) -> None:
        """Restore belief state from snapshot."""
        self.version = snapshot.belief_version
        self.entity_beliefs = dict(snapshot.entity_beliefs)
        self.evidence = dict(snapshot.evidence)
        self.correlations = dict(snapshot.correlations)
        self.warnings = list(snapshot.warnings)
        self.last_updated = snapshot.timestamp

    def attacker_location_distribution(self) -> dict[str, float]:
        """Return attacker location distribution over assets plus unknown."""
        asset_beliefs = [
            belief
            for belief in self.entity_beliefs.values()
            if belief.entity_type == "asset"
            and belief.candidate_attacker_location_probability > 0
        ]
        known_mass = min(
            0.85,
            sum(
                belief.candidate_attacker_location_probability
                for belief in asset_beliefs
            ),
        )
        if not asset_beliefs or known_mass <= 0:
            return {"unknown": 1.0}
        total = sum(
            belief.candidate_attacker_location_probability
            for belief in asset_beliefs
        )
        distribution = {
            belief.entity_id: (
                belief.candidate_attacker_location_probability / total
            )
            * known_mass
            for belief in asset_beliefs
        }
        distribution["unknown"] = 1.0 - known_mass
        return dict(sorted(distribution.items()))

    def _active_evidence_for(
        self,
        entity_id: str,
        reference_time: datetime,
    ) -> list[Evidence]:
        return [
            item
            for item in self.evidence.values()
            if entity_id in item.entity_ids
            and (item.expires_at is None or item.expires_at > reference_time)
        ]

    def _evidence_strength(self, item: Evidence, reference_time: datetime) -> float:
        age = max(0.0, (reference_time - item.last_seen).total_seconds())
        decay_seconds = float(item.attributes.get("decay_seconds", 3600))
        decay = math.exp(-age / max(1.0, decay_seconds))
        return item.score * item.confidence * decay

    def _propagate(
        self,
        direct_beliefs: dict[str, EntityBelief],
        reference_time: datetime,
    ) -> list[str]:
        if self.twin is None or self.propagation_depth <= 0:
            return []
        created: list[str] = []
        frontier = list(direct_beliefs.values())
        visited = {belief.entity_id for belief in frontier}
        for depth in range(self.propagation_depth):
            next_frontier: list[EntityBelief] = []
            for belief in frontier:
                if belief.compromise_probability < self.compromise_threshold:
                    continue
                for relationship in self.twin.active_relationships(
                    at_time=reference_time
                ).values():
                    if relationship.source_entity_id != belief.entity_id:
                        continue
                    target = relationship.target_entity_id
                    if target in visited or target.startswith("credential:"):
                        continue
                    score = (
                        belief.compromise_probability
                        * relationship.confidence
                        * self.propagation_decay
                        / (depth + 1)
                    )
                    if score <= 0.05:
                        continue
                    evidence_id = stable_id(
                        "evidence:inferred",
                        [
                            belief.entity_id,
                            target,
                            relationship.relationship_id,
                            reference_time.isoformat(),
                        ],
                    )
                    self.evidence[evidence_id] = Evidence(
                        evidence_id=evidence_id,
                        event_ids=list(relationship.source_event_ids),
                        entity_ids=[target],
                        rule_id="GRAPH_PROPAGATION",
                        description=(
                            "Inferred graph risk propagated from "
                            f"{belief.entity_id} via {relationship.relationship_type}."
                        ),
                        stage_hints=[belief.most_likely_stage],
                        score=min(score, belief.compromise_probability * 0.7),
                        confidence=relationship.confidence * 0.6,
                        first_seen=reference_time,
                        last_seen=reference_time,
                        expires_at=relationship.expiry_time,
                        attributes={"inferred": True, "depth": depth + 1},
                    )
                    created.append(target)
                    visited.add(target)
                    if target in self.entity_beliefs:
                        next_frontier.append(self.entity_beliefs[target])
            frontier = next_frontier
        return created
