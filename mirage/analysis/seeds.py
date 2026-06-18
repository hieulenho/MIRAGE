"""Seed entity selection for local attack analysis."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from mirage.analysis.utils import canonical_entity_type, clamp01, recency_score, stable_id
from mirage.domain.schemas import BeliefSnapshot, IncidentBelief, SeedEntity


STAGE_SEVERITY = {
    "normal": 0.0,
    "reconnaissance": 0.15,
    "initial_access": 0.45,
    "execution": 0.50,
    "persistence": 0.55,
    "privilege_escalation": 0.70,
    "defense_evasion": 0.65,
    "credential_access": 0.75,
    "discovery": 0.40,
    "lateral_movement": 0.80,
    "collection": 0.85,
    "command_and_control": 0.70,
    "exfiltration": 0.95,
    "impact": 1.0,
}


class SeedEntitySelector:
    """Select deterministic high-value entities for bounded local analysis."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.minimum_compromise = float(
            self.config.get("minimum_compromise_probability", 0.30)
        )
        self.minimum_location = float(
            self.config.get("minimum_attacker_location_probability", 0.20)
        )
        self.uncertainty_penalty = float(self.config.get("uncertainty_penalty", 0.20))
        self.deception_priority = float(self.config.get("deception_event_priority", 0.25))
        self.neighborhood_deduplication = bool(
            self.config.get("neighborhood_deduplication", True)
        )

    def select(
        self,
        belief_snapshot: BeliefSnapshot,
        incident_beliefs: Iterable[IncidentBelief] | None = None,
        reference_time: datetime | None = None,
        limit: int = 20,
    ) -> list[SeedEntity]:
        """Return top seed entities with auditable reasons."""
        reference = reference_time or belief_snapshot.timestamp
        incident_ids = {
            entity_id
            for incident in incident_beliefs or []
            for entity_id in incident.entity_beliefs
        }
        candidates: list[SeedEntity] = []
        for entity_id, belief in belief_snapshot.entity_beliefs.items():
            if entity_id == "unknown":
                continue
            evidence = [
                belief_snapshot.evidence[evidence_id]
                for evidence_id in belief.evidence_ids
                if evidence_id in belief_snapshot.evidence
            ]
            deception = any(
                item.rule_id == "R008_DECEPTION_INTERACTION" for item in evidence
            )
            direct = any(not item.attributes.get("inferred") for item in evidence)
            inferred_only = bool(evidence) and not direct
            max_confidence = max([item.confidence for item in evidence], default=belief.confidence)
            max_recency = max(
                [
                    recency_score(reference, item.last_seen, 3600)
                    for item in evidence
                ],
                default=0.2,
            )
            stage_severity = STAGE_SEVERITY.get(belief.most_likely_stage, 0.2)
            if (
                belief.compromise_probability < self.minimum_compromise
                and belief.candidate_attacker_location_probability < self.minimum_location
                and not deception
                and entity_id not in incident_ids
            ):
                continue
            priority = (
                0.38 * belief.compromise_probability
                + 0.25 * belief.candidate_attacker_location_probability
                + 0.12 * max_confidence
                + 0.10 * max_recency
                + 0.15 * stage_severity
                + (self.deception_priority if deception else 0.0)
                + (0.08 if entity_id in incident_ids else 0.0)
                - self.uncertainty_penalty * belief.uncertainty
                - (0.15 if inferred_only else 0.0)
            )
            reasons = []
            if deception:
                reasons.append("high-confidence deception interaction")
            if belief.compromise_probability >= self.minimum_compromise:
                reasons.append("compromise probability above threshold")
            if belief.candidate_attacker_location_probability >= self.minimum_location:
                reasons.append("candidate attacker location")
            if inferred_only:
                reasons.append("inferred graph risk only")
            if entity_id in incident_ids:
                reasons.append("included in active incident belief")
            candidates.append(
                SeedEntity(
                    entity_id=entity_id,
                    entity_type=canonical_entity_type(entity_id),
                    seed_reason="; ".join(reasons) or "contextual belief priority",
                    compromise_probability=belief.compromise_probability,
                    attacker_location_probability=(
                        belief.candidate_attacker_location_probability
                    ),
                    belief_confidence=belief.confidence,
                    belief_uncertainty=belief.uncertainty,
                    most_likely_stage=belief.most_likely_stage,
                    supporting_evidence_ids=belief.evidence_ids,
                    priority_score=clamp01(priority),
                    selected_at=reference,
                )
            )
        candidates.sort(
            key=lambda seed: (
                -seed.priority_score,
                -seed.compromise_probability,
                seed.entity_type,
                seed.entity_id,
            )
        )
        if self.neighborhood_deduplication:
            candidates = self._dedupe_neighborhoods(candidates)
        return candidates[: max(1, int(limit))]

    def _dedupe_neighborhoods(self, seeds: list[SeedEntity]) -> list[SeedEntity]:
        retained: list[SeedEntity] = []
        seen_keys: set[str] = set()
        for seed in seeds:
            key = self._neighborhood_key(seed.entity_id)
            if key in seen_keys and "deception" not in seed.seed_reason:
                continue
            retained.append(seed)
            seen_keys.add(key)
        return retained

    def _neighborhood_key(self, entity_id: str) -> str:
        if entity_id.startswith("comm:"):
            return stable_id("neighborhood", [entity_id.split(":", 1)[1].split("->", 1)[0]])
        if entity_id.startswith("asset:ip:"):
            octets = entity_id.rsplit(":", 1)[-1].split(".")
            return ".".join(octets[:3]) if len(octets) == 4 else entity_id
        return entity_id
