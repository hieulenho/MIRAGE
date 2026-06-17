"""Deterministic probabilistic attack-stage estimator."""

from __future__ import annotations

import math
from datetime import datetime

from mirage.detection.utils import entropy_uncertainty, normalized_stage_distribution
from mirage.domain.schemas import (
    EntityBelief,
    Evidence,
    STAGE_NAMES_V1,
    StageEstimationResult,
    StageScore,
)


DEFAULT_PRIORS = normalized_stage_distribution({"normal": 0.7})
TRANSITION_HINTS = {
    "reconnaissance": {"discovery": 0.05, "initial_access": 0.04},
    "initial_access": {"discovery": 0.05, "credential_access": 0.04},
    "discovery": {"lateral_movement": 0.06, "credential_access": 0.04},
    "credential_access": {"lateral_movement": 0.07, "collection": 0.04},
    "lateral_movement": {"collection": 0.06, "exfiltration": 0.03},
    "collection": {"exfiltration": 0.06, "impact": 0.03},
}


class AttackStageEstimator:
    """Combine evidence, priors, decay, and previous belief into stage scores."""

    def __init__(
        self,
        *,
        stage_priors: dict[str, float] | None = None,
        evidence_decay_seconds: int = 3600,
        transition_weight: float = 0.15,
    ) -> None:
        if evidence_decay_seconds < 1:
            raise ValueError("evidence_decay_seconds must be at least 1")
        self.stage_priors = normalized_stage_distribution(
            stage_priors or {"normal": 0.7, "discovery": 0.05}
        )
        self.evidence_decay_seconds = int(evidence_decay_seconds)
        self.transition_weight = float(transition_weight)

    def estimate(
        self,
        entity_id: str,
        reference_time: datetime,
        evidence: list[Evidence],
        previous_belief: EntityBelief | None = None,
    ) -> StageEstimationResult:
        """Estimate stage distribution for one entity."""
        raw_scores = {
            stage: max(1e-6, self.stage_priors.get(stage, 0.0))
            for stage in STAGE_NAMES_V1
        }
        supporting: dict[str, list[str]] = {stage: [] for stage in STAGE_NAMES_V1}
        contradicting: dict[str, list[str]] = {stage: [] for stage in STAGE_NAMES_V1}
        breakdown: dict[str, float] = {}

        if previous_belief is not None:
            for stage, probability in previous_belief.stage_distribution.items():
                raw_scores[stage] += probability * self.transition_weight
                for next_stage, weight in TRANSITION_HINTS.get(stage, {}).items():
                    raw_scores[next_stage] += probability * weight

        active_evidence = [
            item
            for item in evidence
            if item.expires_at is None or item.expires_at > reference_time
        ]
        for item in active_evidence:
            age = max(0.0, (reference_time - item.last_seen).total_seconds())
            decay = math.exp(-age / self.evidence_decay_seconds)
            contribution = item.score * item.confidence * decay
            breakdown[item.evidence_id] = round(contribution, 6)
            if item.attributes.get("suppression") or contribution < 0:
                raw_scores["normal"] += abs(contribution)
                for stage in item.stage_hints:
                    if stage in raw_scores and stage != "normal":
                        raw_scores[stage] = max(
                            1e-6,
                            raw_scores[stage] - abs(contribution) * 0.5,
                        )
                        contradicting[stage].append(item.evidence_id)
                supporting["normal"].append(item.evidence_id)
                continue
            for stage in item.stage_hints:
                if stage not in raw_scores:
                    continue
                raw_scores[stage] += contribution
                supporting[stage].append(item.evidence_id)

        distribution = self._softmax(raw_scores)
        most_likely = max(distribution, key=distribution.get)
        uncertainty = entropy_uncertainty(distribution)
        evidence_confidence = max(
            [item.confidence for item in active_evidence],
            default=0.3,
        )
        confidence = min(1.0, (1.0 - uncertainty) * 0.7 + evidence_confidence * 0.3)
        stage_scores = {
            stage: StageScore(
                stage=stage,
                raw_score=raw_scores[stage],
                probability=distribution[stage],
                supporting_evidence_ids=supporting[stage],
                contradicting_evidence_ids=contradicting[stage],
                last_updated=reference_time,
            )
            for stage in STAGE_NAMES_V1
        }
        return StageEstimationResult(
            entity_id=entity_id,
            stage_scores=stage_scores,
            stage_distribution=distribution,
            most_likely_stage=most_likely,
            supporting_evidence_ids=sorted(
                {
                    evidence_id
                    for ids in supporting.values()
                    for evidence_id in ids
                }
            ),
            contradicting_evidence_ids=sorted(
                {
                    evidence_id
                    for ids in contradicting.values()
                    for evidence_id in ids
                }
            ),
            uncertainty=uncertainty,
            confidence=confidence,
            score_breakdown=breakdown,
            reference_time=reference_time,
        )

    def _softmax(self, scores: dict[str, float]) -> dict[str, float]:
        max_score = max(scores.values())
        exp_scores = {
            stage: math.exp(value - max_score)
            for stage, value in scores.items()
        }
        total = sum(exp_scores.values())
        return {
            stage: exp_scores[stage] / total
            for stage in STAGE_NAMES_V1
        }
