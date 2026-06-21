"""Conservative baseline policies for offline RL evaluation."""

from __future__ import annotations

import json
import math
import random
from collections import Counter
from pathlib import Path

from mirage.rl.schema import ActionScore, BlueTeamTactic, EncodedRLState, PolicyInferenceResult, RLTransition


def _softmax(scores: list[float]) -> list[float]:
    if not scores:
        return []
    max_score = max(scores)
    exps = [math.exp(max(-50.0, min(50.0, score - max_score))) for score in scores]
    total = sum(exps)
    return [value / total for value in exps]


class HeuristicCandidatePolicy:
    policy_id = "heuristic_ranker"
    policy_version = "v1"

    def recommend(self, state: EncodedRLState) -> PolicyInferenceResult:
        ranked = []
        for feature in state.candidate_action_features:
            masked = feature.action_id not in state.allowed_action_ids or feature.action_mask_status != "allowed"
            score = (
                feature.expected_risk_reduction
                + 0.4 * feature.information_gain
                + 0.3 * feature.path_coverage
                - 0.4 * feature.business_risk
                - 0.2 * feature.uncertainty
                - (10.0 if masked else 0.0)
            )
            ranked.append((score, feature, masked))
        ranked.sort(key=lambda item: (-item[0], item[1].approval_required, item[1].action_id))
        probs = _softmax([score for score, _, masked in ranked if not masked])
        prob_iter = iter(probs)
        scores = []
        for score, feature, masked in ranked:
            scores.append(ActionScore(
                action_id=feature.action_id,
                tactic=feature.tactic_category,
                score=round(score, 6),
                probability=0.0 if masked else next(prob_iter),
                masked=masked,
                reasons=[] if not masked else ["action_mask"],
            ))
        selected = next((item for item in scores if not item.masked), None)
        if selected is None:
            selected_id = "__NO_OP__"
            tactic = BlueTeamTactic.NO_OP
            confidence = 0.0
        else:
            selected_id = selected.action_id
            tactic = selected.tactic
            confidence = selected.probability
        return PolicyInferenceResult(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            state_id=state.state_reference.state_id,
            selected_high_level_tactic=tactic,
            selected_action_id=selected_id,
            ranked_action_scores=scores,
            policy_confidence=round(confidence, 6),
            policy_uncertainty=round(1.0 - confidence, 6),
            fallback_used=False,
            explanation="Deterministic heuristic ranking over allowed candidate actions.",
        )


class RandomSafePolicy:
    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def recommend(self, state: EncodedRLState) -> PolicyInferenceResult:
        allowed = [
            feature for feature in state.candidate_action_features
            if feature.action_id in state.allowed_action_ids and feature.action_mask_status == "allowed"
        ]
        if not allowed:
            selected = None
        else:
            selected = allowed[self.rng.randrange(len(allowed))]
        probability = 1.0 / max(1, len(allowed))
        scores = [
            ActionScore(
                action_id=feature.action_id,
                tactic=feature.tactic_category,
                score=probability if feature in allowed else -10.0,
                probability=probability if feature in allowed else 0.0,
                masked=feature not in allowed,
                reasons=[] if feature in allowed else ["action_mask"],
            )
            for feature in state.candidate_action_features
        ]
        return PolicyInferenceResult(
            policy_id="random_safe",
            policy_version="v1",
            state_id=state.state_reference.state_id,
            selected_high_level_tactic=selected.tactic_category if selected else BlueTeamTactic.NO_OP,
            selected_action_id=selected.action_id if selected else "__NO_OP__",
            ranked_action_scores=scores,
            policy_confidence=probability if selected else 0.0,
            policy_uncertainty=1.0 - (probability if selected else 0.0),
            explanation="Random selection among currently allowed actions.",
        )


class AlwaysObservePolicy:
    def recommend(self, state: EncodedRLState) -> PolicyInferenceResult:
        observe = [
            feature for feature in state.candidate_action_features
            if feature.action_id in state.allowed_action_ids
            and feature.tactic_category in {BlueTeamTactic.OBSERVE, BlueTeamTactic.ESCALATE}
        ]
        if not observe:
            return HeuristicCandidatePolicy().recommend(state).model_copy(
                update={"policy_id": "always_observe", "fallback_used": True, "fallback_reason": "no_observe_action"}
            )
        observe.sort(key=lambda feature: (-feature.information_gain, feature.business_risk, feature.action_id))
        selected = observe[0]
        scores = [
            ActionScore(
                action_id=feature.action_id,
                tactic=feature.tactic_category,
                score=1.0 if feature.action_id == selected.action_id else 0.0,
                probability=1.0 if feature.action_id == selected.action_id else 0.0,
                masked=feature.action_id not in state.allowed_action_ids,
                reasons=[],
            )
            for feature in state.candidate_action_features
        ]
        return PolicyInferenceResult(
            policy_id="always_observe",
            policy_version="v1",
            state_id=state.state_reference.state_id,
            selected_high_level_tactic=selected.tactic_category,
            selected_action_id=selected.action_id,
            ranked_action_scores=scores,
            policy_confidence=1.0,
            policy_uncertainty=0.0,
            explanation="Deterministic observe/escalate baseline.",
        )


class BehaviorCloningPolicy:
    """Mask-aware per-action scorer trained from selected candidate features."""

    def __init__(self) -> None:
        self.action_type_scores: Counter[str] = Counter()
        self.tactic_scores: Counter[str] = Counter()
        self.feature_weights: list[float] = []
        self.policy_id = "behavior_cloning"
        self.policy_version = "v1"

    def fit(self, transitions: list[RLTransition]) -> "BehaviorCloningPolicy":
        positives: list[list[float]] = []
        negatives: list[list[float]] = []
        for transition in transitions:
            for feature in transition.candidate_action_features:
                if feature.action_id == transition.selected_action_id:
                    self.action_type_scores[feature.action_type] += 1
                    self.tactic_scores[feature.tactic_category.value] += 1
                    positives.append(feature.encoded_feature_vector)
                else:
                    negatives.append(feature.encoded_feature_vector)
        if positives:
            dim = len(positives[0])
            pos_mean = [sum(row[i] for row in positives) / len(positives) for i in range(dim)]
            neg_mean = [sum(row[i] for row in negatives) / max(1, len(negatives)) for i in range(dim)]
            self.feature_weights = [round(pos_mean[i] - neg_mean[i], 6) for i in range(dim)]
        return self

    def score_feature(self, feature) -> float:
        dot = sum(w * x for w, x in zip(self.feature_weights, feature.encoded_feature_vector, strict=False))
        dot += math.log1p(self.action_type_scores.get(feature.action_type, 0))
        dot += 0.5 * math.log1p(self.tactic_scores.get(feature.tactic_category.value, 0))
        return dot

    def recommend(self, state: EncodedRLState) -> PolicyInferenceResult:
        ranked = []
        for feature in state.candidate_action_features:
            masked = feature.action_id not in state.allowed_action_ids or feature.action_mask_status != "allowed"
            score = self.score_feature(feature) - (10.0 if masked else 0.0)
            ranked.append((score, feature, masked))
        ranked.sort(key=lambda item: (-item[0], item[1].business_risk, item[1].action_id))
        valid_scores = [score for score, _, masked in ranked if not masked]
        probs = _softmax(valid_scores)
        prob_iter = iter(probs)
        action_scores = []
        for score, feature, masked in ranked:
            action_scores.append(ActionScore(
                action_id=feature.action_id,
                tactic=feature.tactic_category,
                score=round(score, 6),
                probability=0.0 if masked else next(prob_iter),
                masked=masked,
                reasons=[] if not masked else ["action_mask"],
            ))
        selected = next((score for score in action_scores if not score.masked), None)
        return PolicyInferenceResult(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            state_id=state.state_reference.state_id,
            selected_high_level_tactic=selected.tactic if selected else BlueTeamTactic.NO_OP,
            selected_action_id=selected.action_id if selected else "__NO_OP__",
            ranked_action_scores=action_scores,
            policy_confidence=selected.probability if selected else 0.0,
            policy_uncertainty=1.0 - (selected.probability if selected else 0.0),
            explanation="Behavior-cloning per-action masked scorer.",
        )

    def save(self, path: str) -> None:
        target = Path(path)
        target.mkdir(parents=True, exist_ok=True)
        payload = {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "action_type_scores": dict(self.action_type_scores),
            "tactic_scores": dict(self.tactic_scores),
            "feature_weights": self.feature_weights,
        }
        (target / "policy.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "BehaviorCloningPolicy":
        payload = json.loads((Path(path) / "policy.json").read_text(encoding="utf-8"))
        policy = cls()
        policy.policy_id = payload.get("policy_id", policy.policy_id)
        policy.policy_version = payload.get("policy_version", policy.policy_version)
        policy.action_type_scores.update(payload.get("action_type_scores", {}))
        policy.tactic_scores.update(payload.get("tactic_scores", {}))
        policy.feature_weights = [float(value) for value in payload.get("feature_weights", [])]
        return policy


class HierarchicalBehaviorCloningPolicy(BehaviorCloningPolicy):
    """Behavior cloning with explicit tactic then action selection."""

    def __init__(self) -> None:
        super().__init__()
        self.policy_id = "hierarchical_behavior_cloning"

    def recommend(self, state: EncodedRLState) -> PolicyInferenceResult:
        available_tactics = {
            feature.tactic_category
            for feature in state.candidate_action_features
            if feature.action_id in state.allowed_action_ids and feature.action_mask_status == "allowed"
        }
        if not available_tactics:
            return super().recommend(state)
        tactic_order = sorted(
            available_tactics,
            key=lambda tactic: (-self.tactic_scores.get(tactic.value, 0), tactic.value),
        )
        selected_tactic = tactic_order[0]
        tactic_features = [
            feature for feature in state.candidate_action_features
            if feature.tactic_category == selected_tactic
        ]
        scoped = state.model_copy(update={"candidate_action_features": tactic_features})
        result = super().recommend(scoped)
        all_scores = {score.action_id: score for score in result.ranked_action_scores}
        for feature in state.candidate_action_features:
            if feature.action_id not in all_scores:
                all_scores[feature.action_id] = ActionScore(
                    action_id=feature.action_id,
                    tactic=feature.tactic_category,
                    score=-10.0,
                    probability=0.0,
                    masked=True,
                    reasons=["tactic_filter"],
                )
        return result.model_copy(
            update={
                "policy_id": self.policy_id,
                "selected_high_level_tactic": selected_tactic,
                "ranked_action_scores": sorted(all_scores.values(), key=lambda item: (-item.probability, item.action_id)),
                "explanation": "Hierarchical behavior cloning: tactic classifier followed by masked action scorer.",
            }
        )
