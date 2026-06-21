"""Conservative hierarchical offline RL policy."""

from __future__ import annotations

import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from mirage.rl.analysis import ActionSupportModel
from mirage.rl.baselines import HierarchicalBehaviorCloningPolicy, HeuristicCandidatePolicy, _softmax
from mirage.rl.schema import (
    ActionScore,
    BlueTeamTactic,
    EncodedRLState,
    PolicyInferenceResult,
    RLTransition,
    TrainingMetrics,
)


class OfflineBlueTeamPolicy:
    """Small discrete offline policy with conservative support constraints.

    The implementation is intentionally compact and CPU-safe.  It uses
    behavior-cloning initialization, empirical conservative Q estimates, and
    advantage-weighted masked ranking over the current candidate set.
    """

    def __init__(
        self,
        *,
        policy_id: str = "offline_blue_team_policy",
        policy_version: str = "v1",
        min_support_threshold: float = 0.05,
        uncertainty_threshold: float = 0.65,
        advantage_temperature: float = 1.0,
        q_clip: float = 5.0,
    ) -> None:
        self.policy_id = policy_id
        self.policy_version = policy_version
        self.min_support_threshold = float(min_support_threshold)
        self.uncertainty_threshold = float(uncertainty_threshold)
        self.advantage_temperature = float(advantage_temperature)
        self.q_clip = float(q_clip)
        self.bc = HierarchicalBehaviorCloningPolicy()
        self.action_q: defaultdict[str, list[float]] = defaultdict(list)
        self.tactic_q: defaultdict[str, list[float]] = defaultdict(list)
        self.action_type_q: defaultdict[str, list[float]] = defaultdict(list)
        self.support = ActionSupportModel()
        self.training_steps = 0
        self.training_history: list[dict[str, Any]] = []

    def fit(self, transitions: list[RLTransition]) -> "OfflineBlueTeamPolicy":
        self.bc.fit(transitions)
        self.support.fit(transitions)
        for transition in transitions:
            reward = max(-self.q_clip, min(self.q_clip, transition.scalar_reward))
            self.action_q[transition.selected_action_id].append(reward)
            self.tactic_q[transition.selected_high_level_tactic.value].append(reward)
            selected_feature = next(
                (feature for feature in transition.candidate_action_features if feature.action_id == transition.selected_action_id),
                None,
            )
            if selected_feature is not None:
                self.action_type_q[selected_feature.action_type].append(reward)
        return self

    def train_step(self, batch: list[RLTransition]) -> TrainingMetrics:
        if not batch:
            return TrainingMetrics(step=self.training_steps, warnings=["empty_batch"])
        before = self._mean_q()
        self.fit(batch)
        self.training_steps += 1
        rewards = [transition.scalar_reward for transition in batch]
        after = self._mean_q()
        entropy = _entropy([len(values) for values in self.action_q.values()])
        support_penalty = sum(
            1.0
            for transition in batch
            if self.support.unsupported(
                transition.state_feature_vector,
                transition.selected_action_id,
                transition.selected_high_level_tactic,
                self.min_support_threshold,
            )
        ) / max(1, len(batch))
        metrics = TrainingMetrics(
            step=self.training_steps,
            loss=round(abs(after - before), 6),
            policy_loss=round(max(0.0, before - after), 6),
            q_loss=round(abs(after - sum(rewards) / len(rewards)), 6),
            value_loss=0.0,
            entropy=round(entropy, 6),
            mean_reward=round(sum(rewards) / len(rewards), 6),
            support_penalty=round(support_penalty, 6),
        )
        self.training_history.append(metrics.model_dump(mode="json"))
        return metrics

    def select_tactic(
        self,
        state: EncodedRLState,
        available_tactics: list[BlueTeamTactic] | None = None,
    ) -> tuple[BlueTeamTactic, float, float]:
        available = available_tactics or sorted({
            feature.tactic_category
            for feature in state.candidate_action_features
            if feature.action_id in state.allowed_action_ids and feature.action_mask_status == "allowed"
        }, key=lambda tactic: tactic.value)
        if not available:
            return BlueTeamTactic.NO_OP, 0.0, 1.0
        scored = []
        for tactic in available:
            q = self._avg(self.tactic_q.get(tactic.value, []))
            support = self.support.tactic_counts.get(tactic.value, 0) / max(1, self.support.total)
            uncertainty = 1.0 - min(1.0, support * 4.0)
            scored.append((q - uncertainty * 0.2, tactic, uncertainty))
        scored.sort(key=lambda item: (-item[0], item[1].value))
        probs = _softmax([item[0] for item in scored])
        return scored[0][1], probs[0] if probs else 0.0, scored[0][2]

    def rank_actions(
        self,
        state: EncodedRLState,
        candidate_actions=None,
        action_masks=None,
        selected_tactic: BlueTeamTactic | None = None,
    ) -> list[ActionScore]:
        tactic = selected_tactic
        ranked = []
        for feature in state.candidate_action_features:
            masked = feature.action_id not in state.allowed_action_ids or feature.action_mask_status != "allowed"
            if tactic is not None and tactic != BlueTeamTactic.NO_OP and feature.tactic_category != tactic:
                masked = True
                reason = "tactic_filter"
            else:
                reason = "action_mask"
            support_score = self.support.score(state.feature_vector, feature.action_id, feature.tactic_category)
            q = max(
                self._avg(self.action_q.get(feature.action_id, [])),
                self._avg(self.action_type_q.get(feature.action_type, [])),
                self._avg(self.tactic_q.get(feature.tactic_category.value, [])),
            )
            bc_score = self.bc.score_feature(feature)
            uncertainty_penalty = feature.uncertainty + max(0.0, self.min_support_threshold - support_score)
            score = (
                q
                + 0.25 * bc_score
                + feature.expected_risk_reduction
                - 0.8 * feature.business_risk
                - 0.4 * uncertainty_penalty
                - (10.0 if masked else 0.0)
            )
            ranked.append((score, feature, masked, support_score, reason))
        ranked.sort(key=lambda item: (-item[0], item[1].business_risk, item[1].action_id))
        valid_scores = [score for score, _, masked, _, _ in ranked if not masked]
        probs = _softmax(valid_scores)
        prob_iter = iter(probs)
        return [
            ActionScore(
                action_id=feature.action_id,
                tactic=feature.tactic_category,
                score=round(score, 6),
                probability=0.0 if masked else next(prob_iter),
                support_score=round(support_score, 6),
                masked=masked,
                reasons=[] if not masked else [reason],
            )
            for score, feature, masked, support_score, reason in ranked
        ]

    def recommend(self, state: EncodedRLState) -> PolicyInferenceResult:
        tactic, tactic_confidence, tactic_uncertainty = self.select_tactic(state)
        scores = self.rank_actions(state, selected_tactic=tactic)
        selected = next((score for score in scores if not score.masked), None)
        warnings: list[str] = []
        fallback = False
        fallback_reason = ""
        if selected is None:
            fallback = True
            fallback_reason = "no_valid_action_under_tactic"
            fallback_result = self.bc.recommend(state)
            if fallback_result.selected_action_id == "__NO_OP__":
                fallback_result = HeuristicCandidatePolicy().recommend(state)
            return fallback_result.model_copy(
                update={
                    "policy_id": self.policy_id,
                    "policy_version": self.policy_version,
                    "fallback_used": True,
                    "fallback_reason": fallback_reason,
                    "explanation": "Offline RL had no valid action under selected tactic; fallback used.",
                }
            )
        if selected.support_score < self.min_support_threshold:
            fallback = True
            fallback_reason = "low_action_support"
        if selected.probability < 0.05 or tactic_uncertainty > self.uncertainty_threshold:
            fallback = True
            fallback_reason = fallback_reason or "high_policy_uncertainty"
        if fallback:
            fallback_result = self.bc.recommend(state)
            if fallback_result.selected_action_id == "__NO_OP__":
                fallback_result = HeuristicCandidatePolicy().recommend(state)
            warnings.append(f"rl_fallback:{fallback_reason}")
            return fallback_result.model_copy(
                update={
                    "policy_id": self.policy_id,
                    "policy_version": self.policy_version,
                    "fallback_used": True,
                    "fallback_reason": fallback_reason,
                    "ood_warnings": warnings,
                    "explanation": "Conservative offline RL fallback to behavior cloning or heuristic ranker.",
                }
            )
        confidence = min(selected.probability, tactic_confidence)
        uncertainty = max(1.0 - confidence, tactic_uncertainty)
        return PolicyInferenceResult(
            policy_id=self.policy_id,
            policy_version=self.policy_version,
            state_id=state.state_reference.state_id,
            selected_high_level_tactic=tactic,
            selected_action_id=selected.action_id,
            ranked_action_scores=scores,
            policy_confidence=round(confidence, 6),
            policy_uncertainty=round(uncertainty, 6),
            ood_warnings=warnings,
            fallback_used=False,
            explanation="Conservative hierarchical offline RL recommendation in shadow mode.",
        )

    def save(self, path: str) -> None:
        target = Path(path)
        target.mkdir(parents=True, exist_ok=True)
        self.bc.save(str(target / "bc"))
        payload = {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "min_support_threshold": self.min_support_threshold,
            "uncertainty_threshold": self.uncertainty_threshold,
            "advantage_temperature": self.advantage_temperature,
            "q_clip": self.q_clip,
            "action_q": {key: values for key, values in self.action_q.items()},
            "tactic_q": {key: values for key, values in self.tactic_q.items()},
            "action_type_q": {key: values for key, values in self.action_type_q.items()},
            "support": self.support.to_dict(),
            "training_steps": self.training_steps,
            "training_history": self.training_history,
        }
        (target / "policy.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str) -> "OfflineBlueTeamPolicy":
        source = Path(path)
        payload = json.loads((source / "policy.json").read_text(encoding="utf-8"))
        policy = cls(
            policy_id=payload.get("policy_id", "offline_blue_team_policy"),
            policy_version=payload.get("policy_version", "v1"),
            min_support_threshold=float(payload.get("min_support_threshold", 0.05)),
            uncertainty_threshold=float(payload.get("uncertainty_threshold", 0.65)),
            advantage_temperature=float(payload.get("advantage_temperature", 1.0)),
            q_clip=float(payload.get("q_clip", 5.0)),
        )
        policy.bc = HierarchicalBehaviorCloningPolicy.load(str(source / "bc"))
        policy.action_q.update({key: [float(x) for x in values] for key, values in payload.get("action_q", {}).items()})
        policy.tactic_q.update({key: [float(x) for x in values] for key, values in payload.get("tactic_q", {}).items()})
        policy.action_type_q.update({key: [float(x) for x in values] for key, values in payload.get("action_type_q", {}).items()})
        policy.support = ActionSupportModel.from_dict(payload.get("support", {}))
        policy.training_steps = int(payload.get("training_steps", 0))
        policy.training_history = list(payload.get("training_history", []))
        return policy

    def _avg(self, values: list[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    def _mean_q(self) -> float:
        values = [value for bucket in self.action_q.values() for value in bucket]
        return self._avg(values)


def _entropy(counts: list[int]) -> float:
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counts:
        if count <= 0:
            continue
        p = count / total
        entropy -= p * math.log(p)
    return entropy
