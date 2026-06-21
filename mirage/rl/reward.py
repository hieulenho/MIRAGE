"""Explicit reward and hard-constraint model for offline RL."""

from __future__ import annotations

import math
from typing import Any

from mirage.rl.schema import BlueTeamTactic, CandidateActionFeature, EncodedRLState, RewardBreakdown


DEFAULT_REWARD_WEIGHTS = {
    "asset_protection_reward": 1.0,
    "interception_reward": 1.2,
    "attacker_delay_reward": 0.4,
    "information_gain_reward": 0.35,
    "risk_reduction_reward": 1.0,
    "safe_deception_reward": 0.6,
    "analyst_acceptance_reward": 0.3,
    "asset_loss_penalty": 1.4,
    "business_impact_penalty": 0.8,
    "operational_cost_penalty": 0.25,
    "false_positive_penalty": 0.8,
    "unnecessary_action_penalty": 0.35,
    "policy_instability_penalty": 0.2,
    "irreversible_action_penalty": 0.45,
    "stale_recommendation_penalty": 0.4,
    "analyst_rejection_penalty": 0.5,
}


HARD_CONSTRAINTS = {
    "masked_action_selection",
    "protected_asset_without_approval",
    "external_or_hackback_action",
    "missing_required_rollback",
    "blast_radius_limit_exceeded",
    "managed_boundary_exceeded",
    "kill_switch_bypassed",
    "execution_without_required_approval",
}


def _clamp(value: float, low: float, high: float) -> float:
    if not math.isfinite(float(value)):
        return 0.0
    return max(low, min(high, float(value)))


class DefenseRewardModel:
    """Auditable configurable reward model.

    Hard constraints are recorded separately and never offset by positive reward.
    """

    def __init__(
        self,
        weights: dict[str, float] | None = None,
        *,
        clip_min: float = -5.0,
        clip_max: float = 5.0,
        version: str = "defense_reward_v1",
    ) -> None:
        self.weights = dict(DEFAULT_REWARD_WEIGHTS)
        self.weights.update(weights or {})
        self.clip_min = float(clip_min)
        self.clip_max = float(clip_max)
        self.version = version

    def compute(
        self,
        state: EncodedRLState | None,
        action: CandidateActionFeature,
        next_state: EncodedRLState | None = None,
        outcome: dict[str, Any] | None = None,
    ) -> RewardBreakdown:
        outcome = outcome or {}
        violations = self.hard_constraint_violations(state, action, outcome)
        tactic = action.tactic_category
        risk_delta = float(outcome.get("risk_reduction", action.expected_risk_reduction))
        info_gain = float(outcome.get("information_gain", action.information_gain))
        if state is not None and next_state is not None:
            try:
                current_max_risk = state.feature_vector[state.feature_schema.state_feature_names.index("max_path_risk")]
                next_max_risk = next_state.feature_vector[next_state.feature_schema.state_feature_names.index("max_path_risk")]
                risk_delta = max(risk_delta, float(current_max_risk) - float(next_max_risk))
            except (ValueError, IndexError):
                pass
        breakdown = RewardBreakdown(
            asset_protection_reward=1.0 if outcome.get("protected_asset_safe", True) else 0.0,
            interception_reward=float(outcome.get("decoy_interception", 0.0)),
            attacker_delay_reward=_clamp(float(outcome.get("delay_delta", 0.0)), 0.0, 1.0),
            information_gain_reward=_clamp(info_gain, 0.0, 1.0),
            risk_reduction_reward=_clamp(risk_delta, 0.0, 1.0),
            safe_deception_reward=(
                _clamp(action.confidence - action.business_risk, 0.0, 1.0)
                if tactic == BlueTeamTactic.DECEIVE
                else 0.0
            ),
            analyst_acceptance_reward=1.0 if outcome.get("analyst_decision") == "ACCEPT" else 0.0,
            asset_loss_penalty=float(outcome.get("asset_loss", 0.0)),
            business_impact_penalty=action.business_risk + float(outcome.get("business_impact", 0.0)),
            operational_cost_penalty=action.operational_cost,
            false_positive_penalty=float(outcome.get("false_positive", 0.0)),
            unnecessary_action_penalty=(
                0.35
                if action.expected_risk_reduction < 0.05
                and tactic not in {BlueTeamTactic.OBSERVE, BlueTeamTactic.ESCALATE, BlueTeamTactic.NO_OP}
                else 0.0
            ),
            policy_instability_penalty=float(outcome.get("policy_instability", 0.0)),
            irreversible_action_penalty=0.0 if action.reversibility >= 0.5 else 1.0,
            stale_recommendation_penalty=float(outcome.get("stale_recommendation", 0.0)),
            analyst_rejection_penalty=1.0 if outcome.get("analyst_decision") in {"REJECT", "UNSAFE", "IRRELEVANT"} else 0.0,
            hard_constraint_violations=violations,
        )
        scalar = 0.0
        for name, value in breakdown.components().items():
            weight = float(self.weights.get(name, 1.0))
            if name.endswith("_penalty"):
                scalar -= weight * abs(float(value))
            else:
                scalar += weight * float(value)
        if violations:
            scalar = min(scalar, -1.0 * len(violations))
        clipped = scalar < self.clip_min or scalar > self.clip_max
        scalar = _clamp(scalar, self.clip_min, self.clip_max)
        return breakdown.model_copy(update={"scalar_reward": round(scalar, 6), "clipped": clipped})

    def hard_constraint_violations(
        self,
        state: EncodedRLState | None,
        action: CandidateActionFeature,
        outcome: dict[str, Any] | None = None,
    ) -> list[str]:
        outcome = outcome or {}
        violations: list[str] = []
        if action.action_mask_status != "allowed":
            violations.append("masked_action_selection")
        if outcome.get("protected_asset_modified") and action.approval_required:
            violations.append("protected_asset_without_approval")
        if outcome.get("external_or_hackback"):
            violations.append("external_or_hackback_action")
        if action.reversibility <= 0.0 and action.tactic_category in {
            BlueTeamTactic.DELAY,
            BlueTeamTactic.LIMITED_CONTAIN,
        }:
            violations.append("missing_required_rollback")
        if outcome.get("blast_radius_exceeded"):
            violations.append("blast_radius_limit_exceeded")
        if outcome.get("managed_boundary_exceeded"):
            violations.append("managed_boundary_exceeded")
        if outcome.get("kill_switch_enabled") and outcome.get("would_execute"):
            violations.append("kill_switch_bypassed")
        if action.approval_required and outcome.get("executed_without_approval"):
            violations.append("execution_without_required_approval")
        return sorted(set(violations))

    def ablate(self, disabled_components: list[str]) -> "DefenseRewardModel":
        weights = dict(self.weights)
        for name in disabled_components:
            if name in weights:
                weights[name] = 0.0
        return DefenseRewardModel(weights, clip_min=self.clip_min, clip_max=self.clip_max, version=self.version)


def reward_quality_report(transitions) -> dict[str, Any]:
    rewards = [float(t.scalar_reward) for t in transitions]
    clipped = [t.reward_components.clipped for t in transitions]
    by_action: dict[str, list[float]] = {}
    by_policy: dict[str, list[float]] = {}
    violations = 0
    for transition in transitions:
        selected = next(
            (feature for feature in transition.candidate_action_features if feature.action_id == transition.selected_action_id),
            None,
        )
        action_type = selected.action_type if selected is not None else "__NO_OP__"
        by_action.setdefault(action_type, []).append(transition.scalar_reward)
        by_policy.setdefault(transition.behavior_policy_source, []).append(transition.scalar_reward)
        violations += len(transition.hard_constraint_violations)
    def stats(values: list[float]) -> dict[str, float]:
        if not values:
            return {"count": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}
        return {
            "count": float(len(values)),
            "mean": round(sum(values) / len(values), 6),
            "min": round(min(values), 6),
            "max": round(max(values), 6),
        }
    return {
        "reward_distribution": stats(rewards),
        "reward_by_action_type": {key: stats(value) for key, value in sorted(by_action.items())},
        "reward_by_policy_source": {key: stats(value) for key, value in sorted(by_policy.items())},
        "reward_clipping_frequency": round(sum(1 for value in clipped if value) / max(1, len(clipped)), 6),
        "hard_constraint_violation_count": violations,
        "contradictory_reward_frequency": round(
            sum(1 for transition in transitions if transition.hard_constraint_violations and transition.scalar_reward > 0)
            / max(1, len(transitions)),
            6,
        ),
    }
