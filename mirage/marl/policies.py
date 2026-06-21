"""Scripted and lightweight trainable MARL policies."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Iterable

from mirage.marl.schema import (
    BlueObservation,
    RedAction,
    RedActionCategory,
    RedObservation,
)


RED_PROFILE_ORDER = [
    "random",
    "shortest_path",
    "highest_value",
    "credential_focused",
    "stealth",
    "speed",
    "deception_naive",
    "deception_aware",
    "risk_sensitive",
    "goal_switching",
]


class RedAgentPolicy:
    """Mask-aware scripted red policy for graph-simulator actions."""

    def __init__(self, policy_id: str = "red:random", seed: int = 42) -> None:
        self.policy_id = policy_id
        self.profile = policy_id.split(":", 1)[-1]
        self.rng = random.Random(seed)

    def select_action(
        self,
        observation: RedObservation,
        actions: list[RedAction],
        valid_action_ids: Iterable[str] | None = None,
    ) -> str:
        valid = set(valid_action_ids or [action.action_id for action in actions])
        candidates = [action for action in actions if action.action_id in valid]
        if not candidates:
            return "red:wait"
        if self.profile == "random":
            return self.rng.choice(candidates).action_id
        scored = [(self._score(observation, action), action.action_id) for action in candidates]
        scored.sort(key=lambda item: (item[0], item[1]), reverse=True)
        return scored[0][1]

    def _score(self, observation: RedObservation, action: RedAction) -> float:
        value_hint = float(action.metadata.get("target_value_hint", 0.0))
        difficulty = float(action.metadata.get("edge_difficulty", 0.4))
        category = action.category
        score = value_hint + action.success_probability - action.noise * 0.4
        if self.profile == "shortest_path":
            preferences = {
                RedActionCategory.MOVE_ALONG_EDGE: 2.0,
                RedActionCategory.DISCOVER_NEIGHBOR: 1.2,
                RedActionCategory.RECON: 0.6,
            }
            score += preferences.get(category, 0.0) - difficulty
        elif self.profile == "highest_value":
            score += value_hint * 2.0
        elif self.profile == "credential_focused":
            if category in {
                RedActionCategory.USE_SIMULATED_CREDENTIAL,
                RedActionCategory.INSPECT_SERVICE,
            }:
                score += 2.0
        elif self.profile == "stealth":
            score += (1.0 - action.noise) * 1.6
            if category == RedActionCategory.REDUCE_NOISE:
                score += 2.5
        elif self.profile == "speed":
            if category in {
                RedActionCategory.MOVE_ALONG_EDGE,
                RedActionCategory.INCREASE_SPEED,
                RedActionCategory.COLLECT_SYNTHETIC_OBJECTIVE,
            }:
                score += 1.8
        elif self.profile == "deception_naive":
            score += value_hint * 1.4
        elif self.profile == "deception_aware":
            recent_targets = " ".join(observation.recent_blue_actions)
            if action.target_node_id and action.target_node_id in recent_targets:
                score -= 1.5
            score += (1.0 - observation.defender_pressure) * 0.5
        elif self.profile == "risk_sensitive":
            score -= action.noise * 2.2 + observation.defender_pressure
            if category == RedActionCategory.REDUCE_NOISE:
                score += 1.8
        elif self.profile == "goal_switching":
            if category == RedActionCategory.CHANGE_TARGET:
                score += 1.4
            score += value_hint
        if category == RedActionCategory.COLLECT_SYNTHETIC_OBJECTIVE:
            score += 4.0
        if category == RedActionCategory.TERMINATE:
            score -= 2.0
        return score


@dataclass
class MaskedLinearPolicy:
    """Small trainable masked policy over red action categories."""

    policy_id: str
    weights: dict[str, float] = field(default_factory=dict)

    def select_action(self, actions: list[RedAction], valid_action_ids: Iterable[str]) -> str:
        valid = set(valid_action_ids)
        candidates = [action for action in actions if action.action_id in valid]
        if not candidates:
            return "red:wait"
        return max(
            candidates,
            key=lambda action: (
                self.weights.get(action.category.value, 0.0)
                + float(action.metadata.get("target_value_hint", 0.0))
                - action.noise * 0.2,
                action.action_id,
            ),
        ).action_id

    def train_step(self, actions: list[RedAction], returns: list[float], lr: float = 0.05) -> None:
        for action, value in zip(actions, returns):
            current = self.weights.get(action.category.value, 0.0)
            self.weights[action.category.value] = current + lr * float(value)


class BlueMARLPolicyAdapter:
    """Mask-aware blue policy over synthetic CandidateDefenseAction objects."""

    def __init__(self, policy_id: str = "blue:shadow_heuristic") -> None:
        self.policy_id = policy_id

    def select_action(self, observation: BlueObservation) -> str:
        allowed = [
            action
            for action in observation.candidate_actions
            if observation.action_masks.get(action.action_id)
            and observation.action_masks[action.action_id].allowed
        ]
        if not allowed:
            return "blue:noop"
        return max(
            allowed,
            key=lambda action: (
                action.expected_risk_reduction * 1.4
                + action.expected_information_gain * 0.8
                + observation.detection_confidence * 0.2
                - action.operational_cost * 0.12
                - action.business_risk * 0.6,
                action.action_id,
            ),
        ).action_id


def scripted_red_policies(seed: int = 42) -> list[RedAgentPolicy]:
    """Return the default scripted red population."""
    return [
        RedAgentPolicy(f"red:{profile}", seed=seed + index)
        for index, profile in enumerate(RED_PROFILE_ORDER)
    ]
