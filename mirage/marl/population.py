"""Opponent population utilities for self-play."""

from __future__ import annotations

import random

from mirage.marl.policies import RedAgentPolicy, scripted_red_policies
from mirage.marl.schema import OpponentMetadata


class OpponentPopulation:
    """Small in-memory opponent population."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)
        self._red_policies: dict[str, RedAgentPolicy] = {}
        self._metadata: dict[str, OpponentMetadata] = {}

    def add_scripted_defaults(self) -> None:
        for policy in scripted_red_policies():
            self.add_red_policy(policy, policy_type="scripted")

    def add_red_policy(self, policy: RedAgentPolicy, policy_type: str = "scripted") -> None:
        self._red_policies[policy.policy_id] = policy
        self._metadata[policy.policy_id] = OpponentMetadata(
            opponent_id=policy.policy_id,
            role="red",
            policy_type=policy_type,
        )

    def sample_red(self) -> RedAgentPolicy:
        if not self._red_policies:
            self.add_scripted_defaults()
        policies = sorted(self._red_policies.values(), key=lambda item: item.policy_id)
        return self.rng.choice(policies)

    def update_rating(self, opponent_id: str, delta: float) -> None:
        metadata = self._metadata[opponent_id]
        self._metadata[opponent_id] = metadata.model_copy(
            update={"rating": metadata.rating + float(delta)}
        )

    def list_metadata(self) -> list[OpponentMetadata]:
        return sorted(self._metadata.values(), key=lambda item: item.opponent_id)

    def get_red(self, policy_id: str) -> RedAgentPolicy:
        return self._red_policies[policy_id]
