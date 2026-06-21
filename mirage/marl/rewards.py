"""Reward model for MARL cyber-range self-play."""

from __future__ import annotations

from typing import Any

from mirage.marl.schema import (
    MultiAgentRewardBreakdown,
    RangeScenario,
    RangeState,
    RedAction,
    RedActionCategory,
    clamp01,
)


class MultiAgentRewardModel:
    """Compute auditable red and blue reward components."""

    def compute(
        self,
        *,
        scenario: RangeScenario,
        previous: RangeState,
        current: RangeState,
        red_action: RedAction | None,
        blue_action_id: str,
        info: dict[str, Any],
    ) -> MultiAgentRewardBreakdown:
        red_invalid = bool(info.get("red_invalid", False))
        blue_invalid = bool(info.get("blue_invalid", False))
        discovered_delta = max(
            0,
            len(current.discovered_node_ids) - len(previous.discovered_node_ids),
        )
        moved = bool(info.get("red_moved", False))
        objective = current.terminal_reason == "objective_collected"
        intercepted = current.terminal_reason in {
            "intercepted_by_deception",
            "red_detected",
            "contained_by_blue",
        }
        protected_remaining = sum(
            1
            for node in scenario.nodes
            if node.protected and node.node_id not in current.compromised_node_ids
        )
        protected_total = max(1, sum(1 for node in scenario.nodes if node.protected))
        hard_violations: list[str] = []
        if red_invalid:
            hard_violations.append("invalid_red_action")
        if blue_invalid:
            hard_violations.append("invalid_blue_action")
        if info.get("blue_execution_mode") != "shadow":
            hard_violations.append("blue_execution_not_shadow")

        red_progress = 0.08 * discovered_delta + (0.12 if moved else 0.0)
        if red_action and red_action.category == RedActionCategory.INTERACT_WITH_RESOURCE:
            red_progress += 0.05
        return MultiAgentRewardBreakdown(
            red_progress=round(red_progress, 6),
            red_objective=1.0 if objective else 0.0,
            red_stealth=round(0.12 * (1.0 - current.detection_score), 6),
            red_noise_penalty=round(current.noise_level * 0.2, 6),
            red_invalid_action_penalty=1.0 if red_invalid else 0.0,
            blue_asset_protection=round(protected_remaining / protected_total, 6),
            blue_detection=round(
                max(0.0, current.detection_score - previous.detection_score) * 0.8,
                6,
            ),
            blue_deception=0.8 if intercepted else 0.0,
            blue_delay=0.2 if info.get("red_delayed", False) else 0.0,
            blue_cost_penalty=round(clamp01(float(info.get("blue_cost", 0.0)) / 5.0), 6),
            blue_invalid_action_penalty=1.0 if blue_invalid else 0.0,
            hard_constraint_violations=hard_violations,
        )
