"""Deterministic synthetic cyber range for MARL self-play."""

from __future__ import annotations

import copy
import random
from typing import Any

from mirage.marl.actions import BlueActionAdapter, RedActionCatalog, action_map
from mirage.marl.observations import MultiAgentObservationAdapter
from mirage.marl.rewards import MultiAgentRewardModel
from mirage.marl.schema import (
    BlueActionKind,
    MultiAgentObservation,
    MultiAgentStepResult,
    RangeIsolationConfig,
    RangeScenario,
    RangeState,
    RedAction,
    RedActionCategory,
    clamp01,
)


class CyberRangeEnvironment:
    """Graph-only adversarial red/blue simulator.

    The environment has no network, shell, exploit, or production adapters.
    Red and blue actions mutate only the in-memory :class:`RangeState`.
    """

    def __init__(
        self,
        scenario: RangeScenario,
        *,
        isolation: RangeIsolationConfig | None = None,
        red_catalog: RedActionCatalog | None = None,
        blue_adapter: BlueActionAdapter | None = None,
        observation_adapter: MultiAgentObservationAdapter | None = None,
        reward_model: MultiAgentRewardModel | None = None,
    ) -> None:
        self.scenario = scenario
        self.isolation = isolation or RangeIsolationConfig(
            max_steps=scenario.max_steps,
            random_seed=scenario.random_seed,
        )
        self.isolation.assert_safe()
        self.red_catalog = red_catalog or RedActionCatalog()
        self.blue_adapter = blue_adapter or BlueActionAdapter()
        self.observation_adapter = observation_adapter or MultiAgentObservationAdapter()
        self.reward_model = reward_model or MultiAgentRewardModel()
        self.state: RangeState | None = None

    def reset(self, *, seed: int | None = None) -> MultiAgentObservation:
        """Reset the scenario and return the first joint observation."""
        self.isolation.assert_safe()
        rng_seed = int(seed if seed is not None else self.scenario.random_seed)
        rng = random.Random(rng_seed)
        entry = rng.choice(self.scenario.entry_node_ids)
        objective = rng.choice(self.scenario.objective_node_ids)
        outgoing = self.scenario.outgoing_edges(entry)
        discovered_edges = [edge.edge_id for edge in outgoing[:1]]
        discovered_nodes = sorted({entry, *(edge.target for edge in outgoing[:1])})
        self.state = RangeState(
            scenario_id=self.scenario.scenario_id,
            step_index=0,
            red_position=entry,
            target_objective_id=objective,
            discovered_node_ids=discovered_nodes,
            discovered_edge_ids=discovered_edges,
            compromised_node_ids=[entry],
            blue_budget_remaining=self.scenario.blue_budget,
            rng_seed=rng_seed,
            last_events=[
                {
                    "event_type": "range_reset",
                    "node_id": entry,
                    "scenario_id": self.scenario.scenario_id,
                }
            ],
        )
        return self.observe()

    def observe(self) -> MultiAgentObservation:
        """Return the current joint observation."""
        if self.state is None:
            return self.reset()
        return self.observation_adapter.encode(self.scenario, self.state)

    def valid_red_actions(self) -> list[RedAction]:
        """Return valid red actions for the current state."""
        state = self._state()
        return self.red_catalog.build(self.scenario, state)

    def valid_blue_action_ids(self) -> list[str]:
        """Return allowed blue action IDs for the current state."""
        state = self._state()
        actions, masks = self.blue_adapter.candidate_actions(self.scenario, state)
        return [
            action.action_id
            for action in actions
            if masks[action.action_id].allowed
        ]

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON-safe state snapshot."""
        return self._state().model_dump(mode="json")

    def restore(self, snapshot: dict[str, Any] | RangeState) -> MultiAgentObservation:
        """Restore a previously serialized state."""
        self.isolation.assert_safe()
        if isinstance(snapshot, RangeState):
            self.state = snapshot.model_copy(deep=True)
        else:
            self.state = RangeState.model_validate(snapshot)
        if self.state.scenario_id != self.scenario.scenario_id:
            raise ValueError("snapshot scenario_id does not match environment")
        return self.observe()

    def replay(self, steps: list[dict[str, str]]) -> list[MultiAgentStepResult]:
        """Replay serialized red/blue action IDs from the current state."""
        results: list[MultiAgentStepResult] = []
        for step in steps:
            results.append(
                self.step(
                    step.get("red_action_id", "red:wait"),
                    step.get("blue_action_id"),
                )
            )
            if results[-1].terminal:
                break
        return results

    def step(
        self,
        red_action_id: str,
        blue_action_id: str | None = None,
    ) -> MultiAgentStepResult:
        """Advance one simultaneous red/blue step."""
        self.isolation.assert_safe()
        previous = self._state().model_copy(deep=True)
        state = self._state().model_copy(deep=True)
        if state.terminal:
            observation = self.observe()
            reward = self.reward_model.compute(
                scenario=self.scenario,
                previous=previous,
                current=state,
                red_action=None,
                blue_action_id=blue_action_id or "blue:noop",
                info={"blue_execution_mode": self.isolation.blue_execution_mode},
            )
            return MultiAgentStepResult(
                observation=observation,
                state=state,
                red_action=None,
                blue_action_id=blue_action_id or "blue:noop",
                reward=reward,
                red_reward=reward.red_total,
                blue_reward=reward.blue_total,
                terminal=True,
                info={"already_terminal": True},
            )

        blue_actions, blue_masks = self.blue_adapter.candidate_actions(
            self.scenario,
            state,
        )
        blue_by_id = action_map(blue_actions)
        if blue_action_id is None:
            blue_action_id = self._default_blue_action_id(blue_actions, blue_masks)
        blue_action = blue_by_id.get(blue_action_id)
        blue_mask = blue_masks.get(blue_action_id)
        blue_invalid = blue_action is None or blue_mask is None or not blue_mask.allowed
        info: dict[str, Any] = {
            "blue_execution_mode": self.isolation.blue_execution_mode,
            "blue_invalid": blue_invalid,
            "blue_cost": 0.0,
        }
        if not blue_invalid and blue_action is not None:
            self._apply_blue_action(state, blue_action_id, blue_action, info)

        red_action = self.red_catalog.get(self.scenario, state, red_action_id)
        red_invalid = red_action is None
        info["red_invalid"] = red_invalid
        if red_action is None:
            state.noise_level = clamp01(state.noise_level + 0.08)
            state.detection_score = clamp01(state.detection_score + 0.08)
            red_event = {
                "event_type": "invalid_red_action",
                "red_action_id": red_action_id,
            }
        else:
            red_event = self._apply_red_action(state, red_action, info)

        state.step_index += 1
        if state.step_index >= min(self.scenario.max_steps, self.isolation.max_steps):
            state.terminal = True
            state.terminal_reason = state.terminal_reason or "max_steps_reached"
        if state.detection_score >= 1.0 and not state.terminal:
            state.terminal = True
            state.terminal_reason = "red_detected"
        state.discovered_node_ids = sorted(set(state.discovered_node_ids))
        state.discovered_edge_ids = sorted(set(state.discovered_edge_ids))
        state.compromised_node_ids = sorted(set(state.compromised_node_ids))
        state.known_credentials = sorted(set(state.known_credentials))
        state.active_decoys = sorted(set(state.active_decoys))
        state.contained_nodes = sorted(set(state.contained_nodes))
        state.hardened_edges = sorted(set(state.hardened_edges))
        state.last_events = [
            {
                "event_type": "blue_shadow_action",
                "blue_action_id": blue_action_id,
                "invalid": blue_invalid,
            },
            red_event,
        ]
        state.history.append(
            {
                "step_index": state.step_index - 1,
                "red_action_id": red_action_id,
                "red_source_node_id": previous.red_position,
                "blue_action_id": blue_action_id,
                "terminal_reason": state.terminal_reason,
            }
        )
        self.state = state
        reward = self.reward_model.compute(
            scenario=self.scenario,
            previous=previous,
            current=state,
            red_action=red_action,
            blue_action_id=blue_action_id,
            info=info,
        )
        return MultiAgentStepResult(
            observation=self.observe(),
            state=state,
            red_action=red_action,
            blue_action_id=blue_action_id,
            reward=reward,
            red_reward=reward.red_total,
            blue_reward=reward.blue_total,
            terminal=state.terminal,
            info=info,
        )

    def _state(self) -> RangeState:
        if self.state is None:
            self.reset()
        assert self.state is not None
        return self.state

    def _default_blue_action_id(self, actions, masks) -> str:
        allowed = [
            action
            for action in actions
            if action.action_id in masks and masks[action.action_id].allowed
        ]
        if not allowed:
            return "blue:noop"
        return max(
            allowed,
            key=lambda action: (
                action.expected_risk_reduction + action.expected_information_gain
                - action.operational_cost * 0.05
            ),
        ).action_id

    def _apply_blue_action(self, state, blue_action_id, blue_action, info) -> None:
        kind = self.blue_adapter.kind_for_action_id(blue_action_id)
        state.blue_budget_remaining = max(
            0.0,
            state.blue_budget_remaining - blue_action.operational_cost,
        )
        info["blue_cost"] = blue_action.operational_cost
        if kind == BlueActionKind.OBSERVE:
            state.detection_score = clamp01(state.detection_score + 0.08)
        elif kind == BlueActionKind.DECEIVE:
            state.active_decoys.extend(blue_action.target_entity_ids)
            state.detection_score = clamp01(state.detection_score + 0.04)
        elif kind == BlueActionKind.DELAY:
            state.hardened_edges.extend(blue_action.affected_edge_ids)
            state.detection_score = clamp01(state.detection_score + 0.03)
            info["red_delayed"] = True
        elif kind == BlueActionKind.LIMITED_CONTAIN:
            state.contained_nodes.extend(blue_action.target_entity_ids)
            state.detection_score = clamp01(state.detection_score + 0.12)
            if state.red_position in blue_action.target_entity_ids:
                state.terminal = True
                state.terminal_reason = "contained_by_blue"
        elif kind == BlueActionKind.ESCALATE:
            state.detection_score = clamp01(state.detection_score + 0.05)

    def _apply_red_action(
        self,
        state: RangeState,
        red_action: RedAction,
        info: dict[str, Any],
    ) -> dict[str, Any]:
        category = red_action.category
        state.noise_level = clamp01(state.noise_level + red_action.noise)
        state.detection_score = clamp01(
            state.detection_score + red_action.noise * 0.35
        )
        success = self._deterministic_success(state, red_action)
        event = {
            "event_type": "red_range_action",
            "red_action_id": red_action.action_id,
            "category": category.value,
            "success": success,
        }
        if state.red_position in state.contained_nodes:
            state.terminal = True
            state.terminal_reason = "contained_by_blue"
            event["success"] = False
            return event
        if category == RedActionCategory.DISCOVER_NEIGHBOR and success:
            if red_action.edge_id:
                state.discovered_edge_ids.append(red_action.edge_id)
            if red_action.target_node_id:
                state.discovered_node_ids.append(red_action.target_node_id)
        elif category == RedActionCategory.RECON:
            for edge in self.scenario.outgoing_edges(state.red_position)[:2]:
                state.discovered_edge_ids.append(edge.edge_id)
                state.discovered_node_ids.append(edge.target)
        elif category == RedActionCategory.INSPECT_SERVICE and success:
            node = self.scenario.node_map()[state.red_position]
            if node.credential_hint:
                state.known_credentials.append(f"cred:{state.red_position}")
        elif category == RedActionCategory.USE_SIMULATED_CREDENTIAL and success:
            if red_action.credential_id:
                state.known_credentials.append(red_action.credential_id)
        elif category == RedActionCategory.MOVE_ALONG_EDGE and success:
            if red_action.target_node_id:
                state.red_position = red_action.target_node_id
                state.compromised_node_ids.append(red_action.target_node_id)
                state.discovered_node_ids.append(red_action.target_node_id)
                info["red_moved"] = True
                target = self.scenario.node_map()[red_action.target_node_id]
                if target.is_decoy or target.node_id in state.active_decoys:
                    state.terminal = True
                    state.terminal_reason = "intercepted_by_deception"
                elif target.protected:
                    state.detection_score = clamp01(state.detection_score + 0.12)
        elif category == RedActionCategory.CHANGE_TARGET:
            if red_action.target_node_id:
                state.target_objective_id = red_action.target_node_id
        elif category == RedActionCategory.REDUCE_NOISE:
            state.noise_level = clamp01(state.noise_level - 0.18)
            state.detection_score = clamp01(state.detection_score - 0.03)
        elif category == RedActionCategory.INCREASE_SPEED:
            state.noise_level = clamp01(state.noise_level + 0.08)
        elif category == RedActionCategory.INTERACT_WITH_RESOURCE and success:
            node = self.scenario.node_map()[state.red_position]
            if node.is_decoy or state.red_position in state.active_decoys:
                state.terminal = True
                state.terminal_reason = "intercepted_by_deception"
            else:
                state.detection_score = clamp01(state.detection_score + node.exposure * 0.15)
        elif category == RedActionCategory.COLLECT_SYNTHETIC_OBJECTIVE and success:
            if state.red_position in self.scenario.objective_node_ids:
                state.terminal = True
                state.terminal_reason = "objective_collected"
        elif category == RedActionCategory.TERMINATE:
            state.terminal = True
            state.terminal_reason = "red_terminated"
        return event

    def _deterministic_success(self, state: RangeState, action: RedAction) -> bool:
        seed_material = (
            f"{state.rng_seed}:{state.step_index}:{state.red_position}:"
            f"{action.action_id}"
        )
        return random.Random(seed_material).random() <= action.success_probability


def clone_environment(env: CyberRangeEnvironment) -> CyberRangeEnvironment:
    """Return a deep-copy environment for evaluation rollouts."""
    cloned = CyberRangeEnvironment(
        copy.deepcopy(env.scenario),
        isolation=env.isolation.model_copy(deep=True),
    )
    if env.state is not None:
        cloned.restore(env.state.model_copy(deep=True))
    return cloned
