"""Observation encoders for red and blue MARL agents."""

from __future__ import annotations

from typing import Any

from mirage.marl.actions import BlueActionAdapter
from mirage.marl.schema import (
    BlueObservation,
    MultiAgentObservation,
    RangeScenario,
    RangeState,
    RedObservation,
    clamp01,
)


class RedObservationEncoder:
    """Encode partial red observations without hidden defender truth."""

    def encode(self, scenario: RangeScenario, state: RangeState) -> RedObservation:
        node_map = scenario.node_map()
        discovered_nodes = set(state.discovered_node_ids) | {state.red_position}
        discovered_edges = set(state.discovered_edge_ids)
        visible_nodes: list[dict[str, Any]] = []
        for node_id in sorted(discovered_nodes):
            node = node_map[node_id]
            visible_nodes.append(
                {
                    "node_id": node.node_id,
                    "visible_label": node.visible_label,
                    "asset_type": node.asset_type,
                    "service_count": len(node.services),
                    "value_hint": round(node.value * 0.75, 4),
                    "exposure_hint": round(node.exposure, 4),
                }
            )
        edge_map = scenario.edge_map()
        visible_edges = [
            {
                "edge_id": edge_id,
                "source": edge_map[edge_id].source,
                "target": edge_map[edge_id].target,
                "difficulty_hint": round(edge_map[edge_id].difficulty, 4),
                "credential_required": edge_map[edge_id].credential_required,
            }
            for edge_id in sorted(discovered_edges)
            if edge_id in edge_map
        ]
        recent_blue = [
            event.get("blue_action_id", "")
            for event in state.history[-3:]
            if event.get("blue_action_id")
        ]
        return RedObservation(
            observation_id=f"red:{scenario.scenario_id}:{state.step_index}",
            scenario_id=scenario.scenario_id,
            step_index=state.step_index,
            current_node_id=state.red_position,
            visible_nodes=visible_nodes,
            visible_edges=visible_edges,
            discovered_node_ids=sorted(discovered_nodes),
            discovered_edge_ids=sorted(discovered_edges),
            known_credentials=sorted(state.known_credentials),
            remaining_steps=max(0, scenario.max_steps - state.step_index),
            noise_level=clamp01(state.noise_level),
            defender_pressure=clamp01(state.detection_score),
            recent_blue_actions=recent_blue,
        )


class BlueObservationAdapter:
    """Create blue observations using existing candidate-action schemas."""

    def __init__(self, action_adapter: BlueActionAdapter | None = None) -> None:
        self.action_adapter = action_adapter or BlueActionAdapter()

    def encode(self, scenario: RangeScenario, state: RangeState) -> BlueObservation:
        actions, masks = self.action_adapter.candidate_actions(scenario, state)
        suspected = [state.red_position]
        if state.detection_score < 0.35 and state.history:
            previous = state.history[-1].get("red_source_node_id")
            if previous and previous not in suspected:
                suspected.append(str(previous))
        protected_assets = [
            node.node_id
            for node in scenario.nodes
            if node.protected and node.node_id in state.discovered_node_ids
        ]
        return BlueObservation(
            observation_id=f"blue:{scenario.scenario_id}:{state.step_index}",
            scenario_id=scenario.scenario_id,
            step_index=state.step_index,
            suspected_red_node_ids=sorted(set(suspected)),
            detection_confidence=clamp01(state.detection_score),
            protected_assets_at_risk=sorted(protected_assets),
            candidate_actions=actions,
            action_masks=masks,
            telemetry_events=list(state.last_events),
            budget_remaining=state.blue_budget_remaining,
            warnings=[],
        )


class MultiAgentObservationAdapter:
    """Build joint observations."""

    def __init__(
        self,
        red_encoder: RedObservationEncoder | None = None,
        blue_adapter: BlueObservationAdapter | None = None,
    ) -> None:
        self.red_encoder = red_encoder or RedObservationEncoder()
        self.blue_adapter = blue_adapter or BlueObservationAdapter()

    def encode(self, scenario: RangeScenario, state: RangeState) -> MultiAgentObservation:
        return MultiAgentObservation(
            red=self.red_encoder.encode(scenario, state),
            blue=self.blue_adapter.encode(scenario, state),
        )
