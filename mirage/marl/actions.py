"""Action catalogs and blue-action adapters for the MARL cyber range."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from mirage.domain.schemas import (
    ActionMask,
    AutomationLevel,
    CandidateDefenseAction,
    RiskTier,
)
from mirage.marl.schema import (
    BlueActionKind,
    RangeScenario,
    RangeState,
    RedAction,
    RedActionCategory,
    RedActionMask,
    clamp01,
)


class RedActionCatalog:
    """Build finite allowlisted red actions for one range state."""

    def build(self, scenario: RangeScenario, state: RangeState) -> list[RedAction]:
        node_map = scenario.node_map()
        current = node_map[state.red_position]
        actions: list[RedAction] = [
            RedAction(
                action_id=f"red:recon:{state.red_position}",
                category=RedActionCategory.RECON,
                source_node_id=state.red_position,
                cost=0.05,
                noise=0.03,
                description="Gather synthetic local context.",
            ),
            RedAction(
                action_id="red:wait",
                category=RedActionCategory.WAIT,
                source_node_id=state.red_position,
                cost=0.02,
                noise=0.0,
                description="Wait inside the simulator.",
            ),
            RedAction(
                action_id="red:terminate",
                category=RedActionCategory.TERMINATE,
                source_node_id=state.red_position,
                cost=0.0,
                noise=0.0,
                description="End the synthetic episode.",
            ),
        ]
        if state.terminal:
            return actions

        discovered_edges = set(state.discovered_edge_ids)
        discovered_nodes = set(state.discovered_node_ids)
        known_credentials = set(state.known_credentials)

        for edge in scenario.outgoing_edges(state.red_position):
            target = node_map[edge.target]
            if edge.edge_id not in discovered_edges:
                actions.append(
                    RedAction(
                        action_id=f"red:discover:{edge.edge_id}",
                        category=RedActionCategory.DISCOVER_NEIGHBOR,
                        source_node_id=edge.source,
                        target_node_id=edge.target,
                        edge_id=edge.edge_id,
                        cost=0.08,
                        noise=0.04 + edge.noise * 0.2,
                        success_probability=0.95,
                        description="Reveal an adjacent synthetic node.",
                        metadata={"target_value_hint": round(target.value * 0.5, 4)},
                    )
                )
                continue

            if edge.target in discovered_nodes and edge.edge_id not in set(
                state.hardened_edges
            ):
                credential_id = f"cred:{edge.source}->{edge.target}"
                if not edge.credential_required or credential_id in known_credentials:
                    actions.append(
                        RedAction(
                            action_id=f"red:move:{edge.edge_id}",
                            category=RedActionCategory.MOVE_ALONG_EDGE,
                            source_node_id=edge.source,
                            target_node_id=edge.target,
                            edge_id=edge.edge_id,
                            credential_id=credential_id if edge.credential_required else None,
                            cost=0.16 + edge.difficulty * 0.1,
                            noise=edge.noise,
                            success_probability=clamp01(0.95 - edge.difficulty * 0.45),
                            description="Move along a discovered synthetic edge.",
                            metadata={
                                "target_value_hint": round(target.value, 4),
                                "edge_difficulty": round(edge.difficulty, 4),
                            },
                        )
                    )

        if current.services:
            actions.append(
                RedAction(
                    action_id=f"red:inspect:{state.red_position}",
                    category=RedActionCategory.INSPECT_SERVICE,
                    source_node_id=state.red_position,
                    cost=0.08,
                    noise=0.05 + current.exposure * 0.1,
                    success_probability=0.85,
                    description="Inspect synthetic service labels.",
                    metadata={"service_count": len(current.services)},
                )
            )
        if current.credential_hint:
            credential_id = f"cred:{state.red_position}"
            if credential_id not in known_credentials:
                actions.append(
                    RedAction(
                        action_id=f"red:credential:{state.red_position}",
                        category=RedActionCategory.USE_SIMULATED_CREDENTIAL,
                        source_node_id=state.red_position,
                        credential_id=credential_id,
                        cost=0.1,
                        noise=0.08,
                        success_probability=0.75,
                        description="Acquire a simulated credential token.",
                    )
                )
        if current.value > 0.2 or state.red_position in state.active_decoys:
            actions.append(
                RedAction(
                    action_id=f"red:interact:{state.red_position}",
                    category=RedActionCategory.INTERACT_WITH_RESOURCE,
                    source_node_id=state.red_position,
                    cost=0.12,
                    noise=0.1 + current.exposure * 0.1,
                    success_probability=0.9,
                    description="Interact with a synthetic resource.",
                    metadata={"resource_value": round(current.value, 4)},
                )
            )
        if current.is_objective:
            actions.append(
                RedAction(
                    action_id=f"red:collect:{state.red_position}",
                    category=RedActionCategory.COLLECT_SYNTHETIC_OBJECTIVE,
                    source_node_id=state.red_position,
                    target_node_id=state.red_position,
                    cost=0.2,
                    noise=0.18,
                    success_probability=0.9,
                    description="Collect a synthetic objective marker.",
                    metadata={"objective_value": round(current.value, 4)},
                )
            )
        if state.noise_level >= 0.05:
            actions.append(
                RedAction(
                    action_id="red:reduce-noise",
                    category=RedActionCategory.REDUCE_NOISE,
                    source_node_id=state.red_position,
                    cost=0.08,
                    noise=0.0,
                    description="Reduce synthetic activity noise.",
                )
            )
        actions.append(
            RedAction(
                action_id="red:increase-speed",
                category=RedActionCategory.INCREASE_SPEED,
                source_node_id=state.red_position,
                cost=0.03,
                noise=0.11,
                description="Bias the simulator toward faster movement.",
            )
        )
        for objective_id in scenario.objective_node_ids:
            if objective_id != state.target_objective_id:
                actions.append(
                    RedAction(
                        action_id=f"red:target:{objective_id}",
                        category=RedActionCategory.CHANGE_TARGET,
                        source_node_id=state.red_position,
                        target_node_id=objective_id,
                        cost=0.04,
                        noise=0.02,
                        description="Change the synthetic target objective.",
                    )
                )
        return sorted(actions, key=lambda item: item.action_id)

    def mask(self, scenario: RangeScenario, state: RangeState) -> RedActionMask:
        """Return a mask for the current finite action set."""
        valid_ids = [action.action_id for action in self.build(scenario, state)]
        return RedActionMask(valid_action_ids=valid_ids)

    def get(
        self,
        scenario: RangeScenario,
        state: RangeState,
        action_id: str,
    ) -> RedAction | None:
        return next(
            (action for action in self.build(scenario, state) if action.action_id == action_id),
            None,
        )


class BlueActionAdapter:
    """Create synthetic blue candidate actions and masks for the range."""

    def candidate_actions(
        self,
        scenario: RangeScenario,
        state: RangeState,
    ) -> tuple[list[CandidateDefenseAction], dict[str, ActionMask]]:
        now = datetime.now(timezone.utc)
        actions: list[CandidateDefenseAction] = [
            self._make_action(
                action_id="blue:noop",
                action_type="request_analyst_review",
                kind=BlueActionKind.NO_OP,
                targets=[],
                risk_reduction=0.0,
                information_gain=0.05,
                cost=0.0,
                business_risk=0.0,
                confidence=0.8,
                reason="No simulated defensive change.",
                now=now,
            )
        ]
        current_node = scenario.node_map()[state.red_position]
        actions.append(
            self._make_action(
                action_id=f"blue:observe:{state.red_position}",
                action_type="increase_endpoint_logging",
                kind=BlueActionKind.OBSERVE,
                targets=[state.red_position],
                risk_reduction=0.08,
                information_gain=0.65,
                cost=0.2,
                business_risk=0.03,
                confidence=0.85,
                reason="Increase synthetic monitoring on suspected node.",
                now=now,
            )
        )
        for edge in scenario.outgoing_edges(state.red_position):
            if edge.edge_id in state.discovered_edge_ids:
                actions.append(
                    self._make_action(
                        action_id=f"blue:delay:{edge.edge_id}",
                        action_type="throttle_edge",
                        kind=BlueActionKind.DELAY,
                        targets=[edge.target],
                        edges=[edge.edge_id],
                        risk_reduction=0.25 + edge.difficulty * 0.2,
                        information_gain=0.25,
                        cost=0.5,
                        business_risk=0.2,
                        confidence=0.75,
                        reason="Apply synthetic movement friction to an edge.",
                        now=now,
                    )
                )
        for node in scenario.nodes:
            if node.node_id in state.discovered_node_ids and not node.is_objective:
                actions.append(
                    self._make_action(
                        action_id=f"blue:deceive:{node.node_id}",
                        action_type="deploy_decoy_database",
                        kind=BlueActionKind.DECEIVE,
                        targets=[node.node_id],
                        risk_reduction=0.35 + node.exposure * 0.2,
                        information_gain=0.45,
                        cost=0.8,
                        business_risk=0.08,
                        confidence=0.72,
                        reason="Activate synthetic deception at a discovered node.",
                        now=now,
                    )
                )
        if state.detection_score >= 0.45:
            actions.append(
                self._make_action(
                    action_id=f"blue:contain:{state.red_position}",
                    action_type="temporary_segmentation",
                    kind=BlueActionKind.LIMITED_CONTAIN,
                    targets=[state.red_position],
                    risk_reduction=0.45 + current_node.value * 0.2,
                    information_gain=0.15,
                    cost=1.2,
                    business_risk=0.35,
                    confidence=0.7,
                    reason="Simulate limited containment in shadow mode.",
                    now=now,
                    requires_approval=True,
                    risk_tier=RiskTier.HIGH.value,
                )
            )
        if state.detection_score >= 0.7:
            actions.append(
                self._make_action(
                    action_id="blue:escalate",
                    action_type="create_soc_ticket",
                    kind=BlueActionKind.ESCALATE,
                    targets=[state.red_position],
                    risk_reduction=0.12,
                    information_gain=0.25,
                    cost=0.1,
                    business_risk=0.01,
                    confidence=0.9,
                    reason="Escalate synthetic evidence for review.",
                    now=now,
                )
            )
        masks = {action.action_id: self._mask(action, state) for action in actions}
        return sorted(actions, key=lambda item: item.action_id), masks

    def kind_for_action_id(self, action_id: str) -> BlueActionKind:
        if action_id.startswith("blue:observe:"):
            return BlueActionKind.OBSERVE
        if action_id.startswith("blue:deceive:"):
            return BlueActionKind.DECEIVE
        if action_id.startswith("blue:delay:"):
            return BlueActionKind.DELAY
        if action_id.startswith("blue:contain:"):
            return BlueActionKind.LIMITED_CONTAIN
        if action_id == "blue:escalate":
            return BlueActionKind.ESCALATE
        return BlueActionKind.NO_OP

    def _make_action(
        self,
        *,
        action_id: str,
        action_type: str,
        kind: BlueActionKind,
        targets: list[str],
        risk_reduction: float,
        information_gain: float,
        cost: float,
        business_risk: float,
        confidence: float,
        reason: str,
        now: datetime,
        edges: list[str] | None = None,
        requires_approval: bool = False,
        risk_tier: str = RiskTier.LOW.value,
    ) -> CandidateDefenseAction:
        return CandidateDefenseAction(
            action_id=action_id,
            action_type=action_type,
            target_entity_ids=targets,
            affected_path_ids=[],
            affected_edge_ids=edges or [],
            expected_risk_reduction=clamp01(risk_reduction),
            expected_information_gain=clamp01(information_gain),
            operational_cost=cost,
            business_risk=clamp01(business_risk),
            deployment_cost=cost,
            confidence=clamp01(confidence),
            uncertainty=clamp01(1.0 - confidence),
            risk_tier=risk_tier,
            automation_level=AutomationLevel.RECOMMEND_ONLY.value,
            requires_approval=requires_approval,
            rollback_supported=True,
            rollback_plan="Synthetic range state rollback only.",
            ttl_seconds=1800,
            preconditions=["cyber_range_only", "blue_execution_mode_shadow"],
            postconditions=[f"synthetic_{kind.value.lower()}"],
            constraints=["no_production_execution"],
            supporting_evidence_ids=[],
            reason=reason,
            generated_at=now,
            score_breakdown={
                "risk_reduction": clamp01(risk_reduction),
                "information_gain": clamp01(information_gain),
                "cost_penalty": float(cost),
            },
        )

    def _mask(self, action: CandidateDefenseAction, state: RangeState) -> ActionMask:
        allowed = True
        reasons: list[str] = []
        if action.operational_cost > state.blue_budget_remaining:
            allowed = False
            reasons.append("insufficient_synthetic_budget")
        if action.action_id.startswith("blue:contain:") and state.detection_score < 0.45:
            allowed = False
            reasons.append("insufficient_detection_confidence")
        return ActionMask(
            action_id=action.action_id,
            allowed=allowed,
            mask_reasons=reasons,
            required_conditions=list(action.preconditions),
            approval_required=action.requires_approval,
            effective_risk_tier=action.risk_tier,
        )


def action_map(actions: list[CandidateDefenseAction]) -> dict[str, CandidateDefenseAction]:
    """Map candidate actions by ID."""
    return {action.action_id: action for action in actions}


def mask_allows(masks: dict[str, ActionMask], action_id: str) -> bool:
    """Return whether a blue action ID is currently allowed."""
    return masks.get(action_id, ActionMask(
        action_id=action_id,
        allowed=False,
        mask_reasons=["unknown_blue_action"],
        required_conditions=[],
        approval_required=False,
        effective_risk_tier=RiskTier.LOW.value,
    )).allowed


def action_summary(action: CandidateDefenseAction | None) -> dict[str, Any]:
    """Compact action summary for telemetry and docs."""
    if action is None:
        return {"action_id": "unknown", "action_type": "unknown"}
    return {
        "action_id": action.action_id,
        "action_type": action.action_type,
        "targets": list(action.target_entity_ids),
        "cost": action.operational_cost,
    }
