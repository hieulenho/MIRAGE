"""Candidate defense actions, constraints, masks, and ranking."""

from __future__ import annotations

from datetime import datetime, timedelta

from mirage.analysis.utils import clamp01, mean, stable_id
from mirage.domain.schemas import (
    ActionConstraintResult,
    ActionMask,
    AttackPathAnalysis,
    AutomationLevel,
    BeliefSnapshot,
    CandidateDefenseAction,
    DeceptionPosition,
    LocalOperationalSubgraph,
    RiskTier,
    TwinSnapshot,
)


OBSERVE_ACTIONS = {
    "increase_endpoint_logging",
    "increase_network_telemetry",
    "enable_limited_packet_capture",
    "enable_auth_auditing",
    "create_soc_ticket",
    "request_analyst_review",
}
DECEPTION_ACTIONS = {
    "deploy_decoy_database",
    "deploy_fake_share",
    "scatter_honey_credential",
    "add_decoy_service",
}
CONTROL_ACTIONS = {
    "throttle_edge",
    "restrict_smb",
    "require_mfa",
    "temporary_segmentation",
    "block_egress",
    "isolate_host",
}
DISRUPTIVE_ACTIONS = {
    "restrict_smb",
    "temporary_segmentation",
    "block_egress",
    "isolate_host",
}


class DeceptionPositionAnalyzer:
    """Identify high-value non-executing deception placement positions."""

    def analyze(
        self,
        subgraph: LocalOperationalSubgraph,
        path_analysis: AttackPathAnalysis,
    ) -> list[DeceptionPosition]:
        """Return deterministic deception opportunities from path overlap."""
        node_to_paths: dict[str, set[str]] = {}
        edge_to_paths: dict[str, set[str]] = {}
        for path in path_analysis.paths:
            if path.contains_decoy:
                continue
            for node_id in path.node_ids[1:-1]:
                node_to_paths.setdefault(node_id, set()).add(path.path_id)
            for edge_id in path.edge_ids:
                edge_to_paths.setdefault(edge_id, set()).add(path.path_id)
        positions: list[DeceptionPosition] = []
        for node_id, path_ids in sorted(
            node_to_paths.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )[:10]:
            positions.append(
                DeceptionPosition(
                    position_id=stable_id("deception-position", ["node", node_id, *sorted(path_ids)]),
                    entity_id=node_id,
                    affected_path_ids=sorted(path_ids),
                    estimated_interception_coverage=clamp01(len(path_ids) / max(1, len(path_analysis.paths))),
                    estimated_deployment_cost=1.0,
                    realism_requirements=["service banner", "credential plausibility"],
                    current_decoy_coverage=0.0,
                    operational_constraints=["recommendation only; no deployment in Milestone 3"],
                    explanation=f"Node {node_id} lies on {len(path_ids)} risky path(s).",
                )
            )
        for edge_id, path_ids in sorted(
            edge_to_paths.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )[:10]:
            positions.append(
                DeceptionPosition(
                    position_id=stable_id("deception-position", ["edge", edge_id, *sorted(path_ids)]),
                    edge_id=edge_id,
                    affected_path_ids=sorted(path_ids),
                    estimated_interception_coverage=clamp01(len(path_ids) / max(1, len(path_analysis.paths))),
                    estimated_deployment_cost=0.8,
                    realism_requirements=["adjacent fake service", "telemetry hook"],
                    current_decoy_coverage=0.0,
                    operational_constraints=["recommendation only; no deployment in Milestone 3"],
                    explanation=f"Edge {edge_id} is shared by {len(path_ids)} risky path(s).",
                )
            )
        return sorted(
            positions,
            key=lambda item: (
                -item.estimated_interception_coverage,
                item.entity_id or "",
                item.edge_id or "",
                item.position_id,
            ),
        )[:15]


class CandidateActionGenerator:
    """Generate allowlisted candidate defense actions from path analysis."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.enabled = set(self.config.get("enabled_action_types", []))
        self.costs = self.config.get("action_costs", {})
        self.business_risks = self.config.get("business_risks", {})
        self.ttl = int(self.config.get("default_ttl_seconds", 3600))

    def generate(
        self,
        subgraph: LocalOperationalSubgraph,
        path_analysis: AttackPathAnalysis,
        belief_snapshot: BeliefSnapshot,
        twin_snapshot: TwinSnapshot,
        reference_time: datetime,
        deception_positions: list[DeceptionPosition] | None = None,
    ) -> list[CandidateDefenseAction]:
        """Generate deterministic candidate actions from top paths."""
        paths = sorted(path_analysis.paths, key=lambda path: (-path.risk_score, path.path_id))
        positions = deception_positions or []
        actions: list[CandidateDefenseAction] = []
        for path in paths[:20]:
            target = path.target_entity_id
            source = path.source_entity_id
            risk = path.risk_score
            if path.contains_decoy:
                actions.extend([
                    self._action("increase_endpoint_logging", [source], [path.path_id], path.edge_ids, risk, reference_time, "Preserve decoy engagement and collect richer endpoint telemetry."),
                    self._action("increase_network_telemetry", path.node_ids, [path.path_id], path.edge_ids, risk, reference_time, "Monitor traffic around active decoy path."),
                    self._action("create_soc_ticket", path.node_ids, [path.path_id], path.edge_ids, risk, reference_time, "Open SOC case for high-confidence decoy interaction."),
                ])
            else:
                actions.extend([
                    self._action("increase_endpoint_logging", [source], [path.path_id], path.edge_ids, risk, reference_time, "Increase logging on suspected source entity."),
                    self._action("increase_network_telemetry", path.node_ids, [path.path_id], path.edge_ids, risk, reference_time, "Improve visibility along risky local path."),
                    self._action("enable_auth_auditing", path.node_ids, [path.path_id], path.edge_ids, risk, reference_time, "Audit authentication on credential or lateral movement path."),
                    self._action("scatter_honey_credential", [source], [path.path_id], [], risk, reference_time, "Place honey credential near suspected attacker location."),
                ])
                if path.reaches_protected_asset or path.target_criticality >= 0.8:
                    actions.extend([
                        self._action("deploy_decoy_database", [target], [path.path_id], [], risk, reference_time, "Recommend decoy database before protected critical asset."),
                        self._action("deploy_fake_share", [target], [path.path_id], [], risk, reference_time, "Recommend fake share near critical path."),
                        self._action("throttle_edge", path.node_ids[-2:], [path.path_id], path.edge_ids[-1:], risk, reference_time, "Throttle the final risky movement edge."),
                        self._action("restrict_smb", path.node_ids, [path.path_id], path.edge_ids, risk, reference_time, "Restrict SMB on high-risk lateral movement path."),
                    ])
                if risk >= 0.7:
                    actions.extend([
                        self._action("require_mfa", path.node_ids, [path.path_id], path.edge_ids, risk, reference_time, "Require MFA for risky access path."),
                        self._action("temporary_segmentation", path.node_ids, [path.path_id], path.edge_ids, risk, reference_time, "Recommend temporary segmentation for high-risk path."),
                        self._action("isolate_host", [source], [path.path_id], [], risk, reference_time, "Potential containment action for the suspected source host."),
                    ])
        for position in positions[:8]:
            target_ids = [position.entity_id] if position.entity_id else []
            actions.append(
                self._action(
                    "add_decoy_service",
                    target_ids,
                    position.affected_path_ids,
                    [position.edge_id] if position.edge_id else [],
                    position.estimated_interception_coverage,
                    reference_time,
                    position.explanation,
                )
            )
        return self._merge(actions)

    def _action(
        self,
        action_type: str,
        targets: list[str],
        path_ids: list[str],
        edge_ids: list[str],
        risk: float,
        generated_at: datetime,
        reason: str,
    ) -> CandidateDefenseAction:
        if self.enabled and action_type not in self.enabled:
            raise ValueError(f"Action type is not enabled: {action_type}")
        category = (
            "observe"
            if action_type in OBSERVE_ACTIONS
            else "deception"
            if action_type in DECEPTION_ACTIONS
            else "control"
        )
        business_risk = float(self.business_risks.get(action_type, 0.1))
        deployment_cost = float(self.costs.get(action_type, 0.5))
        risk_tier = self._risk_tier(action_type, business_risk, risk)
        automation = self._automation_level(action_type, risk_tier)
        approval = automation == AutomationLevel.HUMAN_APPROVAL_REQUIRED.value
        information_gain = 0.8 if category == "observe" else 0.65 if category == "deception" else 0.25
        risk_reduction = clamp01(
            risk * (0.25 if category == "observe" else 0.45 if category == "deception" else 0.60)
        )
        action_id = stable_id("action", [action_type, *sorted(targets), *sorted(path_ids), *sorted(edge_ids)])
        return CandidateDefenseAction(
            action_id=action_id,
            action_type=action_type,
            target_entity_ids=targets,
            affected_path_ids=path_ids,
            affected_edge_ids=edge_ids,
            expected_risk_reduction=risk_reduction,
            expected_information_gain=information_gain,
            operational_cost=deployment_cost,
            business_risk=business_risk,
            deployment_cost=deployment_cost,
            confidence=clamp01(0.55 + risk * 0.35 - business_risk * 0.1),
            uncertainty=clamp01(0.45 - risk * 0.2 + business_risk * 0.2),
            risk_tier=risk_tier,
            automation_level=automation,
            requires_approval=approval,
            rollback_supported=action_type not in {"create_soc_ticket", "request_analyst_review"},
            rollback_plan=self._rollback(action_type),
            ttl_seconds=self.ttl if action_type not in {"create_soc_ticket", "request_analyst_review"} else None,
            preconditions=["validated target scope", "analyst-visible audit trail"],
            postconditions=["no production enforcement executed by Milestone 3"],
            constraints=["candidate only", "requires later Safety Gate before execution"],
            supporting_evidence_ids=[],
            reason=reason,
            generated_at=generated_at,
        )

    def _merge(self, actions: list[CandidateDefenseAction]) -> list[CandidateDefenseAction]:
        merged: dict[tuple[str, tuple[str, ...]], CandidateDefenseAction] = {}
        for action in actions:
            key = (action.action_type, tuple(action.target_entity_ids))
            if key not in merged:
                merged[key] = action
                continue
            current = merged[key]
            merged[key] = current.model_copy(
                update={
                    "affected_path_ids": sorted(set(current.affected_path_ids) | set(action.affected_path_ids)),
                    "affected_edge_ids": sorted(set(current.affected_edge_ids) | set(action.affected_edge_ids)),
                    "expected_risk_reduction": max(current.expected_risk_reduction, action.expected_risk_reduction),
                    "confidence": max(current.confidence, action.confidence),
                    "reason": current.reason + " " + action.reason,
                }
            )
        return sorted(
            merged.values(),
            key=lambda action: (
                action.action_type,
                action.target_entity_ids,
                action.action_id,
            ),
        )

    def _risk_tier(self, action_type: str, business_risk: float, path_risk: float) -> str:
        score = business_risk + (0.2 if action_type in DISRUPTIVE_ACTIONS else 0.0) + path_risk * 0.1
        if score >= 0.8:
            return RiskTier.CRITICAL.value
        if score >= 0.5:
            return RiskTier.HIGH.value
        if score >= 0.2:
            return RiskTier.MEDIUM.value
        return RiskTier.LOW.value

    def _automation_level(self, action_type: str, risk_tier: str) -> str:
        if action_type in {"isolate_host", "block_egress"}:
            return AutomationLevel.HUMAN_APPROVAL_REQUIRED.value
        if risk_tier in {RiskTier.HIGH.value, RiskTier.CRITICAL.value}:
            return AutomationLevel.HUMAN_APPROVAL_REQUIRED.value
        if action_type in OBSERVE_ACTIONS:
            return AutomationLevel.AUTOMATIC_WITH_MONITORING.value
        return AutomationLevel.RECOMMEND_ONLY.value

    def _rollback(self, action_type: str) -> str | None:
        if action_type in {"create_soc_ticket", "request_analyst_review"}:
            return None
        return f"Remove or expire candidate {action_type} change after TTL."


class ActionConstraintEvaluator:
    """Evaluate safety-oriented constraints before masking actions."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}
        self.protected_ids = set(self.config.get("protected_asset_ids", []))
        self.protected_types = set(self.config.get("protected_asset_types", []))
        self.required_confidence = float(self.config.get("required_confidence_threshold", 0.35))
        self.freshness_threshold = float(self.config.get("twin_freshness_threshold", 0.35))
        self.coverage_threshold = float(self.config.get("graph_coverage_threshold", 0.20))
        self.blast_radius_limit = int(self.config.get("blast_radius_limit", 5))
        self.action_budget = float(self.config.get("action_budget", 6.0))
        self.deny_action_types = set(self.config.get("deny_action_types", []))

    def evaluate(
        self,
        action: CandidateDefenseAction,
        subgraph: LocalOperationalSubgraph,
        reference_time: datetime,
    ) -> ActionConstraintResult:
        """Return explicit allow/approval/block decision metadata."""
        violations: list[str] = []
        warnings: list[str] = []
        allowed = True
        requires_approval = action.requires_approval
        if action.action_type in self.deny_action_types:
            violations.append("action_type_denied")
            allowed = False
        if not action.target_entity_ids and action.action_type not in {"create_soc_ticket", "request_analyst_review"}:
            violations.append("missing_target")
            allowed = False
        if action.confidence < self.required_confidence:
            violations.append("low_confidence")
            allowed = False
        if subgraph.freshness_score < self.freshness_threshold:
            warnings.append("stale_twin_reduces_confidence")
            if action.action_type in DISRUPTIVE_ACTIONS:
                violations.append("stale_twin_blocks_disruptive_action")
                allowed = False
        if subgraph.coverage_score < self.coverage_threshold:
            warnings.append("low_graph_coverage")
            if action.action_type in DISRUPTIVE_ACTIONS:
                violations.append("low_coverage_blocks_disruptive_action")
                allowed = False
        if len(action.target_entity_ids) > self.blast_radius_limit:
            violations.append("blast_radius_limit_exceeded")
            allowed = False
        if action.deployment_cost > self.action_budget:
            violations.append("action_budget_exceeded")
            allowed = False
        if not action.rollback_supported and action.action_type not in {"create_soc_ticket", "request_analyst_review"}:
            violations.append("missing_rollback")
            allowed = False
        if self._touches_protected(action, subgraph):
            if action.action_type in DISRUPTIVE_ACTIONS:
                violations.append("protected_asset_disruptive_action")
                allowed = False
            else:
                requires_approval = True
                warnings.append("protected_asset_requires_approval")
        risk_tier = action.risk_tier
        if action.action_type in DISRUPTIVE_ACTIONS and action.business_risk >= 0.5:
            requires_approval = True
            risk_tier = RiskTier.HIGH.value
        return ActionConstraintResult(
            action_id=action.action_id,
            allowed=allowed,
            requires_approval=requires_approval,
            risk_tier=risk_tier,
            violated_constraints=sorted(set(violations)),
            warnings=sorted(set(warnings)),
            allowed_scope=sorted(action.target_entity_ids) if allowed else [],
            maximum_ttl_seconds=action.ttl_seconds if allowed else None,
            adjusted_business_risk=clamp01(action.business_risk + 0.1 * len(warnings)),
            adjusted_confidence=clamp01(action.confidence - 0.15 * len(warnings)),
            evaluated_at=reference_time,
        )

    def _touches_protected(
        self,
        action: CandidateDefenseAction,
        subgraph: LocalOperationalSubgraph,
    ) -> bool:
        nodes = {node.node_id: node for node in subgraph.nodes}
        for entity_id in action.target_entity_ids:
            node = nodes.get(entity_id)
            if entity_id in self.protected_ids:
                return True
            if node and (node.is_protected or node.asset_type in self.protected_types):
                return True
        return False


class ActionMaskBuilder:
    """Build executable masks while preserving all block reasons."""

    def build(
        self,
        action: CandidateDefenseAction,
        result: ActionConstraintResult,
    ) -> ActionMask:
        """Convert constraint result to an action mask."""
        reasons = []
        if not result.allowed:
            reasons.extend(result.violated_constraints or ["constraint_blocked"])
        if result.requires_approval:
            reasons.append("approval_required")
        expires_at = (
            result.evaluated_at + timedelta(seconds=result.maximum_ttl_seconds)
            if result.maximum_ttl_seconds
            else None
        )
        return ActionMask(
            action_id=action.action_id,
            allowed=result.allowed,
            mask_reasons=sorted(set(reasons)),
            required_conditions=(
                ["human approval"] if result.requires_approval else []
            ),
            approval_required=result.requires_approval,
            effective_risk_tier=result.risk_tier,
            expires_at=expires_at,
        )


class CandidateActionRanker:
    """Deterministic pre-ranker for candidate actions."""

    def __init__(self, config: dict | None = None) -> None:
        self.config = config or {}

    def rank(
        self,
        actions: list[CandidateDefenseAction],
        masks: dict[str, ActionMask],
    ) -> list[CandidateDefenseAction]:
        """Return ranked actions; blocked actions are kept but ranked last."""
        scored = []
        total_paths = max(1, len({path_id for action in actions for path_id in action.affected_path_ids}))
        for action in actions:
            mask = masks[action.action_id]
            coverage = len(action.affected_path_ids) / total_paths
            score = (
                float(self.config.get("risk_reduction_weight", 1.0)) * action.expected_risk_reduction
                + float(self.config.get("information_gain_weight", 0.4)) * action.expected_information_gain
                + float(self.config.get("path_coverage_weight", 0.3)) * coverage
                - float(self.config.get("operational_cost_weight", 0.15)) * action.operational_cost
                - float(self.config.get("deployment_cost_weight", 0.15)) * action.deployment_cost
                - float(self.config.get("business_risk_weight", 0.4)) * action.business_risk
                - float(self.config.get("uncertainty_weight", 0.3)) * action.uncertainty
            )
            if not mask.allowed:
                score -= 10.0
            action = action.model_copy(
                update={
                    "score_breakdown": {
                        "rank_score": round(score, 6),
                        "path_coverage": round(coverage, 6),
                    }
                }
            )
            scored.append((score, action))
        scored.sort(
            key=lambda item: (
                item[0] < -1,
                -item[0],
                item[1].requires_approval,
                item[1].action_type,
                item[1].action_id,
            )
        )
        return [action for _, action in scored]


def summarize_path_analysis(
    analysis_id: str,
    subgraph_id: str,
    reference_time: datetime,
    paths,
    deception_positions: list[DeceptionPosition],
) -> AttackPathAnalysis:
    """Create aggregate path analysis summary."""
    sorted_paths = sorted(paths, key=lambda path: (-path.risk_score, path.path_id))
    critical_assets = sorted(
        {path.target_entity_id for path in sorted_paths if path.reaches_protected_asset}
    )
    return AttackPathAnalysis(
        analysis_id=analysis_id,
        subgraph_id=subgraph_id,
        reference_time=reference_time,
        paths=sorted_paths,
        top_risk_path_ids=[path.path_id for path in sorted_paths[:10]],
        critical_assets_at_risk=critical_assets,
        candidate_deception_positions=[
            position.position_id for position in deception_positions[:10]
        ],
        uncovered_attack_surfaces=sorted(
            {path.target_entity_id for path in sorted_paths if not path.contains_decoy}
        )[:20],
        analysis_confidence=mean([1.0 - path.uncertainty for path in sorted_paths], default=0.0),
        analysis_uncertainty=mean([path.uncertainty for path in sorted_paths], default=1.0),
        warnings=[],
    )
