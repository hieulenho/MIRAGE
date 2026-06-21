"""State and action encoders for MIRAGE offline RL."""

from __future__ import annotations

import hashlib
import math
from datetime import datetime, timezone
from typing import Any

from mirage.domain.schemas import (
    ActionMask,
    AttackAnalysisResult,
    BeliefSnapshot,
    CandidateActionSet,
    CandidateDefenseAction,
    SafetyDecision,
    SafetyVerdict,
    TwinSnapshot,
)
from mirage.rl.schema import (
    BlueTeamTactic,
    CandidateActionFeature,
    EncodedRLState,
    RLFeatureSchema,
    RLStateReference,
    RLOperatingMode,
)


OBSERVE_ACTIONS = {
    "increase_endpoint_logging",
    "increase_network_telemetry",
    "enable_limited_packet_capture",
    "enable_auth_auditing",
}
DECEPTION_ACTIONS = {
    "deploy_decoy_host",
    "deploy_decoy_database",
    "deploy_fake_share",
    "scatter_honey_credential",
    "add_decoy_service",
    "create_honey_credential",
    "create_fake_dns_record",
}
DELAY_ACTIONS = {
    "throttle_edge",
    "restrict_smb",
    "require_mfa",
    "temporary_segmentation",
    "block_flow",
}
CONTAIN_ACTIONS = {
    "block_egress",
    "isolate_host",
    "isolate_database",
    "block_subnet",
    "disable_privileged_identity",
    "revoke_session",
}
ESCALATE_ACTIONS = {"create_soc_ticket", "request_analyst_review"}

STATE_FEATURE_NAMES_V1 = [
    "stage_normal",
    "stage_reconnaissance",
    "stage_initial_access",
    "stage_execution",
    "stage_persistence",
    "stage_privilege_escalation",
    "stage_defense_evasion",
    "stage_credential_access",
    "stage_discovery",
    "stage_lateral_movement",
    "stage_collection",
    "stage_command_and_control",
    "stage_exfiltration",
    "stage_impact",
    "compromise_max",
    "compromise_mean",
    "attacker_location_max",
    "belief_confidence_mean",
    "belief_uncertainty_mean",
    "max_path_risk",
    "mean_path_risk",
    "critical_assets_at_risk",
    "high_risk_paths",
    "active_incidents",
    "direct_evidence_entities",
    "inferred_only_entities",
    "twin_coverage",
    "twin_freshness",
    "twin_confidence",
    "twin_conflict_rate",
    "stale_asset_ratio",
    "unknown_asset_ratio",
    "subgraph_node_count",
    "subgraph_edge_count",
    "critical_asset_distance_mean",
    "critical_asset_distance_min",
    "decoy_coverage",
    "high_risk_branch_points",
    "attack_path_overlap",
    "gnn_graph_risk",
    "gnn_graph_uncertainty",
    "gnn_embedding_mean",
    "active_decoy_count",
    "active_control_count",
    "available_budget",
    "recent_action_count",
    "active_approval_requests",
    "business_impact_score",
    "kill_switch_enabled",
    "candidate_observe_count",
    "candidate_deceive_count",
    "candidate_delay_count",
    "candidate_contain_count",
    "candidate_escalate_count",
    "candidate_noop_count",
    "allowed_action_count",
    "masked_action_count",
    "approval_required_count",
    "max_estimated_risk_reduction",
    "min_business_risk",
    "max_information_gain",
]

ACTION_FEATURE_NAMES_V1 = [
    "tactic_idx",
    "action_type_idx",
    "expected_risk_reduction",
    "expected_information_gain",
    "path_coverage",
    "target_criticality",
    "operational_cost",
    "deployment_cost",
    "business_risk",
    "confidence",
    "uncertainty",
    "reversibility",
    "ttl_hours",
    "risk_tier_idx",
    "approval_required",
    "safety_verdict_idx",
    "affected_path_count",
    "direct_evidence_coverage",
    "inferred_evidence_coverage",
    "decoy_related",
    "containment_related",
    "stage_compatibility",
]

KNOWN_ACTION_TYPES = [
    "unknown",
    "increase_endpoint_logging",
    "increase_network_telemetry",
    "enable_limited_packet_capture",
    "enable_auth_auditing",
    "create_soc_ticket",
    "request_analyst_review",
    "deploy_decoy_host",
    "deploy_decoy_database",
    "deploy_fake_share",
    "scatter_honey_credential",
    "add_decoy_service",
    "create_honey_credential",
    "create_fake_dns_record",
    "throttle_edge",
    "restrict_smb",
    "require_mfa",
    "temporary_segmentation",
    "block_flow",
    "block_egress",
    "revoke_session",
    "isolate_host",
    "isolate_database",
    "block_subnet",
    "disable_privileged_identity",
]

RISK_TIER_INDEX = {"low": 0, "medium": 1, "high": 2, "critical": 3}
SAFETY_VERDICT_INDEX = {
    SafetyVerdict.ALLOW.value: 0,
    SafetyVerdict.ALLOW_WITH_MONITORING.value: 1,
    SafetyVerdict.REQUIRE_APPROVAL.value: 2,
    SafetyVerdict.DENY.value: 3,
}


def default_feature_schema() -> RLFeatureSchema:
    return RLFeatureSchema(
        state_feature_names=list(STATE_FEATURE_NAMES_V1),
        action_feature_names=list(ACTION_FEATURE_NAMES_V1),
    )


def stable_id(prefix: str, parts: list[Any]) -> str:
    payload = "|".join(str(part) for part in parts)
    return f"{prefix}_" + hashlib.sha256(payload.encode()).hexdigest()[:20]


def clamp01(value: float) -> float:
    if not math.isfinite(value):
        return 0.0
    return max(0.0, min(1.0, float(value)))


def mean(values: list[float], default: float = 0.0) -> float:
    clean = [float(value) for value in values if math.isfinite(float(value))]
    return sum(clean) / len(clean) if clean else default


def tactic_for_action(action_type: str) -> BlueTeamTactic:
    if action_type in OBSERVE_ACTIONS:
        return BlueTeamTactic.OBSERVE
    if action_type in DECEPTION_ACTIONS:
        return BlueTeamTactic.DECEIVE
    if action_type in DELAY_ACTIONS:
        return BlueTeamTactic.DELAY
    if action_type in CONTAIN_ACTIONS:
        return BlueTeamTactic.LIMITED_CONTAIN
    if action_type in ESCALATE_ACTIONS:
        return BlueTeamTactic.ESCALATE
    if action_type in {"__NO_OP__", "noop", "no_op"}:
        return BlueTeamTactic.NO_OP
    return BlueTeamTactic.NO_OP


def _stage_distribution(belief_snapshot: BeliefSnapshot) -> dict[str, float]:
    from mirage.domain.schemas import STAGE_NAMES_V1

    totals = {stage: 0.0 for stage in STAGE_NAMES_V1}
    weight_total = 0.0
    for belief in belief_snapshot.entity_beliefs.values():
        weight = max(0.05, belief.compromise_probability + belief.candidate_attacker_location_probability)
        weight_total += weight
        for stage, probability in belief.stage_distribution.items():
            if stage in totals:
                totals[stage] += probability * weight
    if weight_total <= 0:
        totals["normal"] = 1.0
        return totals
    return {stage: clamp01(value / weight_total) for stage, value in totals.items()}


class ActionFeatureEncoder:
    """Encode candidate defense actions without using target IDs as features."""

    def __init__(
        self,
        schema: RLFeatureSchema | None = None,
        *,
        allow_unknown_action_types: bool = False,
    ) -> None:
        self.schema = schema or default_feature_schema()
        self.allow_unknown_action_types = allow_unknown_action_types

    def encode(
        self,
        action: CandidateDefenseAction,
        mask: ActionMask | None = None,
        safety_decision: SafetyDecision | None = None,
        *,
        total_paths: int = 1,
        critical_asset_ids: list[str] | None = None,
        stage_distribution: dict[str, float] | None = None,
    ) -> CandidateActionFeature:
        warnings: list[str] = []
        action_type_idx = 0
        if action.action_type in KNOWN_ACTION_TYPES:
            action_type_idx = KNOWN_ACTION_TYPES.index(action.action_type)
        else:
            warnings.append(f"unknown_action_type:{action.action_type}")
            if not self.allow_unknown_action_types and mask is None:
                mask_status = "masked_unknown_action_type"
            else:
                mask_status = "allowed" if (mask is None or mask.allowed) else "masked"
        if action.action_type in KNOWN_ACTION_TYPES:
            mask_status = "allowed" if (mask is None or mask.allowed) else "masked"
        tactic = tactic_for_action(action.action_type)
        critical_ids = set(critical_asset_ids or [])
        affected_critical = len(critical_ids.intersection(action.target_entity_ids))
        path_coverage = clamp01(len(action.affected_path_ids) / max(1, int(total_paths)))
        reversibility = 1.0 if action.rollback_supported else 0.0
        safety_verdict = (
            safety_decision.verdict.value
            if safety_decision is not None
            else (
                SafetyVerdict.DENY.value
                if mask is not None and not mask.allowed
                else SafetyVerdict.REQUIRE_APPROVAL.value
                if (mask is not None and mask.approval_required) or action.requires_approval
                else SafetyVerdict.ALLOW_WITH_MONITORING.value
            )
        )
        stage_compatibility = self._stage_compatibility(action, stage_distribution or {})
        direct_coverage = 1.0 if action.supporting_evidence_ids else 0.0
        inferred_coverage = clamp01(action.uncertainty)
        vector = [
            float(list(BlueTeamTactic).index(tactic)),
            float(action_type_idx),
            clamp01(action.expected_risk_reduction),
            clamp01(action.expected_information_gain),
            path_coverage,
            clamp01(max(action.expected_risk_reduction, affected_critical / max(1, len(action.target_entity_ids)))),
            float(action.operational_cost),
            float(action.deployment_cost),
            clamp01(action.business_risk),
            clamp01(action.confidence),
            clamp01(action.uncertainty),
            reversibility,
            float(action.ttl_seconds or 0) / 3600.0,
            float(RISK_TIER_INDEX.get(action.risk_tier, 0)),
            1.0 if action.requires_approval or (mask is not None and mask.approval_required) else 0.0,
            float(SAFETY_VERDICT_INDEX.get(safety_verdict, 2)),
            float(len(action.affected_path_ids)),
            direct_coverage,
            inferred_coverage,
            1.0 if tactic == BlueTeamTactic.DECEIVE else 0.0,
            1.0 if tactic == BlueTeamTactic.LIMITED_CONTAIN else 0.0,
            stage_compatibility,
        ]
        feature_mask = [1.0] * len(vector)
        return CandidateActionFeature(
            action_id=action.action_id,
            action_type=action.action_type,
            tactic_category=tactic,
            expected_risk_reduction=action.expected_risk_reduction,
            information_gain=action.expected_information_gain,
            path_coverage=path_coverage,
            operational_cost=action.operational_cost,
            deployment_cost=action.deployment_cost,
            business_risk=action.business_risk,
            uncertainty=action.uncertainty,
            confidence=action.confidence,
            reversibility=reversibility,
            ttl_seconds=action.ttl_seconds,
            risk_tier=action.risk_tier,
            approval_required=action.requires_approval or (mask.approval_required if mask else False),
            affected_critical_assets=affected_critical,
            affected_paths=len(action.affected_path_ids),
            safety_gate_verdict=safety_verdict,
            action_mask_status=mask_status,
            encoded_feature_vector=[round(float(value), 6) for value in vector],
            feature_mask=feature_mask,
            ood_warnings=warnings,
        )

    def _stage_compatibility(
        self,
        action: CandidateDefenseAction,
        stage_distribution: dict[str, float],
    ) -> float:
        if not stage_distribution:
            return 0.5
        tactic = tactic_for_action(action.action_type)
        discovery = stage_distribution.get("discovery", 0.0)
        credential = stage_distribution.get("credential_access", 0.0)
        lateral = stage_distribution.get("lateral_movement", 0.0)
        collection = stage_distribution.get("collection", 0.0)
        impact = stage_distribution.get("impact", 0.0)
        if tactic == BlueTeamTactic.OBSERVE:
            return clamp01(0.45 + discovery + credential * 0.3)
        if tactic == BlueTeamTactic.DECEIVE:
            return clamp01(0.35 + lateral * 0.5 + credential * 0.3 + discovery * 0.2)
        if tactic == BlueTeamTactic.DELAY:
            return clamp01(0.30 + lateral * 0.4 + collection * 0.3)
        if tactic == BlueTeamTactic.LIMITED_CONTAIN:
            return clamp01(0.20 + impact * 0.4 + collection * 0.3 + lateral * 0.2)
        if tactic == BlueTeamTactic.ESCALATE:
            return clamp01(0.40 + impact * 0.3 + collection * 0.2)
        return 0.5


class RLStateEncoder:
    """Construct versioned belief-state features for offline RL."""

    def __init__(
        self,
        schema: RLFeatureSchema | None = None,
        action_encoder: ActionFeatureEncoder | None = None,
        operating_mode: str = RLOperatingMode.RL_SHADOW.value,
    ) -> None:
        self.schema = schema or default_feature_schema()
        self.action_encoder = action_encoder or ActionFeatureEncoder(self.schema)
        self.operating_mode = operating_mode

    def encode(
        self,
        twin_snapshot: TwinSnapshot,
        belief_snapshot: BeliefSnapshot,
        attack_analysis: AttackAnalysisResult,
        candidate_action_set: CandidateActionSet | None = None,
        gnn_result: Any | None = None,
        action_history: list[dict[str, Any]] | None = None,
    ) -> EncodedRLState:
        action_set = candidate_action_set or attack_analysis.candidate_action_set
        stage_dist = _stage_distribution(belief_snapshot)
        entity_beliefs = list(belief_snapshot.entity_beliefs.values())
        path_risks = [path.risk_score for path in attack_analysis.path_analysis.paths]
        high_risk_paths = [value for value in path_risks if value >= 0.6]
        subgraph = attack_analysis.subgraph
        warnings = list(attack_analysis.warnings) + list(action_set.warnings)
        gnn_model_version = None
        gnn_graph_risk = 0.0
        gnn_uncertainty = 1.0
        gnn_embedding_mean = 0.0
        if gnn_result is not None:
            try:
                gnn_model_version = str(gnn_result.model_version)
                gnn_graph_risk = clamp01(float(gnn_result.gnn_output.graph_risk_probability))
                gnn_uncertainty = clamp01(float(gnn_result.gnn_output.graph_uncertainty))
                embedding = list(gnn_result.gnn_output.graph_embedding or [])
                gnn_embedding_mean = mean([abs(float(x)) for x in embedding], default=0.0)
                if getattr(gnn_result, "fallback_recommended", False):
                    warnings.append(f"gnn_fallback:{getattr(gnn_result, 'fallback_reason', '')}")
            except AttributeError:
                warnings.append("gnn_result_incompatible")
        assets = list(twin_snapshot.assets.values())
        stale_assets = [asset for asset in assets if not asset.active]
        unknown_assets = [asset for asset in assets if asset.asset_type == "unknown"]
        conflict_count = 0.0
        if "conflict_count" in twin_snapshot.graph_metadata:
            conflict_count = float(twin_snapshot.graph_metadata.get("conflict_count", 0.0))
        direct_evidence = [
            belief for belief in entity_beliefs if belief.evidence_ids and belief.confidence >= 0.5
        ]
        inferred_only = [
            belief for belief in entity_beliefs if not belief.evidence_ids and belief.compromise_probability > 0.2
        ]
        decoy_count = sum(1 for node in subgraph.nodes if node.is_decoy)
        branch_points = _branch_point_count(subgraph)
        overlap = _path_overlap(attack_analysis)
        candidate_features = [
            self.action_encoder.encode(
                action,
                action_set.masks.get(action.action_id),
                total_paths=max(1, len(attack_analysis.path_analysis.paths)),
                critical_asset_ids=attack_analysis.path_analysis.critical_assets_at_risk,
                stage_distribution=stage_dist,
            )
            for action in action_set.actions[:]
        ]
        tactic_counts = {tactic: 0 for tactic in BlueTeamTactic}
        for feature in candidate_features:
            tactic_counts[feature.tactic_category] += 1
            warnings.extend(feature.ood_warnings)
        allowed_action_ids = [
            action_id for action_id in action_set.allowed_action_ids
            if action_set.masks.get(action_id, None) is None or action_set.masks[action_id].allowed
        ]
        masked_action_ids = sorted(set(action_set.blocked_action_ids) | {
            action_id for action_id, mask in action_set.masks.items() if not mask.allowed
        })
        approvals = [
            mask for mask in action_set.masks.values()
            if mask.approval_required
        ]
        values = []
        values.extend(stage_dist.get(name.removeprefix("stage_"), 0.0) for name in STATE_FEATURE_NAMES_V1[:14])
        values.extend([
            max([belief.compromise_probability for belief in entity_beliefs], default=0.0),
            mean([belief.compromise_probability for belief in entity_beliefs]),
            max([belief.candidate_attacker_location_probability for belief in entity_beliefs], default=0.0),
            mean([belief.confidence for belief in entity_beliefs], default=0.0),
            mean([belief.uncertainty for belief in entity_beliefs], default=1.0),
            max(path_risks, default=0.0),
            mean(path_risks, default=0.0),
            float(len(attack_analysis.path_analysis.critical_assets_at_risk)),
            float(len(high_risk_paths)),
            1.0 if entity_beliefs else 0.0,
            float(len(direct_evidence)),
            float(len(inferred_only)),
            clamp01(twin_snapshot.coverage_score),
            clamp01(twin_snapshot.freshness_score),
            mean([asset.confidence for asset in assets], default=clamp01(twin_snapshot.coverage_score)),
            clamp01(conflict_count / max(1, len(assets))),
            len(stale_assets) / max(1, len(assets)),
            len(unknown_assets) / max(1, len(assets)),
            float(len(subgraph.nodes)),
            float(len(subgraph.edges)),
            float(_critical_distance_proxy(subgraph)[0]),
            float(_critical_distance_proxy(subgraph)[1]),
            decoy_count / max(1, len(subgraph.nodes)),
            float(branch_points),
            overlap,
            gnn_graph_risk,
            gnn_uncertainty,
            gnn_embedding_mean,
            float(decoy_count),
            float(sum(1 for action in action_set.actions if tactic_for_action(action.action_type) in {BlueTeamTactic.DELAY, BlueTeamTactic.LIMITED_CONTAIN})),
            float(getattr(attack_analysis, "budget_remaining", 1.0) if hasattr(attack_analysis, "budget_remaining") else 1.0),
            float(len(action_history or [])),
            float(len(approvals)),
            mean([action.business_risk for action in action_set.actions], default=0.0),
            0.0,
            float(tactic_counts[BlueTeamTactic.OBSERVE]),
            float(tactic_counts[BlueTeamTactic.DECEIVE]),
            float(tactic_counts[BlueTeamTactic.DELAY]),
            float(tactic_counts[BlueTeamTactic.LIMITED_CONTAIN]),
            float(tactic_counts[BlueTeamTactic.ESCALATE]),
            float(tactic_counts[BlueTeamTactic.NO_OP]),
            float(len(allowed_action_ids)),
            float(len(masked_action_ids)),
            float(len(approvals)),
            max([action.expected_risk_reduction for action in action_set.actions], default=0.0),
            min([action.business_risk for action in action_set.actions], default=0.0),
            max([action.expected_information_gain for action in action_set.actions], default=0.0),
        ])
        mask = [1.0] * len(values)
        state_id = stable_id(
            "rl-state",
            [
                twin_snapshot.twin_version,
                attack_analysis.graph_version,
                belief_snapshot.belief_version,
                attack_analysis.analysis_id,
                self.schema.schema_hash(),
            ],
        )
        state_ref = RLStateReference(
            state_id=state_id,
            twin_version=str(twin_snapshot.twin_version),
            graph_version=str(attack_analysis.graph_version),
            belief_version=str(belief_snapshot.belief_version),
            analysis_id=attack_analysis.analysis_id,
            gnn_model_version=gnn_model_version,
            feature_schema_version=self.schema.schema_version,
            timestamp=attack_analysis.reference_time,
            operating_mode=self.operating_mode,
            provenance_refs={
                "analysis_id": attack_analysis.analysis_id,
                "action_set_id": action_set.action_set_id,
            },
        )
        return EncodedRLState(
            state_reference=state_ref,
            feature_schema=self.schema,
            feature_vector=[round(float(value), 6) for value in values],
            feature_mask=mask,
            candidate_action_features=candidate_features,
            allowed_action_ids=allowed_action_ids,
            masked_action_ids=masked_action_ids,
            warnings=sorted(set(warnings)),
        )


def _branch_point_count(subgraph) -> int:
    degree: dict[str, int] = {}
    for edge in subgraph.edges:
        degree[edge.source_entity_id] = degree.get(edge.source_entity_id, 0) + 1
        degree[edge.target_entity_id] = degree.get(edge.target_entity_id, 0) + 1
    return sum(1 for value in degree.values() if value >= 3)


def _path_overlap(analysis: AttackAnalysisResult) -> float:
    paths = analysis.path_analysis.paths
    if len(paths) <= 1:
        return 0.0
    edge_counts: dict[str, int] = {}
    for path in paths:
        for edge_id in path.edge_ids:
            edge_counts[edge_id] = edge_counts.get(edge_id, 0) + 1
    if not edge_counts:
        return 0.0
    return clamp01(max(edge_counts.values()) / len(paths))


def _critical_distance_proxy(subgraph) -> tuple[float, float]:
    if not subgraph.critical_asset_ids:
        return 0.0, 0.0
    critical = set(subgraph.critical_asset_ids)
    distances = [
        0.0 if node.node_id in critical else 1.0
        for node in subgraph.nodes
    ]
    return mean(distances, default=0.0), min(distances, default=0.0)


def simple_safety_decision_for_action(
    action: CandidateDefenseAction,
    mask: ActionMask | None,
    reference_time: datetime | None = None,
) -> SafetyDecision:
    verdict = (
        SafetyVerdict.DENY
        if mask is not None and not mask.allowed
        else SafetyVerdict.REQUIRE_APPROVAL
        if action.requires_approval or (mask is not None and mask.approval_required)
        else SafetyVerdict.ALLOW_WITH_MONITORING
    )
    return SafetyDecision(
        action_id=action.action_id,
        verdict=verdict,
        risk_tier=action.risk_tier,
        confidence=action.confidence,
        business_risk=action.business_risk,
        blast_radius_estimate=len(action.target_entity_ids),
        twin_freshness=1.0,
        graph_coverage=1.0,
        violated_policies=[] if verdict != SafetyVerdict.DENY else (mask.mask_reasons if mask else ["masked"]),
        warnings=[],
        required_approvals=["analyst"] if verdict == SafetyVerdict.REQUIRE_APPROVAL else [],
        allowed_scope=list(action.target_entity_ids) if verdict != SafetyVerdict.DENY else [],
        maximum_ttl_seconds=action.ttl_seconds,
        rollback_required=action.rollback_supported,
        reasons=[verdict.value.lower()],
        policy_version="rl-shadow-safety-context",
        evaluated_at=reference_time or datetime.now(timezone.utc),
    )
