"""Deterministic synthetic RL scenarios for Milestone 7."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from mirage.domain.schemas import (
    ActionMask,
    AttackAnalysisResult,
    AttackPath,
    AttackPathAnalysis,
    AutomationLevel,
    BeliefSnapshot,
    CandidateActionSet,
    CandidateDefenseAction,
    EntityBelief,
    LocalOperationalSubgraph,
    LocalSubgraphEdge,
    LocalSubgraphNode,
    RiskTier,
    STAGE_NAMES_V1,
    SeedEntity,
    TwinSnapshot,
)
from mirage.rl.dataset import split_for_scenario
from mirage.rl.features import RLStateEncoder, stable_id
from mirage.rl.reward import DefenseRewardModel
from mirage.rl.schema import RLTrajectory, RLTrajectorySource, RLTransition


BASE_TIME = datetime(2026, 6, 21, 0, 0, 0, tzinfo=timezone.utc)


SCENARIO_IDS = [
    "benign_administrator_activity",
    "discovery_without_critical_path",
    "credential_access_lateral_movement",
    "multiple_paths_critical_database",
    "high_confidence_decoy_interaction",
    "stale_incomplete_twin",
    "protected_critical_asset",
    "limited_budget",
    "conflicting_candidate_actions",
    "no_valid_action_except_no_op",
    "gnn_unavailable",
    "ood_topology",
    "deception_aware_attacker",
    "high_benefit_excessive_business_risk",
    "analyst_rejects_unsafe_recommendation",
    "robust_rl_strong_disagreement",
]


def build_rl_scenario(scenario_id: str) -> dict[str, Any]:
    if scenario_id not in SCENARIO_IDS:
        raise ValueError(f"Unknown RL scenario: {scenario_id}")
    idx = SCENARIO_IDS.index(scenario_id)
    ref = BASE_TIME + timedelta(minutes=idx)
    stage = _stage_for_scenario(scenario_id)
    high_risk = scenario_id not in {"benign_administrator_activity", "discovery_without_critical_path"}
    stale = "stale" in scenario_id
    protected = "protected" in scenario_id or "critical" in scenario_id
    decoy = "decoy" in scenario_id or "deception" in scenario_id
    nodes = [
        LocalSubgraphNode(
            node_id="asset:seed",
            entity_type="asset",
            label="seed",
            asset_type="host",
            business_criticality=0.4,
            is_seed=True,
            compromise_probability=0.75 if high_risk else 0.08,
            attacker_location_probability=0.65 if high_risk else 0.04,
            confidence=0.85,
        ),
        LocalSubgraphNode(
            node_id="asset:mid",
            entity_type="asset",
            label="mid",
            asset_type="host",
            business_criticality=0.5,
            compromise_probability=0.45 if high_risk else 0.05,
            attacker_location_probability=0.25 if high_risk else 0.02,
            confidence=0.8,
        ),
        LocalSubgraphNode(
            node_id="asset:critical_db",
            entity_type="asset",
            label="critical_db",
            asset_type="database",
            business_criticality=0.95,
            is_critical=True,
            is_protected=protected,
            compromise_probability=0.2 if high_risk else 0.02,
            confidence=0.9,
        ),
    ]
    if decoy:
        nodes.append(LocalSubgraphNode(
            node_id="asset:decoy",
            entity_type="asset",
            label="decoy",
            asset_type="decoy",
            is_decoy=True,
            business_criticality=0.1,
            confidence=0.95,
        ))
    edges = [
        LocalSubgraphEdge(
            edge_id="edge_seed_mid",
            source_entity_id="asset:seed",
            target_entity_id="asset:mid",
            relationship_type="observed_lateral_movement" if high_risk else "authenticated_to",
            confidence=0.82,
            first_seen=ref - timedelta(hours=1),
            last_seen=ref - timedelta(days=5) if stale else ref,
            directly_observed=not stale,
            inferred=stale,
        ),
        LocalSubgraphEdge(
            edge_id="edge_mid_db",
            source_entity_id="asset:mid",
            target_entity_id="asset:critical_db",
            relationship_type="authenticated_to",
            confidence=0.72,
            first_seen=ref - timedelta(hours=1),
            last_seen=ref - timedelta(days=5) if stale else ref,
            directly_observed=not stale,
            inferred=stale,
        ),
    ]
    if decoy:
        edges.append(LocalSubgraphEdge(
            edge_id="edge_seed_decoy",
            source_entity_id="asset:seed",
            target_entity_id="asset:decoy",
            relationship_type="interacted_with_decoy",
            confidence=0.98,
            first_seen=ref - timedelta(minutes=10),
            last_seen=ref,
            directly_observed=True,
        ))
    subgraph = LocalOperationalSubgraph(
        subgraph_id=f"rl_sg_{scenario_id}",
        graph_version="rl_synthetic_graph_v1",
        twin_version="1",
        belief_version=1,
        created_at=ref,
        reference_time=ref,
        seed_entities=[
            SeedEntity(
                entity_id="asset:seed",
                entity_type="asset",
                seed_reason="synthetic",
                compromise_probability=0.75 if high_risk else 0.08,
                attacker_location_probability=0.65 if high_risk else 0.04,
                belief_confidence=0.85,
                belief_uncertainty=0.25,
                most_likely_stage=stage,
                priority_score=0.8 if high_risk else 0.1,
                selected_at=ref,
            )
        ],
        nodes=nodes,
        edges=edges,
        critical_asset_ids=["asset:critical_db"],
        decoy_ids=["asset:decoy"] if decoy else [],
        coverage_score=0.2 if stale else 0.9,
        freshness_score=0.15 if stale else 0.9,
        warnings=["low_twin_coverage"] if stale else [],
    )
    twin = TwinSnapshot(
        twin_version=1,
        timestamp=ref,
        assets={},
        identities={},
        relationships={},
        coverage_score=0.2 if stale else 0.9,
        freshness_score=0.15 if stale else 0.9,
        warnings=["low_twin_coverage"] if stale else [],
    )
    belief = BeliefSnapshot(
        belief_version=1,
        timestamp=ref,
        entity_beliefs={
            node.node_id: EntityBelief(
                entity_id=node.node_id,
                entity_type=node.entity_type,
                compromise_probability=node.compromise_probability,
                stage_distribution=_stage_dist(stage, 0.74 if high_risk else 0.12),
                most_likely_stage=stage if high_risk else "normal",
                uncertainty=0.25 if not stale else 0.75,
                confidence=0.85 if not stale else 0.35,
                evidence_ids=["evidence:direct"] if not stale and high_risk else [],
                candidate_attacker_location_probability=node.attacker_location_probability,
                last_updated=ref,
                belief_version=1,
            )
            for node in nodes
        },
    )
    paths = [
        AttackPath(
            path_id="path_seed_db",
            source_entity_id="asset:seed",
            target_entity_id="asset:critical_db",
            node_ids=["asset:seed", "asset:mid", "asset:critical_db"],
            edge_ids=["edge_seed_mid", "edge_mid_db"],
            path_length=2,
            path_type="highest_risk",
            success_probability=0.7,
            risk_score=0.82 if high_risk else 0.12,
            target_criticality=0.95,
            stage_compatibility=0.85,
            credential_feasibility=0.7,
            evidence_recency=0.2 if stale else 0.9,
            relationship_confidence=0.75,
            uncertainty=0.7 if stale else 0.2,
            reaches_protected_asset=protected,
            explanation="synthetic path",
        )
    ]
    path_analysis = AttackPathAnalysis(
        analysis_id=f"analysis_{scenario_id}",
        subgraph_id=subgraph.subgraph_id,
        reference_time=ref,
        paths=paths,
        top_risk_path_ids=["path_seed_db"],
        critical_assets_at_risk=["asset:critical_db"] if high_risk else [],
        candidate_deception_positions=["asset:mid"] if high_risk else [],
        uncovered_attack_surfaces=["asset:critical_db"] if high_risk else [],
        analysis_confidence=0.8 if not stale else 0.35,
        analysis_uncertainty=0.2 if not stale else 0.7,
    )
    actions, masks = _actions_for_scenario(scenario_id, ref, high_risk, protected, stale, decoy)
    allowed = [action.action_id for action in actions if masks[action.action_id].allowed]
    blocked = [action.action_id for action in actions if not masks[action.action_id].allowed]
    action_set = CandidateActionSet(
        action_set_id=stable_id("action-set", [scenario_id, *[action.action_id for action in actions]]),
        analysis_id=path_analysis.analysis_id,
        subgraph_id=subgraph.subgraph_id,
        reference_time=ref,
        actions=actions,
        masks=masks,
        allowed_action_ids=allowed,
        blocked_action_ids=blocked,
        recommended_action_ids=allowed[:5],
    )
    analysis = AttackAnalysisResult(
        analysis_id=path_analysis.analysis_id,
        reference_time=ref,
        twin_version="1",
        graph_version="rl_synthetic_graph_v1",
        belief_version=1,
        selected_seeds=subgraph.seed_entities,
        subgraph=subgraph,
        path_analysis=path_analysis,
        candidate_action_set=action_set,
        timing_ms={},
        warnings=["gnn_unavailable"] if "gnn_unavailable" in scenario_id else [],
    )
    return {
        "scenario_id": scenario_id,
        "topology_id": "topology_ood" if "ood" in scenario_id else "topology_rl_v1",
        "twin_snapshot": twin,
        "belief_snapshot": belief,
        "attack_analysis": analysis,
        "candidate_action_set": action_set,
        "selected_action_id": _selected_action_id_for_scenario(scenario_id, actions, masks),
        "outcome": _outcome_for_scenario(scenario_id),
    }


def build_synthetic_trajectories(
    scenarios: list[dict[str, Any]] | None = None,
    source_type: RLTrajectorySource = RLTrajectorySource.SYNTHETIC_FIXTURE,
    encoder: RLStateEncoder | None = None,
    reward_model: DefenseRewardModel | None = None,
) -> list[RLTrajectory]:
    encoder = encoder or RLStateEncoder()
    reward_model = reward_model or DefenseRewardModel()
    entries = scenarios or [build_rl_scenario(sid) for sid in SCENARIO_IDS]
    trajectories: list[RLTrajectory] = []
    for entry in entries:
        encoded = encoder.encode(
            entry["twin_snapshot"],
            entry["belief_snapshot"],
            entry["attack_analysis"],
            entry["candidate_action_set"],
            gnn_result=None,
        )
        selected_id = entry["selected_action_id"]
        selected_feature = next(
            feature for feature in encoded.candidate_action_features
            if feature.action_id == selected_id
        )
        reward = reward_model.compute(encoded, selected_feature, None, entry["outcome"])
        episode_id = stable_id("episode", [entry["scenario_id"], source_type.value])
        transition = RLTransition(
            episode_id=episode_id,
            step_index=0,
            state_reference=encoded.state_reference,
            state_feature_vector=encoded.feature_vector,
            state_feature_mask=encoded.feature_mask,
            candidate_action_features=encoded.candidate_action_features,
            allowed_action_ids=encoded.allowed_action_ids,
            masked_action_ids=encoded.masked_action_ids,
            selected_action_id=selected_id,
            selected_high_level_tactic=selected_feature.tactic_category,
            behavior_policy_source=_policy_source_for_scenario(entry["scenario_id"]),
            behavior_policy_probability=0.75,
            reward_components=reward,
            scalar_reward=reward.scalar_reward,
            hard_constraint_violations=reward.hard_constraint_violations,
            terminal=True,
            termination_reason=entry["outcome"].get("termination_reason", "synthetic_single_step"),
            safety_verdict=selected_feature.safety_gate_verdict,
            execution_or_shadow_outcome=entry["outcome"],
            uncertainty=selected_feature.uncertainty,
            provenance={"scenario_id": entry["scenario_id"]},
            timestamp=entry["attack_analysis"].reference_time,
        )
        trajectories.append(RLTrajectory(
            trajectory_id=stable_id("traj", [entry["scenario_id"], source_type.value]),
            scenario_id=entry["scenario_id"],
            topology_id=entry["topology_id"],
            source_type=source_type,
            policy_source=transition.behavior_policy_source,
            transitions=[transition],
            total_return=transition.scalar_reward,
            total_business_cost=selected_feature.business_risk,
            total_asset_loss=float(entry["outcome"].get("asset_loss", 0.0)),
            interception_result="intercepted" if entry["outcome"].get("decoy_interception") else "not_intercepted",
            safety_violation_count=len(transition.hard_constraint_violations),
            dataset_split=split_for_scenario(entry["scenario_id"], entry["topology_id"], source_type.value),
            labels={"expected_behavior": entry["outcome"].get("expected_behavior", "")},
            provenance={"synthetic": "true"},
            warnings=encoded.warnings,
        ))
    return trajectories


def _actions_for_scenario(scenario_id: str, ref, high_risk: bool, protected: bool, stale: bool, decoy: bool):
    specs = [
        ("increase_network_telemetry", 0.15, 0.8, 0.05, RiskTier.LOW.value, AutomationLevel.AUTOMATIC_WITH_MONITORING.value, False),
        ("request_analyst_review", 0.05, 0.75, 0.01, RiskTier.LOW.value, AutomationLevel.RECOMMEND_ONLY.value, False),
        ("deploy_decoy_database", 0.65 if high_risk else 0.15, 0.55, 0.10, RiskTier.MEDIUM.value, AutomationLevel.RECOMMEND_ONLY.value, protected),
        ("throttle_edge", 0.55 if high_risk else 0.05, 0.2, 0.2, RiskTier.MEDIUM.value, AutomationLevel.RECOMMEND_ONLY.value, protected),
        ("isolate_host", 0.75 if high_risk else 0.05, 0.1, 0.75, RiskTier.HIGH.value, AutomationLevel.HUMAN_APPROVAL_REQUIRED.value, True),
    ]
    if "no_valid_action" in scenario_id:
        specs = [("isolate_host", 0.6, 0.1, 0.75, RiskTier.HIGH.value, AutomationLevel.HUMAN_APPROVAL_REQUIRED.value, True)]
    actions = []
    masks = {}
    for action_type, risk_reduction, info_gain, business_risk, risk_tier, automation, approval in specs:
        action = CandidateDefenseAction(
            action_id=stable_id("action", [scenario_id, action_type]),
            action_type=action_type,
            target_entity_ids=["asset:critical_db"] if "database" in action_type else ["asset:seed"],
            affected_path_ids=["path_seed_db"],
            affected_edge_ids=["edge_mid_db"] if action_type in {"throttle_edge", "isolate_host"} else [],
            expected_risk_reduction=risk_reduction,
            expected_information_gain=info_gain,
            operational_cost=0.2 + business_risk,
            business_risk=business_risk,
            deployment_cost=0.2 + business_risk,
            confidence=0.35 if stale else 0.82,
            uncertainty=0.75 if stale else 0.2 + business_risk * 0.2,
            risk_tier=risk_tier,
            automation_level=automation,
            requires_approval=approval,
            rollback_supported=action_type not in {"request_analyst_review"},
            rollback_plan=f"expire {action_type}",
            ttl_seconds=3600,
            reason=f"synthetic {scenario_id} {action_type}",
            generated_at=ref,
        )
        allowed = not (stale and action_type in {"throttle_edge", "isolate_host"}) and (
            "no_valid_action" not in scenario_id
        )
        if "excessive_business_risk" in scenario_id and action_type == "isolate_host":
            allowed = False
        mask = ActionMask(
            action_id=action.action_id,
            allowed=allowed,
            mask_reasons=[] if allowed else ["low_twin_quality" if stale else "business_risk_too_high"],
            required_conditions=["human approval"] if approval else [],
            approval_required=approval,
            effective_risk_tier=risk_tier,
        )
        actions.append(action)
        masks[action.action_id] = mask
    if "no_valid_action" in scenario_id:
        noop = CandidateDefenseAction(
            action_id="__NO_OP__",
            action_type="__NO_OP__",
            expected_risk_reduction=0.0,
            expected_information_gain=0.0,
            operational_cost=0.0,
            business_risk=0.0,
            deployment_cost=0.0,
            confidence=1.0,
            uncertainty=0.0,
            risk_tier=RiskTier.LOW.value,
            automation_level=AutomationLevel.RECOMMEND_ONLY.value,
            requires_approval=False,
            rollback_supported=True,
            reason="no valid defensive action",
            generated_at=ref,
        )
        actions.append(noop)
        masks[noop.action_id] = ActionMask(
            action_id=noop.action_id,
            allowed=True,
            mask_reasons=[],
            required_conditions=[],
            approval_required=False,
            effective_risk_tier=RiskTier.LOW.value,
        )
    return actions, masks


def _selected_action_id_for_scenario(scenario_id: str, actions, masks) -> str:
    preferred = "increase_network_telemetry"
    if "decoy" in scenario_id or "deception" in scenario_id or "multiple_paths" in scenario_id:
        preferred = "deploy_decoy_database"
    if "stale" in scenario_id or "protected" in scenario_id or "excessive" in scenario_id or "analyst_rejects" in scenario_id:
        preferred = "request_analyst_review"
    if "limited_budget" in scenario_id or "discovery_without" in scenario_id:
        preferred = "increase_network_telemetry"
    if "no_valid_action" in scenario_id:
        preferred = "__NO_OP__"
    for action in actions:
        if action.action_type == preferred and masks[action.action_id].allowed:
            return action.action_id
    return next(action.action_id for action in actions if masks[action.action_id].allowed)


def _outcome_for_scenario(scenario_id: str) -> dict[str, Any]:
    outcome = {
        "protected_asset_safe": True,
        "risk_reduction": 0.4,
        "information_gain": 0.4,
        "delay_delta": 0.2,
        "termination_reason": "maximum_episode_length",
        "expected_behavior": "conservative_action_selection",
    }
    if "decoy" in scenario_id or "deception" in scenario_id:
        outcome["decoy_interception"] = 1.0
    if "analyst_rejects" in scenario_id:
        outcome["analyst_decision"] = "UNSAFE"
    if "benign" in scenario_id:
        outcome.update({"risk_reduction": 0.05, "information_gain": 0.6, "false_positive": 0.0})
    if "no_valid_action" in scenario_id:
        outcome.update({"risk_reduction": 0.0, "information_gain": 0.0})
    return outcome


def _policy_source_for_scenario(scenario_id: str) -> str:
    if "robust" in scenario_id:
        return "robust_planner"
    if "analyst" in scenario_id:
        return "analyst_reviewed"
    if "no_valid" in scenario_id:
        return "heuristic_policy"
    return "heuristic_policy"


def _stage_for_scenario(scenario_id: str) -> str:
    if "credential" in scenario_id:
        return "credential_access"
    if "discovery" in scenario_id:
        return "discovery"
    if "benign" in scenario_id:
        return "normal"
    if "decoy" in scenario_id:
        return "lateral_movement"
    return "lateral_movement"


def _stage_dist(dominant: str, probability: float) -> dict[str, float]:
    if dominant not in STAGE_NAMES_V1:
        dominant = "normal"
    rest = [stage for stage in STAGE_NAMES_V1 if stage != dominant]
    remaining = 1.0 - probability
    per = remaining / max(1, len(rest))
    dist = {stage: round(per, 6) for stage in rest}
    dist[dominant] = round(probability, 6)
    total = sum(dist.values())
    dist[dominant] = round(dist[dominant] + 1.0 - total, 6)
    return dist
