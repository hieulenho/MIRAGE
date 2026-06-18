"""Compatibility adapter for future robust-decision consumption."""

from __future__ import annotations

from mirage.domain.schemas import (
    AttackPathAnalysis,
    BeliefSnapshot,
    CandidateActionSet,
    RobustDecisionInput,
)


def robust_input_from_candidate_action_set(
    candidate_action_set: CandidateActionSet,
    attack_path_analysis: AttackPathAnalysis,
    belief_snapshot: BeliefSnapshot,
) -> RobustDecisionInput:
    """Create a deterministic robust-decision input payload.

    This adapter does not rewrite the current robust decision engine. It
    provides structured action utilities and masks that a later bridge can map
    onto simulator-native `DeceptionAction` portfolios.
    """
    actions = {action.action_id: action for action in candidate_action_set.actions}
    return RobustDecisionInput(
        action_set_id=candidate_action_set.action_set_id,
        analysis_id=candidate_action_set.analysis_id,
        available_action_ids=list(candidate_action_set.allowed_action_ids),
        action_masks=candidate_action_set.masks,
        expected_utilities={
            action_id: round(
                action.expected_risk_reduction
                + action.expected_information_gain * 0.4
                - action.business_risk * 0.4
                - action.uncertainty * 0.2,
                6,
            )
            for action_id, action in actions.items()
            if action_id in candidate_action_set.allowed_action_ids
        },
        pessimistic_factors={
            path.path_id: round(1.0 - path.uncertainty, 6)
            for path in attack_path_analysis.paths
        },
        operational_costs={
            action_id: action.operational_cost for action_id, action in actions.items()
        },
        business_risks={
            action_id: action.business_risk for action_id, action in actions.items()
        },
        uncertainties={
            action_id: action.uncertainty for action_id, action in actions.items()
        },
        affected_attack_paths={
            action_id: list(action.affected_path_ids)
            for action_id, action in actions.items()
        },
        budget_requirements={
            action_id: action.deployment_cost for action_id, action in actions.items()
        },
        warnings=[
            "Heuristic utilities are not calibrated production rewards.",
            f"Belief version used: {belief_snapshot.belief_version}",
        ],
    )
