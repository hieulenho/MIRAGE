"""Extended robust decision adapter for MIRAGE GNN Milestone 6.

Extends the existing robust_input_from_candidate_action_set to optionally
attach GNN-derived features (subgraph embedding, node/edge risk, uncertainty,
OOD flags) to the RobustDecisionInput.

The robust decision engine continues working WITHOUT a GNN model.
Mathematical behavior is NOT modified — GNN features are supplementary only.
"""

from __future__ import annotations

from mirage.analysis.robust_adapter import robust_input_from_candidate_action_set
from mirage.domain.schemas import (
    AttackPathAnalysis,
    BeliefSnapshot,
    CandidateActionSet,
    RobustDecisionInput,
)
from mirage.gnn.schema import GNNDecisionFeatures, GNNInferenceResult


def robust_input_with_gnn(
    candidate_action_set: CandidateActionSet,
    attack_path_analysis: AttackPathAnalysis,
    belief_snapshot: BeliefSnapshot,
    gnn_result: GNNInferenceResult | None = None,
) -> tuple[RobustDecisionInput, GNNDecisionFeatures | None]:
    """Create a RobustDecisionInput and optional GNNDecisionFeatures.

    Parameters
    ----------
    candidate_action_set, attack_path_analysis, belief_snapshot:
        Same as existing robust_input_from_candidate_action_set().
    gnn_result:
        Optional GNN inference result.  If None or fallback_recommended,
        GNN features are not attached.

    Returns
    -------
    (robust_input, gnn_features_or_none)
        robust_input is the standard RobustDecisionInput.
        gnn_features is attached supplementary GNN data (or None).
    """
    robust_input = robust_input_from_candidate_action_set(
        candidate_action_set, attack_path_analysis, belief_snapshot
    )

    if gnn_result is None or gnn_result.fallback_recommended:
        return robust_input, None

    # Build node risk map  (entity_id → risk_probability)
    node_risk_map: dict[str, float] = {}
    for node_id, prob in zip(
        gnn_result.node_ids,
        gnn_result.gnn_output.node_risk_probabilities,
    ):
        node_risk_map[node_id] = round(float(prob), 6)

    # Build edge movement map
    edge_movement_map: dict[str, float] = {}
    for edge_id, prob in zip(
        gnn_result.edge_ids,
        gnn_result.gnn_output.edge_movement_probabilities,
    ):
        edge_movement_map[edge_id] = round(float(prob), 6)

    ood_flag_strs = [w.warning_type for w in gnn_result.ood_warnings]

    gnn_features = GNNDecisionFeatures(
        subgraph_embedding=list(gnn_result.gnn_output.graph_embedding),
        node_risk_by_entity_id=node_risk_map,
        edge_movement_by_edge_id=edge_movement_map,
        graph_risk=round(float(gnn_result.gnn_output.graph_risk_probability), 6),
        graph_uncertainty=round(float(gnn_result.gnn_output.graph_uncertainty), 6),
        ood_flags=ood_flag_strs,
        model_version=gnn_result.model_version,
        feature_schema_version=gnn_result.feature_schema_version,
    )

    return robust_input, gnn_features
