"""Hybrid path-risk scoring adapter for MIRAGE GNN Milestone 6.

Combines existing heuristic AttackPathRiskScorer output with optional
GNN-learned edge-risk predictions.

Operating modes (GNNOperatingMode):
  heuristic_only         — GNN output is ignored entirely
  gnn_shadow (DEFAULT)   — GNN predictions are logged but DO NOT modify scores
  hybrid_recommendation  — Hybrid score is used for ranking

Hard constraints that GNN CANNOT override:
  - Protected-asset rules
  - Decoy rules
  - Action masks from Safety Gate

Formula:
  hybrid_risk = heuristic_w × heuristic_risk + gnn_w × gnn_edge_risk
  where gnn_w → 0 when model unavailable, OOD, or high uncertainty.
"""

from __future__ import annotations

from typing import Any

from mirage.analysis.paths import AttackPathRiskScorer
from mirage.domain.schemas import AttackPath, BeliefSnapshot, LocalOperationalSubgraph
from mirage.gnn.schema import (
    GNNInferenceResult,
    GNNOperatingMode,
    GraphFeatureSchema,
    HybridPathRisk,
)
from mirage.gnn.uncertainty import OODDetector


class HybridPathRiskAdapter:
    """Combine heuristic and GNN path-risk scores.

    Parameters
    ----------
    heuristic_weight:
        Weight for the existing heuristic score (0..1).
    gnn_weight:
        Maximum weight for the GNN score (0..1).
        Reduced to 0 automatically when model unavailable or OOD.
    operating_mode:
        Default operating mode.
    schema:
        Feature schema for OOD detection.
    ood_detector:
        OOD detector.  Uses defaults if not provided.
    """

    def __init__(
        self,
        heuristic_weight: float = 0.7,
        gnn_weight: float = 0.3,
        operating_mode: GNNOperatingMode = GNNOperatingMode.GNN_SHADOW,
        schema: GraphFeatureSchema | None = None,
        ood_detector: OODDetector | None = None,
    ) -> None:
        if abs(heuristic_weight + gnn_weight - 1.0) > 1e-6:
            raise ValueError(
                f"heuristic_weight + gnn_weight must sum to 1.0 "
                f"(got {heuristic_weight} + {gnn_weight})."
            )
        self.heuristic_weight = heuristic_weight
        self.gnn_weight = gnn_weight
        self.operating_mode = operating_mode
        self.schema = schema or GraphFeatureSchema()
        self.ood_detector = ood_detector or OODDetector(schema=self.schema)
        self._heuristic_scorer = AttackPathRiskScorer()
        self._shadow_log: list[HybridPathRisk] = []

    def score_paths(
        self,
        paths: list[AttackPath],
        subgraph: LocalOperationalSubgraph,
        belief_snapshot: BeliefSnapshot,
        reference_time: Any,
        gnn_result: GNNInferenceResult | None = None,
    ) -> list[tuple[AttackPath, HybridPathRisk]]:
        """Score each path and return (updated_path, hybrid_risk) pairs.

        In gnn_shadow mode the AttackPath risk_score is NOT modified;
        only the HybridPathRisk is recorded.
        """
        # First apply heuristic scorer (always runs)
        heuristic_scored = [
            self._heuristic_scorer.score(path, subgraph, belief_snapshot, reference_time)
            for path in paths
        ]

        # Build edge-risk map from GNN result
        gnn_edge_risks: dict[str, float] = {}
        effective_gnn_weight = 0.0

        if gnn_result is not None and not gnn_result.fallback_recommended:
            # Compute effective GNN weight based on uncertainty and OOD
            effective_gnn_weight = self.ood_detector.gnn_trust_weight(
                gnn_result.gnn_output,
                gnn_result.ood_warnings,
                base_gnn_weight=self.gnn_weight,
            )
            for edge_id, prob in zip(
                gnn_result.edge_ids,
                gnn_result.gnn_output.edge_movement_probabilities,
            ):
                gnn_edge_risks[edge_id] = float(prob)

        results: list[tuple[AttackPath, HybridPathRisk]] = []
        for path in heuristic_scored:
            h_risk = float(path.risk_score)

            # Mean GNN edge risk for this path's edges
            gnn_edge_scores = [
                gnn_edge_risks[eid]
                for eid in path.edge_ids
                if eid in gnn_edge_risks
            ]
            gnn_edge_risk: float | None = (
                sum(gnn_edge_scores) / len(gnn_edge_scores)
                if gnn_edge_scores
                else None
            )

            # Cannot override protected-asset or decoy constraints
            protected_override_attempt = path.reaches_protected_asset
            decoy_override_attempt = path.contains_decoy
            path_gnn_weight = effective_gnn_weight

            # Compute hybrid score
            if (
                self.operating_mode == GNNOperatingMode.HYBRID_RECOMMENDATION
                and gnn_edge_risk is not None
                and not gnn_result.fallback_recommended  # type: ignore[union-attr]
                and path_gnn_weight > 0
                and not protected_override_attempt
                and not decoy_override_attempt
            ):
                effective_heuristic_w = 1.0 - path_gnn_weight
                hybrid = (
                    effective_heuristic_w * h_risk
                    + path_gnn_weight * gnn_edge_risk
                )
                # Clamp
                hybrid = max(0.0, min(1.0, hybrid))
            else:
                # shadow or heuristic_only: always use heuristic score
                hybrid = h_risk
                path_gnn_weight = 0.0

            ood_flag = gnn_result is not None and bool(gnn_result.ood_warnings)
            unc_high = gnn_result is not None and gnn_result.uncertainty_high

            hybrid_risk = HybridPathRisk(
                path_id=path.path_id,
                heuristic_risk=h_risk,
                gnn_edge_risk=gnn_edge_risk,
                hybrid_risk=hybrid,
                heuristic_weight=1.0 - path_gnn_weight,
                gnn_weight=path_gnn_weight,
                operating_mode=self.operating_mode,
                gnn_contribution=round(
                    path_gnn_weight * (gnn_edge_risk or 0.0), 6
                ),
                heuristic_contribution=round(
                    (1.0 - path_gnn_weight) * h_risk, 6
                ),
                uncertainty_high=unc_high,
                ood_warning=ood_flag,
                fallback_active=path_gnn_weight == 0.0,
                explanation=(
                    f"Mode={self.operating_mode.value}; "
                    f"heuristic={h_risk:.3f}, gnn_edge={gnn_edge_risk}, "
                    f"hybrid={hybrid:.3f}, gnn_w={path_gnn_weight:.3f}."
                ),
            )

            # In shadow mode: path risk_score is UNCHANGED
            if self.operating_mode in {
                GNNOperatingMode.GNN_SHADOW,
                GNNOperatingMode.HEURISTIC_ONLY,
            }:
                final_path = path  # heuristic score preserved
            else:
                # hybrid mode: update path score
                final_path = path.model_copy(
                    update={"risk_score": round(hybrid, 6)}
                )

            self._shadow_log.append(hybrid_risk)
            results.append((final_path, hybrid_risk))

        return results

    def get_shadow_log(self) -> list[HybridPathRisk]:
        """Return all hybrid risk records logged so far."""
        return list(self._shadow_log)

    def clear_shadow_log(self) -> None:
        """Clear the in-memory shadow log."""
        self._shadow_log.clear()
