"""Uncertainty estimation and OOD detection for MIRAGE GNN."""
from __future__ import annotations
import math
from mirage.gnn.schema import GNNOutput, GraphFeatureSchema, GraphSample, OODWarning


def predictive_entropy(probabilities: list[float]) -> float:
    if not probabilities:
        return 1.0
    entropies = []
    for p in probabilities:
        p = max(1e-8, min(1 - 1e-8, p))
        h = -(p * math.log(p) + (1 - p) * math.log(1 - p))
        entropies.append(h)
    return sum(entropies) / len(entropies)


def calibration_error(y_true: list[int], y_prob: list[float], n_bins: int = 10) -> float:
    if not y_true:
        return 0.0
    bin_size = 1.0 / n_bins
    ece = 0.0
    n = len(y_true)
    for b in range(n_bins):
        lo = b * bin_size
        hi = lo + bin_size
        indices = [i for i, p in enumerate(y_prob) if lo <= p < hi]
        if not indices:
            continue
        acc = sum(y_true[i] for i in indices) / len(indices)
        conf = sum(y_prob[i] for i in indices) / len(indices)
        ece += abs(acc - conf) * (len(indices) / n)
    return ece


class OODDetector:
    """Detect out-of-distribution inputs before or after GNN inference."""

    def __init__(
        self,
        schema: GraphFeatureSchema | None = None,
        feature_stats: dict[str, dict[str, float]] | None = None,
        max_nodes_train: int = 80,
        max_edges_train: int = 160,
        uncertainty_threshold: float = 0.4,
        missing_feature_threshold: float = 0.3,
        min_coverage_threshold: float = 0.25,
    ) -> None:
        self.schema = schema or GraphFeatureSchema()
        self.feature_stats = feature_stats or {}
        self.max_nodes_train = max_nodes_train
        self.max_edges_train = max_edges_train
        self.uncertainty_threshold = uncertainty_threshold
        self.missing_feature_threshold = missing_feature_threshold
        self.min_coverage_threshold = min_coverage_threshold

    def check_sample(self, sample: GraphSample) -> list[OODWarning]:
        warnings: list[OODWarning] = []
        known_node_types = set(self.schema.node_entity_types)
        for nt in sample.node_types:
            if nt not in known_node_types:
                warnings.append(OODWarning(
                    warning_type="unseen_node_type",
                    details=f"Node type {nt!r} not in training vocabulary.",
                    severity="high",
                ))
        known_edge_types = set(self.schema.edge_relationship_types)
        for et in sample.edge_types:
            if et not in known_edge_types:
                warnings.append(OODWarning(
                    warning_type="unseen_edge_type",
                    details=f"Edge type {et!r} not in training vocabulary.",
                    severity="high",
                ))
        if sample.num_nodes > self.max_nodes_train:
            warnings.append(OODWarning(
                warning_type="topology_size_ood",
                details=f"Graph has {sample.num_nodes} nodes (max: {self.max_nodes_train}).",
                severity="medium",
            ))
        if sample.num_edges > self.max_edges_train:
            warnings.append(OODWarning(
                warning_type="topology_size_ood",
                details=f"Graph has {sample.num_edges} edges (max: {self.max_edges_train}).",
                severity="medium",
            ))
        if sample.node_feature_mask:
            all_mask_vals = [v for row in sample.node_feature_mask for v in row]
            if all_mask_vals:
                frac_missing = 1.0 - sum(all_mask_vals) / len(all_mask_vals)
                if frac_missing > self.missing_feature_threshold:
                    warnings.append(OODWarning(
                        warning_type="excessive_missing_features",
                        details=f"{frac_missing:.1%} of node features are missing.",
                        severity="medium",
                    ))
        if "low_twin_coverage" in sample.warnings:
            warnings.append(OODWarning(
                warning_type="low_twin_coverage",
                details="Digital Twin coverage is below 25%.",
                severity="high",
            ))
        if self.feature_stats and sample.node_feature_matrix:
            for feat_name, stats in self.feature_stats.items():
                idx_list = [
                    i for i, n in enumerate(self.schema.node_feature_names)
                    if n == feat_name
                ]
                if not idx_list:
                    continue
                feat_idx = idx_list[0]
                mean_t = stats.get("mean", 0.5)
                std_t = stats.get("std", 0.5)
                for row in sample.node_feature_matrix:
                    if feat_idx < len(row):
                        deviation = abs(row[feat_idx] - mean_t) / max(std_t, 1e-8)
                        if deviation > 4.0:
                            warnings.append(OODWarning(
                                warning_type="feature_value_ood",
                                details=f"Feature {feat_name!r}: {row[feat_idx]:.3f} ({deviation:.1f}sigma from training mean).",
                                severity="low",
                            ))
                            break
        return warnings

    def check_output(
        self,
        gnn_output: GNNOutput,
        ood_warnings: list[OODWarning],
    ) -> tuple[bool, bool]:
        mean_uncertainty = (
            sum(gnn_output.node_uncertainty) / len(gnn_output.node_uncertainty)
            if gnn_output.node_uncertainty
            else gnn_output.graph_uncertainty
        )
        high_unc = mean_uncertainty > self.uncertainty_threshold
        high_severity_ood = any(w.severity == "high" for w in ood_warnings)
        fallback = high_unc or high_severity_ood
        return high_unc, fallback

    def gnn_trust_weight(
        self,
        gnn_output: GNNOutput,
        ood_warnings: list[OODWarning],
        base_gnn_weight: float = 0.4,
    ) -> float:
        high_unc, fallback = self.check_output(gnn_output, ood_warnings)
        if fallback:
            return 0.0
        mean_unc = (
            sum(gnn_output.node_uncertainty) / len(gnn_output.node_uncertainty)
            if gnn_output.node_uncertainty
            else gnn_output.graph_uncertainty
        )
        reduction = min(1.0, mean_unc / max(self.uncertainty_threshold, 1e-8))
        return base_gnn_weight * (1.0 - reduction * 0.5)
