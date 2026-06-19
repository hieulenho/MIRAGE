"""Baseline models for MIRAGE GNN Milestone 6.

All baselines expose the same interface as GNNStateEncoder so results
can be compared directly.  GNN claims of improvement must beat ALL of:
  - HeuristicBaseline (existing AttackPathRiskScorer)
  - LogisticBaseline  (scikit-learn LogisticRegression on flat node features)
  - MLPBaseline       (scikit-learn MLPClassifier on flat node features)

None of these baselines require PyTorch.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from mirage.gnn.schema import GraphFeatureSchema, GraphSample


# ---------------------------------------------------------------------------
# Shared interface
# ---------------------------------------------------------------------------

class BaselineModel:
    """Abstract baseline model interface."""

    name: str = "baseline"

    def fit(self, samples: list[GraphSample]) -> "BaselineModel":
        """Train on labelled samples.  Returns self."""
        raise NotImplementedError

    def predict(self, sample: GraphSample) -> dict[str, Any]:
        """Return node-level predictions.

        Output dict contains:
          node_risk_probabilities: list[float] (one per node)
          graph_risk_probability: float
          node_ids: list[str]
        """
        raise NotImplementedError

    def evaluate(self, samples: list[GraphSample]) -> dict[str, float]:
        """Compute node-level metrics over a sample list."""
        y_true: list[int] = []
        y_prob: list[float] = []
        for sample in samples:
            if sample.labels is None:
                continue
            preds = self.predict(sample)
            probs = preds.get("node_risk_probabilities", [])
            for node_id, prob in zip(sample.node_ids, probs):
                nl = sample.labels.node_labels.get(node_id)
                if nl is None:
                    continue
                y_true.append(int(nl.is_compromised))
                y_prob.append(float(prob))
        return _classification_metrics(y_true, y_prob, self.name)


# ---------------------------------------------------------------------------
# Heuristic baseline — wraps existing belief-based scores
# ---------------------------------------------------------------------------

class HeuristicBaseline(BaselineModel):
    """Use existing compromise_probability from BeliefSnapshot as predictor.

    No training required.  The heuristic risk score comes directly from the
    node feature matrix column for 'compromise_probability'.
    """

    name = "heuristic_belief"

    def __init__(self, schema: GraphFeatureSchema | None = None) -> None:
        self.schema = schema or GraphFeatureSchema()
        self._comp_idx = self.schema.node_feature_names.index("compromise_probability")
        self._edge_move_idx = self.schema.edge_feature_names.index("movement_likelihood")

    def fit(self, samples: list[GraphSample]) -> "HeuristicBaseline":
        return self  # no training

    def predict(self, sample: GraphSample) -> dict[str, Any]:
        probs: list[float] = []
        for feat_row in sample.node_feature_matrix:
            if feat_row:
                probs.append(float(feat_row[self._comp_idx]))
            else:
                probs.append(0.0)
        graph_prob = max(probs) if probs else 0.0
        edge_probs = [
            float(row[self._edge_move_idx]) if row else 0.0
            for row in sample.edge_feature_matrix
        ]
        return {
            "node_ids": list(sample.node_ids),
            "node_risk_probabilities": probs,
            "edge_movement_probabilities": edge_probs,
            "graph_risk_probability": graph_prob,
        }


# ---------------------------------------------------------------------------
# Logistic regression baseline
# ---------------------------------------------------------------------------

class LogisticBaseline(BaselineModel):
    """Logistic regression on flat node features (scikit-learn)."""

    name = "logistic_regression"

    def __init__(self, schema: GraphFeatureSchema | None = None,
                 max_iter: int = 1000, random_state: int = 42) -> None:
        self.schema = schema or GraphFeatureSchema()
        self.max_iter = max_iter
        self.random_state = random_state
        self._model: Any = None
        self._is_fitted = False

    def fit(self, samples: list[GraphSample]) -> "LogisticBaseline":
        try:
            from sklearn.linear_model import LogisticRegression
        except ImportError:
            self._is_fitted = False
            return self

        X, y = _flatten_node_data(samples)
        if len(X) < 2 or len(set(y)) < 2:
            # Cannot fit; keep defaults
            return self
        self._model = LogisticRegression(
            max_iter=self.max_iter,
            random_state=self.random_state,
            class_weight="balanced",
        )
        self._model.fit(X, y)
        self._is_fitted = True
        return self

    def predict(self, sample: GraphSample) -> dict[str, Any]:
        if not self._is_fitted or self._model is None or not sample.node_feature_matrix:
            probs = [0.5] * len(sample.node_ids)
        else:
            X = np.array(sample.node_feature_matrix, dtype=np.float32)
            probs = self._model.predict_proba(X)[:, 1].tolist()
        graph_prob = max(probs) if probs else 0.0
        edge_probs = _edge_movement_probs(sample, self.schema)
        return {
            "node_ids": list(sample.node_ids),
            "node_risk_probabilities": probs,
            "edge_movement_probabilities": edge_probs,
            "graph_risk_probability": graph_prob,
        }


# ---------------------------------------------------------------------------
# MLP baseline
# ---------------------------------------------------------------------------

class MLPBaseline(BaselineModel):
    """MLP classifier on flat node features (scikit-learn)."""

    name = "mlp"

    def __init__(self, schema: GraphFeatureSchema | None = None,
                 hidden_layer_sizes: tuple[int, ...] = (64, 32),
                 max_iter: int = 500, random_state: int = 42) -> None:
        self.schema = schema or GraphFeatureSchema()
        self.hidden_layer_sizes = hidden_layer_sizes
        self.max_iter = max_iter
        self.random_state = random_state
        self._model: Any = None
        self._is_fitted = False

    def fit(self, samples: list[GraphSample]) -> "MLPBaseline":
        try:
            from sklearn.neural_network import MLPClassifier
        except ImportError:
            self._is_fitted = False
            return self

        X, y = _flatten_node_data(samples)
        if len(X) < 2 or len(set(y)) < 2:
            return self
        self._model = MLPClassifier(
            hidden_layer_sizes=self.hidden_layer_sizes,
            max_iter=self.max_iter,
            random_state=self.random_state,
        )
        self._model.fit(X, y)
        self._is_fitted = True
        return self

    def predict(self, sample: GraphSample) -> dict[str, Any]:
        if not self._is_fitted or self._model is None or not sample.node_feature_matrix:
            probs = [0.5] * len(sample.node_ids)
        else:
            X = np.array(sample.node_feature_matrix, dtype=np.float32)
            probs = self._model.predict_proba(X)[:, 1].tolist()
        graph_prob = max(probs) if probs else 0.0
        edge_probs = _edge_movement_probs(sample, self.schema)
        return {
            "node_ids": list(sample.node_ids),
            "node_risk_probabilities": probs,
            "edge_movement_probabilities": edge_probs,
            "graph_risk_probability": graph_prob,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_node_data(
    samples: list[GraphSample],
) -> tuple[np.ndarray, np.ndarray]:
    """Build X, y arrays from labelled node features."""
    X_rows: list[list[float]] = []
    y_vals: list[int] = []
    for sample in samples:
        if sample.labels is None:
            continue
        for node_id, feat_row in zip(sample.node_ids, sample.node_feature_matrix):
            nl = sample.labels.node_labels.get(node_id)
            if nl is None:
                continue
            X_rows.append(feat_row)
            y_vals.append(int(nl.is_compromised))
    if not X_rows:
        return np.zeros((0, 1), dtype=np.float32), np.zeros(0, dtype=np.int32)
    return np.array(X_rows, dtype=np.float32), np.array(y_vals, dtype=np.int32)


def _classification_metrics(
    y_true: list[int],
    y_prob: list[float],
    name: str,
) -> dict[str, float]:
    """Compute basic classification metrics without sklearn dependency."""
    n = len(y_true)
    if n == 0:
        return {"n_samples": 0.0}
    threshold = 0.5
    y_pred = [1 if p >= threshold else 0 for p in y_prob]
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    acc = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp) / n
    brier = sum((p - t) ** 2 for p, t in zip(y_prob, y_true)) / n
    return {
        "n_samples": float(n),
        "accuracy": round(acc, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "brier_score": round(brier, 4),
    }


def _edge_movement_probs(
    sample: GraphSample,
    schema: GraphFeatureSchema,
) -> list[float]:
    """Return heuristic edge-movement probabilities from edge features."""
    try:
        idx = schema.edge_feature_names.index("movement_likelihood")
    except ValueError:
        return [0.5] * len(sample.edge_ids)
    return [
        float(row[idx]) if row and idx < len(row) else 0.5
        for row in sample.edge_feature_matrix
    ]


def compare_baselines(
    baselines: list[BaselineModel],
    test_samples: list[GraphSample],
) -> dict[str, dict[str, float]]:
    """Evaluate all baselines and return comparison table."""
    return {b.name: b.evaluate(test_samples) for b in baselines}
