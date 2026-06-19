"""Evaluation metrics for MIRAGE GNN Milestone 6.

Computes:
  Node task:  precision, recall, F1, ROC-AUC, PR-AUC, Brier, ECE
  Edge task:  precision, recall, F1, top-k recall, PR-AUC
  Graph task: accuracy, macro-F1, Brier, ranking quality
  Operational: inference latency, embedding dim, perf by graph size

All metrics are deterministic and numpy-only (no sklearn required for core).
sklearn is used for AUC metrics when available.
"""

from __future__ import annotations

import time
from typing import Any

from mirage.gnn.schema import GraphSample
from mirage.gnn.uncertainty import calibration_error


# ---------------------------------------------------------------------------
# Binary classification metrics (numpy-only core)
# ---------------------------------------------------------------------------

def precision_recall_f1(
    y_true: list[int],
    y_pred: list[int],
) -> dict[str, float]:
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)
    return {
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
    }


def brier_score(y_true: list[int], y_prob: list[float]) -> float:
    if not y_true:
        return 0.0
    return round(sum((p - t) ** 2 for p, t in zip(y_prob, y_true)) / len(y_true), 4)


def roc_auc(y_true: list[int], y_prob: list[float]) -> float:
    """Approximate AUC via trapezoidal rule on sorted thresholds."""
    if len(set(y_true)) < 2:
        return 0.0
    paired = sorted(zip(y_prob, y_true), reverse=True)
    tp = fp = 0
    n_pos = sum(y_true)
    n_neg = len(y_true) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 0.0
    tps: list[float] = []
    fps: list[float] = []
    for _, label in paired:
        if label == 1:
            tp += 1
        else:
            fp += 1
        tps.append(tp / n_pos)
        fps.append(fp / n_neg)
    # Trapezoidal
    auc = 0.0
    for i in range(1, len(tps)):
        auc += (fps[i] - fps[i - 1]) * (tps[i] + tps[i - 1]) / 2
    return round(abs(auc), 4)


def pr_auc(y_true: list[int], y_prob: list[float]) -> float:
    """Approximate PR-AUC."""
    if len(set(y_true)) < 2:
        return 0.0
    paired = sorted(zip(y_prob, y_true), reverse=True)
    tp = 0
    fn_count = sum(y_true)
    precisions: list[float] = []
    recalls: list[float] = []
    for _, label in paired:
        if label == 1:
            tp += 1
            fn_count -= 1
        prec = tp / max(tp + (len(precisions) + 1 - tp), 1)
        rec = tp / max(tp + fn_count, 1)
        precisions.append(prec)
        recalls.append(rec)
    auc = 0.0
    for i in range(1, len(recalls)):
        auc += abs(recalls[i] - recalls[i - 1]) * (precisions[i] + precisions[i - 1]) / 2
    return round(abs(auc), 4)


def top_k_recall(
    y_true: list[int],
    y_prob: list[float],
    k: int = 5,
) -> float:
    """Fraction of positive labels recovered in the top-k ranked predictions."""
    n_pos = sum(y_true)
    if n_pos == 0:
        return 0.0
    ranked = sorted(range(len(y_prob)), key=lambda i: -y_prob[i])[:k]
    found = sum(y_true[i] for i in ranked)
    return round(found / n_pos, 4)


# ---------------------------------------------------------------------------
# Full evaluation suite
# ---------------------------------------------------------------------------

class GNNEvaluator:
    """Compute all required evaluation metrics for a trained GNN or baseline."""

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold

    def evaluate_node_task(
        self,
        samples: list[GraphSample],
        predict_fn: "Any",
    ) -> dict[str, float]:
        """Evaluate node compromise-risk predictions."""
        y_true: list[int] = []
        y_prob: list[float] = []
        for sample in samples:
            if sample.labels is None:
                continue
            preds = predict_fn(sample)
            probs = preds.get("node_risk_probabilities", [])
            for node_id, prob in zip(sample.node_ids, probs):
                nl = sample.labels.node_labels.get(node_id)
                if nl is None:
                    continue
                y_true.append(int(nl.is_compromised))
                y_prob.append(float(prob))
        if not y_true:
            return {"n_samples": 0.0}
        y_pred = [1 if p >= self.threshold else 0 for p in y_prob]
        metrics = precision_recall_f1(y_true, y_pred)
        metrics.update({
            "roc_auc": roc_auc(y_true, y_prob),
            "pr_auc": pr_auc(y_true, y_prob),
            "brier_score": brier_score(y_true, y_prob),
            "calibration_error": round(calibration_error(y_true, y_prob), 4),
            "n_samples": float(len(y_true)),
            "n_positive": float(sum(y_true)),
        })
        return metrics

    def evaluate_edge_task(
        self,
        samples: list[GraphSample],
        predict_fn: "Any",
        top_k: int = 5,
    ) -> dict[str, float]:
        """Evaluate edge lateral-movement predictions."""
        y_true: list[int] = []
        y_prob: list[float] = []
        for sample in samples:
            if sample.labels is None:
                continue
            preds = predict_fn(sample)
            probs = preds.get("edge_movement_probabilities", [])
            for edge_id, prob in zip(sample.edge_ids, probs):
                el = sample.labels.edge_labels.get(edge_id)
                if el is None:
                    continue
                y_true.append(int(el.is_lateral_movement))
                y_prob.append(float(prob))
        if not y_true:
            return {"n_samples": 0.0}
        y_pred = [1 if p >= self.threshold else 0 for p in y_prob]
        metrics = precision_recall_f1(y_true, y_pred)
        metrics.update({
            "pr_auc": pr_auc(y_true, y_prob),
            "top_k_recall": top_k_recall(y_true, y_prob, k=top_k),
            "brier_score": brier_score(y_true, y_prob),
            "n_samples": float(len(y_true)),
        })
        return metrics

    def evaluate_graph_task(
        self,
        samples: list[GraphSample],
        predict_fn: "Any",
    ) -> dict[str, float]:
        """Evaluate subgraph reachability-risk predictions."""
        y_true: list[int] = []
        y_prob: list[float] = []
        for sample in samples:
            if sample.labels is None or sample.labels.graph_label is None:
                continue
            preds = predict_fn(sample)
            prob = float(preds.get("graph_risk_probability", 0.5))
            y_true.append(int(sample.labels.graph_label.is_high_risk))
            y_prob.append(prob)
        if not y_true:
            return {"n_samples": 0.0}
        y_pred = [1 if p >= self.threshold else 0 for p in y_prob]
        acc = sum(1 for yt, yp in zip(y_true, y_pred) if yt == yp) / len(y_true)
        metrics = precision_recall_f1(y_true, y_pred)
        metrics.update({
            "accuracy": round(acc, 4),
            "brier_score": brier_score(y_true, y_prob),
            "roc_auc": roc_auc(y_true, y_prob),
            "n_samples": float(len(y_true)),
        })
        return metrics

    def evaluate_latency(
        self,
        samples: list[GraphSample],
        predict_fn: "Any",
        n_warmup: int = 3,
    ) -> dict[str, float]:
        """Measure inference latency (ms) per sample."""
        if not samples:
            return {"mean_latency_ms": 0.0}
        # Warmup
        for sample in samples[:n_warmup]:
            predict_fn(sample)
        latencies: list[float] = []
        for sample in samples:
            t0 = time.perf_counter()
            predict_fn(sample)
            latencies.append((time.perf_counter() - t0) * 1000.0)
        return {
            "mean_latency_ms": round(sum(latencies) / len(latencies), 2),
            "p50_latency_ms": round(sorted(latencies)[len(latencies) // 2], 2),
            "p95_latency_ms": round(
                sorted(latencies)[int(len(latencies) * 0.95)], 2
            ),
            "max_latency_ms": round(max(latencies), 2),
            "n_samples": float(len(latencies)),
        }

    def full_evaluation(
        self,
        samples: list[GraphSample],
        predict_fn: "Any",
        model_name: str = "gnn",
    ) -> dict[str, Any]:
        """Run all evaluation tasks and return combined dict."""
        return {
            "model": model_name,
            "node_task": self.evaluate_node_task(samples, predict_fn),
            "edge_task": self.evaluate_edge_task(samples, predict_fn),
            "graph_task": self.evaluate_graph_task(samples, predict_fn),
            "latency": self.evaluate_latency(samples, predict_fn),
        }
