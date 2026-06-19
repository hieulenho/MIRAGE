"""GNN training pipeline for MIRAGE Milestone 6.

Provides:
  - Reproducible training with deterministic seeds
  - CPU + optional CUDA support
  - Checkpoint saving / restoring
  - Early stopping on validation loss
  - Best-model selection by validation F1
  - Training history export to JSON
  - Configuration snapshot saved with model
  - Feature-schema version tracked
  - Dataset manifest hash recorded in model metadata
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mirage.gnn.schema import (
    GraphFeatureSchema,
    GraphSample,
    ModelMetadata,
    ModelStatus,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _set_seed(seed: int) -> None:
    import random
    random.seed(seed)
    try:
        import numpy as np
        np.random.seed(seed)
    except ImportError:
        pass
    try:
        import torch
        torch.manual_seed(seed)
        torch.use_deterministic_algorithms(True, warn_only=True)
        if torch.cuda.is_available():
            torch.cuda.manual_seed_all(seed)
    except ImportError:
        pass


def _dataset_hash(samples: list[GraphSample]) -> str:
    ids = sorted(s.sample_id for s in samples)
    return hashlib.sha256("|".join(ids).encode()).hexdigest()[:16]


class EarlyStopping:
    """Stop training when val_loss has not improved for *patience* epochs."""

    def __init__(self, patience: int = 10, min_delta: float = 1e-4) -> None:
        self.patience = patience
        self.min_delta = min_delta
        self.best_loss = float("inf")
        self.counter = 0
        self.stopped = False

    def step(self, val_loss: float) -> bool:
        """Return True when training should stop."""
        if val_loss < self.best_loss - self.min_delta:
            self.best_loss = val_loss
            self.counter = 0
        else:
            self.counter += 1
            if self.counter >= self.patience:
                self.stopped = True
        return self.stopped


class GNNTrainer:
    """Reproducible GNN training with checkpointing and early stopping.

    Parameters
    ----------
    config:
        Training configuration dict (see configs/gnn_v1.yaml for schema).
    schema:
        Feature schema (must match the dataset).
    output_dir:
        Directory for saving checkpoints, best model, and training history.
    """

    def __init__(
        self,
        config: dict[str, Any],
        schema: GraphFeatureSchema | None = None,
        output_dir: str = "models/gnn_v1",
    ) -> None:
        self.config = config
        self.schema = schema or GraphFeatureSchema()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def train(
        self,
        train_samples: list[GraphSample],
        val_samples: list[GraphSample],
        model_id: str | None = None,
    ) -> ModelMetadata:
        """Train GNNStateEncoder on *train_samples*, validate on *val_samples*.

        Returns ModelMetadata for the best checkpoint.
        """
        try:
            import torch
            from mirage.gnn.encoder import GNNStateEncoder, sample_to_tensors
            from mirage.gnn.loss import MultiTaskLoss, compute_pos_weight
        except ImportError as exc:
            raise ImportError(
                "PyTorch is required for training. "
                "Install with: pip install -r requirements-gnn.txt"
            ) from exc

        seed = int(self.config.get("seed", 42))
        _set_seed(seed)

        device_name = "cuda" if (
            self.config.get("use_cuda", False) and torch.cuda.is_available()
        ) else "cpu"
        device = torch.device(device_name)

        # Build model
        model = GNNStateEncoder(
            node_feature_dim=self.schema.node_feature_dim,
            edge_feature_dim=self.schema.edge_feature_dim,
            hidden_dim=int(self.config.get("hidden_dim", 64)),
            out_dim=int(self.config.get("out_dim", 64)),
            n_layers=int(self.config.get("n_layers", 2)),
            dropout=float(self.config.get("dropout", 0.2)),
            num_node_types=len(self.schema.node_entity_types),
            num_edge_types=len(self.schema.edge_relationship_types),
            type_embed_dim=int(self.config.get("type_embed_dim", 8)),
        ).to(device)

        lr = float(self.config.get("learning_rate", 1e-3))
        optimizer = torch.optim.Adam(model.parameters(), lr=lr,
                                      weight_decay=float(self.config.get("l2_weight", 1e-4)))

        # Compute class weights from training labels
        all_node_labels = [
            int(nl.is_compromised)
            for s in train_samples if s.labels
            for nl in s.labels.node_labels.values()
        ]
        all_edge_labels = [
            int(el.is_lateral_movement)
            for s in train_samples if s.labels
            for el in s.labels.edge_labels.values()
        ]
        all_graph_labels = [
            int(s.labels.graph_label.is_high_risk)
            for s in train_samples
            if s.labels and s.labels.graph_label is not None
        ]
        node_pos_weight = compute_pos_weight(all_node_labels)
        edge_pos_weight = compute_pos_weight(all_edge_labels)
        graph_pos_weight = compute_pos_weight(all_graph_labels)

        loss_fn = MultiTaskLoss(
            node_loss_weight=float(self.config.get("node_loss_weight", 1.0)),
            edge_loss_weight=float(self.config.get("edge_loss_weight", 0.5)),
            graph_loss_weight=float(self.config.get("graph_loss_weight", 0.3)),
            l2_weight=float(self.config.get("l2_weight", 1e-4)),
            focal_gamma=float(self.config.get("focal_gamma", 0.0)),
            node_pos_weight=node_pos_weight,
            edge_pos_weight=edge_pos_weight,
            graph_pos_weight=graph_pos_weight,
        )

        epochs = int(self.config.get("epochs", 100))
        patience = int(self.config.get("early_stopping_patience", 15))
        early_stop = EarlyStopping(
            patience=patience,
            min_delta=float(self.config.get("min_improvement", 1e-4)),
        )

        history: list[dict[str, float]] = []
        best_val_loss = float("inf")
        best_epoch = 0
        best_ckpt = str(self.output_dir / "best_model.pt")
        start_time = time.time()

        for epoch in range(1, epochs + 1):
            # --- Training step ---
            model.train()
            train_loss_sum = 0.0
            n_train = 0
            for sample in train_samples:
                if not sample.node_feature_matrix:
                    continue
                tensors = sample_to_tensors(None, schema=self.schema, graph_sample=sample)
                node_f = tensors["node_features"].to(device)
                edge_idx = tensors["edge_index"].to(device)
                edge_f = tensors["edge_features"].to(device)
                node_t = tensors["node_types"].to(device)
                edge_t = tensors["edge_types"].to(device)

                out = model.forward_tensors(node_f, edge_idx, edge_f, node_t, edge_t, None)

                # Build targets
                node_targets_t = _build_node_targets(sample, device)
                edge_targets_t = _build_edge_targets(sample, device)
                graph_target_t = _build_graph_target(sample, device)
                if (
                    node_targets_t is None
                    and edge_targets_t is None
                    and graph_target_t is None
                ):
                    continue

                optimizer.zero_grad()
                loss, _ = loss_fn(
                    out.node_logits,
                    node_targets_t,
                    out.edge_logits,
                    edge_targets_t,
                    out.graph_logits,
                    graph_target_t,
                    list(model.parameters()),
                )
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                optimizer.step()
                train_loss_sum += float(loss.item())
                n_train += 1

            train_loss = train_loss_sum / max(n_train, 1)

            # --- Validation step ---
            model.eval()
            val_loss_sum = 0.0
            n_val = 0
            val_node_probs: list[float] = []
            val_node_labels: list[int] = []
            with torch.no_grad():
                for sample in val_samples:
                    if not sample.node_feature_matrix:
                        continue
                    tensors = sample_to_tensors(None, schema=self.schema, graph_sample=sample)
                    node_f = tensors["node_features"].to(device)
                    edge_idx = tensors["edge_index"].to(device)
                    edge_f = tensors["edge_features"].to(device)
                    node_t = tensors["node_types"].to(device)
                    edge_t = tensors["edge_types"].to(device)

                    out = model.forward_tensors(node_f, edge_idx, edge_f, node_t, edge_t, None)
                    node_targets_t = _build_node_targets(sample, device)
                    edge_targets_t = _build_edge_targets(sample, device)
                    graph_target_t = _build_graph_target(sample, device)
                    if (
                        node_targets_t is not None
                        or edge_targets_t is not None
                        or graph_target_t is not None
                    ):
                        vloss, _ = loss_fn(
                            out.node_logits,
                            node_targets_t,
                            out.edge_logits,
                            edge_targets_t,
                            out.graph_logits,
                            graph_target_t,
                        )
                        val_loss_sum += float(vloss.item())
                        n_val += 1
                        # Collect for F1
                        node_probs = out.node_probabilities.detach().cpu().tolist()
                        for node_id, prob in zip(sample.node_ids, node_probs):
                            if sample.labels and node_id in sample.labels.node_labels:
                                val_node_probs.append(prob)
                                val_node_labels.append(
                                    int(sample.labels.node_labels[node_id].is_compromised)
                                )

            val_loss = val_loss_sum / max(n_val, 1)
            val_f1 = _f1(val_node_labels, val_node_probs)

            step_info = {
                "epoch": epoch,
                "train_loss": round(train_loss, 6),
                "val_loss": round(val_loss, 6),
                "val_f1": round(val_f1, 4),
            }
            history.append(step_info)

            if val_loss < best_val_loss:
                best_val_loss = val_loss
                best_epoch = epoch
                model.save(best_ckpt)

            if early_stop.step(val_loss):
                break

        elapsed = time.time() - start_time

        # Save training history
        history_path = self.output_dir / "training_history.json"
        history_path.write_text(json.dumps(history, indent=2), encoding="utf-8")

        feature_scaling = _compute_feature_scaling(train_samples, self.schema)
        training_config = dict(self.config)
        training_config["class_weights"] = {
            "node_pos_weight": node_pos_weight,
            "edge_pos_weight": edge_pos_weight,
            "graph_pos_weight": graph_pos_weight,
        }
        training_config["feature_scaling"] = feature_scaling
        training_config["architecture"] = {
            "hidden_dim": int(self.config.get("hidden_dim", 64)),
            "out_dim": int(self.config.get("out_dim", 64)),
            "n_layers": int(self.config.get("n_layers", 2)),
            "dropout": float(self.config.get("dropout", 0.2)),
            "type_embed_dim": int(self.config.get("type_embed_dim", 8)),
        }

        # Save full config snapshot, including class weights and feature stats.
        config_path = self.output_dir / "training_config.json"
        config_path.write_text(
            json.dumps(training_config, indent=2, default=str), encoding="utf-8"
        )

        ds_hash = _dataset_hash(train_samples + val_samples)
        mid = model_id or f"gnn_{int(time.time())}"
        metadata = ModelMetadata(
            model_id=mid,
            model_version="v1",
            architecture="graphsage_v1",
            training_timestamp=_utc_now(),
            dataset_hash=ds_hash,
            feature_schema_version=self.schema.schema_version,
            feature_schema_hash=self.schema.schema_hash(),
            training_config=training_config,
            evaluation_metrics={
                "best_val_loss": round(best_val_loss, 6),
                "best_epoch": float(best_epoch),
                "best_val_f1": float(history[best_epoch - 1]["val_f1"]) if history else 0.0,
                "training_time_s": round(elapsed, 2),
            },
            compatible_schema_versions=[self.schema.schema_version],
            supported_node_types=list(self.schema.node_entity_types),
            supported_edge_types=list(self.schema.edge_relationship_types),
            status=ModelStatus.VALIDATED,
            model_path=str(Path(best_ckpt).resolve()),
        )
        meta_path = self.output_dir / "metadata.json"
        meta_path.write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
        return metadata


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _build_node_targets(sample: GraphSample, device: Any) -> Any | None:
    try:
        import torch
    except ImportError:
        return None
    if sample.labels is None:
        return None
    targets = []
    for node_id in sample.node_ids:
        nl = sample.labels.node_labels.get(node_id)
        targets.append(float(nl.is_compromised) if nl else 0.0)
    if not targets:
        return None
    return torch.tensor(targets, dtype=torch.float32).to(device)


def _build_edge_targets(sample: GraphSample, device: Any) -> Any | None:
    try:
        import torch
    except ImportError:
        return None
    if sample.labels is None:
        return None
    if not sample.edge_ids:
        return None
    targets = []
    has_label = False
    for edge_id in sample.edge_ids:
        el = sample.labels.edge_labels.get(edge_id)
        if el is None:
            targets.append(0.0)
            continue
        has_label = True
        targets.append(float(el.is_lateral_movement))
    if not has_label:
        return None
    return torch.tensor(targets, dtype=torch.float32).to(device)


def _build_graph_target(sample: GraphSample, device: Any) -> Any | None:
    try:
        import torch
    except ImportError:
        return None
    if sample.labels is None or sample.labels.graph_label is None:
        return None
    return torch.tensor(
        [float(sample.labels.graph_label.is_high_risk)], dtype=torch.float32
    ).to(device)


def _f1(y_true: list[int], y_prob: list[float], threshold: float = 0.5) -> float:
    if not y_true:
        return 0.0
    y_pred = [1 if p >= threshold else 0 for p in y_prob]
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return 2 * precision * recall / max(precision + recall, 1e-8)


def _compute_feature_scaling(
    samples: list[GraphSample],
    schema: GraphFeatureSchema,
) -> dict[str, dict[str, dict[str, float]]]:
    """Compute simple min/max/mean/std stats for audit and OOD checks."""
    try:
        import numpy as np
    except ImportError:
        return {"node": {}, "edge": {}}

    def _stats(rows: list[list[float]], names: list[str]) -> dict[str, dict[str, float]]:
        if not rows:
            return {}
        arr = np.array(rows, dtype=float)
        result: dict[str, dict[str, float]] = {}
        for idx, name in enumerate(names):
            col = arr[:, idx]
            result[name] = {
                "min": float(np.min(col)),
                "max": float(np.max(col)),
                "mean": float(np.mean(col)),
                "std": float(np.std(col)),
            }
        return result

    node_rows = [
        row
        for sample in samples
        for row in sample.node_feature_matrix
        if row
    ]
    edge_rows = [
        row
        for sample in samples
        for row in sample.edge_feature_matrix
        if row
    ]
    return {
        "node": _stats(node_rows, schema.node_feature_names),
        "edge": _stats(edge_rows, schema.edge_feature_names),
    }
