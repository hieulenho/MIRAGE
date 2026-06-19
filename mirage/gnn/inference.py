"""GNN Inference Service for MIRAGE Milestone 6.

Read-only inference service.  No training, no action execution.
Gracefully handles missing or incompatible models.

Usage
-----
>>> service = GNNInferenceService()
>>> service.load_model("models/gnn_v1/best_model.pt",
...                    metadata_path="models/gnn_v1/metadata.json")
>>> result = service.encode_subgraph(graph_sample)
>>> result.node_risk_predictions      # per-node risk probs
>>> result.ood_warnings               # OOD flags
>>> result.fallback_recommended       # True if heuristic should dominate
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mirage.gnn.schema import (
    GNNInferenceResult,
    GNNOperatingMode,
    GNNOutput,
    GraphFeatureSchema,
    GraphSample,
    ModelHealth,
    ModelMetadata,
    OODWarning,
)
from mirage.gnn.uncertainty import OODDetector


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class GNNInferenceService:
    """Read-only GNN inference service.

    Parameters
    ----------
    schema:
        Feature schema to validate compatibility.
    ood_detector:
        OOD detector instance.  Created with defaults if not provided.
    max_nodes:
        Hard limit on input graph size (safety bound).
    max_edges:
        Hard limit on input graph edges.
    """

    def __init__(
        self,
        schema: GraphFeatureSchema | None = None,
        ood_detector: OODDetector | None = None,
        max_nodes: int = 200,
        max_edges: int = 400,
    ) -> None:
        self.schema = schema or GraphFeatureSchema()
        self.ood_detector = ood_detector or OODDetector(schema=self.schema)
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self._model: Any = None
        self._metadata: ModelMetadata | None = None
        self._total_inferences = 0
        self._ood_warning_count = 0
        self._high_uncertainty_count = 0
        self._last_latency_ms = 0.0
        self._is_loaded = False

    def load_model(
        self,
        model_path: str,
        metadata_path: str | None = None,
    ) -> None:
        """Load model weights and validate feature-schema compatibility.

        Raises RuntimeError if schema is incompatible.
        Raises ImportError if PyTorch is not installed.
        """
        try:
            from mirage.gnn.encoder import GNNStateEncoder
        except ImportError as exc:
            raise ImportError(
                "PyTorch required for GNNInferenceService. "
                "Install with: pip install -r requirements-gnn.txt"
            ) from exc

        meta: ModelMetadata | None = None
        if metadata_path and Path(metadata_path).exists():
            meta = ModelMetadata.model_validate_json(
                Path(metadata_path).read_text(encoding="utf-8")
            )
        elif Path(model_path).parent.joinpath("metadata.json").exists():
            meta_auto = Path(model_path).parent / "metadata.json"
            meta = ModelMetadata.model_validate_json(
                meta_auto.read_text(encoding="utf-8")
            )

        if meta is not None:
            # Schema compatibility check
            if self.schema.schema_version not in meta.compatible_schema_versions:
                raise RuntimeError(
                    f"Model {meta.model_id!r} is not compatible with "
                    f"schema version {self.schema.schema_version!r}. "
                    f"Compatible: {meta.compatible_schema_versions}"
                )
            if meta.feature_schema_hash and meta.feature_schema_hash != self.schema.schema_hash():
                raise RuntimeError(
                    f"Model {meta.model_id!r} expects feature schema hash "
                    f"{meta.feature_schema_hash!r}; active schema hash is "
                    f"{self.schema.schema_hash()!r}."
                )
            self._metadata = meta
            feature_scaling = meta.training_config.get("feature_scaling", {})
            node_stats = feature_scaling.get("node", {}) if isinstance(feature_scaling, dict) else {}
            if node_stats:
                self.ood_detector.feature_stats = node_stats

        arch = (meta.training_config.get("architecture", {}) if meta is not None else {})
        model_kwargs = {
            "hidden_dim": int(arch.get("hidden_dim", 64)),
            "out_dim": int(arch.get("out_dim", 64)),
            "n_layers": int(arch.get("n_layers", 2)),
            "dropout": float(arch.get("dropout", 0.2)),
            "type_embed_dim": int(arch.get("type_embed_dim", 8)),
            "num_node_types": len(self.schema.node_entity_types),
            "num_edge_types": len(self.schema.edge_relationship_types),
        }
        self._model = GNNStateEncoder.load(
            model_path,
            schema=self.schema,
            **model_kwargs,
        )
        self._model.eval()
        self._is_loaded = True

    def encode_subgraph(self, graph_sample: GraphSample) -> GNNInferenceResult:
        """Encode a subgraph and return predictions + OOD warnings.

        If no model is loaded, returns a fallback result with heuristic recommendation.
        Raises ValueError if input exceeds max_nodes / max_edges bounds.
        """
        if graph_sample.num_nodes > self.max_nodes:
            raise ValueError(
                f"Input graph has {graph_sample.num_nodes} nodes "
                f"(limit: {self.max_nodes})."
            )
        if graph_sample.num_edges > self.max_edges:
            raise ValueError(
                f"Input graph has {graph_sample.num_edges} edges "
                f"(limit: {self.max_edges})."
            )
        if graph_sample.feature_schema_version != self.schema.schema_version:
            raise ValueError(
                f"Sample schema version {graph_sample.feature_schema_version!r} "
                f"is incompatible with service schema "
                f"{self.schema.schema_version!r}."
            )
        if (
            graph_sample.feature_schema_hash
            and graph_sample.feature_schema_hash != self.schema.schema_hash()
        ):
            raise ValueError(
                f"Sample feature schema hash {graph_sample.feature_schema_hash!r} "
                f"is incompatible with service schema hash "
                f"{self.schema.schema_hash()!r}."
            )

        ood_warnings = self.ood_detector.check_sample(graph_sample)
        model_version = self._metadata.model_version if self._metadata else "none"
        schema_version = self.schema.schema_version

        if not self._is_loaded or self._model is None:
            gnn_output = _empty_gnn_output(graph_sample)
            return GNNInferenceResult(
                model_version=model_version,
                feature_schema_version=schema_version,
                subgraph_id=graph_sample.sample_id,
                sample_id=graph_sample.sample_id,
                gnn_output=gnn_output,
                node_ids=list(graph_sample.node_ids),
                edge_ids=list(graph_sample.edge_ids),
                ood_warnings=ood_warnings,
                uncertainty_high=True,
                fallback_recommended=True,
                fallback_reason="no_model_loaded",
                inference_time_ms=0.0,
            )

        t0 = time.perf_counter()
        try:
            import torch
            from mirage.gnn.encoder import sample_to_tensors

            tensors = sample_to_tensors(None, schema=self.schema, graph_sample=graph_sample)
            with torch.no_grad():
                gnn_output = self._model.forward(
                    tensors["node_features"],
                    tensors["edge_index"],
                    tensors["edge_features"],
                    tensors["node_types"],
                    tensors["edge_types"],
                    batch=None,
                )
        except Exception as exc:  # noqa: BLE001
            ood_warnings.append(OODWarning(
                warning_type="inference_error",
                details=str(exc),
                severity="high",
            ))
            gnn_output = _empty_gnn_output(graph_sample)
            latency_ms = (time.perf_counter() - t0) * 1000.0
            self._last_latency_ms = latency_ms
            self._total_inferences += 1
            self._ood_warning_count += len(ood_warnings)
            return GNNInferenceResult(
                model_version=model_version,
                feature_schema_version=schema_version,
                subgraph_id=graph_sample.sample_id,
                sample_id=graph_sample.sample_id,
                gnn_output=gnn_output,
                node_ids=list(graph_sample.node_ids),
                edge_ids=list(graph_sample.edge_ids),
                ood_warnings=ood_warnings,
                uncertainty_high=True,
                fallback_recommended=True,
                fallback_reason=f"inference_error: {exc}",
                inference_time_ms=latency_ms,
            )

        latency_ms = (time.perf_counter() - t0) * 1000.0
        self._last_latency_ms = latency_ms
        self._total_inferences += 1

        high_unc, fallback = self.ood_detector.check_output(gnn_output, ood_warnings)
        fallback_reason = ""
        if high_unc:
            fallback_reason = "high_uncertainty"
            self._high_uncertainty_count += 1
        elif fallback:
            fallback_reason = "ood_warning"
        self._ood_warning_count += len(ood_warnings)

        return GNNInferenceResult(
            model_version=model_version,
            feature_schema_version=schema_version,
            subgraph_id=graph_sample.sample_id,
            sample_id=graph_sample.sample_id,
            gnn_output=gnn_output,
            node_ids=list(graph_sample.node_ids),
            edge_ids=list(graph_sample.edge_ids),
            ood_warnings=ood_warnings,
            uncertainty_high=high_unc,
            fallback_recommended=fallback,
            fallback_reason=fallback_reason,
            inference_time_ms=round(latency_ms, 2),
        )

    def health(self) -> ModelHealth:
        """Return current health status."""
        status = "ok" if self._is_loaded else "no_model"
        if self._is_loaded and self._high_uncertainty_count > self._total_inferences * 0.5:
            status = "degraded"
        return ModelHealth(
            status=status,
            model_version=self._metadata.model_version if self._metadata else "",
            feature_schema_version=self.schema.schema_version,
            model_path=self._metadata.model_path if self._metadata else "",
            last_inference_time_ms=round(self._last_latency_ms, 2),
            total_inferences=self._total_inferences,
            ood_warning_count=self._ood_warning_count,
            high_uncertainty_count=self._high_uncertainty_count,
            operating_mode=GNNOperatingMode.GNN_SHADOW.value,
        )


def _empty_gnn_output(sample: GraphSample) -> GNNOutput:
    """Return a zero GNNOutput when no model is available."""
    n = sample.num_nodes
    e = sample.num_edges
    return GNNOutput(
        node_embeddings=[[0.0] * 64 for _ in range(n)],
        graph_embedding=[0.0] * 64,
        node_risk_probabilities=[0.5] * n,
        edge_movement_probabilities=[0.5] * e,
        graph_risk_probability=0.5,
        node_uncertainty=[1.0] * n,
        graph_uncertainty=1.0,
        embedding_dim=64,
        num_nodes=n,
        num_edges=e,
    )
