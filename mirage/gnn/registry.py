"""Model registry for MIRAGE GNN.

Lightweight JSON-file based model registry.  Stores ModelMetadata records
and enforces lifecycle transitions.

Supported statuses:
  TRAINING → VALIDATED → SHADOW → APPROVED / REJECTED / ARCHIVED

Milestone 6 models may reach SHADOW status.
APPROVED requires explicit human sign-off (not automatic).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.gnn.schema import ModelMetadata, ModelStatus


class ModelRegistry:
    """Lightweight JSON-file model registry.

    Parameters
    ----------
    registry_path:
        Path to the JSON file storing all model metadata.
        Created automatically if it does not exist.
    """

    def __init__(self, registry_path: str = "models/gnn_registry.json") -> None:
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._models: dict[str, ModelMetadata] = {}
        self._load()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(self, metadata: ModelMetadata) -> None:
        """Add or update a model entry."""
        self._models[metadata.model_id] = metadata
        self._save()

    def get(self, model_id: str) -> ModelMetadata | None:
        """Return model metadata by ID, or None."""
        return self._models.get(model_id)

    def list_models(
        self,
        status: ModelStatus | None = None,
    ) -> list[ModelMetadata]:
        """Return all models, optionally filtered by status."""
        models = list(self._models.values())
        if status is not None:
            models = [m for m in models if m.status == status]
        return sorted(models, key=lambda m: m.training_timestamp)

    def transition(
        self,
        model_id: str,
        new_status: ModelStatus,
        notes: str = "",
    ) -> ModelMetadata:
        """Transition a model to a new status.

        Enforces allowed transitions:
          TRAINING   → VALIDATED, REJECTED
          VALIDATED  → SHADOW, REJECTED, ARCHIVED
          SHADOW     → APPROVED, REJECTED, ARCHIVED
          APPROVED   → ARCHIVED
          REJECTED   → ARCHIVED
          ARCHIVED   → (terminal)
        """
        allowed: dict[ModelStatus, set[ModelStatus]] = {
            ModelStatus.TRAINING: {ModelStatus.VALIDATED, ModelStatus.REJECTED},
            ModelStatus.VALIDATED: {
                ModelStatus.SHADOW, ModelStatus.REJECTED, ModelStatus.ARCHIVED
            },
            ModelStatus.SHADOW: {
                ModelStatus.APPROVED, ModelStatus.REJECTED, ModelStatus.ARCHIVED
            },
            ModelStatus.APPROVED: {ModelStatus.ARCHIVED},
            ModelStatus.REJECTED: {ModelStatus.ARCHIVED},
            ModelStatus.ARCHIVED: set(),
        }
        model = self._models.get(model_id)
        if model is None:
            raise KeyError(f"Model {model_id!r} not found in registry.")
        if new_status not in allowed.get(model.status, set()):
            raise ValueError(
                f"Cannot transition model {model_id!r} "
                f"from {model.status.value} to {new_status.value}."
            )
        updated = model.model_copy(update={"status": new_status, "notes": notes})
        self._models[model_id] = updated
        self._save()
        return updated

    def delete(self, model_id: str) -> None:
        """Remove a model entry (ARCHIVED only)."""
        model = self._models.get(model_id)
        if model is None:
            raise KeyError(f"Model {model_id!r} not found.")
        if model.status != ModelStatus.ARCHIVED:
            raise ValueError(
                f"Model {model_id!r} must be ARCHIVED before deletion."
            )
        del self._models[model_id]
        self._save()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        if not self.registry_path.exists():
            self._models = {}
            return
        data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self._models = {
            mid: ModelMetadata.model_validate(meta)
            for mid, meta in data.items()
        }

    def _save(self) -> None:
        data = {
            mid: json.loads(meta.model_dump_json())
            for mid, meta in self._models.items()
        }
        self.registry_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def summary(self) -> dict[str, Any]:
        """Return a human-readable registry summary."""
        status_counts: dict[str, int] = {}
        for m in self._models.values():
            status_counts[m.status.value] = status_counts.get(m.status.value, 0) + 1
        return {
            "total_models": len(self._models),
            "status_counts": status_counts,
            "registry_path": str(self.registry_path.resolve()),
        }
