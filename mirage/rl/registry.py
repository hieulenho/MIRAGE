"""JSON policy registry for Milestone 7."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.rl.schema import PolicyMetadata, PolicyStatus


class PolicyRegistry:
    """Lightweight file-backed policy registry."""

    def __init__(self, registry_path: str = "models/rl_policy_registry.json") -> None:
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._policies: dict[str, PolicyMetadata] = {}
        self._load()

    def register(self, metadata: PolicyMetadata) -> None:
        self._policies[metadata.policy_id] = metadata
        self._save()

    def get(self, policy_id: str) -> PolicyMetadata | None:
        return self._policies.get(policy_id)

    def list_policies(self, status: PolicyStatus | None = None) -> list[PolicyMetadata]:
        values = list(self._policies.values())
        if status is not None:
            values = [item for item in values if item.status == status]
        return sorted(values, key=lambda item: (item.created_at, item.policy_id))

    def transition(self, policy_id: str, new_status: PolicyStatus, notes: str = "") -> PolicyMetadata:
        allowed = {
            PolicyStatus.TRAINING: {PolicyStatus.VALIDATED, PolicyStatus.REVIEW_REQUIRED, PolicyStatus.REJECTED},
            PolicyStatus.VALIDATED: {PolicyStatus.SHADOW, PolicyStatus.REVIEW_REQUIRED, PolicyStatus.REJECTED, PolicyStatus.ARCHIVED},
            PolicyStatus.SHADOW: {PolicyStatus.REVIEW_REQUIRED, PolicyStatus.REJECTED, PolicyStatus.ARCHIVED},
            PolicyStatus.REVIEW_REQUIRED: {PolicyStatus.SHADOW, PolicyStatus.REJECTED, PolicyStatus.ARCHIVED},
            PolicyStatus.REJECTED: {PolicyStatus.ARCHIVED},
            PolicyStatus.ARCHIVED: set(),
        }
        current = self._policies.get(policy_id)
        if current is None:
            raise KeyError(policy_id)
        if new_status not in allowed[current.status]:
            raise ValueError(f"Cannot transition {policy_id!r} from {current.status.value} to {new_status.value}.")
        updated = current.model_copy(update={"status": new_status, "notes": notes})
        self._policies[policy_id] = updated
        self._save()
        return updated

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for policy in self._policies.values():
            counts[policy.status.value] = counts.get(policy.status.value, 0) + 1
        return {
            "total_policies": len(self._policies),
            "status_counts": counts,
            "registry_path": str(self.registry_path.resolve()),
        }

    def _load(self) -> None:
        if not self.registry_path.exists():
            self._policies = {}
            return
        data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self._policies = {
            policy_id: PolicyMetadata.model_validate(payload)
            for policy_id, payload in data.items()
        }

    def _save(self) -> None:
        payload = {
            policy_id: json.loads(metadata.model_dump_json())
            for policy_id, metadata in self._policies.items()
        }
        self.registry_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

