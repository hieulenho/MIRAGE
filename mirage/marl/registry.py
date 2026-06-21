"""File-backed MARL policy registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.marl.schema import MARLPolicyMetadata, MARLPolicyStatus


class MARLPolicyRegistry:
    """Lightweight JSON registry for MARL policy metadata."""

    def __init__(self, registry_path: str = "models/marl_policy_registry.json") -> None:
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self._policies: dict[str, MARLPolicyMetadata] = {}
        self._load()

    def register(self, metadata: MARLPolicyMetadata) -> None:
        self._policies[metadata.policy_id] = metadata
        self._save()

    def get(self, policy_id: str) -> MARLPolicyMetadata | None:
        return self._policies.get(policy_id)

    def list_policies(
        self,
        status: MARLPolicyStatus | None = None,
    ) -> list[MARLPolicyMetadata]:
        policies = list(self._policies.values())
        if status is not None:
            policies = [policy for policy in policies if policy.status == status]
        return sorted(policies, key=lambda item: (item.created_at, item.policy_id))

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
            policy_id: MARLPolicyMetadata.model_validate(payload)
            for policy_id, payload in data.items()
        }

    def _save(self) -> None:
        payload = {
            policy_id: json.loads(metadata.model_dump_json())
            for policy_id, metadata in self._policies.items()
        }
        self.registry_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
