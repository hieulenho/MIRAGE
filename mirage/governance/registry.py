"""Unified governance registry."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.governance.schema import (
    GovernanceDecision,
    GovernedArtifact,
    ModelCard,
    PolicyCard,
)


class GovernanceRegistry:
    """File-backed governance registry for artifacts, cards, and decisions."""

    def __init__(self, registry_path: str = "models/governance_registry.json") -> None:
        self.registry_path = Path(registry_path)
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.artifacts: dict[str, GovernedArtifact] = {}
        self.model_cards: dict[str, ModelCard] = {}
        self.policy_cards: dict[str, PolicyCard] = {}
        self.decisions: dict[str, GovernanceDecision] = {}
        self._load()

    def register_artifact(self, artifact: GovernedArtifact) -> None:
        self.artifacts[artifact.artifact_id] = artifact
        self._save()

    def get_artifact(self, artifact_id: str) -> GovernedArtifact | None:
        return self.artifacts.get(artifact_id)

    def list_artifacts(self) -> list[GovernedArtifact]:
        return sorted(self.artifacts.values(), key=lambda item: (item.artifact_type.value, item.artifact_id))

    def set_model_card(self, card: ModelCard) -> None:
        self.model_cards[card.artifact_id] = card
        self._save()

    def set_policy_card(self, card: PolicyCard) -> None:
        self.policy_cards[card.artifact_id] = card
        self._save()

    def register_decision(self, decision: GovernanceDecision) -> None:
        self.decisions[decision.decision_id] = decision
        self._save()

    def summary(self) -> dict[str, Any]:
        return {
            "artifact_count": len(self.artifacts),
            "model_card_count": len(self.model_cards),
            "policy_card_count": len(self.policy_cards),
            "decision_count": len(self.decisions),
            "registry_path": str(self.registry_path.resolve()),
        }

    def _load(self) -> None:
        if not self.registry_path.exists():
            return
        data = json.loads(self.registry_path.read_text(encoding="utf-8"))
        self.artifacts = {
            key: GovernedArtifact.model_validate(value)
            for key, value in data.get("artifacts", {}).items()
        }
        self.model_cards = {
            key: ModelCard.model_validate(value)
            for key, value in data.get("model_cards", {}).items()
        }
        self.policy_cards = {
            key: PolicyCard.model_validate(value)
            for key, value in data.get("policy_cards", {}).items()
        }
        self.decisions = {
            key: GovernanceDecision.model_validate(value)
            for key, value in data.get("decisions", {}).items()
        }

    def _save(self) -> None:
        payload = {
            "artifacts": {key: value.model_dump(mode="json") for key, value in self.artifacts.items()},
            "model_cards": {key: value.model_dump(mode="json", by_alias=True) for key, value in self.model_cards.items()},
            "policy_cards": {key: value.model_dump(mode="json", by_alias=True) for key, value in self.policy_cards.items()},
            "decisions": {key: value.model_dump(mode="json") for key, value in self.decisions.items()},
        }
        self.registry_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
