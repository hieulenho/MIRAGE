"""Training helpers for behavior cloning and offline RL."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.rl.baselines import BehaviorCloningPolicy, HierarchicalBehaviorCloningPolicy
from mirage.rl.dataset import OfflineRLDatasetBuilder
from mirage.rl.policy import OfflineBlueTeamPolicy
from mirage.rl.schema import PolicyMetadata, PolicyStatus


def transitions_from_trajectories(trajectories):
    return [transition for trajectory in trajectories for transition in trajectory.transitions]


def train_behavior_cloning(
    dataset_path: str,
    output_path: str,
    config: dict[str, Any] | None = None,
) -> PolicyMetadata:
    trajectories, manifest = OfflineRLDatasetBuilder().load_dataset(dataset_path)
    transitions = transitions_from_trajectories(trajectories)
    hierarchical = bool((config or {}).get("hierarchical", True))
    policy = HierarchicalBehaviorCloningPolicy() if hierarchical else BehaviorCloningPolicy()
    policy.fit(transitions)
    policy.save(output_path)
    metadata = PolicyMetadata(
        policy_id=policy.policy_id,
        version=policy.policy_version,
        algorithm="behavior_cloning",
        architecture="hierarchical_per_action_scorer" if hierarchical else "flat_per_action_scorer",
        feature_schema_version=manifest.feature_schema_version,
        action_schema_version=manifest.action_schema_version,
        dataset_id=manifest.dataset_id,
        dataset_hash=manifest.dataset_hash,
        reward_model_version="defense_reward_v1",
        split_manifest=manifest.split_manifest,
        hyperparameters=config or {},
        training_seeds=[int((config or {}).get("seed", 42))],
        status=PolicyStatus.VALIDATED,
        model_path=str(Path(output_path).resolve()),
    )
    (Path(output_path) / "metadata.json").write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
    return metadata


def train_offline_policy(
    dataset_path: str,
    output_path: str,
    init_policy_path: str | None = None,
    config: dict[str, Any] | None = None,
) -> PolicyMetadata:
    config = config or {}
    trajectories, manifest = OfflineRLDatasetBuilder().load_dataset(dataset_path)
    transitions = transitions_from_trajectories(trajectories)
    policy = OfflineBlueTeamPolicy(
        min_support_threshold=float(config.get("min_support_threshold", 0.05)),
        uncertainty_threshold=float(config.get("uncertainty_threshold", 0.65)),
        advantage_temperature=float(config.get("advantage_temperature", 1.0)),
        q_clip=float(config.get("q_clip", 5.0)),
    )
    if init_policy_path and Path(init_policy_path, "policy.json").exists():
        try:
            policy.bc = HierarchicalBehaviorCloningPolicy.load(init_policy_path)
        except Exception:
            policy.bc = BehaviorCloningPolicy.load(init_policy_path)
    epochs = int(config.get("epochs", 5))
    batch_size = max(1, int(config.get("batch_size", len(transitions) or 1)))
    history = []
    for epoch in range(epochs):
        for start in range(0, len(transitions), batch_size):
            metrics = policy.train_step(transitions[start:start + batch_size])
            history.append(metrics.model_dump(mode="json"))
    policy.save(output_path)
    (Path(output_path) / "training_history.json").write_text(json.dumps(history, indent=2), encoding="utf-8")
    metadata = PolicyMetadata(
        policy_id=policy.policy_id,
        version=policy.policy_version,
        algorithm="implicit_q_learning_style_discrete",
        architecture="hierarchical_tactic_action_policy",
        feature_schema_version=manifest.feature_schema_version,
        action_schema_version=manifest.action_schema_version,
        dataset_id=manifest.dataset_id,
        dataset_hash=manifest.dataset_hash,
        reward_model_version="defense_reward_v1",
        split_manifest=manifest.split_manifest,
        hyperparameters=config,
        training_seeds=[int(config.get("seed", 42))],
        status=PolicyStatus.VALIDATED,
        model_path=str(Path(output_path).resolve()),
    )
    (Path(output_path) / "metadata.json").write_text(metadata.model_dump_json(indent=2), encoding="utf-8")
    return metadata

