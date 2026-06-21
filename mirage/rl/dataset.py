"""Offline RL trajectory dataset builder and deterministic serialization."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from mirage.rl.analysis import BehaviorPolicyAnalyzer
from mirage.rl.features import RLStateEncoder, stable_id
from mirage.rl.reward import DefenseRewardModel, reward_quality_report
from mirage.rl.schema import (
    EncodedRLState,
    OfflineRLDatasetManifest,
    RLDatasetSplit,
    RLTrajectory,
    RLTrajectorySource,
    RLTransition,
)


def _jsonable(model_or_value: Any) -> Any:
    if hasattr(model_or_value, "model_dump"):
        return model_or_value.model_dump(mode="json")
    return model_or_value


def stable_dataset_hash(trajectories: list[RLTrajectory]) -> str:
    ordered = sorted(trajectories, key=lambda trajectory: trajectory.trajectory_id)
    payload = json.dumps(
        [_jsonable(trajectory) for trajectory in ordered],
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


class OfflineRLDatasetBuilder:
    """Build, save, and load offline RL trajectory datasets."""

    def __init__(
        self,
        encoder: RLStateEncoder | None = None,
        reward_model: DefenseRewardModel | None = None,
    ) -> None:
        self.encoder = encoder or RLStateEncoder()
        self.reward_model = reward_model or DefenseRewardModel()

    def build_from_simulator(self, scenarios: list[dict[str, Any]] | None = None, **_: Any) -> list[RLTrajectory]:
        from mirage.rl.scenarios import build_synthetic_trajectories

        return build_synthetic_trajectories(
            scenarios=scenarios,
            source_type=RLTrajectorySource.SIMULATOR,
            encoder=self.encoder,
            reward_model=self.reward_model,
        )

    def build_from_replay(self, analyses: Iterable[dict[str, Any]] | None = None, **_: Any) -> list[RLTrajectory]:
        if analyses is None:
            return self.build_from_simulator()
        return [
            self._trajectory_from_encoded_sequence(
                encoded_states=item["encoded_states"],
                selected_action_ids=item["selected_action_ids"],
                scenario_id=item.get("scenario_id", "replay"),
                topology_id=item.get("topology_id", "unknown"),
                policy_source=item.get("policy_source", "heuristic_policy"),
                source_type=RLTrajectorySource.HEURISTIC_POLICY,
            )
            for item in analyses
        ]

    def build_from_lab_records(self, records: Iterable[dict[str, Any]] | None = None, **_: Any) -> list[RLTrajectory]:
        trajectories = self.build_from_replay(records or [])
        return [
            trajectory.model_copy(update={"source_type": RLTrajectorySource.DOCKER_LAB})
            for trajectory in trajectories
        ]

    def build_from_shadow_records(self, records: Iterable[dict[str, Any]] | None = None, **_: Any) -> list[RLTrajectory]:
        trajectories = self.build_from_replay(records or [])
        return [
            trajectory.model_copy(update={"source_type": RLTrajectorySource.SHADOW_MODE})
            for trajectory in trajectories
        ]

    def _trajectory_from_encoded_sequence(
        self,
        encoded_states: list[EncodedRLState],
        selected_action_ids: list[str],
        scenario_id: str,
        topology_id: str,
        policy_source: str,
        source_type: RLTrajectorySource,
    ) -> RLTrajectory:
        transitions: list[RLTransition] = []
        for index, encoded in enumerate(encoded_states):
            selected_action_id = selected_action_ids[index]
            action_feature = next(
                (feature for feature in encoded.candidate_action_features if feature.action_id == selected_action_id),
                None,
            )
            if action_feature is None:
                action_feature = encoded.candidate_action_features[0]
                selected_action_id = action_feature.action_id
            reward = self.reward_model.compute(encoded, action_feature, None, {})
            transition_id = stable_id("episode", [scenario_id, policy_source, source_type.value])
            transitions.append(
                RLTransition(
                    episode_id=transition_id,
                    step_index=index,
                    state_reference=encoded.state_reference,
                    state_feature_vector=encoded.feature_vector,
                    state_feature_mask=encoded.feature_mask,
                    candidate_action_features=encoded.candidate_action_features,
                    allowed_action_ids=encoded.allowed_action_ids,
                    masked_action_ids=encoded.masked_action_ids,
                    selected_action_id=selected_action_id,
                    selected_high_level_tactic=action_feature.tactic_category,
                    behavior_policy_source=policy_source,
                    behavior_policy_probability=None,
                    reward_components=reward,
                    scalar_reward=reward.scalar_reward,
                    hard_constraint_violations=reward.hard_constraint_violations,
                    terminal=index == len(encoded_states) - 1,
                    termination_reason="sequence_end" if index == len(encoded_states) - 1 else "",
                    safety_verdict=action_feature.safety_gate_verdict,
                    execution_or_shadow_outcome={"source": source_type.value},
                    uncertainty=action_feature.uncertainty,
                    provenance={"scenario_id": scenario_id},
                    timestamp=encoded.state_reference.timestamp,
                )
            )
        total_return = sum(t.scalar_reward for t in transitions)
        return RLTrajectory(
            trajectory_id=stable_id("traj", [scenario_id, topology_id, policy_source, source_type.value]),
            scenario_id=scenario_id,
            topology_id=topology_id,
            source_type=source_type,
            policy_source=policy_source,
            transitions=transitions,
            total_return=round(total_return, 6),
            total_business_cost=sum(
                feature.business_risk
                for transition in transitions
                for feature in transition.candidate_action_features
                if feature.action_id == transition.selected_action_id
            ),
            total_asset_loss=sum(float(t.execution_or_shadow_outcome.get("asset_loss", 0.0)) for t in transitions),
            interception_result="unknown",
            safety_violation_count=sum(len(t.hard_constraint_violations) for t in transitions),
            dataset_split=split_for_scenario(scenario_id, topology_id, source_type.value),
            provenance={"builder": "OfflineRLDatasetBuilder"},
        )

    def create_manifest(
        self,
        trajectories: list[RLTrajectory],
        *,
        dataset_id: str | None = None,
        dataset_version: str = "v1",
    ) -> OfflineRLDatasetManifest:
        transitions = [transition for trajectory in trajectories for transition in trajectory.transitions]
        source_counts = Counter(trajectory.source_type.value for trajectory in trajectories)
        tactic_counts = Counter(transition.selected_high_level_tactic.value for transition in transitions)
        action_counts = Counter(transition.selected_action_id for transition in transitions)
        splits: dict[str, list[str]] = {}
        for trajectory in trajectories:
            splits.setdefault(trajectory.dataset_split.value, []).append(trajectory.trajectory_id)
        dataset_hash = stable_dataset_hash(trajectories)
        rewards = [transition.scalar_reward for transition in transitions]
        safety_failures = sum(len(transition.hard_constraint_violations) for transition in transitions)
        schema = self.encoder.schema
        return OfflineRLDatasetManifest(
            dataset_id=dataset_id or "rl_dataset_" + dataset_hash[:12],
            dataset_version=dataset_version,
            feature_schema_version=schema.schema_version,
            action_schema_version=schema.action_schema_version,
            graph_schema_version="mirage_graph_v1",
            gnn_model_versions=sorted({
                transition.state_reference.gnn_model_version
                for transition in transitions
                if transition.state_reference.gnn_model_version
            }),
            trajectory_count=len(trajectories),
            transition_count=len(transitions),
            source_distributions=dict(sorted(source_counts.items())),
            tactic_distributions=dict(sorted(tactic_counts.items())),
            action_distributions=dict(sorted(action_counts.items())),
            reward_statistics={
                "mean": round(sum(rewards) / max(1, len(rewards)), 6),
                "min": round(min(rewards), 6) if rewards else 0.0,
                "max": round(max(rewards), 6) if rewards else 0.0,
            },
            safety_statistics={
                "hard_constraint_violations": float(safety_failures),
                "safety_failure_rate": round(safety_failures / max(1, len(transitions)), 6),
            },
            split_manifest={key: sorted(value) for key, value in sorted(splits.items())},
            dataset_hash=dataset_hash,
            creation_timestamp=max(
                (transition.timestamp for transition in transitions),
                default=datetime.now(timezone.utc),
            ),
            warnings=self._dataset_warnings(transitions),
        )

    def save_dataset(
        self,
        trajectories: list[RLTrajectory],
        output_path: str,
        *,
        manifest: OfflineRLDatasetManifest | None = None,
    ) -> OfflineRLDatasetManifest:
        out_dir = Path(output_path)
        traj_dir = out_dir / "trajectories"
        traj_dir.mkdir(parents=True, exist_ok=True)
        manifest = manifest or self.create_manifest(trajectories)
        for trajectory in sorted(trajectories, key=lambda item: item.trajectory_id):
            (traj_dir / f"{trajectory.trajectory_id}.json").write_text(
                trajectory.model_dump_json(indent=2),
                encoding="utf-8",
            )
        (out_dir / "manifest.json").write_text(
            manifest.model_dump_json(indent=2),
            encoding="utf-8",
        )
        analysis = BehaviorPolicyAnalyzer().analyze([
            transition for trajectory in trajectories for transition in trajectory.transitions
        ])
        (out_dir / "behavior_analysis.json").write_text(
            json.dumps(analysis, indent=2, default=str),
            encoding="utf-8",
        )
        return manifest

    def load_dataset(self, input_path: str) -> tuple[list[RLTrajectory], OfflineRLDatasetManifest]:
        in_dir = Path(input_path)
        manifest = OfflineRLDatasetManifest.model_validate_json(
            (in_dir / "manifest.json").read_text(encoding="utf-8")
        )
        trajectories = [
            RLTrajectory.model_validate_json(path.read_text(encoding="utf-8"))
            for path in sorted((in_dir / "trajectories").glob("*.json"))
        ]
        if stable_dataset_hash(trajectories) != manifest.dataset_hash:
            raise ValueError("dataset hash mismatch")
        return trajectories, manifest

    def _dataset_warnings(self, transitions: list[RLTransition]) -> list[str]:
        warnings: list[str] = []
        if not transitions:
            return ["empty_dataset"]
        analysis = BehaviorPolicyAnalyzer().analyze(transitions)
        if analysis["class_imbalance"]["majority_fraction"] > 0.8:
            warnings.append("high_action_class_imbalance")
        if analysis["missing_behavior_probabilities"] > 0:
            warnings.append("behavior_probabilities_missing_for_some_transitions")
        if analysis["safety_violation_frequency"] > 0:
            warnings.append("hard_constraint_violations_present")
        reward_report = reward_quality_report(transitions)
        if reward_report["contradictory_reward_frequency"] > 0:
            warnings.append("contradictory_rewards_detected")
        return sorted(set(warnings))


def split_for_scenario(
    scenario_id: str,
    topology_id: str,
    source_type: str,
) -> RLDatasetSplit:
    sid = scenario_id.lower()
    if "unseen_topology" in sid or "ood_topology" in sid or "topology_ood" in topology_id:
        return RLDatasetSplit.UNSEEN_TOPOLOGY
    if "gnn_unavailable" in sid:
        return RLDatasetSplit.GNN_UNAVAILABLE
    if "stale" in sid or "incomplete" in sid:
        return RLDatasetSplit.STALE_OR_INCOMPLETE_TWIN
    if "ood" in sid or "unknown_action" in sid:
        return RLDatasetSplit.OOD_TYPES
    if "analyst" in source_type or "analyst" in sid:
        return RLDatasetSplit.ANALYST_REVIEWED
    digest = int(hashlib.sha256(f"{scenario_id}|{topology_id}".encode()).hexdigest()[:8], 16)
    bucket = digest % 10
    if bucket < 7:
        return RLDatasetSplit.TRAIN
    if bucket < 8:
        return RLDatasetSplit.VALIDATION
    return RLDatasetSplit.TEST
