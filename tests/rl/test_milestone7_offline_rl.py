from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.domain.schemas import (
    AutomationLevel,
    CandidateDefenseAction,
    RiskTier,
)
from mirage.rl.dataset import OfflineRLDatasetBuilder
from mirage.rl.evaluation import _state_from_transition
from mirage.rl.features import ActionFeatureEncoder
from mirage.rl.inference import OfflineRLInferenceService
from mirage.rl.policy import OfflineBlueTeamPolicy
from mirage.rl.reward import DefenseRewardModel
from mirage.rl.scenarios import build_synthetic_trajectories
from mirage.rl.training import train_behavior_cloning, train_offline_policy


def test_rl_dataset_serialization_hash_and_split_are_deterministic(tmp_path):
    builder = OfflineRLDatasetBuilder()
    trajectories = build_synthetic_trajectories()
    out_dir = tmp_path / "rl_dataset"

    manifest = builder.save_dataset(trajectories, str(out_dir))
    loaded, loaded_manifest = builder.load_dataset(str(out_dir))
    manifest_2 = builder.create_manifest(loaded)

    assert loaded_manifest.dataset_hash == manifest.dataset_hash
    assert manifest_2.dataset_hash == manifest.dataset_hash
    assert loaded_manifest.trajectory_count == 16
    assert loaded_manifest.transition_count == 16
    assert "train" in loaded_manifest.split_manifest
    assert "unseen_topology" in loaded_manifest.split_manifest
    for trajectory in loaded:
        assert [t.step_index for t in trajectory.transitions] == sorted(
            t.step_index for t in trajectory.transitions
        )
        for transition in trajectory.transitions:
            assert transition.selected_action_id not in transition.masked_action_ids
            assert all(isinstance(value, float) for value in transition.state_feature_vector)


def test_reward_hard_constraint_cannot_be_canceled_by_positive_reward():
    transition = build_synthetic_trajectories()[0].transitions[0]
    state = _state_from_transition(transition)
    feature = transition.candidate_action_features[0].model_copy(
        update={"action_mask_status": "masked"}
    )

    reward = DefenseRewardModel().compute(
        state,
        feature,
        None,
        {
            "risk_reduction": 1.0,
            "decoy_interception": 1.0,
            "protected_asset_safe": True,
        },
    )

    assert "masked_action_selection" in reward.hard_constraint_violations
    assert reward.scalar_reward <= -1.0


def test_action_encoder_unknown_action_warns_and_masks_by_default():
    action = CandidateDefenseAction(
        action_id="action:unknown",
        action_type="launch_magic_box",
        expected_risk_reduction=0.8,
        expected_information_gain=0.1,
        operational_cost=1.0,
        business_risk=0.2,
        deployment_cost=1.0,
        confidence=0.9,
        uncertainty=0.1,
        risk_tier=RiskTier.MEDIUM.value,
        automation_level=AutomationLevel.RECOMMEND_ONLY.value,
        requires_approval=False,
        rollback_supported=True,
        reason="unknown action fixture",
        generated_at=datetime(2026, 6, 21, tzinfo=timezone.utc),
    )

    feature = ActionFeatureEncoder().encode(action)

    assert feature.tactic_category.value == "NO_OP"
    assert feature.action_mask_status == "masked_unknown_action_type"
    assert any("unknown_action_type" in warning for warning in feature.ood_warnings)


def test_bc_and_offline_policy_train_save_load_and_respect_masks(tmp_path):
    dataset_dir = tmp_path / "dataset"
    bc_dir = tmp_path / "bc"
    policy_dir = tmp_path / "offline"
    builder = OfflineRLDatasetBuilder()
    builder.save_dataset(build_synthetic_trajectories(), str(dataset_dir))

    bc_meta = train_behavior_cloning(str(dataset_dir), str(bc_dir), {"hierarchical": True})
    rl_meta = train_offline_policy(str(dataset_dir), str(policy_dir), str(bc_dir), {"epochs": 2})
    policy = OfflineBlueTeamPolicy.load(str(policy_dir))
    trajectories, _ = builder.load_dataset(str(dataset_dir))
    state = _state_from_transition(trajectories[0].transitions[0])
    result = policy.recommend(state)
    service = OfflineRLInferenceService()
    service.load_policy(str(policy_dir))
    served = service.recommend(state)

    assert bc_meta.algorithm == "behavior_cloning"
    assert rl_meta.algorithm == "implicit_q_learning_style_discrete"
    assert result.selected_action_id not in state.masked_action_ids
    assert served.selected_action_id not in state.masked_action_ids
    assert service.health().status == "ok"


def test_rl_api_health_and_training_endpoints_are_safe_by_default():
    client = TestClient(create_app())

    health = client.get("/api/v1/rl/health")
    build = client.post("/api/v1/rl/datasets/build", json={})
    train = client.post(
        "/api/v1/rl/train",
        json={
            "dataset_path": "artifacts/rl_dataset",
            "output_path": "models/rl_api_test",
            "algorithm": "offline_rl",
        },
    )

    assert health.status_code == 200
    assert health.json()["execution_enabled"] is False
    assert build.status_code == 403
    assert train.status_code == 403


def test_rl_api_recommend_is_read_only_and_returns_fallback_when_unloaded():
    transition = build_synthetic_trajectories()[0].transitions[0]
    state = _state_from_transition(transition)
    client = TestClient(create_app())

    response = client.post(
        "/api/v1/rl/recommend",
        json={"encoded_state": state.model_dump(mode="json")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["fallback_used"] is True
    assert body["fallback_reason"] == "no_policy_loaded"
    assert body["selected_action_id"] not in transition.masked_action_ids
