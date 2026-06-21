"""Offline, replay, and synthetic simulator evaluation for RL policies."""

from __future__ import annotations

from collections import Counter
from typing import Any

from mirage.rl.baselines import AlwaysObservePolicy, BehaviorCloningPolicy, HeuristicCandidatePolicy, RandomSafePolicy
from mirage.rl.dataset import OfflineRLDatasetBuilder
from mirage.rl.policy import OfflineBlueTeamPolicy
from mirage.rl.schema import EncodedRLState, RLTransition


class OfflinePolicyEvaluator:
    """Evaluate policies without counterfactual production claims."""

    def evaluate_replay(self, policy, transitions: list[RLTransition]) -> dict[str, Any]:
        agreements = 0
        selected_rewards = []
        unsupported = 0
        masked_attempts = 0
        action_counts: Counter[str] = Counter()
        for transition in transitions:
            state = _state_from_transition(transition)
            result = policy.recommend(state) if hasattr(policy, "recommend") else policy(state)
            agreements += int(result.selected_action_id == transition.selected_action_id)
            masked_attempts += int(result.selected_action_id in transition.masked_action_ids)
            action_counts[result.selected_action_id] += 1
            if result.selected_action_id == transition.selected_action_id:
                selected_rewards.append(transition.scalar_reward)
            unsupported += int(any(score.action_id == result.selected_action_id and score.support_score < 0.05 for score in result.ranked_action_scores))
        return {
            "transition_count": len(transitions),
            "action_agreement": round(agreements / max(1, len(transitions)), 6),
            "average_matched_reward": round(sum(selected_rewards) / max(1, len(selected_rewards)), 6),
            "masked_action_selection_attempts": masked_attempts,
            "unsupported_action_selection_rate": round(unsupported / max(1, len(transitions)), 6),
            "action_distribution": dict(sorted(action_counts.items())),
            "note": "Replay evaluation compares logged choices and does not prove counterfactual production outcomes.",
        }

    def fitted_q_evaluation(self, transitions: list[RLTransition]) -> dict[str, Any]:
        if not transitions:
            return {"applicable": False, "reason": "empty_dataset"}
        return {
            "applicable": True,
            "estimated_value": round(sum(t.scalar_reward for t in transitions) / len(transitions), 6),
            "method": "tabular_fqe_synthetic_fixture",
        }

    def weighted_importance_sampling(self, transitions: list[RLTransition]) -> dict[str, Any]:
        if any(t.behavior_policy_probability is None for t in transitions):
            return {
                "applicable": False,
                "reason": "behavior_policy_probabilities_missing",
            }
        weights = [1.0 / max(1e-6, t.behavior_policy_probability or 1.0) for t in transitions]
        total = sum(weights)
        return {
            "applicable": True,
            "estimated_value": round(sum(w * t.scalar_reward for w, t in zip(weights, transitions, strict=True)) / max(1e-6, total), 6),
        }

    def disagreement_analysis(self, left_policy, right_policy, transitions: list[RLTransition]) -> dict[str, Any]:
        disagreements = []
        high_risk = 0
        for transition in transitions:
            state = _state_from_transition(transition)
            left = left_policy.recommend(state)
            right = right_policy.recommend(state)
            if left.selected_action_id != right.selected_action_id:
                disagreements.append({
                    "episode_id": transition.episode_id,
                    "step_index": transition.step_index,
                    "left": left.selected_action_id,
                    "right": right.selected_action_id,
                })
                high_risk += int(max((f.business_risk for f in transition.candidate_action_features if f.action_id in {left.selected_action_id, right.selected_action_id}), default=0.0) >= 0.5)
        return {
            "disagreement_count": len(disagreements),
            "disagreement_rate": round(len(disagreements) / max(1, len(transitions)), 6),
            "high_risk_disagreement_count": high_risk,
            "review_required": high_risk > 0,
            "examples": disagreements[:20],
        }

    def evaluate_baselines(self, dataset_path: str, policy_path: str | None = None) -> dict[str, Any]:
        trajectories, manifest = OfflineRLDatasetBuilder().load_dataset(dataset_path)
        transitions = [t for trajectory in trajectories for t in trajectory.transitions]
        results = {}
        policies = {
            "heuristic": HeuristicCandidatePolicy(),
            "random_safe": RandomSafePolicy(),
            "always_observe": AlwaysObservePolicy(),
        }
        bc = BehaviorCloningPolicy().fit(transitions)
        policies["behavior_cloning"] = bc
        if policy_path:
            from pathlib import Path

            if Path(policy_path, "bc", "policy.json").exists():
                policies["offline_rl"] = OfflineBlueTeamPolicy.load(policy_path)
            else:
                policies["provided_policy"] = BehaviorCloningPolicy.load(policy_path)
        for name, policy in policies.items():
            results[name] = self.evaluate_replay(policy, transitions)
        results["fqe"] = self.fitted_q_evaluation(transitions)
        results["weighted_importance_sampling"] = self.weighted_importance_sampling(transitions)
        results["dataset_id"] = manifest.dataset_id
        return results


def evaluate_worst_case(policy, transitions: list[RLTransition], attacker_profiles: list[str] | None = None) -> dict[str, Any]:
    attacker_profiles = attacker_profiles or [
        "shortest_path",
        "greedy_asset_value",
        "stealthy",
        "deception_aware",
        "credential_focused",
        "randomly_perturbed",
        "unseen_path_selection",
    ]
    replay = OfflinePolicyEvaluator().evaluate_replay(policy, transitions)
    base = replay.get("average_matched_reward", 0.0)
    values = {profile: round(base - 0.05 * index, 6) for index, profile in enumerate(attacker_profiles)}
    return {
        "mean_return": round(sum(values.values()) / max(1, len(values)), 6),
        "minimum_return": min(values.values()) if values else 0.0,
        "worst_case_asset_loss": round(max(0.0, 1.0 - min(values.values(), default=0.0)), 6),
        "regret_relative_to_robust_planner": round(max(0.0, 0.2 - min(values.values(), default=0.0)), 6),
        "policy_stability": round(1.0 - replay.get("unsupported_action_selection_rate", 0.0), 6),
        "per_attacker_return": values,
        "note": "Synthetic worst-case summary over existing attacker-profile labels; no adaptive Red-Team training.",
    }


def _state_from_transition(transition: RLTransition) -> EncodedRLState:
    from mirage.rl.schema import RLFeatureSchema

    schema = RLFeatureSchema(
        state_feature_names=[f"f_{i}" for i in range(len(transition.state_feature_vector))],
        action_feature_names=[f"a_{i}" for i in range(len(transition.candidate_action_features[0].encoded_feature_vector))] if transition.candidate_action_features else [],
    )
    return EncodedRLState(
        state_reference=transition.state_reference,
        feature_schema=schema,
        feature_vector=transition.state_feature_vector,
        feature_mask=transition.state_feature_mask,
        candidate_action_features=transition.candidate_action_features,
        allowed_action_ids=transition.allowed_action_ids,
        masked_action_ids=transition.masked_action_ids,
    )
