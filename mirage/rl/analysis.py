"""Dataset behavior-policy analysis and support scoring."""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Iterable

from mirage.rl.schema import BlueTeamTactic, RLTransition


def state_region_key(vector: list[float], bins: int = 4) -> str:
    coarse = [str(min(bins - 1, max(0, int(float(value) * bins)))) for value in vector[:12]]
    payload = "|".join(coarse)
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


class ActionSupportModel:
    """Counts supported state/action regions from offline data."""

    def __init__(self, min_support: int = 1) -> None:
        self.min_support = int(min_support)
        self.region_action_counts: Counter[tuple[str, str]] = Counter()
        self.action_counts: Counter[str] = Counter()
        self.tactic_counts: Counter[str] = Counter()
        self.total = 0

    def fit(self, transitions: Iterable[RLTransition]) -> "ActionSupportModel":
        for transition in transitions:
            region = state_region_key(transition.state_feature_vector)
            self.region_action_counts[(region, transition.selected_action_id)] += 1
            self.action_counts[transition.selected_action_id] += 1
            self.tactic_counts[transition.selected_high_level_tactic.value] += 1
            self.total += 1
        return self

    def score(self, state_vector: list[float], action_id: str, tactic: BlueTeamTactic | None = None) -> float:
        if self.total <= 0:
            return 0.0
        region = state_region_key(state_vector)
        count = self.region_action_counts.get((region, action_id), 0)
        if count >= self.min_support:
            return min(1.0, count / max(self.min_support, 1))
        fallback = self.action_counts.get(action_id, 0) / max(1, self.total)
        if tactic is not None:
            fallback = max(fallback, self.tactic_counts.get(tactic.value, 0) / max(1, self.total) * 0.5)
        return min(1.0, fallback)

    def unsupported(self, state_vector: list[float], action_id: str, tactic: BlueTeamTactic | None = None, threshold: float = 0.05) -> bool:
        return self.score(state_vector, action_id, tactic) < threshold

    def to_dict(self) -> dict:
        return {
            "min_support": self.min_support,
            "region_action_counts": {
                f"{region}|{action}": count
                for (region, action), count in sorted(self.region_action_counts.items())
            },
            "action_counts": dict(sorted(self.action_counts.items())),
            "tactic_counts": dict(sorted(self.tactic_counts.items())),
            "total": self.total,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ActionSupportModel":
        model = cls(min_support=int(data.get("min_support", 1)))
        for key, count in data.get("region_action_counts", {}).items():
            region, action = key.split("|", 1)
            model.region_action_counts[(region, action)] = int(count)
        model.action_counts.update({key: int(value) for key, value in data.get("action_counts", {}).items()})
        model.tactic_counts.update({key: int(value) for key, value in data.get("tactic_counts", {}).items()})
        model.total = int(data.get("total", sum(model.action_counts.values())))
        return model


class BehaviorPolicyAnalyzer:
    """Summarize behavior-policy support before offline RL training."""

    def analyze(self, transitions: Iterable[RLTransition]) -> dict:
        transitions = list(transitions)
        action_frequency: Counter[str] = Counter()
        tactic_frequency: Counter[str] = Counter()
        candidate_sizes: list[int] = []
        mask_counts: list[int] = []
        policy_sources: Counter[str] = Counter()
        missing_probs = 0
        returns: list[float] = []
        violations = 0
        robust_coverage = 0
        state_regions: defaultdict[str, set[str]] = defaultdict(set)
        for transition in transitions:
            action_frequency[transition.selected_action_id] += 1
            tactic_frequency[transition.selected_high_level_tactic.value] += 1
            candidate_sizes.append(len(transition.candidate_action_features))
            mask_counts.append(len(transition.masked_action_ids))
            policy_sources[transition.behavior_policy_source] += 1
            missing_probs += int(transition.behavior_policy_probability is None)
            returns.append(transition.scalar_reward)
            violations += len(transition.hard_constraint_violations)
            robust_coverage += int("robust" in transition.behavior_policy_source)
            state_regions[state_region_key(transition.state_feature_vector)].add(transition.selected_action_id)
        support = ActionSupportModel().fit(transitions)
        unsupported = [
            transition.selected_action_id
            for transition in transitions
            if support.unsupported(
                transition.state_feature_vector,
                transition.selected_action_id,
                transition.selected_high_level_tactic,
            )
        ]
        return {
            "transition_count": len(transitions),
            "action_frequency": dict(sorted(action_frequency.items())),
            "tactic_frequency": dict(sorted(tactic_frequency.items())),
            "candidate_set_size": _stats(candidate_sizes),
            "mask_frequency": _stats(mask_counts),
            "action_support_by_state_region": {
                region: len(actions)
                for region, actions in sorted(state_regions.items())
            },
            "behavior_policy_diversity": dict(sorted(policy_sources.items())),
            "robust_planner_coverage": round(robust_coverage / max(1, len(transitions)), 6),
            "unsupported_action_state_combinations": sorted(set(unsupported)),
            "missing_behavior_probabilities": missing_probs,
            "class_imbalance": _imbalance(action_frequency),
            "return_distribution": _stats(returns),
            "safety_violation_frequency": round(violations / max(1, len(transitions)), 6),
            "support_model": support.to_dict(),
        }


def _stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0.0, "mean": 0.0, "min": 0.0, "max": 0.0}
    return {
        "count": float(len(values)),
        "mean": round(sum(values) / len(values), 6),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
    }


def _imbalance(counter: Counter[str]) -> dict[str, float]:
    if not counter:
        return {"majority_fraction": 0.0, "unique_classes": 0.0}
    total = sum(counter.values())
    return {
        "majority_fraction": round(max(counter.values()) / max(1, total), 6),
        "unique_classes": float(len(counter)),
    }

