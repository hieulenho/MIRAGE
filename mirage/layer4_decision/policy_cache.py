"""Offline policy optimization and low-latency online policy lookup."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional
import json
import os
import tempfile
import time


@dataclass
class CachedPolicy:
    stage: str
    belief_key: str
    criterion: str
    budget: float
    action_ids: List[str]
    metrics: Dict[str, float]
    created_at: float


class PolicyCache:
    def __init__(self, path: str = "results/policy_cache.json"):
        self.path = path
        self._policies: Dict[str, CachedPolicy] = {}
        self.load()

    @staticmethod
    def belief_key(
        belief_state: Optional[Dict[int, float]],
        top_k: int = 3,
        precision: int = 2,
    ) -> str:
        if not belief_state:
            return "entry"
        top = sorted(
            belief_state.items(),
            key=lambda item: (-item[1], item[0]),
        )[:top_k]
        return "|".join(
            f"{state}:{round(probability, precision):.{precision}f}"
            for state, probability in top
        )

    @staticmethod
    def _key(stage: str, belief_key: str, criterion: str, budget: float) -> str:
        return f"{stage}::{belief_key}::{criterion}::{budget:.2f}"

    def put(self, policy: CachedPolicy) -> None:
        key = self._key(
            policy.stage,
            policy.belief_key,
            policy.criterion,
            policy.budget,
        )
        self._policies[key] = policy

    def get(
        self,
        stage: str,
        belief_state: Optional[Dict[int, float]],
        criterion: str,
        budget: float,
    ) -> Optional[CachedPolicy]:
        key = self._key(
            stage,
            self.belief_key(belief_state),
            criterion,
            budget,
        )
        return self._policies.get(key)

    def save(self) -> None:
        directory = os.path.dirname(self.path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        target_directory = directory or "."
        descriptor, temporary_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(self.path)}.",
            suffix=".tmp",
            dir=target_directory,
            text=True,
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                json.dump(
                    {
                        key: asdict(policy)
                        for key, policy in self._policies.items()
                    },
                    output,
                    indent=2,
                )
            os.replace(temporary_path, self.path)
        finally:
            if os.path.exists(temporary_path):
                os.unlink(temporary_path)

    def load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as source:
                data = json.load(source)
            self._policies = {
                key: CachedPolicy(**value)
                for key, value in data.items()
            }
        except (OSError, ValueError, TypeError):
            self._policies = {}


class OfflinePolicyOptimizer:
    """Runs the expensive optimizer outside the online request path."""

    def __init__(self, engine, cache: PolicyCache):
        self.engine = engine
        self.cache = cache

    def optimize_and_store(
        self,
        stage: str,
        belief_state: Optional[Dict[int, float]],
        budget: float,
        criterion: str = "cost_aware_robust",
        min_actions: int = 1,
    ) -> CachedPolicy:
        portfolio, result = self.engine.optimize_portfolio(
            budget=budget,
            belief_state=belief_state,
            criterion=criterion,
            min_actions=min_actions,
        )
        policy = CachedPolicy(
            stage=stage,
            belief_key=self.cache.belief_key(belief_state),
            criterion=criterion,
            budget=budget,
            action_ids=[action.action_id for action in portfolio],
            metrics={
                "pessimistic_value": result.get("pessimistic_value", 0.0),
                "expected_value": result.get("expected_value", 0.0),
                "margin_guarantee": result.get("margin_guarantee", 0.0),
                "total_cost": result.get("total_cost", 0.0),
                "false_positive_cost": result.get("false_positive_cost", 0.0),
            },
            created_at=time.time(),
        )
        self.cache.put(policy)
        self.cache.save()
        return policy


class OnlinePolicyController:
    """
    Online path:
    telemetry -> stage estimate -> belief update -> lookup -> safety -> deploy.
    """

    def __init__(self, fabric, cache: PolicyCache):
        self.fabric = fabric
        self.cache = cache

    def handle(
        self,
        telemetry,
        stage_estimator: Callable,
        belief_updater: Callable,
        safety_gate: Callable,
        deploy_action: Optional[Callable] = None,
        budget: float = 4.0,
        criterion: str = "cost_aware_robust",
    ) -> Dict:
        stage = stage_estimator(telemetry)
        belief_state = belief_updater(telemetry)
        policy = self.cache.get(stage, belief_state, criterion, budget)
        if policy is None:
            return {"status": "cache_miss", "stage": stage, "belief": belief_state}

        catalog = {
            action.action_id: action
            for action in self.fabric.action_catalog
        }
        actions = [
            catalog[action_id]
            for action_id in policy.action_ids
            if action_id in catalog
        ]
        missing = [
            action_id
            for action_id in policy.action_ids
            if action_id not in catalog
        ]
        if missing:
            return {
                "status": "cache_stale",
                "stage": stage,
                "belief": belief_state,
                "missing_action_ids": missing,
            }
        safe, reason = safety_gate(actions, belief_state)
        if not safe:
            return {
                "status": "blocked",
                "stage": stage,
                "belief": belief_state,
                "reason": reason,
            }

        deploy = deploy_action or self.fabric.deploy_action
        deployed = [deploy(action) for action in actions]
        return {
            "status": "deployed",
            "stage": stage,
            "belief": belief_state,
            "action_ids": policy.action_ids,
            "deployed": deployed,
        }
