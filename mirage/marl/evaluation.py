"""Evaluation utilities for MARL cyber-range policies."""

from __future__ import annotations

from statistics import mean

from mirage.marl.policies import BlueMARLPolicyAdapter, RedAgentPolicy, scripted_red_policies
from mirage.marl.schema import (
    ExploitabilityReport,
    PolicyRobustnessReport,
    RangeIsolationConfig,
    RangeScenario,
)
from mirage.marl.scenarios import load_scenarios
from mirage.marl.training import SelfPlayTrainer


class ExploitabilityEvaluator:
    """Approximate exploitability via bounded scripted best responses."""

    def __init__(
        self,
        scenarios: list[RangeScenario] | None = None,
        isolation: RangeIsolationConfig | None = None,
    ) -> None:
        self.scenarios = scenarios or load_scenarios(6)
        self.isolation = isolation or RangeIsolationConfig()

    def evaluate(
        self,
        blue_policy: BlueMARLPolicyAdapter | None = None,
    ) -> ExploitabilityReport:
        blue = blue_policy or BlueMARLPolicyAdapter()
        returns: dict[str, float] = {}
        trainer = SelfPlayTrainer(
            self.scenarios,
            isolation=self.isolation,
            blue_policy=blue,
        )
        for policy in scripted_red_policies():
            values = [
                trainer.run_episode(scenario, policy).total_red_return
                for scenario in self.scenarios
            ]
            returns[policy.policy_id] = round(mean(values), 6)
        best_policy = max(returns, key=returns.get)
        baseline = mean(returns.values()) if returns else 0.0
        exploitability = max(0.0, returns[best_policy] - baseline)
        return ExploitabilityReport(
            evaluated_policy_id=blue.policy_id,
            scenario_count=len(self.scenarios),
            best_response_policy_id=best_policy,
            approximate_exploitability=round(exploitability, 6),
            per_opponent_return=returns,
        )


class PolicyRobustnessEvaluator:
    """Evaluate a blue policy across scenarios and opponent profiles."""

    def __init__(
        self,
        scenarios: list[RangeScenario] | None = None,
        isolation: RangeIsolationConfig | None = None,
    ) -> None:
        self.scenarios = scenarios or load_scenarios(8)
        self.isolation = isolation or RangeIsolationConfig()

    def evaluate(
        self,
        blue_policy: BlueMARLPolicyAdapter | None = None,
        red_policies: list[RedAgentPolicy] | None = None,
    ) -> PolicyRobustnessReport:
        blue = blue_policy or BlueMARLPolicyAdapter()
        reds = red_policies or scripted_red_policies()
        trainer = SelfPlayTrainer(
            self.scenarios,
            isolation=self.isolation,
            blue_policy=blue,
        )
        per_scenario: dict[str, float] = {}
        all_returns: list[float] = []
        for scenario in self.scenarios:
            values = [
                trainer.run_episode(scenario, red_policy).total_blue_return
                for red_policy in reds
            ]
            per_scenario[scenario.scenario_id] = round(mean(values), 6)
            all_returns.extend(values)
        return PolicyRobustnessReport(
            policy_id=blue.policy_id,
            scenario_count=len(self.scenarios),
            opponent_count=len(reds),
            mean_blue_return=round(mean(all_returns), 6) if all_returns else 0.0,
            worst_case_blue_return=round(min(all_returns), 6) if all_returns else 0.0,
            per_scenario_return=per_scenario,
            warnings=[
                "Robustness is measured in the synthetic cyber range only."
            ],
        )
