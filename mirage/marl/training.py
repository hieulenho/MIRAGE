"""Self-play training loops for the synthetic MARL cyber range."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from statistics import mean
from typing import Any

from mirage.marl.curriculum import CurriculumManager
from mirage.marl.environment import CyberRangeEnvironment
from mirage.marl.policies import BlueMARLPolicyAdapter, MaskedLinearPolicy, RedAgentPolicy
from mirage.marl.population import OpponentPopulation
from mirage.marl.schema import (
    MARLPolicyMetadata,
    MARLPolicyStatus,
    MARLTrajectory,
    MARLTrajectoryStep,
    RangeIsolationConfig,
    RangeScenario,
    TrainingSummary,
)
from mirage.marl.scenarios import load_scenarios


class SelfPlayTrainer:
    """Compact CPU-only self-play trainer for MARL V1."""

    def __init__(
        self,
        scenarios: list[RangeScenario] | None = None,
        *,
        isolation: RangeIsolationConfig | None = None,
        population: OpponentPopulation | None = None,
        blue_policy: BlueMARLPolicyAdapter | None = None,
    ) -> None:
        self.scenarios = scenarios or load_scenarios()
        self.isolation = isolation or RangeIsolationConfig()
        self.isolation.assert_safe()
        self.population = population or OpponentPopulation()
        self.population.add_scripted_defaults()
        self.blue_policy = blue_policy or BlueMARLPolicyAdapter()
        self.curriculum = CurriculumManager(self.scenarios)

    def run_episode(
        self,
        scenario: RangeScenario,
        red_policy: RedAgentPolicy,
        blue_policy: BlueMARLPolicyAdapter | None = None,
        *,
        seed: int | None = None,
    ) -> MARLTrajectory:
        env = CyberRangeEnvironment(scenario, isolation=self.isolation)
        observation = env.reset(seed=seed)
        blue = blue_policy or self.blue_policy
        steps: list[MARLTrajectoryStep] = []
        total_red = 0.0
        total_blue = 0.0
        while True:
            red_actions = env.valid_red_actions()
            red_action_id = red_policy.select_action(
                observation.red,
                red_actions,
                [action.action_id for action in red_actions],
            )
            blue_action_id = blue.select_action(observation.blue)
            result = env.step(red_action_id, blue_action_id)
            steps.append(
                MARLTrajectoryStep(
                    step_index=observation.red.step_index,
                    red_observation=observation.red,
                    blue_observation=observation.blue,
                    red_action_id=red_action_id,
                    blue_action_id=blue_action_id,
                    red_reward=result.red_reward,
                    blue_reward=result.blue_reward,
                    terminal=result.terminal,
                    info=result.info,
                )
            )
            total_red += result.red_reward
            total_blue += result.blue_reward
            observation = result.observation
            if result.terminal:
                break
        return MARLTrajectory(
            trajectory_id=(
                f"traj:{scenario.scenario_id}:{red_policy.policy_id}:"
                f"{seed if seed is not None else scenario.random_seed}"
            ),
            scenario_id=scenario.scenario_id,
            red_policy_id=red_policy.policy_id,
            blue_policy_id=blue.policy_id,
            steps=steps,
            total_red_return=round(total_red, 6),
            total_blue_return=round(total_blue, 6),
            terminal_reason=env._state().terminal_reason,
        )

    def collect_rollouts(self, episodes: int = 4) -> list[MARLTrajectory]:
        trajectories: list[MARLTrajectory] = []
        scenarios = self.curriculum.active_scenarios() or self.scenarios[:1]
        for episode in range(int(episodes)):
            scenario = scenarios[episode % len(scenarios)]
            red_policy = self.population.sample_red()
            trajectories.append(
                self.run_episode(
                    scenario,
                    red_policy,
                    seed=scenario.random_seed + episode,
                )
            )
        return trajectories

    def train_red(self, episodes: int = 4) -> TrainingSummary:
        trajectories = self.collect_rollouts(episodes)
        policy = MaskedLinearPolicy("red:self_play_linear")
        for trajectory in trajectories:
            for step in trajectory.steps:
                env = CyberRangeEnvironment(
                    next(s for s in self.scenarios if s.scenario_id == trajectory.scenario_id),
                    isolation=self.isolation,
                )
                env.reset()
                actions = env.valid_red_actions()
                policy.train_step(actions, [step.red_reward for _ in actions])
        return self._summary("train_red", "masked_linear_red", trajectories)

    def train_blue(self, episodes: int = 4) -> TrainingSummary:
        trajectories = self.collect_rollouts(episodes)
        return self._summary("train_blue", "shadow_blue_adapter", trajectories)

    def self_play(self, episodes: int = 6) -> TrainingSummary:
        trajectories = self.collect_rollouts(episodes)
        mean_blue = mean([t.total_blue_return for t in trajectories]) if trajectories else 0.0
        self.curriculum.update(episodes, mean_blue)
        return self._summary("self_play", "population_self_play", trajectories)

    def evaluate_population(self, episodes: int = 4) -> dict[str, Any]:
        trajectories = self.collect_rollouts(episodes)
        by_policy: dict[str, list[float]] = {}
        for trajectory in trajectories:
            by_policy.setdefault(trajectory.red_policy_id, []).append(
                trajectory.total_blue_return
            )
        return {
            "episodes": episodes,
            "mean_blue_return": mean([t.total_blue_return for t in trajectories]) if trajectories else 0.0,
            "per_red_policy_blue_return": {
                policy_id: round(mean(values), 6)
                for policy_id, values in sorted(by_policy.items())
            },
            "terminal_reasons": dict(Counter(t.terminal_reason for t in trajectories)),
        }

    def save_checkpoint(self, output_path: str, summary: TrainingSummary) -> None:
        path = Path(output_path)
        path.mkdir(parents=True, exist_ok=True)
        (path / "summary.json").write_text(
            json.dumps(summary.model_dump(mode="json"), indent=2),
            encoding="utf-8",
        )

    def _summary(
        self,
        job_id: str,
        algorithm: str,
        trajectories: list[MARLTrajectory],
    ) -> TrainingSummary:
        terminal_reasons = Counter(t.terminal_reason for t in trajectories)
        metadata = MARLPolicyMetadata(
            policy_id=f"marl_{algorithm}_v1",
            version="v1",
            role="blue" if "blue" in algorithm or "self_play" in algorithm else "red",
            algorithm=algorithm,
            architecture="masked_discrete_graph_policy",
            scenario_ids=sorted({t.scenario_id for t in trajectories}),
            training_steps=sum(len(t.steps) for t in trajectories),
            status=MARLPolicyStatus.VALIDATED,
            safety={
                "cyber_range_only": True,
                "blue_execution_mode": self.isolation.blue_execution_mode,
                "real_exploitation_enabled": False,
            },
        )
        return TrainingSummary(
            job_id=job_id,
            algorithm=algorithm,
            episodes=len(trajectories),
            trajectories=len(trajectories),
            mean_red_return=round(mean([t.total_red_return for t in trajectories]), 6)
            if trajectories
            else 0.0,
            mean_blue_return=round(mean([t.total_blue_return for t in trajectories]), 6)
            if trajectories
            else 0.0,
            terminal_reasons=dict(terminal_reasons),
            policy_metadata=metadata,
            warnings=[
                "Synthetic MARL V1 uses bounded graph-simulator self-play only."
            ],
        )
