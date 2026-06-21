"""Curriculum scheduling for the synthetic MARL range."""

from __future__ import annotations

from dataclasses import dataclass

from mirage.marl.schema import RangeScenario


@dataclass
class CurriculumStage:
    """One curriculum stage."""

    stage_id: str
    scenario_ids: list[str]
    min_episodes: int
    promotion_threshold: float


class CurriculumManager:
    """Select scenarios as policies improve."""

    def __init__(self, scenarios: list[RangeScenario]) -> None:
        self.scenarios = scenarios
        split = max(1, len(scenarios) // 4)
        self.stages = [
            CurriculumStage("intro", [s.scenario_id for s in scenarios[:split]], 2, 0.2),
            CurriculumStage(
                "deception",
                [s.scenario_id for s in scenarios[split : split * 2]],
                4,
                0.35,
            ),
            CurriculumStage(
                "credential",
                [s.scenario_id for s in scenarios[split * 2 : split * 3]],
                6,
                0.5,
            ),
            CurriculumStage(
                "robust",
                [s.scenario_id for s in scenarios[split * 3 :]],
                8,
                0.65,
            ),
        ]
        self.current_stage_index = 0

    def active_stage(self) -> CurriculumStage:
        return self.stages[self.current_stage_index]

    def active_scenarios(self) -> list[RangeScenario]:
        ids = set(self.active_stage().scenario_ids)
        return [scenario for scenario in self.scenarios if scenario.scenario_id in ids]

    def update(self, episodes_completed: int, mean_blue_return: float) -> CurriculumStage:
        stage = self.active_stage()
        if (
            episodes_completed >= stage.min_episodes
            and mean_blue_return >= stage.promotion_threshold
            and self.current_stage_index < len(self.stages) - 1
        ):
            self.current_stage_index += 1
        return self.active_stage()
