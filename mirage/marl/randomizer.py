"""Scenario randomization for robust range evaluation."""

from __future__ import annotations

import random

from mirage.marl.schema import RangeScenario, clamp01


class ScenarioRandomizer:
    """Create bounded synthetic scenario variants."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)

    def randomize(self, scenario: RangeScenario, variant_id: str | None = None) -> RangeScenario:
        suffix = variant_id or f"variant_{self.rng.randint(1, 1_000_000)}"
        nodes = []
        for node in scenario.nodes:
            delta = self.rng.uniform(-0.08, 0.08)
            nodes.append(
                node.model_copy(
                    update={
                        "value": clamp01(node.value + delta),
                        "exposure": clamp01(node.exposure + self.rng.uniform(-0.08, 0.08)),
                    }
                )
            )
        edges = []
        for edge in scenario.edges:
            edges.append(
                edge.model_copy(
                    update={
                        "difficulty": clamp01(edge.difficulty + self.rng.uniform(-0.1, 0.1)),
                        "noise": clamp01(edge.noise + self.rng.uniform(-0.04, 0.04)),
                    }
                )
            )
        return scenario.model_copy(
            update={
                "scenario_id": f"{scenario.scenario_id}:{suffix}",
                "name": f"{scenario.name} {suffix}",
                "nodes": nodes,
                "edges": edges,
                "random_seed": scenario.random_seed + self.rng.randint(1, 999),
                "tags": sorted({*scenario.tags, "randomized"}),
            }
        )
