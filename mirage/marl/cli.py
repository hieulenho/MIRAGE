"""CLI for MIRAGE Milestone 8 MARL cyber range."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _isolation() -> Any:
    from mirage.config import load_config
    from mirage.marl.schema import RangeIsolationConfig

    return RangeIsolationConfig.model_validate(load_config().get("marl", {}))


def cmd_range_check(args) -> int:
    from mirage.marl.registry import MARLPolicyRegistry
    from mirage.marl.scenarios import load_scenarios
    from mirage.marl.schema import RangeHealth

    isolation = _isolation()
    registry = MARLPolicyRegistry(args.registry)
    health = RangeHealth(
        status="isolated",
        isolation=isolation,
        training_api_enabled=isolation.training_api_enabled,
        policy_count=len(registry.list_policies()),
        scenario_count=len(load_scenarios()),
        warnings=[],
    )
    _print_json(health.model_dump(mode="json"))
    return 0


def cmd_generate_scenarios(args) -> int:
    from mirage.marl.scenarios import load_scenarios

    scenarios = load_scenarios(args.count)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    for scenario in scenarios:
        (output / f"{scenario.scenario_id}.json").write_text(
            scenario.model_dump_json(indent=2),
            encoding="utf-8",
        )
    _print_json({"scenario_count": len(scenarios), "output": str(output)})
    return 0


def _trainer(scenario_count: int | None = None):
    from mirage.marl.scenarios import load_scenarios
    from mirage.marl.training import SelfPlayTrainer

    scenarios = load_scenarios(scenario_count or 6)
    return SelfPlayTrainer(scenarios, isolation=_isolation())


def cmd_train_red(args) -> int:
    summary = _trainer(args.scenarios).train_red(args.episodes)
    if args.output:
        _trainer(args.scenarios).save_checkpoint(args.output, summary)
    _print_json(summary.model_dump(mode="json"))
    return 0


def cmd_train_blue(args) -> int:
    trainer = _trainer(args.scenarios)
    summary = trainer.train_blue(args.episodes)
    if args.output:
        trainer.save_checkpoint(args.output, summary)
    _print_json(summary.model_dump(mode="json"))
    return 0


def cmd_self_play(args) -> int:
    trainer = _trainer(args.scenarios)
    summary = trainer.self_play(args.episodes)
    if args.output:
        trainer.save_checkpoint(args.output, summary)
    _print_json(summary.model_dump(mode="json"))
    return 0


def cmd_evaluate(args) -> int:
    from mirage.marl.evaluation import ExploitabilityEvaluator, PolicyRobustnessEvaluator
    from mirage.marl.scenarios import load_scenarios

    scenarios = load_scenarios(args.scenarios)
    output = {
        "exploitability": ExploitabilityEvaluator(
            scenarios,
            isolation=_isolation(),
        ).evaluate().model_dump(mode="json"),
        "robustness": PolicyRobustnessEvaluator(
            scenarios,
            isolation=_isolation(),
        ).evaluate().model_dump(mode="json"),
    }
    _print_json(output)
    return 0


def cmd_population(args) -> int:
    from mirage.marl.population import OpponentPopulation

    population = OpponentPopulation()
    population.add_scripted_defaults()
    _print_json({
        "opponents": [
            item.model_dump(mode="json") for item in population.list_metadata()
        ]
    })
    return 0


def cmd_replay(args) -> int:
    from mirage.marl.environment import CyberRangeEnvironment
    from mirage.marl.scenarios import scenario_by_id

    env = CyberRangeEnvironment(scenario_by_id(args.scenario), isolation=_isolation())
    env.reset()
    steps = json.loads(Path(args.steps).read_text(encoding="utf-8"))
    results = env.replay(steps)
    _print_json({
        "steps": [result.model_dump(mode="json") for result in results],
        "final_state": env.snapshot(),
    })
    return 0


def cmd_compare_blue(args) -> int:
    from mirage.marl.evaluation import PolicyRobustnessEvaluator
    from mirage.marl.scenarios import load_scenarios

    report = PolicyRobustnessEvaluator(
        load_scenarios(args.scenarios),
        isolation=_isolation(),
    ).evaluate()
    _print_json(report.model_dump(mode="json"))
    return 0


def cmd_policies(args) -> int:
    from mirage.marl.registry import MARLPolicyRegistry

    registry = MARLPolicyRegistry(args.registry)
    _print_json({
        "summary": registry.summary(),
        "policies": [
            policy.model_dump(mode="json") for policy in registry.list_policies()
        ],
    })
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mirage marl",
        description="MIRAGE MARL cyber-range commands",
    )
    sub = parser.add_subparsers(dest="marl_command", required=True)
    p = sub.add_parser("range-check")
    p.add_argument("--registry", default="models/marl_policy_registry.json")
    p = sub.add_parser("generate-scenarios")
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--output", default="artifacts/marl_scenarios")
    for name in ("train-red", "train-blue", "self-play"):
        p = sub.add_parser(name)
        p.add_argument("--episodes", type=int, default=4)
        p.add_argument("--scenarios", type=int, default=6)
        p.add_argument("--output", default="")
    p = sub.add_parser("evaluate")
    p.add_argument("--scenarios", type=int, default=6)
    sub.add_parser("population")
    p = sub.add_parser("replay")
    p.add_argument("--scenario", default="marl_scenario_00")
    p.add_argument("--steps", required=True)
    p = sub.add_parser("compare-blue")
    p.add_argument("--scenarios", type=int, default=6)
    p = sub.add_parser("policies")
    p.add_argument("--registry", default="models/marl_policy_registry.json")
    args = parser.parse_args(argv)
    dispatch = {
        "range-check": cmd_range_check,
        "generate-scenarios": cmd_generate_scenarios,
        "train-red": cmd_train_red,
        "train-blue": cmd_train_blue,
        "self-play": cmd_self_play,
        "evaluate": cmd_evaluate,
        "population": cmd_population,
        "replay": cmd_replay,
        "compare-blue": cmd_compare_blue,
        "policies": cmd_policies,
    }
    return dispatch[args.marl_command](args)


if __name__ == "__main__":
    raise SystemExit(main())
