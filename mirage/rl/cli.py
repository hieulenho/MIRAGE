"""CLI for MIRAGE Milestone 7 offline RL."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def _load_config(path: str | None) -> dict[str, Any]:
    if not path or not Path(path).exists():
        return {}
    try:
        import yaml

        return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except ImportError:
        data: dict[str, Any] = {}
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            stripped = line.split("#", 1)[0].strip()
            if not stripped or ":" not in stripped:
                continue
            key, value = stripped.split(":", 1)
            value = value.strip().strip("'\"")
            if value.lower() in {"true", "false"}:
                data[key.strip()] = value.lower() == "true"
            else:
                try:
                    data[key.strip()] = int(value)
                except ValueError:
                    try:
                        data[key.strip()] = float(value)
                    except ValueError:
                        data[key.strip()] = value
        return data


def cmd_build_dataset(args) -> int:
    from mirage.rl.dataset import OfflineRLDatasetBuilder
    from mirage.rl.scenarios import build_synthetic_trajectories

    builder = OfflineRLDatasetBuilder()
    trajectories = build_synthetic_trajectories()
    manifest = builder.save_dataset(trajectories, args.output)
    _print_json(manifest.model_dump(mode="json"))
    return 0


def cmd_analyze_dataset(args) -> int:
    from mirage.rl.analysis import BehaviorPolicyAnalyzer
    from mirage.rl.dataset import OfflineRLDatasetBuilder
    from mirage.rl.reward import reward_quality_report

    trajectories, manifest = OfflineRLDatasetBuilder().load_dataset(args.dataset)
    transitions = [t for trajectory in trajectories for t in trajectory.transitions]
    output = {
        "manifest": manifest.model_dump(mode="json"),
        "behavior_policy_analysis": BehaviorPolicyAnalyzer().analyze(transitions),
        "reward_quality": reward_quality_report(transitions),
    }
    _print_json(output)
    return 0


def cmd_train_bc(args) -> int:
    from mirage.rl.training import train_behavior_cloning

    config = _load_config(args.config)
    metadata = train_behavior_cloning(args.dataset, args.output, config)
    _print_json(metadata.model_dump(mode="json"))
    return 0


def cmd_train_offline(args) -> int:
    from mirage.rl.training import train_offline_policy

    config = _load_config(args.config)
    metadata = train_offline_policy(args.dataset, args.output, args.init_policy, config)
    _print_json(metadata.model_dump(mode="json"))
    return 0


def cmd_evaluate(args) -> int:
    from mirage.rl.dataset import OfflineRLDatasetBuilder
    from mirage.rl.evaluation import OfflinePolicyEvaluator, evaluate_worst_case
    from mirage.rl.policy import OfflineBlueTeamPolicy

    evaluator = OfflinePolicyEvaluator()
    results = evaluator.evaluate_baselines(args.dataset, args.policy if args.policy and Path(args.policy).exists() else None)
    if args.policy and Path(args.policy, "bc", "policy.json").exists():
        trajectories, _ = OfflineRLDatasetBuilder().load_dataset(args.dataset)
        transitions = [t for trajectory in trajectories for t in trajectory.transitions]
        results["worst_case"] = evaluate_worst_case(OfflineBlueTeamPolicy.load(args.policy), transitions)
    _print_json(results)
    return 0


def cmd_policies(args) -> int:
    from mirage.rl.registry import PolicyRegistry

    reg = PolicyRegistry(args.registry)
    _print_json({
        "summary": reg.summary(),
        "policies": [policy.model_dump(mode="json") for policy in reg.list_policies()],
    })
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage rl", description="MIRAGE offline RL commands")
    sub = parser.add_subparsers(dest="rl_command", required=True)
    p = sub.add_parser("build-dataset")
    p.add_argument("--sources", default="simulator,robust,shadow,lab")
    p.add_argument("--output", default="artifacts/rl_dataset")
    p = sub.add_parser("analyze-dataset")
    p.add_argument("--dataset", default="artifacts/rl_dataset")
    p = sub.add_parser("train-bc")
    p.add_argument("--dataset", default="artifacts/rl_dataset")
    p.add_argument("--config", default="configs/rl_bc_v1.yaml")
    p.add_argument("--output", default="models/rl_bc_v1")
    p = sub.add_parser("train-offline")
    p.add_argument("--dataset", default="artifacts/rl_dataset")
    p.add_argument("--init-policy", default=None)
    p.add_argument("--config", default="configs/rl_offline_v1.yaml")
    p.add_argument("--output", default="models/rl_offline_v1")
    p = sub.add_parser("evaluate")
    p.add_argument("--policy", default="models/rl_offline_v1")
    p.add_argument("--dataset", default="artifacts/rl_dataset")
    p.add_argument("--simulator-config", default="configs/rl_eval.yaml")
    p = sub.add_parser("policies")
    p.add_argument("--registry", default="models/rl_policy_registry.json")
    args = parser.parse_args(argv)
    dispatch = {
        "build-dataset": cmd_build_dataset,
        "analyze-dataset": cmd_analyze_dataset,
        "train-bc": cmd_train_bc,
        "train-offline": cmd_train_offline,
        "evaluate": cmd_evaluate,
        "policies": cmd_policies,
    }
    return dispatch[args.rl_command](args)


if __name__ == "__main__":
    raise SystemExit(main())
