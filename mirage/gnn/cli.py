"""CLI entrypoint for MIRAGE GNN commands.

Commands
--------
  python -m mirage gnn build-dataset --snapshots <path> --output <path>
  python -m mirage gnn train          --dataset <path> --config <path> [--output <path>]
  python -m mirage gnn evaluate       --dataset <path> --model <path>
  python -m mirage gnn encode         --sample <path>  [--model <path>]
  python -m mirage gnn models         [--registry <path>]

All commands print JSON output to stdout.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _print_json(data: object) -> None:
    print(json.dumps(data, indent=2, default=str))


def _load_config_file(path: str) -> dict[str, Any]:
    """Load YAML config with PyYAML when available, else parse simple key/value."""
    config_path = Path(path)
    if not config_path.exists():
        return {}
    try:
        import yaml

        with open(config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except ImportError:
        parsed: dict[str, Any] = {}
        for raw_line in config_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.split("#", 1)[0].strip()
            if not line or ":" not in line:
                continue
            key, raw_value = line.split(":", 1)
            value = raw_value.strip().strip("\"'")
            if value.lower() in {"true", "false"}:
                parsed[key.strip()] = value.lower() == "true"
                continue
            try:
                parsed[key.strip()] = int(value)
                continue
            except ValueError:
                pass
            try:
                parsed[key.strip()] = float(value)
                continue
            except ValueError:
                pass
            parsed[key.strip()] = value
        return parsed


def cmd_build_dataset(args: argparse.Namespace) -> int:
    """Build a GNN dataset from scenario snapshots."""
    from mirage.gnn.dataset import GraphDatasetBuilder
    from mirage.gnn.scenarios import SCENARIO_IDS, build_scenario
    from mirage.gnn.schema import GraphFeatureSchema

    schema = GraphFeatureSchema()
    builder = GraphDatasetBuilder(schema=schema)

    snapshot_sequence = []
    if args.snapshots and args.snapshots != "scenarios":
        snapshots_path = Path(args.snapshots)
        if snapshots_path.exists() and snapshots_path.is_dir():
            for sample_file in sorted(snapshots_path.glob("*.json")):
                print(f"  [SKIP] custom snapshot loading not yet implemented: {sample_file.name}",
                      file=sys.stderr)
        else:
            print(f"  [WARN] Snapshots path not found: {args.snapshots}", file=sys.stderr)
    else:
        print("  Using built-in synthetic scenarios...", file=sys.stderr)
        for scenario_id in SCENARIO_IDS:
            entry = build_scenario(scenario_id)
            snapshot_sequence.append(entry)

    output = getattr(args, "output", "artifacts/gnn_dataset")
    summary = builder.build_dataset(snapshot_sequence, output_path=output)
    _print_json(json.loads(summary.model_dump_json()))
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    """Train a GNN on a built dataset."""
    try:
        import torch  # noqa: F401
    except ImportError:
        print("ERROR: PyTorch not installed. Run: pip install -r requirements-gnn.txt",
              file=sys.stderr)
        return 1

    from mirage.gnn.dataset import GraphDatasetBuilder
    from mirage.gnn.schema import GraphFeatureSchema, SplitType
    from mirage.gnn.training import GNNTrainer

    dataset_path = getattr(args, "dataset", "artifacts/gnn_dataset")
    config_path = getattr(args, "config", "configs/gnn_v1.yaml")
    output = getattr(args, "output", "models/gnn_v1")
    model_id = getattr(args, "model_id", None)

    if not Path(dataset_path).exists():
        print(f"ERROR: Dataset not found at {dataset_path}", file=sys.stderr)
        return 1

    if Path(config_path).exists():
        config = _load_config_file(config_path)
    else:
        config = {}
        print(f"  [WARN] Config not found at {config_path}; using defaults.", file=sys.stderr)

    samples, _ = GraphDatasetBuilder.load_dataset(dataset_path)
    train_samples = [s for s in samples if s.split == SplitType.TRAIN]
    val_samples = [s for s in samples if s.split == SplitType.VALIDATION]
    if not train_samples:
        print("ERROR: No training samples found.", file=sys.stderr)
        return 1
    if not val_samples:
        val_samples = train_samples[:max(1, len(train_samples) // 5)]

    schema = GraphFeatureSchema()
    trainer = GNNTrainer(config=config, schema=schema, output_dir=output)
    metadata = trainer.train(train_samples, val_samples, model_id=model_id)
    _print_json(json.loads(metadata.model_dump_json()))
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    """Evaluate a trained model against a dataset."""
    from mirage.gnn.baselines import HeuristicBaseline, LogisticBaseline, MLPBaseline
    from mirage.gnn.dataset import GraphDatasetBuilder
    from mirage.gnn.evaluation import GNNEvaluator
    from mirage.gnn.schema import GraphFeatureSchema, SplitType

    dataset_path = getattr(args, "dataset", "artifacts/gnn_dataset")
    model_path = getattr(args, "model", None)

    if not Path(dataset_path).exists():
        print(f"ERROR: Dataset not found at {dataset_path}", file=sys.stderr)
        return 1

    samples, _ = GraphDatasetBuilder.load_dataset(dataset_path)
    test_samples = [s for s in samples if s.split == SplitType.TEST]
    if not test_samples:
        test_samples = samples  # fall back to all samples

    schema = GraphFeatureSchema()
    evaluator = GNNEvaluator()
    results: dict = {}

    # Baselines (always available)
    for baseline_cls in [HeuristicBaseline, LogisticBaseline, MLPBaseline]:
        b = baseline_cls(schema=schema)
        train_s = [s for s in samples if s.split == SplitType.TRAIN]
        b.fit(train_s)
        results[b.name] = evaluator.full_evaluation(test_samples, b.predict, b.name)

    # GNN model if provided
    if model_path and Path(model_path).exists():
        try:
            from mirage.gnn.inference import GNNInferenceService

            service = GNNInferenceService(schema=schema)
            service.load_model(model_path)

            def gnn_predict(sample):
                result = service.encode_subgraph(sample)
                return {
                    "node_risk_probabilities": result.gnn_output.node_risk_probabilities,
                    "edge_movement_probabilities": result.gnn_output.edge_movement_probabilities,
                    "graph_risk_probability": result.gnn_output.graph_risk_probability,
                }

            results["gnn_v1"] = evaluator.full_evaluation(
                test_samples, gnn_predict, "gnn_v1"
            )
        except Exception as exc:
            print(f"  [WARN] GNN evaluation failed: {exc}", file=sys.stderr)

    _print_json(results)
    return 0


def cmd_encode(args: argparse.Namespace) -> int:
    """Encode a single sample with the GNN."""
    from mirage.gnn.dataset import GraphDatasetBuilder
    from mirage.gnn.inference import GNNInferenceService
    from mirage.gnn.schema import GraphFeatureSchema

    sample_path = getattr(args, "sample", None)
    model_path = getattr(args, "model", None)

    if not sample_path or not Path(sample_path).exists():
        print(f"ERROR: Sample not found at {sample_path}", file=sys.stderr)
        return 1

    sample = GraphDatasetBuilder.load_sample(sample_path)
    schema = GraphFeatureSchema()
    service = GNNInferenceService(schema=schema)
    if model_path and Path(model_path).exists():
        try:
            service.load_model(model_path)
        except Exception as exc:
            print(f"  [WARN] Could not load model: {exc}", file=sys.stderr)

    result = service.encode_subgraph(sample)
    _print_json(json.loads(result.model_dump_json()))
    return 0


def cmd_models(args: argparse.Namespace) -> int:
    """List all models in the registry."""
    from mirage.gnn.registry import ModelRegistry

    registry_path = getattr(args, "registry", "models/gnn_registry.json")
    reg = ModelRegistry(registry_path=registry_path)
    models = reg.list_models()
    output = {
        "summary": reg.summary(),
        "models": [json.loads(m.model_dump_json()) for m in models],
    }
    _print_json(output)
    return 0


def main(args: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="mirage gnn",
        description="MIRAGE GNN commands (Milestone 6)",
    )
    sub = parser.add_subparsers(dest="gnn_command", required=True)

    # build-dataset
    p_ds = sub.add_parser("build-dataset", help="Build GNN dataset from snapshots")
    p_ds.add_argument("--snapshots", default="scenarios",
                       help="Path to snapshot dir or 'scenarios' for built-in")
    p_ds.add_argument("--output", default="artifacts/gnn_dataset",
                       help="Output directory for dataset")

    # train
    p_tr = sub.add_parser("train", help="Train GNN on dataset")
    p_tr.add_argument("--dataset", default="artifacts/gnn_dataset")
    p_tr.add_argument("--config", default="configs/gnn_v1.yaml")
    p_tr.add_argument("--output", default="models/gnn_v1")
    p_tr.add_argument("--model-id", dest="model_id", default=None)

    # evaluate
    p_ev = sub.add_parser("evaluate", help="Evaluate model on dataset")
    p_ev.add_argument("--dataset", default="artifacts/gnn_dataset")
    p_ev.add_argument("--model", default=None)

    # encode
    p_en = sub.add_parser("encode", help="Encode a single sample")
    p_en.add_argument("--sample", required=True, help="Path to sample JSON")
    p_en.add_argument("--model", default=None)

    # models
    p_mo = sub.add_parser("models", help="List registry models")
    p_mo.add_argument("--registry", default="models/gnn_registry.json")

    parsed = parser.parse_args(args)
    dispatch = {
        "build-dataset": cmd_build_dataset,
        "train": cmd_train,
        "evaluate": cmd_evaluate,
        "encode": cmd_encode,
        "models": cmd_models,
    }
    fn = dispatch.get(parsed.gnn_command)
    if fn is None:
        parser.print_help()
        return 2
    return fn(parsed)
