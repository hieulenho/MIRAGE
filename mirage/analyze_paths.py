"""CLI for Milestone 3 attack-path analysis."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from mirage.analysis.pipeline import AttackAnalysisPipeline
from mirage.config import load_config, resolve_project_path
from mirage.domain.schemas import BeliefSnapshot, CandidateActionSet, TwinSnapshot


def load_twin_snapshot(path: str | Path) -> TwinSnapshot:
    """Load a TwinSnapshot from JSON."""
    return TwinSnapshot.model_validate_json(Path(path).read_text(encoding="utf-8"))


def load_belief_snapshot(path: str | Path) -> BeliefSnapshot:
    """Load a BeliefSnapshot from JSON."""
    return BeliefSnapshot.model_validate_json(Path(path).read_text(encoding="utf-8"))


def save_json_model(model, path: str | Path) -> Path:
    """Save a Pydantic model deterministically."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(model.model_dump(mode="json"), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return output


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""
    parser = argparse.ArgumentParser(description="Analyze MIRAGE attack paths")
    parser.add_argument("--twin-snapshot", required=True)
    parser.add_argument("--belief-snapshot", required=True)
    parser.add_argument("--analysis-out", default="artifacts/attack_analysis.json")
    parser.add_argument("--actions-out", default="artifacts/candidate_actions.json")
    parser.add_argument("--seed-entity", action="append", default=[])
    parser.add_argument("--max-hops", type=int, default=None)
    parser.add_argument("--max-nodes", type=int, default=None)
    parser.add_argument("--max-paths", type=int, default=None)
    parser.add_argument("--criticality-threshold", type=float, default=None)
    parser.add_argument("--reference-time", default=None)
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run attack-path analysis CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        twin = load_twin_snapshot(resolve_project_path(args.twin_snapshot))
        belief = load_belief_snapshot(resolve_project_path(args.belief_snapshot))
        config = load_config()
        analysis_config = config.get("analysis", {})
        if args.criticality_threshold is not None:
            analysis_config = {
                **analysis_config,
                "subgraph": {
                    **analysis_config.get("subgraph", {}),
                    "criticality_threshold": args.criticality_threshold,
                },
            }
        pipeline = AttackAnalysisPipeline(config=analysis_config)
        reference_time = None
        if args.reference_time:
            from datetime import datetime

            reference_time = datetime.fromisoformat(
                args.reference_time.replace("Z", "+00:00")
            )
        result = pipeline.analyze(
            twin,
            belief,
            reference_time=reference_time,
            seed_entity_ids=args.seed_entity,
            max_hops=args.max_hops,
            max_nodes=args.max_nodes,
            max_paths=args.max_paths,
        )
        analysis_path = save_json_model(result, resolve_project_path(args.analysis_out))
        action_set = CandidateActionSet.model_validate(
            result.candidate_action_set.model_dump()
        )
        actions_path = save_json_model(action_set, resolve_project_path(args.actions_out))
    except (OSError, ValueError) as exc:
        print(f"Attack analysis failed: {exc}")
        return 2

    top_paths = result.path_analysis.paths[:5]
    masks = result.candidate_action_set.masks
    approval_required = [
        action_id for action_id, mask in masks.items() if mask.approval_required
    ]
    print("MIRAGE attack-path analysis complete")
    print(f"  selected seed entities:    {len(result.selected_seeds)}")
    print(f"  subgraph nodes/edges:      {len(result.subgraph.nodes)}/{len(result.subgraph.edges)}")
    print(f"  coverage/freshness:        {result.subgraph.coverage_score:.3f}/{result.subgraph.freshness_score:.3f}")
    print(f"  attack paths found:        {len(result.path_analysis.paths)}")
    print(f"  critical assets at risk:   {len(result.path_analysis.critical_assets_at_risk)}")
    print(f"  deception positions:       {len(result.deception_positions)}")
    print(f"  actions generated:         {len(result.candidate_action_set.actions)}")
    print(f"  allowed actions:           {len(result.candidate_action_set.allowed_action_ids)}")
    print(f"  blocked actions:           {len(result.candidate_action_set.blocked_action_ids)}")
    print(f"  approval-required actions: {len(approval_required)}")
    print(f"  recommended actions:       {', '.join(result.candidate_action_set.recommended_action_ids[:5])}")
    if top_paths:
        print("  top paths:")
        for path in top_paths:
            print(f"    {path.path_id}: risk={path.risk_score:.3f} type={path.path_type}")
    if args.verbose:
        for path in top_paths:
            print(f"  breakdown {path.path_id}: {path.score_breakdown}")
        for action in result.candidate_action_set.actions[:5]:
            mask = result.candidate_action_set.masks[action.action_id]
            print(
                f"  action {action.action_id}: {action.action_type} "
                f"rank={action.score_breakdown.get('rank_score')} "
                f"mask={mask.mask_reasons}"
            )
    print(f"  analysis saved:            {analysis_path}")
    print(f"  actions saved:             {actions_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
