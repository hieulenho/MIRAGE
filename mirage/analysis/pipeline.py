"""Coordinating attack-analysis pipeline for Milestone 3."""

from __future__ import annotations

from datetime import datetime

from mirage.analysis.actions import (
    ActionConstraintEvaluator,
    ActionMaskBuilder,
    CandidateActionGenerator,
    CandidateActionRanker,
    DeceptionPositionAnalyzer,
    summarize_path_analysis,
)
from mirage.analysis.paths import AttackPathFinder, AttackPathRiskScorer
from mirage.analysis.seeds import SeedEntitySelector
from mirage.analysis.subgraph import LocalSubgraphExtractor
from mirage.analysis.utils import analysis_time, stable_id
from mirage.domain.schemas import (
    ActionConstraintResult,
    AttackAnalysisResult,
    BeliefSnapshot,
    CandidateActionSet,
    IncidentBelief,
    LocalSubgraphRequest,
    SeedEntity,
    TwinSnapshot,
)
from mirage.layer2_graph_engine.attack_graph import MIRAGEAttackGraph


class AttackAnalysisPipeline:
    """Run seed selection, local paths, risk scoring, and action masks."""

    def __init__(
        self,
        *,
        attack_graph=None,
        config: dict | None = None,
        seed_selector: SeedEntitySelector | None = None,
        subgraph_extractor: LocalSubgraphExtractor | None = None,
        path_finder: AttackPathFinder | None = None,
        risk_scorer: AttackPathRiskScorer | None = None,
        deception_analyzer: DeceptionPositionAnalyzer | None = None,
        action_generator: CandidateActionGenerator | None = None,
        constraint_evaluator: ActionConstraintEvaluator | None = None,
        mask_builder: ActionMaskBuilder | None = None,
        action_ranker: CandidateActionRanker | None = None,
    ) -> None:
        self.attack_graph = attack_graph
        self.config = config or {}
        self.seed_selector = seed_selector or SeedEntitySelector(
            self.config.get("seed_selection", {})
        )
        self.subgraph_extractor = subgraph_extractor or LocalSubgraphExtractor(
            self.config.get("subgraph", {})
        )
        self.path_finder = path_finder or AttackPathFinder(
            self.config.get("paths", {})
        )
        self.risk_scorer = risk_scorer or AttackPathRiskScorer(
            self.config.get("risk_scoring", {})
        )
        self.deception_analyzer = deception_analyzer or DeceptionPositionAnalyzer()
        self.action_generator = action_generator or CandidateActionGenerator(
            self.config.get("candidate_actions", {})
        )
        self.constraint_evaluator = constraint_evaluator or ActionConstraintEvaluator(
            self.config.get("constraints", {})
        )
        self.mask_builder = mask_builder or ActionMaskBuilder()
        self.action_ranker = action_ranker or CandidateActionRanker(
            self.config.get("ranking", {})
        )

    def analyze(
        self,
        twin_snapshot: TwinSnapshot,
        belief_snapshot: BeliefSnapshot,
        incident_beliefs: list[IncidentBelief] | None = None,
        reference_time: datetime | None = None,
        seed_entity_ids: list[str] | None = None,
        max_hops: int | None = None,
        max_nodes: int | None = None,
        max_paths: int | None = None,
    ) -> AttackAnalysisResult:
        """Run a deterministic attack analysis from snapshots."""
        reference = analysis_time(reference_time, belief_snapshot.timestamp)
        graph = self.attack_graph or MIRAGEAttackGraph.from_twin_snapshot(twin_snapshot)
        configured_seed_limit = int(
            self.config.get("seed_selection", {}).get("maximum_seeds", 20)
        )
        node_limit = max_nodes if max_nodes is not None else int(
            self.config.get("subgraph", {}).get("max_nodes", 80)
        )
        seed_limit = max(1, min(configured_seed_limit, int(node_limit)))
        selected = self.seed_selector.select(
            belief_snapshot,
            incident_beliefs=incident_beliefs,
            reference_time=reference,
            limit=seed_limit,
        )
        if seed_entity_ids:
            selected = self._force_seed_entities(
                selected,
                seed_entity_ids,
                belief_snapshot,
                reference,
            )
        request = LocalSubgraphRequest(
            seed_entity_ids=[seed.entity_id for seed in selected],
            max_hops=max_hops
            if max_hops is not None
            else int(self.config.get("subgraph", {}).get("default_max_hops", 3)),
            max_nodes=max_nodes
            if max_nodes is not None
            else int(self.config.get("subgraph", {}).get("max_nodes", 80)),
            max_edges=int(self.config.get("subgraph", {}).get("max_edges", 160)),
            reference_time=reference,
            relationship_types=(
                self.config.get("subgraph", {}).get("relationship_allowlist") or None
            ),
            minimum_edge_confidence=float(
                self.config.get("subgraph", {}).get("minimum_edge_confidence", 0.10)
            ),
            include_decoys=True,
            include_credentials=True,
            include_identities=True,
            include_subnets=False,
            include_critical_assets=True,
            criticality_threshold=float(
                self.config.get("subgraph", {}).get("criticality_threshold", 0.80)
            ),
            freshness_threshold=self.config.get("subgraph", {}).get(
                "freshness_threshold"
            ),
        )
        subgraph = self.subgraph_extractor.extract(
            graph,
            twin_snapshot,
            belief_snapshot,
            request,
            seed_entities=selected,
        )
        paths = self.path_finder.find_paths(subgraph, belief_snapshot, reference)
        if max_paths is not None:
            paths = paths[:max_paths]
        scored_paths = [
            self.risk_scorer.score(path, subgraph, belief_snapshot, reference)
            for path in paths
        ]
        scored_paths.sort(key=lambda path: (-path.risk_score, path.path_id))
        analysis_id = stable_id(
            "analysis",
            [
                twin_snapshot.twin_version,
                belief_snapshot.belief_version,
                subgraph.subgraph_id,
                *[path.path_id for path in scored_paths],
            ],
        )
        preliminary = summarize_path_analysis(
            analysis_id,
            subgraph.subgraph_id,
            reference,
            scored_paths,
            [],
        )
        deception_positions = self.deception_analyzer.analyze(subgraph, preliminary)
        path_analysis = summarize_path_analysis(
            analysis_id,
            subgraph.subgraph_id,
            reference,
            scored_paths,
            deception_positions,
        )
        actions = self.action_generator.generate(
            subgraph,
            path_analysis,
            belief_snapshot,
            twin_snapshot,
            reference,
            deception_positions=deception_positions,
        )
        constraint_results: dict[str, ActionConstraintResult] = {}
        masks = {}
        for action in actions:
            constraint = self.constraint_evaluator.evaluate(action, subgraph, reference)
            mask = self.mask_builder.build(action, constraint)
            constraint_results[action.action_id] = constraint
            masks[action.action_id] = mask
        ranked = self.action_ranker.rank(actions, masks)
        allowed = [
            action.action_id
            for action in ranked
            if masks[action.action_id].allowed
        ]
        blocked = [
            action.action_id
            for action in ranked
            if not masks[action.action_id].allowed
        ]
        recommended = [
            action.action_id
            for action in ranked
            if masks[action.action_id].allowed
        ][:10]
        action_set = CandidateActionSet(
            action_set_id=stable_id(
                "action-set",
                [analysis_id, *[action.action_id for action in ranked]],
            ),
            analysis_id=analysis_id,
            subgraph_id=subgraph.subgraph_id,
            reference_time=reference,
            actions=ranked,
            masks=masks,
            allowed_action_ids=allowed,
            blocked_action_ids=blocked,
            recommended_action_ids=recommended,
            warnings=[],
        )
        warnings = sorted(set(subgraph.warnings + path_analysis.warnings))
        return AttackAnalysisResult(
            analysis_id=analysis_id,
            reference_time=reference,
            twin_version=str(twin_snapshot.twin_version),
            graph_version=str(getattr(graph, "name", "mirage_attack_graph")),
            belief_version=belief_snapshot.belief_version,
            selected_seeds=selected,
            subgraph=subgraph,
            path_analysis=path_analysis,
            deception_positions=deception_positions,
            candidate_action_set=action_set,
            constraint_results=constraint_results,
            timing_ms={
                "seed_selection": 0.0,
                "subgraph_extraction": 0.0,
                "path_analysis": 0.0,
                "action_generation": 0.0,
            },
            warnings=warnings,
        )

    def _force_seed_entities(
        self,
        selected: list[SeedEntity],
        seed_entity_ids: list[str],
        belief_snapshot: BeliefSnapshot,
        reference: datetime,
    ) -> list[SeedEntity]:
        existing = {seed.entity_id: seed for seed in selected}
        for entity_id in seed_entity_ids:
            if entity_id in existing:
                continue
            belief = belief_snapshot.entity_beliefs.get(entity_id)
            if belief is None:
                continue
            existing[entity_id] = SeedEntity(
                entity_id=entity_id,
                entity_type=belief.entity_type,
                seed_reason="explicit CLI/API seed",
                compromise_probability=belief.compromise_probability,
                attacker_location_probability=(
                    belief.candidate_attacker_location_probability
                ),
                belief_confidence=belief.confidence,
                belief_uncertainty=belief.uncertainty,
                most_likely_stage=belief.most_likely_stage,
                supporting_evidence_ids=belief.evidence_ids,
                priority_score=1.0,
                selected_at=reference,
            )
        return sorted(
            existing.values(),
            key=lambda seed: (-seed.priority_score, seed.entity_id),
        )
