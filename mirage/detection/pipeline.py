"""Contextual detection pipeline orchestration."""

from __future__ import annotations

from datetime import timedelta
from typing import Iterable

from mirage.detection.belief import BeliefEngine
from mirage.detection.correlation import TemporalCorrelator
from mirage.detection.features import FeatureExtractor
from mirage.detection.rules import DetectionContext, RuleEngine
from mirage.detection.stage_estimator import AttackStageEstimator
from mirage.detection.timeline import TimelineStore
from mirage.detection.utils import stable_id
from mirage.domain.schemas import (
    DetectionPipelineResult,
    DetectionPipelineSummary,
    EntityBelief,
    Evidence,
    RuleMatch,
    SecurityEvent,
)
from mirage.layer2_graph_engine.attack_graph import MIRAGEAttackGraph
from mirage.layer6_twin.digital_twin import DigitalTwin


class ContextualDetectionPipeline:
    """Coordinate timeline, rule, correlation, stage, and belief updates."""

    def __init__(
        self,
        *,
        twin: DigitalTwin | None = None,
        attack_graph: MIRAGEAttackGraph | None = None,
        timeline_store: TimelineStore | None = None,
        feature_extractor: FeatureExtractor | None = None,
        rule_engine: RuleEngine | None = None,
        correlator: TemporalCorrelator | None = None,
        belief_engine: BeliefEngine | None = None,
        config: dict | None = None,
    ) -> None:
        self.config = config or {}
        self.twin = twin
        self.attack_graph = attack_graph
        self.timeline_store = timeline_store or TimelineStore(
            retention_seconds=int(
                self.config.get("timeline_retention_seconds", 86400)
            )
        )
        self.feature_extractor = feature_extractor or FeatureExtractor(
            windows=self.config.get("windows", (60, 300, 900, 3600)),
            maintenance_windows=self.config.get("maintenance_windows", []),
        )
        self.rule_engine = rule_engine or RuleEngine(self.config)
        self.correlator = correlator or TemporalCorrelator(
            window_seconds=int(self.config.get("correlation_window_seconds", 3600))
        )
        stage_estimator = AttackStageEstimator(
            stage_priors=self.config.get("stage_priors"),
            evidence_decay_seconds=int(
                self.config.get("evidence_decay_seconds", 3600)
            ),
            transition_weight=float(
                self.config.get("stage_transition_weight", 0.15)
            ),
        )
        self.belief_engine = belief_engine or BeliefEngine(
            twin=twin,
            stage_estimator=stage_estimator,
            compromise_threshold=float(
                self.config.get("compromise_threshold", 0.35)
            ),
            high_confidence_deception_threshold=float(
                self.config.get("high_confidence_deception_threshold", 0.85)
            ),
            propagation_depth=int(self.config.get("graph_propagation_depth", 1)),
            propagation_decay=float(self.config.get("graph_propagation_decay", 0.45)),
        )

    def process_event(self, event: SecurityEvent) -> DetectionPipelineResult:
        """Process one validated canonical event deterministically."""
        twin_update = {}
        warnings: list[str] = []
        if self.twin is not None:
            twin_result = self.twin.apply_event(event)
            twin_update = twin_result.model_dump(mode="json")
            warnings.extend(twin_result.warnings)

        timeline_result = self.timeline_store.add_event(event)
        warnings.extend(timeline_result.warnings)
        if timeline_result.duplicate:
            return DetectionPipelineResult(
                event_id=event.event_id,
                duplicate=True,
                entity_ids=timeline_result.entity_ids,
                timeline_updated=False,
                twin_update=twin_update,
                warnings=warnings,
                belief_version=self.belief_engine.version,
            )

        old_beliefs = {
            entity_id: self.belief_engine.get_entity_belief(entity_id)
            for entity_id in timeline_result.entity_ids
        }
        features = self.feature_extractor.extract(
            event,
            self.timeline_store,
            twin=self.twin,
        )
        feature_values = {
            name: record.value for name, record in features.items()
        }
        self.timeline_store.set_event_features(event.event_id, feature_values)

        recent_evidence_count = sum(
            1
            for item in self.belief_engine.evidence.values()
            if set(timeline_result.entity_ids).intersection(item.entity_ids)
            and (item.expires_at is None or item.expires_at > event.event_time)
        )
        context = DetectionContext(
            entity_ids=timeline_result.entity_ids,
            features=features,
            recent_evidence_count=recent_evidence_count,
            approved_admin_hosts=tuple(
                self.config.get("approved_admin_hosts", ())
            ),
            approved_service_accounts=tuple(
                self.config.get("approved_service_accounts", ())
            ),
        )
        matches = self.rule_engine.evaluate_event(event, context)
        evidence = [self._evidence_from_match(event, match) for match in matches]
        self.belief_engine.record_evidence(evidence)

        correlations = []
        for entity_id in timeline_result.entity_ids:
            correlations.extend(
                self.correlator.correlate(
                    entity_id,
                    self.timeline_store,
                    self.belief_engine.evidence,
                    reference_time=event.event_time,
                )
            )
        unique_correlations = {
            correlation.correlation_id: correlation
            for correlation in correlations
        }
        correlation_evidence = [
            self._evidence_from_correlation(event, correlation)
            for correlation in unique_correlations.values()
        ]
        self.belief_engine.record_evidence(
            correlation_evidence,
            unique_correlations.values(),
        )

        updated_beliefs = self.belief_engine.update_entities_with_propagation(
            timeline_result.entity_ids,
            event.event_time,
        )
        graph_risk_updated = self._apply_graph_risk()

        all_evidence_ids = [item.evidence_id for item in evidence + correlation_evidence]
        result_beliefs = {
            key: updated_beliefs[key]
            for key in sorted(updated_beliefs)
        }
        return DetectionPipelineResult(
            event_id=event.event_id,
            duplicate=False,
            entity_ids=timeline_result.entity_ids,
            timeline_updated=True,
            twin_update=twin_update,
            feature_values=feature_values,
            matched_rule_ids=[match.rule_id for match in matches],
            evidence_ids=sorted(all_evidence_ids),
            correlation_ids=sorted(unique_correlations),
            updated_beliefs=result_beliefs,
            old_compromise_probabilities={
                entity_id: old.compromise_probability
                for entity_id, old in old_beliefs.items()
                if old is not None
            },
            new_compromise_probabilities={
                entity_id: belief.compromise_probability
                for entity_id, belief in result_beliefs.items()
            },
            old_most_likely_stages={
                entity_id: old.most_likely_stage
                for entity_id, old in old_beliefs.items()
                if old is not None
            },
            new_most_likely_stages={
                entity_id: belief.most_likely_stage
                for entity_id, belief in result_beliefs.items()
            },
            uncertainty_by_entity={
                entity_id: belief.uncertainty
                for entity_id, belief in result_beliefs.items()
            },
            graph_risk_updated=graph_risk_updated,
            warnings=warnings,
            belief_version=self.belief_engine.version,
        )

    def process_events(
        self,
        events: Iterable[SecurityEvent],
    ) -> DetectionPipelineSummary:
        """Process a stream of events and return aggregate metrics."""
        summary = DetectionPipelineSummary()
        for event in events:
            result = self.process_event(event)
            summary.processed += 1
            summary.duplicates += int(result.duplicate)
            summary.rule_matches += len(result.matched_rule_ids)
            summary.correlations_created += len(result.correlation_ids)
            summary.deception_interactions += int(
                "R008_DECEPTION_INTERACTION" in result.matched_rule_ids
            )
            summary.warnings.extend(result.warnings)
        suspicious = self.belief_engine.get_top_suspected_entities(limit=1000)
        suspicious = [
            belief
            for belief in suspicious
            if belief.compromise_probability
            >= self.belief_engine.compromise_threshold
        ]
        top = self.belief_engine.get_top_suspected_entities(limit=1)
        summary.suspicious_entities = len(suspicious)
        summary.highest_compromise_probability = (
            top[0].compromise_probability if top else 0.0
        )
        summary.most_likely_attack_stage = (
            top[0].most_likely_stage if top else summary.most_likely_attack_stage
        )
        summary.final_belief_version = self.belief_engine.version
        summary.warnings = sorted(set(summary.warnings))
        return summary

    def recompute_entity(
        self,
        entity_id: str,
        reference_time,
    ) -> EntityBelief:
        """Recompute belief for one entity from retained evidence."""
        belief = self.belief_engine.update_entity(entity_id, reference_time)
        self._apply_graph_risk()
        return belief

    def get_entity_timeline(self, entity_id: str, limit: int = 100):
        """Return a bounded sanitized entity timeline."""
        return self.timeline_store.get_timeline(entity_id, limit=limit)

    def get_entity_evidence(self, entity_id: str) -> list[Evidence]:
        """Return current evidence touching one entity."""
        return sorted(
            [
                item
                for item in self.belief_engine.evidence.values()
                if entity_id in item.entity_ids
            ],
            key=lambda item: (item.first_seen, item.evidence_id),
        )

    def list_incidents(self, limit: int = 10):
        """Return incident beliefs seeded from suspicious entities."""
        suspicious = [
            belief
            for belief in self.belief_engine.get_top_suspected_entities(limit=limit)
            if belief.compromise_probability
            >= self.belief_engine.compromise_threshold
        ]
        if not suspicious:
            return []
        incident = self.belief_engine.create_incident_belief(
            [belief.entity_id for belief in suspicious]
        )
        return [incident]

    def _evidence_from_match(
        self,
        event: SecurityEvent,
        match: RuleMatch,
    ) -> Evidence:
        ttl = match.expires_at
        if ttl is None:
            ttl_seconds = int(self.config.get("evidence_ttl_seconds", 3600))
            ttl = event.event_time + timedelta(seconds=ttl_seconds)
        return Evidence(
            evidence_id=stable_id(
                "evidence",
                [match.rule_id, event.event_id, *match.entity_ids],
            ),
            event_ids=match.event_ids,
            entity_ids=match.entity_ids,
            rule_id=match.rule_id,
            description=match.description,
            stage_hints=match.stage_hints,
            score=match.score,
            confidence=match.confidence,
            first_seen=event.event_time,
            last_seen=event.event_time,
            expires_at=ttl,
            attributes={
                "severity": match.severity,
                "feature_names": match.feature_names,
                "suppression": match.suppresses,
                "technique_ids": match.technique_ids,
                "decay_seconds": int(
                    self.config.get("evidence_decay_seconds", 3600)
                ),
                "direct": True,
            },
        )

    def _evidence_from_correlation(
        self,
        event: SecurityEvent,
        correlation,
    ) -> Evidence:
        ttl_seconds = int(self.config.get("evidence_ttl_seconds", 3600))
        return Evidence(
            evidence_id=stable_id(
                "evidence:correlation",
                [correlation.correlation_id],
            ),
            event_ids=correlation.related_event_ids,
            entity_ids=correlation.related_entity_ids,
            rule_id="TEMPORAL_CORRELATION",
            description=correlation.explanation,
            stage_hints=correlation.inferred_stage_progression,
            score=min(0.45, correlation.confidence * 0.5),
            confidence=correlation.confidence,
            first_seen=correlation.first_seen,
            last_seen=correlation.last_seen,
            expires_at=event.event_time + timedelta(seconds=ttl_seconds),
            attributes={
                "correlation_id": correlation.correlation_id,
                "decay_seconds": int(
                    self.config.get("evidence_decay_seconds", 3600)
                ),
                "direct": False,
                "inferred": False,
            },
        )

    def _apply_graph_risk(self) -> bool:
        if self.attack_graph is None:
            return False
        apply = getattr(self.attack_graph, "apply_belief_snapshot", None)
        if apply is None:
            return False
        apply(self.belief_engine.create_snapshot())
        return True
