"""Realtime Digital Twin update service."""

from __future__ import annotations

from typing import Iterable

from mirage.casm.service import CASMService
from mirage.detection.pipeline import ContextualDetectionPipeline
from mirage.domain.schemas import (
    DiscoveryObservation,
    SecurityEvent,
    TwinBatchUpdateSummary,
    TwinSnapshot,
    TwinUpdateResult,
    TwinQualityReport,
)
from mirage.layer6_twin.digital_twin import DigitalTwin


class RealtimeTwinService:
    """Incrementally update Twin, CASM, timelines, detections, and beliefs."""

    def __init__(
        self,
        *,
        twin: DigitalTwin | None = None,
        detection_pipeline: ContextualDetectionPipeline | None = None,
        casm_service: CASMService | None = None,
    ) -> None:
        self.twin = twin or DigitalTwin()
        self.detection_pipeline = detection_pipeline or ContextualDetectionPipeline(
            twin=self.twin
        )
        self.casm_service = casm_service or CASMService(self.twin)
        self.last_checkpoint: str | None = None

    def process_event(self, event: SecurityEvent) -> TwinUpdateResult:
        """Process one canonical event through the existing realtime pipeline."""
        result = self.detection_pipeline.process_event(event)
        update = result.twin_update
        return TwinUpdateResult.model_validate(update)

    def process_observation(
        self,
        observation: DiscoveryObservation,
    ) -> TwinUpdateResult:
        """Process one CASM observation and return a Twin-style update result."""
        before = self.twin.version
        result = self.casm_service.apply_observation(observation)
        after = self.twin.version
        return TwinUpdateResult(
            event_id=observation.observation_id,
            event_type="casm_observation",
            assets_created=(
                [result.canonical_entity_id]
                if result.created and result.canonical_entity_id
                else []
            ),
            assets_updated=(
                [result.canonical_entity_id]
                if result.updated and result.canonical_entity_id
                else []
            ),
            warnings=result.warnings
            + [conflict.conflict_id for conflict in result.conflicts],
            twin_version=after if after != before else self.twin.version,
        )

    def process_batch(
        self,
        items: Iterable[SecurityEvent | DiscoveryObservation],
    ) -> TwinBatchUpdateSummary:
        """Process mixed canonical events and CASM observations."""
        summary = TwinBatchUpdateSummary(final_twin_version=self.twin.version)
        for item in items:
            try:
                if isinstance(item, SecurityEvent):
                    result = self.process_event(item)
                    summary.processed_events += 1
                    summary.duplicates += int(result.duplicate)
                    summary.warnings.extend(result.warnings)
                else:
                    result = self.process_observation(item)
                    summary.processed_observations += 1
                    summary.warnings.extend(result.warnings)
            except (TypeError, ValueError) as exc:
                summary.failed_items += 1
                summary.warnings.append(str(exc))
            summary.final_twin_version = self.twin.version
        summary.warnings = sorted(set(summary.warnings))
        return summary

    def create_consistent_snapshot(self) -> TwinSnapshot:
        """Return a point-in-time Twin snapshot."""
        return self.twin.create_snapshot()

    def quality_report(self) -> TwinQualityReport:
        """Return current Twin quality metrics."""
        return self.casm_service.quality_report()
