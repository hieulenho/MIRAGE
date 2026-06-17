"""Temporal evidence correlation for contextual detection."""

from __future__ import annotations

from datetime import datetime

from mirage.detection.timeline import TimelineStore
from mirage.detection.utils import stable_id
from mirage.domain.schemas import CorrelationRecord, Evidence


STAGE_ORDER = [
    "execution",
    "discovery",
    "initial_access",
    "credential_access",
    "lateral_movement",
    "collection",
    "exfiltration",
]


class TemporalCorrelator:
    """Correlate local entity evidence into partial attack sequences."""

    def __init__(self, *, window_seconds: int = 3600) -> None:
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        self.window_seconds = int(window_seconds)

    def correlate(
        self,
        entity_id: str,
        timeline_store: TimelineStore,
        evidence: dict[str, Evidence],
        *,
        reference_time: datetime,
    ) -> list[CorrelationRecord]:
        """Return deterministic local correlations for one entity."""
        timeline = timeline_store.get_recent_events(
            entity_id,
            self.window_seconds,
            reference_time,
        )
        event_ids = {event.event_id for event in timeline}
        relevant = [
            item
            for item in evidence.values()
            if entity_id in item.entity_ids
            and event_ids.intersection(item.event_ids)
            and (item.expires_at is None or item.expires_at > reference_time)
        ]
        if len(relevant) < 2:
            return []
        ordered = sorted(relevant, key=lambda item: (item.first_seen, item.evidence_id))
        progression: list[str] = []
        related_event_ids: set[str] = set()
        related_entities: set[str] = {entity_id}
        for item in ordered:
            related_event_ids.update(item.event_ids)
            related_entities.update(item.entity_ids)
            for stage in item.stage_hints:
                if stage in STAGE_ORDER and stage not in progression:
                    progression.append(stage)
        if len(progression) < 2:
            return []
        order_positions = [STAGE_ORDER.index(stage) for stage in progression]
        monotonic_pairs = sum(
            1
            for left, right in zip(order_positions, order_positions[1:], strict=False)
            if right >= left
        )
        confidence = min(
            0.95,
            0.35
            + 0.15 * len(progression)
            + 0.1 * monotonic_pairs
            + 0.05 * min(4, len(ordered)),
        )
        correlation_id = stable_id(
            "corr",
            [entity_id, *sorted(related_event_ids), *progression],
        )
        return [
            CorrelationRecord(
                correlation_id=correlation_id,
                related_event_ids=sorted(related_event_ids),
                related_entity_ids=sorted(related_entities),
                ordered_timeline=[item.evidence_id for item in ordered],
                inferred_stage_progression=progression,
                confidence=confidence,
                explanation=(
                    "Local timeline shows partial stage progression: "
                    + " -> ".join(progression)
                ),
                first_seen=min(item.first_seen for item in ordered),
                last_seen=max(item.last_seen for item in ordered),
            )
        ]
