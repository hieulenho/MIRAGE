"""In-memory deterministic entity timeline store."""

from __future__ import annotations

from datetime import datetime, timedelta

from mirage.detection.utils import event_entity_ids
from mirage.domain.schemas import (
    SecurityEvent,
    TimelineEvent,
    TimelineSnapshot,
    TimelineUpdateResult,
    utc_now,
)


class TimelineStore:
    """Group canonical events by relevant asset, identity, and session entity."""

    def __init__(self, *, retention_seconds: int = 86400) -> None:
        if retention_seconds < 1:
            raise ValueError("retention_seconds must be at least 1")
        self.retention_seconds = int(retention_seconds)
        self._events: dict[str, TimelineEvent] = {}
        self._timeline_index: dict[str, list[str]] = {}

    def add_event(self, event: SecurityEvent) -> TimelineUpdateResult:
        """Add an event to all relevant timelines without duplication."""
        entity_ids = event_entity_ids(event)
        if event.event_id in self._events:
            return TimelineUpdateResult(
                event_id=event.event_id,
                duplicate=True,
                entity_ids=entity_ids,
                timelines_updated=0,
            )

        timeline_event = TimelineEvent(
            event_id=event.event_id,
            event_time=event.event_time,
            entity_ids=entity_ids,
            event_type=event.event_type,
            source=event.source,
            technique_ids=list(event.technique_ids),
            confidence=event.confidence,
            feature_values={
                key: value
                for key, value in {
                    "dst_port": event.dst_port,
                    "protocol": event.attributes.get("protocol"),
                    "src_ip": event.src_ip,
                    "dst_ip": event.dst_ip,
                }.items()
                if value is not None
            },
            raw_event_ref=event.raw_event_ref,
        )
        self._events[event.event_id] = timeline_event
        for entity_id in entity_ids:
            bucket = self._timeline_index.setdefault(entity_id, [])
            bucket.append(event.event_id)
            bucket.sort(key=lambda event_id: self._event_sort_key(event_id))
        expired = self.remove_expired_events(event.event_time)
        return TimelineUpdateResult(
            event_id=event.event_id,
            duplicate=False,
            entity_ids=entity_ids,
            timelines_updated=len(entity_ids),
            expired_events=expired,
        )

    def get_timeline(
        self,
        entity_id: str,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int | None = None,
    ) -> list[TimelineEvent]:
        """Return timeline events for one entity in deterministic order."""
        event_ids = self._timeline_index.get(entity_id, [])
        events = [self._events[event_id] for event_id in event_ids if event_id in self._events]
        if start_time is not None:
            events = [event for event in events if event.event_time >= start_time]
        if end_time is not None:
            events = [event for event in events if event.event_time <= end_time]
        events.sort(key=lambda event: (event.event_time, event.event_id))
        if limit is not None:
            if limit < 0:
                raise ValueError("limit must be non-negative")
            events = events[-limit:]
        return events

    def get_recent_events(
        self,
        entity_id: str,
        window_seconds: int,
        reference_time: datetime,
    ) -> list[TimelineEvent]:
        """Return events inside a lookback window for one entity."""
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        start_time = reference_time - timedelta(seconds=window_seconds)
        return self.get_timeline(
            entity_id,
            start_time=start_time,
            end_time=reference_time,
        )

    def set_event_features(self, event_id: str, feature_values: dict[str, object]) -> None:
        """Attach non-sensitive computed feature values to a stored event."""
        if event_id not in self._events:
            raise KeyError(event_id)
        allowed = (bool, int, float, str)
        sanitized = {
            key: value
            for key, value in feature_values.items()
            if isinstance(value, allowed)
        }
        event = self._events[event_id]
        self._events[event_id] = event.model_copy(
            update={"feature_values": {**event.feature_values, **sanitized}}
        )

    def remove_expired_events(self, reference_time: datetime) -> int:
        """Remove events outside retention from all timeline indexes."""
        cutoff = reference_time - timedelta(seconds=self.retention_seconds)
        expired_ids = [
            event_id
            for event_id, event in self._events.items()
            if event.event_time < cutoff
        ]
        if not expired_ids:
            return 0
        expired = set(expired_ids)
        for event_id in expired:
            self._events.pop(event_id, None)
        for entity_id, event_ids in list(self._timeline_index.items()):
            retained = [event_id for event_id in event_ids if event_id not in expired]
            if retained:
                self._timeline_index[entity_id] = retained
            else:
                self._timeline_index.pop(entity_id, None)
        return len(expired)

    def create_snapshot(self) -> TimelineSnapshot:
        """Create a deterministic snapshot of timeline storage."""
        timestamp = max(
            (event.event_time for event in self._events.values()),
            default=utc_now(),
        )
        return TimelineSnapshot(
            timestamp=timestamp,
            retention_seconds=self.retention_seconds,
            events={key: self._events[key] for key in sorted(self._events)},
            timeline_index={
                key: list(self._timeline_index[key])
                for key in sorted(self._timeline_index)
            },
        )

    def load_snapshot(self, snapshot: TimelineSnapshot) -> None:
        """Restore timeline state from a snapshot."""
        self.retention_seconds = snapshot.retention_seconds
        self._events = dict(snapshot.events)
        self._timeline_index = {
            entity_id: list(event_ids)
            for entity_id, event_ids in snapshot.timeline_index.items()
        }

    def event_count(self) -> int:
        """Return total retained event count."""
        return len(self._events)

    def all_entity_ids(self) -> list[str]:
        """Return entity IDs with retained timelines."""
        return sorted(self._timeline_index)

    def _event_sort_key(self, event_id: str) -> tuple[datetime, str]:
        event = self._events[event_id]
        return event.event_time, event.event_id
