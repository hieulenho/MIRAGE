"""Connector manager and streaming ingestion coordinator."""

from __future__ import annotations

from datetime import timedelta
from typing import Callable

from pydantic import ValidationError

from mirage.connectors.base import SecurityConnector
from mirage.domain.schemas import (
    ConnectorCheckpoint,
    ConnectorHealth,
    ConnectorPollSummary,
    RawConnectorRecord,
    SecurityEvent,
    utc_now,
)
from mirage.streaming.state import (
    CheckpointStore,
    DeadLetterStore,
    DeduplicationStore,
    JSONStateStore,
)


class ConnectorManager:
    """Manage read-only connectors and submit canonical events downstream."""

    def __init__(
        self,
        *,
        event_sink: Callable[[SecurityEvent], object],
        allowed_lateness_seconds: int = 300,
        state_store: JSONStateStore | None = None,
        clock=utc_now,
    ) -> None:
        self.connectors: dict[str, SecurityConnector] = {}
        self.event_sink = event_sink
        self.allowed_lateness = timedelta(seconds=allowed_lateness_seconds)
        self.clock = clock
        self.state_store = state_store or JSONStateStore()
        self.dedup = DeduplicationStore(self.state_store)
        self.checkpoints = CheckpointStore(self.state_store)
        self.dead_letters = DeadLetterStore(self.state_store)
        self.watermarks: dict[str, object] = {}
        self.last_summary = ConnectorPollSummary(timestamp=self.clock())

    def register(self, connector: SecurityConnector) -> None:
        """Register one connector and restore checkpoint if possible."""
        connector.validate_config()
        saved = self.checkpoints.load(connector.config.connector_id)
        if saved is not None:
            connector.commit_checkpoint(saved)
        self.connectors[connector.config.connector_id] = connector

    def start_all(self) -> None:
        """Start all enabled connectors."""
        for connector in self.connectors.values():
            connector.start()

    def poll_once(self, reference_time=None) -> ConnectorPollSummary:
        """Read, deduplicate, order, process, and checkpoint one cycle."""
        reference = reference_time or self.clock()
        summary = ConnectorPollSummary(timestamp=reference)
        candidates: list[tuple[RawConnectorRecord, list[SecurityEvent]]] = []
        batch_seen: set[str] = set()
        for connector_id, connector in self.connectors.items():
            if not connector.config.enabled:
                continue
            try:
                records = connector.read_batch(connector.config.batch_size)
            except Exception as exc:
                self.dead_letters.add(
                    connector_id=connector_id,
                    source_reference="read_batch",
                    failure_stage="read",
                    reason=str(exc),
                    retry_eligible=True,
                    timestamp=reference,
                )
                summary.rejected_records += 1
                continue
            summary.records_read += len(records)
            for record in records:
                try:
                    events = connector.normalize(record)
                except (TypeError, ValueError, ValidationError) as exc:
                    self.dead_letters.add(
                        connector_id=connector_id,
                        source_reference=record.source_record_id,
                        failure_stage="normalize",
                        reason=str(exc),
                        safe_metadata={
                            "raw_event_type": record.raw_event_type,
                            "payload_hash": record.payload_hash,
                        },
                        retry_eligible=not connector.config.strict,
                        timestamp=reference,
                    )
                    summary.rejected_records += 1
                    continue
                event_id = events[0].event_id if events else None
                batch_keys = {
                    f"source:{record.connector_id}:{record.source_record_id}",
                    (
                        "payload:"
                        f"{record.payload_hash}:{record.source_event_time.isoformat()}"
                    ),
                }
                if event_id:
                    batch_keys.add(f"event:{event_id}")
                if batch_seen.intersection(batch_keys):
                    summary.duplicates += 1
                    connector._health = connector.health().model_copy(
                        update={
                            "duplicate_records": connector.health().duplicate_records + 1,
                            "warnings": [
                                *connector.health().warnings,
                                f"duplicate:batch:{record.source_record_id}",
                            ],
                        }
                    )
                    continue
                duplicate, reason = self.dedup.is_duplicate(record, event_id)
                if duplicate:
                    summary.duplicates += 1
                    connector._health = connector.health().model_copy(
                        update={
                            "duplicate_records": connector.health().duplicate_records + 1,
                            "warnings": [
                                *connector.health().warnings,
                                f"duplicate:{reason}:{record.source_record_id}",
                            ],
                        }
                    )
                    continue
                batch_seen.update(batch_keys)
                if self._is_late(connector_id, record, reference):
                    summary.late_records += 1
                    connector._health = connector.health().model_copy(
                        update={
                            "late_records": connector.health().late_records + 1,
                            "warnings": [
                                *connector.health().warnings,
                                f"late_record:{record.source_record_id}",
                            ],
                        }
                    )
                candidates.append((record, events))
                summary.events_normalized += len(events)

        candidates.sort(
            key=lambda item: (
                item[0].source_event_time,
                item[0].connector_id,
                item[1][0].event_id if item[1] else item[0].source_record_id,
            )
        )
        for record, events in candidates:
            connector = self.connectors[record.connector_id]
            try:
                for event in events:
                    self.event_sink(event)
                    self.dedup.mark_seen(record, event.event_id)
                    summary.events_processed += 1
            except Exception as exc:
                self.dead_letters.add(
                    connector_id=record.connector_id,
                    source_reference=record.source_record_id,
                    failure_stage="process",
                    reason=str(exc),
                    safe_metadata={"payload_hash": record.payload_hash},
                    retry_eligible=True,
                    timestamp=reference,
                )
                summary.rejected_records += 1
                continue
            checkpoint = ConnectorCheckpoint(
                connector_id=record.connector_id,
                source_identifier=record.source_partition or record.connector_id,
                last_committed_offset=record.source_offset,
                last_event_time=record.source_event_time,
                last_record_id=record.source_record_id,
                updated_timestamp=reference,
                checksum=record.payload_hash[:16],
            )
            connector.commit_checkpoint(checkpoint)
            self.checkpoints.save(checkpoint)
            self.watermarks[record.connector_id] = record.source_event_time
            summary.checkpoints_committed += 1
        summary.dead_letters = len(self.dead_letters.list_entries())
        self.last_summary = summary
        return summary

    def run_continuous(self) -> None:
        """Run one bounded cycle; long-running loops are left to deployment wrappers."""
        self.start_all()
        self.poll_once(self.clock())

    def stop_all(self) -> None:
        """Stop all connectors."""
        for connector in self.connectors.values():
            connector.stop()

    def health_summary(self) -> list[ConnectorHealth]:
        """Return health for every connector."""
        return [connector.health() for connector in self.connectors.values()]

    def _is_late(
        self,
        connector_id: str,
        record: RawConnectorRecord,
        reference_time,
    ) -> bool:
        watermark = self.watermarks.get(connector_id)
        if watermark is None:
            return reference_time - record.source_event_time > self.allowed_lateness
        return record.source_event_time + self.allowed_lateness < watermark
