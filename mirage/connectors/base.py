"""Base connector abstractions for read-only fixture-driven ingestion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from mirage.domain.schemas import (
    ConnectorCheckpoint,
    ConnectorConfig,
    ConnectorHealth,
    ConnectorHealthState,
    RawConnectorRecord,
    SecurityEvent,
    utc_now,
)
from mirage.ingestion.normalizer import EventNormalizer


class SecurityConnector(Protocol):
    """Common interface for read-only security connectors."""

    config: ConnectorConfig

    def validate_config(self) -> None: ...

    def start(self) -> None: ...

    def read_batch(self, limit: int) -> list[RawConnectorRecord]: ...

    def normalize(self, record: RawConnectorRecord) -> list[SecurityEvent]: ...

    def get_checkpoint(self) -> ConnectorCheckpoint: ...

    def commit_checkpoint(self, checkpoint: ConnectorCheckpoint) -> None: ...

    def health(self) -> ConnectorHealth: ...

    def stop(self) -> None: ...


def payload_hash(payload: dict) -> str:
    """Return a stable SHA-256 hash for a raw payload."""
    encoded = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class BaseJSONLConnector:
    """Read-only JSONL connector with deterministic batching and checkpoints."""

    def __init__(
        self,
        config: ConnectorConfig,
        *,
        normalizer: EventNormalizer | None = None,
        clock=utc_now,
    ) -> None:
        self.config = config
        self.normalizer = normalizer or EventNormalizer()
        self.clock = clock
        self._lines: list[tuple[int, dict]] = []
        self._cursor = 0
        self._started = False
        self._checkpoint = ConnectorCheckpoint(
            connector_id=config.connector_id,
            source_identifier=config.input_path or config.endpoint_ref or "memory",
            last_committed_offset=0,
            updated_timestamp=self.clock(),
        )
        self._health = ConnectorHealth(
            connector_id=config.connector_id,
            state=ConnectorHealthState.STOPPED,
        )

    def validate_config(self) -> None:
        """Validate read-only fixture configuration."""
        if not self.config.enabled:
            return
        if self.config.operating_mode not in {"shadow", "read_only", "lab"}:
            raise ValueError("Connectors must run in shadow/read_only/lab mode")
        if not self.config.input_path:
            raise ValueError("Fixture connector requires input_path")
        path = Path(self.config.input_path)
        if not path.exists():
            raise ValueError(f"Connector input_path does not exist: {path}")
        if any(
            key.lower() in {"password", "token", "secret", "api_key"}
            for key in self.config.source_metadata
        ):
            raise ValueError("Connector config must not store plaintext secrets")

    def start(self) -> None:
        """Start connector and load fixture offsets."""
        self.validate_config()
        self._health = self._health.model_copy(
            update={"state": ConnectorHealthState.STARTING}
        )
        self._lines = []
        if self.config.input_path:
            with Path(self.config.input_path).open("r", encoding="utf-8") as handle:
                for offset, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        raw = json.loads(line)
                    except json.JSONDecodeError as exc:
                        if self.config.strict:
                            self._health = self._health.model_copy(
                                update={
                                    "state": ConnectorHealthState.FAILED,
                                    "error_summary": str(exc),
                                }
                            )
                            raise ValueError(
                                f"Malformed JSON at offset {offset}: {exc}"
                            ) from exc
                        self._health = self._health.model_copy(
                            update={
                                "rejected_records": self._health.rejected_records + 1,
                                "warnings": [
                                    *self._health.warnings,
                                    f"Malformed JSON at offset {offset}",
                                ],
                            }
                        )
                        continue
                    self._lines.append((offset, raw))
        last_offset = int(self._checkpoint.last_committed_offset or 0)
        self._cursor = next(
            (
                index
                for index, (offset, _raw) in enumerate(self._lines)
                if offset > last_offset
            ),
            len(self._lines),
        )
        self._started = True
        self._health = self._health.model_copy(
            update={"state": ConnectorHealthState.HEALTHY}
        )

    def read_batch(self, limit: int) -> list[RawConnectorRecord]:
        """Read a deterministic batch without modifying external systems."""
        if not self._started:
            self.start()
        limit = min(max(1, limit), self.config.batch_size)
        selected = self._lines[self._cursor : self._cursor + limit]
        records = [self._raw_record(offset, raw) for offset, raw in selected]
        self._cursor += len(selected)
        self._health = self._health.model_copy(
            update={
                "records_read": self._health.records_read + len(records),
                "last_successful_read": self.clock() if records else self._health.last_successful_read,
                "buffer_utilization": min(
                    1.0,
                    len(records) / max(1, self.config.maximum_buffered_events),
                ),
            }
        )
        return records

    def normalize(self, record: RawConnectorRecord) -> list[SecurityEvent]:
        """Normalize one raw connector record."""
        try:
            event = self.normalizer.normalize(self.map_record(record))
        except (TypeError, ValueError, ValidationError) as exc:
            if self.config.strict:
                self._health = self._health.model_copy(
                    update={
                        "state": ConnectorHealthState.FAILED,
                        "error_summary": str(exc),
                    }
                )
            raise
        self._health = self._health.model_copy(
            update={"events_normalized": self._health.events_normalized + 1}
        )
        return [event]

    def map_record(self, record: RawConnectorRecord) -> dict:
        """Map source-specific payload to EventNormalizer input."""
        raw = dict(record.raw_payload)
        raw.setdefault("event_id", f"{record.connector_id}:{record.source_record_id}")
        raw.setdefault("source", record.connector_id)
        raw.setdefault("event_time", record.source_event_time.isoformat())
        raw.setdefault("ingest_time", record.ingestion_time.isoformat())
        raw.setdefault("raw_event_ref", record.source_record_id)
        return raw

    def get_checkpoint(self) -> ConnectorCheckpoint:
        """Return current checkpoint."""
        return self._checkpoint

    def commit_checkpoint(self, checkpoint: ConnectorCheckpoint) -> None:
        """Idempotently commit checkpoint after successful processing."""
        if checkpoint.connector_id != self.config.connector_id:
            raise ValueError("Checkpoint connector_id mismatch")
        self._checkpoint = checkpoint.model_copy(
            update={"updated_timestamp": self.clock()}
        )
        self._health = self._health.model_copy(
            update={"last_successful_checkpoint": self.clock()}
        )

    def health(self) -> ConnectorHealth:
        """Return current health."""
        return self._health

    def stop(self) -> None:
        """Stop the connector gracefully."""
        self._started = False
        self._health = self._health.model_copy(
            update={"state": ConnectorHealthState.STOPPED}
        )

    def _raw_record(self, offset: int, raw: dict) -> RawConnectorRecord:
        event_time = self.normalizer.normalize({
            "event_id": f"probe:{self.config.connector_id}:{offset}",
            "event_time": raw.get("event_time")
            or raw.get("timestamp")
            or raw.get("@timestamp")
            or raw.get("ts")
            or self.clock().isoformat(),
            "ingest_time": raw.get("ingest_time")
            or raw.get("received_time")
            or raw.get("@timestamp")
            or raw.get("ts")
            or self.clock().isoformat(),
            "source": self.config.connector_id,
            "event_type": raw.get("event_type") or raw.get("event_id") or raw.get("_path") or "unknown",
        }).event_time
        source_id = str(
            raw.get("event_id")
            or raw.get("id")
            or raw.get("uid")
            or raw.get("record_id")
            or offset
        )
        return RawConnectorRecord(
            connector_id=self.config.connector_id,
            source_record_id=source_id,
            source_event_time=event_time,
            ingestion_time=self.clock(),
            source_offset=offset,
            source_partition=self.config.input_path,
            raw_event_type=str(
                raw.get("event_type")
                or raw.get("event_id")
                or raw.get("_path")
                or "unknown"
            ),
            raw_payload=raw,
            payload_hash=payload_hash(raw),
        )
