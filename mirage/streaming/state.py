"""Lightweight persistent state for streaming ingestion."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.domain.schemas import ConnectorCheckpoint, DeadLetterEntry, RawConnectorRecord
from mirage.execution.audit import sanitize_payload
from mirage.execution.utils import deterministic_id, ensure_utc


class JSONStateStore:
    """Small JSON-file state store used for restart-safe tests and pilots."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.data: dict[str, Any] = {}
        if self.path and self.path.exists():
            self.data = json.loads(self.path.read_text(encoding="utf-8"))

    def save(self) -> None:
        """Persist state if a path is configured."""
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )


class DeduplicationStore:
    """Deduplicate by event ID, source record ID, and payload hash+time."""

    def __init__(self, state: JSONStateStore | None = None) -> None:
        self.state = state or JSONStateStore()
        self.state.data.setdefault("dedup_keys", {})

    def is_duplicate(self, record: RawConnectorRecord, event_id: str | None = None) -> tuple[bool, str]:
        """Return duplicate status and reason."""
        keys = self._keys(record, event_id)
        known = self.state.data["dedup_keys"]
        for key in keys:
            if key in known:
                return True, known[key]["reason"]
        return False, ""

    def mark_seen(self, record: RawConnectorRecord, event_id: str | None = None) -> None:
        """Persist dedup keys for a processed record."""
        known = self.state.data["dedup_keys"]
        for key in self._keys(record, event_id):
            known[key] = {
                "reason": key.split(":", 1)[0],
                "connector_id": record.connector_id,
                "source_record_id": record.source_record_id,
                "event_time": record.source_event_time.isoformat(),
            }
        self.state.save()

    def _keys(self, record: RawConnectorRecord, event_id: str | None) -> list[str]:
        keys = [
            f"source:{record.connector_id}:{record.source_record_id}",
            (
                "payload:"
                f"{record.payload_hash}:{record.source_event_time.isoformat()}"
            ),
        ]
        if event_id:
            keys.insert(0, f"event:{event_id}")
        return keys


class CheckpointStore:
    """Persistent connector checkpoints."""

    def __init__(self, state: JSONStateStore | None = None) -> None:
        self.state = state or JSONStateStore()
        self.state.data.setdefault("checkpoints", {})

    def load(self, connector_id: str) -> ConnectorCheckpoint | None:
        raw = self.state.data["checkpoints"].get(connector_id)
        return ConnectorCheckpoint.model_validate(raw) if raw else None

    def save(self, checkpoint: ConnectorCheckpoint) -> None:
        self.state.data["checkpoints"][checkpoint.connector_id] = checkpoint.model_dump(
            mode="json"
        )
        self.state.save()


class DeadLetterStore:
    """Sanitized dead-letter store with controlled replay metadata."""

    def __init__(self, state: JSONStateStore | None = None) -> None:
        self.state = state or JSONStateStore()
        self.state.data.setdefault("dead_letters", {})

    def add(
        self,
        *,
        connector_id: str,
        source_reference: str,
        failure_stage: str,
        reason: str,
        safe_metadata: dict[str, Any] | None = None,
        retry_eligible: bool = True,
        timestamp=None,
    ) -> DeadLetterEntry:
        """Add one sanitized dead-letter entry."""
        when = ensure_utc(timestamp)
        entry = DeadLetterEntry(
            dead_letter_id=deterministic_id(
                "dead-letter",
                connector_id,
                source_reference,
                failure_stage,
                reason,
            ),
            connector_id=connector_id,
            source_reference=source_reference,
            failure_stage=failure_stage,
            reason=reason,
            safe_metadata=sanitize_payload(safe_metadata or {}),
            retry_eligible=retry_eligible,
            timestamp=when,
        )
        self.state.data["dead_letters"][entry.dead_letter_id] = entry.model_dump(
            mode="json"
        )
        self.state.save()
        return entry

    def list_entries(self) -> list[DeadLetterEntry]:
        return [
            DeadLetterEntry.model_validate(item)
            for item in self.state.data.get("dead_letters", {}).values()
        ]
