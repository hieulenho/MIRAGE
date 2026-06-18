"""Append-only sanitized audit store for Milestone 4."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.domain.schemas import AuditEvent
from mirage.execution.utils import deterministic_id, ensure_utc

SENSITIVE_KEYS = {
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "command_line",
    "raw_event",
    "raw_payload",
}


def sanitize_payload(value: Any) -> Any:
    """Remove sensitive fields from nested audit payloads."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            lower = str(key).lower()
            if any(marker in lower for marker in SENSITIVE_KEYS):
                cleaned[key] = "[redacted]"
            else:
                cleaned[key] = sanitize_payload(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_payload(item) for item in value]
    return value


class ImmutableAuditStore:
    """Append-only JSONL audit store with deterministic event IDs."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.events: list[AuditEvent] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(
        self,
        event_type: str,
        *,
        actor: str = "mirage",
        execution_id: str | None = None,
        plan_id: str | None = None,
        action_id: str | None = None,
        policy_version: str | None = None,
        twin_version: str | None = None,
        graph_version: str | None = None,
        belief_version: str | None = None,
        analysis_id: str | None = None,
        payload: dict[str, Any] | None = None,
        timestamp=None,
    ) -> AuditEvent:
        """Append one sanitized audit event."""
        when = ensure_utc(timestamp)
        safe_payload = sanitize_payload(payload or {})
        audit_id = deterministic_id(
            "audit",
            event_type,
            execution_id or "",
            plan_id or "",
            action_id or "",
            len(self.events),
            when.isoformat(),
        )
        event = AuditEvent(
            audit_id=audit_id,
            event_type=event_type,
            timestamp=when,
            actor=actor,
            execution_id=execution_id,
            plan_id=plan_id,
            action_id=action_id,
            policy_version=policy_version,
            twin_version=twin_version,
            graph_version=graph_version,
            belief_version=belief_version,
            analysis_id=analysis_id,
            payload=safe_payload,
        )
        self.events.append(event)
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.model_dump(mode="json"), sort_keys=True))
                handle.write("\n")
        return event

    def export_jsonl(self) -> str:
        """Return deterministic JSONL text for all in-memory events."""
        return "\n".join(
            json.dumps(event.model_dump(mode="json"), sort_keys=True)
            for event in self.events
        )

    def list_events(self) -> list[dict[str, Any]]:
        """Return serialized audit events."""
        return [event.model_dump(mode="json") for event in self.events]
