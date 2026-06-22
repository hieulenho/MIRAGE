"""Durable event transport abstraction with at-least-once delivery."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from mirage.production.schema import ScopeContext


class EventMessage(BaseModel):
    """Transport message with retry, schema, and idempotency metadata."""

    message_id: str
    topic: str
    event: dict[str, Any]
    idempotency_key: str
    schema_version: str = "v1"
    tenant_id: str = "default"
    environment: str = "shadow"
    state: str = "pending"
    attempts: int = 0
    consumer_group: str = ""
    available_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_error: str = ""


class InMemoryEventBus:
    """In-memory test transport that models duplicate delivery and DLQs."""

    def __init__(
        self,
        *,
        max_retries: int = 3,
        lease_seconds: int = 30,
        allowed_schema_versions: set[str] | None = None,
        max_queue_depth: int = 100000,
    ) -> None:
        self.max_retries = max_retries
        self.lease_seconds = lease_seconds
        self.allowed_schema_versions = allowed_schema_versions or {"v1"}
        self.max_queue_depth = max_queue_depth
        self._messages: dict[str, EventMessage] = {}
        self._idempotency: dict[tuple[str, str, str], str] = {}
        self._lock = threading.RLock()

    def publish(
        self,
        topic: str,
        event: dict[str, Any],
        idempotency_key: str,
        *,
        scope: ScopeContext | None = None,
        schema_version: str = "v1",
    ) -> EventMessage:
        scope = scope or ScopeContext()
        if schema_version not in self.allowed_schema_versions:
            raise ValueError(f"unsupported event schema version: {schema_version}")
        with self._lock:
            if self.lag(topic) >= self.max_queue_depth:
                raise BufferError("event transport backpressure: queue depth exceeded")
            scoped_key = (scope.tenant_id, scope.environment.value, idempotency_key)
            existing_id = self._idempotency.get(scoped_key)
            if existing_id:
                return self._messages[existing_id]
            message_id = _message_id(topic, idempotency_key, scope)
            message = EventMessage(
                message_id=message_id,
                topic=topic,
                event=json.loads(json.dumps(event, sort_keys=True, default=str)),
                idempotency_key=idempotency_key,
                schema_version=schema_version,
                tenant_id=scope.tenant_id,
                environment=scope.environment.value,
            )
            self._messages[message_id] = message
            self._idempotency[scoped_key] = message_id
            return message

    def poll(
        self,
        topic: str,
        *,
        consumer_group: str = "default",
        limit: int = 100,
    ) -> list[EventMessage]:
        now = datetime.now(timezone.utc)
        with self._lock:
            selected: list[EventMessage] = []
            for message in self._messages.values():
                if message.topic != topic:
                    continue
                if message.state == "acked" or message.state == "dead_letter":
                    continue
                if message.state == "in_flight" and message.available_at > now:
                    continue
                updated = message.model_copy(
                    update={
                        "state": "in_flight",
                        "consumer_group": consumer_group,
                        "attempts": message.attempts + 1,
                        "available_at": now + timedelta(seconds=self.lease_seconds),
                    }
                )
                self._messages[message.message_id] = updated
                selected.append(updated)
                if len(selected) >= limit:
                    break
            return selected

    def acknowledge(self, message: EventMessage) -> None:
        with self._lock:
            current = self._messages.get(message.message_id)
            if current:
                self._messages[message.message_id] = current.model_copy(update={"state": "acked"})

    def reject(self, message: EventMessage, reason: str) -> None:
        with self._lock:
            current = self._messages.get(message.message_id)
            if not current:
                return
            state = "dead_letter" if current.attempts >= self.max_retries else "pending"
            self._messages[message.message_id] = current.model_copy(
                update={"state": state, "last_error": reason}
            )

    def lag(self, topic: str) -> int:
        with self._lock:
            return sum(
                1
                for message in self._messages.values()
                if message.topic == topic and message.state not in {"acked", "dead_letter"}
            )

    def dead_letters(self) -> list[EventMessage]:
        with self._lock:
            return [
                message
                for message in self._messages.values()
                if message.state == "dead_letter"
            ]


class SQLiteEventBus(InMemoryEventBus):
    """SQLite-backed local durable event bus."""

    def __init__(
        self,
        path: str | Path,
        *,
        max_retries: int = 3,
        lease_seconds: int = 30,
        allowed_schema_versions: set[str] | None = None,
        max_queue_depth: int = 100000,
    ) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), check_same_thread=False, isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        super().__init__(
            max_retries=max_retries,
            lease_seconds=lease_seconds,
            allowed_schema_versions=allowed_schema_versions,
            max_queue_depth=max_queue_depth,
        )
        self._initialize()
        self._load()

    def _initialize(self) -> None:
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS event_messages (
                message_id TEXT PRIMARY KEY,
                payload_json TEXT NOT NULL,
                tenant_id TEXT NOT NULL,
                environment TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                UNIQUE(tenant_id, environment, idempotency_key)
            )
            """
        )

    def _load(self) -> None:
        rows = self.connection.execute("SELECT payload_json FROM event_messages").fetchall()
        for row in rows:
            message = EventMessage.model_validate_json(row["payload_json"])
            self._messages[message.message_id] = message
            self._idempotency[
                (message.tenant_id, message.environment, message.idempotency_key)
            ] = message.message_id

    def _persist(self, message: EventMessage) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO event_messages
            (message_id, payload_json, tenant_id, environment, idempotency_key)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                message.message_id,
                message.model_dump_json(),
                message.tenant_id,
                message.environment,
                message.idempotency_key,
            ),
        )

    def publish(
        self,
        topic: str,
        event: dict[str, Any],
        idempotency_key: str,
        *,
        scope: ScopeContext | None = None,
        schema_version: str = "v1",
    ) -> EventMessage:
        message = super().publish(
            topic,
            event,
            idempotency_key,
            scope=scope,
            schema_version=schema_version,
        )
        self._persist(message)
        return message

    def acknowledge(self, message: EventMessage) -> None:
        super().acknowledge(message)
        current = self._messages.get(message.message_id)
        if current:
            self._persist(current)

    def reject(self, message: EventMessage, reason: str) -> None:
        super().reject(message, reason)
        current = self._messages.get(message.message_id)
        if current:
            self._persist(current)


def _message_id(topic: str, idempotency_key: str, scope: ScopeContext) -> str:
    material = f"{topic}:{scope.scoped_key(idempotency_key)}".encode("utf-8")
    return "msg_" + hashlib.sha256(material).hexdigest()[:24]
