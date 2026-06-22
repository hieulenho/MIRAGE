"""Persistent repository interfaces and lightweight backends."""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from mirage.production.schema import ScopeContext


class VersionConflictError(RuntimeError):
    """Raised when optimistic concurrency detects a stale update."""


class RecordEnvelope(BaseModel):
    """Versioned, scoped record stored by production repositories."""

    table: str
    record_id: str
    scope: ScopeContext
    payload: dict[str, Any]
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ProductionRepository(Protocol):
    """Generic scoped repository contract."""

    def upsert(
        self,
        table: str,
        record_id: str,
        payload: dict[str, Any],
        *,
        scope: ScopeContext,
        expected_version: int | None = None,
    ) -> RecordEnvelope:
        """Create or update a record."""

    def get(
        self,
        table: str,
        record_id: str,
        *,
        scope: ScopeContext,
    ) -> RecordEnvelope | None:
        """Return one scoped record."""

    def list_records(
        self,
        table: str,
        *,
        scope: ScopeContext,
        limit: int = 100,
    ) -> list[RecordEnvelope]:
        """Return scoped records only."""

    def record_idempotency(
        self,
        key: str,
        response: dict[str, Any],
        *,
        scope: ScopeContext,
    ) -> bool:
        """Persist an idempotency result, returning false when it exists."""

    def get_idempotency(
        self,
        key: str,
        *,
        scope: ScopeContext,
    ) -> dict[str, Any] | None:
        """Return a prior idempotency response."""


class InMemoryProductionRepository:
    """Test backend with the same tenant-scoped semantics as durable stores."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str, str, str], RecordEnvelope] = {}
        self._idempotency: dict[tuple[str, str, str], dict[str, Any]] = {}
        self._lock = threading.RLock()

    def upsert(
        self,
        table: str,
        record_id: str,
        payload: dict[str, Any],
        *,
        scope: ScopeContext,
        expected_version: int | None = None,
    ) -> RecordEnvelope:
        with self._lock:
            key = _record_key(table, record_id, scope)
            current = self._records.get(key)
            if current and expected_version is not None and current.version != expected_version:
                raise VersionConflictError("stale record version")
            now = datetime.now(timezone.utc)
            envelope = RecordEnvelope(
                table=table,
                record_id=record_id,
                scope=scope,
                payload=json.loads(json.dumps(payload, sort_keys=True, default=str)),
                version=(current.version + 1 if current else 1),
                created_at=current.created_at if current else now,
                updated_at=now,
            )
            self._records[key] = envelope
            return envelope

    def get(
        self,
        table: str,
        record_id: str,
        *,
        scope: ScopeContext,
    ) -> RecordEnvelope | None:
        with self._lock:
            return self._records.get(_record_key(table, record_id, scope))

    def list_records(
        self,
        table: str,
        *,
        scope: ScopeContext,
        limit: int = 100,
    ) -> list[RecordEnvelope]:
        with self._lock:
            rows = [
                record
                for (row_table, tenant, environment, _), record in self._records.items()
                if row_table == table
                and tenant == scope.tenant_id
                and environment == scope.environment.value
            ]
            rows.sort(key=lambda record: record.updated_at, reverse=True)
            return rows[:limit]

    def record_idempotency(
        self,
        key: str,
        response: dict[str, Any],
        *,
        scope: ScopeContext,
    ) -> bool:
        scoped = _idempotency_key(key, scope)
        with self._lock:
            if scoped in self._idempotency:
                return False
            self._idempotency[scoped] = json.loads(
                json.dumps(response, sort_keys=True, default=str)
            )
            return True

    def get_idempotency(
        self,
        key: str,
        *,
        scope: ScopeContext,
    ) -> dict[str, Any] | None:
        with self._lock:
            response = self._idempotency.get(_idempotency_key(key, scope))
            return json.loads(json.dumps(response)) if response is not None else None

    def export_snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "records": [
                    record.model_dump(mode="json")
                    for record in self._records.values()
                ],
                "idempotency": [
                    {
                        "tenant_id": tenant,
                        "environment": environment,
                        "key": key,
                        "response": response,
                    }
                    for (tenant, environment, key), response in self._idempotency.items()
                ],
            }

    def import_snapshot(self, snapshot: dict[str, Any], *, replace: bool = False) -> None:
        with self._lock:
            if replace:
                self._records.clear()
                self._idempotency.clear()
            for raw in snapshot.get("records", []):
                record = RecordEnvelope.model_validate(raw)
                self._records[_record_key(record.table, record.record_id, record.scope)] = record
            for raw in snapshot.get("idempotency", []):
                scope = ScopeContext(
                    tenant_id=raw["tenant_id"],
                    environment=raw["environment"],
                )
                self._idempotency[_idempotency_key(raw["key"], scope)] = raw["response"]

    def ping(self) -> bool:
        return True


class SQLiteProductionRepository:
    """SQLite backend for local durable and lightweight deployments."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.connection = sqlite3.connect(
            str(self.path),
            check_same_thread=False,
            isolation_level=None,
        )
        self.connection.row_factory = sqlite3.Row
        self.initialize()

    def initialize(self) -> None:
        with self._lock:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS production_records (
                    table_name TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    tenant_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    pilot_scope_id TEXT NOT NULL,
                    data_classification TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (table_name, record_id, tenant_id, environment)
                );
                CREATE TABLE IF NOT EXISTS production_idempotency (
                    tenant_id TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL,
                    response_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, environment, idempotency_key)
                );
                """
            )

    def upsert(
        self,
        table: str,
        record_id: str,
        payload: dict[str, Any],
        *,
        scope: ScopeContext,
        expected_version: int | None = None,
    ) -> RecordEnvelope:
        with self._lock:
            current = self.get(table, record_id, scope=scope)
            if current and expected_version is not None and current.version != expected_version:
                raise VersionConflictError("stale record version")
            now = datetime.now(timezone.utc)
            version = current.version + 1 if current else 1
            created_at = current.created_at if current else now
            envelope = RecordEnvelope(
                table=table,
                record_id=record_id,
                scope=scope,
                payload=json.loads(json.dumps(payload, sort_keys=True, default=str)),
                version=version,
                created_at=created_at,
                updated_at=now,
            )
            self.connection.execute(
                """
                INSERT OR REPLACE INTO production_records
                (table_name, record_id, tenant_id, environment, pilot_scope_id,
                 data_classification, version, payload_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    table,
                    record_id,
                    scope.tenant_id,
                    scope.environment.value,
                    scope.pilot_scope_id,
                    scope.data_classification,
                    version,
                    json.dumps(envelope.payload, sort_keys=True),
                    created_at.isoformat(),
                    now.isoformat(),
                ),
            )
            return envelope

    def get(
        self,
        table: str,
        record_id: str,
        *,
        scope: ScopeContext,
    ) -> RecordEnvelope | None:
        row = self.connection.execute(
            """
            SELECT * FROM production_records
            WHERE table_name = ? AND record_id = ?
              AND tenant_id = ? AND environment = ?
            """,
            (table, record_id, scope.tenant_id, scope.environment.value),
        ).fetchone()
        return _row_to_envelope(row) if row else None

    def list_records(
        self,
        table: str,
        *,
        scope: ScopeContext,
        limit: int = 100,
    ) -> list[RecordEnvelope]:
        rows = self.connection.execute(
            """
            SELECT * FROM production_records
            WHERE table_name = ? AND tenant_id = ? AND environment = ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (table, scope.tenant_id, scope.environment.value, int(limit)),
        ).fetchall()
        return [_row_to_envelope(row) for row in rows]

    def record_idempotency(
        self,
        key: str,
        response: dict[str, Any],
        *,
        scope: ScopeContext,
    ) -> bool:
        with self._lock:
            try:
                self.connection.execute(
                    """
                    INSERT INTO production_idempotency
                    (tenant_id, environment, idempotency_key, response_json, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scope.tenant_id,
                        scope.environment.value,
                        key,
                        json.dumps(response, sort_keys=True, default=str),
                        datetime.now(timezone.utc).isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                return False
            return True

    def get_idempotency(
        self,
        key: str,
        *,
        scope: ScopeContext,
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT response_json FROM production_idempotency
            WHERE tenant_id = ? AND environment = ? AND idempotency_key = ?
            """,
            (scope.tenant_id, scope.environment.value, key),
        ).fetchone()
        return json.loads(row["response_json"]) if row else None

    def export_snapshot(self) -> dict[str, Any]:
        records = self.connection.execute("SELECT * FROM production_records").fetchall()
        idempotency = self.connection.execute(
            "SELECT * FROM production_idempotency"
        ).fetchall()
        return {
            "records": [_row_to_envelope(row).model_dump(mode="json") for row in records],
            "idempotency": [
                {
                    "tenant_id": row["tenant_id"],
                    "environment": row["environment"],
                    "key": row["idempotency_key"],
                    "response": json.loads(row["response_json"]),
                }
                for row in idempotency
            ],
        }

    def import_snapshot(self, snapshot: dict[str, Any], *, replace: bool = False) -> None:
        with self._lock:
            if replace:
                self.connection.execute("DELETE FROM production_records")
                self.connection.execute("DELETE FROM production_idempotency")
            for raw in snapshot.get("records", []):
                record = RecordEnvelope.model_validate(raw)
                self.upsert(
                    record.table,
                    record.record_id,
                    record.payload,
                    scope=record.scope,
                )
            for raw in snapshot.get("idempotency", []):
                scope = ScopeContext(
                    tenant_id=raw["tenant_id"],
                    environment=raw["environment"],
                )
                self.record_idempotency(raw["key"], raw["response"], scope=scope)

    def ping(self) -> bool:
        try:
            self.connection.execute("SELECT 1").fetchone()
        except sqlite3.Error:
            return False
        return True


def _record_key(
    table: str,
    record_id: str,
    scope: ScopeContext,
) -> tuple[str, str, str, str]:
    return (table, scope.tenant_id, scope.environment.value, record_id)


def _idempotency_key(key: str, scope: ScopeContext) -> tuple[str, str, str]:
    return (scope.tenant_id, scope.environment.value, key)


def _row_to_envelope(row: sqlite3.Row) -> RecordEnvelope:
    scope = ScopeContext(
        tenant_id=row["tenant_id"],
        environment=row["environment"],
        pilot_scope_id=row["pilot_scope_id"],
        data_classification=row["data_classification"],
    )
    return RecordEnvelope(
        table=row["table_name"],
        record_id=row["record_id"],
        scope=scope,
        payload=json.loads(row["payload_json"]),
        version=int(row["version"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


class EventRepository:
    """Named repository facade for normalized event metadata."""

    table = "events"


class TwinRepository:
    """Named repository facade for Twin versions and snapshots."""

    table = "twin"


class BeliefRepository:
    """Named repository facade for beliefs and evidence."""

    table = "beliefs"


class AnalysisRepository:
    """Named repository facade for attack analyses."""

    table = "analyses"


class RecommendationRepository:
    """Named repository facade for recommendations."""

    table = "recommendations"


class ExecutionRepository:
    """Named repository facade for execution state."""

    table = "executions"


class GovernanceRepository:
    """Named repository facade for governance artifacts."""

    table = "governance"


class AuditRepository:
    """Named repository facade for audit-chain records."""

    table = "audit"


class ModelRegistryRepository:
    """Named repository facade for model metadata."""

    table = "model_registry"
