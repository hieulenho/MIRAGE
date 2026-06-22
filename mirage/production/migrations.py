"""Versioned SQLite migration framework for local durable storage."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import BaseModel, Field


class MigrationLockError(RuntimeError):
    """Raised when another migration owner holds the lock."""


@dataclass(frozen=True)
class Migration:
    """A reversible schema migration."""

    version: int
    description: str
    up_sql: tuple[str, ...]
    down_sql: tuple[str, ...] = ()
    destructive: bool = False


class MigrationResult(BaseModel):
    """Migration operation result."""

    current_version: int
    target_version: int
    applied_versions: list[int] = Field(default_factory=list)
    dry_run: bool = False
    backup_required: bool = False


DEFAULT_MIGRATIONS = (
    Migration(
        version=1,
        description="production repository base tables",
        up_sql=(
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
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS production_idempotency (
                tenant_id TEXT NOT NULL,
                environment TEXT NOT NULL,
                idempotency_key TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY (tenant_id, environment, idempotency_key)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS production_leases (
                lease_name TEXT PRIMARY KEY,
                holder_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        ),
        down_sql=(
            "DROP TABLE IF EXISTS production_leases",
            "DROP TABLE IF EXISTS production_idempotency",
            "DROP TABLE IF EXISTS production_records",
        ),
    ),
)


class MigrationManager:
    """Apply forward migrations with version tracking and a lease lock."""

    def __init__(
        self,
        path: str | Path,
        *,
        migrations: tuple[Migration, ...] = DEFAULT_MIGRATIONS,
    ) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.migrations = tuple(sorted(migrations, key=lambda migration: migration.version))
        self._ensure_meta()

    def _ensure_meta(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS schema_migrations (
                version INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS migration_lock (
                lock_name TEXT PRIMARY KEY,
                owner TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            """
        )

    def current_version(self) -> int:
        row = self.connection.execute(
            "SELECT MAX(version) AS version FROM schema_migrations"
        ).fetchone()
        return int(row["version"] or 0)

    def status(self) -> dict[str, int | bool]:
        current = self.current_version()
        target = max((migration.version for migration in self.migrations), default=0)
        return {
            "current_version": current,
            "target_version": target,
            "up_to_date": current == target,
        }

    def acquire_lock(self, owner: str, *, ttl_seconds: int = 60) -> bool:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        row = self.connection.execute(
            "SELECT owner, expires_at FROM migration_lock WHERE lock_name = 'schema'"
        ).fetchone()
        if row and datetime.fromisoformat(row["expires_at"]) > now and row["owner"] != owner:
            return False
        self.connection.execute(
            """
            INSERT OR REPLACE INTO migration_lock(lock_name, owner, expires_at)
            VALUES ('schema', ?, ?)
            """,
            (owner, expires.isoformat()),
        )
        return True

    def release_lock(self, owner: str) -> None:
        self.connection.execute(
            "DELETE FROM migration_lock WHERE lock_name = 'schema' AND owner = ?",
            (owner,),
        )

    def migrate(
        self,
        *,
        dry_run: bool = False,
        owner: str = "mirage",
        backup_confirmed: bool = False,
    ) -> MigrationResult:
        current = self.current_version()
        pending = [migration for migration in self.migrations if migration.version > current]
        backup_required = any(migration.destructive for migration in pending)
        if backup_required and not backup_confirmed:
            return MigrationResult(
                current_version=current,
                target_version=self.migrations[-1].version if self.migrations else current,
                dry_run=dry_run,
                backup_required=True,
            )
        if dry_run:
            return MigrationResult(
                current_version=current,
                target_version=self.migrations[-1].version if self.migrations else current,
                applied_versions=[migration.version for migration in pending],
                dry_run=True,
                backup_required=backup_required,
            )
        if not self.acquire_lock(owner):
            raise MigrationLockError("schema migration lock is held")
        applied: list[int] = []
        try:
            for migration in pending:
                with self.connection:
                    for sql in migration.up_sql:
                        self.connection.execute(sql)
                    self.connection.execute(
                        """
                        INSERT INTO schema_migrations(version, description, applied_at)
                        VALUES (?, ?, ?)
                        """,
                        (
                            migration.version,
                            migration.description,
                            datetime.now(timezone.utc).isoformat(),
                        ),
                    )
                    applied.append(migration.version)
        finally:
            self.release_lock(owner)
        return MigrationResult(
            current_version=current,
            target_version=self.current_version(),
            applied_versions=applied,
            backup_required=backup_required,
        )

    def rollback_last(self, *, owner: str = "mirage") -> MigrationResult:
        current = self.current_version()
        migration = next(
            (candidate for candidate in reversed(self.migrations) if candidate.version == current),
            None,
        )
        if migration is None or not migration.down_sql:
            return MigrationResult(current_version=current, target_version=current)
        if not self.acquire_lock(owner):
            raise MigrationLockError("schema migration lock is held")
        try:
            with self.connection:
                for sql in migration.down_sql:
                    self.connection.execute(sql)
                self.connection.execute(
                    "DELETE FROM schema_migrations WHERE version = ?",
                    (migration.version,),
                )
        finally:
            self.release_lock(owner)
        return MigrationResult(
            current_version=current,
            target_version=self.current_version(),
            applied_versions=[migration.version],
        )
