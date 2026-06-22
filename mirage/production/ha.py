"""Lease-based leadership and distributed-lock primitives."""

from __future__ import annotations

import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pydantic import BaseModel


class LeaseRecord(BaseModel):
    """Lease state for a leader or lock."""

    name: str
    holder_id: str
    expires_at: datetime
    updated_at: datetime


class InMemoryLeaseStore:
    """Test lease store with expiry semantics."""

    def __init__(self) -> None:
        self._leases: dict[str, LeaseRecord] = {}
        self._lock = threading.RLock()

    def acquire(
        self,
        name: str,
        holder_id: str,
        *,
        ttl_seconds: int = 30,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or datetime.now(timezone.utc)
        with self._lock:
            lease = self._leases.get(name)
            if lease and lease.expires_at > current_time and lease.holder_id != holder_id:
                return False
            self._leases[name] = LeaseRecord(
                name=name,
                holder_id=holder_id,
                expires_at=current_time + timedelta(seconds=ttl_seconds),
                updated_at=current_time,
            )
            return True

    def renew(
        self,
        name: str,
        holder_id: str,
        *,
        ttl_seconds: int = 30,
    ) -> bool:
        now = datetime.now(timezone.utc)
        with self._lock:
            lease = self._leases.get(name)
            if not lease or lease.holder_id != holder_id or lease.expires_at <= now:
                return False
            self._leases[name] = lease.model_copy(
                update={
                    "expires_at": now + timedelta(seconds=ttl_seconds),
                    "updated_at": now,
                }
            )
            return True

    def release(self, name: str, holder_id: str) -> None:
        with self._lock:
            lease = self._leases.get(name)
            if lease and lease.holder_id == holder_id:
                del self._leases[name]

    def get(self, name: str) -> LeaseRecord | None:
        with self._lock:
            return self._leases.get(name)


class SQLiteLeaseStore(InMemoryLeaseStore):
    """SQLite lease store usable by multiple local worker processes."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(self.path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        super().__init__()
        self.connection.execute(
            """
            CREATE TABLE IF NOT EXISTS production_leases (
                lease_name TEXT PRIMARY KEY,
                holder_id TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

    def acquire(
        self,
        name: str,
        holder_id: str,
        *,
        ttl_seconds: int = 30,
        now: datetime | None = None,
    ) -> bool:
        current_time = now or datetime.now(timezone.utc)
        row = self.connection.execute(
            "SELECT holder_id, expires_at FROM production_leases WHERE lease_name = ?",
            (name,),
        ).fetchone()
        if row and datetime.fromisoformat(row["expires_at"]) > current_time and row["holder_id"] != holder_id:
            return False
        expires = current_time + timedelta(seconds=ttl_seconds)
        self.connection.execute(
            """
            INSERT OR REPLACE INTO production_leases
            (lease_name, holder_id, expires_at, updated_at)
            VALUES (?, ?, ?, ?)
            """,
            (name, holder_id, expires.isoformat(), current_time.isoformat()),
        )
        return True

    def get(self, name: str) -> LeaseRecord | None:
        row = self.connection.execute(
            "SELECT * FROM production_leases WHERE lease_name = ?",
            (name,),
        ).fetchone()
        if not row:
            return None
        return LeaseRecord(
            name=row["lease_name"],
            holder_id=row["holder_id"],
            expires_at=datetime.fromisoformat(row["expires_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )


class LeaderElector:
    """Lease-backed leader election helper."""

    def __init__(self, store: InMemoryLeaseStore, *, service_name: str, instance_id: str) -> None:
        self.store = store
        self.service_name = service_name
        self.instance_id = instance_id

    def campaign(self, *, ttl_seconds: int = 30, now: datetime | None = None) -> bool:
        return self.store.acquire(
            f"leader:{self.service_name}",
            self.instance_id,
            ttl_seconds=ttl_seconds,
            now=now,
        )

    def is_leader(self) -> bool:
        lease = self.store.get(f"leader:{self.service_name}")
        return bool(
            lease
            and lease.holder_id == self.instance_id
            and lease.expires_at > datetime.now(timezone.utc)
        )
