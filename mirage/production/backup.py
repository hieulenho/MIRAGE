"""Backup and restore workflows for production repositories."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class BackupManifest(BaseModel):
    """Backup metadata with an integrity checksum."""

    backup_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    checksum_sha256: str
    record_count: int
    encrypted: bool = False
    source: str = "mirage-production"


class BackupManager:
    """Create, verify, list, and restore logical repository snapshots."""

    def __init__(self, repository: Any, backup_dir: str | Path) -> None:
        self.repository = repository
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create(self, *, backup_id: str | None = None) -> BackupManifest:
        backup_id = backup_id or datetime.now(timezone.utc).strftime("backup_%Y%m%d%H%M%S")
        snapshot = self.repository.export_snapshot()
        payload = json.dumps(snapshot, sort_keys=True, default=str).encode("utf-8")
        checksum = hashlib.sha256(payload).hexdigest()
        manifest = BackupManifest(
            backup_id=backup_id,
            checksum_sha256=checksum,
            record_count=len(snapshot.get("records", [])),
        )
        backup_path = self.backup_dir / f"{backup_id}.json"
        backup_path.write_text(
            json.dumps(
                {"manifest": manifest.model_dump(mode="json"), "snapshot": snapshot},
                sort_keys=True,
                indent=2,
            ),
            encoding="utf-8",
        )
        return manifest

    def list_backups(self) -> list[BackupManifest]:
        manifests: list[BackupManifest] = []
        for path in sorted(self.backup_dir.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            manifests.append(BackupManifest.model_validate(data["manifest"]))
        return manifests

    def verify(self, backup_id: str) -> dict[str, Any]:
        data = self._read_backup(backup_id)
        manifest = BackupManifest.model_validate(data["manifest"])
        payload = json.dumps(data["snapshot"], sort_keys=True, default=str).encode("utf-8")
        checksum = hashlib.sha256(payload).hexdigest()
        return {
            "backup_id": backup_id,
            "valid": checksum == manifest.checksum_sha256,
            "record_count": manifest.record_count,
        }

    def restore_validate(self, backup_id: str) -> dict[str, Any]:
        verification = self.verify(backup_id)
        data = self._read_backup(backup_id)
        required = {"records", "idempotency"}
        missing = sorted(required.difference(data["snapshot"].keys()))
        return {
            **verification,
            "dry_run": True,
            "missing_sections": missing,
            "restorable": verification["valid"] and not missing,
        }

    def restore_run(self, backup_id: str, *, dry_run: bool = True) -> dict[str, Any]:
        validation = self.restore_validate(backup_id)
        if dry_run or not validation["restorable"]:
            return validation
        data = self._read_backup(backup_id)
        self.repository.import_snapshot(data["snapshot"], replace=True)
        return {**validation, "dry_run": False, "restored": True}

    def _read_backup(self, backup_id: str) -> dict[str, Any]:
        path = self.backup_dir / f"{backup_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"backup not found: {backup_id}")
        return json.loads(path.read_text(encoding="utf-8"))
