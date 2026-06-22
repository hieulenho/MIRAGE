"""Tamper-evident governance audit store."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mirage.execution.audit import sanitize_payload
from mirage.execution.utils import deterministic_id, ensure_utc
from mirage.governance.integrity import sha256_json
from mirage.governance.schema import GovernanceAuditRecord


class GovernanceAuditStore:
    """Append-only governance audit with hash chaining."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.records: list[GovernanceAuditRecord] = []
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists():
                for line in self.path.read_text(encoding="utf-8").splitlines():
                    if line.strip():
                        self.records.append(GovernanceAuditRecord.model_validate_json(line))

    def append(
        self,
        event_type: str,
        *,
        actor: str = "mirage",
        role: str = "system",
        artifact_or_execution_id: str = "",
        before_state: dict[str, Any] | None = None,
        after_state: dict[str, Any] | None = None,
        reason: str = "",
        hashes: dict[str, str] | None = None,
        related_evidence: list[str] | None = None,
    ) -> GovernanceAuditRecord:
        timestamp = ensure_utc(None)
        previous = self.records[-1].record_hash if self.records else ""
        safe_after = sanitize_payload(after_state or {})
        content = {
            "event_type": event_type,
            "actor": actor,
            "role": role,
            "artifact_or_execution_id": artifact_or_execution_id,
            "before_state": sanitize_payload(before_state or {}),
            "after_state": safe_after,
            "reason": reason,
            "timestamp": timestamp.isoformat(),
            "hashes": hashes or {},
            "related_evidence": related_evidence or [],
            "previous_record_hash": previous,
        }
        record_hash = sha256_json({"previous": previous, "content": content})
        record = GovernanceAuditRecord(
            audit_id=deterministic_id("gov_audit", event_type, artifact_or_execution_id, len(self.records), timestamp.isoformat()),
            record_hash=record_hash,
            **content,
        )
        self.records.append(record)
        if self.path:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(record.model_dump_json())
                handle.write("\n")
        return record

    def verify_chain(self) -> dict[str, Any]:
        previous = ""
        for index, record in enumerate(self.records):
            content = record.model_dump(mode="json")
            expected_previous = content.pop("previous_record_hash")
            record_hash = content.pop("record_hash")
            content.pop("audit_id", None)
            if expected_previous != previous:
                return {"valid": False, "failed_index": index, "reason": "previous_hash_mismatch"}
            expected_hash = sha256_json({"previous": previous, "content": content})
            if expected_hash != record_hash:
                return {"valid": False, "failed_index": index, "reason": "record_hash_mismatch"}
            previous = record_hash
        return {"valid": True, "record_count": len(self.records), "head": previous}
