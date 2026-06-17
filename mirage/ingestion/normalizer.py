"""Normalize generic raw event dictionaries into canonical SecurityEvent."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from mirage.domain.schemas import SecurityEvent, utc_now


_EVENT_TYPE_ALIASES = {
    "process_start": {
        "process_start",
        "process_started",
        "process_create",
        "process_creation",
        "exec",
    },
    "authentication_success": {
        "authentication_success",
        "auth_success",
        "login_success",
        "logon_success",
        "successful_login",
    },
    "authentication_failure": {
        "authentication_failure",
        "auth_failure",
        "login_failure",
        "logon_failure",
        "failed_login",
    },
    "network_connection": {
        "network_connection",
        "network_connect",
        "connection",
        "smb_connection",
        "rdp_connection",
    },
    "dns_query": {"dns_query", "dns_request"},
    "file_access": {"file_access", "file_read", "share_access"},
    "credential_use": {"credential_use", "credential_used", "honey_credential_used"},
    "deception_interaction": {
        "deception_interaction",
        "decoy_access",
        "honeypot_touch",
        "honey_credential_triggered",
    },
    "asset_discovered": {"asset_discovered", "asset_seen", "host_discovered"},
    "vulnerability_observed": {
        "vulnerability_observed",
        "vulnerability",
        "vuln_observed",
        "cve_detected",
    },
}


def _canonical_event_type(value: Any) -> str:
    raw = str(value or "unknown").strip().lower().replace("-", "_")
    for canonical, aliases in _EVENT_TYPE_ALIASES.items():
        if raw in aliases:
            return canonical
    if "powershell" in raw or "process" in raw:
        return "process_start"
    if "dns" in raw:
        return "dns_query"
    if "credential" in raw:
        return "credential_use"
    if "decoy" in raw or "honey" in raw:
        return "deception_interaction"
    if "vuln" in raw or "cve" in raw:
        return "vulnerability_observed"
    if "auth" in raw or "login" in raw or "logon" in raw:
        if "fail" in raw or "denied" in raw:
            return "authentication_failure"
        return "authentication_success"
    if "network" in raw or "connect" in raw or "smb" in raw or "rdp" in raw:
        return "network_connection"
    return raw


def _parse_datetime(value: Any, *, default: datetime | None = None) -> datetime:
    if value is None:
        return default or utc_now()
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _first(raw: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in raw and raw[key] not in (None, ""):
            return raw[key]
    return None


def _nested(raw: dict[str, Any], *path: str) -> Any:
    current: Any = raw
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if str(item).strip()]
    return [
        token.strip()
        for token in re.split(r"[,;\s]+", str(value))
        if token.strip()
    ]


def _stable_event_id(raw: dict[str, Any]) -> str:
    payload = json.dumps(raw, sort_keys=True, default=str, ensure_ascii=False)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]
    return f"evt-{digest}"


class EventNormalizer:
    """Normalize vendor-neutral dictionaries into canonical SecurityEvent."""

    CANONICAL_FIELDS = set(SecurityEvent.model_fields)

    def normalize(self, raw_event: dict[str, Any]) -> SecurityEvent:
        """Convert a raw dictionary to a validated canonical event."""
        if not isinstance(raw_event, dict):
            raise TypeError("raw_event must be a dictionary")

        raw = dict(raw_event)
        event_time = _parse_datetime(
            _first(raw, "event_time", "timestamp", "@timestamp", "time")
        )
        ingest_time = _parse_datetime(
            _first(raw, "ingest_time", "received_time"),
            default=event_time,
        )
        event_type = _canonical_event_type(
            _first(raw, "event_type", "type", "action", "event_name")
        )
        confidence = float(_first(raw, "confidence", "score") or 1.0)
        technique_ids = _as_list(
            _first(raw, "technique_ids", "mitre_techniques", "technique_id")
        )

        attributes = dict(raw.get("attributes") or {})
        for key, value in raw.items():
            if key not in self.CANONICAL_FIELDS and key != "attributes":
                attributes.setdefault(key, value)

        normalized = {
            "event_id": str(_first(raw, "event_id", "id") or _stable_event_id(raw)),
            "event_time": event_time,
            "ingest_time": ingest_time,
            "source": str(_first(raw, "source", "data_source") or "generic_jsonl"),
            "event_type": event_type,
            "asset_id": _first(raw, "asset_id", "canonical_asset_id"),
            "user_id": _first(raw, "user_id", "canonical_identity_id"),
            "src_ip": _first(raw, "src_ip", "source_ip", "source.address")
            or _nested(raw, "source", "ip"),
            "dst_ip": _first(raw, "dst_ip", "destination_ip", "dest_ip")
            or _nested(raw, "destination", "ip"),
            "dst_port": _first(raw, "dst_port", "port", "destination_port")
            or _nested(raw, "destination", "port"),
            "process_name": _first(raw, "process_name", "process"),
            "command_line": _first(raw, "command_line", "cmdline"),
            "credential_id": _first(raw, "credential_id", "credential"),
            "technique_ids": technique_ids,
            "confidence": confidence,
            "attributes": attributes,
            "raw_event_ref": _first(raw, "raw_event_ref", "raw_id"),
        }
        if normalized["dst_port"] in ("", None):
            normalized["dst_port"] = None
        elif normalized["dst_port"] is not None:
            normalized["dst_port"] = int(normalized["dst_port"])

        for optional_key in (
            "asset_id",
            "user_id",
            "src_ip",
            "dst_ip",
            "process_name",
            "command_line",
            "credential_id",
            "raw_event_ref",
        ):
            if normalized[optional_key] is not None:
                normalized[optional_key] = str(normalized[optional_key])

        return SecurityEvent.model_validate(normalized)

