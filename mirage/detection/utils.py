"""Shared helpers for contextual detection."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
from datetime import datetime
from typing import Iterable

from mirage.domain.schemas import STAGE_NAMES_V1, SecurityEvent


def slug(value: str) -> str:
    """Return a stable lowercase ID-safe slug."""
    cleaned = re.sub(r"[^a-z0-9_.:-]+", "-", value.strip().lower())
    return cleaned.strip("-") or "unknown"


def stable_id(prefix: str, parts: Iterable[object]) -> str:
    """Create deterministic compact IDs from ordered parts."""
    payload = "|".join(str(part) for part in parts)
    digest = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}:{digest}"


def clamp01(value: float) -> float:
    """Clamp finite numeric value into [0, 1]."""
    if not math.isfinite(value):
        return 0.0
    return min(1.0, max(0.0, value))


def is_internal_ip(value: str | None) -> bool:
    """Return whether an IP string is private/internal."""
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def normalized_stage_distribution(
    scores: dict[str, float] | None = None,
    *,
    default_stage: str = "normal",
) -> dict[str, float]:
    """Normalize a partial stage score map across all supported stages."""
    values = {stage: 0.0 for stage in STAGE_NAMES_V1}
    if scores:
        for stage, value in scores.items():
            if stage in values:
                values[stage] = max(0.0, float(value))
    total = sum(values.values())
    if total <= 0:
        values[default_stage] = 1.0
        return values
    return {stage: value / total for stage, value in values.items()}


def entropy_uncertainty(distribution: dict[str, float]) -> float:
    """Calculate normalized entropy as uncertainty in [0, 1]."""
    positives = [value for value in distribution.values() if value > 0]
    if not positives:
        return 1.0
    entropy = -sum(value * math.log(value) for value in positives)
    return clamp01(entropy / math.log(max(2, len(distribution))))


def event_entity_ids(event: SecurityEvent) -> list[str]:
    """Extract deterministic entity IDs touched by a canonical event."""
    attrs = event.attributes
    ids: set[str] = set()
    if event.asset_id:
        ids.add(event.asset_id)
    if event.user_id:
        ids.add(event.user_id)
    if event.credential_id:
        ids.add(
            event.credential_id
            if event.credential_id.startswith("credential:")
            else f"credential:{event.credential_id}"
        )
    if event.src_ip:
        ids.add(f"asset:ip:{slug(event.src_ip)}")
    if event.dst_ip:
        ids.add(f"asset:ip:{slug(event.dst_ip)}")
    for key, prefix in (
        ("hostname", "asset:host"),
        ("src_hostname", "asset:host"),
        ("dst_hostname", "asset:host"),
        ("user", "identity:user"),
        ("username", "identity:user"),
    ):
        value = attrs.get(key)
        if value:
            ids.add(f"{prefix}:{slug(str(value))}")
    if event.src_ip and event.dst_ip:
        ids.add(f"comm:{slug(event.src_ip)}->{slug(event.dst_ip)}")
    session_id = attrs.get("session_id")
    if session_id:
        ids.add(f"session:{slug(str(session_id))}")
    incident_id = attrs.get("incident_id")
    if incident_id:
        ids.add(f"incident:{slug(str(incident_id))}")
    return sorted(ids)


def canonical_entity_type(entity_id: str) -> str:
    """Infer a broad entity type from a canonical entity ID."""
    if entity_id.startswith("asset:"):
        return "asset"
    if entity_id.startswith("identity:"):
        return "identity"
    if entity_id.startswith("credential:"):
        return "credential"
    if entity_id.startswith("comm:"):
        return "communication"
    if entity_id.startswith("session:"):
        return "session"
    if entity_id.startswith("incident:"):
        return "incident"
    return "derived"


def seconds_between(reference_time: datetime, event_time: datetime) -> float:
    """Return non-negative seconds between reference and event time."""
    return max(0.0, (reference_time - event_time).total_seconds())
