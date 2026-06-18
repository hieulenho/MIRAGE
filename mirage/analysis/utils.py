"""Shared helpers for deterministic attack analysis."""

from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Iterable

from mirage.detection.utils import canonical_entity_type, clamp01, stable_id


def analysis_time(value: datetime | None, fallback: datetime) -> datetime:
    """Return a timezone-aware UTC reference timestamp."""
    raw = value or fallback
    if raw.tzinfo is None or raw.utcoffset() is None:
        raw = raw.replace(tzinfo=timezone.utc)
    return raw.astimezone(timezone.utc)


def mean(values: Iterable[float], default: float = 0.0) -> float:
    """Return deterministic arithmetic mean."""
    items = [float(value) for value in values]
    return sum(items) / len(items) if items else default


def recency_score(reference_time: datetime, last_seen: datetime, horizon_seconds: float) -> float:
    """Map age to [0, 1], where 1 is recent and 0 is stale."""
    age = max(0.0, (reference_time - last_seen).total_seconds())
    if horizon_seconds <= 0:
        return 1.0
    return clamp01(math.exp(-age / horizon_seconds))


def entity_label(entity_id: str) -> str:
    """Return compact label for a canonical entity ID."""
    for prefix in ("asset:host:", "asset:ip:", "identity:user:", "credential:"):
        if entity_id.startswith(prefix):
            return entity_id.removeprefix(prefix)
    return entity_id


__all__ = [
    "analysis_time",
    "canonical_entity_type",
    "clamp01",
    "entity_label",
    "mean",
    "recency_score",
    "stable_id",
]
