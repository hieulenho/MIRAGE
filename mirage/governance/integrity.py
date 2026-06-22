"""Artifact integrity helpers."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_json(value: Any) -> str:
    """Return a canonical SHA-256 hash."""
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def verify_hash(value: Any, expected_hash: str) -> bool:
    """Return whether a value matches an expected hash."""
    return sha256_json(value) == expected_hash
