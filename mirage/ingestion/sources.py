"""Ingestion source abstractions."""

from __future__ import annotations

from typing import Iterator, Protocol

from mirage.domain.schemas import SecurityEvent


class EventSource(Protocol):
    """Synchronous source of canonical security events."""

    def __iter__(self) -> Iterator[SecurityEvent]:
        """Yield canonical events in deterministic source order."""
        ...

