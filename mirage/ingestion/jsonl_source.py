"""Streaming JSONL event source for deterministic local replay."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from pydantic import ValidationError

from mirage.domain.schemas import SecurityEvent
from mirage.ingestion.normalizer import EventNormalizer


@dataclass(frozen=True)
class InvalidEventRecord:
    """Invalid JSONL line captured in tolerant mode."""

    line_number: int
    error: str
    raw_line: str


class JSONLEventSource:
    """Stream one JSON object per line and validate as SecurityEvent."""

    def __init__(
        self,
        path: str | Path,
        *,
        normalizer: EventNormalizer | None = None,
        strict: bool = False,
    ) -> None:
        self.path = Path(path)
        self.normalizer = normalizer or EventNormalizer()
        self.strict = strict
        self.errors: list[InvalidEventRecord] = []
        self.last_line_number = 0

    def __iter__(self) -> Iterator[SecurityEvent]:
        """Yield valid events without loading the entire JSONL file."""
        self.errors.clear()
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                self.last_line_number = line_number
                raw_line = line.rstrip("\n")
                if not raw_line.strip():
                    continue
                try:
                    raw = json.loads(raw_line)
                    event = self.normalizer.normalize(raw)
                except (json.JSONDecodeError, TypeError, ValueError, ValidationError) as exc:
                    invalid = InvalidEventRecord(
                        line_number=line_number,
                        error=str(exc),
                        raw_line=raw_line,
                    )
                    if self.strict:
                        raise ValueError(
                            f"Invalid event at {self.path}:{line_number}: {exc}"
                        ) from exc
                    self.errors.append(invalid)
                    continue
                yield event
