"""Local ingestion adapters and normalizers for canonical MIRAGE events."""

from mirage.ingestion.jsonl_source import InvalidEventRecord, JSONLEventSource
from mirage.ingestion.normalizer import EventNormalizer
from mirage.ingestion.sources import EventSource

__all__ = [
    "EventNormalizer",
    "EventSource",
    "InvalidEventRecord",
    "JSONLEventSource",
]

