"""Structured logs, metrics, and trace-context helpers."""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from mirage.production.schema import EnvironmentProfile
from mirage.production.secrets import redact


@dataclass(frozen=True)
class TraceContext:
    """Minimal OpenTelemetry-compatible propagation surface."""

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    parent_id: str = ""

    def headers(self) -> dict[str, str]:
        return {
            "traceparent": f"00-{self.trace_id}-0000000000000000-01",
            "x-correlation-id": self.correlation_id,
        }

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> "TraceContext":
        traceparent = headers.get("traceparent", "")
        trace_id = traceparent.split("-")[1] if traceparent.count("-") >= 3 else uuid.uuid4().hex
        return cls(
            trace_id=trace_id,
            correlation_id=headers.get("x-correlation-id", uuid.uuid4().hex),
        )


class StructuredLogger:
    """JSON log builder that redacts sensitive fields."""

    def __init__(self, *, service: str, environment: EnvironmentProfile) -> None:
        self.service = service
        self.environment = environment

    def event(
        self,
        severity: str,
        message: str,
        *,
        tenant: str = "default",
        actor: str = "",
        action_id: str = "",
        trace: TraceContext | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        trace = trace or TraceContext()
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity.upper(),
            "service": self.service,
            "environment": self.environment.value,
            "tenant": tenant,
            "correlation_id": trace.correlation_id,
            "trace_id": trace.trace_id,
            "actor": actor,
            "action_id": action_id,
            "message": message,
            "extra": redact(extra or {}),
        }
        return json.dumps(payload, sort_keys=True)


class MetricsRegistry:
    """Small Prometheus-style metrics registry."""

    def __init__(self) -> None:
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}

    def increment(self, name: str, amount: float = 1.0) -> None:
        self._counters[name] = self._counters.get(name, 0.0) + amount

    def gauge(self, name: str, value: float) -> None:
        self._gauges[name] = value

    def observe(self, name: str, value: float) -> None:
        self._histograms.setdefault(name, []).append(value)

    def time_block(self, name: str) -> "_Timer":
        return _Timer(self, name)

    def snapshot(self) -> dict[str, Any]:
        return {
            "counters": dict(self._counters),
            "gauges": dict(self._gauges),
            "histograms": {
                name: {
                    "count": len(values),
                    "sum": sum(values),
                    "max": max(values) if values else 0.0,
                }
                for name, values in self._histograms.items()
            },
        }

    def render_prometheus(self) -> str:
        lines: list[str] = []
        for name, value in sorted(self._counters.items()):
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")
        for name, value in sorted(self._gauges.items()):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")
        for name, values in sorted(self._histograms.items()):
            lines.append(f"# TYPE {name} summary")
            lines.append(f"{name}_count {len(values)}")
            lines.append(f"{name}_sum {sum(values)}")
        return "\n".join(lines) + ("\n" if lines else "")


class _Timer:
    def __init__(self, registry: MetricsRegistry, name: str) -> None:
        self.registry = registry
        self.name = name
        self.started = 0.0

    def __enter__(self) -> "_Timer":
        self.started = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.registry.observe(self.name, time.perf_counter() - self.started)
