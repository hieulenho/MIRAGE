"""Production health, readiness, and dependency checks."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mirage.production.config import validate_production_config
from mirage.production.schema import (
    DependencyCheckResult,
    DependencyStatus,
    EnvironmentProfile,
    HealthReport,
)


DependencyCheck = Callable[[], bool]


class DependencyChecker:
    """Public-safe dependency readiness checker."""

    def __init__(self, checks: dict[str, DependencyCheck] | None = None) -> None:
        self.checks = checks or {}

    def check_all(self) -> list[DependencyCheckResult]:
        results: list[DependencyCheckResult] = []
        for name, check in sorted(self.checks.items()):
            try:
                ok = bool(check())
            except Exception:
                ok = False
            results.append(
                DependencyCheckResult(
                    name=name,
                    status=DependencyStatus.OK if ok else DependencyStatus.UNAVAILABLE,
                    public_message="available" if ok else "unavailable",
                )
            )
        return results


def build_health_report(
    config: dict[str, Any],
    *,
    dependencies: DependencyChecker | None = None,
) -> HealthReport:
    """Build live/ready status without exposing sensitive dependency details."""
    security = validate_production_config(config)
    checks = (dependencies or DependencyChecker()).check_all()
    ready = security.valid and all(result.status == DependencyStatus.OK for result in checks)
    return HealthReport(
        live=True,
        ready=ready,
        profile=security.profile if security else EnvironmentProfile.SHADOW,
        dependencies=checks,
        security=security,
    )
