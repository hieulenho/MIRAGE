"""Canary decision controller."""

from __future__ import annotations

from mirage.pilot.schema import CanaryDecision, CanaryOutcome


class CanaryDecisionController:
    """Decide whether canary evidence permits expansion."""

    def evaluate(self, execution_id: str, checks: dict[str, bool | None]) -> CanaryDecision:
        missing = [name for name, value in checks.items() if value is None]
        bad_when_true = {"protected_dependency_impact", "unexpected_scope_expansion"}
        failed = [
            name for name, value in checks.items()
            if (
                (name in bad_when_true and value is True)
                or (name not in bad_when_true and value is False)
            )
        ]
        if missing:
            return CanaryDecision(
                execution_id=execution_id,
                outcome=CanaryOutcome.REQUIRE_ANALYST,
                checks={key: bool(value) for key, value in checks.items() if value is not None},
                reasons=[f"incomplete_monitoring:{name}" for name in missing],
            )
        rollback_checks = {
            "protected_dependency_impact",
            "unexpected_scope_expansion",
            "business_service_healthy",
            "management_channel_healthy",
            "rollback_channel_healthy",
            "no_unexpected_scope_expansion",
        }
        if any(name in rollback_checks for name in failed):
            return CanaryDecision(
                execution_id=execution_id,
                outcome=CanaryOutcome.ROLLBACK,
                checks={key: bool(value) for key, value in checks.items()},
                reasons=[f"failed:{name}" for name in failed],
            )
        if failed:
            return CanaryDecision(
                execution_id=execution_id,
                outcome=CanaryOutcome.HOLD,
                checks={key: bool(value) for key, value in checks.items()},
                reasons=[f"failed:{name}" for name in failed],
            )
        return CanaryDecision(
            execution_id=execution_id,
            outcome=CanaryOutcome.EXPAND,
            checks={key: bool(value) for key, value in checks.items()},
            reasons=["all_canary_checks_passed"],
        )
