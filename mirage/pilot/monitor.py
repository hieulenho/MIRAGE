"""Runtime safety monitor for pilot actions."""

from __future__ import annotations

from mirage.pilot.schema import RuntimeMonitoringResult, RuntimeMonitorStatus


class RuntimeSafetyMonitor:
    """Evaluate continuous pilot safety metrics."""

    def __init__(self, thresholds: dict[str, float] | None = None) -> None:
        self.thresholds = thresholds or {
            "availability_min": 0.99,
            "latency_ms_max": 500.0,
            "error_rate_max": 0.02,
            "health_success_min": 0.99,
        }

    def evaluate(
        self,
        pilot_execution_id: str,
        metrics: dict[str, float],
        *,
        protected_asset_affected: bool = False,
        management_channel_lost: bool = False,
        rollback_channel_at_risk: bool = False,
        scope_expanded: bool = False,
        kill_switch_active: bool = False,
        policy_suspended: bool = False,
    ) -> RuntimeMonitoringResult:
        triggers: list[str] = []
        if protected_asset_affected:
            triggers.append("protected_asset_affected")
        if management_channel_lost:
            triggers.append("management_channel_lost")
        if rollback_channel_at_risk:
            triggers.append("rollback_channel_at_risk")
        if scope_expanded:
            triggers.append("unexpected_scope_expansion")
        if kill_switch_active:
            triggers.append("kill_switch_active")
        if policy_suspended:
            triggers.append("policy_suspended")
        if metrics.get("availability", 1.0) < self.thresholds["availability_min"]:
            triggers.append("availability_below_threshold")
        if metrics.get("latency_ms", 0.0) > self.thresholds["latency_ms_max"]:
            triggers.append("latency_above_threshold")
        if metrics.get("error_rate", 0.0) > self.thresholds["error_rate_max"]:
            triggers.append("error_rate_above_threshold")
        if metrics.get("health_success", 1.0) < self.thresholds["health_success_min"]:
            triggers.append("health_success_below_threshold")
        status = RuntimeMonitorStatus.NORMAL
        if triggers:
            status = RuntimeMonitorStatus.ROLLBACK_REQUIRED
        return RuntimeMonitoringResult(
            pilot_execution_id=pilot_execution_id,
            status=status,
            metrics=metrics,
            rollback_triggers=triggers,
            evidence=[f"metric:{key}={value}" for key, value in sorted(metrics.items())],
        )
