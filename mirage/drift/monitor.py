"""Data, model, and policy drift monitor."""

from __future__ import annotations

from mirage.drift.schema import DriftReport, DriftStatus
from mirage.execution.utils import deterministic_id


class DriftMonitor:
    """Score drift and suspend automatic pilot execution on critical drift."""

    def __init__(self, thresholds: dict[str, float] | None = None) -> None:
        self.thresholds = thresholds or {
            "warning": 0.35,
            "critical": 0.7,
        }

    def evaluate(
        self,
        *,
        data: dict[str, float] | None = None,
        model: dict[str, float] | None = None,
        policy: dict[str, float] | None = None,
    ) -> DriftReport:
        data = data or {}
        model = model or {}
        policy = policy or {}
        all_scores = {**{f"data:{k}": v for k, v in data.items()}, **{f"model:{k}": v for k, v in model.items()}, **{f"policy:{k}": v for k, v in policy.items()}}
        critical = [
            name for name, value in all_scores.items()
            if float(value) >= self.thresholds["critical"]
        ]
        warnings = [
            name for name, value in all_scores.items()
            if self.thresholds["warning"] <= float(value) < self.thresholds["critical"]
        ]
        status = DriftStatus.CRITICAL if critical else DriftStatus.WARNING if warnings else DriftStatus.NORMAL
        return DriftReport(
            report_id=deterministic_id("drift_report", status.value, ",".join(sorted(all_scores))),
            status=status,
            data_drift=data,
            model_drift=model,
            policy_drift=policy,
            warnings=warnings,
            critical_reasons=critical,
            pilot_suspended=status == DriftStatus.CRITICAL,
            shadow_mode_preserved=True,
        )
