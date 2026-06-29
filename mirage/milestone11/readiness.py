"""SLO, capacity, maturity, and readiness decision services."""

from __future__ import annotations

from typing import Any

from mirage.config import load_config
from mirage.execution.utils import deterministic_id
from mirage.milestone11.assurance import ContinuousAssuranceService
from mirage.milestone11.inventory import InventoryScanner
from mirage.milestone11.schema import (
    CapacityReport,
    ImplementationStatus,
    MaturityReport,
    ReadinessDecision,
    ReadinessEvaluationRequest,
    ReadinessVerdict,
    SLOReport,
)
from mirage.milestone11.validation import ValidationService


class SLOService:
    """Calculate SLO compliance and error-budget state."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config if config is not None else load_config()
        self._reports: list[SLOReport] = []

    def report(self, metrics: dict[str, float] | None = None, period_seconds: int = 3600) -> SLOReport:
        """Create an SLO report from supplied or default metrics."""
        targets = {
            "api_availability": 0.99,
            "event_ingestion_success": 0.995,
            "audit_write_success": 0.999,
            "rollback_success": 0.99,
            "twin_freshness": 0.95,
        }
        targets.update(self.config.get("slo", {}).get("targets", {}))
        values = {
            "api_availability": 0.995,
            "event_ingestion_success": 1.0,
            "audit_write_success": 1.0,
            "rollback_success": 1.0,
            "twin_freshness": 0.98,
        }
        values.update(metrics or {})
        compliance = {
            key: float(values.get(key, 0.0)) >= float(target)
            for key, target in targets.items()
        }
        error_budget_remaining = {
            key: round(max(0.0, float(values.get(key, 0.0)) - float(target)), 6)
            for key, target in targets.items()
        }
        exhausted = sorted([key for key, ok in compliance.items() if not ok])
        report = SLOReport(
            report_id=deterministic_id("slo", values, targets, period_seconds),
            period_seconds=period_seconds,
            sli_values=values,
            targets=targets,
            compliance=compliance,
            error_budget_remaining=error_budget_remaining,
            exhausted_budgets=exhausted,
            release_blocked=bool(exhausted),
        )
        self._reports.append(report)
        return report

    def reports(self) -> dict[str, Any]:
        if not self._reports:
            self.report()
        return {"reports": [report.model_dump(mode="json") for report in self._reports]}

    def error_budgets(self) -> dict[str, Any]:
        latest = self._reports[-1] if self._reports else self.report()
        return {
            "report_id": latest.report_id,
            "error_budget_remaining": latest.error_budget_remaining,
            "exhausted_budgets": latest.exhausted_budgets,
            "release_blocked": latest.release_blocked,
        }


class CapacityPlanner:
    """Generate measured-vs-projected capacity reports."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config if config is not None else load_config()
        self._last_report: CapacityReport | None = None

    def report(self, measured: dict[str, float] | None = None) -> CapacityReport:
        thresholds = {
            "event_rate_eps": 1000.0,
            "broker_lag_messages": 10000.0,
            "worker_saturation": 0.85,
            "storage_growth_mb_per_day": 10240.0,
            "database_load": 0.80,
        }
        thresholds.update(self.config.get("capacity", {}).get("thresholds", {}))
        values = {
            "event_rate_eps": 100.0,
            "broker_lag_messages": 0.0,
            "worker_saturation": 0.25,
            "storage_growth_mb_per_day": 512.0,
            "database_load": 0.20,
        }
        values.update(measured or {})
        projected = {
            "event_rate_eps_3_sites": values["event_rate_eps"] * 3,
            "event_rate_eps_10_sites": values["event_rate_eps"] * 10,
            "storage_growth_mb_per_day_10_sites": values["storage_growth_mb_per_day"] * 10,
        }
        saturation = sorted(
            key for key, threshold in thresholds.items() if float(values.get(key, 0.0)) >= float(threshold)
        )
        recommendations = []
        if saturation:
            recommendations.append("apply backpressure and scale workers before expanding deployment")
        if projected["event_rate_eps_10_sites"] > thresholds["event_rate_eps"]:
            recommendations.append("10-site profile is projected beyond current event-rate threshold")
        report = CapacityReport(
            report_id=deterministic_id("capacity", values, projected, thresholds),
            measured=values,
            projected=projected,
            thresholds=thresholds,
            saturation=saturation,
            recommendations=recommendations,
            limitations=[
                "synthetic defaults are not enterprise-scale proof",
                "projected values are linear extrapolations unless measured values are supplied",
            ],
        )
        self._last_report = report
        return report


class MaturityAssessor:
    """Compute evidence-backed operational maturity."""

    STATUS_SCORES = {
        ImplementationStatus.IMPLEMENTED: 1.0,
        ImplementationStatus.PARTIAL: 0.55,
        ImplementationStatus.MOCK_ONLY: 0.25,
        ImplementationStatus.TEST_ONLY: 0.20,
        ImplementationStatus.DOCUMENTED_ONLY: 0.15,
        ImplementationStatus.STUB: 0.10,
        ImplementationStatus.DEPRECATED: 0.10,
        ImplementationStatus.BROKEN: 0.0,
        ImplementationStatus.NOT_FOUND: 0.0,
    }

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        assurance: ContinuousAssuranceService | None = None,
    ) -> None:
        self.config = config if config is not None else load_config()
        self.assurance = assurance or ContinuousAssuranceService(self.config)

    def assess(self) -> MaturityReport:
        inventory = InventoryScanner(config=self.config).scan()
        groups: dict[str, list[float]] = {}
        evidence: dict[str, list[str]] = {}
        blockers: list[str] = []
        for capability in inventory.capabilities:
            score = self.STATUS_SCORES[capability.implementation_status]
            groups.setdefault(capability.architecture_layer, []).append(score)
            evidence.setdefault(capability.architecture_layer, []).extend(capability.source_files[:3])
            if capability.implementation_status in {
                ImplementationStatus.BROKEN,
                ImplementationStatus.STUB,
                ImplementationStatus.NOT_FOUND,
            }:
                blockers.append(f"{capability.capability_id}: {capability.implementation_status.value}")
        category_scores = {
            layer: round(sum(scores) / len(scores), 3)
            for layer, scores in sorted(groups.items())
            if scores
        }
        overall = round(sum(category_scores.values()) / max(1, len(category_scores)), 3)
        latest = self.assurance.latest_bundle()
        if latest and latest.readiness_blocked:
            overall = min(overall, 0.49)
            blockers.append("latest assurance bundle blocks readiness")
        remediation = [
            "remediate BROKEN/STUB/NOT_FOUND safety and assurance capabilities first",
            "add runtime validation evidence for PARTIAL capabilities",
            "keep mock-only adapters out of production documentation",
        ]
        return MaturityReport(
            report_id=deterministic_id("maturity", category_scores, blockers),
            overall_score=overall,
            category_scores=category_scores,
            evidence={key: sorted(set(paths))[:10] for key, paths in evidence.items()},
            blockers=sorted(set(blockers)),
            recommended_remediation=remediation,
        )


class ReadinessBoard:
    """Deterministic operational readiness decision board."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        assurance: ContinuousAssuranceService | None = None,
        validation: ValidationService | None = None,
        slo: SLOService | None = None,
        maturity: MaturityAssessor | None = None,
    ) -> None:
        self.config = config if config is not None else load_config()
        self.assurance = assurance or ContinuousAssuranceService(self.config)
        self.validation = validation or ValidationService(self.config)
        self.slo = slo or SLOService(self.config)
        self.maturity = maturity or MaturityAssessor(self.config, assurance=self.assurance)
        self._latest: ReadinessDecision | None = None

    def evaluate(
        self,
        request: ReadinessEvaluationRequest | None = None,
    ) -> ReadinessDecision:
        """Evaluate readiness without raising deployment level."""
        request = request or ReadinessEvaluationRequest()
        reasons: list[str] = []
        remediation: list[str] = []
        latest_bundle = self.assurance.latest_bundle()
        maturity = self.maturity.assess()
        slo_report = self.slo.report()

        if request.require_recent_assurance and latest_bundle is None:
            reasons.append("no recent assurance bundle")
            remediation.append("run continuous assurance")
        if latest_bundle and latest_bundle.readiness_blocked:
            reasons.append("latest assurance bundle blocks readiness")
            remediation.append("remediate critical assurance failures")
        if request.require_soak_success and not self.validation.latest_success("soak"):
            reasons.append("no successful soak validation result")
            remediation.append("run CI-bounded soak validation")
        if request.require_chaos_success and not self.validation.latest_success("chaos"):
            reasons.append("no successful chaos validation result")
            remediation.append("run required chaos validation")
        if slo_report.release_blocked:
            reasons.append("SLO error budget exhausted")
            remediation.append("restore SLO compliance before release")
        if maturity.blockers:
            reasons.append("maturity blockers present")
            remediation.extend(maturity.recommended_remediation)

        target = request.target_deployment_level
        threshold = float(self.config.get("readiness", {}).get("maturity_threshold", 0.8))
        if target != "SHADOW_ONLY" and maturity.overall_score < threshold:
            reasons.append(f"maturity score {maturity.overall_score} is below threshold {threshold}")
        if target != "SHADOW_ONLY" and reasons:
            verdict = ReadinessVerdict.RETURN_TO_SHADOW_MODE
        elif target == "SHADOW_ONLY" and reasons:
            verdict = ReadinessVerdict.INSUFFICIENT_EVIDENCE
        elif target == "SHADOW_ONLY":
            verdict = ReadinessVerdict.RETURN_TO_SHADOW_MODE
            reasons.append("shadow mode remains the safe default")
        else:
            verdict = ReadinessVerdict.SUSTAINED_LIMITED_DEPLOYMENT

        decision = ReadinessDecision(
            decision_id=deterministic_id("readiness", target, reasons, remediation, maturity.overall_score),
            verdict=verdict,
            target_deployment_level=target,
            maturity_score=maturity.overall_score,
            reasons=sorted(set(reasons)),
            required_remediation=sorted(set(remediation)),
        )
        self._latest = decision
        return decision

    def latest(self) -> ReadinessDecision | None:
        """Return the latest readiness decision."""
        return self._latest


class OperationalMaturityService:
    """Facade used by CLI and API routes."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config if config is not None else load_config()
        self.assurance = ContinuousAssuranceService(self.config)
        self.validation = ValidationService(self.config)
        self.slo = SLOService(self.config)
        self.capacity = CapacityPlanner(self.config)
        self.maturity = MaturityAssessor(self.config, assurance=self.assurance)
        self.readiness = ReadinessBoard(
            self.config,
            assurance=self.assurance,
            validation=self.validation,
            slo=self.slo,
            maturity=self.maturity,
        )
