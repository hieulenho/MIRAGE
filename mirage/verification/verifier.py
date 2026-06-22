"""Aggregate formal safety verifier."""

from __future__ import annotations

import time
from typing import Iterable

from mirage.domain.schemas import SafetyVerdict
from mirage.execution.utils import action_tier, deterministic_id
from mirage.verification.blast_radius import BlastRadiusVerifier
from mirage.verification.invariants import SafetySpecificationRegistry
from mirage.verification.reachability import ReachabilityVerifier
from mirage.verification.rollback import RollbackVerifier
from mirage.verification.schema import (
    FormalVerificationContext,
    FormalVerificationReport,
    FormalVerificationVerdict,
    SafetyInvariant,
    VerificationFinding,
    VerificationResult,
    VerificationSeverity,
    canonical_hash,
    utc_now,
)
from mirage.verification.solver import (
    ConstraintSolverBackend,
    DeterministicConstraintSolverBackend,
)
from mirage.verification.temporal import TemporalLifecycleVerifier


class FormalSafetyVerifier:
    """Combine static, graph, solver, rollback, and temporal verification."""

    version = "formal-safety-verifier-v1"

    def __init__(
        self,
        *,
        registry: SafetySpecificationRegistry | None = None,
        solver: ConstraintSolverBackend | None = None,
        config: dict | None = None,
    ) -> None:
        self.registry = registry or SafetySpecificationRegistry()
        self.solver = solver or DeterministicConstraintSolverBackend(
            timeout_ms=int((config or {}).get("solver_timeout_ms", 50))
        )
        self.config = config or {}
        self.reachability = ReachabilityVerifier()
        self.blast_radius = BlastRadiusVerifier()
        self.rollback = RollbackVerifier()
        self.temporal = TemporalLifecycleVerifier()

    def verify(
        self,
        execution_plan,
        verification_context: FormalVerificationContext,
        invariants: Iterable[SafetyInvariant] | None = None,
    ) -> FormalVerificationReport:
        """Verify one execution plan against bounded safety invariants."""
        start = time.perf_counter()
        selected = list(invariants or self.registry.list_invariants())
        findings: list[VerificationFinding] = []
        for invariant in selected:
            findings.extend(self._evaluate_invariant(invariant, verification_context))
        proven = sum(1 for finding in findings if finding.result == VerificationResult.PROVEN)
        violated = sum(1 for finding in findings if finding.result == VerificationResult.VIOLATED)
        unknown = sum(1 for finding in findings if finding.result == VerificationResult.UNKNOWN)
        verdict = self._overall_verdict(findings, verification_context)
        duration = round((time.perf_counter() - start) * 1000.0, 3)
        report_id = deterministic_id(
            "formal_report",
            execution_plan.plan_id,
            verification_context.plan_hash,
            verdict.value,
            canonical_hash([finding.model_dump(mode="json") for finding in findings]),
        )
        payload = {
            "report_id": report_id,
            "plan_id": execution_plan.plan_id,
            "findings": [finding.model_dump(mode="json") for finding in findings],
            "verdict": verdict.value,
        }
        return FormalVerificationReport(
            report_id=report_id,
            execution_plan_id=execution_plan.plan_id,
            source_action_id=execution_plan.source_action_id,
            twin_version=str(verification_context.twin_snapshot.twin_version),
            graph_version=execution_plan.graph_version,
            belief_version=execution_plan.belief_version,
            analysis_id=execution_plan.analysis_id,
            model_versions=verification_context.artifact_hashes,
            policy_versions={
                verification_context.selected_policy_id: verification_context.selected_policy_version
            }
            if verification_context.selected_policy_id
            else {},
            safety_policy_version=execution_plan.policy_version,
            invariants_evaluated=[item.invariant_id for item in selected],
            findings=findings,
            proven_count=proven,
            violated_count=violated,
            unknown_count=unknown,
            overall_verdict=verdict,
            counterexamples=[finding.counterexample for finding in findings if finding.counterexample],
            assumptions=verification_context.assumptions,
            verifier_versions={
                "formal": self.version,
                "reachability": self.reachability.version,
                "rollback": self.rollback.version,
                "temporal": self.temporal.version,
            },
            verification_duration_ms=duration,
            report_hash=canonical_hash(payload),
            generated_at=utc_now(),
        )

    def _evaluate_invariant(
        self,
        invariant: SafetyInvariant,
        context: FormalVerificationContext,
    ) -> list[VerificationFinding]:
        plan = context.execution_plan
        action = context.action
        if invariant.invariant_id == "INV-001":
            return [self._protected_asset(context)]
        if invariant.invariant_id == "INV-002":
            return self.reachability.verify(
                plan,
                context.twin_snapshot,
                context.dependency_graph,
                management_sources=context.pilot_scope.get("management_channels", ["soc-control-plane"]),
                rollback_sources=context.pilot_scope.get("rollback_channels", ["rollback-controller"]),
                protected_assets=context.pilot_scope.get("excluded_protected_assets", []),
            )[:2]
        if invariant.invariant_id == "INV-003":
            return self.reachability.verify(plan, context.twin_snapshot, context.dependency_graph)[2:3]
        if invariant.invariant_id == "INV-004":
            estimate = self.blast_radius.estimate(
                plan,
                context.twin_snapshot,
                context.dependency_graph,
                limits=context.pilot_scope,
            )
            if estimate.limit_violations:
                return [self._finding("INV-004", VerificationResult.VIOLATED, VerificationSeverity.HIGH, ", ".join(estimate.limit_violations), estimate.directly_affected_entities + estimate.indirectly_affected_entities)]
            result = VerificationResult.UNKNOWN if estimate.missing_dependency_warnings else VerificationResult.PROVEN
            return [self._finding("INV-004", result, VerificationSeverity.MEDIUM, "Blast radius estimate computed.", estimate.directly_affected_entities)]
        if invariant.invariant_id == "INV-005":
            return [self.rollback.verify(plan, medium_or_high=action_tier(action.action_type, {}) >= 1)]
        if invariant.invariant_id == "INV-006":
            return [self._pilot_scope(context)]
        if invariant.invariant_id == "INV-007":
            return [self._bool_finding("INV-007", context.action_mask.allowed, "Action Mask blocks execution.")]
        if invariant.invariant_id == "INV-008":
            required = bool(plan.required_approvals or action.requires_approval or context.action_mask.approval_required)
            return [self._approval(context, required)]
        if invariant.invariant_id == "INV-009":
            return [self._bool_finding("INV-009", not context.kill_switch_active, "Kill switch blocks new execution.")]
        if invariant.invariant_id == "INV-010":
            ok = (
                context.twin_snapshot.freshness_score >= float(self.config.get("minimum_twin_freshness", 0.35))
                and context.twin_snapshot.coverage_score >= float(self.config.get("minimum_twin_coverage", 0.2))
            )
            return [self._bool_finding("INV-010", ok, "Twin quality below automation threshold.")]
        if invariant.invariant_id == "INV-011":
            return [self._bool_finding("INV-011", bool(plan.ttl_seconds), "TTL is mandatory for temporary pilot action.")]
        if invariant.invariant_id == "INV-012":
            return [self._provenance(context)]
        if invariant.invariant_id == "INV-013":
            missing = [target for target in plan.allowed_scope if target not in context.dependency_graph]
            if missing:
                return [self._finding("INV-013", VerificationResult.UNKNOWN, VerificationSeverity.MEDIUM, "Missing dependency information.", missing)]
            return [self._finding("INV-013", VerificationResult.PROVEN, VerificationSeverity.INFO, "Dependencies observed.", [])]
        if invariant.invariant_id == "INV-014":
            return [self._finding("INV-014", VerificationResult.PROVEN, VerificationSeverity.INFO, "Runtime health gates registered; evaluated during canary/monitoring.", [])]
        if invariant.invariant_id == "INV-015":
            ok = context.model_uncertainty <= float(self.config.get("maximum_model_uncertainty", 0.65)) and not context.ood_warnings
            return [self._bool_finding("INV-015", ok, "Model uncertainty, OOD, or unsupported action prevents automatic execution.")]
        return [self._finding(invariant.invariant_id, VerificationResult.NOT_APPLICABLE, VerificationSeverity.INFO, "Invariant not applicable.", [])]

    def _protected_asset(self, context: FormalVerificationContext) -> VerificationFinding:
        protected = set(context.pilot_scope.get("excluded_protected_assets", []))
        for asset in context.twin_snapshot.assets.values():
            if asset.attributes.get("protected") or asset.business_criticality >= 0.85 or asset.asset_type in {"database", "dc", "domain_controller"}:
                protected.add(asset.asset_id)
        affected = sorted(set(context.execution_plan.allowed_scope or context.execution_plan.targets).intersection(protected))
        if affected and not context.approvals:
            return self._finding("INV-001", VerificationResult.VIOLATED, VerificationSeverity.CRITICAL, "Protected asset would be automatically modified.", affected)
        return self._finding("INV-001", VerificationResult.PROVEN, VerificationSeverity.INFO, "No unapproved protected asset modification.", affected)

    def _pilot_scope(self, context: FormalVerificationContext) -> VerificationFinding:
        scope = context.pilot_scope
        if not scope or not scope.get("enabled", False):
            return self._finding("INV-006", VerificationResult.VIOLATED, VerificationSeverity.CRITICAL, "No enabled pilot scope.", [])
        allowed_actions = set(scope.get("allowed_action_types", []))
        allowed_assets = set(scope.get("allowed_asset_ids", []))
        targets = set(context.execution_plan.allowed_scope or context.execution_plan.targets)
        if context.action.action_type not in allowed_actions:
            return self._finding("INV-006", VerificationResult.VIOLATED, VerificationSeverity.CRITICAL, "Action type outside pilot scope.", [context.action.action_type])
        if not targets.issubset(allowed_assets):
            return self._finding("INV-006", VerificationResult.VIOLATED, VerificationSeverity.CRITICAL, "Target outside pilot scope.", sorted(targets - allowed_assets))
        return self._finding("INV-006", VerificationResult.PROVEN, VerificationSeverity.INFO, "Action remains inside pilot scope.", sorted(targets))

    def _approval(self, context: FormalVerificationContext, required: bool) -> VerificationFinding:
        if not required:
            return self._finding("INV-008", VerificationResult.NOT_APPLICABLE, VerificationSeverity.INFO, "Approval not required.", [])
        plan_hash = context.plan_hash
        valid = any(item.get("decision") == "APPROVED" and item.get("plan_hash") == plan_hash and item.get("valid", True) for item in context.approvals)
        return self._bool_finding("INV-008", valid, "Required approval is missing, expired, or tied to a different plan hash.")

    def _provenance(self, context: FormalVerificationContext) -> VerificationFinding:
        required = {
            "action_mask": context.action_mask.action_id,
            "safety_policy": context.execution_plan.policy_version,
            "plan_hash": context.plan_hash,
        }
        missing = [key for key, value in required.items() if not value]
        if context.safety_decision is None:
            missing.append("safety_decision")
        if missing:
            return self._finding("INV-012", VerificationResult.VIOLATED, VerificationSeverity.HIGH, "Missing provenance: " + ", ".join(missing), missing)
        return self._finding("INV-012", VerificationResult.PROVEN, VerificationSeverity.INFO, "Decision provenance is complete.", [])

    def _bool_finding(self, invariant_id: str, ok: bool, violation_text: str) -> VerificationFinding:
        return self._finding(
            invariant_id,
            VerificationResult.PROVEN if ok else VerificationResult.VIOLATED,
            VerificationSeverity.INFO if ok else VerificationSeverity.CRITICAL,
            "Invariant proven." if ok else violation_text,
            [],
        )

    def _finding(
        self,
        invariant_id: str,
        result: VerificationResult,
        severity: VerificationSeverity,
        explanation: str,
        affected: list[str],
    ) -> VerificationFinding:
        return VerificationFinding(
            finding_id=deterministic_id("finding", invariant_id, result.value, explanation, ",".join(affected)),
            invariant_id=invariant_id,
            result=result,
            severity=severity,
            affected_entities=affected,
            explanation=explanation,
            verifier_name="FormalSafetyVerifier",
            verifier_version=self.version,
            confidence=1.0 if result != VerificationResult.UNKNOWN else 0.35,
            timestamp=utc_now(),
        )

    def _overall_verdict(
        self,
        findings: list[VerificationFinding],
        context: FormalVerificationContext,
    ) -> FormalVerificationVerdict:
        if any(finding.result == VerificationResult.VIOLATED and finding.severity in {VerificationSeverity.HIGH, VerificationSeverity.CRITICAL} for finding in findings):
            return FormalVerificationVerdict.REJECTED
        if any(finding.result == VerificationResult.UNKNOWN for finding in findings):
            return FormalVerificationVerdict.INCONCLUSIVE
        if context.safety_decision and context.safety_decision.verdict == SafetyVerdict.REQUIRE_APPROVAL:
            return FormalVerificationVerdict.REQUIRES_APPROVAL
        if any(finding.result == VerificationResult.VIOLATED for finding in findings):
            return FormalVerificationVerdict.REQUIRES_APPROVAL
        if any(finding.severity in {VerificationSeverity.MEDIUM, VerificationSeverity.HIGH} for finding in findings):
            return FormalVerificationVerdict.VERIFIED_WITH_WARNINGS
        return FormalVerificationVerdict.VERIFIED
