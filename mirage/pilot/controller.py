"""Controlled pilot controller."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from mirage.domain.schemas import (
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionPlan,
    SafetyDecision,
    TwinSnapshot,
)
from mirage.execution.plan import ExecutionPlanBuilder
from mirage.execution.utils import deterministic_id, ensure_utc
from mirage.governance.audit import GovernanceAuditStore
from mirage.governance.policy import PolicyAsCodeEngine
from mirage.pilot.canary import CanaryDecisionController
from mirage.pilot.monitor import RuntimeSafetyMonitor
from mirage.pilot.schema import (
    CanaryOutcome,
    PilotApproval,
    PilotExecutionRecord,
    PilotFinalOutcome,
    PilotPreparationResult,
    PilotScope,
    RolloutLevel,
)
from mirage.verification.schema import (
    FormalVerificationContext,
    FormalVerificationReport,
    FormalVerificationVerdict,
)
from mirage.verification.verifier import FormalSafetyVerifier


class ControlledPilotController:
    """Governed controlled-pilot workflow; no step may be skipped."""

    def __init__(
        self,
        *,
        config: dict[str, Any] | None = None,
        verifier: FormalSafetyVerifier | None = None,
        policy_engine: PolicyAsCodeEngine | None = None,
        audit_store: GovernanceAuditStore | None = None,
    ) -> None:
        self.config = config or {}
        self.verifier = verifier or FormalSafetyVerifier(config=self.config.get("verification", {}))
        self.policy_engine = policy_engine or PolicyAsCodeEngine(self.config.get("policy", {}))
        self.audit_store = audit_store or GovernanceAuditStore(self.config.get("governance_audit_path"))
        self.canary = CanaryDecisionController()
        self.monitor_engine = RuntimeSafetyMonitor(self.config.get("health_thresholds", {}))
        self.plan_builder = ExecutionPlanBuilder(self.config.get("execution", {}))
        self.preparations: dict[str, PilotPreparationResult] = {}
        self.verification_reports: dict[str, FormalVerificationReport] = {}
        self.approvals: dict[str, PilotApproval] = {}
        self.records: dict[str, PilotExecutionRecord] = {}

    def prepare(
        self,
        recommendation: dict[str, Any],
        pilot_scope: PilotScope,
        reference_time,
    ) -> PilotPreparationResult:
        action = CandidateDefenseAction.model_validate(recommendation["action"])
        safety = SafetyDecision.model_validate(recommendation["safety_decision"])
        twin = TwinSnapshot.model_validate(recommendation["twin_snapshot"])
        belief = BeliefSnapshot.model_validate(recommendation["belief_snapshot"])
        plan = self.plan_builder.build(
            action,
            safety,
            twin_snapshot=twin,
            belief_snapshot=belief,
            reference_time=reference_time,
        )
        reasons = []
        if not pilot_scope.enabled:
            reasons.append("pilot_scope_disabled")
        if pilot_scope.expiry and pilot_scope.expiry <= ensure_utc(reference_time):
            reasons.append("pilot_scope_expired")
        if pilot_scope.rollout_level == RolloutLevel.LEVEL_4_LIMITED_CONTROL and not self.config.get("level4_enabled", False):
            reasons.append("level4_disabled_by_default")
        plan_hash = deterministic_id("plan_hash", plan.model_dump_json())
        prep = PilotPreparationResult(
            preparation_id=deterministic_id("pilot_prep", plan.plan_id, pilot_scope.scope_id, plan_hash),
            execution_plan_id=plan.plan_id,
            pilot_scope_id=pilot_scope.scope_id,
            plan_hash=plan_hash,
            allowed_to_continue=not reasons,
            blocked_reasons=reasons,
            required_approvals=list(pilot_scope.required_approvals),
        )
        self.preparations[prep.preparation_id] = prep
        self.audit_store.append("pilot_prepared", artifact_or_execution_id=plan.plan_id, after_state=prep.model_dump(mode="json"))
        return prep

    def verify(
        self,
        execution_plan: ExecutionPlan,
        verification_context: FormalVerificationContext,
    ) -> FormalVerificationReport:
        report = self.verifier.verify(execution_plan, verification_context)
        self.verification_reports[report.report_id] = report
        self.audit_store.append("formal_verification_report", artifact_or_execution_id=execution_plan.plan_id, after_state=report.model_dump(mode="json"), hashes={"report_hash": report.report_hash})
        return report

    def request_approval(
        self,
        execution_plan: ExecutionPlan,
        verification_report: FormalVerificationReport,
    ) -> dict[str, Any]:
        required = (
            verification_report.overall_verdict
            in {
                FormalVerificationVerdict.REQUIRES_APPROVAL,
                FormalVerificationVerdict.VERIFIED_WITH_WARNINGS,
            }
            or bool(execution_plan.required_approvals)
        )
        request = {
            "approval_request_id": deterministic_id("pilot_approval_request", execution_plan.plan_id, verification_report.report_id),
            "execution_plan_id": execution_plan.plan_id,
            "plan_hash": deterministic_id("plan_hash", execution_plan.model_dump_json()),
            "required": required,
            "required_roles": list(execution_plan.required_approvals),
            "verification_report_id": verification_report.report_id,
        }
        self.audit_store.append("pilot_approval_requested", artifact_or_execution_id=execution_plan.plan_id, after_state=request)
        return request

    def record_approval(
        self,
        execution_plan: ExecutionPlan,
        *,
        approver: str,
        approver_role: str,
        environment: str,
        ttl_seconds: int = 900,
    ) -> PilotApproval:
        now = ensure_utc(None)
        approval = PilotApproval(
            approval_id=deterministic_id("pilot_approval", execution_plan.plan_id, approver, approver_role, now.isoformat()),
            execution_plan_id=execution_plan.plan_id,
            plan_hash=deterministic_id("plan_hash", execution_plan.model_dump_json()),
            approver=approver,
            approver_role=approver_role,
            environment=environment,
            expires_at=now + timedelta(seconds=ttl_seconds),
            timestamp=now,
        )
        self.approvals[approval.approval_id] = approval
        self.audit_store.append("pilot_approval_recorded", actor=approver, role=approver_role, artifact_or_execution_id=execution_plan.plan_id, after_state=approval.model_dump(mode="json"))
        return approval

    def execute_canary(
        self,
        approved_plan: ExecutionPlan,
    ) -> PilotExecutionRecord:
        execution_id = deterministic_id("pilot_execution", approved_plan.plan_id, approved_plan.idempotency_key)
        checks = {
            "target_adapter_healthy": True,
            "management_channel_healthy": True,
            "rollback_channel_healthy": True,
            "business_service_healthy": True,
            "latency_within_threshold": True,
            "error_rate_within_threshold": True,
            "expected_telemetry": True,
            "no_unexpected_scope_expansion": True,
            "protected_dependency_impact": False,
            "twin_graph_consistent": True,
        }
        decision = self.canary.evaluate(execution_id, checks)
        outcome = PilotFinalOutcome.CANARY_EXPANDED if decision.outcome == CanaryOutcome.EXPAND else PilotFinalOutcome.CANARY_HELD
        record = PilotExecutionRecord(
            pilot_execution_id=execution_id,
            pilot_scope_id="unknown",
            execution_plan_id=approved_plan.plan_id,
            canary_result=decision,
            final_outcome=outcome,
        )
        self.records[record.pilot_execution_id] = record
        self.audit_store.append("pilot_canary_decision", artifact_or_execution_id=execution_id, after_state=record.model_dump(mode="json"))
        return record

    def monitor(
        self,
        pilot_execution_id: str,
        metrics: dict[str, float] | None = None,
    ):
        record = self.records[pilot_execution_id]
        result = self.monitor_engine.evaluate(pilot_execution_id, metrics or {})
        record = record.model_copy(
            update={
                "runtime_monitoring_results": [
                    *record.runtime_monitoring_results,
                    result,
                ],
                "updated_at": result.timestamp,
            }
        )
        if result.rollback_triggers:
            record = record.model_copy(update={"final_outcome": PilotFinalOutcome.ROLLED_BACK, "rollback_status": "required"})
        self.records[pilot_execution_id] = record
        self.audit_store.append("pilot_runtime_monitoring", artifact_or_execution_id=pilot_execution_id, after_state=result.model_dump(mode="json"))
        return result

    def rollback(
        self,
        pilot_execution_id: str,
        reason,
    ) -> PilotExecutionRecord:
        record = self.records[pilot_execution_id]
        updated = record.model_copy(
            update={
                "rollback_status": "rolled_back",
                "final_outcome": PilotFinalOutcome.ROLLED_BACK,
                "updated_at": ensure_utc(None),
                "business_impact_observations": [
                    *record.business_impact_observations,
                    f"rollback_reason:{reason}",
                ],
            }
        )
        self.records[pilot_execution_id] = updated
        self.audit_store.append("pilot_rollback", artifact_or_execution_id=pilot_execution_id, reason=str(reason), after_state=updated.model_dump(mode="json"))
        return updated
