"""Deception orchestrator, rollback, verification, and TTL lifecycle."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from mirage.domain.schemas import (
    AdapterCallResult,
    ApprovalDecision,
    ApprovalRecord,
    Asset,
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionPlan,
    ExecutionRecord,
    ExecutionState,
    HealthCheckResult,
    Relationship,
    SafetyDecision,
    TwinSnapshot,
)
from mirage.execution.adapters import (
    EnforcementAdapter,
    MockLabState,
    build_default_adapters,
)
from mirage.execution.audit import ImmutableAuditStore
from mirage.execution.kill_switch import KillSwitch
from mirage.execution.plan import ExecutionPlanBuilder
from mirage.execution.state_machine import ExecutionStateMachine
from mirage.execution.utils import deterministic_id, ensure_utc


class CanaryController:
    """Runs canary adapter checks before full execution."""

    def run(self, adapter: EnforcementAdapter, plan: ExecutionPlan) -> AdapterCallResult:
        """Execute the plan canary."""
        return adapter.execute_canary(plan)


class VerificationService:
    """Runs verification and lab health checks."""

    def verify(
        self,
        adapter: EnforcementAdapter,
        plan: ExecutionPlan,
        lab_state: MockLabState,
    ) -> tuple[AdapterCallResult, list[HealthCheckResult]]:
        """Verify adapter result and required health checks."""
        adapter_result = adapter.verify(plan)
        now = ensure_utc(None)
        checks = [
            HealthCheckResult(
                check_name="management_channel_reachable",
                success=lab_state.management_channel_reachable,
                timestamp=now,
            ),
            HealthCheckResult(
                check_name="protected_services_healthy",
                success=lab_state.protected_services_healthy,
                timestamp=now,
            ),
            HealthCheckResult(
                check_name="no_unexpected_scope_expansion",
                success=set(plan.allowed_scope).issubset(set(plan.requested_scope)),
                details={
                    "requested_scope": plan.requested_scope,
                    "allowed_scope": plan.allowed_scope,
                },
                timestamp=now,
            ),
        ]
        if plan.adapter_type == "docker_decoy":
            checks.append(
                HealthCheckResult(
                    check_name="decoy_cannot_reach_protected_service",
                    success=not lab_state.decoy_can_reach_protected,
                    timestamp=now,
                )
            )
        return adapter_result, checks


class RollbackManager:
    """Coordinates rollback through the selected lab adapter."""

    def rollback(
        self,
        adapter: EnforcementAdapter,
        plan: ExecutionPlan,
    ) -> AdapterCallResult:
        """Run idempotent adapter rollback."""
        return adapter.rollback(plan)


class DeceptionOrchestrator:
    """Build, execute, approve, rollback, and audit lab execution plans."""

    def __init__(
        self,
        *,
        config: dict[str, Any] | None = None,
        adapters: dict[str, EnforcementAdapter] | None = None,
        lab_state: MockLabState | None = None,
        audit_store: ImmutableAuditStore | None = None,
        kill_switch: KillSwitch | None = None,
        twin=None,
    ) -> None:
        self.config = config or {}
        self.lab_state = lab_state or MockLabState()
        self.audit_store = audit_store or ImmutableAuditStore(
            self.config.get("audit_path")
        )
        self.kill_switch = kill_switch or KillSwitch(
            default_enabled=bool(
                self.config.get("kill_switch", {}).get("default_enabled", False)
            ),
            audit_store=self.audit_store,
        )
        self.adapters = adapters or build_default_adapters(self.lab_state)
        self.plan_builder = ExecutionPlanBuilder(self.config)
        self.state_machine = ExecutionStateMachine()
        self.canary = CanaryController()
        self.verifier = VerificationService()
        self.rollback_manager = RollbackManager()
        self.twin = twin
        self.plans: dict[str, ExecutionPlan] = {}
        self.records: dict[str, ExecutionRecord] = {}
        self.approvals: dict[str, ApprovalRecord] = {}

    def build_plan(
        self,
        action: CandidateDefenseAction,
        safety_decision: SafetyDecision,
        *,
        twin_snapshot: TwinSnapshot | None = None,
        belief_snapshot: BeliefSnapshot | None = None,
        graph_version: str = "mirage_attack_graph",
        analysis_id: str | None = None,
    ) -> ExecutionPlan:
        """Build and store an execution plan."""
        twin_snapshot = twin_snapshot or self._empty_twin_snapshot()
        belief_snapshot = belief_snapshot or self._empty_belief_snapshot()
        plan = self.plan_builder.build(
            action,
            safety_decision,
            twin_snapshot=twin_snapshot,
            belief_snapshot=belief_snapshot,
            graph_version=graph_version,
            analysis_id=analysis_id,
        )
        self.plans[plan.plan_id] = plan
        self.audit_store.append(
            "execution_plan_built",
            plan_id=plan.plan_id,
            action_id=plan.source_action_id,
            policy_version=plan.policy_version,
            twin_version=plan.twin_version,
            graph_version=plan.graph_version,
            belief_version=plan.belief_version,
            analysis_id=plan.analysis_id,
            payload={"plan": plan.model_dump(mode="json")},
            timestamp=plan.created_at,
        )
        return plan

    def execute(self, plan: ExecutionPlan, *, actor: str = "mirage-policy") -> ExecutionRecord:
        """Execute a plan through prepare, canary, execute, verify, and commit."""
        existing = self._record_for_plan(plan.plan_id)
        if existing and existing.current_state in {
            ExecutionState.SUCCEEDED,
            ExecutionState.ROLLED_BACK,
            ExecutionState.DENIED,
        }:
            return existing
        if (
            existing
            and existing.current_state == ExecutionState.AWAITING_APPROVAL
            and not self._has_valid_approval(existing)
        ):
            return existing

        adapter = self._adapter(plan)
        record = existing or self.state_machine.create_record(plan, actor=actor)
        self.records[record.execution_id] = record
        self._audit_transition(record, "execution_proposed")

        if self.kill_switch.is_blocked(action_type=plan.action_type, environment="lab"):
            record = self.state_machine.transition(
                record,
                ExecutionState.DENIED,
                "kill switch blocks new execution",
            )
            self._store_record(record, "execution_denied")
            return record

        try:
            if record.current_state == ExecutionState.PROPOSED:
                result = adapter.validate(plan)
                record = self._with_adapter_result(record, result)
                if not result.success:
                    record = self.state_machine.transition(
                        record,
                        ExecutionState.DENIED,
                        result.error or "adapter validation failed",
                    )
                    self._store_record(record, "execution_denied")
                    return record
                record = self.state_machine.transition(
                    record,
                    ExecutionState.VALIDATED,
                    "adapter validation passed",
                )
                self._store_record(record, "execution_validated")

            if plan.required_approvals and not self._has_valid_approval(record):
                record = self.state_machine.transition(
                    record,
                    ExecutionState.AWAITING_APPROVAL,
                    "valid approval required before execution",
                )
                self._store_record(record, "execution_awaiting_approval")
                return record

            if record.current_state in {
                ExecutionState.VALIDATED,
                ExecutionState.AWAITING_APPROVAL,
            }:
                result = adapter.prepare(plan)
                record = self._with_adapter_result(record, result)
                if not result.success:
                    record = self.state_machine.mark_failed(
                        record,
                        result.error or "adapter prepare failed",
                    )
                    return self._rollback_after_failure(record, plan, adapter)
                record = self.state_machine.transition(
                    record,
                    ExecutionState.PREPARED,
                    "adapter prepare completed",
                )
                self._store_record(record, "execution_prepared")

            record = self.state_machine.transition(
                record,
                ExecutionState.CANARY_RUNNING,
                "canary started",
            )
            self._store_record(record, "canary_started")
            canary_result = self.canary.run(adapter, plan)
            record = self._with_adapter_result(
                record,
                canary_result,
                canary=True,
            )
            if not canary_result.success:
                record = self.state_machine.mark_failed(
                    record,
                    canary_result.error or "canary failed",
                )
                return self._rollback_after_failure(record, plan, adapter)

            record = self.state_machine.transition(
                record,
                ExecutionState.EXECUTING,
                "full execution started",
            )
            self._store_record(record, "execution_started")
            execute_result = adapter.execute(plan)
            record = self._with_adapter_result(record, execute_result)
            if not execute_result.success:
                record = self.state_machine.mark_failed(
                    record,
                    execute_result.error or "execution failed",
                )
                return self._rollback_after_failure(record, plan, adapter)

            record = self.state_machine.transition(
                record,
                ExecutionState.VERIFYING,
                "verification started",
            )
            self._store_record(record, "verification_started")
            verify_result, checks = self.verifier.verify(adapter, plan, self.lab_state)
            record = self._with_adapter_result(record, verify_result)
            record = record.model_copy(
                update={
                    "health_check_results": [
                        *record.health_check_results,
                        *checks,
                    ]
                }
            )
            if not verify_result.success or not all(check.success for check in checks):
                reason = verify_result.error or "verification health check failed"
                record = self.state_machine.mark_failed(record, reason)
                return self._rollback_after_failure(record, plan, adapter)

            record = self.state_machine.transition(
                record,
                ExecutionState.SUCCEEDED,
                "execution verified and committed",
            )
            self._apply_twin_success(plan, record)
            self._store_record(record, "execution_succeeded")
            return record
        except ValueError:
            raise

    def approve(
        self,
        execution_id: str,
        *,
        approver: str,
        decision: ApprovalDecision = ApprovalDecision.APPROVED,
        reason: str = "",
        ttl_seconds: int | None = None,
    ) -> ApprovalRecord:
        """Record approval or rejection for an awaiting execution."""
        record = self.records[execution_id]
        timestamp = ensure_utc(None)
        expiry = timestamp + timedelta(
            seconds=ttl_seconds or int(self.config.get("approval_ttl_seconds", 900))
        )
        approval = ApprovalRecord(
            approval_id=deterministic_id(
                "approval",
                execution_id,
                approver,
                decision.value,
                timestamp.isoformat(),
            ),
            execution_id=execution_id,
            approver=approver,
            decision=decision,
            reason=reason,
            timestamp=timestamp,
            expiry=expiry,
        )
        self.approvals[approval.approval_id] = approval
        self.audit_store.append(
            "approval_recorded",
            actor=approver,
            execution_id=execution_id,
            plan_id=record.plan_id,
            payload={"approval": approval.model_dump(mode="json")},
            timestamp=timestamp,
        )
        if decision == ApprovalDecision.REJECTED:
            record = self.state_machine.transition(
                record,
                ExecutionState.DENIED,
                "approval rejected",
            )
            self._store_record(record, "execution_denied")
        return approval

    def rollback(
        self,
        execution_id: str,
        *,
        reason: str = "manual rollback",
    ) -> ExecutionRecord:
        """Rollback one execution by ID."""
        record = self.records[execution_id]
        plan = self.plans[record.plan_id]
        adapter = self._adapter(plan)
        if record.current_state == ExecutionState.SUCCEEDED:
            record = self.state_machine.transition(
                record,
                ExecutionState.ROLLING_BACK,
                reason,
            )
        elif record.current_state == ExecutionState.EXPIRED:
            record = self.state_machine.transition(
                record,
                ExecutionState.ROLLING_BACK,
                reason,
            )
        elif record.current_state == ExecutionState.FAILED:
            record = self.state_machine.transition(
                record,
                ExecutionState.ROLLING_BACK,
                reason,
            )
        elif record.current_state == ExecutionState.AWAITING_APPROVAL:
            record = self.state_machine.transition(
                record,
                ExecutionState.CANCELLED,
                reason,
            )
            self._store_record(record, "execution_cancelled")
            return record
        rollback_result = self.rollback_manager.rollback(adapter, plan)
        record = self._with_adapter_result(
            record,
            rollback_result,
            rollback=True,
        )
        if rollback_result.success:
            record = self.state_machine.transition(
                record,
                ExecutionState.ROLLED_BACK,
                "rollback verified",
            )
            self._apply_twin_rollback(plan, record)
            self._store_record(record, "execution_rolled_back")
            return record
        record = self.state_machine.transition(
            record,
            ExecutionState.FAILED,
            rollback_result.error or "rollback failed",
            failure_reason=rollback_result.error or "rollback failed",
        )
        self._store_record(record, "rollback_failed")
        return record

    def expire_due_actions(self, *, reference_time=None) -> list[ExecutionRecord]:
        """Expire and rollback succeeded actions whose TTL has elapsed."""
        now = ensure_utc(reference_time)
        expired: list[ExecutionRecord] = []
        for record in list(self.records.values()):
            if (
                record.current_state == ExecutionState.SUCCEEDED
                and record.expires_at
                and record.expires_at <= now
            ):
                marked = self.state_machine.transition(
                    record,
                    ExecutionState.EXPIRED,
                    "TTL expired",
                    timestamp=now,
                )
                self._store_record(marked, "execution_expired")
                expired.append(
                    self.rollback(marked.execution_id, reason="TTL expiration")
                )
        return expired

    def _rollback_after_failure(
        self,
        record: ExecutionRecord,
        plan: ExecutionPlan,
        adapter: EnforcementAdapter,
    ) -> ExecutionRecord:
        self._store_record(record, "execution_failed")
        record = self.state_machine.transition(
            record,
            ExecutionState.ROLLING_BACK,
            "automatic rollback after failure",
        )
        rollback_result = self.rollback_manager.rollback(adapter, plan)
        record = self._with_adapter_result(
            record,
            rollback_result,
            rollback=True,
        )
        if rollback_result.success:
            record = self.state_machine.transition(
                record,
                ExecutionState.ROLLED_BACK,
                "automatic rollback completed",
            )
            self._apply_twin_rollback(plan, record)
            self._store_record(record, "execution_rolled_back")
            return record
        record = self.state_machine.transition(
            record,
            ExecutionState.FAILED,
            rollback_result.error or "automatic rollback failed",
            failure_reason=rollback_result.error or "automatic rollback failed",
        )
        self._store_record(record, "rollback_failed")
        return record

    def _record_for_plan(self, plan_id: str) -> ExecutionRecord | None:
        for record in self.records.values():
            if record.plan_id == plan_id:
                return record
        return None

    def _adapter(self, plan: ExecutionPlan) -> EnforcementAdapter:
        if plan.adapter_type not in self.adapters:
            raise ValueError(f"No adapter registered for {plan.adapter_type}")
        return self.adapters[plan.adapter_type]

    def _with_adapter_result(
        self,
        record: ExecutionRecord,
        result: AdapterCallResult,
        *,
        canary: bool = False,
        rollback: bool = False,
    ) -> ExecutionRecord:
        update = {
            "adapter_results": [*record.adapter_results, result],
            "updated_at": result.timestamp,
        }
        if canary:
            update["canary_result"] = result
        if rollback:
            update["rollback_result"] = result
        return record.model_copy(update=update)

    def _has_valid_approval(self, record: ExecutionRecord) -> bool:
        now = ensure_utc(None)
        return any(
            approval.execution_id == record.execution_id
            and approval.decision == ApprovalDecision.APPROVED
            and approval.expiry > now
            for approval in self.approvals.values()
        )

    def _store_record(
        self,
        record: ExecutionRecord,
        event_type: str,
    ) -> None:
        self.records[record.execution_id] = record
        self._audit_transition(record, event_type)

    def _audit_transition(self, record: ExecutionRecord, event_type: str) -> None:
        plan = self.plans.get(record.plan_id)
        self.audit_store.append(
            event_type,
            execution_id=record.execution_id,
            plan_id=record.plan_id,
            action_id=plan.source_action_id if plan else None,
            policy_version=plan.policy_version if plan else None,
            twin_version=plan.twin_version if plan else None,
            graph_version=plan.graph_version if plan else None,
            belief_version=plan.belief_version if plan else None,
            analysis_id=plan.analysis_id if plan else None,
            payload={"record": record.model_dump(mode="json")},
            timestamp=record.updated_at,
        )

    def _apply_twin_success(
        self,
        plan: ExecutionPlan,
        record: ExecutionRecord,
    ) -> None:
        if self.twin is None:
            return
        now = ensure_utc(record.updated_at)
        asset_id = deterministic_id("asset:decoy", plan.plan_id)
        if plan.adapter_type == "docker_decoy":
            existing = self.twin.assets.get(asset_id)
            if existing is None:
                self.twin.assets[asset_id] = Asset(
                    asset_id=asset_id,
                    hostname=f"mirage-{plan.action_type}",
                    asset_type="decoy",
                    environment="lab",
                    business_criticality=0.0,
                    first_seen=now,
                    last_seen=now,
                    confidence=1.0,
                    data_sources=["mirage-m4-orchestrator"],
                    active=True,
                    is_decoy=True,
                    attributes={
                        "execution_id": record.execution_id,
                        "plan_id": plan.plan_id,
                        "ttl_seconds": plan.ttl_seconds,
                    },
                )
            else:
                existing.active = True
                existing.last_seen = now
                existing.attributes["execution_id"] = record.execution_id
            for target in plan.allowed_scope:
                rel_id = deterministic_id("rel", asset_id, target, "deception_for")
                self.twin.relationships[rel_id] = Relationship(
                    relationship_id=rel_id,
                    source_entity_id=asset_id,
                    target_entity_id=target,
                    relationship_type="deception_for",
                    confidence=1.0,
                    first_seen=now,
                    last_seen=now,
                    expiry_time=record.expires_at,
                    source_event_ids=[record.execution_id],
                    active=True,
                    attributes={"plan_id": plan.plan_id},
                )
            self.twin.version += 1
        else:
            controls = self.twin.warnings
            marker = f"active_control:{record.execution_id}:{plan.action_type}"
            if marker not in controls:
                controls.append(marker)
                self.twin.version += 1

    def _apply_twin_rollback(
        self,
        plan: ExecutionPlan,
        record: ExecutionRecord,
    ) -> None:
        if self.twin is None:
            return
        now = ensure_utc(record.updated_at)
        changed = False
        asset_id = deterministic_id("asset:decoy", plan.plan_id)
        asset = self.twin.assets.get(asset_id)
        if asset and asset.active:
            asset.active = False
            asset.last_seen = now
            asset.attributes["rolled_back_by"] = record.execution_id
            changed = True
        for relationship in self.twin.relationships.values():
            if relationship.attributes.get("plan_id") == plan.plan_id and relationship.active:
                relationship.active = False
                relationship.last_seen = now
                changed = True
        marker = f"active_control:{record.execution_id}:{plan.action_type}"
        if marker in self.twin.warnings:
            self.twin.warnings.remove(marker)
            self.twin.warnings.append(f"rolled_back_control:{record.execution_id}")
            changed = True
        if changed:
            self.twin.version += 1

    def _empty_twin_snapshot(self) -> TwinSnapshot:
        now = ensure_utc(None)
        return TwinSnapshot(
            twin_version=0,
            timestamp=now,
            coverage_score=1.0,
            freshness_score=1.0,
        )

    def _empty_belief_snapshot(self) -> BeliefSnapshot:
        now = ensure_utc(None)
        return BeliefSnapshot(belief_version=0, timestamp=now)


class TTLActionLifecycleManager:
    """Small facade for expiring temporary actions."""

    def __init__(self, orchestrator: DeceptionOrchestrator) -> None:
        self.orchestrator = orchestrator

    def expire_due(self, *, reference_time=None) -> list[ExecutionRecord]:
        """Expire due actions and rollback them."""
        return self.orchestrator.expire_due_actions(reference_time=reference_time)
