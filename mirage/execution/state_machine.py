"""Execution state machine for Milestone 4."""

from __future__ import annotations

from datetime import timedelta

from mirage.domain.schemas import (
    ExecutionPlan,
    ExecutionRecord,
    ExecutionState,
    StateTransitionRecord,
)
from mirage.execution.utils import deterministic_id, ensure_utc


VALID_TRANSITIONS = {
    ExecutionState.PROPOSED: {
        ExecutionState.VALIDATED,
        ExecutionState.DENIED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.VALIDATED: {
        ExecutionState.AWAITING_APPROVAL,
        ExecutionState.PREPARED,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.AWAITING_APPROVAL: {
        ExecutionState.PREPARED,
        ExecutionState.FAILED,
        ExecutionState.DENIED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.PREPARED: {
        ExecutionState.CANARY_RUNNING,
        ExecutionState.FAILED,
        ExecutionState.CANCELLED,
    },
    ExecutionState.CANARY_RUNNING: {
        ExecutionState.EXECUTING,
        ExecutionState.FAILED,
    },
    ExecutionState.EXECUTING: {
        ExecutionState.VERIFYING,
        ExecutionState.FAILED,
    },
    ExecutionState.VERIFYING: {
        ExecutionState.SUCCEEDED,
        ExecutionState.FAILED,
    },
    ExecutionState.SUCCEEDED: {
        ExecutionState.EXPIRED,
        ExecutionState.ROLLING_BACK,
    },
    ExecutionState.EXPIRED: {
        ExecutionState.ROLLING_BACK,
    },
    ExecutionState.FAILED: {
        ExecutionState.ROLLING_BACK,
    },
    ExecutionState.ROLLING_BACK: {
        ExecutionState.ROLLED_BACK,
        ExecutionState.FAILED,
    },
    ExecutionState.ROLLED_BACK: set(),
    ExecutionState.CANCELLED: set(),
    ExecutionState.DENIED: set(),
}


class ExecutionStateMachine:
    """Small deterministic state machine for execution records."""

    def create_record(
        self,
        plan: ExecutionPlan,
        *,
        actor: str = "mirage-policy",
    ) -> ExecutionRecord:
        """Create a restart-safe initial execution record."""
        now = ensure_utc(plan.created_at)
        execution_id = deterministic_id(
            "execution",
            plan.plan_id,
            plan.idempotency_key,
        )
        first = StateTransitionRecord(
            from_state=None,
            to_state=ExecutionState.PROPOSED,
            reason="execution proposed",
            timestamp=now,
        )
        expires_at = (
            now + timedelta(seconds=plan.ttl_seconds)
            if plan.ttl_seconds
            else None
        )
        return ExecutionRecord(
            execution_id=execution_id,
            plan_id=plan.plan_id,
            current_state=ExecutionState.PROPOSED,
            state_history=[first],
            created_at=now,
            updated_at=now,
            expires_at=expires_at,
            actor=actor,
        )

    def transition(
        self,
        record: ExecutionRecord,
        to_state: ExecutionState,
        reason: str,
        *,
        timestamp=None,
        failure_reason: str | None = None,
    ) -> ExecutionRecord:
        """Return a copy transitioned to the next valid state."""
        if to_state not in VALID_TRANSITIONS[record.current_state]:
            raise ValueError(
                f"Invalid execution transition: "
                f"{record.current_state.value} -> {to_state.value}"
            )
        now = ensure_utc(timestamp)
        history = [
            *record.state_history,
            StateTransitionRecord(
                from_state=record.current_state,
                to_state=to_state,
                reason=reason,
                timestamp=now,
            ),
        ]
        return record.model_copy(
            update={
                "current_state": to_state,
                "state_history": history,
                "updated_at": now,
                "failure_reason": failure_reason or record.failure_reason,
            }
        )

    def mark_failed(
        self,
        record: ExecutionRecord,
        reason: str,
        *,
        timestamp=None,
    ) -> ExecutionRecord:
        """Transition eligible running records to FAILED."""
        return self.transition(
            record,
            ExecutionState.FAILED,
            reason,
            timestamp=timestamp,
            failure_reason=reason,
        )
