"""Temporal lifecycle verification."""

from __future__ import annotations

from mirage.domain.schemas import ExecutionRecord, ExecutionState
from mirage.execution.state_machine import VALID_TRANSITIONS
from mirage.verification.schema import (
    VerificationFinding,
    VerificationResult,
    VerificationSeverity,
    utc_now,
)


class TemporalLifecycleVerifier:
    """Check explicit execution state-machine properties."""

    version = "temporal-lifecycle-v1"

    def verify_record(self, record: ExecutionRecord) -> list[VerificationFinding]:
        findings: list[VerificationFinding] = []
        previous = None
        seen_terminal = False
        for transition in record.state_history:
            if previous is not None and transition.to_state not in VALID_TRANSITIONS[previous]:
                findings.append(self._finding(VerificationResult.VIOLATED, f"Invalid transition {previous.value}->{transition.to_state.value}"))
            if seen_terminal and transition.to_state in {ExecutionState.EXECUTING, ExecutionState.CANARY_RUNNING}:
                findings.append(self._finding(VerificationResult.VIOLATED, "Terminal state returned to execution."))
            if transition.to_state in {ExecutionState.ROLLED_BACK, ExecutionState.CANCELLED, ExecutionState.DENIED}:
                seen_terminal = True
            previous = transition.to_state
        if not findings:
            findings.append(self._finding(VerificationResult.PROVEN, "Execution lifecycle follows allowed transitions."))
        return findings

    def verify_plan_preconditions(self, has_verification: bool, has_approval: bool, approval_required: bool) -> VerificationFinding:
        if not has_verification:
            return self._finding(VerificationResult.VIOLATED, "Execution cannot start before formal verification.")
        if approval_required and not has_approval:
            return self._finding(VerificationResult.VIOLATED, "Required approval missing before execution.")
        return self._finding(VerificationResult.PROVEN, "Temporal preconditions are satisfied.")

    def _finding(self, result: VerificationResult, explanation: str) -> VerificationFinding:
        return VerificationFinding(
            finding_id=f"INV-011:{result.value}:{abs(hash(explanation))}",
            invariant_id="INV-011",
            result=result,
            severity=VerificationSeverity.HIGH if result == VerificationResult.VIOLATED else VerificationSeverity.INFO,
            explanation=explanation,
            verifier_name="TemporalLifecycleVerifier",
            verifier_version=self.version,
            timestamp=utc_now(),
        )
