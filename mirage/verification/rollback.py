"""Rollback verification."""

from __future__ import annotations

from mirage.domain.schemas import ExecutionPlan
from mirage.verification.schema import (
    VerificationFinding,
    VerificationResult,
    VerificationSeverity,
    utc_now,
)


class RollbackVerifier:
    """Verify rollback readiness before execution."""

    version = "rollback-v1"

    def verify(self, plan: ExecutionPlan, *, medium_or_high: bool = False) -> VerificationFinding:
        missing: list[str] = []
        if not plan.rollback_steps:
            missing.append("rollback_steps")
        if not plan.verification_checks:
            missing.append("rollback_verification")
        if not plan.ttl_seconds:
            missing.append("ttl_seconds")
        if plan.timeout_seconds <= 0:
            missing.append("rollback_timeout")
        if int(plan.retry_policy.get("rollback_max_attempts", 0)) < 1:
            missing.append("rollback_retry_policy")
        if missing:
            return self._finding(
                VerificationResult.VIOLATED if medium_or_high else VerificationResult.UNKNOWN,
                "Rollback verification incomplete: " + ", ".join(missing),
                missing,
            )
        return self._finding(
            VerificationResult.PROVEN,
            "Rollback plan has steps, verification, timeout, retry policy, and TTL.",
            [],
        )

    def _finding(
        self,
        result: VerificationResult,
        explanation: str,
        affected: list[str],
    ) -> VerificationFinding:
        return VerificationFinding(
            finding_id=f"INV-005:{result.value}:{abs(hash(explanation))}",
            invariant_id="INV-005",
            result=result,
            severity=VerificationSeverity.HIGH if result != VerificationResult.PROVEN else VerificationSeverity.INFO,
            affected_entities=affected,
            explanation=explanation,
            verifier_name="RollbackVerifier",
            verifier_version=self.version,
            confidence=1.0 if result != VerificationResult.UNKNOWN else 0.4,
            timestamp=utc_now(),
        )
