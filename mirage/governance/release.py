"""Release gate for governed artifacts."""

from __future__ import annotations

from mirage.execution.utils import deterministic_id
from mirage.governance.schema import (
    ArtifactType,
    EvidenceBundle,
    GovernanceDecision,
    GovernanceStatus,
    GovernanceVerdict,
    GovernedArtifact,
)


class ReleaseGate:
    """Decide whether an artifact can enter Shadow or Controlled Pilot."""

    def __init__(self, thresholds: dict[str, float] | None = None) -> None:
        self.thresholds = thresholds or {
            "worst_case_return": 0.0,
            "unseen_topology_return": 0.0,
            "calibration_error_max": 0.25,
            "latency_ms_max": 250.0,
        }

    def evaluate(
        self,
        artifact: GovernedArtifact,
        evidence_bundle: EvidenceBundle,
        target_status: GovernanceStatus,
    ) -> GovernanceDecision:
        required = [
            "tests_pass",
            "no_masked_action_execution",
            "no_hard_safety_violation",
            "formal_verification_passed",
            "model_card_complete",
            "policy_card_complete",
        ]
        results = {
            "tests_pass": all(evidence_bundle.test_results.values()) if evidence_bundle.test_results else False,
            "no_masked_action_execution": evidence_bundle.masked_action_violations == 0,
            "no_hard_safety_violation": evidence_bundle.hard_safety_violations == 0,
            "formal_verification_passed": evidence_bundle.formal_verification_passed,
            "model_card_complete": evidence_bundle.model_card_complete,
            "policy_card_complete": evidence_bundle.policy_card_complete,
            "worst_case_threshold": evidence_bundle.metrics.get("worst_case_return", 0.0) >= self.thresholds["worst_case_return"],
            "unseen_topology_threshold": evidence_bundle.metrics.get("unseen_topology_return", 0.0) >= self.thresholds["unseen_topology_return"],
            "calibration_ok": evidence_bundle.metrics.get("calibration_error", 0.0) <= self.thresholds["calibration_error_max"],
            "latency_ok": evidence_bundle.metrics.get("latency_ms", 0.0) <= self.thresholds["latency_ms_max"],
        }
        if target_status == GovernanceStatus.PILOT_CANDIDATE:
            required.extend(["worst_case_threshold", "unseen_topology_threshold", "calibration_ok", "latency_ok"])
        if target_status == GovernanceStatus.PILOT_APPROVED:
            required.append("explicit_approval")
            results["explicit_approval"] = bool(evidence_bundle.approvals)
        if artifact.artifact_type == ArtifactType.RED_POLICY and target_status in {
            GovernanceStatus.PILOT_CANDIDATE,
            GovernanceStatus.PILOT_APPROVED,
        }:
            results["red_policy_not_pilot"] = False
            required.append("red_policy_not_pilot")
        missing = [item for item in required if not results.get(item, False)]
        verdict = GovernanceVerdict.APPROVED if not missing else GovernanceVerdict.REJECTED
        return GovernanceDecision(
            decision_id=deterministic_id("governance_decision", artifact.artifact_id, artifact.version, target_status.value, ",".join(missing)),
            artifact_type=artifact.artifact_type,
            artifact_id=artifact.artifact_id,
            artifact_version=artifact.version,
            proposed_status=target_status,
            governance_verdict=verdict,
            required_evidence=required,
            missing_evidence=missing,
            approvers=evidence_bundle.approvals,
            approvals=evidence_bundle.approvals,
            rejection_reasons=missing,
            release_gate_results=results,
        )
