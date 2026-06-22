"""Deterministic Milestone 9 scenario fixtures."""

from __future__ import annotations

from datetime import datetime, timezone

from mirage.pilot.schema import CanaryOutcome
from mirage.verification.schema import FormalVerificationVerdict


def build_m9_scenarios() -> list[dict]:
    """Return deterministic scenario expectations for tests and docs."""
    now = datetime(2026, 6, 22, tzinfo=timezone.utc)
    return [
        {"scenario_id": "m9_safe_decoy_pilot", "expected_verdict": FormalVerificationVerdict.VERIFIED.value, "expected_canary": CanaryOutcome.EXPAND.value, "timestamp": now.isoformat()},
        {"scenario_id": "m9_decoy_reaches_protected_db", "expected_verdict": FormalVerificationVerdict.REJECTED.value, "expected_finding": "INV-003", "timestamp": now.isoformat()},
        {"scenario_id": "m9_management_channel_blocked", "expected_verdict": FormalVerificationVerdict.REJECTED.value, "expected_finding": "INV-002", "timestamp": now.isoformat()},
        {"scenario_id": "m9_blast_radius_exceeds_limit", "expected_verdict": FormalVerificationVerdict.REJECTED.value, "expected_finding": "INV-004", "timestamp": now.isoformat()},
        {"scenario_id": "m9_missing_rollback", "expected_verdict": FormalVerificationVerdict.REJECTED.value, "expected_finding": "INV-005", "timestamp": now.isoformat()},
        {"scenario_id": "m9_stale_twin", "expected_verdict": FormalVerificationVerdict.INCONCLUSIVE.value, "expected_finding": "INV-010", "timestamp": now.isoformat()},
        {"scenario_id": "m9_artifact_hash_mismatch", "expected_governance": "REJECTED", "timestamp": now.isoformat()},
        {"scenario_id": "m9_expired_approval", "expected_verdict": FormalVerificationVerdict.REJECTED.value, "expected_finding": "INV-008", "timestamp": now.isoformat()},
        {"scenario_id": "m9_masked_action_with_approval", "expected_verdict": FormalVerificationVerdict.REJECTED.value, "expected_finding": "INV-007", "timestamp": now.isoformat()},
        {"scenario_id": "m9_canary_latency_increase", "expected_canary": CanaryOutcome.HOLD.value, "timestamp": now.isoformat()},
        {"scenario_id": "m9_unexpected_scope_expansion", "expected_canary": CanaryOutcome.ROLLBACK.value, "timestamp": now.isoformat()},
        {"scenario_id": "m9_critical_model_drift", "expected_drift": "CRITICAL", "pilot_suspended": True, "timestamp": now.isoformat()},
        {"scenario_id": "m9_audit_chain_tampering", "expected_audit_valid": False, "timestamp": now.isoformat()},
        {"scenario_id": "m9_marl_unsupported_action", "expected_governance": "REVIEW_REQUIRED", "timestamp": now.isoformat()},
        {"scenario_id": "m9_policy_disagreement_medium_risk", "expected_governance": "REVIEW_REQUIRED", "timestamp": now.isoformat()},
    ]
