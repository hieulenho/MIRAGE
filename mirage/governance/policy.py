"""Versioned policy-as-code engine with deny-by-default behavior."""

from __future__ import annotations

from typing import Any

from mirage.domain.schemas import CandidateDefenseAction, ExecutionPlan
from mirage.governance.integrity import sha256_json
from mirage.governance.schema import PolicyEvaluationResult
from mirage.verification.schema import FormalVerificationContext


class PolicyAsCodeEngine:
    """Evaluate governed actions without dynamic code execution."""

    def __init__(self, policy: dict[str, Any] | None = None) -> None:
        self.policy = policy or {}
        self.version = str(self.policy.get("policy_version", "pilot-policy-v1"))
        self.history: list[dict[str, Any]] = [dict(self.policy)]

    def evaluate(
        self,
        action: CandidateDefenseAction,
        execution_plan: ExecutionPlan,
        verification_context: FormalVerificationContext,
    ) -> PolicyEvaluationResult:
        allowed = True
        reasons: list[str] = []
        required: list[str] = []
        allowed_types = set(self.policy.get("allowed_action_types", []))
        if not allowed_types or action.action_type not in allowed_types:
            allowed = False
            reasons.append("action_type_not_allowed_by_policy")
        if action.action_type in set(self.policy.get("prohibited_action_types", [])):
            allowed = False
            reasons.append("action_type_explicitly_prohibited")
        if execution_plan.ttl_seconds is None:
            allowed = False
            reasons.append("ttl_required")
        elif execution_plan.ttl_seconds > int(self.policy.get("maximum_ttl_seconds", 3600)):
            allowed = False
            reasons.append("ttl_exceeds_policy_maximum")
        if not verification_context.action_mask.allowed:
            allowed = False
            reasons.append("action_mask_blocked")
        if verification_context.model_uncertainty > float(self.policy.get("uncertainty_threshold", 0.65)):
            allowed = False
            reasons.append("model_uncertainty_too_high")
        if verification_context.ood_warnings:
            allowed = False
            reasons.append("ood_warning_present")
        if action.risk_tier in {"medium", "high", "critical"}:
            required.append("authorized_pilot_approver")
        return PolicyEvaluationResult(
            policy_id=self.version,
            policy_version=self.version,
            allowed=allowed,
            deny_reasons=sorted(set(reasons)),
            required_approvals=sorted(set(required)),
            policy_hash=sha256_json(self.policy),
            policy_version_id=self.version,
        )

    def update_policy(self, policy: dict[str, Any]) -> None:
        self.policy = dict(policy)
        self.version = str(self.policy.get("policy_version", self.version))
        self.history.append(dict(policy))

    def rollback_policy(self) -> dict[str, Any]:
        if len(self.history) > 1:
            self.history.pop()
            self.policy = dict(self.history[-1])
            self.version = str(self.policy.get("policy_version", self.version))
        return dict(self.policy)
