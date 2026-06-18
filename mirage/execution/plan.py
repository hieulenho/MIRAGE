"""Execution plan builder for Milestone 4."""

from __future__ import annotations

from typing import Any

from mirage.domain.schemas import (
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionPlan,
    SafetyDecision,
    SafetyVerdict,
    TwinSnapshot,
)
from mirage.execution.utils import adapter_type_for, deterministic_id, ensure_utc


class ExecutionPlanBuilder:
    """Build deterministic lab execution plans from safe candidate actions."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.default_timeout = int(self.config.get("execution_timeout_seconds", 300))
        self.retry_policy = {
            "max_attempts": int(self.config.get("retries", 1)),
            "rollback_max_attempts": int(self.config.get("rollback_retries", 2)),
        }

    def build(
        self,
        action: CandidateDefenseAction,
        safety_decision: SafetyDecision,
        *,
        twin_snapshot: TwinSnapshot,
        belief_snapshot: BeliefSnapshot,
        graph_version: str = "mirage_attack_graph",
        analysis_id: str | None = None,
        reference_time=None,
    ) -> ExecutionPlan:
        """Return a deterministic execution plan."""
        if safety_decision.verdict == SafetyVerdict.DENY:
            raise ValueError("Cannot build execution plan for denied action.")
        reference = ensure_utc(reference_time or safety_decision.evaluated_at)
        adapter_type = adapter_type_for(action.action_type, self.config)
        ttl = safety_decision.maximum_ttl_seconds or action.ttl_seconds
        idempotency_key = deterministic_id(
            "idempotency",
            action.action_id,
            safety_decision.policy_version,
            str(twin_snapshot.twin_version),
            str(belief_snapshot.belief_version),
        )
        plan_id = deterministic_id(
            "plan",
            action.action_id,
            adapter_type,
            ",".join(safety_decision.allowed_scope),
            safety_decision.policy_version,
            idempotency_key,
        )
        steps = self._steps_for(action.action_type)
        return ExecutionPlan(
            plan_id=plan_id,
            source_action_id=action.action_id,
            action_type=action.action_type,
            targets=sorted(action.target_entity_ids),
            adapter_type=adapter_type,
            requested_scope=sorted(action.target_entity_ids),
            allowed_scope=sorted(safety_decision.allowed_scope),
            parameters={
                "expected_risk_reduction": action.expected_risk_reduction,
                "expected_information_gain": action.expected_information_gain,
                "business_risk": action.business_risk,
                "deployment_cost": action.deployment_cost,
                "reason": action.reason,
            },
            preconditions=[
                "target exists",
                "action still allowed",
                "required adapter healthy",
                "rollback path available",
                "management channel reachable",
                *action.preconditions,
            ],
            canary_steps=steps["canary"],
            execution_steps=steps["execute"],
            verification_checks=steps["verify"],
            postconditions=[
                "target action applied",
                "protected service remains available",
                "management channel remains reachable",
                "Digital Twin updated",
                "no unexpected scope expansion",
                *action.postconditions,
            ],
            rollback_steps=steps["rollback"],
            ttl_seconds=ttl,
            timeout_seconds=self.default_timeout,
            retry_policy=dict(self.retry_policy),
            idempotency_key=idempotency_key,
            required_approvals=safety_decision.required_approvals,
            twin_version=str(twin_snapshot.twin_version),
            graph_version=graph_version,
            belief_version=str(belief_snapshot.belief_version),
            analysis_id=analysis_id,
            policy_version=safety_decision.policy_version,
            created_at=reference,
        )

    def _steps_for(self, action_type: str) -> dict[str, list[str]]:
        if action_type in {"deploy_decoy_database", "deploy_decoy_host", "deploy_fake_share", "add_decoy_service"}:
            return {
                "canary": [
                    "select template",
                    "validate lab resources",
                    "create isolated mock container",
                    "verify deny-by-default egress",
                    "verify telemetry hook",
                ],
                "execute": [
                    "start lab decoy service",
                    "expose canary-approved service",
                    "register deception resource",
                ],
                "verify": [
                    "decoy healthy",
                    "expected port exposed",
                    "telemetry active",
                    "protected service unreachable from decoy",
                ],
                "rollback": [
                    "stop lab decoy service",
                    "remove lab route and exposure",
                    "mark decoy inactive in twin",
                ],
            }
        if action_type in {"scatter_honey_credential", "create_fake_dns_record"}:
            return {
                "canary": ["validate target scope", "verify rollback material"],
                "execute": ["create synthetic lure in lab state"],
                "verify": ["lure visible in lab", "telemetry active"],
                "rollback": ["remove synthetic lure", "verify lure removed"],
            }
        if action_type in {"throttle_edge", "restrict_smb", "temporary_segmentation", "block_egress", "block_flow"}:
            return {
                "canary": [
                    "apply to one mock flow",
                    "verify management channel",
                    "verify protected service healthy",
                ],
                "execute": ["apply temporary mock control"],
                "verify": ["control active", "no protected outage"],
                "rollback": ["remove temporary mock control", "verify flow restored"],
            }
        if action_type in {"create_soc_ticket", "request_analyst_review"}:
            return {
                "canary": ["validate ticket queue"],
                "execute": ["create analyst ticket"],
                "verify": ["ticket recorded"],
                "rollback": ["close synthetic ticket"],
            }
        return {
            "canary": ["validate adapter and target"],
            "execute": ["apply mock lab action"],
            "verify": ["mock action recorded"],
            "rollback": ["remove mock lab action"],
        }
