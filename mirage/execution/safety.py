"""Safety Gate V1 for CandidateDefenseAction execution."""

from __future__ import annotations

import ipaddress
from typing import Any

from mirage.domain.schemas import (
    ActionMask,
    BeliefSnapshot,
    CandidateDefenseAction,
    ExecutionRecord,
    ExecutionState,
    SafetyDecision,
    SafetyVerdict,
    TwinSnapshot,
)
from mirage.execution.audit import ImmutableAuditStore
from mirage.execution.kill_switch import KillSwitch
from mirage.execution.utils import (
    action_tier,
    adapter_type_for,
    ensure_utc,
)


class SafetyPolicyEngine:
    """Configurable policy checks for Milestone 4 lab execution."""

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}
        self.version = str(self.config.get("policy_version", "safety-v1"))
        self.protected_asset_ids = set(self.config.get("protected_asset_ids", []))
        self.protected_asset_types = set(
            self.config.get(
                "protected_asset_types",
                ["database", "dc", "domain_controller"],
            )
        )
        self.managed_environments = set(
            self.config.get("managed_environments", ["lab", "test", "dev", ""])
        )
        self.management_channel_ids = set(
            self.config.get("management_channel_ids", [])
        )
        self.confidence_thresholds = {
            str(key): float(value)
            for key, value in self.config.get(
                "confidence_thresholds",
                {
                    "low": 0.20,
                    "medium": 0.35,
                    "high": 0.70,
                    "critical": 0.95,
                },
            ).items()
        }
        self.min_freshness = float(self.config.get("twin_freshness_threshold", 0.35))
        self.min_coverage = float(self.config.get("graph_coverage_threshold", 0.20))
        self.blast_radius_limit = int(self.config.get("blast_radius_limit", 5))
        self.action_budget = float(self.config.get("action_budget", 6.0))
        self.default_ttl = int(self.config.get("default_ttl_seconds", 3600))
        self.maximum_ttl = int(self.config.get("maximum_ttl_seconds", 14400))
        self.rollback_required_tier = int(self.config.get("rollback_required_tier", 2))
        self.reversible_required_tier = int(
            self.config.get("reversible_required_tier", 2)
        )
        self.enabled_adapters = {
            key
            for key, enabled in self.config.get(
                "adapters",
                {
                    "docker_decoy": True,
                    "mock_firewall": True,
                    "mock_edr": True,
                    "mock_iam": True,
                    "mock_dns": True,
                    "mock_telemetry": True,
                    "mock_ticket": True,
                },
            ).items()
            if enabled
        }
        self.compatible_stages = self.config.get(
            "compatible_stages",
            {
                "increase_endpoint_logging": ["execution", "discovery", "lateral_movement", "credential_access", "collection"],
                "increase_network_telemetry": ["discovery", "lateral_movement", "command_and_control", "exfiltration"],
                "deploy_decoy_database": ["discovery", "credential_access", "lateral_movement", "collection"],
                "deploy_fake_share": ["discovery", "lateral_movement", "collection"],
                "scatter_honey_credential": ["credential_access", "lateral_movement", "discovery"],
                "add_decoy_service": ["discovery", "lateral_movement"],
                "throttle_edge": ["lateral_movement", "exfiltration"],
                "restrict_smb": ["lateral_movement"],
                "block_egress": ["command_and_control", "exfiltration"],
                "isolate_host": ["impact", "command_and_control", "exfiltration", "lateral_movement"],
            },
        )

    def evaluate(
        self,
        action: CandidateDefenseAction,
        action_mask: ActionMask,
        twin_snapshot: TwinSnapshot,
        belief_snapshot: BeliefSnapshot,
        active_actions: list[ExecutionRecord],
        reference_time,
        kill_switch: KillSwitch | None = None,
    ) -> SafetyDecision:
        """Evaluate action safety and return an auditable decision."""
        reference = ensure_utc(reference_time)
        violations: list[str] = []
        warnings: list[str] = []
        approvals: list[str] = []
        reasons: list[str] = []
        tier = action_tier(action.action_type, self.config)
        adapter_type = adapter_type_for(action.action_type, self.config)
        blast_radius = len(action.target_entity_ids)
        allowed_scope = sorted(action.target_entity_ids)

        if not action_mask.allowed:
            violations.append("action_mask_blocked")
            reasons.extend(action_mask.mask_reasons)
        if action_mask.approval_required or action.requires_approval:
            approvals.append("action_mask_or_candidate_requires_approval")

        if kill_switch and kill_switch.is_blocked(
            action_type=action.action_type,
            environment="lab",
        ):
            violations.append("automation_kill_switch_enabled")
            reasons.append("Kill switch blocks new automatic execution.")

        if adapter_type not in self.enabled_adapters:
            violations.append("adapter_unavailable")
            reasons.append(f"Required adapter is disabled: {adapter_type}.")

        target_findings = self._evaluate_targets(action, twin_snapshot)
        violations.extend(target_findings["violations"])
        warnings.extend(target_findings["warnings"])
        if target_findings["approval_required"]:
            approvals.append("protected_asset_requires_approval")
        if target_findings["protected_disruptive"]:
            violations.append("protected_asset_disruptive_action")
        if target_findings["management_channel"]:
            violations.append("management_or_rollback_channel_targeted")
        if target_findings["external_target"]:
            violations.append("external_or_hackback_target")

        min_confidence = self.confidence_thresholds.get(
            action.risk_tier,
            self.confidence_thresholds.get("critical", 0.95),
        )
        if action.confidence < min_confidence:
            if tier >= 2:
                violations.append("confidence_below_tier_threshold")
            else:
                approvals.append("low_confidence_monitoring_required")
            warnings.append(
                f"confidence {action.confidence:.3f} below {min_confidence:.3f}"
            )

        if twin_snapshot.freshness_score < self.min_freshness:
            warnings.append("twin_freshness_below_threshold")
            if tier >= 2:
                approvals.append("stale_twin_requires_approval")
        if twin_snapshot.coverage_score < self.min_coverage:
            warnings.append("graph_coverage_below_threshold")
            if tier >= 2:
                approvals.append("low_coverage_requires_approval")

        if blast_radius > self.blast_radius_limit:
            violations.append("blast_radius_limit_exceeded")
        if action.deployment_cost > self.action_budget:
            violations.append("action_budget_exceeded")

        ttl = min(action.ttl_seconds or self.default_ttl, self.maximum_ttl)
        if tier >= 2 and (action.ttl_seconds is None or action.ttl_seconds <= 0):
            violations.append("ttl_required_for_tier")
        if action.ttl_seconds and action.ttl_seconds > self.maximum_ttl:
            warnings.append("ttl_reduced_to_policy_maximum")

        if tier >= self.rollback_required_tier and not action.rollback_plan:
            violations.append("rollback_plan_required")
        if tier >= self.reversible_required_tier and not action.rollback_supported:
            violations.append("reversible_action_required")

        if self._has_conflicting_active_action(action, active_actions):
            violations.append("duplicate_or_conflicting_active_action")

        if not self._stage_compatible(action, belief_snapshot):
            approvals.append("attack_stage_review_required")
            warnings.append("action_stage_not_confirmed")

        if action.action_type in {
            "hack_back",
            "delete_credentials",
            "block_all_traffic",
            "modify_critical_database",
            "block_subnet",
            "disable_privileged_identity",
            "isolate_database",
        }:
            violations.append("prohibited_high_risk_action")

        verdict = self._verdict_for(tier, violations, approvals, action.confidence)
        if verdict == SafetyVerdict.REQUIRE_APPROVAL and not approvals:
            approvals.append("policy_requires_approval")
        if not reasons:
            reasons.append(self._default_reason(verdict, tier, adapter_type))

        return SafetyDecision(
            action_id=action.action_id,
            verdict=verdict,
            risk_tier=action.risk_tier,
            confidence=action.confidence,
            business_risk=action.business_risk,
            blast_radius_estimate=blast_radius,
            twin_freshness=twin_snapshot.freshness_score,
            graph_coverage=twin_snapshot.coverage_score,
            violated_policies=sorted(set(violations)),
            warnings=sorted(set(warnings)),
            required_approvals=sorted(set(approvals)),
            allowed_scope=[] if violations else allowed_scope,
            maximum_ttl_seconds=ttl if not violations else None,
            rollback_required=tier >= self.rollback_required_tier,
            reasons=sorted(set(reasons)),
            policy_version=self.version,
            evaluated_at=reference,
        )

    def _evaluate_targets(
        self,
        action: CandidateDefenseAction,
        twin_snapshot: TwinSnapshot,
    ) -> dict[str, Any]:
        violations: list[str] = []
        warnings: list[str] = []
        approval_required = False
        protected_disruptive = False
        management_channel = False
        external_target = False
        tier = action_tier(action.action_type, self.config)
        if not action.target_entity_ids and action.action_type not in {
            "create_soc_ticket",
            "request_analyst_review",
        }:
            violations.append("missing_target")
        for target in action.target_entity_ids:
            asset = twin_snapshot.assets.get(target)
            identity = twin_snapshot.identities.get(target)
            exists = bool(
                asset
                or identity
                or target.startswith(("credential:", "comm:", "session:", "incident:"))
            )
            if not exists:
                violations.append("target_not_found")
                continue
            if target in self.management_channel_ids:
                management_channel = True
            if asset:
                environment = str(asset.environment or "").lower()
                if environment not in self.managed_environments:
                    violations.append("target_outside_managed_environment")
                if (
                    target in self.protected_asset_ids
                    or asset.asset_type in self.protected_asset_types
                    or asset.business_criticality >= float(
                        self.config.get("protected_criticality_threshold", 0.85)
                    )
                    or asset.attributes.get("protected") is True
                ):
                    approval_required = True
                    warnings.append(f"target_is_protected:{target}")
                    if tier >= 2:
                        protected_disruptive = True
                if asset.asset_type in {"management", "control_plane"}:
                    management_channel = True
                if environment in {"external", "internet", "unmanaged"}:
                    external_target = True
                for ip_value in asset.ip_addresses:
                    if self._is_external_ip(ip_value):
                        external_target = True
            if target.startswith("asset:ip:"):
                raw_ip = target.removeprefix("asset:ip:").replace("-", ".")
                if self._is_external_ip(raw_ip):
                    external_target = True
        return {
            "violations": violations,
            "warnings": warnings,
            "approval_required": approval_required,
            "protected_disruptive": protected_disruptive,
            "management_channel": management_channel,
            "external_target": external_target,
        }

    def _is_external_ip(self, value: str) -> bool:
        try:
            ip = ipaddress.ip_address(value)
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except ValueError:
            return False

    def _has_conflicting_active_action(
        self,
        action: CandidateDefenseAction,
        active_actions: list[ExecutionRecord],
    ) -> bool:
        active_states = {
            ExecutionState.PREPARED,
            ExecutionState.CANARY_RUNNING,
            ExecutionState.EXECUTING,
            ExecutionState.VERIFYING,
            ExecutionState.SUCCEEDED,
        }
        target_set = set(action.target_entity_ids)
        for record in active_actions:
            if record.current_state not in active_states:
                continue
            payload_targets = set()
            for result in record.adapter_results:
                payload_targets.update(result.details.get("targets", []))
            if not payload_targets:
                continue
            if target_set.intersection(payload_targets):
                return True
        return False

    def _stage_compatible(
        self,
        action: CandidateDefenseAction,
        belief_snapshot: BeliefSnapshot,
    ) -> bool:
        allowed = set(self.compatible_stages.get(action.action_type, []))
        if not allowed:
            return True
        for target in action.target_entity_ids:
            belief = belief_snapshot.entity_beliefs.get(target)
            if belief and belief.most_likely_stage in allowed:
                return True
        return not action.target_entity_ids

    def _verdict_for(
        self,
        tier: int,
        violations: list[str],
        approvals: list[str],
        confidence: float,
    ) -> SafetyVerdict:
        if violations:
            return SafetyVerdict.DENY
        if tier >= 4:
            return SafetyVerdict.DENY
        if approvals:
            return SafetyVerdict.REQUIRE_APPROVAL
        if tier == 0:
            return SafetyVerdict.ALLOW
        if tier in {1, 2}:
            return SafetyVerdict.ALLOW_WITH_MONITORING
        if tier == 3:
            high_conf = float(self.config.get("tier3_auto_confidence", 0.98))
            return (
                SafetyVerdict.ALLOW_WITH_MONITORING
                if confidence >= high_conf
                else SafetyVerdict.REQUIRE_APPROVAL
            )
        return SafetyVerdict.DENY

    def _default_reason(
        self,
        verdict: SafetyVerdict,
        tier: int,
        adapter_type: str,
    ) -> str:
        return (
            f"Safety policy {self.version} returned {verdict.value} "
            f"for Tier {tier} action using {adapter_type}."
        )


class SafetyGate:
    """Facade with the requested Milestone 4 evaluate signature."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        audit_store: ImmutableAuditStore | None = None,
        kill_switch: KillSwitch | None = None,
    ) -> None:
        self.policy = SafetyPolicyEngine(config)
        self.audit_store = audit_store or ImmutableAuditStore()
        self.kill_switch = kill_switch

    def evaluate(
        self,
        action,
        action_mask,
        twin_snapshot,
        belief_snapshot,
        active_actions,
        reference_time,
    ) -> SafetyDecision:
        """Evaluate one candidate action against Safety Gate V1."""
        decision = self.policy.evaluate(
            action,
            action_mask,
            twin_snapshot,
            belief_snapshot,
            active_actions,
            reference_time,
            kill_switch=self.kill_switch,
        )
        self.audit_store.append(
            "safety_decision",
            action_id=action.action_id,
            policy_version=decision.policy_version,
            twin_version=str(twin_snapshot.twin_version),
            belief_version=str(belief_snapshot.belief_version),
            payload={
                "action": action.model_dump(mode="json"),
                "mask": action_mask.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
            },
            timestamp=decision.evaluated_at,
        )
        return decision
