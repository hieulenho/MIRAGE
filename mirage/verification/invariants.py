"""Configurable invariant catalog for formal safety verification."""

from __future__ import annotations

from mirage.verification.schema import (
    InvariantCategory,
    SafetyInvariant,
    VerificationSeverity,
    ViolationResponse,
    utc_now,
)


class SafetySpecificationRegistry:
    """In-memory versioned invariant registry."""

    def __init__(self, invariants: list[SafetyInvariant] | None = None) -> None:
        self._invariants = {
            invariant.invariant_id: invariant
            for invariant in (invariants or default_invariants())
        }

    def register(self, invariant: SafetyInvariant) -> None:
        self._invariants[invariant.invariant_id] = invariant

    def list_invariants(self, enabled_only: bool = True) -> list[SafetyInvariant]:
        values = sorted(self._invariants.values(), key=lambda item: item.invariant_id)
        if enabled_only:
            values = [item for item in values if item.enabled]
        return values

    def get(self, invariant_id: str) -> SafetyInvariant | None:
        return self._invariants.get(invariant_id)


def _inv(
    invariant_id: str,
    name: str,
    category: InvariantCategory,
    severity: VerificationSeverity,
    expression: str,
    response: ViolationResponse = ViolationResponse.REJECT,
) -> SafetyInvariant:
    now = utc_now()
    return SafetyInvariant(
        invariant_id=invariant_id,
        name=name,
        description=name,
        category=category,
        severity=severity,
        formal_expression=expression,
        human_readable_expression=expression,
        required_inputs=["action", "mask", "plan", "twin", "pilot_scope"],
        applicable_action_types=[],
        applicable_environments=["lab", "pilot", "controlled_pilot"],
        violation_response=response,
        policy_version="formal-safety-v1",
        provenance={"milestone": "9", "source": "default_catalog"},
        created_at=now,
        updated_at=now,
    )


def default_invariants() -> list[SafetyInvariant]:
    """Return the default Milestone 9 invariant catalog."""
    return [
        _inv("INV-001", "Protected assets cannot be automatically modified", InvariantCategory.PROTECTED_ASSET, VerificationSeverity.CRITICAL, "automatic_action -> target notin protected_assets"),
        _inv("INV-002", "Management and rollback channels remain reachable", InvariantCategory.MANAGEMENT_CHANNEL, VerificationSeverity.CRITICAL, "soc_control_plane reaches target_management and rollback_controller reaches adapter"),
        _inv("INV-003", "Decoys cannot initiate communication to protected production assets", InvariantCategory.REACHABILITY, VerificationSeverity.CRITICAL, "not reachable(decoy, protected_asset)"),
        _inv("INV-004", "Blast radius remains bounded", InvariantCategory.BLAST_RADIUS, VerificationSeverity.HIGH, "blast_radius <= configured_limits"),
        _inv("INV-005", "Medium and high-risk actions require rollback", InvariantCategory.ROLLBACK, VerificationSeverity.HIGH, "risk>=medium -> rollback_complete"),
        _inv("INV-006", "Action must remain inside pilot scope", InvariantCategory.PILOT_SCOPE, VerificationSeverity.CRITICAL, "targets and action_type in enabled pilot_scope"),
        _inv("INV-007", "Masked actions are never executable", InvariantCategory.APPROVAL, VerificationSeverity.CRITICAL, "mask.allowed == true"),
        _inv("INV-008", "Required approval cannot be bypassed", InvariantCategory.APPROVAL, VerificationSeverity.HIGH, "required_approval -> valid_approval"),
        _inv("INV-009", "Kill switch blocks new execution", InvariantCategory.APPROVAL, VerificationSeverity.CRITICAL, "kill_switch_active -> not automatic_execution"),
        _inv("INV-010", "Twin quality constrains automation", InvariantCategory.DECISION_PROVENANCE, VerificationSeverity.HIGH, "twin_quality >= thresholds"),
        _inv("INV-011", "TTL is mandatory for temporary actions", InvariantCategory.TEMPORAL, VerificationSeverity.MEDIUM, "temporary_action -> bounded_ttl"),
        _inv("INV-012", "Evidence and decision provenance are complete", InvariantCategory.DECISION_PROVENANCE, VerificationSeverity.HIGH, "plan references evidence, mask, safety, verification"),
        _inv("INV-013", "Pilot action cannot affect an unobserved dependency", InvariantCategory.DATA_PROTECTION, VerificationSeverity.MEDIUM, "unknown_dependency -> approval_or_reject", ViolationResponse.REQUIRE_APPROVAL),
        _inv("INV-014", "Business health cannot fall below threshold", InvariantCategory.RESOURCE_BUDGET, VerificationSeverity.HIGH, "runtime_health >= thresholds", ViolationResponse.ROLLBACK),
        _inv("INV-015", "Model uncertainty restricts disruptive actions", InvariantCategory.DECISION_PROVENANCE, VerificationSeverity.HIGH, "uncertainty and OOD below thresholds"),
    ]
