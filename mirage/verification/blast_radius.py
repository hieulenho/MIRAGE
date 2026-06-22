"""Blast-radius verification."""

from __future__ import annotations

from mirage.domain.schemas import ExecutionPlan, TwinSnapshot
from mirage.verification.schema import BlastRadiusEstimate


class BlastRadiusVerifier:
    """Estimate maximum impact of an execution plan."""

    def estimate(
        self,
        execution_plan: ExecutionPlan,
        twin_snapshot: TwinSnapshot,
        dependency_graph: dict[str, list[str]] | None = None,
        *,
        limits: dict[str, int] | None = None,
    ) -> BlastRadiusEstimate:
        limits = limits or {"maximum_affected_entities": 5}
        direct = sorted(set(execution_plan.allowed_scope or execution_plan.targets))
        dependencies = dependency_graph or {}
        indirect = sorted({
            dependency
            for entity in direct
            for dependency in dependencies.get(entity, [])
        })
        protected = sorted([
            entity for entity in [*direct, *indirect]
            if _is_protected(entity, twin_snapshot)
        ])
        identities = sorted([
            relationship.target_entity_id
            for relationship in twin_snapshot.relationships.values()
            if relationship.active
            and relationship.source_entity_id in set([*direct, *indirect])
            and relationship.target_entity_id in twin_snapshot.identities
        ])
        services = sorted({
            twin_snapshot.assets[entity].attributes.get("business_service", "")
            for entity in [*direct, *indirect]
            if entity in twin_snapshot.assets
        } - {""})
        missing = [
            f"missing_dependency_info:{entity}"
            for entity in direct
            if entity not in dependencies
        ]
        total = len(set([*direct, *indirect, *identities]))
        violations = []
        if total > int(limits.get("maximum_affected_entities", 5)):
            violations.append("maximum_affected_entities_exceeded")
        if len(protected) > int(limits.get("maximum_protected_entities", 0)):
            violations.append("protected_entities_affected")
        return BlastRadiusEstimate(
            directly_affected_entities=direct,
            indirectly_affected_entities=indirect,
            protected_entities_affected=protected,
            business_services_affected=services,
            affected_identities=identities,
            affected_flows=list(execution_plan.parameters.get("affected_flows", [])),
            affected_subnets=list(execution_plan.parameters.get("affected_subnets", [])),
            uncertainty=0.6 if missing else 0.1,
            missing_dependency_warnings=missing,
            limit_violations=violations,
        )


def _is_protected(entity_id: str, twin_snapshot: TwinSnapshot) -> bool:
    asset = twin_snapshot.assets.get(entity_id)
    return bool(
        asset
        and (
            asset.attributes.get("protected")
            or asset.asset_type in {"database", "dc", "domain_controller"}
            or asset.business_criticality >= 0.85
        )
    )
