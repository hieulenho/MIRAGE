"""Pilot scope registry."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mirage.pilot.schema import PilotScope, RolloutLevel


class PilotScopeRegistry:
    """In-memory pilot scope registry."""

    def __init__(self, scopes: list[PilotScope] | None = None) -> None:
        self._scopes = {scope.scope_id: scope for scope in (scopes or default_scopes())}

    def register(self, scope: PilotScope) -> None:
        self._scopes[scope.scope_id] = scope

    def get(self, scope_id: str) -> PilotScope | None:
        return self._scopes.get(scope_id)

    def list_scopes(self, enabled_only: bool = False) -> list[PilotScope]:
        scopes = sorted(self._scopes.values(), key=lambda item: item.scope_id)
        if enabled_only:
            scopes = [scope for scope in scopes if scope.enabled]
        return scopes


def default_scopes() -> list[PilotScope]:
    expiry = datetime.now(timezone.utc) + timedelta(days=30)
    return [
        PilotScope(
            scope_id="level0-shadow",
            environment="shadow",
            allowed_action_types=["request_analyst_review", "create_soc_ticket"],
            allowed_asset_ids=[],
            required_approvals=[],
            rollout_level=RolloutLevel.LEVEL_0_SHADOW,
            expiry=expiry,
        ),
        PilotScope(
            scope_id="lab-low-risk",
            environment="lab",
            allowed_action_types=[
                "increase_endpoint_logging",
                "increase_network_telemetry",
                "enable_limited_packet_capture",
                "deploy_decoy_database",
                "deploy_fake_share",
                "scatter_honey_credential",
                "create_fake_dns_record",
                "create_soc_ticket",
                "request_analyst_review",
            ],
            allowed_asset_ids=["asset:workstation-1", "asset:app-1", "asset:decoy-zone"],
            excluded_protected_assets=["asset:prod-db"],
            maximum_affected_entities=4,
            maximum_ttl_seconds=1800,
            required_approvals=["soc_analyst"],
            rollout_level=RolloutLevel.LEVEL_1_LAB,
            expiry=expiry,
        ),
        PilotScope(
            scope_id="deception-pilot",
            environment="pilot",
            allowed_action_types=[
                "deploy_decoy_database",
                "deploy_fake_share",
                "scatter_honey_credential",
                "create_fake_dns_record",
                "increase_endpoint_logging",
            ],
            allowed_asset_ids=["asset:pilot-host-1", "asset:decoy-zone"],
            excluded_protected_assets=["asset:prod-db", "asset:domain-controller"],
            maximum_affected_entities=3,
            maximum_ttl_seconds=1200,
            required_approvals=["soc_analyst", "system_owner"],
            rollout_level=RolloutLevel.LEVEL_3_LOW_RISK_DECEPTION,
            expiry=expiry,
        ),
    ]
