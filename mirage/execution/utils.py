"""Shared helpers for lab-safe execution."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from mirage.detection.utils import stable_id


OBSERVE_ACTIONS = {
    "increase_endpoint_logging",
    "increase_network_telemetry",
    "enable_limited_packet_capture",
    "enable_auth_auditing",
    "create_soc_ticket",
    "request_analyst_review",
}
DECEPTION_ACTIONS = {
    "deploy_decoy_host",
    "deploy_decoy_database",
    "deploy_fake_share",
    "scatter_honey_credential",
    "add_decoy_service",
    "create_fake_dns_record",
    "rotate_decoy",
    "remove_decoy",
}
DELAY_ACTIONS = {
    "throttle_edge",
    "restrict_smb",
    "temporary_segmentation",
    "temporary_rate_limit",
    "temporary_smb_throttle",
    "temporary_rdp_throttle",
}
LIMITED_CONTAINMENT_ACTIONS = {
    "block_egress",
    "block_flow",
    "revoke_session",
    "isolate_host",
}
HIGH_RISK_ACTIONS = {
    "isolate_database",
    "block_subnet",
    "disable_privileged_identity",
    "modify_critical_database",
    "delete_credentials",
    "block_all_traffic",
}

ACTION_TIERS = {
    **{action: 0 for action in OBSERVE_ACTIONS},
    **{action: 1 for action in DECEPTION_ACTIONS},
    **{action: 2 for action in DELAY_ACTIONS},
    **{action: 3 for action in LIMITED_CONTAINMENT_ACTIONS},
    **{action: 4 for action in HIGH_RISK_ACTIONS},
}

ADAPTER_BY_ACTION = {
    "increase_endpoint_logging": "mock_telemetry",
    "increase_network_telemetry": "mock_telemetry",
    "enable_limited_packet_capture": "mock_telemetry",
    "enable_auth_auditing": "mock_telemetry",
    "create_soc_ticket": "mock_ticket",
    "request_analyst_review": "mock_ticket",
    "deploy_decoy_host": "docker_decoy",
    "deploy_decoy_database": "docker_decoy",
    "deploy_fake_share": "docker_decoy",
    "add_decoy_service": "docker_decoy",
    "scatter_honey_credential": "mock_iam",
    "create_fake_dns_record": "mock_dns",
    "rotate_decoy": "docker_decoy",
    "remove_decoy": "docker_decoy",
    "throttle_edge": "mock_firewall",
    "restrict_smb": "mock_firewall",
    "temporary_segmentation": "mock_firewall",
    "temporary_rate_limit": "mock_firewall",
    "temporary_smb_throttle": "mock_firewall",
    "temporary_rdp_throttle": "mock_firewall",
    "block_egress": "mock_firewall",
    "block_flow": "mock_firewall",
    "revoke_session": "mock_iam",
    "isolate_host": "mock_edr",
}


def utc_now() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)


def ensure_utc(value: datetime | None) -> datetime:
    """Return a timezone-aware UTC datetime."""
    raw = value or utc_now()
    if raw.tzinfo is None or raw.utcoffset() is None:
        raw = raw.replace(tzinfo=timezone.utc)
    return raw.astimezone(timezone.utc)


def action_tier(action_type: str, config: dict[str, Any] | None = None) -> int:
    """Return configured action tier, defaulting to conservative Tier 4."""
    tiers = (config or {}).get("action_tiers", {})
    if action_type in tiers:
        return int(tiers[action_type])
    return ACTION_TIERS.get(action_type, 4)


def adapter_type_for(action_type: str, config: dict[str, Any] | None = None) -> str:
    """Return the configured lab adapter type for an action."""
    overrides = (config or {}).get("adapter_by_action", {})
    return str(overrides.get(action_type) or ADAPTER_BY_ACTION.get(action_type, "mock_firewall"))


def deterministic_id(prefix: str, *parts: object) -> str:
    """Create a compact deterministic ID."""
    return stable_id(prefix, parts)
