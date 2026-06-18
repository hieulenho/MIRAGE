"""Central configuration helpers for MIRAGE."""

from __future__ import annotations

import copy
import json
import math
import os
from pathlib import Path
from typing import Any, Dict, Optional


PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "general": {
        "budget_limit": 6.0,
        "discount_factor": 0.95,
    },
    "topology": {
        "source": "builtin",
        "path": "examples/enterprise_topology.json",
        "format": "mirage",
    },
    "layer1": {
        "hmm_weight": 0.6,
        "event_history_limit": 1000,
        "max_tracked_hosts": 10000,
    },
    "layer2": {
        "decoy_realism": 0.8,
    },
    "layer3": {
        "max_actions_per_type": 40,
        "deception_actions": {},
    },
    "layer5": {
        "protected_nodes": [10, 13],
        "protected_asset_types": ["database", "dc"],
    },
    "rl": {
        "backend": "numpy",
        "max_steps": 5,
        "n_attacker_episodes": 12,
        "cost_weight": 0.015,
        "max_actions": 200,
        "hidden_size": 128,
        "model_path": "models/mirage_dqn.npz",
    },
    "api": {
        "host": "0.0.0.0",
        "port": 8000,
        "cors_origins": [
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        "max_batch_size": 1000,
        "max_request_bytes": 2097152,
        "decision_history_limit": 1000,
        "pending_decision_limit": 100,
        "decision_backend": "robust",
        "decision_samples": 60,
        "auto_deploy": True,
        "api_key_env": "MIRAGE_API_KEY",
    },
    "twin": {
        "relationship_ttls": {
            "connects_to": 3600,
            "authenticated_to": 86400,
            "auth_failed_to": 3600,
            "uses_credential_on": 86400,
            "accessed_file_on": 3600,
            "ran_process_on": 3600,
            "has_vulnerability": 604800,
            "interacted_with_decoy": 604800,
            "resolved_dns_to": 3600,
        },
        "snapshot_path": "artifacts/twin_snapshot.json",
        "ingestion_strict": False,
        "max_batch_size": 1000,
        "replay_ordering": "event_time",
        "allow_provisional_entities": True,
        "logging_level": "INFO",
    },
    "detection": {
        "timeline_retention_seconds": 86400,
        "windows": [60, 300, 900, 3600],
        "rules": {
            "R001_SUSPICIOUS_SCRIPT": {"enabled": True, "score": 0.65},
            "R002_INTERNAL_DISCOVERY_BURST": {"enabled": True, "score": 0.55},
            "R003_SMB_LATERAL_PATTERN": {"enabled": True, "score": 0.65},
            "R004_AUTH_SPRAY": {"enabled": True, "score": 0.7},
            "R005_SUCCESS_AFTER_FAILURES": {"enabled": True, "score": 0.75},
            "R006_IDENTITY_FANOUT": {"enabled": True, "score": 0.55},
            "R007_CREDENTIAL_TO_REMOTE": {"enabled": True, "score": 0.7},
            "R008_DECEPTION_INTERACTION": {"enabled": True, "score": 0.98},
            "R009_CRITICAL_ASSET_APPROACH": {"enabled": True, "score": 0.68},
            "R010_BENIGN_ADMIN_SUPPRESSION": {"enabled": True, "score": -0.45},
        },
        "stage_priors": {
            "normal": 0.7,
            "reconnaissance": 0.02,
            "initial_access": 0.04,
            "execution": 0.04,
            "credential_access": 0.04,
            "discovery": 0.05,
            "lateral_movement": 0.04,
            "collection": 0.03,
        },
        "stage_transition_weight": 0.15,
        "evidence_decay_seconds": 3600,
        "evidence_ttl_seconds": 3600,
        "correlation_window_seconds": 3600,
        "compromise_threshold": 0.35,
        "high_confidence_deception_threshold": 0.85,
        "approved_admin_hosts": ["admin-jump-01"],
        "approved_service_accounts": ["svc-backup", "svc-monitor"],
        "maintenance_windows": [],
        "graph_propagation_depth": 1,
        "graph_propagation_decay": 0.45,
        "api_timeline_limit": 100,
    },
    "analysis": {
        "seed_selection": {
            "minimum_compromise_probability": 0.30,
            "minimum_attacker_location_probability": 0.20,
            "maximum_seeds": 20,
            "uncertainty_penalty": 0.20,
            "deception_event_priority": 0.25,
            "neighborhood_deduplication": True,
        },
        "subgraph": {
            "default_max_hops": 3,
            "max_nodes": 80,
            "max_edges": 160,
            "minimum_edge_confidence": 0.10,
            "freshness_threshold": 86400,
            "relationship_allowlist": [],
            "criticality_threshold": 0.80,
        },
        "paths": {
            "maximum_path_length": 6,
            "maximum_paths_per_target": 3,
            "maximum_total_paths": 60,
            "enabled_path_types": [
                "shortest_to_critical_asset",
                "highest_success_probability",
                "highest_risk",
                "credential_driven",
                "recently_observed",
                "decoy_path",
                "unprotected_path",
                "high_blast_radius",
            ],
            "observed_edge_bonus": 0.12,
            "inferred_edge_penalty": 0.25,
            "stale_edge_penalty": 0.20,
            "uncertainty_penalty": 0.20,
        },
        "risk_scoring": {
            "source_compromise_weight": 1.0,
            "path_success_weight": 1.0,
            "target_criticality_weight": 1.0,
            "stage_compatibility_weight": 0.8,
            "evidence_recency_weight": 0.8,
            "relationship_confidence_weight": 0.8,
            "credential_feasibility_weight": 0.6,
            "exposure_weight": 0.5,
            "probability_floor": 0.01,
            "probability_ceiling": 0.99,
        },
        "candidate_actions": {
            "enabled_action_types": [
                "increase_endpoint_logging",
                "increase_network_telemetry",
                "enable_limited_packet_capture",
                "enable_auth_auditing",
                "create_soc_ticket",
                "request_analyst_review",
                "deploy_decoy_database",
                "deploy_fake_share",
                "scatter_honey_credential",
                "add_decoy_service",
                "throttle_edge",
                "restrict_smb",
                "require_mfa",
                "temporary_segmentation",
                "block_egress",
                "isolate_host",
            ],
            "default_ttl_seconds": 3600,
            "action_costs": {
                "increase_endpoint_logging": 0.2,
                "increase_network_telemetry": 0.3,
                "enable_limited_packet_capture": 0.5,
                "enable_auth_auditing": 0.25,
                "create_soc_ticket": 0.1,
                "request_analyst_review": 0.1,
                "deploy_decoy_database": 1.5,
                "deploy_fake_share": 0.9,
                "scatter_honey_credential": 0.8,
                "add_decoy_service": 1.0,
                "throttle_edge": 0.5,
                "restrict_smb": 0.7,
                "require_mfa": 0.8,
                "temporary_segmentation": 1.2,
                "block_egress": 1.0,
                "isolate_host": 2.0
            },
            "business_risks": {
                "increase_endpoint_logging": 0.05,
                "increase_network_telemetry": 0.05,
                "enable_limited_packet_capture": 0.15,
                "enable_auth_auditing": 0.05,
                "create_soc_ticket": 0.01,
                "request_analyst_review": 0.01,
                "deploy_decoy_database": 0.10,
                "deploy_fake_share": 0.08,
                "scatter_honey_credential": 0.05,
                "add_decoy_service": 0.10,
                "throttle_edge": 0.20,
                "restrict_smb": 0.30,
                "require_mfa": 0.25,
                "temporary_segmentation": 0.50,
                "block_egress": 0.55,
                "isolate_host": 0.75
            },
            "information_gain_weights": {
                "observe": 0.8,
                "deception": 0.7,
                "control": 0.3
            },
        },
        "constraints": {
            "protected_asset_ids": [],
            "protected_asset_types": ["database", "dc", "domain_controller"],
            "required_confidence_threshold": 0.35,
            "twin_freshness_threshold": 0.35,
            "graph_coverage_threshold": 0.20,
            "blast_radius_limit": 5,
            "action_budget": 6.0,
            "active_decoy_limit": 20,
            "deny_action_types": ["delete_credentials", "block_all_traffic"],
        },
        "ranking": {
            "risk_reduction_weight": 1.0,
            "information_gain_weight": 0.4,
            "path_coverage_weight": 0.3,
            "operational_cost_weight": 0.15,
            "deployment_cost_weight": 0.15,
            "business_risk_weight": 0.4,
            "uncertainty_weight": 0.3,
        },
    },
    "execution": {
        "policy_version": "safety-v1",
        "action_tiers": {
            "increase_endpoint_logging": 0,
            "increase_network_telemetry": 0,
            "enable_limited_packet_capture": 0,
            "enable_auth_auditing": 0,
            "create_soc_ticket": 0,
            "request_analyst_review": 0,
            "deploy_decoy_host": 1,
            "deploy_decoy_database": 1,
            "deploy_fake_share": 1,
            "scatter_honey_credential": 1,
            "add_decoy_service": 1,
            "create_fake_dns_record": 1,
            "throttle_edge": 2,
            "restrict_smb": 2,
            "temporary_segmentation": 2,
            "block_egress": 3,
            "block_flow": 3,
            "revoke_session": 3,
            "isolate_host": 3,
            "isolate_database": 4,
            "block_subnet": 4,
            "disable_privileged_identity": 4,
        },
        "confidence_thresholds": {
            "low": 0.20,
            "medium": 0.35,
            "high": 0.70,
            "critical": 0.95,
        },
        "protected_asset_ids": [],
        "protected_asset_types": ["database", "dc", "domain_controller"],
        "protected_criticality_threshold": 0.85,
        "managed_environments": ["lab", "test", "dev", ""],
        "management_channel_ids": [],
        "twin_freshness_threshold": 0.35,
        "graph_coverage_threshold": 0.20,
        "blast_radius_limit": 5,
        "action_budget": 6.0,
        "default_ttl_seconds": 3600,
        "maximum_ttl_seconds": 14400,
        "approval_ttl_seconds": 900,
        "rollback_required_tier": 2,
        "reversible_required_tier": 2,
        "tier3_auto_confidence": 0.98,
        "adapters": {
            "docker_decoy": True,
            "mock_firewall": True,
            "mock_edr": True,
            "mock_iam": True,
            "mock_dns": True,
            "mock_telemetry": True,
            "mock_ticket": True,
        },
        "canary_timeout_seconds": 60,
        "execution_timeout_seconds": 300,
        "retries": 1,
        "rollback_retries": 2,
        "kill_switch": {
            "default_enabled": False
        },
        "audit_path": "artifacts/execution_audit.jsonl",
        "docker_templates": {
            "decoy_database": "mirage-decoy-db-template",
            "fake_smb": "mirage-fake-smb-template"
        },
        "lab_networks": {
            "control": "mirage-control",
            "workload": "mirage-workload",
            "decoy": "mirage-decoy"
        }
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _finite_number(
    config: Dict[str, Any],
    section: str,
    key: str,
    *,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
) -> float:
    try:
        value = float(config[section][key])
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"{section}.{key} must be numeric") from exc
    if not math.isfinite(value):
        raise ValueError(f"{section}.{key} must be finite")
    if minimum is not None and value < minimum:
        raise ValueError(f"{section}.{key} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{section}.{key} must be <= {maximum}")
    return value


def _validate_config(config: Dict[str, Any]) -> None:
    """Validate values that affect solver safety and API behavior."""
    _finite_number(config, "general", "budget_limit", minimum=0)
    discount = _finite_number(
        config,
        "general",
        "discount_factor",
        minimum=0,
    )
    if discount >= 1:
        raise ValueError("general.discount_factor must be < 1")
    _finite_number(config, "layer1", "hmm_weight", minimum=0, maximum=1)
    if int(config["layer1"]["event_history_limit"]) < 1:
        raise ValueError("layer1.event_history_limit must be at least 1")
    if int(config["layer1"]["max_tracked_hosts"]) < 1:
        raise ValueError("layer1.max_tracked_hosts must be at least 1")
    _finite_number(config, "layer2", "decoy_realism", minimum=0, maximum=1)

    topology = config["topology"]
    if str(topology.get("source", "")).lower() not in {"builtin", "file"}:
        raise ValueError("topology.source must be 'builtin' or 'file'")
    if str(topology.get("format", "")).lower() not in {
        "mirage",
        "bloodhound",
        "nmap",
    }:
        raise ValueError(
            "topology.format must be 'mirage', 'bloodhound', or 'nmap'"
        )

    if int(config["layer3"]["max_actions_per_type"]) < 1:
        raise ValueError("layer3.max_actions_per_type must be at least 1")
    for action_name, action_config in config["layer3"][
        "deception_actions"
    ].items():
        if not isinstance(action_config, dict):
            raise ValueError(
                f"layer3.deception_actions.{action_name} must be an object"
            )
        for key in (
            "risk_score",
            "realism_score",
            "business_impact",
        ):
            if key in action_config:
                value = float(action_config[key])
                if not math.isfinite(value) or not 0 <= value <= 1:
                    raise ValueError(
                        f"layer3.deception_actions.{action_name}.{key} "
                        "must be between 0 and 1"
                    )
        for key in ("cost", "reward_delta", "edge_cost_delta"):
            if key in action_config:
                value = float(action_config[key])
                if not math.isfinite(value) or value < 0:
                    raise ValueError(
                        f"layer3.deception_actions.{action_name}.{key} "
                        "must be finite and non-negative"
                    )

    if not isinstance(config["layer5"]["protected_nodes"], list):
        raise ValueError("layer5.protected_nodes must be a list")
    if not isinstance(config["layer5"]["protected_asset_types"], list):
        raise ValueError("layer5.protected_asset_types must be a list")

    for key in ("max_steps", "n_attacker_episodes", "max_actions", "hidden_size"):
        if int(config["rl"][key]) < 1:
            raise ValueError(f"rl.{key} must be at least 1")
    _finite_number(config, "rl", "cost_weight", minimum=0)
    if str(config["rl"]["backend"]).lower() not in {
        "numpy",
        "torch",
        "auto",
    }:
        raise ValueError("rl.backend must be 'numpy', 'torch', or 'auto'")

    port = int(config["api"]["port"])
    if not 1 <= port <= 65535:
        raise ValueError("api.port must be between 1 and 65535")
    if int(config["api"]["max_batch_size"]) < 1:
        raise ValueError("api.max_batch_size must be at least 1")
    if int(config["api"]["max_request_bytes"]) < 1024:
        raise ValueError("api.max_request_bytes must be at least 1024")
    if int(config["api"]["decision_samples"]) < 1:
        raise ValueError("api.decision_samples must be at least 1")
    if int(config["api"]["decision_history_limit"]) < 1:
        raise ValueError("api.decision_history_limit must be at least 1")
    if int(config["api"]["pending_decision_limit"]) < 1:
        raise ValueError("api.pending_decision_limit must be at least 1")
    if str(config["api"]["decision_backend"]).lower() not in {"robust", "rl"}:
        raise ValueError("api.decision_backend must be 'robust' or 'rl'")
    if not isinstance(config["api"]["cors_origins"], list):
        raise ValueError("api.cors_origins must be a list")

    twin = config["twin"]
    if not isinstance(twin["relationship_ttls"], dict):
        raise ValueError("twin.relationship_ttls must be an object")
    for name, ttl in twin["relationship_ttls"].items():
        if int(ttl) < 0:
            raise ValueError(f"twin.relationship_ttls.{name} must be >= 0")
    if int(twin["max_batch_size"]) < 1:
        raise ValueError("twin.max_batch_size must be at least 1")
    if str(twin["replay_ordering"]).lower() not in {"event_time", "file"}:
        raise ValueError("twin.replay_ordering must be 'event_time' or 'file'")
    if str(twin["logging_level"]).upper() not in {
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        "CRITICAL",
    }:
        raise ValueError("twin.logging_level must be a standard log level")

    detection = config["detection"]
    if int(detection["timeline_retention_seconds"]) < 1:
        raise ValueError("detection.timeline_retention_seconds must be at least 1")
    if not isinstance(detection["windows"], list) or not detection["windows"]:
        raise ValueError("detection.windows must be a non-empty list")
    for window in detection["windows"]:
        if int(window) < 1:
            raise ValueError("detection.windows values must be at least 1")
    for key in (
        "stage_transition_weight",
        "evidence_decay_seconds",
        "evidence_ttl_seconds",
        "correlation_window_seconds",
        "compromise_threshold",
        "high_confidence_deception_threshold",
        "graph_propagation_decay",
    ):
        value = float(detection[key])
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"detection.{key} must be finite and non-negative")
    if not 0 <= float(detection["compromise_threshold"]) <= 1:
        raise ValueError("detection.compromise_threshold must be in [0, 1]")
    if not 0 <= float(detection["high_confidence_deception_threshold"]) <= 1:
        raise ValueError(
            "detection.high_confidence_deception_threshold must be in [0, 1]"
        )
    if int(detection["graph_propagation_depth"]) < 0:
        raise ValueError("detection.graph_propagation_depth must be >= 0")
    if int(detection["api_timeline_limit"]) < 1:
        raise ValueError("detection.api_timeline_limit must be at least 1")

    analysis = config["analysis"]
    seed = analysis["seed_selection"]
    if int(seed["maximum_seeds"]) < 1:
        raise ValueError("analysis.seed_selection.maximum_seeds must be at least 1")
    for key in (
        "minimum_compromise_probability",
        "minimum_attacker_location_probability",
        "uncertainty_penalty",
        "deception_event_priority",
    ):
        value = float(seed[key])
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"analysis.seed_selection.{key} must be >= 0")
    subgraph = analysis["subgraph"]
    for key in ("default_max_hops", "max_nodes", "max_edges"):
        if int(subgraph[key]) < 0:
            raise ValueError(f"analysis.subgraph.{key} must be >= 0")
    if int(subgraph["max_nodes"]) < 1:
        raise ValueError("analysis.subgraph.max_nodes must be at least 1")
    for key in ("minimum_edge_confidence", "criticality_threshold"):
        value = float(subgraph[key])
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"analysis.subgraph.{key} must be in [0, 1]")
    paths = analysis["paths"]
    for key in ("maximum_path_length", "maximum_paths_per_target", "maximum_total_paths"):
        if int(paths[key]) < 1:
            raise ValueError(f"analysis.paths.{key} must be at least 1")
    constraints = analysis["constraints"]
    for key in ("required_confidence_threshold", "twin_freshness_threshold", "graph_coverage_threshold"):
        value = float(constraints[key])
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"analysis.constraints.{key} must be in [0, 1]")
    if float(constraints["action_budget"]) < 0:
        raise ValueError("analysis.constraints.action_budget must be >= 0")

    execution = config["execution"]
    if int(execution["blast_radius_limit"]) < 1:
        raise ValueError("execution.blast_radius_limit must be at least 1")
    for key in (
        "twin_freshness_threshold",
        "graph_coverage_threshold",
        "protected_criticality_threshold",
        "tier3_auto_confidence",
    ):
        value = float(execution[key])
        if not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError(f"execution.{key} must be in [0, 1]")
    for key in (
        "action_budget",
        "default_ttl_seconds",
        "maximum_ttl_seconds",
        "approval_ttl_seconds",
        "canary_timeout_seconds",
        "execution_timeout_seconds",
        "retries",
        "rollback_retries",
    ):
        value = float(execution[key])
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"execution.{key} must be finite and non-negative")
    if int(execution["maximum_ttl_seconds"]) < int(execution["default_ttl_seconds"]):
        raise ValueError(
            "execution.maximum_ttl_seconds must be >= default_ttl_seconds"
        )
    if not isinstance(execution["adapters"], dict):
        raise ValueError("execution.adapters must be an object")


def get_config_path(path: Optional[os.PathLike | str] = None) -> Path:
    configured = path or os.environ.get("MIRAGE_CONFIG")
    if configured:
        candidate = Path(configured).expanduser()
        if not candidate.is_absolute():
            candidate = PROJECT_ROOT / candidate
        return candidate.resolve()
    return DEFAULT_CONFIG_PATH


def load_config(path: Optional[os.PathLike | str] = None) -> Dict[str, Any]:
    """Load configuration and merge missing values from safe defaults."""
    config_path = get_config_path(path)
    if not config_path.exists():
        return copy.deepcopy(DEFAULT_CONFIG)

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            loaded = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid MIRAGE config JSON at {config_path}: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ValueError(f"MIRAGE config must be a JSON object: {config_path}")
    config = _deep_merge(DEFAULT_CONFIG, loaded)
    _validate_config(config)
    return config


def resolve_project_path(value: os.PathLike | str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()
