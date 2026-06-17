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
