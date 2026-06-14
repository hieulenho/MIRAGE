"""Central configuration helpers for MIRAGE."""

from __future__ import annotations

import copy
import json
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
        "decision_backend": "robust",
        "decision_samples": 60,
        "auto_deploy": True,
        "api_key_env": "MIRAGE_API_KEY",
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
    return _deep_merge(DEFAULT_CONFIG, loaded)


def resolve_project_path(value: os.PathLike | str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()
