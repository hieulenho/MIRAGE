"""
MIRAGE — Real-time Log Ingestion API Server
=============================================
FastAPI REST/WebSocket server cho phép Layer 1 nhận log trực tiếp từ
Splunk, ELK Stack, Wazuh SIEM thay vì hàm simulate_attack_telemetry.

Endpoints:
  POST   /api/telemetry          — Nhận một hoặc nhiều telemetry events
  POST   /api/telemetry/batch    — Nhận batch events (bulk từ SIEM)
  GET    /api/belief             — Trả belief state hiện tại (tất cả hosts)
  GET    /api/belief/{host}      — Belief state của một host cụ thể
  GET    /api/status             — Trạng thái hệ thống MIRAGE
  GET    /api/graph              — Trả Attack Graph topology (JSON)
  GET    /api/decoys             — Danh sách active deception actions
  GET    /api/decisions          — Lịch sử quyết định gần đây
  POST   /api/decide             — Trigger decision engine thủ công
  WS     /ws                     — WebSocket streaming real-time updates

Dependencies:
  pip install fastapi uvicorn

Usage:
  python -m mirage.api_server                   # Start server at localhost:8000
  python -m mirage.api_server --port 9000       # Custom port
  python -m mirage.api_server --reload          # Dev mode with hot-reload
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import math
import os
import secrets
import sys
import threading
import time
import uuid
from datetime import datetime
from typing import Annotated, Any, Dict, List, Optional

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from fastapi import (
        Body,
        FastAPI,
        HTTPException,
        Request,
        WebSocket,
        WebSocketDisconnect,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, Field, ValidationError
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from mirage.layer1_contextual_ai.attack_modeling import TelemetryEvent, STAGE_NAMES
from mirage.layer1_contextual_ai.hmm_classifier import EnsembleTelemetryClassifier
from mirage.layer2_graph_engine.attack_graph import MIRAGEAttackGraph, build_configured_attack_graph
from mirage.layer3_deception.deception_fabric import DeceptionFabric
from mirage.layer5_safe_control.safe_control import create_safety_gate
from mirage.config import load_config, resolve_project_path
from mirage import __version__

LOGGER = logging.getLogger(__name__)


# ============================================================
# Pydantic Models (API schema)
# ============================================================

if HAS_FASTAPI:
    class TelemetryEventPayload(BaseModel):
        """Telemetry event from SIEM."""
        timestamp: Optional[float] = Field(
            default=None,
            allow_inf_nan=False,
        )
        source_host: str = Field(min_length=1, max_length=255)
        dest_host: str = Field(min_length=1, max_length=255)
        event_type: str = Field(min_length=1, max_length=100)
        protocol: Optional[str] = Field(default=None, max_length=32)
        port: Optional[int] = Field(default=None, ge=0, le=65535)
        username: Optional[str] = Field(default=None, max_length=255)
        success: bool = True
        extra: Dict[str, Any] = Field(default_factory=dict)

    class TelemetryBatchPayload(BaseModel):
        """Batch of telemetry events."""
        events: List[TelemetryEventPayload]

    class DecisionRequest(BaseModel):
        """Manual decision trigger."""
        belief_override: Optional[Dict[str, float]] = None
        budget_remaining: Optional[float] = Field(default=None, ge=0)
        attacker_stage: Optional[str] = Field(default=None, max_length=100)
        backend: Optional[str] = Field(default=None, max_length=20)
        deploy: Optional[bool] = None

    class ApprovalRequest(BaseModel):
        approved_by: str = Field(min_length=1, max_length=100)


def _parse_timestamp(value: Any) -> float:
    if value is None:
        return time.time()
    if isinstance(value, (int, float)):
        timestamp = float(value)
        return timestamp if math.isfinite(timestamp) else time.time()
    text = str(value).strip()
    try:
        timestamp = float(text)
        return timestamp if math.isfinite(timestamp) else time.time()
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return time.time()


def _parse_port(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid destination port: {value!r}") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"Destination port out of range: {port}")
    return port


def _parse_success(value: Any, fallback_text: str = "") -> bool:
    if value is None:
        return "failed" not in fallback_text.lower()
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "1", "yes", "success", "succeeded", "ok"}:
        return True
    if text in {"false", "0", "no", "failure", "failed", "error"}:
        return False
    return bool(text)


def _event_type_from_raw(raw: Dict[str, Any]) -> str:
    candidates = [
        raw.get("event_type"),
        raw.get("event", {}).get("action") if isinstance(raw.get("event"), dict) else None,
        raw.get("action"),
        raw.get("type"),
        raw.get("rule", {}).get("description") if isinstance(raw.get("rule"), dict) else None,
    ]
    text = " ".join(str(value).lower() for value in candidates if value)
    if any(token in text for token in ("port scan", "port_scan", "network scan")):
        return "port_scan"
    if any(token in text for token in ("authentication", "login", "logon", "sshd")):
        return "login_attempt"
    if "smb" in text:
        return "smb_connect"
    if "rdp" in text or "remote desktop" in text:
        return "rdp_connect"
    if "dns" in text:
        return "dns_query"
    if any(token in text for token in ("credential", "password", "dcsync")):
        return "credential_use"
    if any(token in text for token in ("file", "share access")):
        return "file_access"
    if any(token in text for token in ("transfer", "upload", "download")):
        return "data_transfer"
    if any(token in text for token in ("outbound", "external", "egress")):
        return "external_connect"
    return str(candidates[0] or candidates[1] or candidates[2] or "other").lower()


def normalize_siem_payload(payload: Dict[str, Any], source: str) -> Dict[str, Any]:
    """Normalize common Splunk HEC, Elastic, and Wazuh event shapes."""
    source = source.lower()
    raw = dict(payload)
    wrapper = raw
    if source == "splunk" and isinstance(raw.get("event"), dict):
        raw = dict(raw["event"])
    elif source == "elastic" and isinstance(raw.get("_source"), dict):
        raw = dict(raw["_source"])

    data = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}
    agent = raw.get("agent", {}) if isinstance(raw.get("agent"), dict) else {}
    host = raw.get("host", {}) if isinstance(raw.get("host"), dict) else {}
    source_obj = raw.get("source", {}) if isinstance(raw.get("source"), dict) else {}
    destination_obj = (
        raw.get("destination", {})
        if isinstance(raw.get("destination"), dict)
        else {}
    )
    user = raw.get("user", {}) if isinstance(raw.get("user"), dict) else {}

    source_host = (
        raw.get("source_host")
        or source_obj.get("ip")
        or source_obj.get("address")
        or data.get("srcip")
        or agent.get("name")
        or host.get("name")
        or wrapper.get("host")
        or "unknown-source"
    )
    dest_host = (
        raw.get("dest_host")
        or destination_obj.get("ip")
        or destination_obj.get("address")
        or data.get("dstip")
        or raw.get("destination_host")
        or "unknown-destination"
    )
    port = (
        raw.get("port")
        or destination_obj.get("port")
        or data.get("dstport")
    )
    success = raw.get("success")
    if success is None:
        outcome = ""
        event_obj = raw.get("event")
        if isinstance(event_obj, dict):
            outcome = str(event_obj.get("outcome", "")).lower()
        text = json.dumps(raw, ensure_ascii=False).lower()
        success = outcome not in {"failure", "failed"} and "failed" not in text
    else:
        success = _parse_success(success)

    timestamp = (
        raw.get("timestamp")
        or raw.get("@timestamp")
        or wrapper.get("time")
    )
    normalized = {
        "timestamp": _parse_timestamp(timestamp),
        "source_host": str(source_host),
        "dest_host": str(dest_host),
        "event_type": _event_type_from_raw(raw),
        "protocol": raw.get("protocol") or data.get("protocol"),
        "port": _parse_port(port),
        "username": raw.get("username") or user.get("name") or data.get("srcuser"),
        "success": success,
        "extra": {
            "siem_source": source,
            "raw_id": raw.get("id") or wrapper.get("event_id"),
        },
    }
    return normalized


# ============================================================
# MIRAGE State Manager
# ============================================================

class MIRAGEStateManager:
    """
    Singleton-style state manager that holds references to all MIRAGE layers
    and provides thread-safe access for the API server.
    """

    def __init__(self):
        print("[MIRAGE API] Initializing MIRAGE engine...")
        self.config = load_config()
        self._lock = threading.RLock()

        # Layer 2: Attack Graph
        self.graph: MIRAGEAttackGraph = build_configured_attack_graph(self.config)
        print(f"  Graph: {len(self.graph.states)} nodes, "
              f"goals={self.graph.true_goals}, decoys={self.graph.decoy_sites}")

        # Layer 1: Telemetry classifiers
        layer1_config = self.config.get("layer1", {})
        hmm_weight = float(layer1_config.get("hmm_weight", 0.6))
        self.ensemble_classifier = EnsembleTelemetryClassifier(
            hmm_weight=hmm_weight,
            event_history_limit=int(
                layer1_config.get("event_history_limit", 1000)
            ),
            max_tracked_hosts=int(
                layer1_config.get("max_tracked_hosts", 10000)
            ),
        )

        # Layers 3 and 5
        self.fabric = DeceptionFabric(self.graph, verbose=False)
        self.safety_gate = create_safety_gate(
            "results",
            budget_limit=float(
                self.config.get("general", {}).get("budget_limit", 6.0)
            ),
            verbose=False,
        )

        # Decision history
        self.decision_history: List[Dict] = []
        self.pending_decisions: Dict[str, Any] = {}
        api_config = self.config.get("api", {})
        self.decision_history_limit = int(
            api_config.get("decision_history_limit", 1000)
        )
        self.pending_decision_limit = int(
            api_config.get("pending_decision_limit", 100)
        )
        self._rl_bridge = None

        # Metrics
        self.total_events_processed = 0
        self.start_time = time.time()

        # WebSocket connections
        self.ws_connections: List[WebSocket] = []
        self._ws_broadcast_lock = asyncio.Lock()

        print("[MIRAGE API] Engine ready.")

    def process_event(self, payload) -> Dict:
        """Process a single telemetry event and return belief update."""
        event = TelemetryEvent(
            timestamp=payload.timestamp if payload.timestamp is not None else time.time(),
            source_host=payload.source_host,
            dest_host=payload.dest_host,
            event_type=payload.event_type,
            protocol=payload.protocol,
            port=payload.port,
            username=payload.username,
            success=payload.success,
            extra=payload.extra,
        )

        with self._lock:
            ensemble_dist = self.ensemble_classifier.process_event(event)
            dominant_stage, confidence = self.ensemble_classifier.get_dominant_stage(
                event.source_host
            )
            graph_likelihood = self.ensemble_classifier.get_graph_belief_update(
                event.source_host, self.graph
            )
            self.graph.update_belief(graph_likelihood)
            graph_belief = dict(self.graph.belief_state)
            self.total_events_processed += 1
            total_processed = self.total_events_processed

        result = {
            "host": event.source_host,
            "event_type": event.event_type,
            "dominant_stage": STAGE_NAMES.get(dominant_stage, "Unknown"),
            "dominant_stage_id": int(dominant_stage),
            "confidence": round(confidence, 4),
            "stage_distribution": {
                STAGE_NAMES.get(s, "?"): round(p, 4)
                for s, p in ensemble_dist.items()
                if p > 0.01
            },
            "graph_belief_top5": dict(
                sorted(graph_belief.items(), key=lambda x: -x[1])[:5]
            ),
            "timestamp": event.timestamp,
            "total_processed": total_processed,
        }

        return result

    def get_belief_all(self) -> Dict:
        """Get belief states for all tracked hosts."""
        with self._lock:
            beliefs = self.ensemble_classifier.hmm_clf.get_all_beliefs()
        result = {}
        for host, belief in beliefs.items():
            result[host] = {
                "dominant_stage": STAGE_NAMES.get(belief.dominant_stage, "Unknown"),
                "confidence": round(belief.confidence, 4),
                "n_events": belief.n_events_processed,
                "distribution": {
                    STAGE_NAMES.get(s, "?"): round(p, 4)
                    for s, p in belief.stage_distribution.items()
                    if p > 0.01
                },
            }
        return result

    def get_graph_json(self) -> Dict:
        """Serialize graph topology for frontend visualization."""
        with self._lock:
            active_nodes = {
                deployment.action.target_node
                for deployment in self.fabric.active_decoys.values()
            }
            nodes = []
            for s in self.graph.states:
                meta = self.graph.node_metadata.get(s, {})
                belief = self.graph.belief_state.get(s, 0.0)
                nodes.append({
                    "id": s,
                    "label": self.graph.label(s),
                    "layer": meta.get("layer", "unknown"),
                    "asset_type": meta.get("asset_type", "workstation"),
                    "is_real": meta.get("is_real", True),
                    "value": meta.get("value", 0.0),
                    "belief": round(belief, 4),
                    "is_goal": s in self.graph.true_goals,
                    "is_decoy": s in self.graph.active_decoy_sites,
                    "is_decoy_slot": s in self.graph.decoy_sites,
                    "has_active_defense": s in active_nodes,
                    "is_sink": s == self.graph.sink_state,
                })

            edges = []
            seen = set()
            for src in self.graph.states:
                for action, dist in self.graph.transitions.get(src, {}).items():
                    if action in ("end", "noop"):
                        continue
                    for dst, prob in dist.items():
                        key = (src, dst, action)
                        if key not in seen and prob > 0.01:
                            seen.add(key)
                            edges.append({
                                "source": src,
                                "target": dst,
                                "action": action,
                                "probability": round(prob, 3),
                            })

            return {
                "nodes": nodes,
                "edges": edges,
                "active_defenses": self.get_active_decoys(),
            }

    def get_active_decoys(self) -> List[Dict]:
        """Serialize deployed deception actions for API/dashboard clients."""
        with self._lock:
            deployments = []
            for decoy_id, deployment in self.fabric.active_decoys.items():
                action = deployment.action
                deployments.append({
                    "decoy_id": decoy_id,
                    "action_type": action.action_type.value,
                    "target_node": action.target_node,
                    "target_label": self.graph.label(action.target_node),
                    "status": deployment.status.value,
                    "deployed_at": deployment.deployed_at,
                    "engagement_count": deployment.engagement_count,
                    "cost": action.cost,
                })
            return sorted(
                deployments,
                key=lambda item: item["deployed_at"],
                reverse=True,
            )

    def _normalize_belief_override(
        self,
        belief_override: Optional[Dict[str, float]],
    ) -> Dict[int, float]:
        source = (
            belief_override
            if belief_override is not None
            else self.graph.belief_state
        )
        valid_states = set(self.graph.states)
        belief: Dict[int, float] = {}
        for raw_state, raw_probability in source.items():
            try:
                state = int(raw_state)
                probability = float(raw_probability)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    f"Invalid belief entry {raw_state!r}: {raw_probability!r}"
                ) from exc
            if state not in valid_states:
                raise ValueError(f"Belief references unknown state {state}")
            if state == self.graph.sink_state:
                continue
            if not math.isfinite(probability) or probability < 0:
                raise ValueError(
                    "Belief probabilities must be finite and non-negative"
                )
            if probability > 0:
                belief[state] = belief.get(state, 0.0) + probability
        total = sum(belief.values())
        if total <= 0:
            raise ValueError(
                "Belief must assign positive probability to a non-sink state"
            )
        return {
            state: probability / total
            for state, probability in belief.items()
        }

    def _append_decision(self, record: Dict) -> None:
        """Bound history without evicting records awaiting approval."""
        self.decision_history.append(record)
        while len(self.decision_history) > self.decision_history_limit:
            removable_index = next(
                (
                    index
                    for index, item in enumerate(self.decision_history)
                    if item.get("decision_id") not in self.pending_decisions
                ),
                None,
            )
            if removable_index is None:
                break
            self.decision_history.pop(removable_index)

    def run_decision(self, request) -> Dict:
        """Run a configured decision backend, safety-check, and optionally deploy."""
        api_config = self.config.get("api", {})
        backend = str(
            request.backend or api_config.get("decision_backend", "robust")
        ).lower()
        if backend not in {"robust", "rl"}:
            raise ValueError("backend must be 'robust' or 'rl'")

        belief = self._normalize_belief_override(request.belief_override)
        available_budget = max(
            0.0,
            self.safety_gate.budget_limit - self.safety_gate.budget_spent,
        )
        requested_budget = float(
            request.budget_remaining
            if request.budget_remaining is not None
            else available_budget
        )
        if not math.isfinite(requested_budget) or requested_budget < 0:
            raise ValueError(
                "budget_remaining must be finite and non-negative"
            )
        budget_remaining = min(requested_budget, available_budget)
        deploy_requested = (
            request.deploy
            if request.deploy is not None
            else bool(api_config.get("auto_deploy", True))
        )
        stage_context = (
            {"stage": request.attacker_stage, "confidence": 1.0}
            if request.attacker_stage
            else None
        )

        with self._lock:
            if backend == "rl":
                from mirage.layer4_decision.rl_agent import RLDecisionBridge

                if self._rl_bridge is None:
                    self._rl_bridge = RLDecisionBridge(self.graph, self.fabric)
                    model_path = resolve_project_path(
                        self.config.get("rl", {}).get(
                            "model_path",
                            "models/mirage_dqn.npz",
                        )
                    )
                    if not model_path.exists():
                        raise FileNotFoundError(
                            f"RL model not found: {model_path}. Train it with --mode train_rl."
                        )
                    self._rl_bridge.load_model(str(model_path))
                plan = self._rl_bridge.get_action_plan(
                    belief_state=belief,
                    budget_remaining=budget_remaining,
                )
            else:
                from mirage.layer4_decision.decision_engine import RobustDecisionEngine

                engine = RobustDecisionEngine(
                    self.graph,
                    self.fabric,
                    n_attacker_samples=int(api_config.get("decision_samples", 60)),
                    use_robust_milp=False,
                    verbose=False,
                )
                plan = engine.decide(
                    belief_state=belief,
                    stage_context=stage_context,
                    budget_remaining=budget_remaining,
                )

            timestamp = datetime.now().isoformat()
            decision_id = uuid.uuid4().hex[:12]
            if plan is None:
                record = {
                    "decision_id": decision_id,
                    "timestamp": timestamp,
                    "backend": backend,
                    "status": "noop",
                    "deployed": False,
                    "reasoning": "Decision backend recommends no action.",
                }
                self._append_decision(record)
                return record

            allowed, safety = self.safety_gate.check_action_plan(
                plan,
                self.graph,
                reserve_budget=False,
            )
            deployed = []
            status = "recommended"
            if not allowed:
                status = "blocked"
            elif safety.requires_human_approval:
                status = "pending_approval" if deploy_requested else "approval_required"
                if deploy_requested:
                    if len(self.pending_decisions) >= self.pending_decision_limit:
                        raise ValueError(
                            "Pending decision limit reached; resolve existing "
                            "approvals before creating another."
                        )
                    self.pending_decisions[decision_id] = plan
            elif deploy_requested:
                for action in plan.portfolio or [plan.action]:
                    deployment = self.fabric.deploy_action(action)
                    deployed.append(deployment.decoy_id)
                self.safety_gate.commit_action_plan(plan, self.graph)
                status = "deployed"

            record = {
                **plan.to_dict(),
                "decision_id": decision_id,
                "timestamp": timestamp,
                "backend": backend,
                "status": status,
                "deployed": bool(deployed),
                "deployment_ids": deployed,
                "safety": {
                    "allowed": allowed,
                    "risk_level": safety.risk_level.value,
                    "requires_human_approval": safety.requires_human_approval,
                    "warning": safety.warning_message,
                },
            }
            self._append_decision(record)
            return record

    def approve_decision(self, decision_id: str, approved_by: str) -> Dict:
        """Approve and deploy a pending action plan."""
        with self._lock:
            plan = self.pending_decisions.pop(decision_id, None)
            if plan is None:
                raise KeyError(decision_id)

            from mirage.layer2_graph_engine.mdp_solver import compute_portfolio_cost

            actions = plan.portfolio or [plan.action]
            request_cost = float(
                getattr(plan, "portfolio_cost", 0.0)
                or compute_portfolio_cost(actions, self.graph)["total"]
            )
            if (
                self.safety_gate.budget_spent + request_cost
                > self.safety_gate.budget_limit
            ):
                self.pending_decisions[decision_id] = plan
                raise ValueError("Approval cannot be deployed: safety budget is no longer available.")
            deployed_ids = {
                action.action_id for action in self.fabric.deployed_actions
            }
            if any(action.action_id in deployed_ids for action in actions):
                self.pending_decisions[decision_id] = plan
                raise ValueError("Approval cannot be deployed: an action is already active.")

            deployed = []
            for action in actions:
                deployment = self.fabric.deploy_action(action)
                deployed.append(deployment.decoy_id)
            self.safety_gate.approve_action(plan, approved_by=approved_by)
            self.safety_gate.commit_action_plan(plan, self.graph)

            record = next(
                (
                    item for item in reversed(self.decision_history)
                    if item.get("decision_id") == decision_id
                ),
                None,
            )
            if record is None:
                raise KeyError(decision_id)
            record.update({
                "status": "deployed",
                "deployed": True,
                "deployment_ids": deployed,
                "approved_by": approved_by,
                "approved_at": datetime.now().isoformat(),
            })
            return dict(record)

    def get_status(self) -> Dict:
        """System status summary."""
        with self._lock:
            uptime = time.time() - self.start_time
            return {
                "status": "running",
                "uptime_seconds": round(uptime, 1),
                "total_events_processed": self.total_events_processed,
                "tracked_hosts": len(
                    self.ensemble_classifier.hmm_clf.get_all_beliefs()
                ),
                "graph_nodes": len(self.graph.states),
                "active_decoys": len(self.fabric.active_decoys),
                "decisions_made": len(self.decision_history),
                "pending_approvals": len(self.pending_decisions),
                "ws_connections": len(self.ws_connections),
                "decision_backend": self.config.get("api", {}).get(
                    "decision_backend", "robust"
                ),
                "budget_spent": round(self.safety_gate.budget_spent, 3),
                "budget_limit": self.safety_gate.budget_limit,
                "timestamp": datetime.now().isoformat(),
            }

    async def broadcast_ws(self, message: Dict):
        """Broadcast a message to all connected WebSocket clients."""
        text = json.dumps(message)
        async with self._ws_broadcast_lock:
            connections = list(self.ws_connections)
            results = await asyncio.gather(
                *(ws.send_text(text) for ws in connections),
                return_exceptions=True,
            )
            dead = [
                ws
                for ws, result in zip(connections, results, strict=True)
                if isinstance(result, Exception)
            ]
            for ws in dead:
                if ws in self.ws_connections:
                    self.ws_connections.remove(ws)


# ============================================================
# FastAPI Application
# ============================================================

def create_app() -> Any:
    """Create and configure the FastAPI application."""
    if not HAS_FASTAPI:
        raise ImportError(
            "FastAPI is required for the API server. "
            "Install with: pip install fastapi uvicorn"
        )

    config = load_config()
    api_config = config.get("api", {})
    app = FastAPI(
        title="MIRAGE API",
        description=(
            "Multi-stage Intelligent Robust Adaptive Graph-based Engagement — "
            "Real-time log ingestion and deception orchestration API."
        ),
        version=__version__,
    )

    # CORS — allow dashboard frontend
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(api_config.get("cors_origins", [])),
        allow_credentials=False,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api_key_env = str(api_config.get("api_key_env", "MIRAGE_API_KEY"))
    configured_api_key = os.environ.get(api_key_env)
    max_request_bytes = int(api_config.get("max_request_bytes", 2097152))

    @app.middleware("http")
    async def api_key_guard(request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared_size = int(content_length)
            except ValueError:
                return JSONResponse(
                    status_code=400,
                    content={"detail": "Invalid Content-Length header."},
                )
            if declared_size > max_request_bytes:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": (
                            "Request body exceeds "
                            f"max_request_bytes={max_request_bytes}."
                        )
                    },
                )
        supplied_key = request.headers.get("X-API-Key", "")
        if (
            configured_api_key
            and request.url.path.startswith("/api/")
            and not secrets.compare_digest(supplied_key, configured_api_key)
        ):
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing or invalid X-API-Key."},
            )
        response = await call_next(request)
        if request.url.path == "/dashboard":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self'; "
                "style-src 'self' 'unsafe-inline'; "
                "connect-src 'self' ws: wss:; "
                "img-src 'self' data:; "
                "font-src 'self'; "
                "base-uri 'none'; frame-ancestors 'none'"
            )
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
        return response

    # Serve dashboard static files
    dashboard_dir = os.path.join(os.path.dirname(__file__), "dashboard")
    if os.path.isdir(dashboard_dir):
        @app.get("/dashboard")
        async def dashboard_index():
            """Serve the MIRAGE web dashboard."""
            return FileResponse(os.path.join(dashboard_dir, "index.html"))

        app.mount(
            "/dashboard-static",
            StaticFiles(directory=dashboard_dir),
            name="dashboard",
        )

    # Initialize MIRAGE state
    state = MIRAGEStateManager()
    app.state.mirage_state = state
    decision_lock = asyncio.Lock()

    # ---- REST Endpoints ----

    @app.get("/")
    async def root():
        return {
            "name": "MIRAGE API",
            "version": __version__,
            "docs": "/docs",
            "endpoints": [
                "POST /api/telemetry",
                "POST /api/telemetry/batch",
                "POST /api/ingest/{splunk|elastic|wazuh}",
                "GET  /api/belief",
                "GET  /api/belief/{host}",
                "GET  /api/status",
                "GET  /api/graph",
                "GET  /api/decoys",
                "GET  /api/decisions",
                "POST /api/decide",
                "POST /api/decisions/{id}/approve",
                "WS   /ws",
            ],
        }

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.post("/api/telemetry")
    async def ingest_telemetry(payload: TelemetryEventPayload):
        """
        Ingest a single telemetry event from SIEM.

        Accepts events from Splunk, ELK Stack, Wazuh, or any webhook-capable system.
        Returns the updated belief state for the source host.
        """
        result = state.process_event(payload)

        # Broadcast to WebSocket clients
        await state.broadcast_ws({
            "type": "telemetry_update",
            "data": result,
        })

        return result

    @app.post("/api/telemetry/batch")
    async def ingest_telemetry_batch(payload: TelemetryBatchPayload):
        """
        Ingest a batch of telemetry events.

        For high-throughput SIEM integration (Splunk HEC, Logstash output plugin).
        """
        max_batch_size = int(api_config.get("max_batch_size", 1000))
        if len(payload.events) > max_batch_size:
            raise HTTPException(
                status_code=413,
                detail=f"Batch exceeds max_batch_size={max_batch_size}.",
            )
        results = []
        for event_payload in payload.events:
            result = state.process_event(event_payload)
            results.append(result)

        # Broadcast summary to WebSocket
        await state.broadcast_ws({
            "type": "batch_update",
            "count": len(results),
            "hosts": list({r["host"] for r in results}),
            "results": results,
        })

        return {
            "processed": len(results),
            "results": results,
        }

    @app.post("/api/ingest/{source}")
    async def ingest_siem_payload(
        source: str,
        payload: Annotated[Any, Body()],
    ):
        """Ingest native-ish Splunk HEC, Elastic, or Wazuh payloads."""
        source = source.lower()
        if source not in {"splunk", "elastic", "wazuh"}:
            raise HTTPException(status_code=404, detail=f"Unsupported SIEM source '{source}'.")
        raw_events = payload if isinstance(payload, list) else [payload]
        max_batch_size = int(api_config.get("max_batch_size", 1000))
        if len(raw_events) > max_batch_size:
            raise HTTPException(
                status_code=413,
                detail=f"Batch exceeds max_batch_size={max_batch_size}.",
            )

        results = []
        for raw in raw_events:
            if not isinstance(raw, dict):
                raise HTTPException(status_code=422, detail="Each SIEM event must be an object.")
            try:
                normalized = normalize_siem_payload(raw, source)
                event_payload = TelemetryEventPayload.model_validate(normalized)
            except (TypeError, ValueError, ValidationError) as exc:
                raise HTTPException(
                    status_code=422,
                    detail=f"Invalid {source} event: {exc}",
                ) from exc
            results.append(state.process_event(event_payload))

        await state.broadcast_ws({
            "type": "batch_update",
            "count": len(results),
            "hosts": sorted({result["host"] for result in results}),
            "results": results,
        })
        return {"source": source, "processed": len(results), "results": results}

    @app.get("/api/belief")
    async def get_belief():
        """Get current belief states for all tracked hosts."""
        return state.get_belief_all()

    @app.get("/api/belief/{host}")
    async def get_belief_host(host: str):
        """Get current belief state for a specific host."""
        all_beliefs = state.get_belief_all()
        if host not in all_beliefs:
            raise HTTPException(status_code=404, detail=f"Host '{host}' not tracked.")
        return all_beliefs[host]

    @app.get("/api/status")
    async def get_status():
        """Get system status and health metrics."""
        return state.get_status()

    @app.get("/api/graph")
    async def get_graph():
        """Get full attack graph topology for visualization."""
        return state.get_graph_json()

    @app.get("/api/decoys")
    async def get_decoys():
        """Get list of currently active deception actions."""
        active = state.get_active_decoys()
        return {
            "active_decoys": active,
            "total": len(active),
        }

    @app.get("/api/decisions")
    async def get_decisions():
        """Get recent decision history."""
        with state._lock:
            return {
                "decisions": [
                    dict(item) for item in state.decision_history[-50:]
                ],
                "total": len(state.decision_history),
            }

    @app.post("/api/decide")
    async def trigger_decision(request: DecisionRequest):
        """
        Manually trigger the decision engine.

        Returns an ActionPlan recommendation.
        """
        try:
            async with decision_lock:
                decision_record = await asyncio.to_thread(
                    state.run_decision,
                    request,
                )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        await state.broadcast_ws({
            "type": "decision",
            "data": decision_record,
        })

        if decision_record.get("deployed"):
            await state.broadcast_ws({
                "type": "defenses_update",
                "data": state.get_active_decoys(),
                "graph": state.get_graph_json(),
            })

        return decision_record

    @app.post("/api/decisions/{decision_id}/approve")
    async def approve_decision(decision_id: str, request: ApprovalRequest):
        """Approve and deploy a plan currently waiting for a SOC analyst."""
        try:
            record = await asyncio.to_thread(
                state.approve_decision,
                decision_id,
                request.approved_by,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Pending decision '{decision_id}' was not found.",
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

        await state.broadcast_ws({"type": "decision", "data": record})
        await state.broadcast_ws({
            "type": "defenses_update",
            "data": state.get_active_decoys(),
            "graph": state.get_graph_json(),
        })
        return record

    # ---- WebSocket ----

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        """
        WebSocket endpoint for real-time streaming updates.

        Clients receive automatic notifications when:
          - New telemetry events are processed
          - Belief states change significantly
          - Decisions are made by the engine
        """
        offered_protocols = [
            value.strip()
            for value in websocket.headers.get(
                "sec-websocket-protocol",
                "",
            ).split(",")
            if value.strip()
        ]
        protocol_key = None
        for protocol in offered_protocols:
            if not protocol.startswith("mirage-key."):
                continue
            encoded = protocol.removeprefix("mirage-key.")
            try:
                padding = "=" * (-len(encoded) % 4)
                protocol_key = base64.urlsafe_b64decode(
                    encoded + padding
                ).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                protocol_key = None
            break
        supplied_key = (
            protocol_key
            or websocket.query_params.get("api_key")
            or ""
        )
        accepted_protocol = (
            "mirage" if "mirage" in offered_protocols else None
        )
        await websocket.accept(subprotocol=accepted_protocol)
        if (
            configured_api_key
            and not secrets.compare_digest(supplied_key, configured_api_key)
        ):
            await websocket.close(code=4401, reason="Invalid API key")
            return

        state.ws_connections.append(websocket)
        print(f"[WS] Client connected. Total: {len(state.ws_connections)}")

        try:
            # Send initial state
            await websocket.send_json({
                "type": "init",
                "status": state.get_status(),
                "graph": state.get_graph_json(),
            })

            # Keep connection alive and handle incoming messages
            while True:
                data = await websocket.receive_text()
                try:
                    msg = json.loads(data)
                except json.JSONDecodeError:
                    await websocket.send_json({
                        "type": "error",
                        "detail": "WebSocket messages must be valid JSON.",
                    })
                    continue

                if msg.get("type") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif msg.get("type") == "get_belief":
                    await websocket.send_json({
                        "type": "belief",
                        "data": state.get_belief_all(),
                    })
                elif msg.get("type") == "get_status":
                    await websocket.send_json({
                        "type": "status",
                        "data": state.get_status(),
                    })

        except WebSocketDisconnect:
            pass
        except Exception:
            LOGGER.exception("Unexpected MIRAGE WebSocket client error")
        finally:
            if websocket in state.ws_connections:
                state.ws_connections.remove(websocket)
            print(f"[WS] Client disconnected. Total: {len(state.ws_connections)}")

    return app


# ============================================================
# CLI entrypoint
# ============================================================

def main():
    api_config = load_config().get("api", {})
    parser = argparse.ArgumentParser(description="MIRAGE API Server")
    parser.add_argument(
        "--host",
        default=api_config.get("host", "0.0.0.0"),
        help="Bind host",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(api_config.get("port", 8000)),
        help="Bind port",
    )
    parser.add_argument("--reload", action="store_true", help="Enable hot-reload (dev mode)")
    args = parser.parse_args()

    if not HAS_FASTAPI:
        print("ERROR: FastAPI is required. Install with:")
        print("  pip install fastapi uvicorn")
        sys.exit(1)

    import uvicorn
    print(f"\n[MIRAGE API] Starting server at http://{args.host}:{args.port}")
    print(f"  Swagger UI: http://localhost:{args.port}/docs")
    print(f"  Dashboard:  http://localhost:{args.port}/dashboard")
    print(f"  WebSocket:  ws://localhost:{args.port}/ws\n")

    uvicorn.run(
        "mirage.api_server:create_app",
        factory=True,
        host=args.host,
        port=args.port,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
