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
        Query,
        Request,
        WebSocket,
        WebSocketDisconnect,
    )
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse, FileResponse, PlainTextResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, ConfigDict, Field, ValidationError
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from mirage.layer1_contextual_ai.attack_modeling import TelemetryEvent, STAGE_NAMES
from mirage.layer1_contextual_ai.hmm_classifier import EnsembleTelemetryClassifier
from mirage.layer2_graph_engine.attack_graph import MIRAGEAttackGraph, build_configured_attack_graph
from mirage.layer3_deception.deception_fabric import DeceptionFabric
from mirage.layer5_safe_control.safe_control import create_safety_gate
from mirage.config import load_config, resolve_project_path
from mirage.production.health import DependencyChecker, build_health_report
from mirage.production.observability import MetricsRegistry
from mirage.analysis.pipeline import AttackAnalysisPipeline
from mirage.detection.pipeline import ContextualDetectionPipeline
from mirage.domain.schemas import (
    ActionMask,
    AnalystDecision,
    AnalystFeedback,
    ApprovalDecision,
    ConnectorConfig,
    CandidateDefenseAction,
    DiscoveryObservation,
    SafetyVerdict,
    AttackAnalysisResult,
    SecurityEvent,
)
from mirage.casm.service import CASMService
from mirage.connectors.fixture import build_connector
from mirage.execution.audit import ImmutableAuditStore
from mirage.execution.kill_switch import KillSwitch
from mirage.execution.orchestrator import DeceptionOrchestrator
from mirage.execution.safety import SafetyGate as ExecutionSafetyGate
from mirage.execution.utils import deterministic_id, ensure_utc
from mirage.realtime.twin_service import RealtimeTwinService
from mirage.shadow.controller import ShadowModeController
from mirage.streaming.coordinator import ConnectorManager
from mirage.streaming.state import JSONStateStore
from mirage.ingestion.normalizer import EventNormalizer
from mirage.layer6_twin.digital_twin import DigitalTwin
from mirage import __version__

LOGGER = logging.getLogger(__name__)


def stable_shadow_feedback_id(
    recommendation_id: str,
    analyst_identifier: str,
    decision: str,
) -> str:
    """Create deterministic feedback IDs for API submissions."""
    return deterministic_id(
        "feedback",
        recommendation_id,
        analyst_identifier,
        decision,
    )


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

    class TwinReplayRequest(BaseModel):
        """Replay request for Digital Twin V1."""
        events_path: Optional[str] = None
        events: Optional[List[Dict[str, Any]]] = None
        preserve_file_order: bool = False
        strict: bool = False

    class BeliefRecomputeRequest(BaseModel):
        """Request to recompute one contextual entity belief."""
        entity_id: str = Field(min_length=1)
        reference_time: Optional[datetime] = None

    class AnalysisRunRequest(BaseModel):
        """Request for Milestone 3 attack-path analysis."""
        seed_entity_ids: List[str] = Field(default_factory=list)
        max_hops: Optional[int] = Field(default=None, ge=0, le=10)
        max_nodes: Optional[int] = Field(default=None, ge=1)
        max_paths: Optional[int] = Field(default=None, ge=1)
        reference_time: Optional[datetime] = None

    class SafetyEvaluateRequest(BaseModel):
        """Evaluate one candidate defense action through Safety Gate V1."""
        action: CandidateDefenseAction
        mask: Optional[ActionMask] = None
        analysis_id: Optional[str] = None
        reference_time: Optional[datetime] = None

    class ExecutionPrepareRequest(BaseModel):
        """Prepare a lab execution plan from one candidate action."""
        action: CandidateDefenseAction
        mask: Optional[ActionMask] = None
        analysis_id: Optional[str] = None
        reference_time: Optional[datetime] = None

    class ExecutionExecuteRequest(BaseModel):
        """Execute a stored plan."""
        actor: str = Field(default="api", min_length=1, max_length=100)

    class ExecutionApprovalRequest(BaseModel):
        """Approve or reject an approval-required execution."""
        approver: str = Field(min_length=1, max_length=100)
        decision: ApprovalDecision = ApprovalDecision.APPROVED
        reason: str = Field(default="", max_length=500)
        ttl_seconds: Optional[int] = Field(default=None, ge=1)

    class KillSwitchRequest(BaseModel):
        """Enable or disable kill switch scope."""
        actor: str = Field(default="api", min_length=1, max_length=100)
        reason: str = Field(default="", max_length=500)
        action_type: Optional[str] = Field(default=None, max_length=100)
        environment: Optional[str] = Field(default=None, max_length=100)

    class ConnectorRegisterRequest(BaseModel):
        """Register or replace a read-only connector config."""
        connector: ConnectorConfig

    class CASMReconcileRequest(BaseModel):
        """Apply one CASM discovery observation."""
        observation: DiscoveryObservation

    class ShadowRunRequest(BaseModel):
        """Run shadow recommendations for an existing analysis."""
        analysis_id: str = Field(min_length=1)

    class ShadowFeedbackRequest(BaseModel):
        """Record analyst feedback for a shadow recommendation."""
        analyst_decision: AnalystDecision
        analyst_identifier: str = Field(min_length=1, max_length=100)
        usefulness_score: Optional[float] = Field(default=None, ge=0, le=1)
        correctness_score: Optional[float] = Field(default=None, ge=0, le=1)
        safety_score: Optional[float] = Field(default=None, ge=0, le=1)
        rejection_reason: str = Field(default="", max_length=500)
        corrected_action_type: Optional[str] = Field(default=None, max_length=100)
        comments: str = Field(default="", max_length=1000)

    class GNNEncodeRequest(BaseModel):
        """Read-only GNN encode request.

        Provide either a serialized GraphSample or an existing analysis_id.
        If no model is loaded, the response uses heuristic fallback values.
        """
        model_config = ConfigDict(protected_namespaces=())
        graph_sample: Optional[Dict[str, Any]] = None
        analysis_id: Optional[str] = Field(default=None, min_length=1)
        model_path: Optional[str] = Field(default=None, max_length=500)

    class GNNEvaluateRequest(BaseModel):
        """Evaluate baselines and, optionally, a GNN model on a dataset."""
        model_config = ConfigDict(protected_namespaces=())
        dataset_path: str = Field(min_length=1, max_length=500)
        model_path: Optional[str] = Field(default=None, max_length=500)

    class RLDatasetBuildRequest(BaseModel):
        """Build a deterministic offline-RL dataset."""
        sources: str = Field(default="simulator,robust,shadow,lab", max_length=200)
        output_path: Optional[str] = Field(default=None, max_length=500)

    class RLTrainRequest(BaseModel):
        """Train a BC or offline-RL policy. Disabled by default."""
        dataset_path: str = Field(min_length=1, max_length=500)
        output_path: str = Field(min_length=1, max_length=500)
        algorithm: str = Field(default="offline_rl", max_length=50)
        init_policy_path: Optional[str] = Field(default=None, max_length=500)
        config: Dict[str, Any] = Field(default_factory=dict)

    class RLEvaluateRequest(BaseModel):
        """Evaluate offline-RL policies on a dataset."""
        dataset_path: str = Field(min_length=1, max_length=500)
        policy_path: Optional[str] = Field(default=None, max_length=500)

    class RLRecommendRequest(BaseModel):
        """Run read-only RL shadow recommendation for an encoded state or analysis."""
        encoded_state: Optional[Dict[str, Any]] = None
        analysis_id: Optional[str] = Field(default=None, min_length=1)
        policy_path: Optional[str] = Field(default=None, max_length=500)

    class MARLTrainRequest(BaseModel):
        """Run synthetic MARL self-play training. Disabled by default."""
        algorithm: str = Field(default="self_play", max_length=50)
        episodes: int = Field(default=4, ge=1, le=200)
        scenario_count: int = Field(default=6, ge=1, le=200)
        output_path: Optional[str] = Field(default=None, max_length=500)

    class MARLEvaluateRequest(BaseModel):
        """Evaluate MARL policies in the synthetic range."""
        scenario_count: int = Field(default=6, ge=1, le=200)

    class MARLReplayRequest(BaseModel):
        """Replay red/blue actions in one synthetic scenario."""
        scenario_id: str = Field(default="marl_scenario_00", min_length=1)
        steps: List[Dict[str, str]] = Field(default_factory=list)

    class GovernanceReleaseCheckRequest(BaseModel):
        """Release-gate evidence for one governed artifact."""
        target_status: str = Field(default="PILOT_CANDIDATE", max_length=50)
        evidence: Dict[str, Any] = Field(default_factory=dict)

    class GovernanceApprovalRequest(BaseModel):
        """Governance approval/suspension actor context."""
        actor: str = Field(default="api", min_length=1, max_length=100)
        role: str = Field(default="governance_reviewer", max_length=100)
        reason: str = Field(default="", max_length=500)

    class VerificationPlanRequest(BaseModel):
        """Verify a proposed execution plan."""
        plan: Dict[str, Any]
        action: Dict[str, Any]
        mask: Dict[str, Any]
        safety_decision: Optional[Dict[str, Any]] = None
        twin_snapshot: Dict[str, Any]
        belief_snapshot: Optional[Dict[str, Any]] = None
        pilot_scope: Dict[str, Any] = Field(default_factory=dict)
        approvals: List[Dict[str, Any]] = Field(default_factory=list)
        dependency_graph: Dict[str, List[str]] = Field(default_factory=dict)

    class VerificationInvariantValidateRequest(BaseModel):
        """Validate a custom invariant payload."""
        invariant: Dict[str, Any]

    class PilotPrepareRequest(BaseModel):
        """Prepare a controlled-pilot recommendation."""
        recommendation: Dict[str, Any]
        scope_id: str = Field(default="lab-low-risk", min_length=1)

    class PilotApprovalRequest(BaseModel):
        """Record exact-plan pilot approval."""
        plan: Dict[str, Any]
        approver: str = Field(min_length=1, max_length=100)
        approver_role: str = Field(min_length=1, max_length=100)
        environment: str = Field(default="lab", max_length=100)
        ttl_seconds: int = Field(default=900, ge=1)

    class PilotCanaryRequest(BaseModel):
        """Evaluate canary evidence."""
        checks: Dict[str, Optional[bool]] = Field(default_factory=dict)

    class PilotMonitorRequest(BaseModel):
        """Evaluate runtime monitoring evidence."""
        metrics: Dict[str, float] = Field(default_factory=dict)
        protected_asset_affected: bool = False
        management_channel_lost: bool = False
        rollback_channel_at_risk: bool = False
        scope_expanded: bool = False
        kill_switch_active: bool = False
        policy_suspended: bool = False

    class PilotRollbackRequest(BaseModel):
        """Request pilot rollback."""
        reason: str = Field(min_length=1, max_length=500)


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

        twin_config = self.config.get("twin", {})
        self.twin = DigitalTwin(
            relationship_ttls=twin_config.get("relationship_ttls", {}),
            allow_provisional_entities=bool(
                twin_config.get("allow_provisional_entities", True)
            ),
        )
        self.event_normalizer = EventNormalizer()
        self.detection_pipeline = self._build_detection_pipeline(self.twin)
        self.analysis_pipeline = AttackAnalysisPipeline(
            attack_graph=self.graph,
            config=self.config.get("analysis", {}),
        )
        self.analysis_history: Dict[str, AttackAnalysisResult] = {}
        execution_config = self.config.get("execution", {})
        self.execution_audit_store = ImmutableAuditStore(
            resolve_project_path(
                execution_config.get(
                    "audit_path",
                    "artifacts/execution_audit.jsonl",
                )
            )
        )
        self.execution_kill_switch = KillSwitch(
            default_enabled=bool(
                execution_config.get("kill_switch", {}).get(
                    "default_enabled",
                    False,
                )
            ),
            audit_store=self.execution_audit_store,
        )
        self.execution_safety_gate = ExecutionSafetyGate(
            execution_config,
            audit_store=self.execution_audit_store,
            kill_switch=self.execution_kill_switch,
        )
        self.execution_orchestrator = DeceptionOrchestrator(
            config=execution_config,
            audit_store=self.execution_audit_store,
            kill_switch=self.execution_kill_switch,
            twin=self.twin,
        )
        self.casm_service = CASMService(
            self.twin,
            config=self.config.get("casm", {}),
        )
        self.realtime_twin_service = RealtimeTwinService(
            twin=self.twin,
            detection_pipeline=self.detection_pipeline,
            casm_service=self.casm_service,
        )
        connector_config = self.config.get("connectors", {})
        self.connector_state_store = JSONStateStore(
            resolve_project_path(
                connector_config.get(
                    "checkpoint_state_path",
                    "artifacts/connectors_state.json",
                )
            )
        )
        self.connector_manager = ConnectorManager(
            event_sink=self.realtime_twin_service.process_event,
            allowed_lateness_seconds=int(
                connector_config.get("allowed_lateness_seconds", 300)
            ),
            state_store=self.connector_state_store,
        )
        self.connectors: Dict[str, Any] = {}
        for raw_connector in connector_config.get("definitions", []):
            connector = build_connector(ConnectorConfig.model_validate(raw_connector))
            self.connector_manager.register(connector)
            self.connectors[connector.config.connector_id] = connector
        self.shadow_controller = ShadowModeController(
            self.config.get("shadow", {})
        )
        self.gnn_startup_warnings: List[str] = []
        self.gnn_predictions: Dict[str, Any] = {}
        self._init_gnn_state()
        self.rl_startup_warnings: List[str] = []
        self.rl_predictions: Dict[str, Any] = {}
        self.rl_comparisons: Dict[str, Any] = {}
        self._init_rl_state()
        self.marl_startup_warnings: List[str] = []
        self.marl_jobs: Dict[str, Any] = {}
        self.marl_replays: Dict[str, Any] = {}
        self._init_marl_state()
        self._init_m9_state()

        # Metrics
        self.total_events_processed = 0
        self.start_time = time.time()

        # WebSocket connections
        self.ws_connections: List[WebSocket] = []
        self._ws_broadcast_lock = asyncio.Lock()

        print("[MIRAGE API] Engine ready.")

    def _init_gnn_state(self) -> None:
        """Initialize optional Milestone 6 GNN services without training."""
        from mirage.gnn.inference import GNNInferenceService
        from mirage.gnn.registry import ModelRegistry
        from mirage.gnn.schema import GraphFeatureSchema

        gnn_config = self.config.get("gnn", {})
        self.gnn_schema = GraphFeatureSchema()
        self.gnn_registry = ModelRegistry(
            registry_path=str(
                resolve_project_path(
                    gnn_config.get("registry_path", "models/gnn_registry.json")
                )
            )
        )
        self.gnn_inference_service = GNNInferenceService(
            schema=self.gnn_schema,
            max_nodes=int(gnn_config.get("max_nodes", 200)),
            max_edges=int(gnn_config.get("max_edges", 400)),
        )
        model_path = gnn_config.get("model_path")
        if model_path:
            try:
                self.gnn_inference_service.load_model(
                    str(resolve_project_path(model_path))
                )
            except (ImportError, RuntimeError, OSError, ValueError) as exc:
                self.gnn_startup_warnings.append(f"gnn_model_not_loaded: {exc}")

    def _init_rl_state(self) -> None:
        """Initialize optional Milestone 7 offline-RL services without training."""
        from mirage.rl.features import RLStateEncoder
        from mirage.rl.inference import OfflineRLInferenceService
        from mirage.rl.registry import PolicyRegistry

        rl_config = self.config.get("offline_rl", {})
        self.rl_state_encoder = RLStateEncoder(
            operating_mode=str(rl_config.get("rl_operating_mode", "rl_shadow"))
        )
        self.rl_policy_registry = PolicyRegistry(
            registry_path=str(
                resolve_project_path(
                    rl_config.get("registry_path", "models/rl_policy_registry.json")
                )
            )
        )
        self.rl_inference_service = OfflineRLInferenceService(
            operating_mode=str(rl_config.get("rl_operating_mode", "rl_shadow")),
            max_candidate_actions=int(rl_config.get("max_candidate_actions", 100)),
            uncertainty_threshold=float(rl_config.get("uncertainty_threshold", 0.65)),
        )
        model_path = rl_config.get("model_path")
        if model_path:
            try:
                self.rl_inference_service.load_policy(
                    str(resolve_project_path(model_path))
                )
            except (OSError, ValueError, RuntimeError) as exc:
                self.rl_startup_warnings.append(f"rl_policy_not_loaded: {exc}")

    def _init_marl_state(self) -> None:
        """Initialize Milestone 8 cyber-range services."""
        from mirage.marl.registry import MARLPolicyRegistry
        from mirage.marl.schema import RangeIsolationConfig
        from mirage.marl.scenarios import load_scenarios

        marl_config = self.config.get("marl", {})
        self.marl_isolation = RangeIsolationConfig.model_validate(marl_config)
        self.marl_isolation.assert_safe()
        self.marl_scenarios = load_scenarios(
            int(marl_config.get("max_scenarios_per_job", 20))
        )
        self.marl_policy_registry = MARLPolicyRegistry(
            registry_path=str(
                resolve_project_path(
                    marl_config.get(
                        "registry_path",
                        "models/marl_policy_registry.json",
                    )
                )
            )
        )

    def _init_m9_state(self) -> None:
        """Initialize Milestone 9 governance, verification, pilot, and drift."""
        from mirage.drift.monitor import DriftMonitor
        from mirage.governance.audit import GovernanceAuditStore
        from mirage.governance.registry import GovernanceRegistry
        from mirage.pilot.controller import ControlledPilotController
        from mirage.pilot.scope import PilotScopeRegistry
        from mirage.verification.invariants import SafetySpecificationRegistry
        from mirage.verification.verifier import FormalSafetyVerifier

        governance_config = self.config.get("governance", {})
        pilot_config = self.config.get("pilot", {})
        verification_config = self.config.get("verification", {})
        self.governance_registry = GovernanceRegistry(
            str(resolve_project_path(governance_config.get("registry_path", "models/governance_registry.json")))
        )
        self.governance_audit = GovernanceAuditStore(
            str(resolve_project_path(governance_config.get("audit_path", "artifacts/governance_audit.jsonl")))
        )
        self.invariant_registry = SafetySpecificationRegistry()
        self.formal_verifier = FormalSafetyVerifier(
            registry=self.invariant_registry,
            config=verification_config,
        )
        self.pilot_scope_registry = PilotScopeRegistry()
        self.pilot_controller = ControlledPilotController(
            config={
                **pilot_config,
                "verification": verification_config,
                "policy": pilot_config,
                "governance_audit_path": str(resolve_project_path(governance_config.get("audit_path", "artifacts/governance_audit.jsonl"))),
            },
            verifier=self.formal_verifier,
            audit_store=self.governance_audit,
        )
        drift_config = self.config.get("drift", {})
        self.drift_monitor = DriftMonitor(
            {
                "warning": float(drift_config.get("warning_threshold", 0.35)),
                "critical": float(drift_config.get("critical_threshold", 0.70)),
            }
        )
        self.verification_reports: Dict[str, Any] = {}
        self.drift_reports: Dict[str, Any] = {}

    def _build_detection_pipeline(
        self,
        twin: DigitalTwin,
    ) -> ContextualDetectionPipeline:
        """Create a contextual detection pipeline bound to the API twin."""
        return ContextualDetectionPipeline(
            twin=twin,
            attack_graph=self.graph,
            config=self.config.get("detection", {}),
        )

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

    def apply_canonical_event(self, event: SecurityEvent) -> Dict:
        """Apply one canonical event to the Digital Twin."""
        with self._lock:
            result = self.twin.apply_event(event)
            return result.model_dump(mode="json")

    def get_twin_status(self) -> Dict:
        """Return Digital Twin health metadata."""
        with self._lock:
            status = self.twin.health()
            status["coverage_score"] = self.twin.coverage_score()
            status["freshness_score"] = self.twin.freshness_score()
            status["warnings"] = list(self.twin.warnings[-20:])
            return status

    def get_twin_snapshot(self) -> Dict:
        """Return a JSON-serializable Digital Twin snapshot."""
        with self._lock:
            return self.twin.create_snapshot().model_dump(mode="json")

    def process_detection_event(self, raw_event: Any) -> Dict:
        """Normalize and process one event through Contextual Detection V1."""
        event = (
            raw_event
            if isinstance(raw_event, SecurityEvent)
            else self.event_normalizer.normalize(raw_event)
        )
        with self._lock:
            result = self.detection_pipeline.process_event(event)
            return result.model_dump(mode="json")

    def get_detection_entity(self, entity_id: str) -> Dict:
        """Return contextual belief for one entity."""
        with self._lock:
            belief = self.detection_pipeline.belief_engine.get_entity_belief(entity_id)
        if belief is None:
            raise KeyError(entity_id)
        return belief.model_dump(mode="json")

    def get_detection_timeline(self, entity_id: str, limit: int) -> List[Dict]:
        """Return a bounded sanitized timeline for one entity."""
        with self._lock:
            events = self.detection_pipeline.get_entity_timeline(
                entity_id,
                limit=limit,
            )
        return [event.model_dump(mode="json") for event in events]

    def get_detection_evidence(self, entity_id: str) -> List[Dict]:
        """Return evidence touching one entity."""
        with self._lock:
            evidence = self.detection_pipeline.get_entity_evidence(entity_id)
        return [item.model_dump(mode="json") for item in evidence]

    def get_suspicious_entities(self, limit: int) -> List[Dict]:
        """Return top suspected entities."""
        with self._lock:
            beliefs = self.detection_pipeline.belief_engine.get_top_suspected_entities(
                limit=limit,
            )
        return [belief.model_dump(mode="json") for belief in beliefs]

    def get_incidents(self, limit: int = 10) -> List[Dict]:
        """Return current incident beliefs."""
        with self._lock:
            incidents = self.detection_pipeline.list_incidents(limit=limit)
        return [incident.model_dump(mode="json") for incident in incidents]

    def get_incident(self, incident_id: str) -> Dict:
        """Return one incident belief by ID."""
        for incident in self.get_incidents(limit=50):
            if incident["incident_id"] == incident_id:
                return incident
        raise KeyError(incident_id)

    def get_belief_snapshot(self) -> Dict:
        """Return contextual belief snapshot."""
        with self._lock:
            return self.detection_pipeline.belief_engine.create_snapshot().model_dump(
                mode="json"
            )

    def recompute_belief(self, entity_id: str, reference_time: datetime | None) -> Dict:
        """Recompute one entity belief from retained evidence."""
        with self._lock:
            if reference_time is None:
                reference_time = (
                    self.detection_pipeline.belief_engine.last_updated
                    or self.twin.last_event_time
                    or datetime.now().astimezone()
                )
            belief = self.detection_pipeline.recompute_entity(
                entity_id,
                reference_time,
            )
        return belief.model_dump(mode="json")

    def run_attack_analysis(self, request) -> Dict:
        """Run Milestone 3 attack-path analysis from current snapshots."""
        with self._lock:
            result = self.analysis_pipeline.analyze(
                self.twin.create_snapshot(),
                self.detection_pipeline.belief_engine.create_snapshot(),
                reference_time=request.reference_time,
                seed_entity_ids=request.seed_entity_ids,
                max_hops=request.max_hops,
                max_nodes=request.max_nodes,
                max_paths=request.max_paths,
            )
            self.analysis_history[result.analysis_id] = result
            return result.model_dump(mode="json")

    def get_attack_analysis(self, analysis_id: str) -> AttackAnalysisResult:
        """Return one stored attack analysis."""
        with self._lock:
            if analysis_id not in self.analysis_history:
                raise KeyError(analysis_id)
            return self.analysis_history[analysis_id]

    def _default_execution_mask(
        self,
        action: CandidateDefenseAction,
    ) -> ActionMask:
        return ActionMask(
            action_id=action.action_id,
            allowed=True,
            approval_required=action.requires_approval,
            effective_risk_tier=action.risk_tier,
            mask_reasons=(
                ["approval_required"] if action.requires_approval else []
            ),
            required_conditions=(
                ["human approval"] if action.requires_approval else []
            ),
        )

    def _mask_from_analysis(
        self,
        action: CandidateDefenseAction,
        mask: ActionMask | None,
        analysis_id: str | None,
    ) -> ActionMask:
        if mask is not None:
            return mask
        if analysis_id and analysis_id in self.analysis_history:
            result = self.analysis_history[analysis_id]
            found = result.candidate_action_set.masks.get(action.action_id)
            if found:
                return found
        return self._default_execution_mask(action)

    def evaluate_execution_safety(self, request) -> Dict:
        """Evaluate a candidate action through Safety Gate V1."""
        with self._lock:
            mask = self._mask_from_analysis(
                request.action,
                request.mask,
                request.analysis_id,
            )
            decision = self.execution_safety_gate.evaluate(
                request.action,
                mask,
                self.twin.create_snapshot(),
                self.detection_pipeline.belief_engine.create_snapshot(),
                list(self.execution_orchestrator.records.values()),
                request.reference_time
                or self.detection_pipeline.belief_engine.last_updated
                or datetime.now().astimezone(),
            )
            return decision.model_dump(mode="json")

    def prepare_execution(self, request) -> Dict:
        """Safety-check and build a stored lab execution plan."""
        with self._lock:
            mask = self._mask_from_analysis(
                request.action,
                request.mask,
                request.analysis_id,
            )
            twin_snapshot = self.twin.create_snapshot()
            belief_snapshot = self.detection_pipeline.belief_engine.create_snapshot()
            decision = self.execution_safety_gate.evaluate(
                request.action,
                mask,
                twin_snapshot,
                belief_snapshot,
                list(self.execution_orchestrator.records.values()),
                request.reference_time
                or self.detection_pipeline.belief_engine.last_updated
                or datetime.now().astimezone(),
            )
            if decision.verdict == SafetyVerdict.DENY:
                return {
                    "status": "denied",
                    "safety_decision": decision.model_dump(mode="json"),
                }
            plan = self.execution_orchestrator.build_plan(
                request.action,
                decision,
                twin_snapshot=twin_snapshot,
                belief_snapshot=belief_snapshot,
                graph_version=str(getattr(self.graph, "name", "mirage_attack_graph")),
                analysis_id=request.analysis_id,
            )
            existing = self.execution_orchestrator._record_for_plan(plan.plan_id)
            record = existing or self.execution_orchestrator.state_machine.create_record(
                plan,
                actor="api",
            )
            self.execution_orchestrator.records[record.execution_id] = record
            return {
                "status": "prepared",
                "safety_decision": decision.model_dump(mode="json"),
                "plan": plan.model_dump(mode="json"),
                "execution": record.model_dump(mode="json"),
            }

    def execute_execution(self, execution_id: str, request) -> Dict:
        """Execute a prepared plan by execution ID."""
        with self._lock:
            if execution_id not in self.execution_orchestrator.records:
                raise KeyError(execution_id)
            record = self.execution_orchestrator.records[execution_id]
            plan = self.execution_orchestrator.plans[record.plan_id]
            updated = self.execution_orchestrator.execute(
                plan,
                actor=request.actor,
            )
            return updated.model_dump(mode="json")

    def approve_execution(self, execution_id: str, request) -> Dict:
        """Approve or reject one execution."""
        with self._lock:
            if execution_id not in self.execution_orchestrator.records:
                raise KeyError(execution_id)
            approval = self.execution_orchestrator.approve(
                execution_id,
                approver=request.approver,
                decision=request.decision,
                reason=request.reason,
                ttl_seconds=request.ttl_seconds,
            )
            return approval.model_dump(mode="json")

    def rollback_execution(self, execution_id: str) -> Dict:
        """Rollback one execution."""
        with self._lock:
            if execution_id not in self.execution_orchestrator.records:
                raise KeyError(execution_id)
            record = self.execution_orchestrator.rollback(
                execution_id,
                reason="API rollback",
            )
            return record.model_dump(mode="json")

    def get_execution(self, execution_id: str) -> Dict:
        """Return one execution."""
        with self._lock:
            if execution_id not in self.execution_orchestrator.records:
                raise KeyError(execution_id)
            return self.execution_orchestrator.records[execution_id].model_dump(
                mode="json"
            )

    def list_executions(self) -> List[Dict]:
        """Return all execution records."""
        with self._lock:
            return [
                record.model_dump(mode="json")
                for record in sorted(
                    self.execution_orchestrator.records.values(),
                    key=lambda item: item.created_at,
                    reverse=True,
                )
            ]

    def get_execution_audit(self) -> List[Dict]:
        """Return sanitized execution audit events."""
        with self._lock:
            return self.execution_audit_store.list_events()

    def register_connector(self, config: ConnectorConfig) -> Dict:
        """Register a read-only connector."""
        with self._lock:
            connector = build_connector(config)
            self.connector_manager.register(connector)
            self.connectors[config.connector_id] = connector
            return connector.health().model_dump(mode="json")

    def connector_health(self, connector_id: str | None = None) -> Dict | List[Dict]:
        """Return connector health."""
        with self._lock:
            if connector_id is None:
                return [
                    health.model_dump(mode="json")
                    for health in self.connector_manager.health_summary()
                ]
            connector = self.connectors.get(connector_id)
            if connector is None:
                raise KeyError(connector_id)
            return connector.health().model_dump(mode="json")

    def connector_validate(self, connector_id: str) -> Dict:
        """Validate one connector."""
        with self._lock:
            connector = self.connectors.get(connector_id)
            if connector is None:
                raise KeyError(connector_id)
            connector.validate_config()
            return {"connector_id": connector_id, "valid": True}

    def connector_start(self, connector_id: str) -> Dict:
        """Start one connector."""
        with self._lock:
            connector = self.connectors.get(connector_id)
            if connector is None:
                raise KeyError(connector_id)
            connector.start()
            return connector.health().model_dump(mode="json")

    def connector_stop(self, connector_id: str) -> Dict:
        """Stop one connector."""
        with self._lock:
            connector = self.connectors.get(connector_id)
            if connector is None:
                raise KeyError(connector_id)
            connector.stop()
            return connector.health().model_dump(mode="json")

    def connector_poll(self) -> Dict:
        """Poll all connectors once."""
        with self._lock:
            summary = self.connector_manager.poll_once(
                datetime.now().astimezone()
            )
            return summary.model_dump(mode="json")

    def casm_status(self) -> Dict:
        """Return CASM/Twin status."""
        with self._lock:
            return {
                "twin": self.twin.health(),
                "quality": self.casm_service.quality_report().model_dump(mode="json"),
            }

    def casm_reconcile(self, observation: DiscoveryObservation) -> Dict:
        """Apply one CASM observation."""
        with self._lock:
            return self.casm_service.apply_observation(observation).model_dump(
                mode="json"
            )

    def run_shadow(self, analysis_id: str) -> Dict:
        """Run shadow recommendations for an existing analysis."""
        with self._lock:
            analysis = self.get_attack_analysis(analysis_id)
            twin_snapshot = self.twin.create_snapshot()
            belief_snapshot = self.detection_pipeline.belief_engine.create_snapshot()
            decisions = []
            for action in analysis.candidate_action_set.actions:
                mask = analysis.candidate_action_set.masks[action.action_id]
                decisions.append(
                    self.execution_safety_gate.evaluate(
                        action,
                        mask,
                        twin_snapshot,
                        belief_snapshot,
                        list(self.execution_orchestrator.records.values()),
                        analysis.reference_time,
                    )
                )
            recs = self.shadow_controller.evaluate_analysis(
                analysis,
                decisions,
                analysis.reference_time,
            )
            rl_comparison = None
            try:
                encoded_state = self._rl_encoded_state_from_analysis(analysis_id)
                safety_context = {
                    decision.action_id: decision for decision in decisions
                }
                rl_result = self.rl_inference_service.recommend(
                    encoded_state,
                    safety_context=safety_context,
                )
                rl_comparison = self._rl_policy_comparison(
                    encoded_state,
                    analysis_id=analysis_id,
                    rl_result=rl_result,
                )
                self.rl_predictions[analysis_id] = rl_result
                self.rl_comparisons[analysis_id] = rl_comparison
            except Exception as exc:  # noqa: BLE001
                rl_comparison = {"warning": f"rl_shadow_comparison_failed: {exc}"}
            return {
                "recommendations": [
                    rec.model_dump(mode="json") for rec in recs
                ],
                "policy_comparison": rl_comparison,
            }

    def gnn_health(self) -> Dict:
        """Return read-only GNN model health and registry summary."""
        with self._lock:
            health = self.gnn_inference_service.health().model_dump(mode="json")
            health["registry"] = self.gnn_registry.summary()
            health["warnings"] = list(health.get("warnings", [])) + list(
                self.gnn_startup_warnings
            )
            return health

    def gnn_list_models(self) -> Dict:
        """Return all registered GNN models."""
        with self._lock:
            return {
                "summary": self.gnn_registry.summary(),
                "models": [
                    model.model_dump(mode="json")
                    for model in self.gnn_registry.list_models()
                ],
            }

    def gnn_get_model(self, model_id: str) -> Dict:
        """Return one registered GNN model."""
        with self._lock:
            model = self.gnn_registry.get(model_id)
            if model is None:
                raise KeyError(model_id)
            return model.model_dump(mode="json")

    def _gnn_sample_from_analysis(self, analysis_id: str):
        """Build a GraphSample from a stored attack analysis."""
        from mirage.gnn.dataset import GraphDatasetBuilder

        analysis = self.get_attack_analysis(analysis_id)
        builder = GraphDatasetBuilder(schema=self.gnn_schema)
        return builder.build_sample(
            twin_snapshot=self.twin.create_snapshot(),
            belief_snapshot=self.detection_pipeline.belief_engine.create_snapshot(),
            local_subgraph=analysis.subgraph,
            reference_time=analysis.reference_time,
            scenario_id=f"api:{analysis_id}",
            topology_id="api_current_twin",
        )

    def gnn_encode(self, request) -> Dict:
        """Encode a GraphSample or stored analysis with the GNN service."""
        from mirage.gnn.schema import GraphSample

        with self._lock:
            if request.graph_sample is not None:
                sample = GraphSample.model_validate(request.graph_sample)
                prediction_key = request.analysis_id or sample.sample_id
            elif request.analysis_id:
                sample = self._gnn_sample_from_analysis(request.analysis_id)
                prediction_key = request.analysis_id
            else:
                raise ValueError("graph_sample or analysis_id is required")

            if request.model_path:
                self.gnn_inference_service.load_model(
                    str(resolve_project_path(request.model_path))
                )

            result = self.gnn_inference_service.encode_subgraph(sample)
            self.gnn_predictions[prediction_key] = result
            return result.model_dump(mode="json")

    def gnn_get_prediction(self, analysis_id: str) -> Dict:
        """Return a cached GNN prediction by analysis/sample key."""
        with self._lock:
            result = self.gnn_predictions.get(analysis_id)
            if result is None:
                raise KeyError(analysis_id)
            return result.model_dump(mode="json")

    def gnn_evaluate(self, request) -> Dict:
        """Evaluate baselines and optionally a GNN model on a dataset."""
        from mirage.gnn.baselines import HeuristicBaseline, LogisticBaseline, MLPBaseline
        from mirage.gnn.dataset import GraphDatasetBuilder
        from mirage.gnn.evaluation import GNNEvaluator
        from mirage.gnn.schema import SplitType

        dataset_path = resolve_project_path(request.dataset_path)
        if not os.path.exists(dataset_path):
            raise FileNotFoundError(str(dataset_path))

        samples, _ = GraphDatasetBuilder.load_dataset(str(dataset_path))
        test_samples = [sample for sample in samples if sample.split == SplitType.TEST]
        if not test_samples:
            test_samples = samples
        train_samples = [sample for sample in samples if sample.split == SplitType.TRAIN]
        evaluator = GNNEvaluator()
        results: Dict[str, Any] = {}

        for baseline_cls in (HeuristicBaseline, LogisticBaseline, MLPBaseline):
            baseline = baseline_cls(schema=self.gnn_schema)
            baseline.fit(train_samples)
            results[baseline.name] = evaluator.full_evaluation(
                test_samples,
                baseline.predict,
                baseline.name,
            )

        if request.model_path:
            self.gnn_inference_service.load_model(
                str(resolve_project_path(request.model_path))
            )

            def _predict(sample):
                encoded = self.gnn_inference_service.encode_subgraph(sample)
                return {
                    "node_risk_probabilities": (
                        encoded.gnn_output.node_risk_probabilities
                    ),
                    "edge_movement_probabilities": (
                        encoded.gnn_output.edge_movement_probabilities
                    ),
                    "graph_risk_probability": (
                        encoded.gnn_output.graph_risk_probability
                    ),
                }

            results["gnn_v1"] = evaluator.full_evaluation(
                test_samples,
                _predict,
                "gnn_v1",
            )

        return {
            "dataset_path": str(dataset_path),
            "sample_count": len(samples),
            "test_sample_count": len(test_samples),
            "results": results,
            "note": (
                "Metrics are synthetic/offline evaluation indicators and are "
                "not production cybersecurity-effectiveness claims."
            ),
        }

    def _rl_training_enabled(self) -> bool:
        """Return whether RL dataset/training API mutations are enabled."""
        return bool(
            self.config.get("offline_rl", {}).get("api_training_enabled", False)
        )

    def _rl_encoded_state_from_analysis(self, analysis_id: str):
        """Build an EncodedRLState from a stored attack analysis."""
        analysis = self.get_attack_analysis(analysis_id)
        return self.rl_state_encoder.encode(
            twin_snapshot=self.twin.create_snapshot(),
            belief_snapshot=self.detection_pipeline.belief_engine.create_snapshot(),
            attack_analysis=analysis,
            candidate_action_set=analysis.candidate_action_set,
            gnn_result=self.gnn_predictions.get(analysis_id),
        )

    def _rl_safety_context_for_analysis(self, analysis_id: str) -> Dict[str, Any]:
        """Evaluate Safety Gate decisions for an analysis without execution."""
        analysis = self.get_attack_analysis(analysis_id)
        twin_snapshot = self.twin.create_snapshot()
        belief_snapshot = self.detection_pipeline.belief_engine.create_snapshot()
        decisions = {}
        for action in analysis.candidate_action_set.actions:
            mask = analysis.candidate_action_set.masks[action.action_id]
            decisions[action.action_id] = self.execution_safety_gate.evaluate(
                action,
                mask,
                twin_snapshot,
                belief_snapshot,
                list(self.execution_orchestrator.records.values()),
                analysis.reference_time,
            )
        return decisions

    def rl_health(self) -> Dict:
        """Return offline-RL inference health and policy registry summary."""
        with self._lock:
            health = self.rl_inference_service.health().model_dump(mode="json")
            health["registry"] = self.rl_policy_registry.summary()
            health["warnings"] = list(health.get("warnings", [])) + list(
                self.rl_startup_warnings
            )
            health["execution_enabled"] = bool(
                self.config.get("offline_rl", {}).get(
                    "rl_execution_enabled",
                    False,
                )
            )
            return health

    def rl_list_policies(self) -> Dict:
        """Return registered offline-RL policies."""
        with self._lock:
            return {
                "summary": self.rl_policy_registry.summary(),
                "policies": [
                    policy.model_dump(mode="json")
                    for policy in self.rl_policy_registry.list_policies()
                ],
            }

    def rl_get_policy(self, policy_id: str) -> Dict:
        """Return one registered offline-RL policy."""
        with self._lock:
            policy = self.rl_policy_registry.get(policy_id)
            if policy is None:
                raise KeyError(policy_id)
            return policy.model_dump(mode="json")

    def rl_build_dataset(self, request) -> Dict:
        """Build a deterministic offline-RL dataset. Disabled by default."""
        if not self._rl_training_enabled():
            raise PermissionError(
                "Offline-RL dataset build API is disabled by default. "
                "Set offline_rl.api_training_enabled=true explicitly."
            )
        from mirage.rl.dataset import OfflineRLDatasetBuilder
        from mirage.rl.scenarios import build_synthetic_trajectories

        with self._lock:
            output = request.output_path or self.config.get("offline_rl", {}).get(
                "dataset_path",
                "artifacts/rl_dataset",
            )
            trajectories = build_synthetic_trajectories()
            manifest = OfflineRLDatasetBuilder().save_dataset(
                trajectories,
                str(resolve_project_path(output)),
            )
            return manifest.model_dump(mode="json")

    def rl_train(self, request) -> Dict:
        """Train BC or offline-RL policy. Disabled by default."""
        if not self._rl_training_enabled():
            raise PermissionError(
                "Offline-RL training API is disabled by default. "
                "Set offline_rl.api_training_enabled=true explicitly."
            )
        from mirage.rl.training import train_behavior_cloning, train_offline_policy

        algorithm = str(request.algorithm).lower()
        dataset_path = str(resolve_project_path(request.dataset_path))
        output_path = str(resolve_project_path(request.output_path))
        if algorithm in {"bc", "behavior_cloning", "hierarchical_bc"}:
            metadata = train_behavior_cloning(
                dataset_path,
                output_path,
                request.config,
            )
        elif algorithm in {"offline_rl", "iql", "hierarchical_offline_rl"}:
            init_path = (
                str(resolve_project_path(request.init_policy_path))
                if request.init_policy_path
                else None
            )
            metadata = train_offline_policy(
                dataset_path,
                output_path,
                init_path,
                request.config,
            )
        else:
            raise ValueError("algorithm must be 'behavior_cloning' or 'offline_rl'")
        with self._lock:
            self.rl_policy_registry.register(metadata)
        return metadata.model_dump(mode="json")

    def rl_evaluate(self, request) -> Dict:
        """Run offline/replay evaluation for RL policies."""
        from mirage.rl.evaluation import OfflinePolicyEvaluator

        dataset_path = str(resolve_project_path(request.dataset_path))
        policy_path = (
            str(resolve_project_path(request.policy_path))
            if request.policy_path
            else None
        )
        return OfflinePolicyEvaluator().evaluate_baselines(dataset_path, policy_path)

    def rl_recommend(self, request) -> Dict:
        """Run read-only RL shadow recommendation."""
        from mirage.rl.schema import EncodedRLState

        with self._lock:
            safety_context = {}
            analysis_id = request.analysis_id
            if request.encoded_state is not None:
                encoded_state = EncodedRLState.model_validate(request.encoded_state)
            elif analysis_id:
                encoded_state = self._rl_encoded_state_from_analysis(analysis_id)
                safety_context = self._rl_safety_context_for_analysis(analysis_id)
            else:
                raise ValueError("encoded_state or analysis_id is required")

            if request.policy_path:
                self.rl_inference_service.load_policy(
                    str(resolve_project_path(request.policy_path))
                )

            result = self.rl_inference_service.recommend(
                encoded_state,
                safety_context=safety_context,
            )
            comparison = self._rl_policy_comparison(
                encoded_state,
                analysis_id=analysis_id,
                rl_result=result,
            )
            result = result.model_copy(
                update={"robust_planner_comparison": comparison.get("robust", {})}
            )
            key = analysis_id or encoded_state.state_reference.state_id
            self.rl_predictions[key] = result
            self.rl_comparisons[key] = comparison
            return result.model_dump(mode="json")

    def _rl_policy_comparison(
        self,
        encoded_state,
        *,
        analysis_id: str | None,
        rl_result,
    ) -> Dict[str, Any]:
        from mirage.rl.baselines import BehaviorCloningPolicy, HeuristicCandidatePolicy

        heuristic = HeuristicCandidatePolicy().recommend(encoded_state)
        bc = BehaviorCloningPolicy().recommend(encoded_state)
        robust_choice = "__NO_OP__"
        if analysis_id and analysis_id in self.analysis_history:
            analysis = self.analysis_history[analysis_id]
            robust_choice = next(
                iter(analysis.candidate_action_set.recommended_action_ids),
                "__NO_OP__",
            )
        comparison = {
            "heuristic": {
                "selected_action_id": heuristic.selected_action_id,
                "selected_tactic": heuristic.selected_high_level_tactic.value,
                "confidence": heuristic.policy_confidence,
            },
            "behavior_cloning": {
                "selected_action_id": bc.selected_action_id,
                "selected_tactic": bc.selected_high_level_tactic.value,
                "confidence": bc.policy_confidence,
            },
            "rl": {
                "selected_action_id": rl_result.selected_action_id,
                "selected_tactic": rl_result.selected_high_level_tactic.value,
                "confidence": rl_result.policy_confidence,
                "fallback_used": rl_result.fallback_used,
                "fallback_reason": rl_result.fallback_reason,
            },
            "robust": {
                "selected_action_id": robust_choice,
                "agreement_with_rl": robust_choice == rl_result.selected_action_id,
            },
            "review_required": (
                robust_choice != "__NO_OP__"
                and robust_choice != rl_result.selected_action_id
            ),
        }
        return comparison

    def rl_get_comparison(self, analysis_id: str) -> Dict:
        """Return cached side-by-side policy comparison."""
        with self._lock:
            comparison = self.rl_comparisons.get(analysis_id)
            if comparison is None:
                raise KeyError(analysis_id)
            return comparison

    def _marl_training_enabled(self) -> bool:
        """Return whether MARL training API mutations are enabled."""
        return bool(self.config.get("marl", {}).get("training_api_enabled", False))

    def marl_health(self) -> Dict:
        """Return MARL cyber-range health."""
        from mirage.marl.schema import RangeHealth

        with self._lock:
            health = RangeHealth(
                status="isolated",
                isolation=self.marl_isolation,
                training_api_enabled=self._marl_training_enabled(),
                policy_count=len(self.marl_policy_registry.list_policies()),
                scenario_count=len(self.marl_scenarios),
                warnings=list(self.marl_startup_warnings),
            )
            return health.model_dump(mode="json")

    def marl_list_policies(self) -> Dict:
        """Return registered MARL policy metadata."""
        with self._lock:
            return {
                "summary": self.marl_policy_registry.summary(),
                "policies": [
                    policy.model_dump(mode="json")
                    for policy in self.marl_policy_registry.list_policies()
                ],
            }

    def marl_get_policy(self, policy_id: str) -> Dict:
        """Return one MARL policy metadata record."""
        with self._lock:
            policy = self.marl_policy_registry.get(policy_id)
            if policy is None:
                raise KeyError(policy_id)
            return policy.model_dump(mode="json")

    def marl_population(self) -> Dict:
        """Return default opponent population metadata."""
        from mirage.marl.population import OpponentPopulation

        population = OpponentPopulation()
        population.add_scripted_defaults()
        return {
            "opponents": [
                item.model_dump(mode="json") for item in population.list_metadata()
            ]
        }

    def marl_train(self, request) -> Dict:
        """Run synthetic self-play training. Disabled by default."""
        if not self._marl_training_enabled():
            raise PermissionError(
                "MARL training API is disabled by default. "
                "Set marl.training_api_enabled=true explicitly."
            )
        from mirage.marl.scenarios import load_scenarios
        from mirage.marl.training import SelfPlayTrainer

        scenarios = load_scenarios(int(request.scenario_count))
        trainer = SelfPlayTrainer(scenarios, isolation=self.marl_isolation)
        algorithm = str(request.algorithm).lower()
        if algorithm in {"self_play", "self-play", "population_self_play"}:
            summary = trainer.self_play(int(request.episodes))
        elif algorithm in {"train_blue", "blue"}:
            summary = trainer.train_blue(int(request.episodes))
        elif algorithm in {"train_red", "red"}:
            summary = trainer.train_red(int(request.episodes))
        else:
            raise ValueError("algorithm must be self_play, train_blue, or train_red")
        if request.output_path:
            trainer.save_checkpoint(str(resolve_project_path(request.output_path)), summary)
        if summary.policy_metadata is not None:
            with self._lock:
                self.marl_policy_registry.register(summary.policy_metadata)
                self.marl_jobs[summary.job_id] = summary
        return summary.model_dump(mode="json")

    def marl_evaluate(self, request) -> Dict:
        """Run synthetic exploitability and robustness evaluation."""
        from mirage.marl.evaluation import ExploitabilityEvaluator, PolicyRobustnessEvaluator
        from mirage.marl.scenarios import load_scenarios

        scenarios = load_scenarios(int(request.scenario_count))
        return {
            "exploitability": ExploitabilityEvaluator(
                scenarios,
                isolation=self.marl_isolation,
            ).evaluate().model_dump(mode="json"),
            "robustness": PolicyRobustnessEvaluator(
                scenarios,
                isolation=self.marl_isolation,
            ).evaluate().model_dump(mode="json"),
        }

    def marl_replay(self, request) -> Dict:
        """Replay abstract red/blue actions inside one synthetic scenario."""
        from mirage.marl.environment import CyberRangeEnvironment

        scenario = next(
            (
                item for item in self.marl_scenarios
                if item.scenario_id == request.scenario_id
            ),
            None,
        )
        if scenario is None:
            raise KeyError(request.scenario_id)
        env = CyberRangeEnvironment(scenario, isolation=self.marl_isolation)
        env.reset()
        results = env.replay(request.steps)
        replay_id = deterministic_id(
            "marl_replay",
            request.scenario_id,
            json.dumps(request.steps, sort_keys=True),
        )
        payload = {
            "replay_id": replay_id,
            "scenario_id": request.scenario_id,
            "steps": [result.model_dump(mode="json") for result in results],
            "final_state": env.snapshot(),
        }
        with self._lock:
            self.marl_replays[replay_id] = payload
        return payload

    def marl_get_job(self, job_id: str) -> Dict:
        """Return cached MARL training job output."""
        with self._lock:
            job = self.marl_jobs.get(job_id)
            if job is None:
                raise KeyError(job_id)
            if hasattr(job, "model_dump"):
                return job.model_dump(mode="json")
            return dict(job)

    def marl_get_comparison(self, analysis_id: str) -> Dict:
        """Return a shadow comparison with MARL evaluation context."""
        with self._lock:
            rl = self.rl_comparisons.get(analysis_id, {})
        evaluation = self.marl_evaluate(type("Req", (), {"scenario_count": 3})())
        return {
            "analysis_id": analysis_id,
            "rl_comparison": rl,
            "marl_shadow_context": evaluation,
            "note": (
                "MARL comparison is synthetic cyber-range context only; "
                "it does not execute production actions."
            ),
        }

    def governance_artifacts(self, limit: int = 100) -> Dict:
        with self._lock:
            artifacts = self.governance_registry.list_artifacts()[:limit]
            return {
                "summary": self.governance_registry.summary(),
                "artifacts": [item.model_dump(mode="json") for item in artifacts],
            }

    def governance_get_artifact(self, artifact_id: str) -> Dict:
        artifact = self.governance_registry.get_artifact(artifact_id)
        if artifact is None:
            raise KeyError(artifact_id)
        return artifact.model_dump(mode="json")

    def governance_model_card(self, artifact_id: str) -> Dict:
        card = self.governance_registry.model_cards.get(artifact_id)
        if card is None:
            raise KeyError(artifact_id)
        return card.model_dump(mode="json")

    def governance_policy_card(self, artifact_id: str) -> Dict:
        card = self.governance_registry.policy_cards.get(artifact_id)
        if card is None:
            raise KeyError(artifact_id)
        return card.model_dump(mode="json")

    def governance_release_check(self, artifact_id: str, request) -> Dict:
        from mirage.governance.release import ReleaseGate
        from mirage.governance.schema import EvidenceBundle, GovernanceStatus

        artifact = self.governance_registry.get_artifact(artifact_id)
        if artifact is None:
            raise KeyError(artifact_id)
        evidence = EvidenceBundle.model_validate(request.evidence or {})
        decision = ReleaseGate(
            self.config.get("governance", {}).get("release_gate_thresholds", {})
        ).evaluate(artifact, evidence, GovernanceStatus(request.target_status))
        with self._lock:
            self.governance_registry.register_decision(decision)
            self.governance_audit.append(
                "release_gate_decision",
                actor="api",
                role="governance",
                artifact_or_execution_id=artifact_id,
                after_state=decision.model_dump(mode="json"),
            )
        return decision.model_dump(mode="json")

    def governance_approve(self, artifact_id: str, request) -> Dict:
        from mirage.governance.schema import GovernanceStatus

        artifact = self.governance_registry.get_artifact(artifact_id)
        if artifact is None:
            raise KeyError(artifact_id)
        updated = artifact.model_copy(
            update={
                "status": GovernanceStatus.PILOT_APPROVED,
                "approval_status": GovernanceStatus.PILOT_APPROVED,
            }
        )
        with self._lock:
            self.governance_registry.register_artifact(updated)
            record = self.governance_audit.append(
                "artifact_approved",
                actor=request.actor,
                role=request.role,
                artifact_or_execution_id=artifact_id,
                before_state=artifact.model_dump(mode="json"),
                after_state=updated.model_dump(mode="json"),
                reason=request.reason,
            )
        return {"artifact": updated.model_dump(mode="json"), "audit": record.model_dump(mode="json")}

    def governance_suspend(self, artifact_id: str, request) -> Dict:
        from mirage.governance.schema import GovernanceStatus

        artifact = self.governance_registry.get_artifact(artifact_id)
        if artifact is None:
            raise KeyError(artifact_id)
        updated = artifact.model_copy(update={"status": GovernanceStatus.SUSPENDED})
        with self._lock:
            self.governance_registry.register_artifact(updated)
            record = self.governance_audit.append(
                "artifact_suspended",
                actor=request.actor,
                role=request.role,
                artifact_or_execution_id=artifact_id,
                before_state=artifact.model_dump(mode="json"),
                after_state=updated.model_dump(mode="json"),
                reason=request.reason,
            )
        return {"artifact": updated.model_dump(mode="json"), "audit": record.model_dump(mode="json")}

    def verification_verify_plan(self, request) -> Dict:
        from mirage.domain.schemas import (
            ActionMask,
            BeliefSnapshot,
            CandidateDefenseAction,
            ExecutionPlan,
            SafetyDecision,
            TwinSnapshot,
        )
        from mirage.verification.schema import FormalVerificationContext

        plan = ExecutionPlan.model_validate(request.plan)
        twin = TwinSnapshot.model_validate(request.twin_snapshot)
        context = FormalVerificationContext(
            action=CandidateDefenseAction.model_validate(request.action),
            action_mask=ActionMask.model_validate(request.mask),
            safety_decision=(
                SafetyDecision.model_validate(request.safety_decision)
                if request.safety_decision
                else None
            ),
            execution_plan=plan,
            twin_snapshot=twin,
            belief_snapshot=(
                BeliefSnapshot.model_validate(request.belief_snapshot)
                if request.belief_snapshot
                else None
            ),
            pilot_scope=request.pilot_scope,
            approvals=request.approvals,
            dependency_graph=request.dependency_graph,
        )
        report = self.formal_verifier.verify(plan, context)
        with self._lock:
            self.verification_reports[report.report_id] = report
            self.governance_audit.append(
                "formal_verification_report",
                artifact_or_execution_id=plan.plan_id,
                after_state=report.model_dump(mode="json"),
                hashes={"report_hash": report.report_hash},
            )
        return report.model_dump(mode="json")

    def verification_get_report(self, report_id: str) -> Dict:
        report = self.verification_reports.get(report_id)
        if report is None:
            raise KeyError(report_id)
        return report.model_dump(mode="json")

    def verification_invariants(self) -> Dict:
        return {
            "invariants": [
                invariant.model_dump(mode="json")
                for invariant in self.invariant_registry.list_invariants()
            ]
        }

    def verification_validate_invariant(self, request) -> Dict:
        from mirage.verification.schema import SafetyInvariant

        invariant = SafetyInvariant.model_validate(request.invariant)
        return {"valid": True, "invariant": invariant.model_dump(mode="json")}

    def pilot_scopes(self) -> Dict:
        return {
            "scopes": [
                scope.model_dump(mode="json")
                for scope in self.pilot_scope_registry.list_scopes()
            ]
        }

    def pilot_prepare(self, request) -> Dict:
        scope = self.pilot_scope_registry.get(request.scope_id)
        if scope is None:
            raise KeyError(request.scope_id)
        result = self.pilot_controller.prepare(
            request.recommendation,
            scope,
            ensure_utc(None),
        )
        return result.model_dump(mode="json")

    def pilot_approve(self, execution_id: str, request) -> Dict:
        from mirage.domain.schemas import ExecutionPlan

        plan = ExecutionPlan.model_validate(request.plan)
        approval = self.pilot_controller.record_approval(
            plan,
            approver=request.approver,
            approver_role=request.approver_role,
            environment=request.environment,
            ttl_seconds=request.ttl_seconds,
        )
        return approval.model_dump(mode="json")

    def pilot_canary(self, execution_id: str, request) -> Dict:
        decision = self.pilot_controller.canary.evaluate(execution_id, request.checks)
        return decision.model_dump(mode="json")

    def pilot_monitor(self, execution_id: str, request) -> Dict:
        result = self.pilot_controller.monitor_engine.evaluate(
            execution_id,
            request.metrics,
            protected_asset_affected=request.protected_asset_affected,
            management_channel_lost=request.management_channel_lost,
            rollback_channel_at_risk=request.rollback_channel_at_risk,
            scope_expanded=request.scope_expanded,
            kill_switch_active=request.kill_switch_active,
            policy_suspended=request.policy_suspended,
        )
        return result.model_dump(mode="json")

    def pilot_rollback(self, execution_id: str, request) -> Dict:
        if execution_id not in self.pilot_controller.records:
            from mirage.pilot.schema import PilotExecutionRecord

            self.pilot_controller.records[execution_id] = PilotExecutionRecord(
                pilot_execution_id=execution_id,
                pilot_scope_id="api",
                execution_plan_id="unknown",
            )
        return self.pilot_controller.rollback(
            execution_id,
            request.reason,
        ).model_dump(mode="json")

    def pilot_get_execution(self, execution_id: str) -> Dict:
        record = self.pilot_controller.records.get(execution_id)
        if record is None:
            raise KeyError(execution_id)
        return record.model_dump(mode="json")

    def pilot_list_executions(self, limit: int = 100) -> Dict:
        return {
            "executions": [
                record.model_dump(mode="json")
                for record in list(self.pilot_controller.records.values())[:limit]
            ]
        }

    def drift_status(self) -> Dict:
        report = self.drift_monitor.evaluate()
        self.drift_reports[report.report_id] = report
        return report.model_dump(mode="json")

    def drift_reports_list(self, limit: int = 100) -> Dict:
        return {
            "reports": [
                report.model_dump(mode="json")
                for report in list(self.drift_reports.values())[:limit]
            ]
        }

    def governance_audit_list(self, limit: int = 100) -> Dict:
        return {
            "records": [
                record.model_dump(mode="json")
                for record in self.governance_audit.records[-limit:]
            ]
        }

    def governance_audit_verify(self) -> Dict:
        return self.governance_audit.verify_chain()

    def record_shadow_feedback(
        self,
        recommendation_id: str,
        request,
    ) -> Dict:
        """Record analyst feedback for shadow recommendation."""
        feedback = AnalystFeedback(
            feedback_id=stable_shadow_feedback_id(
                recommendation_id,
                request.analyst_identifier,
                request.analyst_decision.value,
            ),
            recommendation_id=recommendation_id,
            analyst_decision=request.analyst_decision,
            usefulness_score=request.usefulness_score,
            correctness_score=request.correctness_score,
            safety_score=request.safety_score,
            rejection_reason=request.rejection_reason,
            corrected_action_type=request.corrected_action_type,
            comments=request.comments,
            analyst_identifier=request.analyst_identifier,
            timestamp=datetime.now().astimezone(),
        )
        with self._lock:
            self.shadow_controller.record_feedback(feedback)
        return feedback.model_dump(mode="json")

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
                                "contextual_risk": self.graph.edge_metadata.get(
                                    key,
                                    {},
                                ),
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
                "detection_events": self.detection_pipeline.timeline_store.event_count(),
                "detection_belief_version": (
                    self.detection_pipeline.belief_engine.version
                ),
                "detection_evidence": len(
                    self.detection_pipeline.belief_engine.evidence
                ),
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
    production_metrics = MetricsRegistry()
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
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        request.state.correlation_id = correlation_id
        production_metrics.increment("mirage_api_requests_total")
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
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
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
        return response

    # Serve dashboard static files
    dashboard_dir = os.path.join(os.path.dirname(__file__), "..", "dashboard")
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
    app.state.production_metrics = production_metrics
    decision_lock = asyncio.Lock()

    def production_dependencies() -> DependencyChecker:
        audit_path = resolve_project_path(
            config.get("production", {}).get("audit", {}).get(
                "path",
                "artifacts/production/audit.jsonl",
            )
        )
        return DependencyChecker(
            {
                "audit_storage": lambda: audit_path.parent.exists(),
                "governance_store": lambda: True,
                "model_registry": lambda: resolve_project_path("models").exists(),
                "event_bus": lambda: bool(config.get("production", {}).get("event_transport")),
                "database": lambda: True,
            }
        )

    # ---- REST Endpoints ----

    @app.get("/")
    async def root():
        return {
            "name": "MIRAGE API",
            "version": __version__,
            "docs": "/docs",
            "endpoints": [
                "GET  /health/live",
                "GET  /health/ready",
                "GET  /health/dependencies",
                "GET  /health/security",
                "GET  /metrics",
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
                "POST /api/v1/events",
                "POST /api/v1/events/batch",
                "GET  /api/v1/twin/status",
                "GET  /api/v1/twin/snapshot",
                "GET  /api/v1/twin/assets/{asset_id}",
                "GET  /api/v1/twin/subgraph",
                "POST /api/v1/twin/replay",
                "POST /api/v1/detection/events",
                "POST /api/v1/detection/events/batch",
                "GET  /api/v1/detection/entities/{entity_id}",
                "GET  /api/v1/detection/entities/{entity_id}/timeline",
                "GET  /api/v1/detection/entities/{entity_id}/evidence",
                "GET  /api/v1/detection/suspicious",
                "GET  /api/v1/detection/incidents",
                "GET  /api/v1/detection/incidents/{incident_id}",
                "GET  /api/v1/belief/snapshot",
                "POST /api/v1/belief/recompute",
                "POST /api/v1/analysis/run",
                "GET  /api/v1/analysis/{analysis_id}",
                "GET  /api/v1/analysis/{analysis_id}/subgraph",
                "GET  /api/v1/analysis/{analysis_id}/paths",
                "GET  /api/v1/analysis/{analysis_id}/critical-assets",
                "GET  /api/v1/analysis/{analysis_id}/deception-positions",
                "GET  /api/v1/analysis/{analysis_id}/actions",
                "GET  /api/v1/analysis/{analysis_id}/masks",
                "POST /api/v1/analysis/recompute",
                "POST /api/v1/gnn/encode",
                "GET  /api/v1/gnn/models",
                "GET  /api/v1/gnn/models/{id}",
                "GET  /api/v1/gnn/health",
                "POST /api/v1/gnn/evaluate",
                "GET  /api/v1/gnn/predictions/{analysis_id}",
                "POST /api/v1/rl/datasets/build",
                "POST /api/v1/rl/train",
                "POST /api/v1/rl/evaluate",
                "POST /api/v1/rl/recommend",
                "GET  /api/v1/rl/policies",
                "GET  /api/v1/rl/health",
                "GET  /api/v1/marl/range-health",
                "POST /api/v1/marl/train",
                "POST /api/v1/marl/evaluate",
                "POST /api/v1/marl/replay",
                "GET  /api/v1/marl/jobs/{job_id}",
                "GET  /api/v1/marl/population",
                "GET  /api/v1/marl/policies",
                "GET  /api/v1/marl/comparisons/{analysis_id}",
                "GET  /api/v1/governance/artifacts",
                "POST /api/v1/governance/artifacts/{id}/release-check",
                "POST /api/v1/governance/artifacts/{id}/approve",
                "POST /api/v1/governance/artifacts/{id}/suspend",
                "POST /api/v1/verification/plans",
                "GET  /api/v1/verification/reports/{id}",
                "GET  /api/v1/verification/invariants",
                "GET  /api/v1/pilot/scopes",
                "POST /api/v1/pilot/prepare",
                "POST /api/v1/pilot/executions/{id}/approve",
                "POST /api/v1/pilot/executions/{id}/canary",
                "POST /api/v1/pilot/executions/{id}/monitor",
                "POST /api/v1/pilot/executions/{id}/rollback",
                "GET  /api/v1/drift/status",
                "GET  /api/v1/governance/audit/verify",
                "WS   /ws",
            ],
        }

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/health/live")
    async def health_live():
        return {"status": "live"}

    @app.get("/health/ready")
    async def health_ready():
        report = build_health_report(config, dependencies=production_dependencies())
        status_code = 200 if report.ready else 503
        return JSONResponse(
            status_code=status_code,
            content=report.model_dump(mode="json"),
        )

    @app.get("/health/dependencies")
    async def health_dependencies():
        return {
            "dependencies": [
                item.model_dump(mode="json")
                for item in production_dependencies().check_all()
            ]
        }

    @app.get("/health/security")
    async def health_security():
        return build_health_report(config).security.model_dump(mode="json")

    @app.get("/metrics")
    async def metrics():
        snapshot = state.get_status()
        production_metrics.gauge("mirage_pending_decisions", len(state.pending_decisions))
        production_metrics.gauge("mirage_decision_history", len(state.decision_history))
        production_metrics.gauge("mirage_belief_hosts", len(snapshot.get("belief_hosts", [])))
        return PlainTextResponse(
            production_metrics.render_prometheus(),
            media_type="text/plain; version=0.0.4",
        )

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

    @app.post(
        "/api/v1/events",
        summary="Ingest one canonical security event",
        description=(
            "Applies one canonical SecurityEvent to the in-memory Digital "
            "Twin V1. Authentication is not part of Milestone 1; deploy "
            "behind trusted controls before production use."
        ),
    )
    async def ingest_canonical_event(event: SecurityEvent):
        """Apply one canonical SecurityEvent to Digital Twin V1."""
        result = await asyncio.to_thread(state.apply_canonical_event, event)
        await state.broadcast_ws({"type": "twin_update", "data": result})
        return result

    @app.post(
        "/api/v1/events/batch",
        summary="Ingest a batch of canonical or generic security events",
        description="Reports per-event failures without failing the full batch.",
    )
    async def ingest_canonical_event_batch(payload: Annotated[Any, Body()]):
        """Apply a batch of canonical or normalizable event dictionaries."""
        if not isinstance(payload, list):
            raise HTTPException(
                status_code=422,
                detail="Batch payload must be a list of event objects.",
            )
        max_batch_size = int(
            state.config.get("twin", {}).get("max_batch_size", 1000)
        )
        if len(payload) > max_batch_size:
            raise HTTPException(
                status_code=413,
                detail=f"Batch exceeds twin.max_batch_size={max_batch_size}.",
            )

        results = []
        failures = []
        for index, raw_event in enumerate(payload):
            try:
                event = (
                    raw_event
                    if isinstance(raw_event, SecurityEvent)
                    else state.event_normalizer.normalize(raw_event)
                )
                result = await asyncio.to_thread(
                    state.apply_canonical_event,
                    event,
                )
                results.append({"index": index, "result": result})
            except (TypeError, ValueError, ValidationError) as exc:
                failures.append({"index": index, "error": str(exc)})

        response = {
            "processed": len(results),
            "failed": len(failures),
            "results": results,
            "failures": failures,
        }
        if results:
            await state.broadcast_ws({"type": "twin_batch_update", "data": response})
        return response

    @app.get(
        "/api/v1/twin/status",
        summary="Get Digital Twin V1 status",
    )
    async def get_twin_status():
        """Return in-memory twin health and metadata."""
        return state.get_twin_status()

    @app.get(
        "/api/v1/twin/snapshot",
        summary="Get Digital Twin V1 snapshot",
    )
    async def get_twin_snapshot():
        """Return a serializable TwinSnapshot."""
        return state.get_twin_snapshot()

    @app.get(
        "/api/v1/twin/assets/{asset_id}",
        summary="Get one Digital Twin asset",
    )
    async def get_twin_asset(asset_id: str):
        """Return one canonical asset or 404."""
        with state._lock:
            asset = state.twin.get_asset(asset_id)
        if asset is None:
            raise HTTPException(
                status_code=404,
                detail=f"Asset '{asset_id}' was not found.",
            )
        return asset.model_dump(mode="json")

    @app.get(
        "/api/v1/twin/subgraph",
        summary="Get a small Digital Twin relationship neighborhood",
    )
    async def get_twin_subgraph(
        entity_ids: Annotated[
            str,
            Query(description="Comma-separated entity IDs."),
        ],
        hops: Annotated[int, Query(ge=0, le=5)] = 2,
    ):
        """Return a subgraph around one or more entity IDs."""
        ids = [item.strip() for item in entity_ids.split(",") if item.strip()]
        if not ids:
            raise HTTPException(
                status_code=422,
                detail="At least one entity_id is required.",
            )
        with state._lock:
            subgraph = state.twin.get_subgraph(ids, hops=hops)
        return {
            "entities": subgraph["entities"],
            "assets": {
                key: value.model_dump(mode="json")
                for key, value in subgraph["assets"].items()
            },
            "identities": {
                key: value.model_dump(mode="json")
                for key, value in subgraph["identities"].items()
            },
            "relationships": [
                relationship.model_dump(mode="json")
                for relationship in subgraph["relationships"]
            ],
        }

    @app.post(
        "/api/v1/twin/replay",
        summary="Replay events into a fresh in-memory Digital Twin",
    )
    async def replay_twin(request: TwinReplayRequest):
        """Replay local JSONL or supplied event objects into the API twin."""
        try:
            from mirage.replay import sort_events_for_replay

            events = []
            invalid = []
            if request.events_path:
                from mirage.ingestion.jsonl_source import JSONLEventSource

                source = JSONLEventSource(
                    resolve_project_path(request.events_path),
                    strict=request.strict,
                    normalizer=state.event_normalizer,
                )
                events.extend(list(source))
                invalid.extend(
                    {
                        "line_number": error.line_number,
                        "error": error.error,
                    }
                    for error in source.errors
                )
            if request.events:
                for index, raw_event in enumerate(request.events):
                    try:
                        events.append(state.event_normalizer.normalize(raw_event))
                    except (TypeError, ValueError, ValidationError) as exc:
                        if request.strict:
                            raise
                        invalid.append({"index": index, "error": str(exc)})

            ordered_events = sort_events_for_replay(
                events,
                preserve_file_order=request.preserve_file_order,
            )
            twin_config = state.config.get("twin", {})
            fresh_twin = DigitalTwin(
                relationship_ttls=twin_config.get("relationship_ttls", {}),
                allow_provisional_entities=bool(
                    twin_config.get("allow_provisional_entities", True)
                ),
            )
            summary = fresh_twin.apply_events(ordered_events)
            summary.invalid_events = len(invalid)
            with state._lock:
                state.twin = fresh_twin
                state.detection_pipeline = state._build_detection_pipeline(
                    fresh_twin
                )
                state.analysis_pipeline = AttackAnalysisPipeline(
                    attack_graph=state.graph,
                    config=state.config.get("analysis", {}),
                )
                state.analysis_history = {}
                state.execution_orchestrator.twin = fresh_twin
                state.casm_service = CASMService(
                    fresh_twin,
                    config=state.config.get("casm", {}),
                )
                state.realtime_twin_service = RealtimeTwinService(
                    twin=fresh_twin,
                    detection_pipeline=state.detection_pipeline,
                    casm_service=state.casm_service,
                )
                state.connector_manager.event_sink = (
                    state.realtime_twin_service.process_event
                )
            snapshot = fresh_twin.create_snapshot().model_dump(mode="json")
            response = {
                "summary": summary.model_dump(mode="json"),
                "invalid": invalid,
                "snapshot": snapshot,
            }
            await state.broadcast_ws({"type": "twin_replay", "data": response})
            return response
        except (OSError, TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post(
        "/api/v1/detection/events",
        summary="Process one event through Contextual Detection V1",
        description=(
            "Normalizes one canonical or generic event, updates entity "
            "timelines, rules, evidence, correlations, belief, and graph risk."
        ),
    )
    async def ingest_detection_event(payload: Annotated[Any, Body()]):
        """Process one event through contextual detection."""
        try:
            result = await asyncio.to_thread(state.process_detection_event, payload)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        await state.broadcast_ws({"type": "detection_update", "data": result})
        return result

    @app.post(
        "/api/v1/detection/events/batch",
        summary="Process a batch through Contextual Detection V1",
        description="Reports per-event failures without failing the full batch.",
    )
    async def ingest_detection_event_batch(payload: Annotated[Any, Body()]):
        """Process a list of events through contextual detection."""
        if not isinstance(payload, list):
            raise HTTPException(
                status_code=422,
                detail="Batch payload must be a list of event objects.",
            )
        max_batch_size = int(api_config.get("max_batch_size", 1000))
        if len(payload) > max_batch_size:
            raise HTTPException(
                status_code=413,
                detail=f"Batch exceeds api.max_batch_size={max_batch_size}.",
            )
        results = []
        failures = []
        for index, raw_event in enumerate(payload):
            try:
                result = await asyncio.to_thread(
                    state.process_detection_event,
                    raw_event,
                )
                results.append({"index": index, "result": result})
            except (TypeError, ValueError, ValidationError) as exc:
                failures.append({"index": index, "error": str(exc)})
        response = {
            "processed": len(results),
            "failed": len(failures),
            "results": results,
            "failures": failures,
        }
        if results:
            await state.broadcast_ws(
                {"type": "detection_batch_update", "data": response}
            )
        return response

    @app.get(
        "/api/v1/detection/entities/{entity_id}",
        summary="Get contextual belief for one entity",
    )
    async def get_detection_entity(entity_id: str):
        """Return one EntityBelief or 404."""
        try:
            return state.get_detection_entity(entity_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Entity '{entity_id}' was not found in belief state.",
            ) from exc

    @app.get(
        "/api/v1/detection/entities/{entity_id}/timeline",
        summary="Get sanitized entity timeline",
    )
    async def get_detection_entity_timeline(
        entity_id: str,
        limit: Annotated[int, Query(ge=1, le=1000)] = int(
            config.get("detection", {}).get("api_timeline_limit", 100)
        ),
    ):
        """Return bounded timeline entries without raw sensitive payloads."""
        return {
            "entity_id": entity_id,
            "events": state.get_detection_timeline(entity_id, limit),
        }

    @app.get(
        "/api/v1/detection/entities/{entity_id}/evidence",
        summary="Get evidence for one entity",
    )
    async def get_detection_entity_evidence(entity_id: str):
        """Return explainable evidence items for one entity."""
        return {
            "entity_id": entity_id,
            "evidence": state.get_detection_evidence(entity_id),
        }

    @app.get(
        "/api/v1/detection/suspicious",
        summary="Get top suspected entities",
    )
    async def get_detection_suspicious(
        limit: Annotated[int, Query(ge=1, le=1000)] = 20,
    ):
        """Return top entity beliefs ordered by compromise probability."""
        return {"entities": state.get_suspicious_entities(limit)}

    @app.get(
        "/api/v1/detection/incidents",
        summary="Get current incident beliefs",
    )
    async def get_detection_incidents(
        limit: Annotated[int, Query(ge=1, le=100)] = 10,
    ):
        """Return current incident-level beliefs."""
        return {"incidents": state.get_incidents(limit)}

    @app.get(
        "/api/v1/detection/incidents/{incident_id}",
        summary="Get one incident belief",
    )
    async def get_detection_incident(incident_id: str):
        """Return one IncidentBelief or 404."""
        try:
            return state.get_incident(incident_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Incident '{incident_id}' was not found.",
            ) from exc

    @app.get(
        "/api/v1/belief/snapshot",
        summary="Get Contextual Belief V1 snapshot",
    )
    async def get_contextual_belief_snapshot():
        """Return a serializable BeliefSnapshot."""
        return state.get_belief_snapshot()

    @app.post(
        "/api/v1/belief/recompute",
        summary="Recompute contextual belief for one entity",
    )
    async def recompute_contextual_belief(request: BeliefRecomputeRequest):
        """Recompute one entity from retained evidence."""
        try:
            return await asyncio.to_thread(
                state.recompute_belief,
                request.entity_id,
                request.reference_time,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Entity '{request.entity_id}' was not found.",
            ) from exc

    @app.post(
        "/api/v1/analysis/run",
        summary="Run attack-path analysis and candidate action generation",
    )
    async def run_attack_analysis(request: AnalysisRunRequest):
        """Run Milestone 3 analysis from current Twin and belief state."""
        try:
            return await asyncio.to_thread(state.run_attack_analysis, request)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/analysis/recompute",
        summary="Recompute attack-path analysis",
    )
    async def recompute_attack_analysis(request: AnalysisRunRequest):
        """Alias for a fresh analysis run."""
        return await run_attack_analysis(request)

    def _analysis_or_404(analysis_id: str) -> AttackAnalysisResult:
        try:
            return state.get_attack_analysis(analysis_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Analysis '{analysis_id}' was not found.",
            ) from exc

    @app.get(
        "/api/v1/analysis/{analysis_id}",
        summary="Get full attack analysis result",
    )
    async def get_attack_analysis(analysis_id: str):
        """Return full stored analysis."""
        return _analysis_or_404(analysis_id).model_dump(mode="json")

    @app.get(
        "/api/v1/analysis/{analysis_id}/subgraph",
        summary="Get local operational subgraph",
    )
    async def get_attack_analysis_subgraph(analysis_id: str):
        """Return bounded local subgraph."""
        return _analysis_or_404(analysis_id).subgraph.model_dump(mode="json")

    @app.get(
        "/api/v1/analysis/{analysis_id}/paths",
        summary="Get attack paths",
    )
    async def get_attack_analysis_paths(
        analysis_id: str,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        minimum_path_risk: Annotated[float, Query(ge=0.0, le=1.0)] = 0.0,
    ):
        """Return bounded path list."""
        result = _analysis_or_404(analysis_id)
        paths = [
            path
            for path in result.path_analysis.paths
            if path.risk_score >= minimum_path_risk
        ][:limit]
        return {"paths": [path.model_dump(mode="json") for path in paths]}

    @app.get(
        "/api/v1/analysis/{analysis_id}/critical-assets",
        summary="Get critical assets at risk",
    )
    async def get_attack_analysis_critical_assets(analysis_id: str):
        """Return critical assets at risk."""
        result = _analysis_or_404(analysis_id)
        return {"critical_assets": result.path_analysis.critical_assets_at_risk}

    @app.get(
        "/api/v1/analysis/{analysis_id}/deception-positions",
        summary="Get deception placement opportunities",
    )
    async def get_attack_analysis_deception_positions(analysis_id: str):
        """Return non-executing deception placement recommendations."""
        result = _analysis_or_404(analysis_id)
        return {
            "deception_positions": [
                position.model_dump(mode="json")
                for position in result.deception_positions
            ]
        }

    @app.get(
        "/api/v1/analysis/{analysis_id}/actions",
        summary="Get candidate defense actions",
    )
    async def get_attack_analysis_actions(
        analysis_id: str,
        include_blocked: bool = True,
        include_approval_required: bool = True,
    ):
        """Return generated candidate actions with optional filtering."""
        result = _analysis_or_404(analysis_id)
        actions = []
        for action in result.candidate_action_set.actions:
            mask = result.candidate_action_set.masks[action.action_id]
            if not include_blocked and not mask.allowed:
                continue
            if not include_approval_required and mask.approval_required:
                continue
            actions.append(action.model_dump(mode="json"))
        return {"actions": actions}

    @app.get(
        "/api/v1/analysis/{analysis_id}/masks",
        summary="Get action masks",
    )
    async def get_attack_analysis_masks(analysis_id: str):
        """Return action masks and explicit reasons."""
        result = _analysis_or_404(analysis_id)
        return {
            "masks": {
                action_id: mask.model_dump(mode="json")
                for action_id, mask in result.candidate_action_set.masks.items()
            }
        }

    @app.post(
        "/api/v1/safety/evaluate",
        summary="Evaluate a candidate action through Safety Gate V1",
    )
    async def evaluate_safety(request: SafetyEvaluateRequest):
        """Return a typed SafetyDecision without executing anything."""
        try:
            return await asyncio.to_thread(state.evaluate_execution_safety, request)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/executions/prepare",
        summary="Prepare a lab-safe execution plan",
    )
    async def prepare_execution(request: ExecutionPrepareRequest):
        """Run Safety Gate and build a stored execution plan."""
        try:
            return await asyncio.to_thread(state.prepare_execution, request)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/executions/{execution_id}/approve",
        summary="Approve or reject an execution",
    )
    async def approve_execution(
        execution_id: str,
        request: ExecutionApprovalRequest,
    ):
        """Record approval for an approval-required execution."""
        try:
            return await asyncio.to_thread(
                state.approve_execution,
                execution_id,
                request,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Execution '{execution_id}' was not found.",
            ) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/executions/{execution_id}/execute",
        summary="Execute a prepared lab plan",
    )
    async def execute_execution(
        execution_id: str,
        request: ExecutionExecuteRequest,
    ):
        """Execute a prepared plan through canary and verification."""
        try:
            record = await asyncio.to_thread(
                state.execute_execution,
                execution_id,
                request,
            )
            await state.broadcast_ws({"type": "execution_update", "data": record})
            return record
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Execution '{execution_id}' was not found.",
            ) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post(
        "/api/v1/executions/{execution_id}/rollback",
        summary="Rollback a lab execution",
    )
    async def rollback_execution(execution_id: str):
        """Rollback a succeeded, failed, expired, or pending execution."""
        try:
            record = await asyncio.to_thread(
                state.rollback_execution,
                execution_id,
            )
            await state.broadcast_ws({"type": "execution_update", "data": record})
            return record
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Execution '{execution_id}' was not found.",
            ) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get(
        "/api/v1/executions/{execution_id}",
        summary="Get one execution record",
    )
    async def get_execution(execution_id: str):
        """Return one execution record."""
        try:
            return state.get_execution(execution_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=404,
                detail=f"Execution '{execution_id}' was not found.",
            ) from exc

    @app.get(
        "/api/v1/executions",
        summary="List execution records",
    )
    async def list_executions():
        """Return all execution records."""
        return {"executions": state.list_executions()}

    @app.get(
        "/api/v1/audit",
        summary="Return sanitized execution audit events",
    )
    async def get_execution_audit():
        """Return append-only in-memory audit events."""
        return {"events": state.get_execution_audit()}

    @app.get(
        "/api/v1/kill-switch",
        summary="Get automation kill-switch state",
    )
    async def get_kill_switch():
        """Return current kill-switch state."""
        return state.execution_kill_switch.state.model_dump(mode="json")

    @app.post(
        "/api/v1/kill-switch/enable",
        summary="Enable automation kill switch",
    )
    async def enable_kill_switch(request: KillSwitchRequest):
        """Enable global or scoped automation block."""
        result = state.execution_kill_switch.enable(
            actor=request.actor,
            reason=request.reason,
            action_type=request.action_type,
            environment=request.environment,
        )
        return result.model_dump(mode="json")

    @app.post(
        "/api/v1/kill-switch/disable",
        summary="Disable automation kill switch",
    )
    async def disable_kill_switch(request: KillSwitchRequest):
        """Disable global or scoped automation block."""
        result = state.execution_kill_switch.disable(
            actor=request.actor,
            reason=request.reason,
            action_type=request.action_type,
            environment=request.environment,
        )
        return result.model_dump(mode="json")

    @app.get("/api/v1/connectors", summary="List read-only connectors")
    async def list_connectors():
        return {
            "connectors": [
                connector.config.model_dump(mode="json")
                for connector in state.connectors.values()
            ]
        }

    @app.post("/api/v1/connectors", summary="Register a read-only connector")
    async def register_connector(request: ConnectorRegisterRequest):
        try:
            return state.register_connector(request.connector)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/connectors/{connector_id}/validate")
    async def validate_connector(connector_id: str):
        try:
            return state.connector_validate(connector_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Connector not found") from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/connectors/{connector_id}/start")
    async def start_connector(connector_id: str):
        try:
            return state.connector_start(connector_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Connector not found") from exc
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/connectors/{connector_id}/stop")
    async def stop_connector(connector_id: str):
        try:
            return state.connector_stop(connector_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Connector not found") from exc

    @app.post("/api/v1/connectors/poll")
    async def poll_connectors():
        return state.connector_poll()

    @app.get("/api/v1/connectors/{connector_id}/health")
    async def get_connector_health(connector_id: str):
        try:
            return state.connector_health(connector_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Connector not found") from exc

    @app.get("/api/v1/connectors/health")
    async def get_connectors_health():
        return {"connectors": state.connector_health()}

    @app.get("/api/v1/casm/status")
    async def get_casm_status():
        return state.casm_status()

    @app.get("/api/v1/casm/assets")
    async def get_casm_assets(limit: Annotated[int, Query(ge=1, le=1000)] = 100):
        snapshot = state.twin.create_snapshot()
        return {
            "assets": [
                asset.model_dump(mode="json")
                for asset in list(snapshot.assets.values())[:limit]
            ]
        }

    @app.get("/api/v1/casm/conflicts")
    async def get_casm_conflicts():
        return {
            "conflicts": [
                conflict.model_dump(mode="json")
                for conflict in state.casm_service.find_conflicts()
            ]
        }

    @app.get("/api/v1/casm/quality")
    async def get_casm_quality():
        return state.casm_service.quality_report().model_dump(mode="json")

    @app.post("/api/v1/casm/reconcile")
    async def reconcile_casm(request: CASMReconcileRequest):
        return state.casm_reconcile(request.observation)

    @app.post("/api/v1/casm/expire-stale")
    async def expire_stale_casm():
        return state.casm_service.expire_stale_entities(
            datetime.now().astimezone()
        ).model_dump(mode="json")

    @app.get("/api/v1/twin/realtime/status")
    async def get_realtime_status():
        return state.twin.health()

    @app.get("/api/v1/twin/realtime/quality")
    async def get_realtime_quality():
        return state.realtime_twin_service.quality_report().model_dump(mode="json")

    @app.post("/api/v1/twin/realtime/snapshot")
    async def create_realtime_snapshot():
        return state.realtime_twin_service.create_consistent_snapshot().model_dump(
            mode="json"
        )

    @app.post("/api/v1/gnn/encode")
    async def encode_gnn(request: GNNEncodeRequest):
        try:
            return await asyncio.to_thread(state.gnn_encode, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Analysis not found") from exc
        except (ImportError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/gnn/models")
    async def list_gnn_models():
        return state.gnn_list_models()

    @app.get("/api/v1/gnn/models/{model_id}")
    async def get_gnn_model(model_id: str):
        try:
            return state.gnn_get_model(model_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Model not found") from exc

    @app.get("/api/v1/gnn/health")
    async def get_gnn_health():
        return state.gnn_health()

    @app.post("/api/v1/gnn/evaluate")
    async def evaluate_gnn(request: GNNEvaluateRequest):
        try:
            return await asyncio.to_thread(state.gnn_evaluate, request)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (ImportError, RuntimeError, TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/gnn/predictions/{analysis_id}")
    async def get_gnn_prediction(analysis_id: str):
        try:
            return state.gnn_get_prediction(analysis_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Prediction not found") from exc

    @app.post("/api/v1/rl/datasets/build")
    async def build_rl_dataset(request: RLDatasetBuildRequest):
        try:
            return await asyncio.to_thread(state.rl_build_dataset, request)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/rl/datasets")
    async def list_rl_datasets():
        dataset_path = resolve_project_path(
            state.config.get("offline_rl", {}).get(
                "dataset_path",
                "artifacts/rl_dataset",
            )
        )
        exists = dataset_path.exists()
        return {
            "datasets": [
                {
                    "path": str(dataset_path),
                    "exists": exists,
                }
            ]
        }

    @app.get("/api/v1/rl/datasets/{dataset_id}")
    async def get_rl_dataset(dataset_id: str):
        dataset_path = resolve_project_path(
            state.config.get("offline_rl", {}).get(
                "dataset_path",
                "artifacts/rl_dataset",
            )
        )
        manifest_path = dataset_path / "manifest.json"
        if not manifest_path.exists():
            raise HTTPException(status_code=404, detail="Dataset not found")
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if data.get("dataset_id") != dataset_id and dataset_id not in {
            "default",
            data.get("dataset_id", ""),
        }:
            raise HTTPException(status_code=404, detail="Dataset not found")
        return data

    @app.post("/api/v1/rl/train")
    async def train_rl_policy(request: RLTrainRequest):
        try:
            return await asyncio.to_thread(state.rl_train, request)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/rl/evaluate")
    async def evaluate_rl_policy(request: RLEvaluateRequest):
        try:
            return await asyncio.to_thread(state.rl_evaluate, request)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/rl/recommend")
    async def recommend_rl_policy(request: RLRecommendRequest):
        try:
            return await asyncio.to_thread(state.rl_recommend, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Analysis not found") from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/rl/policies")
    async def list_rl_policies():
        return state.rl_list_policies()

    @app.get("/api/v1/rl/policies/{policy_id}")
    async def get_rl_policy(policy_id: str):
        try:
            return state.rl_get_policy(policy_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Policy not found") from exc

    @app.get("/api/v1/rl/health")
    async def get_rl_health():
        return state.rl_health()

    @app.get("/api/v1/rl/comparisons/{analysis_id}")
    async def get_rl_comparison(analysis_id: str):
        try:
            return state.rl_get_comparison(analysis_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Comparison not found") from exc

    @app.get("/api/v1/marl/range-health")
    async def get_marl_range_health():
        return state.marl_health()

    @app.post("/api/v1/marl/train")
    async def train_marl_policy(request: MARLTrainRequest):
        try:
            return await asyncio.to_thread(state.marl_train, request)
        except PermissionError as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/marl/evaluate")
    async def evaluate_marl_policy(request: MARLEvaluateRequest):
        try:
            return await asyncio.to_thread(state.marl_evaluate, request)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/marl/replay")
    async def replay_marl_range(request: MARLReplayRequest):
        try:
            return await asyncio.to_thread(state.marl_replay, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Scenario not found") from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/marl/jobs/{job_id}")
    async def get_marl_job(job_id: str):
        try:
            return state.marl_get_job(job_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Job not found") from exc

    @app.get("/api/v1/marl/population")
    async def get_marl_population():
        return state.marl_population()

    @app.get("/api/v1/marl/policies")
    async def list_marl_policies():
        return state.marl_list_policies()

    @app.get("/api/v1/marl/policies/{policy_id}")
    async def get_marl_policy(policy_id: str):
        try:
            return state.marl_get_policy(policy_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Policy not found") from exc

    @app.get("/api/v1/marl/comparisons/{analysis_id}")
    async def get_marl_comparison(analysis_id: str):
        return await asyncio.to_thread(state.marl_get_comparison, analysis_id)

    @app.get("/api/v1/governance/artifacts")
    async def list_governance_artifacts(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ):
        return state.governance_artifacts(limit)

    @app.get("/api/v1/governance/artifacts/{artifact_id}")
    async def get_governance_artifact(artifact_id: str):
        try:
            return state.governance_get_artifact(artifact_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Artifact not found") from exc

    @app.get("/api/v1/governance/artifacts/{artifact_id}/model-card")
    async def get_governance_model_card(artifact_id: str):
        try:
            return state.governance_model_card(artifact_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Model card not found") from exc

    @app.get("/api/v1/governance/artifacts/{artifact_id}/policy-card")
    async def get_governance_policy_card(artifact_id: str):
        try:
            return state.governance_policy_card(artifact_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Policy card not found") from exc

    @app.post("/api/v1/governance/artifacts/{artifact_id}/release-check")
    async def governance_release_check(
        artifact_id: str,
        request: GovernanceReleaseCheckRequest,
    ):
        try:
            return await asyncio.to_thread(
                state.governance_release_check,
                artifact_id,
                request,
            )
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Artifact not found") from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/governance/artifacts/{artifact_id}/approve")
    async def governance_approve(
        artifact_id: str,
        request: GovernanceApprovalRequest,
    ):
        try:
            return state.governance_approve(artifact_id, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Artifact not found") from exc

    @app.post("/api/v1/governance/artifacts/{artifact_id}/suspend")
    async def governance_suspend(
        artifact_id: str,
        request: GovernanceApprovalRequest,
    ):
        try:
            return state.governance_suspend(artifact_id, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Artifact not found") from exc

    @app.post("/api/v1/verification/plans")
    async def verify_execution_plan(request: VerificationPlanRequest):
        try:
            return await asyncio.to_thread(state.verification_verify_plan, request)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/verification/reports/{report_id}")
    async def get_verification_report(report_id: str):
        try:
            return state.verification_get_report(report_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Report not found") from exc

    @app.get("/api/v1/verification/invariants")
    async def list_verification_invariants():
        return state.verification_invariants()

    @app.post("/api/v1/verification/invariants/validate")
    async def validate_verification_invariant(
        request: VerificationInvariantValidateRequest,
    ):
        try:
            return state.verification_validate_invariant(request)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/v1/pilot/scopes")
    async def list_pilot_scopes():
        return state.pilot_scopes()

    @app.post("/api/v1/pilot/prepare")
    async def prepare_pilot(request: PilotPrepareRequest):
        try:
            return await asyncio.to_thread(state.pilot_prepare, request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Pilot scope not found") from exc
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/pilot/executions/{execution_id}/approve")
    async def approve_pilot_execution(
        execution_id: str,
        request: PilotApprovalRequest,
    ):
        try:
            return state.pilot_approve(execution_id, request)
        except (TypeError, ValueError, ValidationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/v1/pilot/executions/{execution_id}/canary")
    async def pilot_canary(execution_id: str, request: PilotCanaryRequest):
        return state.pilot_canary(execution_id, request)

    @app.post("/api/v1/pilot/executions/{execution_id}/monitor")
    async def pilot_monitor(execution_id: str, request: PilotMonitorRequest):
        return state.pilot_monitor(execution_id, request)

    @app.post("/api/v1/pilot/executions/{execution_id}/rollback")
    async def pilot_rollback(execution_id: str, request: PilotRollbackRequest):
        return state.pilot_rollback(execution_id, request)

    @app.get("/api/v1/pilot/executions/{execution_id}")
    async def get_pilot_execution(execution_id: str):
        try:
            return state.pilot_get_execution(execution_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Pilot execution not found") from exc

    @app.get("/api/v1/pilot/executions")
    async def list_pilot_executions(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ):
        return state.pilot_list_executions(limit)

    @app.get("/api/v1/drift/status")
    async def get_drift_status():
        return state.drift_status()

    @app.get("/api/v1/drift/reports")
    async def list_drift_reports(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ):
        return state.drift_reports_list(limit)

    @app.get("/api/v1/governance/audit")
    async def list_governance_audit(
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ):
        return state.governance_audit_list(limit)

    @app.get("/api/v1/governance/audit/verify")
    async def verify_governance_audit():
        return state.governance_audit_verify()

    @app.post("/api/v1/shadow/run")
    async def run_shadow(request: ShadowRunRequest):
        try:
            return state.run_shadow(request.analysis_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="Analysis not found") from exc

    @app.get("/api/v1/shadow/recommendations")
    async def list_shadow_recommendations(
        status: Optional[str] = None,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
    ):
        return {
            "recommendations": [
                rec.model_dump(mode="json")
                for rec in state.shadow_controller.get_recommendations(status)[:limit]
            ]
        }

    @app.get("/api/v1/shadow/recommendations/{recommendation_id}")
    async def get_shadow_recommendation(recommendation_id: str):
        rec = state.shadow_controller.recommendations.get(recommendation_id)
        if rec is None:
            raise HTTPException(status_code=404, detail="Recommendation not found")
        return rec.model_dump(mode="json")

    @app.post("/api/v1/shadow/recommendations/{recommendation_id}/feedback")
    async def record_shadow_feedback(
        recommendation_id: str,
        request: ShadowFeedbackRequest,
    ):
        return state.record_shadow_feedback(recommendation_id, request)

    @app.get("/api/v1/shadow/metrics")
    async def get_shadow_metrics():
        return state.shadow_controller.metrics().model_dump(mode="json")

    @app.get("/api/v1/dead-letter")
    async def get_dead_letters():
        return {
            "entries": [
                entry.model_dump(mode="json")
                for entry in state.connector_manager.dead_letters.list_entries()
            ]
        }

    @app.post("/api/v1/dead-letter/{dead_letter_id}/retry")
    async def retry_dead_letter(dead_letter_id: str):
        entries = {
            entry.dead_letter_id: entry
            for entry in state.connector_manager.dead_letters.list_entries()
        }
        if dead_letter_id not in entries:
            raise HTTPException(status_code=404, detail="Dead-letter not found")
        return {
            "dead_letter_id": dead_letter_id,
            "retry_queued": entries[dead_letter_id].retry_eligible,
            "note": "Controlled replay is recorded for operator review in Milestone 5.",
        }

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
