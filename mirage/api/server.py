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
from mirage.execution.utils import deterministic_id
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

        # Metrics
        self.total_events_processed = 0
        self.start_time = time.time()

        # WebSocket connections
        self.ws_connections: List[WebSocket] = []
        self._ws_broadcast_lock = asyncio.Lock()

        print("[MIRAGE API] Engine ready.")

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
            return {
                "recommendations": [
                    rec.model_dump(mode="json") for rec in recs
                ]
            }

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
