"""Verified repository inventory generation for Milestone 11."""

from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from mirage.config import PROJECT_ROOT, load_config, resolve_project_path
from mirage.milestone11.schema import (
    CapabilityInventoryItem,
    ImplementationStatus,
    InventoryTotals,
    SystemInventory,
)


FIXED_GENERATED_AT = "1970-01-01T00:00:00Z"

SAFETY_DEFAULTS = {
    "operating_mode": "shadow",
    "deployment_level": "SHADOW_ONLY",
    "production_execution_enabled": False,
    "high_risk_automation_enabled": False,
    "action_mask_required": True,
    "safety_gate_required": True,
    "formal_verification_required": True,
    "governance_gate_required": True,
    "audit_required": True,
    "rollback_required": True,
    "red_agent_cyber_range_only": True,
    "red_agent_external_network": False,
    "real_exploitation_enabled": False,
}

STATUS_RANK = {
    ImplementationStatus.IMPLEMENTED: 0,
    ImplementationStatus.PARTIAL: 1,
    ImplementationStatus.MOCK_ONLY: 2,
    ImplementationStatus.TEST_ONLY: 3,
    ImplementationStatus.DOCUMENTED_ONLY: 4,
    ImplementationStatus.STUB: 5,
    ImplementationStatus.BROKEN: 6,
    ImplementationStatus.DEPRECATED: 7,
    ImplementationStatus.NOT_FOUND: 8,
}

EXCLUDED_PARTS = {
    ".git",
    ".venv",
    ".venv-dev",
    ".python",
    ".pytest_cache",
    ".ruff_cache",
    ".uv-cache",
    "__pycache__",
    "tmp_pytest",
}

TEXT_SUFFIXES = {
    "",
    ".css",
    ".example",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".jsonl",
    ".md",
    ".py",
    ".tf",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}


@dataclass(frozen=True)
class CapabilityDefinition:
    """Search definition for one milestone capability."""

    capability_id: str
    name: str
    milestone: str
    layer: str
    description: str
    path_markers: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()
    config_keys: tuple[str, ...] = ()
    storage: tuple[str, ...] = ()
    events: tuple[str, ...] = ()
    security: tuple[str, ...] = ()
    models: tuple[str, ...] = ()
    expected_tests: tuple[str, ...] = ()


def _cap(
    capability_id: str,
    name: str,
    milestone: str,
    layer: str,
    description: str,
    *,
    path_markers: Iterable[str] = (),
    keywords: Iterable[str] = (),
    config_keys: Iterable[str] = (),
    storage: Iterable[str] = (),
    events: Iterable[str] = (),
    security: Iterable[str] = (),
    models: Iterable[str] = (),
    expected_tests: Iterable[str] = (),
) -> CapabilityDefinition:
    return CapabilityDefinition(
        capability_id=capability_id,
        name=name,
        milestone=milestone,
        layer=layer,
        description=description,
        path_markers=tuple(path_markers),
        keywords=tuple(keywords),
        config_keys=tuple(config_keys),
        storage=tuple(storage),
        events=tuple(events),
        security=tuple(security),
        models=tuple(models),
        expected_tests=tuple(expected_tests),
    )


CAPABILITY_DEFINITIONS: tuple[CapabilityDefinition, ...] = (
    _cap(
        "M1-CANONICAL-TELEMETRY",
        "Canonical telemetry and SecurityEvent schema",
        "Milestone 1",
        "Data foundation",
        "Canonical security event schema with source metadata, timestamps, confidence, raw references, schema versioning, validation, and redaction hooks.",
        path_markers=("mirage/domain/schemas.py", "mirage/ingestion/normalizer.py"),
        keywords=("class SecurityEvent", "schema_version", "raw_event_ref", "redaction"),
        config_keys=("twin", "connectors.redaction"),
        expected_tests=("tests/layer6", "tests/milestone5"),
    ),
    _cap(
        "M1-INGESTION-REPLAY",
        "JSONL ingestion, replay, validation, ordering, deduplication, and dead-letter handling",
        "Milestone 1",
        "Ingestion",
        "JSONL and batch event processing with deterministic replay and malformed-record handling.",
        path_markers=("mirage/ingestion", "mirage/replay.py", "mirage/streaming"),
        keywords=("JSONLEventSource", "sort_events_for_replay", "dead_letter", "dedup"),
        config_keys=("twin.replay_ordering", "connectors.dead_letter_state_path", "connectors.deduplication_window_seconds"),
        storage=("JSONStateStore", "dead-letter JSON state"),
        events=("canonical security events",),
        expected_tests=("tests/layer6", "tests/milestone5"),
    ),
    _cap(
        "M1-ENTITY-RESOLUTION",
        "Entity resolution and normalization",
        "Milestone 1",
        "Digital Twin",
        "Asset, identity, host, domain, IP, alias, confidence, conflict, and provenance resolution.",
        path_markers=("mirage/layer6_twin/entity_resolution.py", "mirage/layer6_twin/digital_twin.py"),
        keywords=("EntityResolver", "normalize_hostname", "aliases", "provenance", "conflict"),
        config_keys=("casm.source_precedence", "twin.allow_provisional_entities"),
        storage=("in-memory twin",),
        expected_tests=("tests/layer6", "tests/milestone5"),
    ),
    _cap(
        "M1-DIGITAL-TWIN",
        "Digital Twin entities, relationships, TTLs, snapshots, and incremental updates",
        "Milestone 1",
        "Digital Twin",
        "Assets, identities, services, vulnerabilities, network/auth/privilege/business relationships, protected and decoy markers, TTLs, and snapshots.",
        path_markers=("mirage/layer6_twin/digital_twin.py", "mirage/realtime/twin_service.py"),
        keywords=("class DigitalTwin", "create_snapshot", "relationship_ttls", "protected", "decoy"),
        config_keys=("twin.relationship_ttls", "twin.snapshot_path", "realtime"),
        storage=("in-memory twin", "snapshot JSON"),
        expected_tests=("tests/layer6/test_digital_twin_v1.py", "tests/api/test_twin_api.py"),
    ),
    _cap(
        "M1-STORAGE",
        "Storage abstractions and backend separation",
        "Milestone 1/10",
        "Storage",
        "Repository abstractions with in-memory, SQLite, and production-oriented backend declarations.",
        path_markers=("mirage/production/storage.py", "mirage/production/schema.py", "mirage/streaming/state.py"),
        keywords=("InMemoryProductionRepository", "SQLiteProductionRepository", "StorageBackend", "JSONStateStore"),
        config_keys=("production.storage", "connectors.checkpoint_state_path"),
        storage=("in-memory", "SQLite", "append-only files", "object storage abstraction"),
        expected_tests=("tests/milestone10",),
    ),
    _cap(
        "M2-TIMELINES",
        "Entity timelines and evidence windows",
        "Milestone 2",
        "Detection",
        "Event-to-entity association, bounded timelines, evidence references, and late-event behavior.",
        path_markers=("mirage/detection/timeline.py", "mirage/detection/pipeline.py"),
        keywords=("EntityTimeline", "bounded", "late", "evidence"),
        config_keys=("detection.timeline_retention_seconds", "detection.windows"),
        events=("canonical security events",),
        expected_tests=("tests/detection",),
    ),
    _cap(
        "M2-DETECTION-RULES",
        "Contextual detection rules and stage classification",
        "Milestone 2",
        "Detection",
        "Deterministic rules, sequence detection, MITRE mapping, severity, confidence, and false-positive controls.",
        path_markers=("mirage/detection/rules.py", "mirage/detection/stage_estimator.py", "mirage/layer1_contextual_ai/mitre_mapper.py"),
        keywords=("DetectionRule", "MITRE", "severity", "confidence", "suppression"),
        config_keys=("detection.rules", "detection.approved_admin_hosts"),
        expected_tests=("tests/detection/test_contextual_detection_v1.py",),
    ),
    _cap(
        "M2-BELIEF-ENGINE",
        "Belief Engine probability updates and decay",
        "Milestone 2",
        "Detection",
        "Compromise probability, attacker-location probability, stage distributions, uncertainty, duplicate protection, and stale-evidence handling.",
        path_markers=("mirage/detection/belief.py", "mirage/detection/pipeline.py"),
        keywords=("BeliefEngine", "compromise_probability", "attacker_location_probability", "belief_decay", "duplicate"),
        config_keys=("detection.evidence_decay_seconds", "detection.evidence_ttl_seconds"),
        expected_tests=("tests/detection",),
    ),
    _cap(
        "M2-EXPLANATIONS",
        "Detection explanations and warnings",
        "Milestone 2",
        "Detection",
        "Human-readable evidence, rule, provenance, belief-version, and warning output.",
        path_markers=("mirage/detection", "mirage/domain/schemas.py"),
        keywords=("evidence_ids", "rule_id", "reasoning", "warnings", "provenance"),
        config_keys=("detection",),
        expected_tests=("tests/detection",),
    ),
    _cap(
        "M3-GRAPH-ANALYSIS",
        "Local attack graph extraction and path-risk scoring",
        "Milestone 3",
        "Attack analysis",
        "Seed selection, bounded subgraphs, path discovery/pruning, protected-target reachability, decoy paths, stale/inferred penalties, and stage compatibility.",
        path_markers=("mirage/analysis", "mirage/layer2_attack_graph.py"),
        keywords=("AttackAnalysisPipeline", "extract_subgraph", "path_risk", "decoy", "stale"),
        config_keys=("analysis.seed_selection", "analysis.subgraph", "analysis.paths", "analysis.risk_scoring"),
        expected_tests=("tests/analysis",),
    ),
    _cap(
        "M3-CANDIDATE-ACTIONS",
        "Candidate defense action generation",
        "Milestone 3",
        "Action recommendation",
        "Observe, deception, delay, containment, escalation, benefit, information gain, cost, business risk, TTL, and approval requirements.",
        path_markers=("mirage/analysis/actions.py", "mirage/domain/schemas.py"),
        keywords=("CandidateDefenseAction", "expected_benefit", "information_gain", "business_risk", "requires_approval"),
        config_keys=("analysis.candidate_actions",),
        security=("approval requirements", "reversibility"),
        expected_tests=("tests/analysis",),
    ),
    _cap(
        "M3-ACTION-MASKS",
        "Action Mask generation and constraints",
        "Milestone 3",
        "Safety",
        "Protected asset, boundary, stale Twin, rollback, blast radius, action budget, conflict, and duplicate restrictions.",
        path_markers=("mirage/analysis/actions.py", "mirage/domain/schemas.py"),
        keywords=("ActionMask", "protected_asset", "blast_radius", "duplicate", "rollback"),
        config_keys=("analysis.constraints",),
        security=("Action Mask",),
        expected_tests=("tests/analysis",),
    ),
    _cap(
        "M3-RANKING",
        "Deterministic ranking and robust adapter fallback",
        "Milestone 3",
        "Decision support",
        "Explainable score breakdown, heuristic ranking, robust adapter, and fallback behavior.",
        path_markers=("mirage/analysis/robust_adapter.py", "mirage/analysis/pipeline.py"),
        keywords=("robust", "score_breakdown", "fallback", "ranking"),
        config_keys=("analysis.ranking",),
        models=("robust planner",),
        expected_tests=("tests/analysis",),
    ),
    _cap(
        "M4-SAFETY-GATE",
        "Safety Gate and hard policy checks",
        "Milestone 4",
        "Safety",
        "Safety verdicts, risk tiers, confidence thresholds, protected assets, Twin freshness, graph coverage, blast radius, rollback, approval, and kill switch.",
        path_markers=("mirage/execution/safety.py", "mirage/execution/kill_switch.py"),
        keywords=("SafetyGate", "kill_switch", "rollback", "blast_radius", "Twin freshness"),
        config_keys=("execution", "production.action_mask_required", "production.safety_gate_required"),
        security=("Safety Gate", "kill switch", "rollback required"),
        expected_tests=("tests/execution",),
    ),
    _cap(
        "M4-EXECUTION-LIFECYCLE",
        "Execution lifecycle, idempotency, retries, timeout, and rollback",
        "Milestone 4/10",
        "Execution",
        "Execution state machine with preparation, approval, canary, execution, verification, rollback, expiry, cancellation, and duplicate prevention.",
        path_markers=("mirage/execution/state_machine.py", "mirage/execution/orchestrator.py", "mirage/production/execution.py"),
        keywords=("ExecutionState", "idempot", "rollback", "timeout", "duplicate"),
        config_keys=("execution.retries", "execution.rollback_retries", "production.deployment_level"),
        storage=("in-memory execution records", "production repository"),
        expected_tests=("tests/execution", "tests/milestone10"),
    ),
    _cap(
        "M4-ADAPTERS",
        "Execution adapters and adapter classification",
        "Milestone 4",
        "Execution",
        "Common adapter interface and Docker/mock firewall, EDR, IAM, DNS, telemetry, and ticket adapters.",
        path_markers=("mirage/execution/adapters.py",),
        keywords=("Docker", "Mock", "Adapter", "firewall", "ticket"),
        config_keys=("execution.adapters",),
        security=("lab-only execution adapters",),
        expected_tests=("tests/execution",),
    ),
    _cap(
        "M4-DECEPTION-ORCHESTRATION",
        "Deception orchestration and rollback",
        "Milestone 4",
        "Execution",
        "Decoy host/database/fake share/DNS/honey credential orchestration with TTL, health, rollback, isolation, and Twin registration.",
        path_markers=("mirage/execution/orchestrator.py", "mirage/layer3_deception"),
        keywords=("decoy", "honey", "fake_dns", "rollback", "Twin"),
        config_keys=("execution.docker_templates", "execution.lab_networks"),
        expected_tests=("tests/execution",),
    ),
    _cap(
        "M5-CONNECTOR-FRAMEWORK",
        "Read-only connector framework",
        "Milestone 5",
        "Connectors",
        "Connector interface, manager, configuration, read-only enforcement, batching, polling, retries, backoff, checkpointing, health, and dead letters.",
        path_markers=("mirage/connectors", "mirage/streaming"),
        keywords=("ConnectorManager", "read_only", "checkpoint", "dead_letter", "backoff"),
        config_keys=("connectors",),
        storage=("checkpoint JSON", "dead-letter JSON"),
        expected_tests=("tests/milestone5",),
    ),
    _cap(
        "M5-CONNECTOR-IMPLEMENTATIONS",
        "Connector implementations and fixture/live-source boundaries",
        "Milestone 5",
        "Connectors",
        "Sysmon, Windows Event Log, Zeek, NetFlow, AD, IAM, asset inventory, vulnerability scanner, and generic JSONL connector behavior.",
        path_markers=("mirage/connectors/fixture.py", "examples/connectors"),
        keywords=("sysmon", "zeek", "netflow", "active_directory", "generic_jsonl"),
        config_keys=("connectors.definitions",),
        expected_tests=("tests/milestone5",),
    ),
    _cap(
        "M5-STREAMING",
        "Streaming ordering, deduplication, watermarks, recovery, and backpressure",
        "Milestone 5/10",
        "Streaming",
        "Persistent deduplication, late windows, watermarks, deterministic ordering, bounded reprocessing, checkpoint recovery, backpressure, and buffer limits.",
        path_markers=("mirage/streaming", "mirage/production/events.py"),
        keywords=("watermark", "dedup", "checkpoint", "backpressure", "max_queue_depth"),
        config_keys=("connectors.allowed_lateness_seconds", "connectors.maximum_buffered_events", "production.event_transport"),
        storage=("JSON state", "SQLite event bus"),
        events=("event bus", "dead-letter queue"),
        expected_tests=("tests/milestone5", "tests/milestone10"),
    ),
    _cap(
        "M5-CASM",
        "CASM discovery, reconciliation, conflicts, provenance, and quality",
        "Milestone 5",
        "CASM",
        "Passive asset discovery, reconciliation, conflict detection, source precedence, staleness, expiry, provenance, unknown-asset rate, and Twin-quality report.",
        path_markers=("mirage/casm", "mirage/layer6_twin/asset_discovery.py"),
        keywords=("CASMService", "quality_report", "conflict", "source_precedence", "unknown_asset"),
        config_keys=("casm",),
        expected_tests=("tests/milestone5",),
    ),
    _cap(
        "M5-SHADOW-MODE",
        "Shadow Mode recommendations and feedback",
        "Milestone 5",
        "Shadow operations",
        "Recommendations, lifecycle statuses, expiry, Safety Gate evaluation, no enforcement, analyst feedback, policy comparison, and metrics.",
        path_markers=("mirage/shadow/controller.py", "mirage/m5_cli.py"),
        keywords=("ShadowModeController", "recommendation", "feedback", "no enforcement", "metrics"),
        config_keys=("shadow", "general.operating_mode"),
        security=("no enforcement calls",),
        expected_tests=("tests/milestone5",),
    ),
    _cap(
        "M6-GRAPH-SCHEMA-FEATURES",
        "Hierarchical graph schema and feature processing",
        "Milestone 6",
        "ML features",
        "Node/edge types, hierarchy, host/subnet/domain/business mapping, feature schema, masks, vocabularies, scaling, schema versioning, and sensitive identifier controls.",
        path_markers=("mirage/gnn/schema.py", "mirage/gnn/features.py", "mirage/gnn/hierarchy.py"),
        keywords=("GraphFeatureSchema", "hierarchy", "feature_schema_version", "sensitive", "mask"),
        config_keys=("gnn.feature_schema_version", "gnn.max_nodes", "gnn.max_edges"),
        models=("GNN features",),
        expected_tests=("tests/gnn/test_dataset_and_hierarchy.py",),
    ),
    _cap(
        "M6-DATASET-GENERATION",
        "GNN dataset generation, labels, splits, hashes, and leakage controls",
        "Milestone 6",
        "ML data",
        "Graph samples, labels, provenance, topology/incident split manifests, leakage prevention, serialization, and dataset hashes.",
        path_markers=("mirage/gnn/dataset.py", "mirage/gnn/scenarios.py"),
        keywords=("GraphDatasetBuilder", "SplitType", "dataset_hash", "leakage", "provenance"),
        config_keys=("gnn",),
        models=("GNN dataset",),
        expected_tests=("tests/gnn",),
    ),
    _cap(
        "M6-MODELS-INFERENCE",
        "GNN and baseline models with registry and shadow inference",
        "Milestone 6",
        "ML inference",
        "Linear/tree/MLP baselines, GraphSAGE/GAT-style models, node/edge/subgraph heads, save/load, CPU inference, optional CUDA, uncertainty, OOD, hybrid scoring, registry, and fallback.",
        path_markers=("mirage/gnn/baselines.py", "mirage/gnn/inference.py", "mirage/gnn/registry.py", "mirage/gnn/hybrid_scorer.py"),
        keywords=("GraphSAGE", "GAT", "uncertainty", "OOD", "ModelRegistry", "heuristic fallback"),
        config_keys=("gnn.model_path", "gnn.registry_path", "gnn.uncertainty_threshold"),
        models=("GNN registry", "baseline models"),
        expected_tests=("tests/gnn",),
    ),
    _cap(
        "M7-OFFLINE-RL-DATA",
        "Offline RL dataset, trajectories, rewards, and constraints",
        "Milestone 7",
        "RL data",
        "State references, candidate-action features, transitions, trajectories, provenance, simulator/robust/lab/shadow sources, splits, rewards, and hard constraints.",
        path_markers=("mirage/rl/dataset.py", "mirage/rl/reward.py", "mirage/rl/features.py"),
        keywords=("OfflineRLDataset", "trajectory", "reward", "Action Mask", "hard_constraints"),
        config_keys=("offline_rl.dataset_path", "offline_rl.reward_model_version"),
        models=("offline RL dataset",),
        expected_tests=("tests/rl",),
    ),
    _cap(
        "M7-POLICIES-RUNTIME",
        "Behavior Cloning, conservative offline RL, policy registry, and shadow runtime",
        "Milestone 7",
        "RL policy",
        "Flat/hierarchical BC, tactic manager, low-level selector, conservative/IQL-style offline RL, support model, uncertainty, OOD fallback, inference service, policy registry, and no enforcement from RL.",
        path_markers=("mirage/rl/policy.py", "mirage/rl/baselines.py", "mirage/rl/inference.py", "mirage/rl/registry.py"),
        keywords=("BehaviorCloning", "IQL", "OfflineRLInferenceService", "fallback_order", "rl_shadow"),
        config_keys=("offline_rl.rl_operating_mode", "offline_rl.rl_execution_enabled", "offline_rl.registry_path"),
        security=("RL execution disabled", "Action Mask preserved"),
        models=("BC policy", "offline RL policy"),
        expected_tests=("tests/rl/test_milestone7_offline_rl.py",),
    ),
    _cap(
        "M8-CYBER-RANGE",
        "Cyber Range isolation, reset, masks, replay, and terminal conditions",
        "Milestone 8",
        "Cyber Range",
        "Isolated deterministic range with graph state, hidden Red state, Blue partial observations, valid masks, snapshots, restore, replay, and terminal conditions.",
        path_markers=("mirage/marl/environment.py", "mirage/marl/schema.py"),
        keywords=("RangeIsolationConfig", "reset", "snapshot", "valid_action", "terminal"),
        config_keys=("marl.cyber_range_only", "marl.red_agent_external_network"),
        security=("cyber-range only", "no external network"),
        models=("MARL range scenarios",),
        expected_tests=("tests/marl",),
    ),
    _cap(
        "M8-RED-BLUE-SELFPLAY",
        "Red/Blue agent policies and self-play evaluation",
        "Milestone 8",
        "MARL",
        "Finite Red actions without payloads, scripted/trainable masked policies, Blue restrictions, robust fallback, self-play curriculum, population, snapshots, exploitability, worst-case, and unseen-attacker evaluation.",
        path_markers=("mirage/marl/actions.py", "mirage/marl/policies.py", "mirage/marl/training.py", "mirage/marl/evaluation.py"),
        keywords=("RedAction", "payload", "self_play", "population", "exploitability"),
        config_keys=("marl.training_api_enabled", "marl.opponent_profiles"),
        security=("no free-form commands", "shadow-only integration"),
        models=("MARL policies",),
        expected_tests=("tests/marl/test_milestone8_marl.py",),
    ),
    _cap(
        "M9-FORMAL-VERIFICATION",
        "Formal safety verification and invariant registry",
        "Milestone 9",
        "Formal safety",
        "Invariant versions, SMT backend, solver timeout, UNKNOWN handling, counterexamples, graph/management/rollback reachability, decoy isolation, blast radius, and temporal lifecycle checks.",
        path_markers=("mirage/verification",),
        keywords=("SafetySpecificationRegistry", "SMT", "UNKNOWN", "counterexample", "Temporal"),
        config_keys=("verification.formal_verification_required", "verification.solver_timeout_ms"),
        security=("formal verification required",),
        expected_tests=("tests/milestone9",),
    ),
    _cap(
        "M9-GOVERNANCE",
        "Governance registry, cards, release gates, hashes, pilot scopes, and approvals",
        "Milestone 9",
        "Governance",
        "Governance registry, model/policy cards, release gates, artifact/dataset/schema hashes, scopes, statuses, suspensions, approval history, and separation of duties.",
        path_markers=("mirage/governance", "mirage/pilot"),
        keywords=("GovernanceRegistry", "model_card", "policy_card", "release_gate", "separation"),
        config_keys=("governance", "pilot"),
        security=("governance gate", "separation of duties"),
        models=("model cards", "policy cards"),
        expected_tests=("tests/milestone9",),
    ),
    _cap(
        "M9-AUDIT",
        "Hash-chained audit and tamper detection",
        "Milestone 9",
        "Audit",
        "Hash chaining, append-only records, chain verification, tamper detection, governance, execution, and approval events.",
        path_markers=("mirage/governance/audit.py", "mirage/execution/audit.py"),
        keywords=("verify_chain", "record_hash", "append-only", "sanitize"),
        config_keys=("governance.audit_path", "execution.audit_path", "production.audit"),
        storage=("JSONL audit",),
        security=("audit required", "tamper evidence"),
        expected_tests=("tests/milestone9", "tests/milestone10"),
    ),
    _cap(
        "M10-PROFILES-PERSISTENCE",
        "Deployment profiles, persistence, migrations, leases, and idempotency",
        "Milestone 10",
        "Production architecture",
        "Development/test/range/lab/shadow/pilot/production profiles, repository abstractions, PostgreSQL/SQLite/object storage settings, migrations, concurrency, leases, and idempotency.",
        path_markers=("mirage/production/schema.py", "mirage/production/storage.py", "mirage/production/migrations.py", "mirage/production/ha.py"),
        keywords=("DeploymentProfileConfig", "Postgres", "MigrationManager", "LeaseRecord", "idempotency"),
        config_keys=("production.profile", "production.profiles", "production.storage"),
        storage=("in-memory", "SQLite", "PostgreSQL-compatible declaration", "object storage declaration"),
        expected_tests=("tests/milestone10",),
    ),
    _cap(
        "M10-EVENT-TRANSPORT-HA",
        "Durable event transport and high availability controls",
        "Milestone 10",
        "Production architecture",
        "Event publisher/consumer, durable local backend, Kafka-compatible declaration, dead letters, consumer groups, retries, backpressure, broker lag, leader election, scheduler/connector ownership, failover, and duplicate prevention.",
        path_markers=("mirage/production/events.py", "mirage/production/ha.py"),
        keywords=("EventBus", "dead_letters", "backpressure", "LeaderElector", "consumer_group"),
        config_keys=("production.event_transport",),
        events=("local durable event bus", "Kafka-compatible configuration"),
        expected_tests=("tests/milestone10",),
    ),
    _cap(
        "M10-SECURITY-OBSERVABILITY-DR",
        "Production security, observability, disaster recovery, and SOC integration",
        "Milestone 10",
        "Operations",
        "Authentication, OIDC, service identity, TLS/mTLS, RBAC, tenant isolation, secrets, metrics, traces/logs, health, SLO declarations, backup/restore, and SOC/webhook adapters.",
        path_markers=("mirage/production/security.py", "mirage/production/secrets.py", "mirage/production/observability.py", "mirage/production/backup.py", "mirage/production/soc.py"),
        keywords=("RBAC", "ServiceTokenIssuer", "MetricsRegistry", "BackupManager", "SOCAdapter"),
        config_keys=("production.auth", "production.tls", "production.api_gateway", "production.audit"),
        security=("RBAC", "TLS", "tenant isolation", "secret redaction"),
        expected_tests=("tests/milestone10",),
    ),
    _cap(
        "M10-DEPLOYMENT-RESOURCES",
        "Container, Kubernetes, Helm, CI/CD, SBOM, and scanning resources",
        "Milestone 10",
        "Deployment",
        "Docker, Kubernetes, Helm, resource limits, PDBs, HPA, topology spread, NetworkPolicies, and validation manifests.",
        path_markers=("deploy/container", "deploy/kubernetes", "deploy/helm", ".github"),
        keywords=("runAsNonRoot", "readOnlyRootFilesystem", "NetworkPolicy", "HorizontalPodAutoscaler", "PodDisruptionBudget"),
        config_keys=("production.profiles",),
        security=("non-root container", "network policies"),
        expected_tests=("tests/milestone10/test_milestone10_production_hardening.py",),
    ),
    _cap(
        "M11-INVENTORY",
        "Verified repository inventory and status matrix",
        "Milestone 11",
        "Continuous assurance",
        "Machine-generated inventory, evidence collection, catalogs, deterministic JSON/YAML, and gap documentation.",
        path_markers=("mirage/milestone11/inventory.py", "docs/inventory", "artifacts/inventory"),
        keywords=("InventoryScanner", "SystemInventory", "IMPLEMENTATION_STATUS_MATRIX"),
        config_keys=("milestone11.inventory",),
        storage=("inventory JSON", "inventory YAML"),
        expected_tests=("tests/milestone11",),
    ),
    _cap(
        "M11-FEDERATION",
        "Multi-site registration, federation policy, residency, and pseudonymized transfer",
        "Milestone 11",
        "Federation",
        "Site identity, policy validation, denied-by-default transfer, residency checks, pseudonymization, duplicate handling, outage behavior, and cross-site correlation summaries.",
        path_markers=("mirage/milestone11/federation.py",),
        keywords=("FederationPolicyEngine", "pseudonymize", "residency", "duplicate"),
        config_keys=("sites", "federation"),
        security=("deny cross-site transfer by default", "no raw credentials"),
        expected_tests=("tests/milestone11",),
    ),
    _cap(
        "M11-ASSURANCE",
        "Continuous assurance evidence bundles",
        "Milestone 11",
        "Continuous assurance",
        "Scheduled/CLI/API assurance checks, evidence hashing, bundle verification, failed critical check handling, and readiness blocking.",
        path_markers=("mirage/milestone11/assurance.py",),
        keywords=("ContinuousAssuranceService", "AssuranceBundle", "bundle_hash", "deployment_reduction_required"),
        config_keys=("assurance",),
        storage=("assurance bundle JSON"),
        security=("audit chain verification", "fail closed critical checks"),
        expected_tests=("tests/milestone11",),
    ),
    _cap(
        "M11-VALIDATION",
        "Long-horizon soak and chaos validation",
        "Milestone 11",
        "Validation",
        "Deterministic CI-bounded soak and chaos scenarios for memory, queues, checkpoints, leader failure, federation outage, audit failure, backup failure, SLO exhaustion, model regression, capacity saturation, certificate expiry, range isolation, and recovery.",
        path_markers=("mirage/milestone11/validation.py",),
        keywords=("SoakValidator", "ChaosValidator", "leader_failure", "bounded"),
        config_keys=("validation",),
        events=("synthetic validation jobs",),
        expected_tests=("tests/milestone11",),
    ),
    _cap(
        "M11-SLO-CAPACITY-MATURITY-READINESS",
        "SLO, capacity, maturity, and readiness decision board",
        "Milestone 11",
        "Operations",
        "SLO/error budget reports, capacity headroom, maturity scoring, readiness evaluation, and return-to-shadow decisions.",
        path_markers=("mirage/milestone11/readiness.py",),
        keywords=("SLOService", "CapacityPlanner", "MaturityAssessor", "ReadinessBoard"),
        config_keys=("slo", "capacity", "maturity", "readiness"),
        security=("no auto-promotion", "restrictive shadow fallback"),
        expected_tests=("tests/milestone11",),
    ),
)


class InventoryScanner:
    """Generate deterministic, evidence-backed MIRAGE repository inventories."""

    def __init__(self, root: Path | None = None, config: dict[str, Any] | None = None) -> None:
        self.root = (root or PROJECT_ROOT).resolve()
        self.config = config if config is not None else load_config()
        self._files = sorted(
            [
                path
                for path in self.root.rglob("*")
                if self._should_scan_file(path)
            ],
            key=lambda item: self._rel(item),
        )
        self._text_cache: dict[Path, str] = {}
        self._api_routes_cache: list[dict[str, Any]] | None = None
        self._cli_commands_cache: list[dict[str, Any]] | None = None
        self._deployment_catalog_cache: list[dict[str, Any]] | None = None

    def scan(self) -> SystemInventory:
        """Return the verified inventory."""
        capabilities = [self._scan_capability(definition) for definition in CAPABILITY_DEFINITIONS]
        status_counts: dict[str, int] = {}
        for capability in capabilities:
            status_counts[capability.implementation_status.value] = (
                status_counts.get(capability.implementation_status.value, 0) + 1
            )
        api_routes = self._api_routes()
        cli_commands = self._cli_commands()
        schemas = self._schema_catalog()
        configuration = self._configuration_catalog()
        deployment = self._deployment_catalog()
        test_inventory = self._test_inventory()
        inventory = SystemInventory(
            generated_at=str(
                self.config.get("milestone11", {})
                .get("inventory", {})
                .get("deterministic_generated_at", FIXED_GENERATED_AT)
            ),
            repository_root=str(self.root),
            safety_defaults=self._safety_defaults(),
            totals=InventoryTotals(
                by_status=dict(sorted(status_counts.items())),
                capability_count=len(capabilities),
                source_file_count=len([p for p in self._files if self._rel(p).startswith("mirage/")]),
                test_file_count=len([p for p in self._files if self._rel(p).startswith("tests/")]),
                api_route_count=len(api_routes),
                cli_command_count=len(cli_commands),
            ),
            capabilities=capabilities,
            api_routes=api_routes,
            cli_commands=cli_commands,
            schemas=schemas,
            configuration=configuration,
            security_controls=self._security_controls(),
            model_and_policy_artifacts=self._model_policy_catalog(),
            deployment_resources=deployment,
            test_inventory=test_inventory,
            known_gaps=self._known_gaps(capabilities),
            system_summary_diagram=self._diagram(capabilities),
        )
        return inventory

    def write_artifacts(self) -> SystemInventory:
        """Scan and write all required inventory and Milestone 11 docs."""
        inventory = self.scan()
        write_inventory_files(inventory, self.root)
        write_milestone11_docs(inventory, self.root)
        return inventory

    def _scan_capability(self, definition: CapabilityDefinition) -> CapabilityInventoryItem:
        source_files = self._source_evidence(definition)
        test_files = self._test_evidence(definition)
        doc_files = self._doc_evidence(definition)
        api_routes = [
            route["route"]
            for route in self._api_routes()
            if self._matches_any(route["route"].lower(), definition.keywords)
            or self._matches_any(route["route"].lower(), definition.path_markers)
        ]
        cli_commands = [
            command["command"]
            for command in self._cli_commands()
            if self._matches_any(command["command"].lower(), definition.keywords)
            or self._matches_any(command["command"].lower(), definition.path_markers)
        ]
        deployment_resources = [
            item["path"]
            for item in self._deployment_catalog()
            if self._matches_any(item["path"].lower(), definition.path_markers)
            or self._matches_any(item.get("summary", "").lower(), definition.keywords)
        ]
        public_interfaces = self._public_interfaces(source_files)
        config_keys = [key for key in definition.config_keys if self._config_key_exists(key)]
        placeholders = self._placeholder_hits(source_files)
        mock_only = self._mock_only(source_files, definition)
        status = self._classify(
            source_files=source_files,
            test_files=test_files,
            doc_files=doc_files,
            config_keys=config_keys,
            placeholders=placeholders,
            mock_only=mock_only,
        )
        limitations = self._limitations(status, placeholders, doc_files, test_files, config_keys, definition)
        known_risks = self._risks(status, definition)
        return CapabilityInventoryItem(
            capability_id=definition.capability_id,
            capability_name=definition.name,
            milestone_origin=definition.milestone,
            architecture_layer=definition.layer,
            implementation_status=status,
            description=definition.description,
            source_files=source_files,
            public_interfaces=public_interfaces,
            storage_dependencies=list(definition.storage),
            event_dependencies=list(definition.events),
            security_dependencies=list(definition.security),
            model_dependencies=list(definition.models),
            configuration_keys=config_keys,
            tests=test_files,
            api_routes=api_routes,
            cli_commands=cli_commands,
            deployment_resources=deployment_resources,
            runtime_verification_result=(
                "test_files_discovered_not_executed_by_inventory_scanner"
                if test_files
                else "no_test_evidence_discovered"
            ),
            limitations=limitations,
            known_risks=known_risks,
            recommended_next_action=self._next_action(status),
        )

    def _classify(
        self,
        *,
        source_files: list[str],
        test_files: list[str],
        doc_files: list[str],
        config_keys: list[str],
        placeholders: list[str],
        mock_only: bool,
    ) -> ImplementationStatus:
        if placeholders and not test_files:
            return ImplementationStatus.STUB
        if source_files and mock_only:
            return ImplementationStatus.MOCK_ONLY
        if source_files and test_files and (config_keys or len(source_files) > 1) and not placeholders:
            return ImplementationStatus.IMPLEMENTED
        if source_files:
            return ImplementationStatus.PARTIAL
        if test_files:
            return ImplementationStatus.TEST_ONLY
        if doc_files:
            return ImplementationStatus.DOCUMENTED_ONLY
        return ImplementationStatus.NOT_FOUND

    def _source_evidence(self, definition: CapabilityDefinition) -> list[str]:
        files: list[str] = []
        for path in self._files:
            rel = self._rel(path)
            if not (
                rel.startswith("mirage/")
                or rel.startswith("deploy/")
                or rel.startswith("configs/")
                or rel.startswith("models/")
                or rel.startswith("artifacts/")
            ):
                continue
            text = self._safe_text(path)
            path_match = self._path_matches(rel, definition.path_markers)
            keyword_match = self._text_matches(text, definition.keywords)
            if rel.startswith("mirage/milestone11/") and not definition.capability_id.startswith("M11-"):
                keyword_match = False
            if path_match or keyword_match:
                files.append(rel)
        return sorted(set(files))

    def _test_evidence(self, definition: CapabilityDefinition) -> list[str]:
        tests: list[str] = []
        for path in self._files:
            rel = self._rel(path)
            if not rel.startswith("tests/") and not rel.startswith("test_"):
                continue
            text = self._safe_text(path)
            if (
                self._path_matches(rel, definition.expected_tests)
                or self._path_matches(rel, definition.path_markers)
                or self._text_matches(text, definition.keywords)
                or definition.capability_id.lower().replace("-", "_") in text.lower()
            ):
                tests.append(rel)
        return sorted(set(tests))

    def _doc_evidence(self, definition: CapabilityDefinition) -> list[str]:
        docs: list[str] = []
        for path in self._files:
            rel = self._rel(path)
            if not (rel.startswith("docs/") or rel == "README.md"):
                continue
            text = self._safe_text(path)
            if self._text_matches(text, definition.keywords) or definition.name.lower() in text.lower():
                docs.append(rel)
        return sorted(set(docs))

    def _public_interfaces(self, rel_paths: list[str]) -> list[str]:
        interfaces: set[str] = set()
        for rel in rel_paths:
            if not rel.endswith(".py"):
                continue
            path = self.root / rel
            try:
                tree = ast.parse(self._safe_text(path))
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    if not node.name.startswith("_"):
                        interfaces.add(node.name)
        return sorted(interfaces)[:50]

    def _placeholder_hits(self, rel_paths: list[str]) -> list[str]:
        hits: list[str] = []
        regex_patterns = (
            r"raise\s+NotImplementedError",
            r"pass\s*(#\s*(placeholder|stub|todo|not implemented))?$",
            r"placeholder implementation",
            r"stub implementation",
            r"return\s+(None|\{\}|\[\])\s*#\s*(placeholder|stub|not implemented)",
        )
        for rel in rel_paths:
            if not rel.endswith((".py", ".yaml", ".yml", ".json", ".md")):
                continue
            text = self._safe_text(self.root / rel)
            for pattern in regex_patterns:
                if re.search(pattern, text, flags=re.IGNORECASE | re.MULTILINE):
                    hits.append(f"{rel}:{pattern}")
        return sorted(set(hits))[:20]

    def _mock_only(self, source_files: list[str], definition: CapabilityDefinition) -> bool:
        if not source_files:
            return False
        lower_paths = " ".join(source_files).lower()
        lower_name = (definition.name + " " + definition.description).lower()
        if "adapter" not in lower_name and "connector implementations" not in lower_name:
            return False
        mock_paths = [path for path in source_files if "mock" in path.lower() or "fixture" in path.lower()]
        if mock_paths and len(mock_paths) == len(source_files):
            return True
        text = "\n".join(self._safe_text(self.root / path).lower() for path in source_files if path.endswith(".py"))
        return "mock" in text and "production_capable" not in text and "real adapter" not in text

    def _limitations(
        self,
        status: ImplementationStatus,
        placeholders: list[str],
        doc_files: list[str],
        test_files: list[str],
        config_keys: list[str],
        definition: CapabilityDefinition,
    ) -> list[str]:
        limitations: list[str] = []
        if status != ImplementationStatus.IMPLEMENTED:
            limitations.append(f"status is {status.value}; do not treat as complete without remediation")
        if placeholders:
            limitations.append("placeholder or TODO markers were found: " + ", ".join(placeholders[:5]))
        if not test_files:
            limitations.append("no direct test evidence found by deterministic scanner")
        if definition.config_keys and not config_keys:
            limitations.append("expected configuration keys were not found")
        if doc_files and status in {ImplementationStatus.DOCUMENTED_ONLY, ImplementationStatus.PARTIAL}:
            limitations.append("documentation exists but implementation evidence is incomplete")
        return limitations

    def _risks(self, status: ImplementationStatus, definition: CapabilityDefinition) -> list[str]:
        risks: list[str] = []
        if status in {
            ImplementationStatus.DOCUMENTED_ONLY,
            ImplementationStatus.NOT_FOUND,
            ImplementationStatus.STUB,
            ImplementationStatus.MOCK_ONLY,
        }:
            risks.append("operational readiness must not rely on this capability")
        if "Execution" in definition.layer or "Safety" in definition.layer:
            risks.append("safety-critical path; require Action Mask, Safety Gate, formal verification, governance, audit, and rollback evidence")
        if "ML" in definition.layer or "RL" in definition.layer or "MARL" in definition.layer:
            risks.append("model output cannot directly execute and must remain governed shadow/recommendation-only")
        return risks

    def _next_action(self, status: ImplementationStatus) -> str:
        if status == ImplementationStatus.IMPLEMENTED:
            return "keep covered by regression, assurance, and long-horizon validation"
        if status == ImplementationStatus.PARTIAL:
            return "complete missing integration, persistence, docs, tests, or runtime verification"
        if status == ImplementationStatus.MOCK_ONLY:
            return "label mock-only in deployment docs and add pilot/production adapter evidence before use"
        if status == ImplementationStatus.TEST_ONLY:
            return "move from fixtures into runtime implementation or remove completion claim"
        if status == ImplementationStatus.DOCUMENTED_ONLY:
            return "either implement with evidence or remove/soften documentation claim"
        if status == ImplementationStatus.STUB:
            return "replace placeholder logic with working implementation and tests"
        if status == ImplementationStatus.BROKEN:
            return "repair failing runtime/tests before expanding deployment"
        return "define, implement, test, configure, and document before claiming availability"

    def _api_routes(self) -> list[dict[str, Any]]:
        if self._api_routes_cache is not None:
            return self._api_routes_cache
        routes: list[dict[str, Any]] = []
        route_pattern = re.compile(r"@app\.(get|post|put|delete|patch|websocket)\(\s*[\"']([^\"']+)[\"']")
        for path in [self.root / "mirage" / "api" / "server.py", self.root / "mirage" / "api_server.py"]:
            if not path.exists():
                continue
            for line_number, line in enumerate(self._safe_text(path).splitlines(), start=1):
                match = route_pattern.search(line)
                if match:
                    routes.append(
                        {
                            "method": match.group(1).upper(),
                            "route": match.group(2),
                            "source_file": self._rel(path),
                            "line": line_number,
                        }
                    )
        self._api_routes_cache = sorted(routes, key=lambda item: (item["route"], item["method"]))
        return self._api_routes_cache

    def _cli_commands(self) -> list[dict[str, Any]]:
        if self._cli_commands_cache is not None:
            return self._cli_commands_cache
        commands: set[tuple[str, str]] = set()
        main_path = self.root / "mirage" / "__main__.py"
        if main_path.exists():
            text = self._safe_text(main_path)
            for match in re.finditer(r"command (?:==|in) \{?([^:\n]+)", text):
                raw = match.group(1)
                for token in re.findall(r"[\"']([a-zA-Z0-9_-]+)[\"']", raw):
                    commands.add((f"python -m mirage {token}", "mirage/__main__.py"))
        for path in sorted((self.root / "mirage").rglob("*cli.py")):
            rel = self._rel(path)
            text = self._safe_text(path)
            prog_match = re.search(r"ArgumentParser\(prog=[\"']([^\"']+)[\"']", text)
            base = prog_match.group(1) if prog_match else f"python -m mirage {path.stem.replace('_cli', '')}"
            for match in re.finditer(r"add_parser\([\"']([^\"']+)[\"']", text):
                commands.add((f"{base} {match.group(1)}", rel))
        self._cli_commands_cache = [
            {"command": command, "source_file": source}
            for command, source in sorted(commands)
        ]
        return self._cli_commands_cache

    def _schema_catalog(self) -> list[dict[str, Any]]:
        schemas: list[dict[str, Any]] = []
        for path in sorted((self.root / "mirage").rglob("*.py"), key=self._rel):
            text = self._safe_text(path)
            if "BaseModel" not in text and "Enum" not in text:
                continue
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                bases = [self._expr_name(base) for base in node.bases]
                if any(base.endswith("BaseModel") or base.endswith("Enum") or base in {"StrictModel", "StrictMARLModel"} for base in bases):
                    schemas.append(
                        {
                            "name": node.name,
                            "source_file": self._rel(path),
                            "bases": bases,
                        }
                    )
        return schemas

    def _configuration_catalog(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for key, value in sorted(_flatten(self.config).items()):
            public_value = value
            if _sensitive_key(key):
                public_value = "<redacted>"
            items.append(
                {
                    "key": key,
                    "type": type(value).__name__,
                    "default_or_configured_value": public_value,
                }
            )
        return items

    def _security_controls(self) -> list[dict[str, Any]]:
        flat = _flatten(self.config)
        controls = []
        for key, expected in SAFETY_DEFAULTS.items():
            candidate_keys = [
                key,
                f"production.{key}",
                f"general.{key}",
                f"marl.{key}",
            ]
            observed = None
            evidence_key = ""
            for candidate in candidate_keys:
                if candidate in flat:
                    observed = flat[candidate]
                    evidence_key = candidate
                    break
            controls.append(
                {
                    "control": key,
                    "expected": expected,
                    "observed": observed,
                    "configuration_key": evidence_key,
                    "satisfied": observed == expected if observed is not None else False,
                }
            )
        return controls

    def _model_policy_catalog(self) -> list[dict[str, Any]]:
        roots = [self.root / "models", self.root / "configs"]
        artifacts: list[dict[str, Any]] = []
        for root in roots:
            if not root.exists():
                continue
            for path in sorted(root.rglob("*"), key=self._rel):
                if path.is_file():
                    artifacts.append(
                        {
                            "path": self._rel(path),
                            "sha256": _sha256_file(path),
                            "size_bytes": path.stat().st_size,
                        }
                    )
        return artifacts

    def _deployment_catalog(self) -> list[dict[str, Any]]:
        if self._deployment_catalog_cache is not None:
            return self._deployment_catalog_cache
        resources: list[dict[str, Any]] = []
        deploy_root = self.root / "deploy"
        if not deploy_root.exists():
            self._deployment_catalog_cache = resources
            return resources
        for path in sorted(deploy_root.rglob("*"), key=self._rel):
            if path.is_file():
                text = self._safe_text(path)
                resources.append(
                    {
                        "path": self._rel(path),
                        "size_bytes": path.stat().st_size,
                        "sha256": _sha256_file(path),
                        "summary": _summarize_deployment_text(text),
                    }
                )
        self._deployment_catalog_cache = resources
        return self._deployment_catalog_cache

    def _test_inventory(self) -> list[dict[str, Any]]:
        tests: list[dict[str, Any]] = []
        for path in sorted([p for p in self._files if self._rel(p).startswith("tests/") or self._rel(p).startswith("test_")], key=self._rel):
            text = self._safe_text(path)
            tests.append(
                {
                    "path": self._rel(path),
                    "test_function_count": len(re.findall(r"def test_", text)),
                    "skipped_markers": len(re.findall(r"pytest\.mark\.skip|@pytest\.mark\.skip|skip\(", text)),
                    "xfail_markers": len(re.findall(r"pytest\.mark\.xfail|@pytest\.mark\.xfail", text)),
                }
            )
        return tests

    def _known_gaps(self, capabilities: list[CapabilityInventoryItem]) -> list[dict[str, Any]]:
        gaps = []
        for capability in sorted(capabilities, key=lambda item: (STATUS_RANK[item.implementation_status], item.capability_id), reverse=True):
            if capability.implementation_status == ImplementationStatus.IMPLEMENTED:
                continue
            gaps.append(
                {
                    "capability_id": capability.capability_id,
                    "capability_name": capability.capability_name,
                    "status": capability.implementation_status.value,
                    "limitations": capability.limitations,
                    "recommended_next_action": capability.recommended_next_action,
                }
            )
        return gaps

    def _diagram(self, capabilities: list[CapabilityInventoryItem]) -> str:
        status_by_layer: dict[str, ImplementationStatus] = {}
        for item in capabilities:
            current = status_by_layer.get(item.architecture_layer, ImplementationStatus.IMPLEMENTED)
            if STATUS_RANK[item.implementation_status] > STATUS_RANK[current]:
                status_by_layer[item.architecture_layer] = item.implementation_status
        layers = [
            ("Telemetry Sources", "Connectors"),
            ("Read-only Connectors", "Connectors"),
            ("Normalization, Validation, Deduplication, Ordering", "Ingestion"),
            ("Durable Event Transport", "Streaming"),
            ("CASM and Entity Resolution", "CASM"),
            ("Real-time Digital Twin", "Digital Twin"),
            ("Entity Timelines and Contextual Detection", "Detection"),
            ("Belief Engine", "Detection"),
            ("Local Attack Graph and Path Risk", "Attack analysis"),
            ("Candidate Defense Actions", "Action recommendation"),
            ("Heuristic / Robust / GNN / BC / Offline RL / MARL Recommendations", "ML inference"),
            ("Action Masks", "Safety"),
            ("Safety Gate", "Safety"),
            ("Formal Verification", "Formal safety"),
            ("Governance and Approval", "Governance"),
            ("Shadow / Controlled Low-risk Execution", "Execution"),
            ("Canary, Monitoring, TTL, Rollback", "Execution"),
            ("Audit, SOC Integration, Assurance, and Readiness", "Continuous assurance"),
        ]
        lines = []
        for label, layer in layers:
            status = status_by_layer.get(layer, ImplementationStatus.NOT_FOUND)
            lines.append(f"{label} [{status.value}]")
            if label != layers[-1][0]:
                lines.append("        ->")
        return "\n".join(lines)

    def _safety_defaults(self) -> dict[str, Any]:
        flat = _flatten(self.config)
        observed = dict(SAFETY_DEFAULTS)
        observed["operating_mode"] = flat.get("general.operating_mode", observed["operating_mode"])
        observed["deployment_level"] = flat.get("production.deployment_level", observed["deployment_level"])
        observed["production_execution_enabled"] = flat.get(
            "production.production_execution_enabled",
            observed["production_execution_enabled"],
        )
        observed["high_risk_automation_enabled"] = flat.get(
            "production.high_risk_automation_enabled",
            observed["high_risk_automation_enabled"],
        )
        observed["red_agent_cyber_range_only"] = flat.get(
            "marl.cyber_range_only",
            observed["red_agent_cyber_range_only"],
        )
        observed["red_agent_external_network"] = flat.get(
            "marl.red_agent_external_network",
            observed["red_agent_external_network"],
        )
        observed["real_exploitation_enabled"] = flat.get(
            "marl.real_exploitation_enabled",
            observed["real_exploitation_enabled"],
        )
        observed["audit_required"] = bool(flat.get("production.audit.fail_closed_for_execution", True))
        observed["rollback_required"] = bool(flat.get("production.rollback_configured_actions", []))
        return observed

    def _config_key_exists(self, dotted_key: str) -> bool:
        flat = _flatten(self.config)
        if dotted_key in flat:
            return True
        prefix = dotted_key + "."
        return any(key.startswith(prefix) for key in flat)

    def _safe_text(self, path: Path) -> str:
        if path in self._text_cache:
            return self._text_cache[path]
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            text = ""
        self._text_cache[path] = text
        return text

    def _should_scan_file(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if any(part in EXCLUDED_PARTS for part in path.parts):
            return False
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"Dockerfile"}:
            return False
        try:
            if path.stat().st_size > 2_000_000:
                return False
        except OSError:
            return False
        return True

    def _rel(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def _path_matches(self, rel_path: str, markers: Iterable[str]) -> bool:
        normalized = rel_path.lower()
        return any(marker.lower().replace("\\", "/") in normalized for marker in markers)

    def _text_matches(self, text: str, keywords: Iterable[str]) -> bool:
        lowered = text.lower()
        return any(keyword.lower() in lowered for keyword in keywords)

    def _matches_any(self, text: str, keywords: Iterable[str]) -> bool:
        lowered = text.lower()
        return any(keyword.lower().replace("\\", "/") in lowered for keyword in keywords)

    def _expr_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._expr_name(node.value)}.{node.attr}"
        return ast.unparse(node) if hasattr(ast, "unparse") else type(node).__name__


def write_inventory_artifacts(root: Path | None = None) -> SystemInventory:
    """Convenience wrapper used by CLI/tests."""
    scanner = InventoryScanner(root=root)
    return scanner.write_artifacts()


def write_inventory_files(inventory: SystemInventory, root: Path) -> None:
    """Write required inventory JSON, YAML, and catalog markdown files."""
    artifacts_dir = root / "artifacts" / "inventory"
    docs_dir = root / "docs" / "inventory"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    docs_dir.mkdir(parents=True, exist_ok=True)
    data = inventory.model_dump(mode="json")
    (artifacts_dir / "system_inventory.json").write_text(
        json.dumps(data, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (artifacts_dir / "system_inventory.yaml").write_text(
        to_yaml(data),
        encoding="utf-8",
    )

    documents = {
        "IMPLEMENTED_SYSTEM_INVENTORY.md": _inventory_overview(inventory),
        "IMPLEMENTATION_STATUS_MATRIX.md": _status_matrix(inventory),
        "SERVICE_AND_MODULE_CATALOG.md": _list_catalog("Service And Module Catalog", _service_catalog(inventory)),
        "API_CATALOG.md": _list_catalog("API Catalog", inventory.api_routes),
        "CLI_CATALOG.md": _list_catalog("CLI Catalog", inventory.cli_commands),
        "SCHEMA_CATALOG.md": _list_catalog("Schema Catalog", inventory.schemas),
        "CONFIGURATION_CATALOG.md": _list_catalog("Configuration Catalog", inventory.configuration),
        "SECURITY_CONTROL_CATALOG.md": _list_catalog("Security Control Catalog", inventory.security_controls),
        "MODEL_AND_POLICY_CATALOG.md": _list_catalog("Model And Policy Catalog", inventory.model_and_policy_artifacts),
        "TEST_COVERAGE_INVENTORY.md": _list_catalog("Test Coverage Inventory", inventory.test_inventory),
        "DEPLOYMENT_INVENTORY.md": _list_catalog("Deployment Inventory", inventory.deployment_resources),
        "KNOWN_GAPS_AND_TECHNICAL_DEBT.md": _list_catalog("Known Gaps And Technical Debt", inventory.known_gaps),
    }
    for filename, content in documents.items():
        (docs_dir / filename).write_text(content, encoding="utf-8")


def write_milestone11_docs(inventory: SystemInventory, root: Path) -> None:
    """Write required Milestone 11 documentation pages from the scan result."""
    docs_dir = root / "docs" / "milestone-11"
    docs_dir.mkdir(parents=True, exist_ok=True)
    common = _milestone_common(inventory)
    pages = {
        "OVERVIEW.md": common,
        "VERIFIED_IMPLEMENTATION_SUMMARY.md": _verified_summary(inventory),
        "MULTI_SITE_ARCHITECTURE.md": _milestone_page("Multi-Site Architecture", inventory, "Federation remains local-first. Sites retain local Action Masks, Safety Gates, formal verification, governance, rollback, and audit controls. Cross-site data is denied by default and only pseudonymized summary classes are eligible."),
        "FEDERATION_POLICY.md": _milestone_page("Federation Policy", inventory, "Policy validation denies raw credentials, secrets, raw event payloads, cross-tenant transfers, unencrypted endpoints, and residency-policy violations."),
        "DATA_RESIDENCY.md": _milestone_page("Data Residency", inventory, "Residency routes are allowlisted. A missing route is a denial, not an implicit approval."),
        "CONTINUOUS_ASSURANCE.md": _milestone_page("Continuous Assurance", inventory, "Assurance bundles hash inventory, configuration, audit-chain, backup, model-card, policy-card, and Cyber Range isolation evidence."),
        "LONG_HORIZON_VALIDATION.md": _milestone_page("Long-Horizon Validation", inventory, "CI uses bounded synthetic soak and chaos profiles. The reports are validation evidence, not enterprise-scale claims."),
        "SLO_AND_ERROR_BUDGET.md": _milestone_page("SLO And Error Budget", inventory, "SLO reports calculate compliance and error-budget exhaustion. Exhausted safety budgets block release and can force more restrictive operation."),
        "CAPACITY_PLANNING.md": _milestone_page("Capacity Planning", inventory, "Capacity reports separate measured values from projections and include limitations for synthetic profiles."),
        "OPERATIONAL_MATURITY.md": _milestone_page("Operational Maturity", inventory, "Maturity scoring is evidence-backed and penalizes missing, documented-only, stub, broken, or mock-only capabilities."),
        "READINESS_DECISION.md": _milestone_page("Readiness Decision", inventory, "The readiness board cannot raise deployment level automatically. Missing critical assurance evidence returns MIRAGE to Shadow Mode or insufficient-evidence status."),
        "KNOWN_LIMITATIONS.md": _list_catalog("Known Limitations", inventory.known_gaps),
    }
    for filename, content in pages.items():
        (docs_dir / filename).write_text(content, encoding="utf-8")


def _inventory_overview(inventory: SystemInventory) -> str:
    lines = [
        "# Implemented System Inventory",
        "",
        "This file is generated from repository evidence. A capability is not marked implemented merely because it is documented.",
        "",
        "## Totals",
        "",
        f"- Capabilities: {inventory.totals.capability_count}",
        f"- Source files: {inventory.totals.source_file_count}",
        f"- Test files: {inventory.totals.test_file_count}",
        f"- API routes: {inventory.totals.api_route_count}",
        f"- CLI commands: {inventory.totals.cli_command_count}",
        "",
        "## Status Counts",
        "",
    ]
    for status, count in inventory.totals.by_status.items():
        lines.append(f"- {status}: {count}")
    lines.extend(["", "## Verified System Summary Diagram", "", "```text", inventory.system_summary_diagram, "```", ""])
    lines.append("## Capabilities")
    lines.append("")
    for item in inventory.capabilities:
        lines.append(f"### {item.capability_id} - {item.capability_name}")
        lines.append("")
        lines.append(f"- Status: {item.implementation_status.value}")
        lines.append(f"- Milestone: {item.milestone_origin}")
        lines.append(f"- Layer: {item.architecture_layer}")
        lines.append(f"- Evidence files: {', '.join(item.source_files[:8]) or 'none'}")
        lines.append(f"- Tests: {', '.join(item.tests[:8]) or 'none'}")
        lines.append(f"- Runtime verification: {item.runtime_verification_result}")
        if item.limitations:
            lines.append(f"- Limitations: {'; '.join(item.limitations[:4])}")
        lines.append("")
    return "\n".join(lines)


def _status_matrix(inventory: SystemInventory) -> str:
    lines = [
        "# Implementation Status Matrix",
        "",
        "| Capability ID | Name | Status | Source Evidence | Test Evidence | Next Action |",
        "| --- | --- | --- | ---: | ---: | --- |",
    ]
    for item in inventory.capabilities:
        lines.append(
            "| {id} | {name} | {status} | {sources} | {tests} | {action} |".format(
                id=item.capability_id,
                name=_escape_md(item.capability_name),
                status=item.implementation_status.value,
                sources=len(item.source_files),
                tests=len(item.tests),
                action=_escape_md(item.recommended_next_action),
            )
        )
    return "\n".join(lines) + "\n"


def _service_catalog(inventory: SystemInventory) -> list[dict[str, Any]]:
    services = []
    for item in inventory.capabilities:
        for source in item.source_files[:10]:
            services.append(
                {
                    "capability_id": item.capability_id,
                    "status": item.implementation_status.value,
                    "source_file": source,
                    "public_interfaces": item.public_interfaces[:10],
                }
            )
    return services


def _list_catalog(title: str, items: list[dict[str, Any]]) -> str:
    lines = [f"# {title}", "", f"Items: {len(items)}", ""]
    if not items:
        lines.append("No evidence found.")
        lines.append("")
        return "\n".join(lines)
    for index, item in enumerate(items, start=1):
        lines.append(f"## {index}. {item.get('capability_id') or item.get('path') or item.get('route') or item.get('command') or item.get('key') or item.get('name') or item.get('control')}")
        lines.append("")
        for key, value in item.items():
            lines.append(f"- {key}: {_format_value(value)}")
        lines.append("")
    return "\n".join(lines)


def _verified_summary(inventory: SystemInventory) -> str:
    status_groups: dict[str, list[CapabilityInventoryItem]] = {}
    for item in inventory.capabilities:
        status_groups.setdefault(item.implementation_status.value, []).append(item)
    lines = [
        "# Verified Implementation Summary",
        "",
        "## 1. Project purpose",
        "",
        "MIRAGE is a governed cyber-defense research and pilot platform for telemetry ingestion, Digital Twin modeling, detection, attack-path analysis, recommendations, deception orchestration, formal safety, governance, and controlled low-risk operations.",
        "",
        "## 2. Current system boundaries",
        "",
        "Default operation remains Shadow Mode. Production execution and high-risk automation remain disabled. Red-agent and MARL components remain Cyber Range only.",
        "",
        "## 3. Complete architecture",
        "",
        "```text",
        inventory.system_summary_diagram,
        "```",
        "",
        "## 4-10. Capability status groups",
        "",
    ]
    for status in ImplementationStatus:
        group = status_groups.get(status.value, [])
        lines.append(f"### {status.value}")
        lines.append("")
        if not group:
            lines.append("No capabilities in this status.")
        for item in group:
            lines.append(f"- {item.capability_id}: {item.capability_name}")
        lines.append("")
    lines.extend(
        [
            "## 11-21. Data, decision, execution, safety, model, API, CLI, configuration, storage, deployment, and security inventory",
            "",
            "See the generated catalog files in `docs/inventory/` and `artifacts/inventory/system_inventory.json`.",
            "",
            "## 22. Tests and current pass/fail status",
            "",
            "The inventory scanner collects test files and skipped/xfail markers. It does not execute the full test suite by itself.",
            "",
            "## 23. Performance results",
            "",
            "Performance measurements are produced by Milestone 11 validation, SLO, and capacity reports. Missing measurements must not be claimed as enterprise-scale evidence.",
            "",
            "## 24-26. Operational limitations, technical debt, and remediation order",
            "",
        ]
    )
    for gap in inventory.known_gaps[:40]:
        lines.append(f"- {gap['capability_id']} ({gap['status']}): {gap['recommended_next_action']}")
    lines.append("")
    return "\n".join(lines)


def _milestone_common(inventory: SystemInventory) -> str:
    return "\n".join(
        [
            "# Milestone 11 Overview",
            "",
            "Milestone 11 adds verified inventory, continuous assurance, multi-site federation, long-horizon validation, SLO/error-budget reporting, capacity planning, maturity scoring, and readiness decisions.",
            "",
            "It does not enable unrestricted production automation, offensive capability, automatic model promotion, or direct RL/MARL execution.",
            "",
            "## Safety defaults",
            "",
            "```json",
            json.dumps(inventory.safety_defaults, indent=2, sort_keys=True),
            "```",
            "",
            "## Verified diagram",
            "",
            "```text",
            inventory.system_summary_diagram,
            "```",
            "",
            "## Current evidence summary",
            "",
            json.dumps(inventory.totals.model_dump(mode="json"), indent=2, sort_keys=True),
            "",
        ]
    )


def _milestone_page(title: str, inventory: SystemInventory, body: str) -> str:
    return "\n".join(
        [
            f"# {title}",
            "",
            body,
            "",
            "## Evidence base",
            "",
            "This page is generated from the Milestone 11 inventory. See `docs/inventory/` for file, API, CLI, schema, configuration, security, deployment, model, and test evidence.",
            "",
            "## Relevant gaps",
            "",
            *[
                f"- {gap['capability_id']} ({gap['status']}): {gap['recommended_next_action']}"
                for gap in inventory.known_gaps[:20]
            ],
            "",
        ]
    )


def to_yaml(value: Any, indent: int = 0) -> str:
    """Render a deterministic YAML subset without adding a PyYAML dependency."""
    prefix = " " * indent
    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = []
        for key in sorted(value):
            rendered = to_yaml(value[key], indent + 2)
            if "\n" in rendered:
                lines.append(f"{prefix}{key}:")
                lines.append(rendered)
            else:
                lines.append(f"{prefix}{key}: {rendered}")
        return "\n".join(lines)
    if isinstance(value, list):
        if not value:
            return "[]"
        lines = []
        for item in value:
            rendered = to_yaml(item, indent + 2)
            if "\n" in rendered:
                lines.append(f"{prefix}-")
                lines.append(rendered)
            else:
                lines.append(f"{prefix}- {rendered}")
        return "\n".join(lines)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    text = str(value)
    if text == "" or any(ch in text for ch in ":#[]{}\n") or text.strip() != text:
        return json.dumps(text)
    return text


def _flatten(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, dict):
        items: dict[str, Any] = {}
        for key, item in value.items():
            child_key = f"{prefix}.{key}" if prefix else str(key)
            items.update(_flatten(item, child_key))
        return items
    return {prefix: value}


def _sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(marker in lowered for marker in ("password", "secret", "token", "credential", "api_key", "private_key"))


def _sha256_file(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return ""


def _summarize_deployment_text(text: str) -> str:
    markers = []
    for marker in (
        "runAsNonRoot",
        "readOnlyRootFilesystem",
        "NetworkPolicy",
        "HorizontalPodAutoscaler",
        "PodDisruptionBudget",
        "fail",
        "production + execution enabled",
    ):
        if marker in text:
            markers.append(marker)
    return ", ".join(markers)


def _escape_md(value: str) -> str:
    return value.replace("|", "\\|")


def _format_value(value: Any) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True)
    else:
        text = str(value)
    if len(text) > 500:
        text = text[:497] + "..."
    return text
