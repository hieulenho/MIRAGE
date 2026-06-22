from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.config import DEFAULT_CONFIG, load_config
from mirage.production.backup import BackupManager
from mirage.production.config import validate_production_config
from mirage.production.deployment import LimitedDeploymentController
from mirage.production.events import InMemoryEventBus, SQLiteEventBus
from mirage.production.execution import (
    NarrowPilotAdapter,
    PersistentExecutionProcessor,
)
from mirage.production.ha import InMemoryLeaseStore, LeaderElector
from mirage.production.health import DependencyChecker, build_health_report
from mirage.production.migrations import MigrationLockError, MigrationManager
from mirage.production.observability import MetricsRegistry, StructuredLogger
from mirage.production.schema import (
    ApprovalRecord,
    DeploymentLevel,
    EnvironmentProfile,
    ScopeContext,
    UserIdentity,
)
from mirage.production.secrets import redact, validate_no_plaintext_secrets
from mirage.production.security import (
    RBACAuthorizer,
    ServiceTokenIssuer,
    validate_approval,
)
from mirage.production.soc import MockSOCAdapter, SOCIncident
from mirage.production.storage import (
    InMemoryProductionRepository,
    SQLiteProductionRepository,
    VersionConflictError,
)


def test_default_config_keeps_milestone10_shadow_boundaries() -> None:
    config = load_config()
    report = validate_production_config(config)

    assert report.valid
    assert config["production"]["operating_mode"] == "shadow"
    assert config["production"]["production_execution_enabled"] is False
    assert config["production"]["high_risk_automation_enabled"] is False
    assert config["production"]["formal_verification_required"] is True
    assert "isolate_host" in config["production"]["prohibited_action_types"]


def test_production_profile_rejects_unsafe_startup(tmp_path: Path) -> None:
    unsafe = deepcopy(DEFAULT_CONFIG)
    unsafe["production"]["profile"] = "production"
    path = tmp_path / "unsafe.json"
    path.write_text(json.dumps(unsafe), encoding="utf-8")

    with pytest.raises(ValueError, match="production safety validation failed"):
        load_config(path)

    report = validate_production_config(unsafe)
    codes = {finding.code for finding in report.findings}
    assert {"auth_required", "tls_required", "storage_backend", "broker_unavailable"}.issubset(codes)


def test_strict_production_profile_can_be_validated_when_dependencies_are_declared() -> None:
    config = deepcopy(DEFAULT_CONFIG)
    production = config["production"]
    production["profile"] = "production"
    production["auth"]["enabled"] = True
    production["auth"]["service_identity_required"] = True
    production["tls"]["enabled"] = True
    production["tls"]["mtls_required"] = True
    production["storage"]["backend"] = "postgres"
    production["storage"]["postgres_dsn"] = "postgresql://mirage.example.invalid/mirage"
    production["event_transport"]["backend"] = "kafka_compatible"
    production["event_transport"]["broker_url"] = "redpanda.example.invalid:9092"
    production["protected_assets"] = ["prod-db-01"]

    assert validate_production_config(config).valid


def test_rbac_denies_by_default_and_prevents_self_approval() -> None:
    scope = ScopeContext(tenant_id="tenant-a", environment=EnvironmentProfile.SHADOW)
    authorizer = RBACAuthorizer()
    analyst = UserIdentity(
        subject="alice",
        roles=["soc_analyst"],
        tenant_id="tenant-a",
        environment=EnvironmentProfile.SHADOW,
    )
    other_tenant = UserIdentity(
        subject="mallory",
        roles=["soc_analyst"],
        tenant_id="tenant-b",
        environment=EnvironmentProfile.SHADOW,
    )

    assert authorizer.authorize(analyst, "soc:case:create", scope=scope)
    assert not authorizer.authorize(analyst, "deployment_level:set", scope=scope)
    assert not authorizer.authorize(other_tenant, "soc:case:create", scope=scope)

    approval = ApprovalRecord(
        approval_id="app-1",
        request_id="req-1",
        approver_subject="alice",
        approver_role="incident_commander",
        requester_subject="alice",
    )
    with pytest.raises(PermissionError, match="cannot approve"):
        validate_approval(
            approval,
            requester=analyst,
            required_roles={"incident_commander"},
        )


def test_service_identity_tokens_validate_audience_scope_and_revocation() -> None:
    issuer = ServiceTokenIssuer("test-signing-key")
    token = issuer.issue(
        "connector-service",
        audience="mirage-api",
        scopes=["events:publish"],
    )

    assert issuer.verify(token, audience="mirage-api", required_scope="events:publish")["sub"] == "connector-service"
    with pytest.raises(PermissionError, match="audience"):
        issuer.verify(token, audience="other")
    with pytest.raises(PermissionError, match="revoked"):
        issuer.verify(token, audience="mirage-api", revoked={token})


def test_repository_crud_tenant_isolation_and_optimistic_concurrency(tmp_path: Path) -> None:
    repo = SQLiteProductionRepository(tmp_path / "repo.db")
    tenant_a = ScopeContext(tenant_id="tenant-a", environment=EnvironmentProfile.SHADOW)
    tenant_b = ScopeContext(tenant_id="tenant-b", environment=EnvironmentProfile.SHADOW)

    first = repo.upsert("events", "event-1", {"count": 1}, scope=tenant_a)
    repo.upsert("events", "event-1", {"count": 99}, scope=tenant_b)
    second = repo.upsert(
        "events",
        "event-1",
        {"count": 2},
        scope=tenant_a,
        expected_version=first.version,
    )

    assert repo.get("events", "event-1", scope=tenant_a).payload["count"] == 2
    assert repo.get("events", "event-1", scope=tenant_b).payload["count"] == 99
    assert len(repo.list_records("events", scope=tenant_a)) == 1
    with pytest.raises(VersionConflictError):
        repo.upsert(
            "events",
            "event-1",
            {"count": 3},
            scope=tenant_a,
            expected_version=first.version,
        )
    assert second.version == 2


def test_backup_verify_and_restore_rehearsal(tmp_path: Path) -> None:
    scope = ScopeContext()
    source = InMemoryProductionRepository()
    source.upsert("twin", "snapshot-1", {"assets": 3}, scope=scope)
    manager = BackupManager(source, tmp_path / "backups")

    manifest = manager.create(backup_id="b1")
    assert manifest.record_count == 1
    assert manager.verify("b1")["valid"]
    assert manager.restore_validate("b1")["restorable"]

    target = InMemoryProductionRepository()
    restore = BackupManager(target, tmp_path / "backups")
    assert restore.restore_run("b1", dry_run=False)["restored"]
    assert target.get("twin", "snapshot-1", scope=scope).payload["assets"] == 3


def test_migrations_support_dry_run_lock_and_rollback(tmp_path: Path) -> None:
    manager = MigrationManager(tmp_path / "mirage.db")
    dry = manager.migrate(dry_run=True)
    assert dry.applied_versions == [1]

    assert manager.migrate(owner="worker-a").target_version == 1
    assert manager.status()["up_to_date"] is True
    assert manager.acquire_lock("worker-a")
    with pytest.raises(MigrationLockError):
        manager.migrate(owner="worker-b")
    manager.release_lock("worker-a")

    rollback = manager.rollback_last()
    assert rollback.target_version == 0


def test_event_bus_deduplicates_redelivers_dead_letters_and_rejects_schema() -> None:
    bus = InMemoryEventBus(max_retries=2, lease_seconds=0, max_queue_depth=10)
    scope = ScopeContext(tenant_id="tenant-a")

    first = bus.publish("security.events.normalized", {"host": "a"}, "k1", scope=scope)
    duplicate = bus.publish("security.events.normalized", {"host": "a"}, "k1", scope=scope)
    assert first.message_id == duplicate.message_id

    polled = bus.poll("security.events.normalized", limit=1)
    assert polled[0].attempts == 1
    redelivered = bus.poll("security.events.normalized", limit=1)
    assert redelivered[0].message_id == first.message_id
    assert redelivered[0].attempts == 2
    bus.reject(redelivered[0], "consumer failed")
    assert bus.dead_letters()[0].message_id == first.message_id

    with pytest.raises(ValueError, match="schema"):
        bus.publish("security.events.normalized", {}, "k2", schema_version="v0")


def test_sqlite_event_bus_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "events.db"
    bus = SQLiteEventBus(path)
    message = bus.publish("analysis.completed", {"analysis_id": "a1"}, "analysis:a1")

    restarted = SQLiteEventBus(path)
    assert restarted.poll("analysis.completed", limit=1)[0].message_id == message.message_id


def test_leader_election_transfers_after_lease_expiry() -> None:
    store = InMemoryLeaseStore()
    now = datetime.now(timezone.utc)
    leader_a = LeaderElector(store, service_name="ttl-expiry", instance_id="a")
    leader_b = LeaderElector(store, service_name="ttl-expiry", instance_id="b")

    assert leader_a.campaign(ttl_seconds=1, now=now)
    assert not leader_b.campaign(ttl_seconds=1, now=now)
    assert leader_b.campaign(ttl_seconds=1, now=now + timedelta(seconds=2))


def test_persistent_execution_is_idempotent_and_level_gated() -> None:
    repo = InMemoryProductionRepository()
    leases = InMemoryLeaseStore()
    adapter = NarrowPilotAdapter()
    processor = PersistentExecutionProcessor(repo, leases, adapter)
    scope = ScopeContext()

    shadow = processor.process(
        "exec-shadow",
        "create_soc_ticket",
        {"target_allowlisted": True},
        scope=scope,
        idempotency_key="idem-shadow",
        deployment_level=DeploymentLevel.SHADOW_ONLY,
        action_tier=0,
    )
    assert shadow.state == "shadow_only"
    assert adapter.execute_calls == []

    first = processor.process(
        "exec-1",
        "create_soc_ticket",
        {"target_allowlisted": True},
        scope=scope,
        idempotency_key="idem-1",
        deployment_level=DeploymentLevel.LOW_RISK_PILOT,
        action_tier=1,
    )
    second = processor.process(
        "exec-1",
        "create_soc_ticket",
        {"target_allowlisted": True},
        scope=scope,
        idempotency_key="idem-1",
        deployment_level=DeploymentLevel.LOW_RISK_PILOT,
        action_tier=1,
    )
    assert first.state == "succeeded"
    assert second.duplicate is True
    assert len(adapter.execute_calls) == 1


def test_deployment_controller_requires_authorization_and_reduces_on_drift() -> None:
    repo = InMemoryProductionRepository()
    scope = ScopeContext()
    controller = LimitedDeploymentController(repo, scope=scope)
    reviewer = UserIdentity(
        subject="reviewer",
        roles=["governance_reviewer"],
        environment=EnvironmentProfile.SHADOW,
    )
    viewer = UserIdentity(subject="viewer", roles=["viewer"], environment=EnvironmentProfile.SHADOW)

    with pytest.raises(PermissionError):
        controller.set_level(
            DeploymentLevel.LOW_RISK_PILOT,
            actor=viewer,
            reason="not authorized",
        )
    with pytest.raises(PermissionError, match="models cannot raise"):
        controller.set_level(
            DeploymentLevel.LOW_RISK_PILOT,
            actor=reviewer,
            reason="model request",
            actor_kind="model",
        )
    assert controller.set_level(
        DeploymentLevel.LOW_RISK_PILOT,
        actor=reviewer,
        reason="approved pilot",
    ).level == DeploymentLevel.LOW_RISK_PILOT
    assert controller.apply_runtime_signal(critical_drift=True).level == DeploymentLevel.SHADOW_ONLY


def test_secret_redaction_structured_logs_and_soc_payload_minimize_sensitive_data() -> None:
    payload = {
        "api_token": "secret-value",
        "nested": {"password": "hidden", "safe": "visible"},
    }
    assert redact(payload)["api_token"] == "<redacted>"
    assert validate_no_plaintext_secrets({"connector": {"token": "${TOKEN}"}}) == []

    logger = StructuredLogger(service="api", environment=EnvironmentProfile.SHADOW)
    line = logger.event("info", "created case", extra=payload)
    assert "secret-value" not in line
    assert "visible" in line

    soc = MockSOCAdapter()
    case = soc.create_case(
        SOCIncident(
            incident_id="inc-1",
            summary="Suspicious path",
            affected_entities=["host-a"],
            evidence_refs=["ev-1"],
            twin_quality={"api_key": "secret-value"},
        )
    )
    assert "secret-value" not in json.dumps(case)


def test_health_metrics_and_api_endpoints_are_public_safe() -> None:
    config = load_config()
    report = build_health_report(
        config,
        dependencies=DependencyChecker({"database": lambda: True, "audit_storage": lambda: False}),
    )
    assert report.live is True
    assert report.ready is False

    metrics = MetricsRegistry()
    metrics.increment("mirage_events_received_total")
    metrics.gauge("mirage_broker_lag", 2)
    rendered = metrics.render_prometheus()
    assert "mirage_events_received_total" in rendered
    assert "mirage_broker_lag" in rendered

    client = TestClient(create_app())
    assert client.get("/health/live").status_code == 200
    assert client.get("/health/security").json()["valid"] is True
    metrics_response = client.get("/metrics")
    assert metrics_response.status_code == 200
    assert "text/plain" in metrics_response.headers["content-type"]


def test_deployment_manifests_include_required_hardening_controls() -> None:
    kube = Path("deploy/kubernetes/mirage-production.yaml").read_text(encoding="utf-8")
    network = Path("deploy/kubernetes/network-policies.yaml").read_text(encoding="utf-8")
    helm_validation = Path("deploy/helm/mirage/templates/validation.yaml").read_text(encoding="utf-8")

    assert "runAsNonRoot: true" in kube
    assert "readOnlyRootFilesystem: true" in kube
    assert "HorizontalPodAutoscaler" in kube
    assert "PodDisruptionBudget" in kube
    assert "NetworkPolicy" in network
    assert "mirage-default-deny" in network
    assert "mirage-cyber-range-isolated" in network
    assert "fail" in helm_validation
    assert "production + execution enabled" in helm_validation
