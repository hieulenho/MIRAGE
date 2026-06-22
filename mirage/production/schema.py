"""Typed public schemas for production deployment controls."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EnvironmentProfile(str, Enum):
    """Explicit MIRAGE runtime profiles."""

    DEVELOPMENT = "development"
    TEST = "test"
    CYBER_RANGE = "cyber_range"
    LAB = "lab"
    SHADOW = "shadow"
    CONTROLLED_PILOT = "controlled_pilot"
    PRODUCTION = "production"


class StorageBackend(str, Enum):
    """Supported storage backend families."""

    IN_MEMORY = "in_memory"
    SQLITE = "sqlite"
    POSTGRES = "postgres"


class EventTransportBackend(str, Enum):
    """Supported event transport backend families."""

    IN_MEMORY = "in_memory"
    LOCAL_DURABLE = "local_durable"
    KAFKA_COMPATIBLE = "kafka_compatible"


class DeploymentMode(str, Enum):
    """Logical service deployment topology."""

    MODULAR_MONOLITH = "modular_monolith"
    DISTRIBUTED_SERVICES = "distributed_services"


class DeploymentLevel(str, Enum):
    """Limited production automation levels."""

    SHADOW_ONLY = "SHADOW_ONLY"
    READ_ONLY_PRODUCTION = "READ_ONLY_PRODUCTION"
    LOW_RISK_PILOT = "LOW_RISK_PILOT"
    LIMITED_REVERSIBLE_CONTROL = "LIMITED_REVERSIBLE_CONTROL"


class DependencyStatus(str, Enum):
    """Dependency health state."""

    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class ScopeContext(BaseModel):
    """Tenant/environment scope attached to production state records."""

    tenant_id: str = "default"
    environment: EnvironmentProfile = EnvironmentProfile.SHADOW
    pilot_scope_id: str = ""
    data_classification: str = "internal"

    @property
    def idempotency_prefix(self) -> str:
        return (
            f"{self.tenant_id}:{self.environment.value}:"
            f"{self.pilot_scope_id or 'none'}:"
        )

    def scoped_key(self, key: str) -> str:
        """Return a tenant-aware idempotency/cache key."""
        return f"{self.idempotency_prefix}{key}"


class ResourceLimits(BaseModel):
    """Basic resource controls for a deployment profile."""

    cpu: str = "500m"
    memory: str = "512Mi"
    replicas_min: int = 1
    replicas_max: int = 1


class BackupPolicy(BaseModel):
    """Backup expectations for an environment profile."""

    enabled: bool = False
    frequency: str = "manual"
    retention_days: int = 7
    encryption_required: bool = True
    rpo_minutes: int = 1440
    rto_minutes: int = 240


class DeploymentProfileConfig(BaseModel):
    """Profile-specific storage, transport, security, and rollout defaults."""

    profile: EnvironmentProfile
    storage_backend: StorageBackend
    event_transport_backend: EventTransportBackend
    connector_permissions: str
    enforcement_permissions: str
    authentication_required: bool
    tls_required: bool
    audit_retention_days: int
    logging_level: str
    model_operating_modes: dict[str, str] = Field(default_factory=dict)
    allowed_action_tiers: list[int] = Field(default_factory=list)
    pilot_scopes: list[str] = Field(default_factory=list)
    resource_limits: ResourceLimits = Field(default_factory=ResourceLimits)
    backup_policy: BackupPolicy = Field(default_factory=BackupPolicy)


class AuthConfig(BaseModel):
    """Production authentication boundary settings."""

    enabled: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = "mirage-api"
    service_identity_required: bool = False
    api_tokens_enabled: bool = False
    token_ttl_seconds: int = 900
    revocation_list_path: str = "artifacts/revoked_service_tokens.json"
    default_credentials_allowed: bool = False


class TLSConfig(BaseModel):
    """Transport-security settings."""

    enabled: bool = False
    mtls_required: bool = False
    ca_bundle: str = ""
    cert_file: str = ""
    key_file: str = ""
    verify_hostname: bool = True
    insecure_skip_verify: bool = False


class StorageConfig(BaseModel):
    """Persistent storage settings."""

    backend: StorageBackend = StorageBackend.SQLITE
    sqlite_path: str = "artifacts/production/mirage.db"
    postgres_dsn: str = ""
    object_storage_uri: str = "artifacts/production/object_store"
    schema_compatibility_window: int = 1


class EventTransportConfig(BaseModel):
    """Durable event transport settings."""

    backend: EventTransportBackend = EventTransportBackend.LOCAL_DURABLE
    sqlite_path: str = "artifacts/production/events.db"
    broker_url: str = ""
    max_retries: int = 3
    poll_lease_seconds: int = 30
    max_queue_depth: int = 100000


class ProductionAuditConfig(BaseModel):
    """Durable audit settings."""

    path: str = "artifacts/production/audit.jsonl"
    retention_days: int = 365
    write_only_identity: str = "mirage-audit-writer"
    immutable_export_uri: str = "artifacts/production/audit_exports"
    fail_closed_for_execution: bool = True


class APIProtectionConfig(BaseModel):
    """API-gateway protection defaults."""

    require_correlation_id: bool = True
    rate_limit_per_minute: int = 600
    timeout_seconds: int = 30
    max_page_size: int = 1000
    cors_policy: str = "explicit"
    openapi_public: bool = False
    training_endpoints_enabled: bool = False


class ProductionConfig(BaseModel):
    """Milestone 10 production-hardening settings."""

    operating_mode: str = "shadow"
    production_execution_enabled: bool = False
    high_risk_automation_enabled: bool = False
    formal_verification_required: bool = True
    governance_gate_required: bool = True
    action_mask_required: bool = True
    safety_gate_required: bool = True
    deployment_mode: DeploymentMode = DeploymentMode.MODULAR_MONOLITH
    profile: EnvironmentProfile = EnvironmentProfile.SHADOW
    deployment_level: DeploymentLevel = DeploymentLevel.SHADOW_ONLY
    profiles: dict[str, DeploymentProfileConfig] = Field(default_factory=dict)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    event_transport: EventTransportConfig = Field(default_factory=EventTransportConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    tls: TLSConfig = Field(default_factory=TLSConfig)
    audit: ProductionAuditConfig = Field(default_factory=ProductionAuditConfig)
    api_gateway: APIProtectionConfig = Field(default_factory=APIProtectionConfig)
    allowed_automatic_action_types: list[str] = Field(default_factory=list)
    prohibited_action_types: list[str] = Field(default_factory=list)
    protected_assets: list[str] = Field(default_factory=list)
    rollback_configured_actions: list[str] = Field(default_factory=list)
    tenants: list[str] = Field(default_factory=lambda: ["default"])
    required_policy_versions: list[str] = Field(default_factory=list)
    required_model_versions: list[str] = Field(default_factory=list)


class ValidationFinding(BaseModel):
    """A production configuration or dependency finding."""

    code: str
    severity: str = "error"
    message: str
    safe_to_start: bool = False


class ValidationReport(BaseModel):
    """Validation result used by startup, CLI, and readiness APIs."""

    valid: bool
    profile: EnvironmentProfile
    findings: list[ValidationFinding] = Field(default_factory=list)


class DependencyCheckResult(BaseModel):
    """Readiness result for one dependency."""

    name: str
    status: DependencyStatus
    public_message: str
    checked_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class HealthReport(BaseModel):
    """Public-safe health or readiness response."""

    live: bool
    ready: bool
    profile: EnvironmentProfile
    dependencies: list[DependencyCheckResult] = Field(default_factory=list)
    security: ValidationReport | None = None


class UserIdentity(BaseModel):
    """Authenticated user or service identity."""

    subject: str
    roles: list[str] = Field(default_factory=list)
    tenant_id: str = "default"
    environment: EnvironmentProfile = EnvironmentProfile.SHADOW
    scopes: list[str] = Field(default_factory=list)
    is_service: bool = False


class ApprovalRecord(BaseModel):
    """Approval bound to an exact actor, role, and request."""

    approval_id: str
    request_id: str
    approver_subject: str
    approver_role: str
    requester_subject: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=15)
    )


class DeploymentLevelRecord(BaseModel):
    """Governed deployment level state."""

    level: DeploymentLevel = DeploymentLevel.SHADOW_ONLY
    actor: str = "mirage"
    role: str = "system"
    reason: str = "default"
    expires_at: datetime | None = None
    review_at: datetime | None = None
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


LOW_RISK_AUTOMATIC_ACTIONS = [
    "increase_endpoint_logging",
    "increase_network_telemetry",
    "enable_limited_packet_capture",
    "enable_auth_auditing",
    "create_soc_ticket",
    "request_analyst_review",
    "deploy_decoy_host",
    "deploy_decoy_database",
    "deploy_fake_share",
    "add_decoy_service",
    "scatter_honey_credential",
    "create_fake_dns_record",
    "throttle_edge",
]

PROHIBITED_PRODUCTION_ACTIONS = [
    "isolate_host",
    "isolate_database",
    "disable_privileged_identity",
    "block_subnet",
    "modify_critical_database",
    "change_core_routing",
    "block_all_traffic",
    "delete_credentials",
]


def default_profile_configs() -> dict[str, dict[str, Any]]:
    """Return serializable defaults for every explicit deployment profile."""
    profiles = {
        EnvironmentProfile.DEVELOPMENT: DeploymentProfileConfig(
            profile=EnvironmentProfile.DEVELOPMENT,
            storage_backend=StorageBackend.IN_MEMORY,
            event_transport_backend=EventTransportBackend.IN_MEMORY,
            connector_permissions="fixture_read_only",
            enforcement_permissions="disabled",
            authentication_required=False,
            tls_required=False,
            audit_retention_days=7,
            logging_level="DEBUG",
            model_operating_modes={"gnn": "gnn_shadow", "rl": "rl_shadow", "marl": "shadow"},
            allowed_action_tiers=[0, 1],
        ),
        EnvironmentProfile.TEST: DeploymentProfileConfig(
            profile=EnvironmentProfile.TEST,
            storage_backend=StorageBackend.IN_MEMORY,
            event_transport_backend=EventTransportBackend.IN_MEMORY,
            connector_permissions="fixture_read_only",
            enforcement_permissions="mock_only",
            authentication_required=False,
            tls_required=False,
            audit_retention_days=14,
            logging_level="DEBUG",
            model_operating_modes={"gnn": "gnn_shadow", "rl": "rl_shadow", "marl": "shadow"},
            allowed_action_tiers=[0, 1],
        ),
        EnvironmentProfile.CYBER_RANGE: DeploymentProfileConfig(
            profile=EnvironmentProfile.CYBER_RANGE,
            storage_backend=StorageBackend.SQLITE,
            event_transport_backend=EventTransportBackend.LOCAL_DURABLE,
            connector_permissions="synthetic_only",
            enforcement_permissions="range_only",
            authentication_required=False,
            tls_required=False,
            audit_retention_days=30,
            logging_level="INFO",
            model_operating_modes={"gnn": "gnn_shadow", "rl": "rl_shadow", "marl": "shadow"},
            allowed_action_tiers=[0, 1, 2],
            backup_policy=BackupPolicy(enabled=True, frequency="daily"),
        ),
        EnvironmentProfile.LAB: DeploymentProfileConfig(
            profile=EnvironmentProfile.LAB,
            storage_backend=StorageBackend.SQLITE,
            event_transport_backend=EventTransportBackend.LOCAL_DURABLE,
            connector_permissions="fixture_read_only",
            enforcement_permissions="lab_mock_only",
            authentication_required=False,
            tls_required=False,
            audit_retention_days=30,
            logging_level="INFO",
            model_operating_modes={"gnn": "gnn_shadow", "rl": "rl_shadow", "marl": "shadow"},
            allowed_action_tiers=[0, 1, 2],
            backup_policy=BackupPolicy(enabled=True, frequency="daily"),
        ),
        EnvironmentProfile.SHADOW: DeploymentProfileConfig(
            profile=EnvironmentProfile.SHADOW,
            storage_backend=StorageBackend.SQLITE,
            event_transport_backend=EventTransportBackend.LOCAL_DURABLE,
            connector_permissions="read_only",
            enforcement_permissions="disabled",
            authentication_required=True,
            tls_required=True,
            audit_retention_days=180,
            logging_level="INFO",
            model_operating_modes={"gnn": "gnn_shadow", "rl": "rl_shadow", "marl": "shadow"},
            allowed_action_tiers=[0],
            backup_policy=BackupPolicy(enabled=True, frequency="daily"),
        ),
        EnvironmentProfile.CONTROLLED_PILOT: DeploymentProfileConfig(
            profile=EnvironmentProfile.CONTROLLED_PILOT,
            storage_backend=StorageBackend.SQLITE,
            event_transport_backend=EventTransportBackend.LOCAL_DURABLE,
            connector_permissions="read_only",
            enforcement_permissions="allowlisted_low_risk",
            authentication_required=True,
            tls_required=True,
            audit_retention_days=365,
            logging_level="INFO",
            model_operating_modes={"gnn": "hybrid_recommendation", "rl": "rl_robust_hybrid", "marl": "shadow"},
            allowed_action_tiers=[0, 1, 2],
            backup_policy=BackupPolicy(enabled=True, frequency="daily"),
        ),
        EnvironmentProfile.PRODUCTION: DeploymentProfileConfig(
            profile=EnvironmentProfile.PRODUCTION,
            storage_backend=StorageBackend.POSTGRES,
            event_transport_backend=EventTransportBackend.KAFKA_COMPATIBLE,
            connector_permissions="read_only",
            enforcement_permissions="approved_pilot_scope_only",
            authentication_required=True,
            tls_required=True,
            audit_retention_days=365,
            logging_level="INFO",
            model_operating_modes={"gnn": "hybrid_recommendation", "rl": "rl_robust_hybrid", "marl": "shadow"},
            allowed_action_tiers=[0, 1, 2],
            backup_policy=BackupPolicy(
                enabled=True,
                frequency="hourly",
                retention_days=90,
                rpo_minutes=15,
                rto_minutes=60,
            ),
            resource_limits=ResourceLimits(
                cpu="1000m",
                memory="1Gi",
                replicas_min=3,
                replicas_max=12,
            ),
        ),
    }
    return {
        profile.value: config.model_dump(mode="json")
        for profile, config in profiles.items()
    }


def default_production_config() -> dict[str, Any]:
    """Return serializable safe defaults for config.json."""
    return ProductionConfig(
        profiles={
            name: DeploymentProfileConfig.model_validate(value)
            for name, value in default_profile_configs().items()
        },
        allowed_automatic_action_types=LOW_RISK_AUTOMATIC_ACTIONS,
        prohibited_action_types=PROHIBITED_PRODUCTION_ACTIONS,
        rollback_configured_actions=[
            "increase_endpoint_logging",
            "increase_network_telemetry",
            "enable_limited_packet_capture",
            "enable_auth_auditing",
            "create_soc_ticket",
            "request_analyst_review",
            "deploy_decoy_host",
            "deploy_decoy_database",
            "deploy_fake_share",
            "add_decoy_service",
            "scatter_honey_credential",
            "create_fake_dns_record",
            "throttle_edge",
        ],
        required_policy_versions=["safety-v1", "formal-safety-v1"],
    ).model_dump(mode="json")
