"""Canonical security-event and digital-twin schemas for MIRAGE."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


def utc_now() -> datetime:
    """Return a timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc)


def require_aware(value: datetime) -> datetime:
    """Require timezone-aware datetimes and normalize them to UTC."""
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc)


class StrictModel(BaseModel):
    """Base model that rejects accidental duplicate concepts as extra fields."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class SecurityEvent(StrictModel):
    """Canonical security event used by ingestion, replay, API, and twin."""

    event_id: str = Field(min_length=1)
    event_time: datetime
    ingest_time: datetime
    source: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    asset_id: str | None = None
    user_id: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    process_name: str | None = None
    command_line: str | None = None
    credential_id: str | None = None
    technique_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_event_ref: str | None = None

    @field_validator("event_id", "source", "event_type")
    @classmethod
    def _non_empty(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("value must not be empty")
        return cleaned

    @field_validator("event_time", "ingest_time")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class Asset(StrictModel):
    """Canonical asset registry record."""

    asset_id: str = Field(min_length=1)
    hostname: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    asset_type: str = "unknown"
    operating_system: str | None = None
    environment: str | None = None
    subnet: str | None = None
    business_criticality: float = Field(default=0.0, ge=0.0, le=1.0)
    owner: str | None = None
    first_seen: datetime
    last_seen: datetime
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    data_sources: list[str] = Field(default_factory=list)
    active: bool = True
    aliases: list[str] = Field(default_factory=list)
    is_decoy: bool = False
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    @model_validator(mode="after")
    def _validate_seen_order(self) -> "Asset":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class Identity(StrictModel):
    """Canonical identity registry record."""

    identity_id: str = Field(min_length=1)
    username: str | None = None
    domain: str | None = None
    identity_type: str = "user"
    privilege_level: str = "unknown"
    groups: list[str] = Field(default_factory=list)
    associated_assets: list[str] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    data_sources: list[str] = Field(default_factory=list)
    aliases: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)

    @model_validator(mode="after")
    def _validate_seen_order(self) -> "Identity":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class Relationship(StrictModel):
    """Relationship between two canonical or derived twin entities."""

    relationship_id: str = Field(min_length=1)
    source_entity_id: str = Field(min_length=1)
    target_entity_id: str = Field(min_length=1)
    relationship_type: str = Field(min_length=1)
    protocol: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    privilege_requirement: str | None = None
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    expiry_time: datetime | None = None
    source_event_ids: list[str] = Field(default_factory=list)
    active: bool = True
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("first_seen", "last_seen", "expiry_time")
    @classmethod
    def _aware_datetime(cls, value: datetime | None) -> datetime | None:
        return require_aware(value) if value is not None else None

    @model_validator(mode="after")
    def _validate_seen_order(self) -> "Relationship":
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


class TwinSnapshot(StrictModel):
    """Serializable point-in-time Digital Twin state."""

    twin_version: int = Field(ge=0)
    timestamp: datetime
    assets: dict[str, Asset] = Field(default_factory=dict)
    identities: dict[str, Identity] = Field(default_factory=dict)
    relationships: dict[str, Relationship] = Field(default_factory=dict)
    graph_metadata: dict[str, Any] = Field(default_factory=dict)
    source_position: str | None = None
    coverage_score: float = Field(default=0.0, ge=0.0, le=1.0)
    freshness_score: float = Field(default=0.0, ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def _aware_datetime(cls, value: datetime) -> datetime:
        return require_aware(value)


class TwinUpdateResult(StrictModel):
    """Result of applying one event to the Digital Twin."""

    event_id: str
    event_type: str
    duplicate: bool = False
    assets_created: list[str] = Field(default_factory=list)
    assets_updated: list[str] = Field(default_factory=list)
    identities_created: list[str] = Field(default_factory=list)
    identities_updated: list[str] = Field(default_factory=list)
    relationships_created: list[str] = Field(default_factory=list)
    relationships_updated: list[str] = Field(default_factory=list)
    expired_relationships: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    twin_version: int


class TwinUpdateSummary(StrictModel):
    """Aggregate result for a batch replay or ingestion call."""

    processed: int = 0
    duplicates: int = 0
    invalid_events: int = 0
    assets_created: int = 0
    assets_updated: int = 0
    identities_created: int = 0
    identities_updated: int = 0
    relationships_created: int = 0
    relationships_updated: int = 0
    expired_relationships: int = 0
    final_twin_version: int = 0
    warnings: list[str] = Field(default_factory=list)


EventOrdering = Literal["event_time", "file"]
