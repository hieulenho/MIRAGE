"""Drift monitoring schemas."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class StrictDriftModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class DriftStatus(str, Enum):
    NORMAL = "NORMAL"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class DriftReport(StrictDriftModel):
    report_id: str
    status: DriftStatus
    data_drift: dict[str, float] = Field(default_factory=dict)
    model_drift: dict[str, float] = Field(default_factory=dict)
    policy_drift: dict[str, float] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    critical_reasons: list[str] = Field(default_factory=list)
    pilot_suspended: bool = False
    shadow_mode_preserved: bool = True
    timestamp: datetime = Field(default_factory=utc_now)
