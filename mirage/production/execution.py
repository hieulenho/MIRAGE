"""Persistent, idempotent execution processing for limited automation."""

from __future__ import annotations

from typing import Any, Protocol

from pydantic import BaseModel, Field

from mirage.production.ha import InMemoryLeaseStore
from mirage.production.schema import DeploymentLevel, ScopeContext
from mirage.production.storage import ExecutionRepository, ProductionRepository


class ExecutionResult(BaseModel):
    """Result persisted around every external adapter call."""

    execution_id: str
    action_type: str
    state: str
    adapter_result: dict[str, Any] = Field(default_factory=dict)
    rollback_result: dict[str, Any] = Field(default_factory=dict)
    duplicate: bool = False


class LimitedExecutionAdapter(Protocol):
    """Narrowly scoped production adapter interface."""

    def health(self) -> dict[str, Any]:
        """Return public-safe adapter health."""

    def canary(self, action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Run a dry canary before execution."""

    def execute(
        self,
        action_type: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Execute exactly one bounded action step."""

    def rollback(
        self,
        action_type: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        """Rollback the bounded action step."""


class NarrowPilotAdapter:
    """Mock-safe adapter for tickets, telemetry requests, decoys, and throttles."""

    allowed_actions = {
        "create_soc_ticket",
        "request_analyst_review",
        "increase_endpoint_logging",
        "increase_network_telemetry",
        "enable_limited_packet_capture",
        "enable_auth_auditing",
        "deploy_decoy_host",
        "deploy_decoy_database",
        "deploy_fake_share",
        "add_decoy_service",
        "scatter_honey_credential",
        "create_fake_dns_record",
        "throttle_edge",
    }

    def __init__(self) -> None:
        self.execute_calls: list[str] = []
        self.healthy = True

    def health(self) -> dict[str, Any]:
        return {"healthy": self.healthy, "adapter": "narrow_pilot"}

    def canary(self, action_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._validate(action_type, payload)
        return {"ok": True, "dry_run": True}

    def execute(
        self,
        action_type: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._validate(action_type, payload)
        if not self.healthy:
            raise RuntimeError("pilot adapter unavailable")
        if idempotency_key not in self.execute_calls:
            self.execute_calls.append(idempotency_key)
        return {
            "ok": True,
            "action_type": action_type,
            "idempotency_key": idempotency_key,
            "dry_run": bool(payload.get("dry_run", False)),
        }

    def rollback(
        self,
        action_type: str,
        payload: dict[str, Any],
        *,
        idempotency_key: str,
    ) -> dict[str, Any]:
        self._validate(action_type, payload)
        return {"ok": True, "rolled_back": True, "idempotency_key": idempotency_key}

    def _validate(self, action_type: str, payload: dict[str, Any]) -> None:
        if action_type not in self.allowed_actions:
            raise PermissionError(f"action is not eligible for pilot adapter: {action_type}")
        if payload.get("target_allowlisted") is False:
            raise PermissionError("pilot adapter target is not allowlisted")


class PersistentExecutionProcessor:
    """Idempotent execution worker using persistent intent and leases."""

    def __init__(
        self,
        repository: ProductionRepository,
        leases: InMemoryLeaseStore,
        adapter: LimitedExecutionAdapter,
    ) -> None:
        self.repository = repository
        self.leases = leases
        self.adapter = adapter

    def process(
        self,
        execution_id: str,
        action_type: str,
        payload: dict[str, Any],
        *,
        scope: ScopeContext,
        idempotency_key: str,
        deployment_level: DeploymentLevel = DeploymentLevel.SHADOW_ONLY,
        action_tier: int = 0,
    ) -> ExecutionResult:
        existing = self.repository.get_idempotency(idempotency_key, scope=scope)
        if existing:
            return ExecutionResult.model_validate({**existing, "duplicate": True})
        if not _level_allows_execution(deployment_level, action_tier):
            result = ExecutionResult(
                execution_id=execution_id,
                action_type=action_type,
                state="shadow_only",
                adapter_result={"executed": False},
            )
            self.repository.record_idempotency(
                idempotency_key,
                result.model_dump(mode="json"),
                scope=scope,
            )
            return result

        self.repository.upsert(
            ExecutionRepository.table,
            execution_id,
            {
                "state": "intent_persisted",
                "action_type": action_type,
                "payload": payload,
                "idempotency_key": idempotency_key,
            },
            scope=scope,
        )
        if not self.leases.acquire(f"execution:{scope.scoped_key(execution_id)}", idempotency_key):
            current = self.repository.get(ExecutionRepository.table, execution_id, scope=scope)
            return ExecutionResult(
                execution_id=execution_id,
                action_type=action_type,
                state="leased_elsewhere",
                adapter_result=current.payload if current else {},
            )
        try:
            canary = self.adapter.canary(action_type, payload)
            adapter_result = self.adapter.execute(
                action_type,
                payload,
                idempotency_key=scope.scoped_key(idempotency_key),
            )
            result = ExecutionResult(
                execution_id=execution_id,
                action_type=action_type,
                state="succeeded",
                adapter_result={"canary": canary, "execution": adapter_result},
            )
            self.repository.upsert(
                ExecutionRepository.table,
                execution_id,
                result.model_dump(mode="json"),
                scope=scope,
            )
            self.repository.record_idempotency(
                idempotency_key,
                result.model_dump(mode="json"),
                scope=scope,
            )
            return result
        except Exception as exc:
            rollback = self.adapter.rollback(
                action_type,
                payload,
                idempotency_key=scope.scoped_key(idempotency_key),
            )
            result = ExecutionResult(
                execution_id=execution_id,
                action_type=action_type,
                state="rolled_back",
                adapter_result={"error": str(exc)},
                rollback_result=rollback,
            )
            self.repository.upsert(
                ExecutionRepository.table,
                execution_id,
                result.model_dump(mode="json"),
                scope=scope,
            )
            self.repository.record_idempotency(
                idempotency_key,
                result.model_dump(mode="json"),
                scope=scope,
            )
            return result
        finally:
            self.leases.release(f"execution:{scope.scoped_key(execution_id)}", idempotency_key)


def _level_allows_execution(level: DeploymentLevel, action_tier: int) -> bool:
    if level in {DeploymentLevel.SHADOW_ONLY, DeploymentLevel.READ_ONLY_PRODUCTION}:
        return False
    if level == DeploymentLevel.LOW_RISK_PILOT:
        return action_tier <= 1
    if level == DeploymentLevel.LIMITED_REVERSIBLE_CONTROL:
        return action_tier <= 2
    return False
