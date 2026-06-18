"""Mock/lab enforcement adapters for Milestone 4."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from mirage.domain.schemas import AdapterCallResult, ExecutionPlan
from mirage.execution.utils import ensure_utc


@dataclass
class MockLabState:
    """In-memory lab state; no real infrastructure is contacted."""

    resources: dict[str, dict] = field(default_factory=dict)
    controls: dict[str, dict] = field(default_factory=dict)
    tickets: dict[str, dict] = field(default_factory=dict)
    adapter_calls: list[AdapterCallResult] = field(default_factory=list)
    failure_injections: dict[str, str] = field(default_factory=dict)
    protected_services_healthy: bool = True
    management_channel_reachable: bool = True
    decoy_can_reach_protected: bool = False

    def failure_for(self, adapter_type: str, operation: str) -> str | None:
        """Return a configured failure reason for an adapter operation."""
        return (
            self.failure_injections.get(f"{adapter_type}.{operation}")
            or self.failure_injections.get(operation)
        )


class EnforcementAdapter(Protocol):
    """Common interface for lab-safe enforcement adapters."""

    adapter_type: str

    def validate(self, plan: ExecutionPlan) -> AdapterCallResult: ...

    def prepare(self, plan: ExecutionPlan) -> AdapterCallResult: ...

    def execute_canary(self, plan: ExecutionPlan) -> AdapterCallResult: ...

    def execute(self, plan: ExecutionPlan) -> AdapterCallResult: ...

    def verify(self, plan: ExecutionPlan) -> AdapterCallResult: ...

    def rollback(self, plan: ExecutionPlan) -> AdapterCallResult: ...

    def status(self, execution_id: str) -> AdapterCallResult: ...


class BaseMockAdapter:
    """Base idempotent mock adapter implementation."""

    adapter_type = "mock"

    def __init__(self, lab_state: MockLabState | None = None) -> None:
        self.lab_state = lab_state or MockLabState()

    def validate(self, plan: ExecutionPlan) -> AdapterCallResult:
        return self._result(plan, "validate")

    def prepare(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        self.lab_state.resources.setdefault(
            key,
            {
                "plan_id": plan.plan_id,
                "adapter_type": self.adapter_type,
                "targets": list(plan.allowed_scope),
                "prepared": True,
                "active": False,
            },
        )
        return self._result(plan, "prepare", changed=[key])

    def execute_canary(self, plan: ExecutionPlan) -> AdapterCallResult:
        if not self.lab_state.management_channel_reachable:
            return self._result(
                plan,
                "execute_canary",
                success=False,
                error="management_channel_unreachable",
            )
        if not self.lab_state.protected_services_healthy:
            return self._result(
                plan,
                "execute_canary",
                success=False,
                error="protected_service_unhealthy",
            )
        return self._result(plan, "execute_canary")

    def execute(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        resource = self.lab_state.resources.setdefault(
            key,
            {
                "plan_id": plan.plan_id,
                "adapter_type": self.adapter_type,
                "targets": list(plan.allowed_scope),
            },
        )
        resource["active"] = True
        resource["action_type"] = plan.action_type
        return self._result(plan, "execute", changed=[key])

    def verify(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        resource = self.lab_state.resources.get(key, {})
        if not resource.get("active"):
            return self._result(
                plan,
                "verify",
                success=False,
                error="resource_not_active",
            )
        return self._result(plan, "verify", changed=[key])

    def rollback(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        resource = self.lab_state.resources.setdefault(
            key,
            {
                "plan_id": plan.plan_id,
                "adapter_type": self.adapter_type,
                "targets": list(plan.allowed_scope),
            },
        )
        resource["active"] = False
        resource["rolled_back"] = True
        return self._result(plan, "rollback", changed=[key])

    def status(self, execution_id: str) -> AdapterCallResult:
        return self._record(
            operation="status",
            success=True,
            idempotency_key=execution_id,
            details={"execution_id": execution_id},
        )

    def _resource_key(self, plan: ExecutionPlan) -> str:
        return f"{self.adapter_type}:{plan.plan_id}"

    def _result(
        self,
        plan: ExecutionPlan,
        operation: str,
        *,
        success: bool = True,
        changed: list[str] | None = None,
        error: str | None = None,
    ) -> AdapterCallResult:
        injected = self.lab_state.failure_for(self.adapter_type, operation)
        if injected:
            success = False
            error = injected
        return self._record(
            operation=operation,
            success=success,
            idempotency_key=f"{plan.idempotency_key}:{operation}",
            changed=changed or [],
            error=error,
            details={
                "plan_id": plan.plan_id,
                "action_type": plan.action_type,
                "targets": list(plan.allowed_scope),
            },
        )

    def _record(
        self,
        *,
        operation: str,
        success: bool,
        idempotency_key: str,
        changed: list[str] | None = None,
        error: str | None = None,
        details: dict | None = None,
    ) -> AdapterCallResult:
        result = AdapterCallResult(
            adapter_type=self.adapter_type,
            operation=operation,
            success=success,
            idempotency_key=idempotency_key,
            changed_resources=changed or [],
            details=details or {},
            error=error,
            timestamp=ensure_utc(None),
        )
        self.lab_state.adapter_calls.append(result)
        return result


class DockerDecoyAdapter(BaseMockAdapter):
    """Mock Docker decoy adapter; never talks to Docker daemon."""

    adapter_type = "docker_decoy"

    def execute_canary(self, plan: ExecutionPlan) -> AdapterCallResult:
        result = super().execute_canary(plan)
        if not result.success:
            return result
        if self.lab_state.decoy_can_reach_protected:
            return self._result(
                plan,
                "execute_canary",
                success=False,
                error="decoy_can_reach_protected_service",
            )
        return result.model_copy(
            update={
                "details": {
                    **result.details,
                    "deny_by_default_egress": True,
                    "telemetry_hook": True,
                }
            }
        )

    def execute(self, plan: ExecutionPlan) -> AdapterCallResult:
        result = super().execute(plan)
        key = self._resource_key(plan)
        self.lab_state.resources[key]["isolated_network"] = True
        self.lab_state.resources[key]["egress_policy"] = "deny_by_default"
        self.lab_state.resources[key]["telemetry"] = "enabled"
        return result

    def verify(self, plan: ExecutionPlan) -> AdapterCallResult:
        result = super().verify(plan)
        if not result.success:
            return result
        if self.lab_state.decoy_can_reach_protected:
            return self._result(
                plan,
                "verify",
                success=False,
                error="protected_service_reachable_from_decoy",
            )
        return result


class MockFirewallAdapter(BaseMockAdapter):
    """Mock firewall adapter for lab flow controls."""

    adapter_type = "mock_firewall"

    def execute(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        self.lab_state.controls[key] = {
            "plan_id": plan.plan_id,
            "targets": list(plan.allowed_scope),
            "control": plan.action_type,
            "active": True,
        }
        return self._result(plan, "execute", changed=[key])

    def verify(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        if not self.lab_state.controls.get(key, {}).get("active"):
            return self._result(plan, "verify", success=False, error="control_not_active")
        return self._result(plan, "verify", changed=[key])

    def rollback(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        self.lab_state.controls.setdefault(key, {})["active"] = False
        return self._result(plan, "rollback", changed=[key])


class MockEDRAdapter(BaseMockAdapter):
    """Mock EDR adapter for non-critical lab endpoint containment."""

    adapter_type = "mock_edr"


class MockIAMAdapter(BaseMockAdapter):
    """Mock IAM adapter for honey credentials or lab session revocation."""

    adapter_type = "mock_iam"


class MockDNSAdapter(BaseMockAdapter):
    """Mock DNS adapter for fake DNS records."""

    adapter_type = "mock_dns"


class MockTelemetryAdapter(BaseMockAdapter):
    """Mock telemetry adapter for logging/packet capture actions."""

    adapter_type = "mock_telemetry"


class MockTicketAdapter(BaseMockAdapter):
    """Mock ticket adapter for analyst-review workflows."""

    adapter_type = "mock_ticket"

    def execute(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        self.lab_state.tickets[key] = {
            "plan_id": plan.plan_id,
            "targets": list(plan.allowed_scope),
            "status": "open",
        }
        return self._result(plan, "execute", changed=[key])

    def rollback(self, plan: ExecutionPlan) -> AdapterCallResult:
        key = self._resource_key(plan)
        self.lab_state.tickets.setdefault(key, {})["status"] = "closed"
        return self._result(plan, "rollback", changed=[key])


def build_default_adapters(
    lab_state: MockLabState | None = None,
) -> dict[str, EnforcementAdapter]:
    """Build all lab-safe adapters over a shared in-memory lab state."""
    state = lab_state or MockLabState()
    return {
        "docker_decoy": DockerDecoyAdapter(state),
        "mock_firewall": MockFirewallAdapter(state),
        "mock_edr": MockEDRAdapter(state),
        "mock_iam": MockIAMAdapter(state),
        "mock_dns": MockDNSAdapter(state),
        "mock_telemetry": MockTelemetryAdapter(state),
        "mock_ticket": MockTicketAdapter(state),
    }
