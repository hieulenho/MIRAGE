"""Automation kill switch for lab-safe execution."""

from __future__ import annotations

from mirage.domain.schemas import KillSwitchState
from mirage.execution.audit import ImmutableAuditStore
from mirage.execution.utils import ensure_utc


class KillSwitch:
    """Global, per-action, and per-environment automation kill switch."""

    def __init__(
        self,
        *,
        default_enabled: bool = False,
        audit_store: ImmutableAuditStore | None = None,
    ) -> None:
        self.audit_store = audit_store or ImmutableAuditStore()
        self.state = KillSwitchState(
            global_enabled=default_enabled,
            updated_by="config",
            reason="default",
            updated_at=ensure_utc(None),
        )

    def is_blocked(
        self,
        *,
        action_type: str | None = None,
        environment: str | None = None,
    ) -> bool:
        """Return whether automation is blocked."""
        if self.state.global_enabled:
            return True
        if action_type and self.state.action_type_blocks.get(action_type, False):
            return True
        if environment and self.state.environment_blocks.get(environment, False):
            return True
        return False

    def enable(
        self,
        *,
        actor: str,
        reason: str,
        action_type: str | None = None,
        environment: str | None = None,
    ) -> KillSwitchState:
        """Enable global or scoped automation block."""
        action_blocks = dict(self.state.action_type_blocks)
        env_blocks = dict(self.state.environment_blocks)
        global_enabled = self.state.global_enabled
        if action_type:
            action_blocks[action_type] = True
        elif environment:
            env_blocks[environment] = True
        else:
            global_enabled = True
        self.state = KillSwitchState(
            global_enabled=global_enabled,
            action_type_blocks=action_blocks,
            environment_blocks=env_blocks,
            updated_by=actor,
            reason=reason,
            updated_at=ensure_utc(None),
        )
        self.audit_store.append(
            "kill_switch_enabled",
            actor=actor,
            payload={
                "reason": reason,
                "action_type": action_type,
                "environment": environment,
                "state": self.state.model_dump(mode="json"),
            },
        )
        return self.state

    def disable(
        self,
        *,
        actor: str,
        reason: str,
        action_type: str | None = None,
        environment: str | None = None,
    ) -> KillSwitchState:
        """Disable global or scoped automation block."""
        action_blocks = dict(self.state.action_type_blocks)
        env_blocks = dict(self.state.environment_blocks)
        global_enabled = self.state.global_enabled
        if action_type:
            action_blocks[action_type] = False
        elif environment:
            env_blocks[environment] = False
        else:
            global_enabled = False
        self.state = KillSwitchState(
            global_enabled=global_enabled,
            action_type_blocks=action_blocks,
            environment_blocks=env_blocks,
            updated_by=actor,
            reason=reason,
            updated_at=ensure_utc(None),
        )
        self.audit_store.append(
            "kill_switch_disabled",
            actor=actor,
            payload={
                "reason": reason,
                "action_type": action_type,
                "environment": environment,
                "state": self.state.model_dump(mode="json"),
            },
        )
        return self.state
