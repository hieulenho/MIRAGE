"""Limited-deployment controller and rollout safety checks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from mirage.production.schema import (
    DeploymentLevel,
    DeploymentLevelRecord,
    ScopeContext,
    UserIdentity,
)
from mirage.production.security import RBACAuthorizer
from mirage.production.storage import GovernanceRepository, ProductionRepository


LEVEL_ORDER = {
    DeploymentLevel.SHADOW_ONLY: 0,
    DeploymentLevel.READ_ONLY_PRODUCTION: 1,
    DeploymentLevel.LOW_RISK_PILOT: 2,
    DeploymentLevel.LIMITED_REVERSIBLE_CONTROL: 3,
}


class LimitedDeploymentController:
    """Governed deployment-level state machine.

    Models may recommend actions, but only authorized human/platform operators
    can raise the level.  Drift, audit failure, or kill switch events reduce it
    back to Shadow Mode.
    """

    record_id = "deployment_level"

    def __init__(
        self,
        repository: ProductionRepository,
        *,
        scope: ScopeContext,
        authorizer: RBACAuthorizer | None = None,
    ) -> None:
        self.repository = repository
        self.scope = scope
        self.authorizer = authorizer or RBACAuthorizer()

    def get_level(self) -> DeploymentLevelRecord:
        record = self.repository.get(GovernanceRepository.table, self.record_id, scope=self.scope)
        if record is None:
            return DeploymentLevelRecord()
        return DeploymentLevelRecord.model_validate(record.payload)

    def set_level(
        self,
        level: DeploymentLevel,
        *,
        actor: UserIdentity,
        reason: str,
        expires_in_seconds: int = 3600,
        actor_kind: str = "human",
    ) -> DeploymentLevelRecord:
        current = self.get_level()
        if actor_kind == "model" and LEVEL_ORDER[level] > LEVEL_ORDER[current.level]:
            raise PermissionError("models cannot raise deployment level")
        self.authorizer.require(actor, "deployment_level:set", scope=self.scope)
        if LEVEL_ORDER[level] > LEVEL_ORDER[current.level] and expires_in_seconds <= 0:
            raise ValueError("raised deployment levels require an expiry")
        record = DeploymentLevelRecord(
            level=level,
            actor=actor.subject,
            role=actor.roles[0] if actor.roles else "",
            reason=reason,
            expires_at=(
                datetime.now(timezone.utc) + timedelta(seconds=expires_in_seconds)
                if expires_in_seconds
                else None
            ),
            review_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        self.repository.upsert(
            GovernanceRepository.table,
            self.record_id,
            record.model_dump(mode="json"),
            scope=self.scope,
        )
        return record

    def reduce_to_shadow(self, *, reason: str, actor: str = "mirage") -> DeploymentLevelRecord:
        record = DeploymentLevelRecord(
            level=DeploymentLevel.SHADOW_ONLY,
            actor=actor,
            role="system",
            reason=reason,
        )
        self.repository.upsert(
            GovernanceRepository.table,
            self.record_id,
            record.model_dump(mode="json"),
            scope=self.scope,
        )
        return record

    def apply_runtime_signal(
        self,
        *,
        critical_drift: bool = False,
        audit_failure: bool = False,
        kill_switch: bool = False,
    ) -> DeploymentLevelRecord:
        if kill_switch:
            return self.reduce_to_shadow(reason="kill_switch")
        if audit_failure:
            return self.reduce_to_shadow(reason="audit_failure")
        if critical_drift:
            return self.reduce_to_shadow(reason="critical_drift")
        current = self.get_level()
        if current.expires_at and current.expires_at < datetime.now(timezone.utc):
            return self.reduce_to_shadow(reason="deployment_level_expired")
        return current

    def execution_allowed(self, *, action_tier: int) -> bool:
        level = self.apply_runtime_signal().level
        if level in {DeploymentLevel.SHADOW_ONLY, DeploymentLevel.READ_ONLY_PRODUCTION}:
            return False
        if level == DeploymentLevel.LOW_RISK_PILOT:
            return action_tier <= 1
        if level == DeploymentLevel.LIMITED_REVERSIBLE_CONTROL:
            return action_tier <= 2
        return False
