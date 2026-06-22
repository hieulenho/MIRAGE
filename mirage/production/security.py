"""Authentication, service identity, and RBAC helpers."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from mirage.production.schema import ApprovalRecord, ScopeContext, UserIdentity


ROLE_PERMISSIONS: dict[str, set[str]] = {
    "viewer": {"telemetry:view", "recommendation:view"},
    "soc_analyst": {
        "telemetry:view",
        "recommendation:view",
        "feedback:submit",
        "soc:case:create",
        "approval:request",
    },
    "incident_commander": {
        "telemetry:view",
        "recommendation:view",
        "action:approve",
        "rollback:trigger",
        "automation:pause",
    },
    "system_owner": {
        "pilot:prepare",
        "pilot:execute",
        "pilot_scope:manage",
        "action:approve",
    },
    "security_engineer": {
        "connector:manage",
        "model:register",
        "policy:promote",
        "safety_invariant:modify",
    },
    "governance_reviewer": {
        "policy:promote",
        "policy:suspend",
        "deployment_level:set",
        "action:approve",
    },
    "platform_operator": {
        "backup:create",
        "backup:restore",
        "storage:migrate",
        "automation:pause",
        "automation:resume_shadow",
    },
    "auditor": {"audit:view", "audit:sensitive:view", "audit:verify"},
}


class RBACAuthorizer:
    """Deny-by-default role authorization with tenant/environment scoping."""

    def __init__(self, role_permissions: dict[str, set[str]] | None = None) -> None:
        self.role_permissions = role_permissions or ROLE_PERMISSIONS

    def permissions_for(self, identity: UserIdentity) -> set[str]:
        permissions: set[str] = set()
        for role in identity.roles:
            permissions.update(self.role_permissions.get(role, set()))
        permissions.update(identity.scopes)
        return permissions

    def authorize(
        self,
        identity: UserIdentity,
        permission: str,
        *,
        scope: ScopeContext,
    ) -> bool:
        if identity.tenant_id != scope.tenant_id:
            return False
        if identity.environment != scope.environment:
            return False
        return permission in self.permissions_for(identity)

    def require(
        self,
        identity: UserIdentity,
        permission: str,
        *,
        scope: ScopeContext,
    ) -> None:
        if not self.authorize(identity, permission, scope=scope):
            raise PermissionError(
                f"{identity.subject} is not authorized for {permission}"
            )


def validate_approval(
    approval: ApprovalRecord,
    *,
    requester: UserIdentity,
    required_roles: set[str],
    now: datetime | None = None,
) -> None:
    """Validate separation of duties and bound approval identity."""
    current = now or datetime.now(timezone.utc)
    if approval.requester_subject != requester.subject:
        raise PermissionError("approval requester identity mismatch")
    if approval.approver_subject == requester.subject:
        raise PermissionError("requester cannot approve their own action")
    if approval.approver_role not in required_roles:
        raise PermissionError("approver role is not authorized")
    if approval.expires_at < current:
        raise PermissionError("approval expired")


class ServiceTokenIssuer:
    """Small signed-token helper for service identities.

    This is intentionally compatible with external identity providers rather
    than a replacement for OIDC.  It is used in tests and controlled machine
    integrations where a short-lived signed token is sufficient.
    """

    def __init__(self, signing_key: str, *, issuer: str = "mirage") -> None:
        if not signing_key:
            raise ValueError("signing key is required")
        self.signing_key = signing_key.encode("utf-8")
        self.issuer = issuer

    def issue(
        self,
        subject: str,
        *,
        audience: str,
        scopes: list[str],
        ttl_seconds: int = 900,
    ) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "scope": scopes,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        }
        encoded_payload = _b64(json.dumps(payload, sort_keys=True).encode("utf-8"))
        signature = _b64(hmac.new(self.signing_key, encoded_payload.encode("ascii"), hashlib.sha256).digest())
        return f"{encoded_payload}.{signature}"

    def verify(
        self,
        token: str,
        *,
        audience: str,
        required_scope: str | None = None,
        revoked: set[str] | None = None,
    ) -> dict[str, Any]:
        try:
            encoded_payload, supplied_signature = token.split(".", 1)
        except ValueError as exc:
            raise PermissionError("malformed service token") from exc
        expected = _b64(hmac.new(self.signing_key, encoded_payload.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(supplied_signature, expected):
            raise PermissionError("invalid service token signature")
        payload = json.loads(_unb64(encoded_payload).decode("utf-8"))
        if revoked and token in revoked:
            raise PermissionError("service token revoked")
        if payload.get("aud") != audience:
            raise PermissionError("service token audience mismatch")
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            raise PermissionError("service token expired")
        if required_scope and required_scope not in payload.get("scope", []):
            raise PermissionError("service token missing required scope")
        return payload


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
