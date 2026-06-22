"""Secret-provider abstraction and redaction helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol


SENSITIVE_KEY_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "credential",
    "private_key",
    "api_key",
    "signing_key",
)


@dataclass(frozen=True)
class SecretReference:
    """Reference to a secret without carrying the secret value in config."""

    name: str
    key: str = ""
    provider: str = "env"


class SecretProvider(Protocol):
    """Fetch secrets from a replaceable backend."""

    def get_secret(self, reference: SecretReference) -> str:
        """Return the secret value or raise a clear error."""


class EnvironmentSecretProvider:
    """Development provider backed by environment variables."""

    def get_secret(self, reference: SecretReference) -> str:
        value = os.environ.get(reference.name)
        if value is None:
            raise KeyError(f"Missing environment secret: {reference.name}")
        return value


class SecretReferenceProvider:
    """Provider for Docker/Kubernetes secret references.

    It validates that a reference exists, but deliberately does not expose a
    plaintext value.  Runtime sidecars or mounted files can implement the same
    protocol for real deployments.
    """

    def get_secret(self, reference: SecretReference) -> str:
        if not reference.name:
            raise KeyError("Secret reference name is required")
        return f"secretref://{reference.provider}/{reference.name}/{reference.key}"


def redact(value: Any) -> Any:
    """Return a recursively redacted copy of diagnostic data."""
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            lower = str(key).lower()
            if any(part in lower for part in SENSITIVE_KEY_PARTS):
                redacted[key] = "<redacted>"
            else:
                redacted[key] = redact(item)
        return redacted
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact(item) for item in value)
    return value


def validate_no_plaintext_secrets(config: dict[str, Any]) -> list[str]:
    """Return paths that appear to contain committed plaintext secrets."""
    findings: list[str] = []

    def visit(prefix: str, data: Any) -> None:
        if isinstance(data, dict):
            for key, item in data.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                lower = str(key).lower()
                if any(part in lower for part in SENSITIVE_KEY_PARTS):
                    if isinstance(item, str) and item and not item.startswith("${"):
                        findings.append(path)
                visit(path, item)
        elif isinstance(data, list):
            for index, item in enumerate(data):
                visit(f"{prefix}[{index}]", item)

    visit("", config)
    return findings
