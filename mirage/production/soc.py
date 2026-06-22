"""SOC integration adapter interfaces and safe mock/webhook implementations."""

from __future__ import annotations

import json
import urllib.request
from typing import Any, Protocol

from pydantic import BaseModel, Field

from mirage.production.secrets import redact


class SOCIncident(BaseModel):
    """Minimized incident payload for SOC tooling."""

    incident_id: str
    summary: str
    affected_entities: list[str] = Field(default_factory=list)
    attack_stage: str = ""
    top_paths: list[str] = Field(default_factory=list)
    recommendation: str = ""
    safety_verdict: str = ""
    verification_result: str = ""
    model_disagreement: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    twin_quality: dict[str, Any] = Field(default_factory=dict)
    approval_required: bool = True


class SOCIntegrationAdapter(Protocol):
    """Vendor-neutral SOC integration contract."""

    def create_case(self, incident: SOCIncident) -> dict[str, Any]:
        """Create a case or ticket."""

    def update_case(self, case_id: str, update: dict[str, Any]) -> dict[str, Any]:
        """Update a case."""

    def add_evidence(self, case_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        """Attach minimized evidence."""

    def request_approval(self, request: dict[str, Any]) -> dict[str, Any]:
        """Request human approval."""

    def publish_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        """Publish an alert to SOC or platform operations."""


class MockSOCAdapter:
    """Deterministic adapter for tests and local controlled pilots."""

    def __init__(self) -> None:
        self.cases: dict[str, dict[str, Any]] = {}
        self.alerts: list[dict[str, Any]] = []

    def create_case(self, incident: SOCIncident) -> dict[str, Any]:
        payload = redact(incident.model_dump(mode="json"))
        case_id = f"case-{incident.incident_id}"
        self.cases[case_id] = payload
        return {"case_id": case_id, "payload": payload}

    def update_case(self, case_id: str, update: dict[str, Any]) -> dict[str, Any]:
        safe_update = redact(update)
        self.cases.setdefault(case_id, {}).update(safe_update)
        return {"case_id": case_id, "updated": True}

    def add_evidence(self, case_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        safe_evidence = redact(evidence)
        self.cases.setdefault(case_id, {}).setdefault("evidence", []).append(safe_evidence)
        return {"case_id": case_id, "evidence_added": True}

    def request_approval(self, request: dict[str, Any]) -> dict[str, Any]:
        return {"approval_requested": True, "request": redact(request)}

    def publish_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        safe_alert = redact(alert)
        self.alerts.append(safe_alert)
        return {"published": True, "alert": safe_alert}


class GenericWebhookSOCAdapter:
    """Generic webhook adapter with dry-run default."""

    def __init__(self, webhook_url: str, *, dry_run: bool = True, timeout_seconds: int = 5) -> None:
        self.webhook_url = webhook_url
        self.dry_run = dry_run
        self.timeout_seconds = timeout_seconds

    def create_case(self, incident: SOCIncident) -> dict[str, Any]:
        return self._post("create_case", incident.model_dump(mode="json"))

    def update_case(self, case_id: str, update: dict[str, Any]) -> dict[str, Any]:
        return self._post("update_case", {"case_id": case_id, "update": update})

    def add_evidence(self, case_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        return self._post("add_evidence", {"case_id": case_id, "evidence": evidence})

    def request_approval(self, request: dict[str, Any]) -> dict[str, Any]:
        return self._post("request_approval", request)

    def publish_alert(self, alert: dict[str, Any]) -> dict[str, Any]:
        return self._post("publish_alert", alert)

    def _post(self, event_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = {"event_type": event_type, "payload": redact(payload)}
        if self.dry_run:
            return {"dry_run": True, "body": body}
        data = json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout_seconds) as response:
            return {"status": response.status, "body": response.read().decode("utf-8")}
