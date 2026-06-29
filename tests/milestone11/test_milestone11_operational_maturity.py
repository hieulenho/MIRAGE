from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.config import DEFAULT_CONFIG, load_config
from mirage.milestone11.assurance import ContinuousAssuranceService
from mirage.milestone11.federation import FederationService
from mirage.milestone11.inventory import InventoryScanner
from mirage.milestone11.readiness import OperationalMaturityService
from mirage.milestone11.schema import (
    FederationTransferRequest,
    ReadinessEvaluationRequest,
)
from mirage.milestone11.validation import ValidationService


def test_inventory_is_deterministic_and_evidence_backed() -> None:
    scanner = InventoryScanner(config=load_config())

    first = scanner.scan().model_dump(mode="json")
    second = scanner.scan().model_dump(mode="json")

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["generated_at"] == "1970-01-01T00:00:00Z"
    assert first["totals"]["capability_count"] >= 40
    assert "M11-FEDERATION" in {item["capability_id"] for item in first["capabilities"]}
    assert first["known_gaps"]
    assert any(route["route"] == "/api/v1/inventory" for route in first["api_routes"])


def test_federation_denies_by_default_and_pseudonymizes_allowed_summary() -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["federation"]["mode"] = "enabled"
    config["sites"]["registered"] = [
        {
            "site_id": "site-b",
            "tenant_id": "default",
            "display_name": "Site B",
            "data_residency_zone": "local",
            "policy_version": "federation-policy-v1",
            "endpoint": "https://site-b.example.invalid/federation",
            "public_identity": "site-b-identity",
        }
    ]
    service = FederationService(config)

    allowed = service.validate_transfer(
        FederationTransferRequest(
            message_id="msg-1",
            source_site_id="site-local",
            destination_site_id="site-b",
            data_class="PSEUDONYMIZED_ENTITY_DATA",
            payload={"entity_id": "host-01", "username": "alice", "summary": "lateral movement"},
        )
    )
    assert allowed["allowed"] is True
    assert allowed["sanitized_payload"]["entity_id"].startswith("pseudonym:")
    assert allowed["sanitized_payload"]["username"].startswith("pseudonym:")

    duplicate = service.validate_transfer(
        FederationTransferRequest(
            message_id="msg-1",
            source_site_id="site-local",
            destination_site_id="site-b",
            data_class="PSEUDONYMIZED_ENTITY_DATA",
            payload={"entity_id": "host-01"},
        )
    )
    assert duplicate["allowed"] is False
    assert "duplicate" in duplicate["reason"]

    prohibited = service.validate_transfer(
        FederationTransferRequest(
            message_id="msg-2",
            source_site_id="site-local",
            destination_site_id="site-b",
            data_class="PSEUDONYMIZED_ENTITY_DATA",
            payload={"credential": "secret"},
        )
    )
    assert prohibited["allowed"] is False
    assert prohibited["denied_fields"] == ["credential"]

    cross_tenant = service.validate_transfer(
        FederationTransferRequest(
            message_id="msg-3",
            source_site_id="site-local",
            destination_site_id="site-b",
            tenant_id="tenant-b",
            data_class="SUMMARY_INCIDENT",
            payload={"summary": "x"},
        )
    )
    assert cross_tenant["allowed"] is False
    assert "cross-tenant" in cross_tenant["reason"]


def test_assurance_bundle_is_hash_verifiable(tmp_path: Path) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["assurance"]["bundle_path"] = str(tmp_path / "bundles")
    config["assurance"]["backup_rehearsal_path"] = str(tmp_path / "backups")

    service = ContinuousAssuranceService(config)
    bundle = service.run()

    assert bundle.bundle_id
    assert bundle.readiness_blocked is False
    assert service.verify_bundle(bundle.bundle_id)["valid"] is True
    assert any(check.check_id == "federation_default_deny" and check.passed for check in bundle.checks)


def test_validation_slo_capacity_maturity_and_readiness_are_restrictive(tmp_path: Path) -> None:
    config = deepcopy(DEFAULT_CONFIG)
    config["assurance"]["bundle_path"] = str(tmp_path / "bundles")
    config["assurance"]["backup_rehearsal_path"] = str(tmp_path / "backups")
    service = OperationalMaturityService(config)

    assurance = service.assurance.run()
    soak = service.validation.run_soak(duration="6h", profile="ci")
    chaos = service.validation.run_chaos(experiment="leader-failure", environment="staging")
    slo = service.slo.report()
    capacity = service.capacity.report()
    maturity = service.maturity.assess()
    readiness = service.readiness.evaluate(ReadinessEvaluationRequest(target_deployment_level="SHADOW_ONLY"))

    assert assurance.readiness_blocked is False
    assert soak.status == "succeeded"
    assert soak.metrics["requested_duration_seconds"] == 21600
    assert soak.metrics["effective_duration_seconds"] == config["validation"]["ci_max_soak_seconds"]
    assert chaos.status == "succeeded"
    assert slo.release_blocked is False
    assert "synthetic defaults are not enterprise-scale proof" in capacity.limitations
    assert 0.0 <= maturity.overall_score <= 1.0
    assert readiness.verdict in {"RETURN_TO_SHADOW_MODE", "INSUFFICIENT_EVIDENCE"}


def test_milestone11_api_endpoints_are_public_safe() -> None:
    client = TestClient(create_app())

    assert client.get("/api/v1/federation/status").status_code == 200
    assert client.get("/api/v1/sites").json()["sites"][0]["site_id"] == "site-local"
    assert client.get("/api/v1/slo/error-budgets").status_code == 200

    readiness = client.post(
        "/api/v1/readiness/evaluate",
        json={"target_deployment_level": "SHADOW_ONLY"},
    )
    assert readiness.status_code == 200
    assert readiness.json()["target_deployment_level"] == "SHADOW_ONLY"
