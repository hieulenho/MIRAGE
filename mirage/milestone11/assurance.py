"""Continuous assurance evidence generation for Milestone 11."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mirage.config import PROJECT_ROOT, load_config, resolve_project_path
from mirage.governance.audit import GovernanceAuditStore
from mirage.governance.integrity import sha256_json
from mirage.marl.schema import RangeIsolationConfig
from mirage.milestone11.federation import FederationPolicyEngine
from mirage.milestone11.inventory import InventoryScanner
from mirage.milestone11.schema import (
    AssuranceBundle,
    AssuranceCheckResult,
    AssuranceSeverity,
    FederationTransferRequest,
)
from mirage.production.backup import BackupManager
from mirage.production.config import validate_production_config
from mirage.production.schema import ScopeContext
from mirage.production.storage import InMemoryProductionRepository


class ContinuousAssuranceService:
    """Run deterministic assurance checks and produce hash-verifiable bundles."""

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        *,
        root: Path | None = None,
    ) -> None:
        self.config = config if config is not None else load_config()
        self.root = (root or PROJECT_ROOT).resolve()
        self.bundle_dir = resolve_project_path(
            self.config.get("assurance", {}).get(
                "bundle_path",
                "artifacts/assurance/bundles",
            )
        )
        self.bundle_dir.mkdir(parents=True, exist_ok=True)
        self._last_bundle: AssuranceBundle | None = None

    def run(self) -> AssuranceBundle:
        """Run all configured checks and write an evidence bundle."""
        checks = [
            self._check_safety_defaults(),
            self._check_inventory_available(),
            self._check_production_config(),
            self._check_governance_audit_chain(),
            self._check_backup_restore(),
            self._check_model_and_policy_cards(),
            self._check_cyber_range_isolation(),
            self._check_federation_default_deny(),
        ]
        evidence_hashes = {
            check.check_id: sha256_json(check.model_dump(mode="json"))
            for check in checks
        }
        critical_failed = any(
            not check.passed and check.severity == AssuranceSeverity.CRITICAL
            for check in checks
        )
        content = {
            "checks": [check.model_dump(mode="json") for check in checks],
            "evidence_hashes": evidence_hashes,
            "deployment_reduction_required": critical_failed,
            "readiness_blocked": critical_failed,
        }
        bundle_hash = sha256_json(content)
        bundle = AssuranceBundle(
            bundle_id=f"assurance_{bundle_hash[:16]}",
            checks=checks,
            evidence_hashes=evidence_hashes,
            bundle_hash=bundle_hash,
            deployment_reduction_required=critical_failed,
            readiness_blocked=critical_failed,
        )
        self._write_bundle(bundle)
        self._last_bundle = bundle
        return bundle

    def list_bundles(self) -> list[dict[str, Any]]:
        """Return bundle manifests sorted by bundle ID."""
        bundles = []
        for path in sorted(self.bundle_dir.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            bundles.append(
                {
                    "bundle_id": data["bundle_id"],
                    "created_at": data["created_at"],
                    "bundle_hash": data["bundle_hash"],
                    "readiness_blocked": data["readiness_blocked"],
                    "deployment_reduction_required": data["deployment_reduction_required"],
                }
            )
        return bundles

    def get_bundle(self, bundle_id: str) -> AssuranceBundle:
        """Read one bundle by ID."""
        path = self.bundle_dir / f"{bundle_id}.json"
        if not path.exists():
            raise KeyError(bundle_id)
        return AssuranceBundle.model_validate_json(path.read_text(encoding="utf-8"))

    def verify_bundle(self, bundle_id: str) -> dict[str, Any]:
        """Verify one stored bundle hash."""
        bundle = self.get_bundle(bundle_id)
        content = {
            "checks": [check.model_dump(mode="json") for check in bundle.checks],
            "evidence_hashes": bundle.evidence_hashes,
            "deployment_reduction_required": bundle.deployment_reduction_required,
            "readiness_blocked": bundle.readiness_blocked,
        }
        expected = sha256_json(content)
        return {
            "bundle_id": bundle_id,
            "valid": expected == bundle.bundle_hash,
            "expected_hash": expected,
            "bundle_hash": bundle.bundle_hash,
        }

    def checks(self) -> list[dict[str, Any]]:
        """Run checks without creating a bundle."""
        return [
            check.model_dump(mode="json")
            for check in [
                self._check_safety_defaults(),
                self._check_inventory_available(),
                self._check_production_config(),
                self._check_governance_audit_chain(),
                self._check_backup_restore(),
                self._check_model_and_policy_cards(),
                self._check_cyber_range_isolation(),
                self._check_federation_default_deny(),
            ]
        ]

    def status(self) -> dict[str, Any]:
        """Return public-safe assurance status."""
        bundles = self.list_bundles()
        latest = bundles[-1] if bundles else None
        return {
            "bundle_count": len(bundles),
            "last_bundle": latest,
            "operational_maturity_signal": "blocked" if latest and latest["readiness_blocked"] else "collecting_evidence",
        }

    def latest_bundle(self) -> AssuranceBundle | None:
        """Return the latest in-memory or persisted bundle."""
        if self._last_bundle is not None:
            return self._last_bundle
        bundles = self.list_bundles()
        if not bundles:
            return None
        return self.get_bundle(bundles[-1]["bundle_id"])

    def _write_bundle(self, bundle: AssuranceBundle) -> None:
        path = self.bundle_dir / f"{bundle.bundle_id}.json"
        path.write_text(
            json.dumps(bundle.model_dump(mode="json"), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _check_safety_defaults(self) -> AssuranceCheckResult:
        production = self.config.get("production", {})
        marl = self.config.get("marl", {})
        findings = []
        expected = {
            "production.production_execution_enabled": False,
            "production.high_risk_automation_enabled": False,
            "production.action_mask_required": True,
            "production.safety_gate_required": True,
            "production.formal_verification_required": True,
            "production.governance_gate_required": True,
            "marl.cyber_range_only": True,
            "marl.red_agent_external_network": False,
            "marl.real_exploitation_enabled": False,
        }
        observed = {
            "production.production_execution_enabled": production.get("production_execution_enabled"),
            "production.high_risk_automation_enabled": production.get("high_risk_automation_enabled"),
            "production.action_mask_required": production.get("action_mask_required"),
            "production.safety_gate_required": production.get("safety_gate_required"),
            "production.formal_verification_required": production.get("formal_verification_required"),
            "production.governance_gate_required": production.get("governance_gate_required"),
            "marl.cyber_range_only": marl.get("cyber_range_only"),
            "marl.red_agent_external_network": marl.get("red_agent_external_network"),
            "marl.real_exploitation_enabled": marl.get("real_exploitation_enabled"),
        }
        for key, value in expected.items():
            if observed.get(key) != value:
                findings.append(f"{key} expected {value!r}, observed {observed.get(key)!r}")
        return AssuranceCheckResult(
            check_id="safety_defaults",
            name="Mandatory safety defaults",
            passed=not findings,
            severity=AssuranceSeverity.CRITICAL,
            evidence_refs=["config"],
            details={"findings": findings, "observed": observed},
            remediation="Restore mandatory shadow-mode and safety-gate defaults.",
        )

    def _check_inventory_available(self) -> AssuranceCheckResult:
        inventory = InventoryScanner(self.root, self.config).scan()
        non_implemented = [
            item.capability_id
            for item in inventory.capabilities
            if item.implementation_status.value != "IMPLEMENTED"
        ]
        return AssuranceCheckResult(
            check_id="verified_inventory",
            name="Verified repository inventory",
            passed=bool(inventory.capabilities),
            severity=AssuranceSeverity.ERROR,
            evidence_refs=["artifacts/inventory/system_inventory.json"],
            details={
                "capability_count": len(inventory.capabilities),
                "status_counts": inventory.totals.by_status,
                "non_implemented_capabilities": non_implemented[:30],
            },
            remediation="Generate inventory and remediate non-implemented capabilities before readiness expansion.",
        )

    def _check_production_config(self) -> AssuranceCheckResult:
        report = validate_production_config(self.config)
        return AssuranceCheckResult(
            check_id="production_config",
            name="Production safety configuration",
            passed=report.valid,
            severity=AssuranceSeverity.CRITICAL,
            evidence_refs=["config.production"],
            details=report.model_dump(mode="json"),
            remediation="Fix production configuration findings before startup or deployment-level expansion.",
        )

    def _check_governance_audit_chain(self) -> AssuranceCheckResult:
        path = resolve_project_path(
            self.config.get("governance", {}).get(
                "audit_path",
                "artifacts/governance_audit.jsonl",
            )
        )
        store = GovernanceAuditStore(path)
        result = store.verify_chain()
        return AssuranceCheckResult(
            check_id="governance_audit_chain",
            name="Governance audit hash chain",
            passed=bool(result.get("valid")),
            severity=AssuranceSeverity.CRITICAL,
            evidence_refs=[str(path)],
            details=result,
            remediation="Investigate audit tampering or rebuild from immutable export; keep sensitive execution suspended.",
        )

    def _check_backup_restore(self) -> AssuranceCheckResult:
        backup_dir = resolve_project_path(
            self.config.get("assurance", {}).get(
                "backup_rehearsal_path",
                "artifacts/assurance/backups",
            )
        )
        repo = InMemoryProductionRepository()
        manager = BackupManager(repo, backup_dir)
        backup_id = "assurance_rehearsal"
        repo.upsert("assurance", "probe", {"ok": True}, scope=ScopeContext())
        manifest = manager.create(backup_id=backup_id)
        verification = manager.verify(backup_id)
        restore = manager.restore_validate(backup_id)
        passed = verification["valid"] and restore["restorable"]
        return AssuranceCheckResult(
            check_id="backup_restore_rehearsal",
            name="Backup verification and restore rehearsal",
            passed=passed,
            severity=AssuranceSeverity.CRITICAL,
            evidence_refs=[str(backup_dir / f"{backup_id}.json")],
            details={
                "manifest": manifest.model_dump(mode="json"),
                "verification": verification,
                "restore": restore,
            },
            remediation="Restore rehearsal must pass before sustained deployment.",
        )

    def _check_model_and_policy_cards(self) -> AssuranceCheckResult:
        registry_path = resolve_project_path(
            self.config.get("governance", {}).get(
                "registry_path",
                "models/governance_registry.json",
            )
        )
        exists = registry_path.exists()
        details: dict[str, Any] = {"registry_path": str(registry_path), "exists": exists}
        if exists:
            try:
                details["registry_keys"] = sorted(json.loads(registry_path.read_text(encoding="utf-8")).keys())
            except (json.JSONDecodeError, OSError) as exc:
                details["error"] = str(exc)
        return AssuranceCheckResult(
            check_id="model_policy_cards",
            name="Model and policy card registry",
            passed=exists,
            severity=AssuranceSeverity.WARNING,
            evidence_refs=[str(registry_path)],
            details=details,
            remediation="Register model and policy cards with hashes before model-influenced deployment expansion.",
        )

    def _check_cyber_range_isolation(self) -> AssuranceCheckResult:
        try:
            isolation = RangeIsolationConfig.model_validate(self.config.get("marl", {}))
            violations = isolation.violations()
        except ValueError as exc:
            violations = [str(exc)]
        return AssuranceCheckResult(
            check_id="cyber_range_isolation",
            name="Cyber Range isolation",
            passed=not violations,
            severity=AssuranceSeverity.CRITICAL,
            evidence_refs=["config.marl"],
            details={"violations": violations},
            remediation="Stop MARL/range jobs and restore cyber_range_only, no production connectivity, no external network, and shadow Blue mode.",
        )

    def _check_federation_default_deny(self) -> AssuranceCheckResult:
        engine = FederationPolicyEngine(config=self.config)
        local = engine.registry.local_site_id
        denied = engine.validate_transfer(
            request=FederationTransferRequest(
                message_id="assurance-probe",
                source_site_id=local,
                destination_site_id=local,
                data_class="RAW_CREDENTIALS",
                payload={"credential": "secret"},
            ),
            record_duplicate=False,
        )
        return AssuranceCheckResult(
            check_id="federation_default_deny",
            name="Federation denies prohibited data by default",
            passed=not denied.allowed,
            severity=AssuranceSeverity.CRITICAL,
            evidence_refs=["config.federation"],
            details=denied.model_dump(mode="json"),
            remediation="Deny prohibited federation classes and fields by default.",
        )
