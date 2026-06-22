"""Administrative CLI for production hardening workflows."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from mirage.config import load_config, resolve_project_path
from mirage.governance.audit import GovernanceAuditStore
from mirage.production.backup import BackupManager
from mirage.production.config import validate_production_config
from mirage.production.deployment import LimitedDeploymentController
from mirage.production.health import DependencyChecker, build_health_report
from mirage.production.migrations import MigrationManager
from mirage.production.schema import DeploymentLevel, EnvironmentProfile, ScopeContext, UserIdentity
from mirage.production.storage import SQLiteProductionRepository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mirage production-ops")
    sub = parser.add_subparsers(dest="area", required=True)
    _add_production(sub.add_parser("production"))
    _add_storage(sub.add_parser("storage"))
    _add_backup(sub.add_parser("backup"))
    _add_restore(sub.add_parser("restore"))
    _add_audit(sub.add_parser("audit"))
    _add_operations(sub.add_parser("operations"))
    args = parser.parse_args(argv)

    config = load_config()
    if args.area == "production":
        return _run_production(args, config)
    if args.area == "storage":
        return _run_storage(args, config)
    if args.area == "backup":
        return _run_backup(args, config)
    if args.area == "restore":
        return _run_restore(args, config)
    if args.area == "audit":
        return _run_audit(args, config)
    if args.area == "operations":
        return _run_operations(args, config)
    return 2


def _add_production(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("validate-config")
    sub.add_parser("dependencies")
    sub.add_parser("readiness")
    sub.add_parser("deployment-level")
    set_level = sub.add_parser("set-deployment-level")
    set_level.add_argument("--level", required=True, choices=[level.value for level in DeploymentLevel])
    set_level.add_argument("--actor", required=True)
    set_level.add_argument("--role", required=True)
    set_level.add_argument("--reason", required=True)
    set_level.add_argument("--expires-in-seconds", type=int, default=3600)


def _add_storage(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    migrate = sub.add_parser("migrate")
    migrate.add_argument("--dry-run", action="store_true")
    migrate.add_argument("--backup-confirmed", action="store_true")
    sub.add_parser("status")


def _add_backup(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--backup-id", default="")
    verify = sub.add_parser("verify")
    verify.add_argument("--backup-id", required=True)
    sub.add_parser("list")


def _add_restore(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--backup-id", required=True)
    run = sub.add_parser("run")
    run.add_argument("--backup-id", required=True)
    run.add_argument("--dry-run", action="store_true")


def _add_audit(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--audit", default="")


def _add_operations(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("active-executions")
    sub.add_parser("pending-rollbacks")
    pause = sub.add_parser("pause-automation")
    pause.add_argument("--reason", default="operator requested")
    sub.add_parser("resume-shadow")


def _run_production(args: argparse.Namespace, config: dict[str, Any]) -> int:
    if args.command == "validate-config":
        _print(validate_production_config(config).model_dump(mode="json"))
        return 0
    if args.command in {"dependencies", "readiness"}:
        checker = DependencyChecker(_dependency_checks(config))
        _print(build_health_report(config, dependencies=checker).model_dump(mode="json"))
        return 0
    controller = _deployment_controller(config)
    if args.command == "deployment-level":
        _print(controller.get_level().model_dump(mode="json"))
        return 0
    if args.command == "set-deployment-level":
        identity = UserIdentity(
            subject=args.actor,
            roles=[args.role],
            environment=_profile(config),
        )
        record = controller.set_level(
            DeploymentLevel(args.level),
            actor=identity,
            reason=args.reason,
            expires_in_seconds=args.expires_in_seconds,
        )
        _print(record.model_dump(mode="json"))
        return 0
    return 2


def _run_storage(args: argparse.Namespace, config: dict[str, Any]) -> int:
    manager = MigrationManager(_storage_path(config))
    if args.command == "status":
        _print(manager.status())
        return 0
    result = manager.migrate(
        dry_run=args.dry_run,
        backup_confirmed=args.backup_confirmed,
    )
    _print(result.model_dump(mode="json"))
    return 0


def _run_backup(args: argparse.Namespace, config: dict[str, Any]) -> int:
    manager = BackupManager(_repository(config), _backup_dir(config))
    if args.command == "create":
        manifest = manager.create(backup_id=args.backup_id or None)
        _print(manifest.model_dump(mode="json"))
        return 0
    if args.command == "verify":
        _print(manager.verify(args.backup_id))
        return 0
    _print({"backups": [item.model_dump(mode="json") for item in manager.list_backups()]})
    return 0


def _run_restore(args: argparse.Namespace, config: dict[str, Any]) -> int:
    manager = BackupManager(_repository(config), _backup_dir(config))
    if args.command == "validate":
        _print(manager.restore_validate(args.backup_id))
        return 0
    _print(manager.restore_run(args.backup_id, dry_run=args.dry_run))
    return 0


def _run_audit(args: argparse.Namespace, config: dict[str, Any]) -> int:
    audit_path = args.audit or config.get("production", {}).get("audit", {}).get(
        "path",
        "artifacts/production/audit.jsonl",
    )
    store = GovernanceAuditStore(resolve_project_path(audit_path))
    _print(store.verify_chain())
    return 0


def _run_operations(args: argparse.Namespace, config: dict[str, Any]) -> int:
    controller = _deployment_controller(config)
    repo = _repository(config)
    scope = _scope(config)
    if args.command == "active-executions":
        _print({"executions": [item.model_dump(mode="json") for item in repo.list_records("executions", scope=scope)]})
        return 0
    if args.command == "pending-rollbacks":
        rollbacks = [
            item.model_dump(mode="json")
            for item in repo.list_records("executions", scope=scope)
            if item.payload.get("state") in {"failed", "rolled_back", "rollback_pending"}
        ]
        _print({"executions": rollbacks})
        return 0
    if args.command == "pause-automation":
        _print(controller.reduce_to_shadow(reason=args.reason).model_dump(mode="json"))
        return 0
    if args.command == "resume-shadow":
        _print(controller.reduce_to_shadow(reason="resume_shadow").model_dump(mode="json"))
        return 0
    return 2


def _dependency_checks(config: dict[str, Any]) -> dict[str, Any]:
    storage = _repository(config)
    audit_path = resolve_project_path(
        config.get("production", {}).get("audit", {}).get("path", "artifacts/production/audit.jsonl")
    )
    return {
        "database": storage.ping,
        "audit_storage": lambda: audit_path.parent.exists(),
        "governance_store": storage.ping,
        "event_bus": lambda: bool(config.get("production", {}).get("event_transport", {})),
        "model_registry": lambda: Path("models").exists(),
    }


def _repository(config: dict[str, Any]) -> SQLiteProductionRepository:
    return SQLiteProductionRepository(_storage_path(config))


def _storage_path(config: dict[str, Any]) -> Path:
    value = config.get("production", {}).get("storage", {}).get(
        "sqlite_path",
        "artifacts/production/mirage.db",
    )
    return resolve_project_path(value)


def _backup_dir(config: dict[str, Any]) -> Path:
    return resolve_project_path(
        config.get("production", {}).get("backup_dir", "artifacts/production/backups")
    )


def _profile(config: dict[str, Any]) -> EnvironmentProfile:
    return EnvironmentProfile(config.get("production", {}).get("profile", "shadow"))


def _scope(config: dict[str, Any]) -> ScopeContext:
    return ScopeContext(environment=_profile(config))


def _deployment_controller(config: dict[str, Any]) -> LimitedDeploymentController:
    return LimitedDeploymentController(_repository(config), scope=_scope(config))


def _print(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
