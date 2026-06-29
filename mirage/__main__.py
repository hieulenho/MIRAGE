"""MIRAGE package command entry point."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    """Dispatch package-level commands such as `python -m mirage replay`."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print(
            "Usage: python -m mirage "
            "{replay,detect,analyze-paths,safety-check,execute-plan,"
            "execution-status,rollback,kill-switch,connectors,casm,shadow,twin,gnn,rl,marl,"
            "verify,governance,pilot,production,storage,backup,restore,audit,operations,"
            "inventory,sites,federation,assurance,validation,slo,capacity,maturity,readiness} "
            "[options]"
        )
        return 0
    command = args.pop(0)
    if command == "replay":
        from mirage.replay import main as replay_main

        return replay_main(args)
    if command == "detect":
        from mirage.detect import main as detect_main

        return detect_main(args)
    if command == "analyze-paths":
        from mirage.analyze_paths import main as analyze_main

        return analyze_main(args)
    if command in {
        "safety-check",
        "execute-plan",
        "execution-status",
        "rollback",
        "kill-switch",
    }:
        from mirage.execution_cli import main as execution_main

        return execution_main([command, *args])
    if command in {"connectors", "casm", "shadow", "twin"}:
        from mirage.m5_cli import main as m5_main

        return m5_main([command, *args])
    if command == "gnn":
        from mirage.gnn.cli import main as gnn_main

        return gnn_main(args)
    if command == "rl":
        from mirage.rl.cli import main as rl_main

        return rl_main(args)
    if command == "marl":
        from mirage.marl.cli import main as marl_main

        return marl_main(args)
    if command == "verify":
        from mirage.verification.cli import main as verify_main

        return verify_main(args)
    if command == "governance":
        from mirage.governance.cli import main as governance_main

        return governance_main(args)
    if command == "pilot":
        from mirage.pilot.cli import main as pilot_main

        return pilot_main(args)
    if command in {"production", "storage", "backup", "restore", "audit", "operations"}:
        from mirage.production.cli import main as production_main

        return production_main([command, *args])
    if command in {
        "inventory",
        "sites",
        "federation",
        "assurance",
        "validation",
        "slo",
        "capacity",
        "maturity",
        "readiness",
    }:
        from mirage.milestone11.cli import main as milestone11_main

        return milestone11_main([command, *args])
    print(f"Unknown MIRAGE command: {command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
