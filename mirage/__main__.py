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
            "execution-status,rollback,kill-switch,connectors,casm,shadow,twin,gnn,rl} "
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
    print(f"Unknown MIRAGE command: {command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
