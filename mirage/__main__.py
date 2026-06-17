"""MIRAGE package command entry point."""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    """Dispatch package-level commands such as `python -m mirage replay`."""
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print("Usage: python -m mirage {replay,detect} [options]")
        return 0
    command = args.pop(0)
    if command == "replay":
        from mirage.replay import main as replay_main

        return replay_main(args)
    if command == "detect":
        from mirage.detect import main as detect_main

        return detect_main(args)
    print(f"Unknown MIRAGE command: {command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
