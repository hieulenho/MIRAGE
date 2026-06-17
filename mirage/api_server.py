"""Backward-compatible entry point for the MIRAGE FastAPI server."""

from mirage.api.server import *  # noqa: F403

if __name__ == "__main__":
    from mirage.api.server import main

    main()

