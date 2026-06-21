"""Milestone 8 adversarial self-play cyber range.

All red-team behavior in this package is synthetic graph simulation only.
There are no exploit payloads, network clients, shells, scanners, or
production-control paths.
"""

from mirage.marl.environment import CyberRangeEnvironment
from mirage.marl.schema import RangeIsolationConfig, RangeScenario

__all__ = [
    "CyberRangeEnvironment",
    "RangeIsolationConfig",
    "RangeScenario",
]
