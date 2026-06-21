"""Milestone 7 offline RL package for MIRAGE.

The package is intentionally additive.  It never replaces action masks,
Safety Gate decisions, Shadow Mode, or the existing robust decision engine.
"""

from mirage.rl.schema import (
    BlueTeamTactic,
    CandidateActionFeature,
    EncodedRLState,
    OfflineRLDatasetManifest,
    PolicyInferenceResult,
    RLStateReference,
    RLTrajectory,
    RLTransition,
    RewardBreakdown,
)

__all__ = [
    "BlueTeamTactic",
    "CandidateActionFeature",
    "EncodedRLState",
    "OfflineRLDatasetManifest",
    "PolicyInferenceResult",
    "RLStateReference",
    "RLTrajectory",
    "RLTransition",
    "RewardBreakdown",
]

