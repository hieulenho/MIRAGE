"""Self-contained compatibility utilities for MIRAGE optimization."""

from mirage.utils.mdp_model import AttackGraphMDP, InterventionSite
from mirage.utils.robust_reward_design import (
    RobustRewardDesignResult,
    solve_max_margin_reward_design,
)

__all__ = [
    "AttackGraphMDP",
    "InterventionSite",
    "RobustRewardDesignResult",
    "solve_max_margin_reward_design",
]
