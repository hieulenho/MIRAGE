"""Dependency-free reward allocation for portable MIRAGE MDP models."""

from __future__ import annotations

import itertools
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Tuple

from mirage.mdp_solver import MDPSolver
from mirage.utils.mdp_model import AttackGraphMDP, InterventionSite


@dataclass(frozen=True)
class RobustRewardDesignResult:
    """Result compatible with the original external reward-design solver."""

    x_ip: Dict[str, float]
    c_star: float
    v1_star: float
    solver_status: str
    objective_evaluations: int


def _weighted_start_value(
    solver: MDPSolver,
    interventions: Dict[Tuple[int, str], float],
) -> float:
    values = solver.solve_value_function(interventions)
    return sum(
        probability * values.get(state, 0.0)
        for state, probability in solver.graph.start_distribution.items()
    )


def _rank_sites(
    solver: MDPSolver,
    sites: Iterable[InterventionSite],
) -> List[InterventionSite]:
    occupancy = solver.compute_occupancy_measure()
    state_occupancy: Dict[int, float] = {}
    for (state, _), value in occupancy.items():
        state_occupancy[state] = state_occupancy.get(state, 0.0) + value
    return sorted(
        sites,
        key=lambda site: (
            -state_occupancy.get(site.state, 0.0),
            site.state,
            site.action,
            site.name,
        ),
    )


def solve_max_margin_reward_design(
    mdp: AttackGraphMDP,
    solver_msg: bool = False,
    time_limit_seconds: float = 30,
    max_subset_size: int = 3,
    max_evaluations: int = 256,
) -> RobustRewardDesignResult:
    """
    Allocate non-negative reward bait under an L1 budget.

    The dependency-free solver enumerates full-budget, equal-split portfolios
    up to ``max_subset_size`` and evaluates the attacker's exact greedy best
    response with MIRAGE's Bellman solver. It is exhaustive when all sites fit
    within that bound; larger models are occupancy-ranked and explicitly
    reported as heuristic rather than mislabeled as MILP-optimal.
    """
    if not isinstance(mdp, AttackGraphMDP):
        raise TypeError("mdp must be an AttackGraphMDP")
    if time_limit_seconds <= 0:
        raise ValueError("time_limit_seconds must be positive")
    if max_subset_size < 1:
        raise ValueError("max_subset_size must be at least 1")
    if max_evaluations < 1:
        raise ValueError("max_evaluations must be at least 1")

    graph = mdp.to_mirage_graph()
    solver = MDPSolver(graph)
    sites = _rank_sites(solver, mdp.interventions)
    zero_allocation = {site.name: 0.0 for site in sites}
    baseline = _weighted_start_value(solver, {})

    if not sites:
        return RobustRewardDesignResult(
            x_ip=zero_allocation,
            c_star=0.0,
            v1_star=baseline,
            solver_status="NO_INTERVENTIONS",
            objective_evaluations=1,
        )
    if mdp.budget <= 0:
        return RobustRewardDesignResult(
            x_ip=zero_allocation,
            c_star=0.0,
            v1_star=baseline,
            solver_status="ZERO_BUDGET",
            objective_evaluations=1,
        )

    started = time.perf_counter()
    best_score = baseline
    best_allocation = zero_allocation
    evaluations = 1
    timed_out = False
    truncated = False
    subset_limit = min(len(sites), max_subset_size)

    for subset_size in range(1, subset_limit + 1):
        for subset in itertools.combinations(sites, subset_size):
            if evaluations >= max_evaluations:
                truncated = True
                break
            if time.perf_counter() - started >= time_limit_seconds:
                timed_out = True
                break

            amount = float(mdp.budget) / subset_size
            state_action_allocation = {
                (site.state, site.action): amount
                for site in subset
            }
            score = _weighted_start_value(solver, state_action_allocation)
            evaluations += 1

            candidate = dict(zero_allocation)
            for site in subset:
                candidate[site.name] = amount
            if score > best_score + 1e-12:
                best_score = score
                best_allocation = candidate
            elif abs(score - best_score) <= 1e-12:
                best_active = sum(value > 0 for value in best_allocation.values())
                candidate_active = sum(value > 0 for value in candidate.values())
                if candidate_active < best_active:
                    best_allocation = candidate
        if timed_out or truncated:
            break

    exhaustive_candidates = (
        not timed_out
        and not truncated
        and len(sites) <= max_subset_size
    )
    if timed_out:
        status = "TIME_LIMIT_FEASIBLE"
    elif exhaustive_candidates:
        status = "EXHAUSTIVE_CANDIDATES"
    else:
        status = "HEURISTIC_ENUMERATED"

    result = RobustRewardDesignResult(
        x_ip=best_allocation,
        c_star=best_score - baseline,
        v1_star=best_score,
        solver_status=status,
        objective_evaluations=evaluations,
    )
    if solver_msg:
        print(
            f"[reward-design] status={status} evaluations={evaluations} "
            f"margin={result.c_star:+.6f}"
        )
    return result
