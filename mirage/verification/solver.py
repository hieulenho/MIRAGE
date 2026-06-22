"""Replaceable bounded constraint solver backend."""

from __future__ import annotations

import time
from typing import Any, Protocol

from mirage.verification.schema import SolverResult


class ConstraintSolverBackend(Protocol):
    """Solver backend interface."""

    def check(self, specification: dict[str, Any], facts: dict[str, Any]) -> SolverResult:
        """Check a bounded specification against facts."""


class DeterministicConstraintSolverBackend:
    """Small deterministic solver facade used when z3 is unavailable."""

    def __init__(self, timeout_ms: int = 50) -> None:
        self.timeout_ms = int(timeout_ms)

    def check(self, specification: dict[str, Any], facts: dict[str, Any]) -> SolverResult:
        start = time.perf_counter()
        if facts.get("force_timeout"):
            return SolverResult(
                status="UNKNOWN",
                solver_duration_ms=float(self.timeout_ms),
                timeout=True,
                counterexample={"reason": "solver_timeout"},
            )
        violated: list[str] = []
        model: dict[str, Any] = {}
        for item in specification.get("constraints", []):
            name = str(item.get("name", "constraint"))
            op = str(item.get("op", "eq"))
            left = facts.get(str(item.get("fact")))
            right = item.get("value")
            if not _holds(left, op, right):
                violated.append(name)
                model[name] = {"actual": left, "expected": right, "op": op}
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            if elapsed_ms > self.timeout_ms:
                return SolverResult(
                    status="UNKNOWN",
                    violated_constraints=violated,
                    model=model,
                    solver_duration_ms=round(elapsed_ms, 3),
                    timeout=True,
                )
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return SolverResult(
            status="UNSAT" if violated else "SAT",
            violated_constraints=violated,
            model=model,
            counterexample=model if violated else {},
            solver_duration_ms=round(elapsed_ms, 3),
            timeout=False,
        )


def _holds(left: Any, op: str, right: Any) -> bool:
    if op == "eq":
        return left == right
    if op == "neq":
        return left != right
    if op == "lte":
        return float(left) <= float(right)
    if op == "gte":
        return float(left) >= float(right)
    if op == "in":
        return left in set(right or [])
    if op == "subset":
        return set(left or []).issubset(set(right or []))
    if op == "disjoint":
        return set(left or []).isdisjoint(set(right or []))
    raise ValueError(f"Unsupported solver operation: {op}")
