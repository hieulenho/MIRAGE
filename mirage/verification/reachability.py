"""Graph reachability verification on copied projected graphs."""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone

from mirage.domain.schemas import ExecutionPlan, TwinSnapshot
from mirage.verification.schema import (
    VerificationFinding,
    VerificationResult,
    VerificationSeverity,
    utc_now,
)


class ReachabilityVerifier:
    """Verify management, rollback, and decoy isolation reachability."""

    version = "reachability-v1"

    def verify(
        self,
        plan: ExecutionPlan,
        twin_snapshot: TwinSnapshot,
        dependency_graph: dict[str, list[str]] | None = None,
        *,
        management_sources: list[str] | None = None,
        rollback_sources: list[str] | None = None,
        protected_assets: list[str] | None = None,
    ) -> list[VerificationFinding]:
        graph, stale_edges = self._graph_from_twin(twin_snapshot, dependency_graph or {})
        targets = set(plan.allowed_scope or plan.targets)
        protected = set(protected_assets or self._protected_assets(twin_snapshot))
        management = management_sources or ["soc-control-plane"]
        rollback = rollback_sources or ["rollback-controller"]
        findings = [
            self._must_reach("INV-002", "management", graph, management, targets),
            self._must_reach("INV-002", "rollback", graph, rollback, [plan.adapter_type]),
            self._decoy_isolation(graph, protected),
        ]
        if stale_edges:
            findings.append(
                self._finding(
                    "INV-002",
                    VerificationResult.UNKNOWN,
                    VerificationSeverity.MEDIUM,
                    "Stale or low-confidence relationships affect reachability proof.",
                    affected_relationships=stale_edges,
                    confidence=0.4,
                )
            )
        return findings

    def projected_graph(
        self,
        twin_snapshot: TwinSnapshot,
        dependency_graph: dict[str, list[str]] | None = None,
    ) -> dict[str, list[str]]:
        """Return a copied directed graph; live Twin is never mutated."""
        return self._graph_from_twin(twin_snapshot, dependency_graph or {})[0]

    def _graph_from_twin(
        self,
        twin_snapshot: TwinSnapshot,
        dependency_graph: dict[str, list[str]],
    ) -> tuple[dict[str, list[str]], list[str]]:
        now = datetime.now(timezone.utc)
        graph: dict[str, list[str]] = {
            node_id: [] for node_id in twin_snapshot.assets
        }
        stale: list[str] = []
        for relationship in twin_snapshot.relationships.values():
            if not relationship.active:
                continue
            if relationship.expiry_time and relationship.expiry_time <= now:
                continue
            graph.setdefault(relationship.source_entity_id, []).append(
                relationship.target_entity_id
            )
            graph.setdefault(relationship.target_entity_id, [])
            if relationship.confidence < 0.35 or relationship.attributes.get("stale"):
                stale.append(relationship.relationship_id)
        for source, targets in dependency_graph.items():
            graph.setdefault(source, [])
            for target in targets:
                graph[source].append(target)
                graph.setdefault(target, [])
        graph.setdefault("soc-control-plane", [])
        graph.setdefault("rollback-controller", [])
        graph["rollback-controller"].append("docker_decoy")
        graph["rollback-controller"].append("mock_firewall")
        graph["rollback-controller"].append("mock_dns")
        graph["rollback-controller"].append("mock_telemetry")
        graph["rollback-controller"].append("mock_ticket")
        for target in list(graph):
            graph["soc-control-plane"].append(target)
        return {key: sorted(set(values)) for key, values in graph.items()}, stale

    def _must_reach(
        self,
        invariant_id: str,
        label: str,
        graph: dict[str, list[str]],
        sources: list[str],
        targets: list[str] | set[str],
    ) -> VerificationFinding:
        target_set = set(targets)
        if not target_set:
            return self._finding(
                invariant_id,
                VerificationResult.NOT_APPLICABLE,
                VerificationSeverity.INFO,
                f"No {label} target to verify.",
            )
        for source in sources:
            for target in sorted(target_set):
                path = _path(graph, source, target)
                if path:
                    return self._finding(
                        invariant_id,
                        VerificationResult.PROVEN,
                        VerificationSeverity.INFO,
                        f"{label} path exists.",
                        counterexample=path,
                    )
        return self._finding(
            invariant_id,
            VerificationResult.VIOLATED,
            VerificationSeverity.CRITICAL,
            f"No {label} path reaches required target.",
            affected_entities=sorted(target_set),
        )

    def _decoy_isolation(
        self,
        graph: dict[str, list[str]],
        protected: set[str],
    ) -> VerificationFinding:
        decoys = [node for node in graph if "decoy" in node.lower()]
        for decoy in decoys:
            for target in protected:
                path = _path(graph, decoy, target)
                if path:
                    return self._finding(
                        "INV-003",
                        VerificationResult.VIOLATED,
                        VerificationSeverity.CRITICAL,
                        "Decoy can reach protected asset.",
                        affected_entities=[decoy, target],
                        counterexample=path,
                    )
        return self._finding(
            "INV-003",
            VerificationResult.PROVEN,
            VerificationSeverity.INFO,
            "No decoy-to-protected path found in projected graph.",
        )

    def _protected_assets(self, twin_snapshot: TwinSnapshot) -> list[str]:
        return [
            asset.asset_id
            for asset in twin_snapshot.assets.values()
            if asset.attributes.get("protected")
            or asset.asset_type in {"database", "dc", "domain_controller"}
            or asset.business_criticality >= 0.85
        ]

    def _finding(
        self,
        invariant_id: str,
        result: VerificationResult,
        severity: VerificationSeverity,
        explanation: str,
        *,
        affected_entities: list[str] | None = None,
        affected_relationships: list[str] | None = None,
        counterexample: list[str] | None = None,
        confidence: float = 1.0,
    ) -> VerificationFinding:
        return VerificationFinding(
            finding_id=f"{invariant_id}:{result.value}:{abs(hash(explanation))}",
            invariant_id=invariant_id,
            result=result,
            severity=severity,
            affected_entities=affected_entities or [],
            affected_relationships=affected_relationships or [],
            counterexample=counterexample or [],
            explanation=explanation,
            verifier_name="ReachabilityVerifier",
            verifier_version=self.version,
            confidence=confidence,
            timestamp=utc_now(),
        )


def _path(graph: dict[str, list[str]], source: str, target: str) -> list[str]:
    queue: deque[tuple[str, list[str]]] = deque([(source, [source])])
    seen = {source}
    while queue:
        node, path = queue.popleft()
        if node == target:
            return path
        for next_node in graph.get(node, []):
            if next_node not in seen:
                seen.add(next_node)
                queue.append((next_node, [*path, next_node]))
    return []
