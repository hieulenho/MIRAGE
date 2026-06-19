"""Deterministic synthetic scenarios for GNN dataset generation and testing.

Ten scenarios with fixed seeds covering the full evaluation matrix from
Milestone 6 §22.  All scenarios are reproducible — same seed produces
identical topology, belief, and label data.

Scenarios:
  1. lateral_movement_to_critical_db
  2. multi_credential_paths
  3. benign_admin_activity
  4. decoy_interaction
  5. stale_incomplete_twin
  6. unseen_topology
  7. new_node_edge_type
  8. high_risk_inferred_only
  9. overlapping_paths
  10. large_hierarchical_graph
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta, timezone
from typing import Any


from mirage.domain.schemas import (
    Asset,
    BeliefSnapshot,
    EntityBelief,
    Evidence,
    Identity,
    LocalOperationalSubgraph,
    LocalSubgraphEdge,
    LocalSubgraphNode,
    Relationship,
    SeedEntity,
    TwinSnapshot,
    STAGE_NAMES_V1,
)
from mirage.gnn.schema import (
    EdgeLabel,
    GraphLabel,
    GraphSampleLabels,
    NodeLabel,
)

BASE_TIME = datetime(2026, 6, 17, 12, 0, 0, tzinfo=timezone.utc)


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _now(offset_hours: int = 0) -> datetime:
    return BASE_TIME - timedelta(hours=offset_hours)


def _stable_id(*parts: str) -> str:
    payload = "|".join(parts)
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _uniform_stage_dist(dominant: str, dominant_prob: float = 0.7) -> dict[str, float]:
    """Return a stage distribution with one dominant stage."""
    rest = [s for s in STAGE_NAMES_V1 if s != dominant]
    remaining = 1.0 - dominant_prob
    per_other = remaining / max(len(rest), 1)
    dist = {s: round(per_other, 6) for s in rest}
    dist[dominant] = round(dominant_prob, 6)
    # Fix rounding
    total = sum(dist.values())
    dist[dominant] = round(dist[dominant] + (1.0 - total), 6)
    return dist


def _make_asset(
    asset_id: str,
    asset_type: str = "host",
    criticality: float = 0.3,
    is_decoy: bool = False,
    subnet: str = "10.0.0.0/24",
    environment: str = "production",
    ts: datetime | None = None,
) -> Asset:
    t = ts or _now(1)
    return Asset(
        asset_id=asset_id,
        hostname=None,   # No raw hostnames
        asset_type=asset_type,
        environment=environment,
        subnet=subnet,
        business_criticality=criticality,
        is_decoy=is_decoy,
        first_seen=_utc(t - timedelta(days=30)),
        last_seen=_utc(t),
        confidence=0.9,
        active=True,
    )


def _make_identity(
    identity_id: str,
    identity_type: str = "user",
    privilege_level: str = "standard",
    ts: datetime | None = None,
) -> Identity:
    t = ts or _now(1)
    return Identity(
        identity_id=identity_id,
        username=None,  # No raw usernames
        identity_type=identity_type,
        privilege_level=privilege_level,
        first_seen=_utc(t - timedelta(days=10)),
        last_seen=_utc(t),
        confidence=0.85,
    )


def _make_relationship(
    src: str,
    dst: str,
    rel_type: str,
    confidence: float = 0.8,
    ts: datetime | None = None,
    active: bool = True,
) -> Relationship:
    t = ts or _now(1)
    rel_id = _stable_id("rel", src, dst, rel_type)
    return Relationship(
        relationship_id=rel_id,
        source_entity_id=src,
        target_entity_id=dst,
        relationship_type=rel_type,
        confidence=confidence,
        first_seen=_utc(t - timedelta(hours=2)),
        last_seen=_utc(t),
        active=active,
    )


def _make_belief(
    entity_id: str,
    entity_type: str,
    compromise_prob: float = 0.1,
    stage: str = "normal",
    evidence_ids: list[str] | None = None,
    ts: datetime | None = None,
) -> EntityBelief:
    t = ts or _now(1)
    stage_dist = _uniform_stage_dist(stage)
    return EntityBelief(
        entity_id=entity_id,
        entity_type=entity_type,
        compromise_probability=compromise_prob,
        stage_distribution=stage_dist,
        most_likely_stage=stage,
        uncertainty=0.2 if compromise_prob < 0.3 else 0.5,
        confidence=0.8,
        evidence_ids=evidence_ids or [],
        candidate_attacker_location_probability=compromise_prob * 0.7,
        last_updated=_utc(t),
        belief_version=1,
    )


def _make_evidence(
    evidence_id: str,
    entity_ids: list[str],
    description: str,
    score: float = 0.5,
    ts: datetime | None = None,
) -> Evidence:
    t = ts or _now(1)
    return Evidence(
        evidence_id=evidence_id,
        entity_ids=entity_ids,
        description=description,
        score=score,
        confidence=0.8,
        first_seen=_utc(t - timedelta(minutes=30)),
        last_seen=_utc(t),
    )


def _make_subgraph_node(
    node: LocalSubgraphNode | None = None,
    *,
    node_id: str = "",
    entity_type: str = "asset",
    label: str = "",
    asset_type: str = "host",
    criticality: float = 0.3,
    is_seed: bool = False,
    is_decoy: bool = False,
    is_critical: bool = False,
    is_protected: bool = False,
    compromise_prob: float = 0.1,
    attacker_loc_prob: float = 0.05,
    confidence: float = 0.85,
    attributes: dict | None = None,
) -> LocalSubgraphNode:
    if node is not None:
        return node
    return LocalSubgraphNode(
        node_id=node_id,
        entity_type=entity_type,
        label=label or node_id,
        asset_type=asset_type,
        business_criticality=criticality,
        is_seed=is_seed,
        is_decoy=is_decoy,
        is_critical=is_critical,
        is_protected=is_protected,
        compromise_probability=compromise_prob,
        attacker_location_probability=attacker_loc_prob,
        confidence=confidence,
        attributes=attributes or {},
    )


def _make_subgraph_edge(
    src_id: str,
    dst_id: str,
    rel_type: str,
    confidence: float = 0.8,
    directly_observed: bool = True,
    inferred: bool = False,
    ts: datetime | None = None,
    source_event_ids: list[str] | None = None,
) -> LocalSubgraphEdge:
    t = ts or _now(1)
    edge_id = _stable_id("edge", src_id, dst_id, rel_type)
    return LocalSubgraphEdge(
        edge_id=edge_id,
        source_entity_id=src_id,
        target_entity_id=dst_id,
        relationship_type=rel_type,
        confidence=confidence,
        first_seen=_utc(t - timedelta(hours=3)),
        last_seen=_utc(t),
        directly_observed=directly_observed,
        inferred=inferred,
        source_event_ids=source_event_ids or [],
    )


def _make_twin(
    assets: dict[str, Asset] | None = None,
    identities: dict[str, Identity] | None = None,
    relationships: dict[str, Relationship] | None = None,
    coverage: float = 0.9,
    freshness: float = 0.9,
    version: int = 1,
) -> TwinSnapshot:
    return TwinSnapshot(
        twin_version=version,
        timestamp=_now(0),
        assets=assets or {},
        identities=identities or {},
        relationships=relationships or {},
        coverage_score=coverage,
        freshness_score=freshness,
    )


def _make_belief_snapshot(
    beliefs: dict[str, EntityBelief] | None = None,
    evidence: dict[str, Evidence] | None = None,
    version: int = 1,
) -> BeliefSnapshot:
    return BeliefSnapshot(
        belief_version=version,
        timestamp=_now(0),
        entity_beliefs=beliefs or {},
        evidence=evidence or {},
    )


def _make_subgraph(
    subgraph_id: str,
    nodes: list[LocalSubgraphNode],
    edges: list[LocalSubgraphEdge],
    seed_ids: list[str] | None = None,
    critical_ids: list[str] | None = None,
    decoy_ids: list[str] | None = None,
    coverage: float = 0.9,
    freshness: float = 0.9,
) -> LocalOperationalSubgraph:
    ref = _now(0)
    seed_entities = []
    for nid in (seed_ids or []):
        node = next((n for n in nodes if n.node_id == nid), None)
        if node is not None:
            seed_entities.append(SeedEntity(
                entity_id=nid,
                entity_type=node.entity_type,
                seed_reason="test_scenario",
                compromise_probability=node.compromise_probability,
                attacker_location_probability=node.attacker_location_probability,
                belief_confidence=node.confidence,
                belief_uncertainty=0.3,
                most_likely_stage="lateral_movement",
                priority_score=node.compromise_probability,
                selected_at=ref,
            ))
    return LocalOperationalSubgraph(
        subgraph_id=subgraph_id,
        graph_version="test_v1",
        twin_version="1",
        belief_version=1,
        created_at=ref,
        reference_time=ref,
        seed_entities=seed_entities,
        nodes=sorted(nodes, key=lambda n: n.node_id),
        edges=sorted(edges, key=lambda e: e.edge_id),
        critical_asset_ids=sorted(critical_ids or []),
        decoy_ids=sorted(decoy_ids or []),
        coverage_score=coverage,
        freshness_score=freshness,
    )


# ===========================================================================
# Public scenario factory
# ===========================================================================

def build_scenario(scenario_id: str) -> dict[str, Any]:
    """Return a dict ready for GraphDatasetBuilder.build_sample().

    Keys: twin_snapshot, belief_snapshot, local_subgraph, reference_time,
          labels, scenario_id, topology_id.
    """
    builders = {
        "lateral_movement_to_critical_db": _scenario_lateral_movement,
        "multi_credential_paths": _scenario_multi_credential,
        "benign_admin_activity": _scenario_benign_admin,
        "decoy_interaction": _scenario_decoy_interaction,
        "stale_incomplete_twin": _scenario_stale_twin,
        "unseen_topology": _scenario_unseen_topology,
        "new_node_edge_type": _scenario_new_type,
        "high_risk_inferred_only": _scenario_inferred_only,
        "overlapping_paths": _scenario_overlapping_paths,
        "large_hierarchical_graph": _scenario_large_hierarchical,
    }
    if scenario_id not in builders:
        raise ValueError(f"Unknown scenario: {scenario_id!r}. "
                         f"Available: {sorted(builders)}")
    return builders[scenario_id]()


SCENARIO_IDS: list[str] = [
    "lateral_movement_to_critical_db",
    "multi_credential_paths",
    "benign_admin_activity",
    "decoy_interaction",
    "stale_incomplete_twin",
    "unseen_topology",
    "new_node_edge_type",
    "high_risk_inferred_only",
    "overlapping_paths",
    "large_hierarchical_graph",
]


# ===========================================================================
# Individual scenario builders
# ===========================================================================

def _scenario_lateral_movement() -> dict[str, Any]:
    """Scenario 1: lateral movement path toward a critical database."""
    ref = _now(0)
    n_entry = _make_subgraph_node(
        node_id="asset:entry_host", entity_type="asset", label="EntryHost",
        asset_type="host", criticality=0.3, is_seed=True, compromise_prob=0.85,
        attacker_loc_prob=0.80,
    )
    n_mid = _make_subgraph_node(
        node_id="asset:mid_server", entity_type="asset", label="MidServer",
        asset_type="host", criticality=0.5, compromise_prob=0.55,
    )
    n_db = _make_subgraph_node(
        node_id="asset:critical_db", entity_type="asset", label="CriticalDB",
        asset_type="database", criticality=0.95, is_critical=True, is_protected=True,
        compromise_prob=0.2,
    )
    e1 = _make_subgraph_edge("asset:entry_host", "asset:mid_server",
                              "observed_lateral_movement", 0.85,
                              source_event_ids=["evt001"])
    e2 = _make_subgraph_edge("asset:mid_server", "asset:critical_db",
                              "authenticated_to", 0.7)

    ev1 = _make_evidence("ev001", ["asset:entry_host"],
                          "Lateral movement observed", score=0.9, ts=ref)
    b_entry = _make_belief("asset:entry_host", "asset",
                            compromise_prob=0.85, stage="lateral_movement",
                            evidence_ids=["ev001"])
    b_mid = _make_belief("asset:mid_server", "asset",
                          compromise_prob=0.55, stage="lateral_movement")
    b_db = _make_belief("asset:critical_db", "asset",
                         compromise_prob=0.2, stage="normal")

    twin = _make_twin(
        assets={
            "asset:entry_host": _make_asset("asset:entry_host", "host", 0.3),
            "asset:mid_server": _make_asset("asset:mid_server", "host", 0.5),
            "asset:critical_db": _make_asset("asset:critical_db", "database", 0.95),
        }
    )
    belief = _make_belief_snapshot(
        beliefs={
            "asset:entry_host": b_entry,
            "asset:mid_server": b_mid,
            "asset:critical_db": b_db,
        },
        evidence={"ev001": ev1},
    )
    subgraph = _make_subgraph(
        "sg_lateral_movement",
        nodes=[n_entry, n_mid, n_db],
        edges=[e1, e2],
        seed_ids=["asset:entry_host"],
        critical_ids=["asset:critical_db"],
        coverage=0.9,
        freshness=0.95,
    )
    labels = GraphSampleLabels(
        node_labels={
            "asset:entry_host": NodeLabel(node_id="asset:entry_host",
                                           is_compromised=True, confidence=0.9,
                                           provenance="synthetic"),
            "asset:mid_server": NodeLabel(node_id="asset:mid_server",
                                           is_compromised=True, confidence=0.7,
                                           provenance="synthetic"),
            "asset:critical_db": NodeLabel(node_id="asset:critical_db",
                                            is_compromised=False, confidence=0.9,
                                            provenance="synthetic"),
        },
        edge_labels={
            e1.edge_id: EdgeLabel(edge_id=e1.edge_id, is_lateral_movement=True,
                                   confidence=0.9, provenance="synthetic"),
            e2.edge_id: EdgeLabel(edge_id=e2.edge_id, is_lateral_movement=True,
                                   confidence=0.7, provenance="synthetic"),
        },
        graph_label=GraphLabel(is_high_risk=True, risk_level=0.85,
                                provenance="synthetic"),
        label_source="synthetic",
        label_timestamp=ref,
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="lateral_movement_to_critical_db",
                topology_id="topology_abc")


def _scenario_multi_credential() -> dict[str, Any]:
    """Scenario 2: multiple credential-driven paths."""
    ref = _now(0)
    nodes = [
        _make_subgraph_node(node_id="asset:workstation1", entity_type="asset",
                             label="WS1", asset_type="host", criticality=0.3,
                             is_seed=True, compromise_prob=0.7),
        _make_subgraph_node(node_id="credential:svc_account", entity_type="credential",
                             label="SvcAccount", asset_type="credential", criticality=0.7,
                             compromise_prob=0.6),
        _make_subgraph_node(node_id="identity:admin_user", entity_type="identity",
                             label="AdminUser", asset_type="user", criticality=0.8,
                             compromise_prob=0.5),
        _make_subgraph_node(node_id="asset:app_server", entity_type="asset",
                             label="AppServer", asset_type="host", criticality=0.7,
                             compromise_prob=0.4),
        _make_subgraph_node(node_id="asset:file_server", entity_type="asset",
                             label="FileServer", asset_type="host", criticality=0.85,
                             is_critical=True, is_protected=True, compromise_prob=0.15),
    ]
    edges = [
        _make_subgraph_edge("asset:workstation1", "credential:svc_account",
                             "uses_credential", 0.9, source_event_ids=["evt002"]),
        _make_subgraph_edge("credential:svc_account", "asset:app_server",
                             "authenticated_to", 0.8),
        _make_subgraph_edge("identity:admin_user", "asset:file_server",
                             "authenticated_to", 0.75),
        _make_subgraph_edge("asset:workstation1", "identity:admin_user",
                             "uses_credential_on", 0.65),
        _make_subgraph_edge("asset:app_server", "asset:file_server",
                             "communicates_with", 0.6),
    ]
    assets = {n.node_id: _make_asset(n.node_id, n.asset_type, n.business_criticality)
              for n in nodes if n.entity_type == "asset"}
    beliefs = {n.node_id: _make_belief(n.node_id, n.entity_type,
                                        n.compromise_probability, "credential_access")
               for n in nodes}
    twin = _make_twin(assets=assets)
    belief = _make_belief_snapshot(beliefs=beliefs)
    subgraph = _make_subgraph("sg_multi_cred", nodes, edges,
                               seed_ids=["asset:workstation1"],
                               critical_ids=["asset:file_server"])
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id,
                                           is_compromised=n.compromise_probability > 0.45,
                                           confidence=0.8, provenance="synthetic")
                     for n in nodes},
        graph_label=GraphLabel(is_high_risk=True, risk_level=0.75, provenance="synthetic"),
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="multi_credential_paths",
                topology_id="topology_def")


def _scenario_benign_admin() -> dict[str, Any]:
    """Scenario 3: benign administrator activity — should NOT get high risk."""
    ref = _now(0)
    n_admin = _make_subgraph_node(node_id="identity:admin_benign", entity_type="identity",
                                   label="AdminBenign", asset_type="user", criticality=0.6,
                                   is_seed=True, compromise_prob=0.05)
    n_server = _make_subgraph_node(node_id="asset:mgmt_server", entity_type="asset",
                                    label="MgmtServer", asset_type="host", criticality=0.5,
                                    compromise_prob=0.05)
    n_db = _make_subgraph_node(node_id="asset:audit_db", entity_type="asset",
                                label="AuditDB", asset_type="database", criticality=0.7,
                                is_critical=True, is_protected=True, compromise_prob=0.02)
    e1 = _make_subgraph_edge("identity:admin_benign", "asset:mgmt_server",
                              "authenticated_to", 0.95, source_event_ids=["evt_admin01"])
    e2 = _make_subgraph_edge("asset:mgmt_server", "asset:audit_db",
                              "authenticated_to", 0.9, source_event_ids=["evt_admin02"])
    twin = _make_twin(
        assets={"asset:mgmt_server": _make_asset("asset:mgmt_server"),
                "asset:audit_db": _make_asset("asset:audit_db", "database", 0.7)},
        identities={"identity:admin_benign": _make_identity("identity:admin_benign",
                                                             privilege_level="admin")},
    )
    belief = _make_belief_snapshot(
        beliefs={n.node_id: _make_belief(n.node_id, n.entity_type, n.compromise_probability)
                 for n in [n_admin, n_server, n_db]}
    )
    subgraph = _make_subgraph("sg_benign_admin", [n_admin, n_server, n_db],
                               [e1, e2], seed_ids=["identity:admin_benign"],
                               critical_ids=["asset:audit_db"])
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id, is_compromised=False,
                                           confidence=0.95, provenance="synthetic")
                     for n in [n_admin, n_server, n_db]},
        graph_label=GraphLabel(is_high_risk=False, risk_level=0.05, provenance="synthetic"),
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="benign_admin_activity",
                topology_id="topology_abc")


def _scenario_decoy_interaction() -> dict[str, Any]:
    """Scenario 4: confirmed decoy interaction — high confidence label."""
    ref = _now(0)
    n_attacker = _make_subgraph_node(node_id="asset:compromised_host", entity_type="asset",
                                      label="CompromisedHost", asset_type="host",
                                      criticality=0.3, is_seed=True, compromise_prob=0.9)
    n_decoy = _make_subgraph_node(node_id="asset:decoy_server", entity_type="asset",
                                   label="DecoyServer", asset_type="decoy",
                                   criticality=0.1, is_decoy=True, compromise_prob=0.0)
    e1 = _make_subgraph_edge("asset:compromised_host", "asset:decoy_server",
                              "interacted_with_decoy", 0.99, source_event_ids=["evt_decoy01"])
    twin = _make_twin(
        assets={
            "asset:compromised_host": _make_asset("asset:compromised_host"),
            "asset:decoy_server": _make_asset("asset:decoy_server", "host", 0.1, is_decoy=True),
        }
    )
    belief = _make_belief_snapshot(
        beliefs={
            "asset:compromised_host": _make_belief("asset:compromised_host", "asset", 0.9,
                                                    stage="lateral_movement"),
            "asset:decoy_server": _make_belief("asset:decoy_server", "asset", 0.0),
        }
    )
    subgraph = _make_subgraph("sg_decoy", [n_attacker, n_decoy], [e1],
                               seed_ids=["asset:compromised_host"],
                               decoy_ids=["asset:decoy_server"])
    labels = GraphSampleLabels(
        node_labels={
            "asset:compromised_host": NodeLabel(node_id="asset:compromised_host",
                                                 is_compromised=True, confidence=0.99,
                                                 provenance="confirmed_deception"),
            "asset:decoy_server": NodeLabel(node_id="asset:decoy_server",
                                             is_compromised=False, confidence=0.99,
                                             provenance="confirmed_deception"),
        },
        edge_labels={
            e1.edge_id: EdgeLabel(edge_id=e1.edge_id, is_lateral_movement=True,
                                   confidence=0.99, provenance="confirmed_deception"),
        },
        graph_label=GraphLabel(is_high_risk=True, risk_level=0.95, provenance="confirmed_deception"),
        label_source="confirmed_deception",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="decoy_interaction",
                topology_id="topology_ghi")


def _scenario_stale_twin() -> dict[str, Any]:
    """Scenario 5: stale / incomplete Twin — should trigger OOD warnings."""
    ref = _now(0)
    old_time = ref - timedelta(days=7)
    n1 = _make_subgraph_node(node_id="asset:stale_host_a", entity_type="asset",
                              label="StaleA", criticality=0.5, is_seed=True,
                              compromise_prob=0.3)
    n2 = _make_subgraph_node(node_id="asset:stale_host_b", entity_type="asset",
                              label="StaleB", criticality=0.4, compromise_prob=0.2)
    e1 = _make_subgraph_edge("asset:stale_host_a", "asset:stale_host_b",
                              "communicates_with", 0.4, ts=old_time)
    twin = _make_twin(
        assets={
            "asset:stale_host_a": _make_asset("asset:stale_host_a", ts=old_time),
            "asset:stale_host_b": _make_asset("asset:stale_host_b", ts=old_time),
        },
        coverage=0.15,   # Very low coverage
        freshness=0.1,
    )
    belief = _make_belief_snapshot(
        beliefs={n.node_id: _make_belief(n.node_id, n.entity_type,
                                          n.compromise_probability)
                 for n in [n1, n2]}
    )
    subgraph = _make_subgraph("sg_stale", [n1, n2], [e1],
                               seed_ids=["asset:stale_host_a"],
                               coverage=0.15, freshness=0.1)
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id, is_compromised=False,
                                           confidence=0.4, provenance="synthetic")
                     for n in [n1, n2]},
        graph_label=GraphLabel(is_high_risk=False, risk_level=0.2, provenance="synthetic"),
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="stale_incomplete_twin",
                topology_id="topology_stale")


def _scenario_unseen_topology() -> dict[str, Any]:
    """Scenario 6: completely different topology — tests generalisation."""
    ref = _now(0)
    nodes = [
        _make_subgraph_node(node_id=f"asset:unseen_{i}", entity_type="asset",
                             label=f"Unseen{i}", asset_type="service",
                             criticality=0.4 + 0.1 * i,
                             is_seed=(i == 0), compromise_prob=0.2 + 0.1 * i)
        for i in range(4)
    ]
    edges = [
        _make_subgraph_edge(nodes[i].node_id, nodes[i + 1].node_id,
                             "communicates_with", 0.7)
        for i in range(len(nodes) - 1)
    ]
    assets = {n.node_id: _make_asset(n.node_id, "service", n.business_criticality)
              for n in nodes}
    beliefs = {n.node_id: _make_belief(n.node_id, n.entity_type,
                                        n.compromise_probability)
               for n in nodes}
    twin = _make_twin(assets=assets)
    belief = _make_belief_snapshot(beliefs=beliefs)
    subgraph = _make_subgraph("sg_unseen", nodes, edges,
                               seed_ids=[nodes[0].node_id],
                               critical_ids=[nodes[-1].node_id])
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id,
                                           is_compromised=n.compromise_probability > 0.4,
                                           confidence=0.6, provenance="synthetic")
                     for n in nodes},
        graph_label=GraphLabel(is_high_risk=True, risk_level=0.55, provenance="synthetic"),
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="unseen_topology",
                topology_id="topology_unseen_xyz")


def _scenario_new_type() -> dict[str, Any]:
    """Scenario 7: node/edge type not in standard vocabulary — triggers OOD."""
    ref = _now(0)
    n1 = _make_subgraph_node(node_id="asset:known_host", entity_type="asset",
                              label="KnownHost", is_seed=True, compromise_prob=0.5)
    n2 = LocalSubgraphNode(
        node_id="asset:iot_device",
        entity_type="iot_device",   # Unknown type!
        label="IoTDevice",
        asset_type="iot",
        business_criticality=0.4,
        confidence=0.7,
    )
    e1 = LocalSubgraphEdge(
        edge_id=_stable_id("edge", "asset:known_host", "asset:iot_device", "iot_protocol"),
        source_entity_id="asset:known_host",
        target_entity_id="asset:iot_device",
        relationship_type="iot_protocol",   # Unknown edge type!
        confidence=0.6,
        first_seen=_utc(ref - timedelta(hours=1)),
        last_seen=_utc(ref),
        directly_observed=True,
    )
    twin = _make_twin(
        assets={
            "asset:known_host": _make_asset("asset:known_host"),
            "asset:iot_device": _make_asset("asset:iot_device", "iot"),
        }
    )
    belief = _make_belief_snapshot(
        beliefs={n.node_id: _make_belief(n.node_id, n.entity_type,
                                          n.compromise_probability)
                 for n in [n1, n2]}
    )
    subgraph = _make_subgraph("sg_new_type", [n1, n2], [e1],
                               seed_ids=["asset:known_host"])
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id, is_compromised=False,
                                           confidence=0.5, provenance="synthetic")
                     for n in [n1, n2]},
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="new_node_edge_type",
                topology_id="topology_iot")


def _scenario_inferred_only() -> dict[str, Any]:
    """Scenario 8: high-risk path with ONLY inferred edges (no direct observation)."""
    ref = _now(0)
    n1 = _make_subgraph_node(node_id="asset:suspected_entry", entity_type="asset",
                              label="SuspectedEntry", is_seed=True, compromise_prob=0.6)
    n2 = _make_subgraph_node(node_id="asset:intermediate", entity_type="asset",
                              label="Intermediate", compromise_prob=0.4)
    n3 = _make_subgraph_node(node_id="asset:target_server", entity_type="asset",
                              label="TargetServer", criticality=0.9,
                              is_critical=True, is_protected=True, compromise_prob=0.15)
    # Both edges are inferred only
    e1 = _make_subgraph_edge("asset:suspected_entry", "asset:intermediate",
                              "communicates_with", 0.55, directly_observed=False, inferred=True)
    e2 = _make_subgraph_edge("asset:intermediate", "asset:target_server",
                              "authenticated_to", 0.5, directly_observed=False, inferred=True)
    twin = _make_twin(
        assets={n.node_id: _make_asset(n.node_id, criticality=n.business_criticality)
                for n in [n1, n2, n3]}
    )
    belief = _make_belief_snapshot(
        beliefs={n.node_id: _make_belief(n.node_id, n.entity_type, n.compromise_probability,
                                          "lateral_movement")
                 for n in [n1, n2, n3]}
    )
    subgraph = _make_subgraph("sg_inferred_only", [n1, n2, n3], [e1, e2],
                               seed_ids=["asset:suspected_entry"],
                               critical_ids=["asset:target_server"])
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id,
                                           is_compromised=n.compromise_probability > 0.4,
                                           confidence=0.5, provenance="synthetic")
                     for n in [n1, n2, n3]},
        graph_label=GraphLabel(is_high_risk=True, risk_level=0.65, provenance="synthetic"),
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="high_risk_inferred_only",
                topology_id="topology_def")


def _scenario_overlapping_paths() -> dict[str, Any]:
    """Scenario 9: multiple overlapping paths sharing nodes."""
    ref = _now(0)
    nodes = [
        _make_subgraph_node(node_id="asset:hub", entity_type="asset",
                             label="Hub", is_seed=True, compromise_prob=0.7, criticality=0.5),
        _make_subgraph_node(node_id="asset:branch_a", entity_type="asset",
                             label="BranchA", compromise_prob=0.5, criticality=0.4),
        _make_subgraph_node(node_id="asset:branch_b", entity_type="asset",
                             label="BranchB", compromise_prob=0.4, criticality=0.3),
        _make_subgraph_node(node_id="asset:shared_mid", entity_type="asset",
                             label="SharedMid", compromise_prob=0.6, criticality=0.6),
        _make_subgraph_node(node_id="asset:critical_target", entity_type="asset",
                             label="CriticalTarget", criticality=0.95,
                             is_critical=True, is_protected=True, compromise_prob=0.1),
    ]
    edges = [
        _make_subgraph_edge("asset:hub", "asset:branch_a", "communicates_with", 0.8,
                             source_event_ids=["evt10"]),
        _make_subgraph_edge("asset:hub", "asset:branch_b", "communicates_with", 0.75,
                             source_event_ids=["evt11"]),
        _make_subgraph_edge("asset:branch_a", "asset:shared_mid", "authenticated_to", 0.7),
        _make_subgraph_edge("asset:branch_b", "asset:shared_mid", "authenticated_to", 0.65),
        _make_subgraph_edge("asset:shared_mid", "asset:critical_target",
                             "authenticated_to", 0.6, source_event_ids=["evt12"]),
    ]
    assets = {n.node_id: _make_asset(n.node_id, criticality=n.business_criticality)
              for n in nodes}
    beliefs = {n.node_id: _make_belief(n.node_id, n.entity_type, n.compromise_probability,
                                        "lateral_movement")
               for n in nodes}
    twin = _make_twin(assets=assets)
    belief = _make_belief_snapshot(beliefs=beliefs)
    subgraph = _make_subgraph("sg_overlapping", nodes, edges,
                               seed_ids=["asset:hub"],
                               critical_ids=["asset:critical_target"])
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id,
                                           is_compromised=n.compromise_probability > 0.45,
                                           confidence=0.8, provenance="synthetic")
                     for n in nodes},
        edge_labels={
            e.edge_id: EdgeLabel(
                edge_id=e.edge_id,
                is_lateral_movement=e.relationship_type in {
                    "authenticated_to",
                    "observed_lateral_movement",
                    "connects_to",
                },
                confidence=e.confidence,
                provenance="synthetic",
            )
            for e in edges
        },
        graph_label=GraphLabel(is_high_risk=True, risk_level=0.8, provenance="synthetic"),
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="overlapping_paths",
                topology_id="topology_star")


def _scenario_large_hierarchical() -> dict[str, Any]:
    """Scenario 10: large graph with multiple subnets and domains."""
    ref = _now(0)
    rng = random.Random(42)
    n_nodes = 20
    subnets = ["subnet_a", "subnet_b", "subnet_c"]
    nodes = []
    for i in range(n_nodes):
        subnet = subnets[i % len(subnets)]
        crit = round(rng.uniform(0.1, 0.9), 2)
        comp = round(rng.uniform(0.05, 0.75), 2)
        nodes.append(
            _make_subgraph_node(
                node_id=f"asset:large_node_{i:02d}",
                entity_type="asset",
                label=f"Node{i:02d}",
                asset_type="host",
                criticality=crit,
                is_seed=(i == 0),
                is_critical=(i == n_nodes - 1),
                is_protected=(i == n_nodes - 1),
                compromise_prob=comp,
                attributes={"subnet": subnet},
            )
        )
    edges = []
    for i in range(n_nodes - 1):
        conf = round(rng.uniform(0.5, 0.95), 2)
        edge_type = rng.choice(["communicates_with", "authenticated_to", "connects_to"])
        edges.append(_make_subgraph_edge(nodes[i].node_id, nodes[i + 1].node_id,
                                          edge_type, conf))
    # Extra cross edges
    for _ in range(5):
        a, b = rng.sample(range(n_nodes), 2)
        edges.append(_make_subgraph_edge(nodes[a].node_id, nodes[b].node_id,
                                          "communicates_with", 0.6))
    # Deduplicate edges by edge_id
    seen: set[str] = set()
    unique_edges = []
    for e in edges:
        if e.edge_id not in seen:
            seen.add(e.edge_id)
            unique_edges.append(e)

    assets = {n.node_id: _make_asset(n.node_id, "host", n.business_criticality)
              for n in nodes}
    beliefs = {n.node_id: _make_belief(n.node_id, n.entity_type, n.compromise_probability)
               for n in nodes}
    twin = _make_twin(assets=assets)
    belief = _make_belief_snapshot(beliefs=beliefs)
    subgraph = _make_subgraph(
        "sg_large_hier", nodes, unique_edges,
        seed_ids=[nodes[0].node_id],
        critical_ids=[nodes[-1].node_id],
        coverage=0.8,
        freshness=0.85,
    )
    labels = GraphSampleLabels(
        node_labels={n.node_id: NodeLabel(node_id=n.node_id,
                                           is_compromised=n.compromise_probability > 0.5,
                                           confidence=0.7, provenance="synthetic")
                     for n in nodes},
        edge_labels={
            e.edge_id: EdgeLabel(
                edge_id=e.edge_id,
                is_lateral_movement=e.relationship_type in {
                    "authenticated_to",
                    "observed_lateral_movement",
                    "connects_to",
                },
                confidence=e.confidence,
                provenance="synthetic",
            )
            for e in unique_edges
        },
        graph_label=GraphLabel(is_high_risk=True, risk_level=0.7, provenance="synthetic"),
        label_source="synthetic",
    )
    return dict(twin_snapshot=twin, belief_snapshot=belief, local_subgraph=subgraph,
                reference_time=ref, labels=labels, scenario_id="large_hierarchical_graph",
                topology_id="topology_large")
