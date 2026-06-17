"""Adapter from Digital Twin snapshots to MIRAGE attack graphs."""

from __future__ import annotations

from mirage.domain.schemas import Asset, Relationship, TwinSnapshot
from mirage.layer2_graph_engine.attack_graph import MIRAGEAttackGraph


def _entity_metadata(entity_id: str, snapshot: TwinSnapshot) -> dict:
    if entity_id in snapshot.assets:
        asset = snapshot.assets[entity_id]
        return {
            "label": asset.hostname or asset.asset_id,
            "layer": asset.environment or asset.subnet or "twin_asset",
            "asset_type": asset.asset_type,
            "is_real": not asset.is_decoy,
            "value": asset.business_criticality,
            "business_criticality": asset.business_criticality,
            "confidence": asset.confidence,
            "is_decoy": asset.is_decoy,
            "active": asset.active,
            "source_entity_id": asset.asset_id,
        }
    if entity_id in snapshot.identities:
        identity = snapshot.identities[entity_id]
        label = (
            f"{identity.domain}\\{identity.username}"
            if identity.domain and identity.username
            else identity.username or identity.identity_id
        )
        privilege_value = {
            "unknown": 0.2,
            "low": 0.2,
            "user": 0.3,
            "admin": 0.8,
            "domain_admin": 0.95,
        }.get(identity.privilege_level.lower(), 0.3)
        return {
            "label": label,
            "layer": "identity",
            "asset_type": identity.identity_type,
            "is_real": True,
            "value": privilege_value,
            "business_criticality": privilege_value,
            "confidence": identity.confidence,
            "source_entity_id": identity.identity_id,
        }
    if entity_id.startswith("credential:"):
        return {
            "label": entity_id.removeprefix("credential:"),
            "layer": "credentials",
            "asset_type": "credential",
            "is_real": True,
            "value": 0.6,
            "business_criticality": 0.6,
            "confidence": 0.7,
            "source_entity_id": entity_id,
        }
    if entity_id.startswith("vulnerability:"):
        return {
            "label": entity_id.removeprefix("vulnerability:"),
            "layer": "vulnerability",
            "asset_type": "vulnerability",
            "is_real": True,
            "value": 0.5,
            "business_criticality": 0.5,
            "confidence": 0.7,
            "source_entity_id": entity_id,
        }
    return {
        "label": entity_id,
        "layer": "derived",
        "asset_type": entity_id.split(":", 1)[0],
        "is_real": True,
        "value": 0.1,
        "business_criticality": 0.1,
        "confidence": 0.5,
        "source_entity_id": entity_id,
    }


def _active_relationships(snapshot: TwinSnapshot) -> list[Relationship]:
    active = []
    for relationship in snapshot.relationships.values():
        if not relationship.active:
            continue
        if (
            relationship.expiry_time is not None
            and relationship.expiry_time <= snapshot.timestamp
        ):
            continue
        active.append(relationship)
    return sorted(active, key=lambda rel: rel.relationship_id)


def _asset_is_goal(asset: Asset) -> bool:
    if asset.is_decoy:
        return False
    return (
        asset.business_criticality >= 0.85
        or asset.asset_type in {"database", "dc", "domain_controller"}
    )


def attack_graph_from_twin_snapshot(
    snapshot: TwinSnapshot,
    *,
    budget: float = 6.0,
    discount: float = 0.95,
) -> MIRAGEAttackGraph:
    """Build a MIRAGEAttackGraph from active Digital Twin state."""
    relationships = _active_relationships(snapshot)
    entity_ids = set(snapshot.assets) | set(snapshot.identities)
    for relationship in relationships:
        entity_ids.add(relationship.source_entity_id)
        entity_ids.add(relationship.target_entity_id)
    if not entity_ids:
        entity_ids.add("asset:provisional:empty")

    ordered_entities = sorted(entity_ids)
    entity_to_state = {
        entity_id: index for index, entity_id in enumerate(ordered_entities)
    }
    sink_state = len(entity_to_state)
    states = list(range(sink_state + 1))

    state_labels = {}
    node_metadata = {}
    decoy_sites = []
    true_goals = []
    for entity_id, state in entity_to_state.items():
        metadata = _entity_metadata(entity_id, snapshot)
        state_labels[state] = metadata["label"]
        node_metadata[state] = metadata
        if metadata.get("is_decoy"):
            decoy_sites.append(state)
    for asset in snapshot.assets.values():
        if _asset_is_goal(asset) and asset.asset_id in entity_to_state:
            true_goals.append(entity_to_state[asset.asset_id])
    if not true_goals:
        asset_candidates = [
            asset
            for asset in snapshot.assets.values()
            if not asset.is_decoy and asset.asset_id in entity_to_state
        ]
        if asset_candidates:
            top_asset = max(
                asset_candidates,
                key=lambda asset: (asset.business_criticality, asset.asset_id),
            )
            true_goals.append(entity_to_state[top_asset.asset_id])

    state_labels[sink_state] = "Sink"
    node_metadata[sink_state] = {
        "label": "Sink",
        "layer": "sink",
        "asset_type": "sink",
        "is_real": True,
        "value": 0.0,
        "business_criticality": 0.0,
        "confidence": 1.0,
    }

    transitions = {state: {} for state in states}
    available_actions = {state: [] for state in states}
    for relationship in relationships:
        src = entity_to_state[relationship.source_entity_id]
        dst = entity_to_state[relationship.target_entity_id]
        action = relationship.relationship_type
        available_actions[src].append(action)
        transitions[src].setdefault(action, {})
        transitions[src][action][dst] = max(
            transitions[src][action].get(dst, 0.0),
            max(relationship.confidence, 0.01),
        )

    for state in states:
        if state == sink_state:
            available_actions[state] = ["noop"]
            transitions[state] = {"noop": {sink_state: 1.0}}
            continue
        unique_actions = []
        for action in available_actions[state]:
            if action not in unique_actions:
                unique_actions.append(action)
        for action in unique_actions:
            total = sum(transitions[state][action].values())
            transitions[state][action] = {
                dst: probability / total
                for dst, probability in sorted(transitions[state][action].items())
            }
        if "end" not in unique_actions:
            unique_actions.append("end")
        transitions[state]["end"] = {sink_state: 1.0}
        available_actions[state] = unique_actions

    starts = [
        state
        for entity_id, state in entity_to_state.items()
        if entity_id in snapshot.assets
        and snapshot.assets[entity_id].asset_type in {"workstation", "entry"}
    ]
    if not starts:
        starts = [0]
    start_probability = 1.0 / len(starts)
    start_distribution = {state: start_probability for state in starts}
    belief_state = {
        state: 1.0 / max(1, sink_state)
        for state in range(sink_state)
    }

    attacker_reward = {
        (state, "end"): 1.0 for state in true_goals
    }
    defender_reward = {
        (state, "end"): -2.0 for state in true_goals
    }
    for state in decoy_sites:
        attacker_reward.setdefault((state, "end"), 0.0)
        defender_reward[(state, "end")] = 1.0

    return MIRAGEAttackGraph(
        states=states,
        actions=sorted(
            {action for actions in available_actions.values() for action in actions}
        ),
        available_actions=available_actions,
        transitions=transitions,
        start_distribution=start_distribution,
        discount=discount,
        budget=budget,
        true_goals=sorted(set(true_goals)),
        decoy_sites=sorted(set(decoy_sites)),
        sink_state=sink_state,
        state_labels=state_labels,
        attacker_reward=attacker_reward,
        defender_reward=defender_reward,
        node_metadata=node_metadata,
        edge_costs={},
        belief_state=belief_state,
        active_decoy_sites=sorted(set(decoy_sites)),
        decoy_transition_templates={},
    )
