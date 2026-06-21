"""Deterministic synthetic scenarios for the MARL cyber range."""

from __future__ import annotations

from mirage.marl.schema import RangeEdge, RangeNode, RangeScenario


def build_scenario(index: int) -> RangeScenario:
    """Build one deterministic synthetic scenario."""
    idx = int(index)
    branch = idx % 5
    hardness = 0.18 + (idx % 7) * 0.08
    include_decoy = idx % 2 == 0
    nodes = [
        RangeNode(
            node_id=f"s{idx}:entry",
            visible_label="internet-entry",
            asset_type="entry",
            value=0.05,
            exposure=0.7,
            services=["synthetic_gateway"],
            is_entry=True,
        ),
        RangeNode(
            node_id=f"s{idx}:workstation",
            visible_label="workstation",
            asset_type="workstation",
            value=0.2,
            exposure=0.45,
            services=["file", "auth"],
            credential_hint=idx % 3 == 0,
        ),
        RangeNode(
            node_id=f"s{idx}:app",
            visible_label="application",
            asset_type="application",
            value=0.45 + branch * 0.04,
            exposure=0.35,
            services=["web", "api"],
            credential_hint=idx % 4 in {0, 1},
        ),
        RangeNode(
            node_id=f"s{idx}:identity",
            visible_label="identity-service",
            asset_type="identity",
            value=0.55,
            exposure=0.25,
            services=["directory"],
            credential_hint=True,
        ),
        RangeNode(
            node_id=f"s{idx}:objective",
            visible_label="records-store",
            asset_type="database",
            value=0.95,
            exposure=0.18,
            services=["db"],
            is_objective=True,
            protected=True,
        ),
    ]
    if include_decoy:
        nodes.append(
            RangeNode(
                node_id=f"s{idx}:decoy",
                visible_label="records-cache",
                asset_type="database",
                value=0.75,
                exposure=0.55,
                services=["db"],
                is_decoy=True,
            )
        )
    edges = [
        RangeEdge(
            edge_id=f"s{idx}:e-entry-workstation",
            source=f"s{idx}:entry",
            target=f"s{idx}:workstation",
            difficulty=hardness,
            noise=0.06,
        ),
        RangeEdge(
            edge_id=f"s{idx}:e-workstation-app",
            source=f"s{idx}:workstation",
            target=f"s{idx}:app",
            difficulty=min(0.95, hardness + 0.15),
            noise=0.08,
            credential_required=idx % 3 == 1,
        ),
        RangeEdge(
            edge_id=f"s{idx}:e-app-identity",
            source=f"s{idx}:app",
            target=f"s{idx}:identity",
            difficulty=min(0.95, hardness + 0.25),
            noise=0.1,
            credential_required=True,
        ),
        RangeEdge(
            edge_id=f"s{idx}:e-identity-objective",
            source=f"s{idx}:identity",
            target=f"s{idx}:objective",
            difficulty=min(0.98, hardness + 0.35),
            noise=0.13,
            credential_required=True,
        ),
        RangeEdge(
            edge_id=f"s{idx}:e-app-objective",
            source=f"s{idx}:app",
            target=f"s{idx}:objective",
            difficulty=min(0.99, hardness + 0.45),
            noise=0.16,
            credential_required=True,
        ),
    ]
    if include_decoy:
        edges.append(
            RangeEdge(
                edge_id=f"s{idx}:e-workstation-decoy",
                source=f"s{idx}:workstation",
                target=f"s{idx}:decoy",
                difficulty=max(0.05, hardness - 0.1),
                noise=0.05,
            )
        )
        edges.append(
            RangeEdge(
                edge_id=f"s{idx}:e-decoy-objective",
                source=f"s{idx}:decoy",
                target=f"s{idx}:objective",
                difficulty=0.9,
                noise=0.2,
                credential_required=True,
            )
        )
    return RangeScenario(
        scenario_id=f"marl_scenario_{idx:02d}",
        name=f"Synthetic MARL Range {idx:02d}",
        nodes=nodes,
        edges=edges,
        entry_node_ids=[f"s{idx}:entry"],
        objective_node_ids=[f"s{idx}:objective"],
        max_steps=9 + branch,
        blue_budget=4.0 + (idx % 4) * 0.5,
        random_seed=42 + idx,
        tags=[
            "synthetic",
            "deception" if include_decoy else "no_initial_decoy",
            f"difficulty_{idx % 5}",
        ],
    )


def load_scenarios(count: int = 20) -> list[RangeScenario]:
    """Return the default deterministic scenario suite."""
    return [build_scenario(index) for index in range(count)]


def scenario_by_id(scenario_id: str) -> RangeScenario:
    """Find a scenario by ID in the default suite."""
    for scenario in load_scenarios():
        if scenario.scenario_id == scenario_id:
            return scenario
    raise KeyError(scenario_id)
