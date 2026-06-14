"""Validated MDP model used by the in-package reward-design solver."""

from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Dict, List, Mapping, Optional, Tuple

from mirage.layer2_attack_graph import MIRAGEAttackGraph

StateAction = Tuple[int, str]


def _parse_sa_key(key: object) -> StateAction:
    """Parse a ``(state, action)`` key from tuple/list or ``"state|action"``."""
    if isinstance(key, (tuple, list)) and len(key) == 2:
        return int(key[0]), str(key[1])
    if isinstance(key, str) and "|" in key:
        state, action = key.split("|", 1)
        return int(state), action
    raise ValueError(f"Invalid state-action key: {key!r}")


@dataclass(frozen=True)
class InterventionSite:
    """A state-action pair where defender reward bait may be allocated."""

    name: str
    state: int
    action: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Intervention name cannot be empty")
        if not self.action.strip():
            raise ValueError("Intervention action cannot be empty")


@dataclass
class AttackGraphMDP:
    """
    Portable attack-graph MDP.

    The required fields match the external ``mdp_model`` API used by early
    MIRAGE versions. Optional MIRAGE metadata keeps conversion lossless.
    """

    name: str
    states: List[int]
    actions: List[str]
    available_actions: Dict[int, List[str]]
    transitions: Dict[int, Dict[str, Dict[int, float]]]
    start_distribution: Dict[int, float]
    discount: float
    budget: float
    defender_reward: Dict[StateAction, float]
    interventions: List[InterventionSite]
    attacker_reward: Dict[StateAction, float] = field(default_factory=dict)
    true_goals: List[int] = field(default_factory=list)
    decoy_sites: List[int] = field(default_factory=list)
    sink_state: Optional[int] = None
    state_labels: Dict[int, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.name = str(self.name)
        self.discount = float(self.discount)
        self.budget = float(self.budget)
        self.states = [int(state) for state in self.states]
        self.actions = [str(action) for action in self.actions]
        self.available_actions = {
            int(state): [str(action) for action in actions]
            for state, actions in self.available_actions.items()
        }
        self.transitions = {
            int(state): {
                str(action): {
                    int(next_state): float(probability)
                    for next_state, probability in distribution.items()
                }
                for action, distribution in actions.items()
            }
            for state, actions in self.transitions.items()
        }
        self.start_distribution = {
            int(state): float(probability)
            for state, probability in self.start_distribution.items()
        }
        self.defender_reward = {
            _parse_sa_key(key): float(value)
            for key, value in self.defender_reward.items()
        }
        self.attacker_reward = {
            _parse_sa_key(key): float(value)
            for key, value in self.attacker_reward.items()
        }
        self.true_goals = [int(state) for state in self.true_goals]
        self.decoy_sites = [int(state) for state in self.decoy_sites]
        self.state_labels = {
            int(state): str(label)
            for state, label in self.state_labels.items()
        }
        if self.sink_state is not None:
            self.sink_state = int(self.sink_state)
        self.validate()

    def validate(self) -> None:
        """Reject malformed models before they reach numerical solvers."""
        state_set = set(self.states)
        if not self.states or len(state_set) != len(self.states):
            raise ValueError("states must be non-empty and unique")
        if not self.actions or len(self.actions) != len(set(self.actions)):
            raise ValueError("actions must be non-empty and unique")
        if (
            not math.isfinite(float(self.discount))
            or not 0.0 <= float(self.discount) < 1.0
        ):
            raise ValueError("discount must satisfy 0 <= discount < 1")
        if not math.isfinite(float(self.budget)) or float(self.budget) < 0.0:
            raise ValueError("budget cannot be negative")
        if self.sink_state is not None and self.sink_state not in state_set:
            raise ValueError("sink_state references an unknown state")
        if any(state not in state_set for state in self.true_goals):
            raise ValueError("true_goals references an unknown state")
        if any(state not in state_set for state in self.decoy_sites):
            raise ValueError("decoy_sites references an unknown state")

        start_total = sum(self.start_distribution.values())
        if any(state not in state_set for state in self.start_distribution):
            raise ValueError("start_distribution references an unknown state")
        if any(
            not math.isfinite(probability) or probability < 0
            for probability in self.start_distribution.values()
        ):
            raise ValueError(
                "start_distribution must contain finite non-negative values"
            )
        if abs(start_total - 1.0) > 1e-6:
            raise ValueError("start_distribution probabilities must sum to 1")

        action_set = set(self.actions)
        for state, available in self.available_actions.items():
            if state not in state_set:
                raise ValueError(f"available_actions references unknown state {state}")
            unknown = set(available) - action_set
            if unknown:
                raise ValueError(f"Unknown actions for state {state}: {sorted(unknown)}")
            if len(available) != len(set(available)):
                raise ValueError(f"Duplicate available action at state {state}")

        for state, actions in self.transitions.items():
            if state not in state_set:
                raise ValueError(f"transitions references unknown state {state}")
            for action, distribution in actions.items():
                if action not in self.available_actions.get(state, []):
                    raise ValueError(
                        f"Transition action {action!r} is unavailable at state {state}"
                    )
                if any(next_state not in state_set for next_state in distribution):
                    raise ValueError(
                        f"Transition from state {state} references an unknown state"
                    )
                if any(
                    not math.isfinite(probability) or probability < 0
                    for probability in distribution.values()
                ):
                    raise ValueError(
                        "Transition probabilities must be finite and non-negative"
                    )
                if abs(sum(distribution.values()) - 1.0) > 1e-6:
                    raise ValueError(
                        f"Transition probabilities for ({state}, {action}) must sum to 1"
                    )
        for state, available in self.available_actions.items():
            missing = set(available) - set(self.transitions.get(state, {}))
            if missing:
                raise ValueError(
                    f"Missing transitions for state {state}: {sorted(missing)}"
                )

        for reward_name, rewards in (
            ("defender_reward", self.defender_reward),
            ("attacker_reward", self.attacker_reward),
        ):
            for state, action in rewards:
                if not math.isfinite(rewards[(state, action)]):
                    raise ValueError(
                        f"{reward_name} contains a non-finite value"
                    )
                if state not in state_set:
                    raise ValueError(f"{reward_name} references unknown state {state}")
                if action not in self.available_actions.get(state, []):
                    raise ValueError(
                        f"{reward_name} targets unavailable action "
                        f"({state}, {action})"
                    )

        names = [site.name for site in self.interventions]
        keys = [(site.state, site.action) for site in self.interventions]
        if len(names) != len(set(names)):
            raise ValueError("Intervention names must be unique")
        if len(keys) != len(set(keys)):
            raise ValueError("Intervention state-action pairs must be unique")
        for site in self.interventions:
            if site.state not in state_set:
                raise ValueError(f"Intervention {site.name!r} has an unknown state")
            if site.action not in self.available_actions.get(site.state, []):
                raise ValueError(
                    f"Intervention {site.name!r} targets an unavailable action"
                )

    def _infer_sink_state(self) -> int:
        if self.sink_state is not None:
            return self.sink_state
        for state in self.states:
            actions = self.available_actions.get(state, [])
            if actions == ["noop"]:
                distribution = self.transitions.get(state, {}).get("noop", {})
                if distribution == {state: 1.0}:
                    return state
        return max(self.states)

    def to_mirage_graph(self) -> MIRAGEAttackGraph:
        """Convert to the graph type consumed by MIRAGE's exact MDP solver."""
        sink_state = self._infer_sink_state()
        decoy_sites = list(dict.fromkeys(
            self.decoy_sites or [site.state for site in self.interventions]
        ))
        labels = {
            state: self.state_labels.get(state, f"State_{state}")
            for state in self.states
        }
        metadata = {
            state: {
                "label": labels[state],
                "internal_label": labels[state],
                "attacker_visible_label": labels[state],
                "asset_type": "sink" if state == sink_state else "generic",
                "layer": "sink" if state == sink_state else "imported",
                "is_real": state not in decoy_sites,
                "value": 0.0,
            }
            for state in self.states
        }
        return MIRAGEAttackGraph(
            states=list(self.states),
            actions=list(self.actions),
            available_actions={
                state: list(actions)
                for state, actions in self.available_actions.items()
            },
            transitions={
                state: {
                    action: dict(distribution)
                    for action, distribution in actions.items()
                }
                for state, actions in self.transitions.items()
            },
            start_distribution=dict(self.start_distribution),
            discount=float(self.discount),
            budget=float(self.budget),
            true_goals=list(self.true_goals),
            decoy_sites=decoy_sites,
            sink_state=sink_state,
            state_labels=labels,
            attacker_reward=dict(self.attacker_reward),
            defender_reward=dict(self.defender_reward),
            node_metadata=metadata,
            belief_state=dict(self.start_distribution),
            active_decoy_sites=list(decoy_sites),
        )

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "AttackGraphMDP":
        """Load the portable JSON-compatible representation."""
        interventions = [
            InterventionSite(
                name=str(item["name"]),
                state=int(item["state"]),
                action=str(item["action"]),
            )
            for item in data.get("interventions", [])
        ]
        return cls(
            name=str(data.get("name", "attack_graph")),
            states=[int(state) for state in data["states"]],
            actions=[str(action) for action in data["actions"]],
            available_actions={
                int(state): list(actions)
                for state, actions in data["available_actions"].items()
            },
            transitions={
                int(state): {
                    str(action): {
                        int(next_state): float(probability)
                        for next_state, probability in distribution.items()
                    }
                    for action, distribution in actions.items()
                }
                for state, actions in data["transitions"].items()
            },
            start_distribution={
                int(state): float(probability)
                for state, probability in data["start_distribution"].items()
            },
            discount=float(data["discount"]),
            budget=float(data["budget"]),
            defender_reward={
                _parse_sa_key(key): float(value)
                for key, value in data["defender_reward"].items()
            },
            attacker_reward={
                _parse_sa_key(key): float(value)
                for key, value in data.get("attacker_reward", {}).items()
            },
            interventions=interventions,
            true_goals=[int(state) for state in data.get("true_goals", [])],
            decoy_sites=[int(state) for state in data.get("decoy_sites", [])],
            sink_state=data.get("sink_state"),
            state_labels={
                int(state): str(label)
                for state, label in data.get("state_labels", {}).items()
            },
        )

    @classmethod
    def from_mirage_graph(
        cls,
        graph: MIRAGEAttackGraph,
    ) -> "AttackGraphMDP":
        """Create a portable design model from a live MIRAGE graph."""
        design_transitions = {
            state: {
                action: dict(distribution)
                for action, distribution in actions.items()
            }
            for state, actions in graph.transitions.items()
        }
        for (state, action), distribution in graph.decoy_transition_templates.items():
            if state in design_transitions and action in design_transitions[state]:
                design_transitions[state][action] = dict(distribution)

        return cls(
            name=graph.name,
            states=list(graph.states),
            actions=list(graph.actions),
            available_actions={
                state: list(actions)
                for state, actions in graph.available_actions.items()
            },
            transitions=design_transitions,
            start_distribution=dict(graph.start_distribution),
            discount=graph.discount,
            budget=graph.budget,
            defender_reward=dict(graph.defender_reward),
            attacker_reward=dict(graph.attacker_reward),
            interventions=[
                InterventionSite(
                    name=f"decoy_{state}",
                    state=state,
                    action="end",
                )
                for state in graph.decoy_sites
                if "end" in graph.available_actions.get(state, [])
            ],
            true_goals=list(graph.true_goals),
            decoy_sites=list(graph.decoy_sites),
            sink_state=graph.sink_state,
            state_labels=dict(graph.state_labels),
        )
