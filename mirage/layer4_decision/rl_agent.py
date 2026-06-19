"""
MIRAGE — Deep RL Decision Agent
==================================
Thay thế/bổ sung MDP Solver truyền thống bằng Deep Reinforcement Learning
cho đồ thị mạng khổng lồ (hàng nghìn nodes) mà MDP Solver O(|S|³) quá tải.

Kiến trúc:
  1. MIRAGEDefenderEnv   — Gymnasium-compatible environment
  2. DQNAgent            — Deep Q-Network tự viết (không phụ thuộc external lib)
  3. RLDecisionBridge     — Adapter chuyển RL output → ActionPlan (Layer 4 compatible)

Workflow:
  env = MIRAGEDefenderEnv(graph, fabric)
  agent = DQNAgent(env)
  agent.train(n_episodes=1000)
  plan = agent.decide(belief_state)   # → ActionPlan

Scaling:
  - MDP Solver: O(|S|³) — 15 nodes: <5ms, 1000 nodes: ~1s, 10000 nodes: INTRACTABLE
  - DQN Agent:  O(|S|)  per step — 10000 nodes: ~50ms per decision after training

Dependencies:
  - numpy (required)
  - torch (optional, for GPU acceleration — fallback to numpy if unavailable)
"""

from __future__ import annotations

import math
import random
import copy
from collections import deque
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np

from mirage.config import load_config

try:
    # pyrefly: ignore [missing-import]
    import gymnasium as gym
    # pyrefly: ignore [missing-import]
    from gymnasium import spaces
    HAS_GYMNASIUM = True
except ImportError:
    gym = None
    spaces = None
    HAS_GYMNASIUM = False

# Optional torch import — graceful fallback to a NumPy MLP DQN.
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

from mirage.layer2_graph_engine.attack_graph import MIRAGEAttackGraph
from mirage.layer3_deception.deception_fabric import DeceptionAction, DeceptionFabric, DeceptionActionType


_BaseEnv = gym.Env if HAS_GYMNASIUM else object


# ============================================================
# Gymnasium-compatible Environment
# ============================================================

class MIRAGEDefenderEnv(_BaseEnv):
    """
    Gymnasium-compatible RL environment for the MIRAGE defender.

    State:  Belief vector (|nodes| dimensional) + budget remaining + step count
    Action: Index into the deception action catalog
    Reward: Defender value = +1 decoy interception, -2 true goal breach,
            +0.2 * delay_bonus, -cost_penalty

    This environment wraps the core MIRAGE layers and simulates
    attacker-defender interaction over a configurable number of rounds.
    """

    def __init__(
        self,
        graph: MIRAGEAttackGraph,
        fabric: DeceptionFabric,
        max_steps: Optional[int] = None,
        n_attacker_episodes: Optional[int] = None,
        cost_weight: Optional[float] = None,
        attacker_type: str = "greedy",
        seed: int = 42,
    ):
        config = load_config().get("rl", {})
        self.graph = graph
        self.fabric = fabric
        self._base_graph = copy.deepcopy(
            getattr(fabric, "_base_graph", graph)
        )
        self.max_steps = int(
            max_steps if max_steps is not None else config.get("max_steps", 5)
        )
        self.n_attacker_episodes = int(
            n_attacker_episodes
            if n_attacker_episodes is not None
            else config.get("n_attacker_episodes", 12)
        )
        self.cost_weight = float(
            cost_weight if cost_weight is not None else config.get("cost_weight", 0.015)
        )
        self.max_actions = int(config.get("max_actions", 200))
        self.attacker_type = attacker_type
        if self.max_steps < 1:
            raise ValueError("max_steps must be at least 1")
        if self.n_attacker_episodes < 1:
            raise ValueError("n_attacker_episodes must be at least 1")
        if not math.isfinite(self.cost_weight) or self.cost_weight < 0:
            raise ValueError("cost_weight must be finite and non-negative")
        if self.max_actions < 1:
            raise ValueError("rl.max_actions must be at least 1")
        self.rng = random.Random(seed)
        self.np_rng = np.random.RandomState(seed)

        # Build action catalog
        self._action_catalog = self._build_action_catalog()
        self.n_actions = len(self._action_catalog) + 1  # +1 for "do nothing"

        # State dimensions
        n_nodes = len(graph.states)
        self.node_to_index = {
            node_id: index for index, node_id in enumerate(graph.states)
        }
        # Belief + budget + progress + deployed-action bitmap.
        self.state_dim = n_nodes + 2 + len(self._action_catalog)
        self.n_nodes = n_nodes
        if HAS_GYMNASIUM:
            self.action_space = spaces.Discrete(self.n_actions)
            self.observation_space = spaces.Box(
                low=0.0,
                high=1.0,
                shape=(self.state_dim,),
                dtype=np.float32,
            )

        # Episode state
        self._step = 0
        self._budget_remaining = graph.budget
        self._active_actions: List[DeceptionAction] = []
        self._active_action_ids = set()
        self._belief = None

    def _build_action_catalog(self) -> List[DeceptionAction]:
        """Build all possible deception actions from the fabric."""
        catalog = self.fabric.generate_action_catalog()
        # Limit catalog size for tractability
        if len(catalog) > self.max_actions:
            catalog = catalog[:self.max_actions]
        return catalog

    def _get_obs(self) -> np.ndarray:
        """Construct observation vector from current state."""
        # Belief vector
        belief_vec = np.zeros(self.n_nodes, dtype=np.float32)
        if self._belief:
            for s, p in self._belief.items():
                index = self.node_to_index.get(int(s))
                if index is not None:
                    belief_vec[index] = max(0.0, float(p))

        budget_frac = self._budget_remaining / max(1.0, self.graph.budget)
        budget_frac = min(1.0, max(0.0, budget_frac))
        step_frac = self._step / max(1, self.max_steps)

        active_vec = np.zeros(len(self._action_catalog), dtype=np.float32)
        for index, action in enumerate(self._action_catalog):
            if action.action_id in self._active_action_ids:
                active_vec[index] = 1.0

        return np.concatenate([
            belief_vec,
            np.array([budget_frac, step_frac], dtype=np.float32),
            active_vec,
        ])

    def _normalize_belief(
        self,
        belief_state: Optional[Dict[int, float]],
    ) -> Dict[int, float]:
        source = belief_state or self.graph.belief_state
        valid_states = set(self.graph.states)
        normalized: Dict[int, float] = {}
        for raw_state, raw_probability in source.items():
            state = int(raw_state)
            probability = float(raw_probability)
            if state not in valid_states:
                raise ValueError(f"Belief references unknown state {state}")
            if state == self.graph.sink_state:
                continue
            if not math.isfinite(probability) or probability < 0:
                raise ValueError(
                    "Belief probabilities must be finite and non-negative"
                )
            if probability > 0:
                normalized[state] = (
                    normalized.get(state, 0.0) + probability
                )
        total = sum(normalized.values())
        if total <= 0:
            raise ValueError(
                "Belief must assign positive probability to a non-sink state"
            )
        return {
            state: probability / total
            for state, probability in normalized.items()
        }

    def reset(
        self,
        *,
        seed: Optional[int] = None,
        options: Optional[Dict] = None,
    ) -> Tuple[np.ndarray, Dict]:
        """Reset the environment using the Gymnasium API."""
        if HAS_GYMNASIUM:
            super().reset(seed=seed)
        if seed is not None:
            self.rng.seed(seed)
            self.np_rng.seed(seed)
        options = options or {}
        belief_state = options.get("belief_state")
        self._step = 0
        requested_budget = float(
            options.get("budget_remaining", self.graph.budget)
        )
        if not math.isfinite(requested_budget) or requested_budget < 0:
            raise ValueError(
                "budget_remaining must be finite and non-negative"
            )
        self._budget_remaining = min(requested_budget, self.graph.budget)
        self._active_actions = list(self.fabric.deployed_actions)
        self._active_action_ids = {
            action.action_id for action in self._active_actions
        }
        self._belief = self._normalize_belief(belief_state)
        return self._get_obs(), {"action_mask": self.action_mask()}

    def step(self, action_idx: int) -> Tuple[np.ndarray, float, bool, bool, Dict]:
        """
        Execute one defender action and simulate attacker response.

        Args:
            action_idx: Index into action catalog (0..n_actions-1).
                        n_actions-1 = "do nothing" (NOOP)

        Returns:
            Gymnasium tuple: (observation, reward, terminated, truncated, info)
        """
        from mirage.shared.attacker_agents import run_simulation
        from mirage.layer2_graph_engine.attack_graph import build_runtime_graph
        from mirage.layer2_graph_engine.mdp_solver import compute_composite_cost

        self._step += 1
        reward = 0.0
        info = {"action": "noop", "cost": 0.0}
        if action_idx < 0 or action_idx >= self.n_actions:
            raise ValueError(f"Invalid action index {action_idx}")

        # Apply defender action
        if action_idx < len(self._action_catalog):
            action = self._action_catalog[action_idx]
            cost = compute_composite_cost(action, self.graph).total

            if action.action_id in self._active_action_ids:
                reward -= 0.25
                info["invalid_reason"] = "action_already_active"
            elif cost <= self._budget_remaining:
                self._budget_remaining -= cost
                self._active_actions.append(action)
                self._active_action_ids.add(action.action_id)
                info["action"] = action.action_type.value
                info["cost"] = cost
                info["target_node"] = action.target_node
            else:
                reward -= 0.25
                info["invalid_reason"] = "budget_exceeded"

        # Simulate attacker against current defense setup
        reward_interventions = {}
        for act in self._active_actions:
            if act.action_type in (
                DeceptionActionType.DEPLOY_DECOY_DATABASE,
                DeceptionActionType.DEPLOY_DECOY_ROUTER,
            ):
                key = (act.target_node, "end")
                reward_interventions[key] = (
                    reward_interventions.get(key, 0.0) + act.reward_delta
                )
            elif act.action_type == DeceptionActionType.SCATTER_HONEY_CREDENTIAL:
                cred_key = (act.target_node, "cred_dump")
                end_key = (act.target_node, "end")
                reward_interventions[cred_key] = (
                    reward_interventions.get(cred_key, 0.0)
                    + act.reward_delta * 0.5
                )
                reward_interventions[end_key] = (
                    reward_interventions.get(end_key, 0.0)
                    + act.reward_delta * 0.3
                )

        runtime_graph = build_runtime_graph(
            self._base_graph,
            actions=self._active_actions,
        )
        result = run_simulation(
            runtime_graph,
            self.attacker_type,
            n_episodes=self.n_attacker_episodes,
            reward_interventions=reward_interventions,
            seed=self.rng.randint(0, 100000),
            start_distribution=self._belief,
        )

        # Compute defender reward
        decoy_rate = result["decoy_interception_rate"]
        true_goal_rate = result["hit_true_goal_rate"]
        avg_steps = result["avg_steps_to_terminal"]
        cost_penalty = info["cost"] * self.cost_weight

        reward += (
            decoy_rate * 1.0
            - true_goal_rate * 2.0
            + (avg_steps / 30.0) * 0.2
            - cost_penalty
        )

        info["decoy_rate"] = decoy_rate
        info["true_goal_rate"] = true_goal_rate
        info["avg_steps"] = avg_steps
        info["reward"] = reward

        terminated = self._budget_remaining <= 0.01
        truncated = self._step >= self.max_steps
        info["action_mask"] = self.action_mask()

        return self._get_obs(), reward, terminated, truncated, info

    def action_mask(self) -> np.ndarray:
        """Return a boolean mask of valid actions (budget-feasible)."""
        from mirage.layer2_graph_engine.mdp_solver import compute_composite_cost
        mask = np.ones(self.n_actions, dtype=bool)
        for i, act in enumerate(self._action_catalog):
            cost = compute_composite_cost(act, self.graph).total
            if (
                cost > self._budget_remaining
                or act.action_id in self._active_action_ids
            ):
                mask[i] = False
        # NOOP is always valid
        mask[-1] = True
        return mask


# ============================================================
# Experience Replay Buffer
# ============================================================

class ReplayBuffer:
    """Fixed-size circular buffer for DQN experience replay."""

    def __init__(self, capacity: int = 10000, seed: int = 42):
        self.buffer = deque(maxlen=capacity)
        self.rng = random.Random(seed)

    def push(self, state, action, reward, next_state, done):
        self.buffer.append((state, action, reward, next_state, done))

    def sample(self, batch_size: int) -> Tuple:
        batch = self.rng.sample(list(self.buffer), min(batch_size, len(self.buffer)))
        states, actions, rewards, next_states, dones = zip(*batch, strict=True)
        return (
            np.array(states, dtype=np.float32),
            np.array(actions, dtype=np.int64),
            np.array(rewards, dtype=np.float32),
            np.array(next_states, dtype=np.float32),
            np.array(dones, dtype=np.float32),
        )

    def __len__(self):
        return len(self.buffer)


# ============================================================
# DQN Agent — PyTorch (primary) or NumPy (fallback)
# ============================================================

if HAS_TORCH:
    class _QNetwork(nn.Module):
        """3-layer MLP Q-network."""

        def __init__(self, state_dim: int, n_actions: int, hidden: int = 128):
            super().__init__()
            self.net = nn.Sequential(
                nn.Linear(state_dim, hidden),
                nn.ReLU(),
                nn.Linear(hidden, hidden),
                nn.ReLU(),
                nn.Linear(hidden, n_actions),
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            return self.net(x)


class DQNAgent:
    """
    Deep Q-Network agent for MIRAGE defender decisions.

    Architecture:
      - 3-layer MLP: state_dim → 128 → 128 → n_actions
      - Experience Replay (buffer size 10000)
      - Target Network (update every 100 steps)
      - ε-greedy exploration (ε: 1.0 → 0.05 over training)
      - Action masking (only budget-feasible actions)

    Falls back to a two-hidden-layer NumPy DQN if PyTorch is unavailable.
    """

    def __init__(
        self,
        env: MIRAGEDefenderEnv,
        lr: float = 1e-3,
        gamma: float = 0.99,
        epsilon_start: float = 1.0,
        epsilon_end: float = 0.05,
        epsilon_decay: int = 500,
        batch_size: int = 64,
        buffer_size: int = 10000,
        target_update: int = 100,
        seed: int = 42,
        backend: Optional[str] = None,
    ):
        self.env = env
        self.gamma = gamma
        self.epsilon_start = epsilon_start
        self.epsilon_end = epsilon_end
        self.epsilon_decay = epsilon_decay
        self.batch_size = batch_size
        self.target_update = target_update
        self.rng = random.Random(seed)
        self.steps_done = 0
        self.training_rewards: List[float] = []
        if not math.isfinite(lr) or lr <= 0:
            raise ValueError("lr must be finite and positive")
        if not math.isfinite(gamma) or not 0 <= gamma <= 1:
            raise ValueError("gamma must satisfy 0 <= gamma <= 1")
        if (
            not math.isfinite(epsilon_start)
            or not math.isfinite(epsilon_end)
            or not 0 <= epsilon_end <= epsilon_start <= 1
        ):
            raise ValueError(
                "epsilon values must satisfy 0 <= end <= start <= 1"
            )
        if epsilon_decay < 1:
            raise ValueError("epsilon_decay must be at least 1")
        if batch_size < 1 or buffer_size < 1 or target_update < 1:
            raise ValueError(
                "batch_size, buffer_size, and target_update must be at least 1"
            )

        self.buffer = ReplayBuffer(buffer_size, seed=seed)

        state_dim = env.state_dim
        n_actions = env.n_actions
        rl_config = load_config().get("rl", {})
        hidden = int(rl_config.get("hidden_size", 128))
        selected_backend = str(
            backend or rl_config.get("backend", "numpy")
        ).lower()
        if selected_backend not in {"numpy", "torch", "auto"}:
            raise ValueError("backend must be 'numpy', 'torch', or 'auto'")
        if selected_backend == "torch" and not HAS_TORCH:
            raise RuntimeError(
                "PyTorch backend requested but torch is not installed"
            )
        use_torch = HAS_TORCH and selected_backend in {"torch", "auto"}

        if use_torch:
            torch.manual_seed(seed)
            self.device = torch.device("cpu")
            self.q_network = _QNetwork(state_dim, n_actions, hidden=hidden).to(self.device)
            self.target_network = _QNetwork(state_dim, n_actions, hidden=hidden).to(self.device)
            self.target_network.load_state_dict(self.q_network.state_dict())
            self.optimizer = optim.Adam(self.q_network.parameters(), lr=lr)
            self._use_torch = True
        else:
            np_rng = np.random.RandomState(seed)
            scale1 = math.sqrt(2.0 / max(1, state_dim))
            scale2 = math.sqrt(2.0 / max(1, hidden))
            self._W1 = (np_rng.randn(state_dim, hidden) * scale1).astype(np.float32)
            self._b1 = np.zeros(hidden, dtype=np.float32)
            self._W2 = (np_rng.randn(hidden, hidden) * scale2).astype(np.float32)
            self._b2 = np.zeros(hidden, dtype=np.float32)
            self._W3 = (np_rng.randn(hidden, n_actions) * scale2).astype(np.float32)
            self._b3 = np.zeros(n_actions, dtype=np.float32)
            self._target_weights = self._numpy_weights_copy()
            self._lr = lr
            self._use_torch = False

        from mirage.layer2_graph_engine.mdp_solver import compute_composite_cost

        self._action_costs = np.asarray(
            [
                compute_composite_cost(action, env.graph).total
                for action in env._action_catalog
            ] + [0.0],
            dtype=np.float32,
        )

    def _model_signature(self) -> Tuple[List[int], List[str]]:
        state_ids = [int(state) for state in self.env.graph.states]
        action_ids = [
            action.action_id for action in self.env._action_catalog
        ] + ["__noop__"]
        return state_ids, action_ids

    def _numpy_weights_copy(self) -> Tuple[np.ndarray, ...]:
        return tuple(
            value.copy()
            for value in (
                self._W1, self._b1, self._W2,
                self._b2, self._W3, self._b3,
            )
        )

    @staticmethod
    def _numpy_forward(
        states: np.ndarray,
        weights: Tuple[np.ndarray, ...],
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        W1, b1, W2, b2, W3, b3 = weights
        z1 = states @ W1 + b1
        h1 = np.maximum(z1, 0.0)
        z2 = h1 @ W2 + b2
        h2 = np.maximum(z2, 0.0)
        q_values = h2 @ W3 + b3
        return z1, h1, z2, h2, q_values

    def _get_epsilon(self) -> float:
        return self.epsilon_end + (self.epsilon_start - self.epsilon_end) * \
            math.exp(-self.steps_done / self.epsilon_decay)

    def _action_masks_from_states(self, states: np.ndarray) -> np.ndarray:
        """Reconstruct budget/duplicate masks from encoded observations."""
        budgets = (
            states[:, self.env.n_nodes]
            * max(1.0, float(self.env.graph.budget))
        )
        masks = self._action_costs[None, :] <= budgets[:, None] + 1e-7
        if self.env._action_catalog:
            active_start = self.env.n_nodes + 2
            active = states[
                :,
                active_start:active_start + len(self.env._action_catalog),
            ]
            masks[:, :-1] &= active < 0.5
        masks[:, -1] = True
        return masks

    def select_action(
        self,
        state: np.ndarray,
        action_mask: Optional[np.ndarray] = None,
        greedy: bool = False,
    ) -> int:
        """Select action using ε-greedy with action masking."""
        epsilon = 0.0 if greedy else self._get_epsilon()

        if self.rng.random() < epsilon:
            # Random valid action
            if action_mask is not None:
                valid = np.where(action_mask)[0]
                return int(self.rng.choice(valid)) if len(valid) > 0 else 0
            return self.rng.randint(0, self.env.n_actions - 1)

        # Greedy from Q-values
        q_values = self._predict_q(state)

        if action_mask is not None:
            # Mask invalid actions with -inf
            q_values[~action_mask] = -1e10

        return int(np.argmax(q_values))

    def _predict_q(self, state: np.ndarray) -> np.ndarray:
        """Predict Q-values for a single state."""
        if self._use_torch:
            with torch.no_grad():
                s = torch.FloatTensor(state).unsqueeze(0).to(self.device)
                q = self.q_network(s).cpu().numpy()[0]
            return q
        else:
            weights = (
                self._W1, self._b1, self._W2,
                self._b2, self._W3, self._b3,
            )
            return self._numpy_forward(state.reshape(1, -1), weights)[-1][0]

    def _update(self):
        """Perform one gradient update on the Q-network."""
        if len(self.buffer) < self.batch_size:
            return

        states, actions, rewards, next_states, dones = self.buffer.sample(self.batch_size)

        if self._use_torch:
            s = torch.FloatTensor(states).to(self.device)
            a = torch.LongTensor(actions).to(self.device)
            r = torch.FloatTensor(rewards).to(self.device)
            s_next = torch.FloatTensor(next_states).to(self.device)
            d = torch.FloatTensor(dones).to(self.device)

            # Current Q-values
            q_values = self.q_network(s).gather(1, a.unsqueeze(1)).squeeze(1)

            # Target Q-values (from target network)
            with torch.no_grad():
                next_all = self.target_network(s_next)
                next_mask = torch.BoolTensor(
                    self._action_masks_from_states(next_states)
                ).to(self.device)
                next_all = next_all.masked_fill(~next_mask, -1e10)
                next_q = next_all.max(1)[0]
                target = r + self.gamma * next_q * (1 - d)

            loss = nn.functional.mse_loss(q_values, target)
            self.optimizer.zero_grad()
            loss.backward()
            # Gradient clipping
            nn.utils.clip_grad_norm_(self.q_network.parameters(), 1.0)
            self.optimizer.step()
        else:
            weights = (
                self._W1, self._b1, self._W2,
                self._b2, self._W3, self._b3,
            )
            z1, h1, z2, h2, q_all = self._numpy_forward(states, weights)
            next_q = self._numpy_forward(next_states, self._target_weights)[-1]
            next_q = np.where(
                self._action_masks_from_states(next_states),
                next_q,
                -1e10,
            )
            targets = rewards + self.gamma * np.max(next_q, axis=1) * (1 - dones)

            batch_indices = np.arange(len(states))
            td_error = q_all[batch_indices, actions] - targets
            dq = np.zeros_like(q_all)
            dq[batch_indices, actions] = (2.0 / len(states)) * td_error

            grad_W3 = h2.T @ dq
            grad_b3 = dq.sum(axis=0)
            dh2 = dq @ self._W3.T
            dz2 = dh2 * (z2 > 0)
            grad_W2 = h1.T @ dz2
            grad_b2 = dz2.sum(axis=0)
            dh1 = dz2 @ self._W2.T
            dz1 = dh1 * (z1 > 0)
            grad_W1 = states.T @ dz1
            grad_b1 = dz1.sum(axis=0)

            gradients = [grad_W1, grad_b1, grad_W2, grad_b2, grad_W3, grad_b3]
            total_norm = math.sqrt(sum(float(np.sum(g * g)) for g in gradients))
            scale = min(1.0, 1.0 / max(total_norm, 1e-8))
            parameters = [
                self._W1,
                self._b1,
                self._W2,
                self._b2,
                self._W3,
                self._b3,
            ]
            for index, gradient in enumerate(gradients):
                parameters[index] -= self._lr * gradient * scale

    def _update_target_network(self):
        """Copy Q-network weights to target network."""
        if self._use_torch:
            self.target_network.load_state_dict(self.q_network.state_dict())
        else:
            self._target_weights = self._numpy_weights_copy()

    def train(
        self,
        n_episodes: int = 500,
        belief_state: Optional[Dict[int, float]] = None,
        verbose: bool = True,
        log_every: int = 50,
    ) -> List[float]:
        """
        Train the DQN agent via interaction with the MIRAGE environment.

        Args:
            n_episodes: Number of training episodes
            belief_state: Initial belief state for each episode
            verbose: Print training progress
            log_every: Print reward every N episodes

        Returns:
            List of per-episode cumulative rewards
        """
        if n_episodes < 1:
            raise ValueError("n_episodes must be at least 1")
        if log_every < 1:
            raise ValueError("log_every must be at least 1")
        all_rewards = []
        best_reward = -float('inf')

        if verbose:
            print(f"[RL Agent] Training DQN for {n_episodes} episodes...")
            print(f"  State dim: {self.env.state_dim}, Actions: {self.env.n_actions}")
            print(f"  Backend: {'PyTorch' if self._use_torch else 'NumPy (fallback)'}")

        for ep in range(n_episodes):
            state, _ = self.env.reset(
                options={"belief_state": belief_state}
            )
            episode_reward = 0.0
            done = False

            while not done:
                mask = self.env.action_mask()
                action = self.select_action(state, mask)
                next_state, reward, terminated, truncated, info = self.env.step(action)
                done = terminated or truncated

                self.buffer.push(state, action, reward, next_state, float(done))
                self._update()

                state = next_state
                episode_reward += reward
                self.steps_done += 1

                # Periodically update target network
                if self.steps_done % self.target_update == 0:
                    self._update_target_network()

            all_rewards.append(episode_reward)
            self.training_rewards.append(episode_reward)

            if episode_reward > best_reward:
                best_reward = episode_reward

            if verbose and (ep + 1) % log_every == 0:
                recent = all_rewards[-log_every:]
                avg = sum(recent) / len(recent)
                eps = self._get_epsilon()
                print(f"  Ep {ep+1:4d}/{n_episodes}: avg_reward={avg:+.4f}, "
                      f"best={best_reward:+.4f}, ε={eps:.3f}")

        if verbose:
            print(f"[RL Agent] Training complete. Best reward: {best_reward:+.4f}")

        return all_rewards

    def decide(
        self,
        belief_state: Optional[Dict[int, float]] = None,
        budget_remaining: Optional[float] = None,
    ) -> Tuple[int, Optional[DeceptionAction], Dict]:
        """
        Make a single greedy decision (inference mode).

        Returns:
            (action_idx, DeceptionAction or None, info_dict)
        """
        options = {
            "belief_state": belief_state,
            "budget_remaining": (
                budget_remaining
                if budget_remaining is not None
                else self.env.graph.budget
            ),
        }
        state, _ = self.env.reset(options=options)
        mask = self.env.action_mask()
        action_idx = self.select_action(state, mask, greedy=True)

        q_values = self._predict_q(state)
        valid_q = q_values[mask]
        if len(valid_q) > 1:
            ordered = np.sort(valid_q)
            confidence = float(1.0 / (1.0 + math.exp(-(ordered[-1] - ordered[-2]))))
        else:
            confidence = 1.0

        if action_idx < len(self.env._action_catalog):
            chosen_action = self.env._action_catalog[action_idx]
        else:
            chosen_action = None  # NOOP

        info = {
            "action_idx": action_idx,
            "q_value": float(q_values[action_idx]),
            "confidence": confidence,
            "epsilon": self._get_epsilon(),
            "is_noop": chosen_action is None,
            "budget_remaining": self.env._budget_remaining,
        }

        return action_idx, chosen_action, info

    def save(self, path: str) -> None:
        """Save trained model weights."""
        model_path = Path(path)
        model_path.parent.mkdir(parents=True, exist_ok=True)
        state_ids, action_ids = self._model_signature()
        if self._use_torch:
            torch.save({
                "q_network": self.q_network.state_dict(),
                "target_network": self.target_network.state_dict(),
                "optimizer": self.optimizer.state_dict(),
                "steps_done": self.steps_done,
                "training_rewards": self.training_rewards,
                "state_dim": self.env.state_dim,
                "n_actions": self.env.n_actions,
                "state_ids": state_ids,
                "action_ids": action_ids,
            }, model_path)
        else:
            with model_path.open("wb") as output:
                np.savez(
                    output,
                    W1=self._W1,
                    b1=self._b1,
                    W2=self._W2,
                    b2=self._b2,
                    W3=self._W3,
                    b3=self._b3,
                    steps_done=self.steps_done,
                    training_rewards=np.asarray(
                        self.training_rewards,
                        dtype=np.float32,
                    ),
                    state_dim=self.env.state_dim,
                    n_actions=self.env.n_actions,
                    state_ids=np.asarray(state_ids, dtype=np.int64),
                    action_ids=np.asarray(action_ids, dtype=np.str_),
                )
        print(f"[RL Agent] Model saved to {model_path}")

    def load(self, path: str) -> None:
        """Load trained model weights."""
        if self._use_torch:
            checkpoint = torch.load(
                path,
                map_location=self.device,
                weights_only=True,
            )
            if (
                checkpoint.get("state_dim", self.env.state_dim) != self.env.state_dim
                or checkpoint.get("n_actions", self.env.n_actions) != self.env.n_actions
            ):
                raise ValueError("Saved RL model is incompatible with this graph/action catalog.")
            expected_states, expected_actions = self._model_signature()
            if (
                checkpoint.get("state_ids") != expected_states
                or checkpoint.get("action_ids") != expected_actions
            ):
                raise ValueError(
                    "Saved RL model graph/action signature does not match"
                )
            self.q_network.load_state_dict(checkpoint["q_network"])
            self.target_network.load_state_dict(checkpoint["target_network"])
            self.optimizer.load_state_dict(checkpoint["optimizer"])
            self.steps_done = checkpoint["steps_done"]
            self.training_rewards = checkpoint.get("training_rewards", [])
        else:
            required = {
                "W1", "b1", "W2", "b2", "W3", "b3",
                "steps_done", "training_rewards", "state_dim", "n_actions",
                "state_ids", "action_ids",
            }
            with np.load(path, allow_pickle=False) as data:
                missing = required.difference(data.files)
                if missing:
                    raise ValueError(
                        f"Saved RL model is missing fields: {sorted(missing)}"
                    )
                if (
                    int(data["state_dim"]) != self.env.state_dim
                    or int(data["n_actions"]) != self.env.n_actions
                ):
                    raise ValueError(
                        "Saved RL model is incompatible with this "
                        "graph/action catalog."
                    )
                expected_states, expected_actions = self._model_signature()
                saved_states = [
                    int(value) for value in data["state_ids"]
                ]
                saved_actions = [
                    str(value) for value in data["action_ids"]
                ]
                if (
                    saved_states != expected_states
                    or saved_actions != expected_actions
                ):
                    raise ValueError(
                        "Saved RL model graph/action signature does not match"
                    )
                arrays = {
                    name: np.asarray(data[name], dtype=np.float32)
                    for name in ("W1", "b1", "W2", "b2", "W3", "b3")
                }
                if not all(
                    np.all(np.isfinite(value))
                    for value in arrays.values()
                ):
                    raise ValueError("Saved RL model contains non-finite weights")
                expected_shapes = {
                    "W1": self._W1.shape,
                    "b1": self._b1.shape,
                    "W2": self._W2.shape,
                    "b2": self._b2.shape,
                    "W3": self._W3.shape,
                    "b3": self._b3.shape,
                }
                for name, expected_shape in expected_shapes.items():
                    if arrays[name].shape != expected_shape:
                        raise ValueError(
                            f"Saved RL model field {name} has shape "
                            f"{arrays[name].shape}, expected {expected_shape}"
                        )
                self._W1 = arrays["W1"]
                self._b1 = arrays["b1"]
                self._W2 = arrays["W2"]
                self._b2 = arrays["b2"]
                self._W3 = arrays["W3"]
                self._b3 = arrays["b3"]
                self.steps_done = int(data["steps_done"])
                self.training_rewards = [
                    float(value) for value in data["training_rewards"]
                ]
                if self.steps_done < 0 or not all(
                    math.isfinite(value) for value in self.training_rewards
                ):
                    raise ValueError(
                        "Saved RL model contains invalid training metadata"
                    )
            self._target_weights = self._numpy_weights_copy()
        print(f"[RL Agent] Model loaded from {path}")


# ============================================================
# RL → ActionPlan Bridge (Layer 4 compatible)
# ============================================================

class RLDecisionBridge:
    """
    Adapter that converts RL agent output into ActionPlan objects
    compatible with Layer 4's RobustDecisionEngine interface.

    Usage:
        bridge = RLDecisionBridge(graph, fabric)
        bridge.train(n_episodes=500)
        plan = bridge.get_action_plan(belief_state, budget_remaining=4.0)
    """

    def __init__(
        self,
        graph: MIRAGEAttackGraph,
        fabric: DeceptionFabric,
        n_attacker_episodes: Optional[int] = None,
        seed: int = 42,
    ):
        self.graph = graph
        self.fabric = fabric

        self.env = MIRAGEDefenderEnv(
            graph, fabric,
            n_attacker_episodes=n_attacker_episodes,
            seed=seed,
        )
        self.agent = DQNAgent(self.env, seed=seed)
        self._trained = False

    def train(self, n_episodes: int = 500, belief_state=None, verbose=True):
        """Train the RL agent."""
        self.agent.train(n_episodes=n_episodes, belief_state=belief_state, verbose=verbose)
        self._trained = True

    def get_action_plan(
        self,
        belief_state: Optional[Dict[int, float]] = None,
        budget_remaining: float = 4.0,
    ):
        """
        Get an ActionPlan from the trained RL agent.

        Returns an ActionPlan compatible with Layer 4/5 pipeline.
        """
        from mirage.layer4_decision.decision_engine import ActionPlan
        from mirage.layer2_graph_engine.mdp_solver import compute_composite_cost

        if not self._trained:
            raise RuntimeError("RL agent has not been trained yet. Call train() first.")

        action_idx, chosen_action, info = self.agent.decide(
            belief_state=belief_state,
            budget_remaining=budget_remaining,
        )

        if chosen_action is None:
            return None

        cost_info = compute_composite_cost(chosen_action, self.graph)

        return ActionPlan(
            action=chosen_action,
            target_node=chosen_action.target_node,
            target_node_label=self.graph.label(chosen_action.target_node),
            optimistic_value=info["q_value"],
            pessimistic_value=(
                info["q_value"]
                - abs(info["q_value"]) * (1.0 - info["confidence"])
            ),
            expected_value=info["q_value"],
            margin_guarantee=0.0,
            risk_score=chosen_action.risk_score,
            confidence=info["confidence"],
            required_approval=chosen_action.risk_score > 0.6,
            reasoning=(
                f"RL agent (DQN) selected {chosen_action.action_type.value} at node "
                f"{chosen_action.target_node} ({self.graph.label(chosen_action.target_node)}). "
                f"Estimated Q-value: {info['q_value']:.4f}, "
                f"ε: {info['epsilon']:.3f}. "
                "No exact MDP margin is claimed for this RL inference."
            ),
            evidence=[
                f"Q-value: {info['q_value']:.4f}",
                f"Confidence: {info['confidence']:.3f}",
                f"Cost: {cost_info.total:.2f}",
                f"Training episodes: {len(self.agent.training_rewards)}",
                "Pessimistic value is a confidence-adjusted RL estimate",
            ],
            rollback_plan=f"Remove {chosen_action.action_type.value} from node {chosen_action.target_node}.",
            monitoring_metrics=[
                "decoy_interception_rate",
                "true_goal_hit_rate",
                "belief_state_drift",
            ],
            portfolio=[chosen_action],
            portfolio_cost=cost_info.total,
            false_positive_cost=cost_info.fp_cost,
            cost_adjusted_value=info["q_value"] - cost_info.total * 0.015,
        )

    def save_model(self, path: str):
        self.agent.save(path)

    def load_model(self, path: str):
        self.agent.load(path)
        self._trained = True


# ============================================================
# Quick demo
# ============================================================

if __name__ == "__main__":
    from mirage.layer2_graph_engine.attack_graph import build_enterprise_attack_graph

    print("=" * 70)
    print("MIRAGE Deep RL Agent — Demo")
    print("=" * 70)

    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)

    bridge = RLDecisionBridge(graph, fabric, seed=42)

    belief = {4: 0.45, 3: 0.25, 5: 0.15, 1: 0.10, 0: 0.05}

    # Train (reduced episodes for demo)
    bridge.train(n_episodes=100, belief_state=belief, verbose=True)

    # Decide
    plan = bridge.get_action_plan(belief_state=belief, budget_remaining=4.0)
    print(plan)
