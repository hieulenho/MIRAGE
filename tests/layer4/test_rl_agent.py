import numpy as np
import pytest

from mirage.layer2_graph_engine.attack_graph import build_enterprise_attack_graph
from mirage.layer3_deception.deception_fabric import DeceptionFabric
from mirage.layer4_decision.rl_agent import DQNAgent, MIRAGEDefenderEnv


def test_rl_environment_uses_gymnasium_contract_and_action_mask(tmp_path):
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    env = MIRAGEDefenderEnv(
        graph,
        fabric,
        max_steps=1,
        n_attacker_episodes=1,
        seed=7,
    )

    observation, info = env.reset(seed=7)
    assert observation.shape == (env.state_dim,)
    from mirage.layer4_decision.rl_agent import HAS_GYMNASIUM
    if HAS_GYMNASIUM:
        assert env.observation_space.contains(observation)
    assert info["action_mask"].shape == (env.n_actions,)

    action = int(np.flatnonzero(env.action_mask())[0])
    next_observation, reward, terminated, truncated, step_info = env.step(action)
    assert next_observation.shape == observation.shape
    assert isinstance(reward, float)
    assert terminated or truncated
    if action < len(env._action_catalog):
        assert not step_info["action_mask"][action]

    agent = DQNAgent(env, batch_size=2, seed=7)
    model_path = tmp_path / "mirage_dqn.npz"
    agent.save(str(model_path))
    agent.load(str(model_path))


def test_numpy_model_loader_disables_pickle(tmp_path):
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    env = MIRAGEDefenderEnv(
        graph,
        fabric,
        max_steps=1,
        n_attacker_episodes=1,
    )
    agent = DQNAgent(env, batch_size=2)
    if agent._use_torch:
        pytest.skip("NumPy fallback security test")

    model_path = tmp_path / "unsafe.npz"
    np.savez(
        model_path,
        W1=np.array([{"payload": "object"}], dtype=object),
        b1=agent._b1,
        W2=agent._W2,
        b2=agent._b2,
        W3=agent._W3,
        b3=agent._b3,
        steps_done=0,
        training_rewards=np.array([], dtype=np.float32),
        state_dim=env.state_dim,
        n_actions=env.n_actions,
        state_ids=np.asarray(graph.states, dtype=np.int64),
        action_ids=np.asarray(
            [action.action_id for action in env._action_catalog]
            + ["__noop__"],
            dtype=np.str_,
        ),
    )

    with pytest.raises(ValueError, match="Object arrays"):
        agent.load(str(model_path))


def test_model_signature_rejects_reordered_action_catalog(tmp_path):
    graph = build_enterprise_attack_graph()
    fabric = DeceptionFabric(graph)
    env = MIRAGEDefenderEnv(
        graph,
        fabric,
        max_steps=1,
        n_attacker_episodes=1,
    )
    model_path = tmp_path / "signed_model.npz"
    DQNAgent(env, batch_size=2).save(str(model_path))

    graph2 = build_enterprise_attack_graph()
    fabric2 = DeceptionFabric(graph2)
    fabric2.action_catalog.reverse()
    env2 = MIRAGEDefenderEnv(
        graph2,
        fabric2,
        max_steps=1,
        n_attacker_episodes=1,
    )

    with pytest.raises(ValueError, match="signature"):
        DQNAgent(env2, batch_size=2).load(str(model_path))
