import numpy as np

from mirage.layer2_attack_graph import build_enterprise_attack_graph
from mirage.layer3_deception import DeceptionFabric
from mirage.rl_agent import DQNAgent, MIRAGEDefenderEnv


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
