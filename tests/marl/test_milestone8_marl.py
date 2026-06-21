from __future__ import annotations

import json
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient

from mirage.api.server import create_app
from mirage.config import DEFAULT_CONFIG, load_config
from mirage.marl.actions import BlueActionAdapter, RedActionCatalog
from mirage.marl.cli import main as marl_main
from mirage.marl.environment import CyberRangeEnvironment
from mirage.marl.evaluation import ExploitabilityEvaluator, PolicyRobustnessEvaluator
from mirage.marl.policies import BlueMARLPolicyAdapter
from mirage.marl.scenarios import load_scenarios
from mirage.marl.schema import RangeIsolationConfig, RedActionCategory
from mirage.marl.training import SelfPlayTrainer


def test_marl_isolation_defaults_and_config_fail_closed(tmp_path):
    isolation = RangeIsolationConfig()

    assert isolation.cyber_range_only is True
    assert isolation.red_agent_external_network is False
    assert isolation.production_connectivity is False
    assert isolation.real_exploitation_enabled is False
    assert isolation.blue_execution_mode == "shadow"
    assert isolation.training_api_enabled is False

    unsafe = deepcopy(DEFAULT_CONFIG)
    unsafe["marl"]["real_exploitation_enabled"] = True
    config_path = tmp_path / "unsafe.json"
    config_path.write_text(json.dumps(unsafe), encoding="utf-8")

    with pytest.raises(ValueError, match="real_exploitation_enabled=false"):
        load_config(config_path)


def test_red_action_catalog_is_finite_allowlisted_and_non_executable():
    scenario = load_scenarios(1)[0]
    env = CyberRangeEnvironment(scenario)
    env.reset(seed=123)
    actions = RedActionCatalog().build(scenario, env._state())
    allowed_categories = {category for category in RedActionCategory}
    forbidden = [
        "command",
        "payload",
        "shell",
        "socket",
        "http://",
        "https://",
        "nmap",
        "metasploit",
    ]

    assert actions
    assert {action.category for action in actions} <= allowed_categories
    assert len(actions) < 30
    for action in actions:
        text = action.model_dump_json().lower()
        assert not any(term in text for term in forbidden)


def test_environment_snapshot_restore_replay_is_deterministic():
    scenario = load_scenarios(1)[0]
    env_a = CyberRangeEnvironment(scenario)
    env_a.reset(seed=99)
    snapshot = env_a.snapshot()

    env_b = CyberRangeEnvironment(scenario)
    env_c = CyberRangeEnvironment(scenario)
    env_b.restore(snapshot)
    env_c.restore(snapshot)
    red_action = next(
        action.action_id
        for action in env_b.valid_red_actions()
        if action.category == RedActionCategory.RECON
    )

    result_b = env_b.step(red_action, "blue:noop")
    result_c = env_c.step(red_action, "blue:noop")

    assert result_b.red_reward == result_c.red_reward
    assert result_b.blue_reward == result_c.blue_reward
    assert env_b.snapshot() == env_c.snapshot()

    env_replay = CyberRangeEnvironment(scenario)
    env_replay.restore(snapshot)
    replay = env_replay.replay([
        {"red_action_id": red_action, "blue_action_id": "blue:noop"}
    ])
    assert replay[0].red_reward == result_b.red_reward
    assert env_replay.snapshot() == env_b.snapshot()


def test_blue_adapter_and_policy_respect_action_masks():
    scenario = load_scenarios(1)[0]
    env = CyberRangeEnvironment(scenario)
    env.reset(seed=5)
    state = env._state()
    state.blue_budget_remaining = 0.0
    actions, masks = BlueActionAdapter().candidate_actions(scenario, state)
    selected = BlueMARLPolicyAdapter().select_action(
        env.observation_adapter.blue_adapter.encode(scenario, state)
    )

    assert "blue:noop" in {action.action_id for action in actions}
    assert selected == "blue:noop"
    assert masks[selected].allowed is True
    assert any(not mask.allowed for action_id, mask in masks.items() if action_id != "blue:noop")


def test_self_play_exploitability_and_robustness_are_synthetic_and_bounded():
    scenarios = load_scenarios(3)
    trainer = SelfPlayTrainer(scenarios)

    summary = trainer.self_play(episodes=3)
    exploitability = ExploitabilityEvaluator(scenarios).evaluate()
    robustness = PolicyRobustnessEvaluator(scenarios).evaluate()

    assert summary.episodes == 3
    assert summary.policy_metadata is not None
    assert summary.policy_metadata.safety["real_exploitation_enabled"] is False
    assert exploitability.scenario_count == 3
    assert exploitability.approximate_exploitability >= 0
    assert "not production evidence" in exploitability.note
    assert robustness.scenario_count == 3
    assert robustness.opponent_count >= 5


def test_marl_cli_range_check_and_evaluate(capsys):
    assert marl_main(["range-check"]) == 0
    assert marl_main(["evaluate", "--scenarios", "2"]) == 0

    output = capsys.readouterr().out
    assert '"status": "isolated"' in output
    assert '"exploitability"' in output


def test_marl_api_health_training_disabled_eval_replay_and_population():
    client = TestClient(create_app())

    health = client.get("/api/v1/marl/range-health")
    train = client.post(
        "/api/v1/marl/train",
        json={"algorithm": "self_play", "episodes": 1, "scenario_count": 1},
    )
    evaluate = client.post("/api/v1/marl/evaluate", json={"scenario_count": 2})
    replay = client.post(
        "/api/v1/marl/replay",
        json={
            "scenario_id": "marl_scenario_00",
            "steps": [
                {
                    "red_action_id": "red:recon:s0:entry",
                    "blue_action_id": "blue:noop",
                }
            ],
        },
    )
    population = client.get("/api/v1/marl/population")

    assert health.status_code == 200
    assert health.json()["status"] == "isolated"
    assert health.json()["training_api_enabled"] is False
    assert train.status_code == 403
    assert evaluate.status_code == 200
    assert "robustness" in evaluate.json()
    assert replay.status_code == 200
    assert replay.json()["final_state"]["scenario_id"] == "marl_scenario_00"
    assert population.status_code == 200
    assert len(population.json()["opponents"]) >= 5
