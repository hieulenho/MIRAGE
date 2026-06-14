from mirage.policy_cache import (
    CachedPolicy,
    OnlinePolicyController,
    PolicyCache,
)


class _Fabric:
    action_catalog = []

    @staticmethod
    def deploy_action(action):
        return action


def test_policy_cache_atomic_round_trip(tmp_path):
    path = tmp_path / "policy_cache.json"
    cache = PolicyCache(str(path))
    cache.put(CachedPolicy(
        stage="Discovery",
        belief_key="entry",
        criterion="expected",
        budget=2.0,
        action_ids=[],
        metrics={"expected_value": 0.1},
        created_at=1.0,
    ))
    cache.save()

    loaded = PolicyCache(str(path))

    assert loaded.get("Discovery", None, "expected", 2.0) is not None
    assert not list(tmp_path.glob("*.tmp"))


def test_online_controller_rejects_stale_action_ids(tmp_path):
    cache = PolicyCache(str(tmp_path / "cache.json"))
    cache.put(CachedPolicy(
        stage="Discovery",
        belief_key="entry",
        criterion="expected",
        budget=2.0,
        action_ids=["missing-action"],
        metrics={},
        created_at=1.0,
    ))
    controller = OnlinePolicyController(_Fabric(), cache)

    result = controller.handle(
        telemetry={},
        stage_estimator=lambda _: "Discovery",
        belief_updater=lambda _: None,
        safety_gate=lambda actions, belief: (True, ""),
        budget=2.0,
        criterion="expected",
    )

    assert result["status"] == "cache_stale"
