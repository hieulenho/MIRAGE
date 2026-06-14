import pytest

from mirage.layer1_attack_modeling import (
    AttackStage,
    AttackStageClassifier,
    TelemetryEvent,
)
from mirage.layer1_hmm import HMMTelemetryClassifier
from mirage.layer2_attack_graph import build_enterprise_attack_graph


def _event(event_type, success=True):
    return TelemetryEvent(
        timestamp=1.0,
        source_host="attacker",
        dest_host="target",
        event_type=event_type,
        success=success,
    )


def test_hmm_distribution_and_graph_belief_are_normalized():
    classifier = HMMTelemetryClassifier()
    for event_type in ["port_scan", "login_attempt", "smb_connect", "credential_use"]:
        belief = classifier.update(_event(event_type))

    assert sum(belief.stage_distribution.values()) == pytest.approx(1.0)
    assert belief.dominant_stage != AttackStage.UNKNOWN

    graph_belief = classifier.get_graph_belief_update(
        "attacker",
        build_enterprise_attack_graph(),
    )
    assert sum(graph_belief.values()) == pytest.approx(1.0)


def test_layer1_bounds_host_and_event_state():
    rule = AttackStageClassifier(
        event_history_limit=2,
        max_tracked_hosts=1,
    )
    rule.process_event(_event("port_scan"))
    rule.process_event(_event("port_scan"))
    rule.process_event(_event("login_attempt"))

    assert len(rule._event_history["attacker"]) == 2
    assert rule._host_counters["attacker"]["port_scans"] == 1

    second_host = TelemetryEvent(
        timestamp=2.0,
        source_host="second",
        dest_host="target",
        event_type="dns_query",
    )
    rule.process_event(second_host)
    assert set(rule.get_all_estimates()) == {"second"}

    hmm = HMMTelemetryClassifier(max_tracked_hosts=1)
    hmm.update(_event("port_scan"))
    hmm.update(second_host)
    assert set(hmm.get_all_beliefs()) == {"second"}


def test_hmm_rejects_malformed_probability_matrices():
    with pytest.raises(ValueError, match="shape"):
        HMMTelemetryClassifier(transition=[[1.0]])
