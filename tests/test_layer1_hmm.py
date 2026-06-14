import pytest

from mirage.layer1_attack_modeling import AttackStage, TelemetryEvent
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
