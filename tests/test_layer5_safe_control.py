from mirage.layer5_safe_control import create_safety_gate, RiskLevel
from mirage.layer3_deception import DeceptionAction, DeceptionActionType

class MockPlan:
    def __init__(self, action, target_node, label, pess_val, confidence):
        self.action = action
        self.target_node = target_node
        self.target_node_label = label
        self.pessimistic_value = pess_val
        self.confidence = confidence
        self.reasoning = "Test reasoning"

def test_safety_gate_protected_node():
    gate = create_safety_gate("results")
    # Action nhắm vào protected node (10)
    action = DeceptionAction(
        action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
        target_node=10,
        risk_score=0.6,
        business_impact=0.2,
    )
    plan = MockPlan(action, 10, "ProtectedDB", 0.5, 0.8)
    
    allowed, decision = gate.check_action_plan(plan, None)
    
    # Should require human approval because it's a protected node
    assert decision.requires_human_approval is True
    assert decision.risk_level == RiskLevel.CRITICAL

def test_safety_gate_fail_safe():
    gate = create_safety_gate("results")
    gate.enter_fail_safe("Testing")
    
    action = DeceptionAction(
        action_type=DeceptionActionType.DEPLOY_DECOY_DATABASE,
        target_node=5,
        risk_score=0.1,
    )
    plan = MockPlan(action, 5, "NormalDB", 0.5, 0.8)
    
    allowed, decision = gate.check_action_plan(plan, None)
    assert not allowed
    assert decision.risk_level == RiskLevel.CRITICAL


def test_safety_gate_honors_plan_approval_flag():
    gate = create_safety_gate("results")
    action = DeceptionAction(
        action_type=DeceptionActionType.SCATTER_HONEY_CREDENTIAL,
        target_node=5,
        risk_score=0.05,
    )
    plan = MockPlan(action, 5, "NormalNode", -0.8, 0.9)
    plan.required_approval = True

    allowed, decision = gate.check_action_plan(plan, None)

    assert allowed
    assert decision.requires_human_approval is True
    assert gate.budget_spent == 0
