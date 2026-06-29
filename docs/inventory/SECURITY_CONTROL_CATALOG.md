# Security Control Catalog

Items: 13

## 1. operating_mode

- control: operating_mode
- expected: shadow
- observed: shadow
- configuration_key: production.operating_mode
- satisfied: True

## 2. deployment_level

- control: deployment_level
- expected: SHADOW_ONLY
- observed: SHADOW_ONLY
- configuration_key: production.deployment_level
- satisfied: True

## 3. production_execution_enabled

- control: production_execution_enabled
- expected: False
- observed: False
- configuration_key: production.production_execution_enabled
- satisfied: True

## 4. high_risk_automation_enabled

- control: high_risk_automation_enabled
- expected: False
- observed: False
- configuration_key: production.high_risk_automation_enabled
- satisfied: True

## 5. action_mask_required

- control: action_mask_required
- expected: True
- observed: True
- configuration_key: production.action_mask_required
- satisfied: True

## 6. safety_gate_required

- control: safety_gate_required
- expected: True
- observed: True
- configuration_key: production.safety_gate_required
- satisfied: True

## 7. formal_verification_required

- control: formal_verification_required
- expected: True
- observed: True
- configuration_key: production.formal_verification_required
- satisfied: True

## 8. governance_gate_required

- control: governance_gate_required
- expected: True
- observed: True
- configuration_key: production.governance_gate_required
- satisfied: True

## 9. audit_required

- control: audit_required
- expected: True
- observed: None
- configuration_key: 
- satisfied: False

## 10. rollback_required

- control: rollback_required
- expected: True
- observed: None
- configuration_key: 
- satisfied: False

## 11. red_agent_cyber_range_only

- control: red_agent_cyber_range_only
- expected: True
- observed: None
- configuration_key: 
- satisfied: False

## 12. red_agent_external_network

- control: red_agent_external_network
- expected: False
- observed: False
- configuration_key: marl.red_agent_external_network
- satisfied: True

## 13. real_exploitation_enabled

- control: real_exploitation_enabled
- expected: False
- observed: False
- configuration_key: marl.real_exploitation_enabled
- satisfied: True
