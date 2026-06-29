# Configuration Catalog

Items: 682

## 1. analysis.candidate_actions.action_costs.add_decoy_service

- key: analysis.candidate_actions.action_costs.add_decoy_service
- type: float
- default_or_configured_value: 1.0

## 2. analysis.candidate_actions.action_costs.block_egress

- key: analysis.candidate_actions.action_costs.block_egress
- type: float
- default_or_configured_value: 1.0

## 3. analysis.candidate_actions.action_costs.create_soc_ticket

- key: analysis.candidate_actions.action_costs.create_soc_ticket
- type: float
- default_or_configured_value: 0.1

## 4. analysis.candidate_actions.action_costs.deploy_decoy_database

- key: analysis.candidate_actions.action_costs.deploy_decoy_database
- type: float
- default_or_configured_value: 1.5

## 5. analysis.candidate_actions.action_costs.deploy_fake_share

- key: analysis.candidate_actions.action_costs.deploy_fake_share
- type: float
- default_or_configured_value: 0.9

## 6. analysis.candidate_actions.action_costs.enable_auth_auditing

- key: analysis.candidate_actions.action_costs.enable_auth_auditing
- type: float
- default_or_configured_value: 0.25

## 7. analysis.candidate_actions.action_costs.enable_limited_packet_capture

- key: analysis.candidate_actions.action_costs.enable_limited_packet_capture
- type: float
- default_or_configured_value: 0.5

## 8. analysis.candidate_actions.action_costs.increase_endpoint_logging

- key: analysis.candidate_actions.action_costs.increase_endpoint_logging
- type: float
- default_or_configured_value: 0.2

## 9. analysis.candidate_actions.action_costs.increase_network_telemetry

- key: analysis.candidate_actions.action_costs.increase_network_telemetry
- type: float
- default_or_configured_value: 0.3

## 10. analysis.candidate_actions.action_costs.isolate_host

- key: analysis.candidate_actions.action_costs.isolate_host
- type: float
- default_or_configured_value: 2.0

## 11. analysis.candidate_actions.action_costs.request_analyst_review

- key: analysis.candidate_actions.action_costs.request_analyst_review
- type: float
- default_or_configured_value: 0.1

## 12. analysis.candidate_actions.action_costs.require_mfa

- key: analysis.candidate_actions.action_costs.require_mfa
- type: float
- default_or_configured_value: 0.8

## 13. analysis.candidate_actions.action_costs.restrict_smb

- key: analysis.candidate_actions.action_costs.restrict_smb
- type: float
- default_or_configured_value: 0.7

## 14. analysis.candidate_actions.action_costs.scatter_honey_credential

- key: analysis.candidate_actions.action_costs.scatter_honey_credential
- type: float
- default_or_configured_value: <redacted>

## 15. analysis.candidate_actions.action_costs.temporary_segmentation

- key: analysis.candidate_actions.action_costs.temporary_segmentation
- type: float
- default_or_configured_value: 1.2

## 16. analysis.candidate_actions.action_costs.throttle_edge

- key: analysis.candidate_actions.action_costs.throttle_edge
- type: float
- default_or_configured_value: 0.5

## 17. analysis.candidate_actions.business_risks.add_decoy_service

- key: analysis.candidate_actions.business_risks.add_decoy_service
- type: float
- default_or_configured_value: 0.1

## 18. analysis.candidate_actions.business_risks.block_egress

- key: analysis.candidate_actions.business_risks.block_egress
- type: float
- default_or_configured_value: 0.55

## 19. analysis.candidate_actions.business_risks.create_soc_ticket

- key: analysis.candidate_actions.business_risks.create_soc_ticket
- type: float
- default_or_configured_value: 0.01

## 20. analysis.candidate_actions.business_risks.deploy_decoy_database

- key: analysis.candidate_actions.business_risks.deploy_decoy_database
- type: float
- default_or_configured_value: 0.1

## 21. analysis.candidate_actions.business_risks.deploy_fake_share

- key: analysis.candidate_actions.business_risks.deploy_fake_share
- type: float
- default_or_configured_value: 0.08

## 22. analysis.candidate_actions.business_risks.enable_auth_auditing

- key: analysis.candidate_actions.business_risks.enable_auth_auditing
- type: float
- default_or_configured_value: 0.05

## 23. analysis.candidate_actions.business_risks.enable_limited_packet_capture

- key: analysis.candidate_actions.business_risks.enable_limited_packet_capture
- type: float
- default_or_configured_value: 0.15

## 24. analysis.candidate_actions.business_risks.increase_endpoint_logging

- key: analysis.candidate_actions.business_risks.increase_endpoint_logging
- type: float
- default_or_configured_value: 0.05

## 25. analysis.candidate_actions.business_risks.increase_network_telemetry

- key: analysis.candidate_actions.business_risks.increase_network_telemetry
- type: float
- default_or_configured_value: 0.05

## 26. analysis.candidate_actions.business_risks.isolate_host

- key: analysis.candidate_actions.business_risks.isolate_host
- type: float
- default_or_configured_value: 0.75

## 27. analysis.candidate_actions.business_risks.request_analyst_review

- key: analysis.candidate_actions.business_risks.request_analyst_review
- type: float
- default_or_configured_value: 0.01

## 28. analysis.candidate_actions.business_risks.require_mfa

- key: analysis.candidate_actions.business_risks.require_mfa
- type: float
- default_or_configured_value: 0.25

## 29. analysis.candidate_actions.business_risks.restrict_smb

- key: analysis.candidate_actions.business_risks.restrict_smb
- type: float
- default_or_configured_value: 0.3

## 30. analysis.candidate_actions.business_risks.scatter_honey_credential

- key: analysis.candidate_actions.business_risks.scatter_honey_credential
- type: float
- default_or_configured_value: <redacted>

## 31. analysis.candidate_actions.business_risks.temporary_segmentation

- key: analysis.candidate_actions.business_risks.temporary_segmentation
- type: float
- default_or_configured_value: 0.5

## 32. analysis.candidate_actions.business_risks.throttle_edge

- key: analysis.candidate_actions.business_risks.throttle_edge
- type: float
- default_or_configured_value: 0.2

## 33. analysis.candidate_actions.default_ttl_seconds

- key: analysis.candidate_actions.default_ttl_seconds
- type: int
- default_or_configured_value: 3600

## 34. analysis.candidate_actions.enabled_action_types

- key: analysis.candidate_actions.enabled_action_types
- type: list
- default_or_configured_value: ["increase_endpoint_logging", "increase_network_telemetry", "enable_limited_packet_capture", "enable_auth_auditing", "create_soc_ticket", "request_analyst_review", "deploy_decoy_database", "deploy_fake_share", "scatter_honey_credential", "add_decoy_service", "throttle_edge", "restrict_smb", "require_mfa", "temporary_segmentation", "block_egress", "isolate_host"]

## 35. analysis.candidate_actions.information_gain_weights.control

- key: analysis.candidate_actions.information_gain_weights.control
- type: float
- default_or_configured_value: 0.3

## 36. analysis.candidate_actions.information_gain_weights.deception

- key: analysis.candidate_actions.information_gain_weights.deception
- type: float
- default_or_configured_value: 0.7

## 37. analysis.candidate_actions.information_gain_weights.observe

- key: analysis.candidate_actions.information_gain_weights.observe
- type: float
- default_or_configured_value: 0.8

## 38. analysis.constraints.action_budget

- key: analysis.constraints.action_budget
- type: float
- default_or_configured_value: 6.0

## 39. analysis.constraints.active_decoy_limit

- key: analysis.constraints.active_decoy_limit
- type: int
- default_or_configured_value: 20

## 40. analysis.constraints.blast_radius_limit

- key: analysis.constraints.blast_radius_limit
- type: int
- default_or_configured_value: 5

## 41. analysis.constraints.deny_action_types

- key: analysis.constraints.deny_action_types
- type: list
- default_or_configured_value: ["delete_credentials", "block_all_traffic"]

## 42. analysis.constraints.graph_coverage_threshold

- key: analysis.constraints.graph_coverage_threshold
- type: float
- default_or_configured_value: 0.2

## 43. analysis.constraints.protected_asset_ids

- key: analysis.constraints.protected_asset_ids
- type: list
- default_or_configured_value: []

## 44. analysis.constraints.protected_asset_types

- key: analysis.constraints.protected_asset_types
- type: list
- default_or_configured_value: ["database", "dc", "domain_controller"]

## 45. analysis.constraints.required_confidence_threshold

- key: analysis.constraints.required_confidence_threshold
- type: float
- default_or_configured_value: 0.35

## 46. analysis.constraints.twin_freshness_threshold

- key: analysis.constraints.twin_freshness_threshold
- type: float
- default_or_configured_value: 0.35

## 47. analysis.paths.enabled_path_types

- key: analysis.paths.enabled_path_types
- type: list
- default_or_configured_value: ["shortest_to_critical_asset", "highest_success_probability", "highest_risk", "credential_driven", "recently_observed", "decoy_path", "unprotected_path", "high_blast_radius"]

## 48. analysis.paths.inferred_edge_penalty

- key: analysis.paths.inferred_edge_penalty
- type: float
- default_or_configured_value: 0.25

## 49. analysis.paths.maximum_path_length

- key: analysis.paths.maximum_path_length
- type: int
- default_or_configured_value: 6

## 50. analysis.paths.maximum_paths_per_target

- key: analysis.paths.maximum_paths_per_target
- type: int
- default_or_configured_value: 3

## 51. analysis.paths.maximum_total_paths

- key: analysis.paths.maximum_total_paths
- type: int
- default_or_configured_value: 60

## 52. analysis.paths.observed_edge_bonus

- key: analysis.paths.observed_edge_bonus
- type: float
- default_or_configured_value: 0.12

## 53. analysis.paths.stale_edge_penalty

- key: analysis.paths.stale_edge_penalty
- type: float
- default_or_configured_value: 0.2

## 54. analysis.paths.uncertainty_penalty

- key: analysis.paths.uncertainty_penalty
- type: float
- default_or_configured_value: 0.2

## 55. analysis.ranking.business_risk_weight

- key: analysis.ranking.business_risk_weight
- type: float
- default_or_configured_value: 0.4

## 56. analysis.ranking.deployment_cost_weight

- key: analysis.ranking.deployment_cost_weight
- type: float
- default_or_configured_value: 0.15

## 57. analysis.ranking.information_gain_weight

- key: analysis.ranking.information_gain_weight
- type: float
- default_or_configured_value: 0.4

## 58. analysis.ranking.operational_cost_weight

- key: analysis.ranking.operational_cost_weight
- type: float
- default_or_configured_value: 0.15

## 59. analysis.ranking.path_coverage_weight

- key: analysis.ranking.path_coverage_weight
- type: float
- default_or_configured_value: 0.3

## 60. analysis.ranking.risk_reduction_weight

- key: analysis.ranking.risk_reduction_weight
- type: float
- default_or_configured_value: 1.0

## 61. analysis.ranking.uncertainty_weight

- key: analysis.ranking.uncertainty_weight
- type: float
- default_or_configured_value: 0.3

## 62. analysis.risk_scoring.credential_feasibility_weight

- key: analysis.risk_scoring.credential_feasibility_weight
- type: float
- default_or_configured_value: <redacted>

## 63. analysis.risk_scoring.evidence_recency_weight

- key: analysis.risk_scoring.evidence_recency_weight
- type: float
- default_or_configured_value: 0.8

## 64. analysis.risk_scoring.exposure_weight

- key: analysis.risk_scoring.exposure_weight
- type: float
- default_or_configured_value: 0.5

## 65. analysis.risk_scoring.path_success_weight

- key: analysis.risk_scoring.path_success_weight
- type: float
- default_or_configured_value: 1.0

## 66. analysis.risk_scoring.probability_ceiling

- key: analysis.risk_scoring.probability_ceiling
- type: float
- default_or_configured_value: 0.99

## 67. analysis.risk_scoring.probability_floor

- key: analysis.risk_scoring.probability_floor
- type: float
- default_or_configured_value: 0.01

## 68. analysis.risk_scoring.relationship_confidence_weight

- key: analysis.risk_scoring.relationship_confidence_weight
- type: float
- default_or_configured_value: 0.8

## 69. analysis.risk_scoring.source_compromise_weight

- key: analysis.risk_scoring.source_compromise_weight
- type: float
- default_or_configured_value: 1.0

## 70. analysis.risk_scoring.stage_compatibility_weight

- key: analysis.risk_scoring.stage_compatibility_weight
- type: float
- default_or_configured_value: 0.8

## 71. analysis.risk_scoring.target_criticality_weight

- key: analysis.risk_scoring.target_criticality_weight
- type: float
- default_or_configured_value: 1.0

## 72. analysis.seed_selection.deception_event_priority

- key: analysis.seed_selection.deception_event_priority
- type: float
- default_or_configured_value: 0.25

## 73. analysis.seed_selection.maximum_seeds

- key: analysis.seed_selection.maximum_seeds
- type: int
- default_or_configured_value: 20

## 74. analysis.seed_selection.minimum_attacker_location_probability

- key: analysis.seed_selection.minimum_attacker_location_probability
- type: float
- default_or_configured_value: 0.2

## 75. analysis.seed_selection.minimum_compromise_probability

- key: analysis.seed_selection.minimum_compromise_probability
- type: float
- default_or_configured_value: 0.3

## 76. analysis.seed_selection.neighborhood_deduplication

- key: analysis.seed_selection.neighborhood_deduplication
- type: bool
- default_or_configured_value: True

## 77. analysis.seed_selection.uncertainty_penalty

- key: analysis.seed_selection.uncertainty_penalty
- type: float
- default_or_configured_value: 0.2

## 78. analysis.subgraph.criticality_threshold

- key: analysis.subgraph.criticality_threshold
- type: float
- default_or_configured_value: 0.8

## 79. analysis.subgraph.default_max_hops

- key: analysis.subgraph.default_max_hops
- type: int
- default_or_configured_value: 3

## 80. analysis.subgraph.freshness_threshold

- key: analysis.subgraph.freshness_threshold
- type: int
- default_or_configured_value: 86400

## 81. analysis.subgraph.max_edges

- key: analysis.subgraph.max_edges
- type: int
- default_or_configured_value: 160

## 82. analysis.subgraph.max_nodes

- key: analysis.subgraph.max_nodes
- type: int
- default_or_configured_value: 80

## 83. analysis.subgraph.minimum_edge_confidence

- key: analysis.subgraph.minimum_edge_confidence
- type: float
- default_or_configured_value: 0.1

## 84. analysis.subgraph.relationship_allowlist

- key: analysis.subgraph.relationship_allowlist
- type: list
- default_or_configured_value: []

## 85. api.api_key_env

- key: api.api_key_env
- type: str
- default_or_configured_value: <redacted>

## 86. api.auto_deploy

- key: api.auto_deploy
- type: bool
- default_or_configured_value: True

## 87. api.cors_origins

- key: api.cors_origins
- type: list
- default_or_configured_value: ["http://localhost:8000", "http://127.0.0.1:8000"]

## 88. api.decision_backend

- key: api.decision_backend
- type: str
- default_or_configured_value: robust

## 89. api.decision_history_limit

- key: api.decision_history_limit
- type: int
- default_or_configured_value: 1000

## 90. api.decision_samples

- key: api.decision_samples
- type: int
- default_or_configured_value: 60

## 91. api.host

- key: api.host
- type: str
- default_or_configured_value: 0.0.0.0

## 92. api.max_batch_size

- key: api.max_batch_size
- type: int
- default_or_configured_value: 1000

## 93. api.max_request_bytes

- key: api.max_request_bytes
- type: int
- default_or_configured_value: 2097152

## 94. api.pending_decision_limit

- key: api.pending_decision_limit
- type: int
- default_or_configured_value: 100

## 95. api.port

- key: api.port
- type: int
- default_or_configured_value: 8000

## 96. assurance.backup_rehearsal_path

- key: assurance.backup_rehearsal_path
- type: str
- default_or_configured_value: artifacts/assurance/backups

## 97. assurance.bundle_path

- key: assurance.bundle_path
- type: str
- default_or_configured_value: artifacts/assurance/bundles

## 98. assurance.checks

- key: assurance.checks
- type: list
- default_or_configured_value: ["safety_defaults", "verified_inventory", "production_config", "governance_audit_chain", "backup_restore_rehearsal", "model_policy_cards", "cyber_range_isolation", "federation_default_deny"]

## 99. assurance.evidence_retention_days

- key: assurance.evidence_retention_days
- type: int
- default_or_configured_value: 90

## 100. assurance.schedules.full_hours

- key: assurance.schedules.full_hours
- type: int
- default_or_configured_value: 24

## 101. assurance.schedules.quick_minutes

- key: assurance.schedules.quick_minutes
- type: int
- default_or_configured_value: 60

## 102. capacity.thresholds.broker_lag_messages

- key: capacity.thresholds.broker_lag_messages
- type: float
- default_or_configured_value: 10000.0

## 103. capacity.thresholds.database_load

- key: capacity.thresholds.database_load
- type: float
- default_or_configured_value: 0.8

## 104. capacity.thresholds.event_rate_eps

- key: capacity.thresholds.event_rate_eps
- type: float
- default_or_configured_value: 1000.0

## 105. capacity.thresholds.storage_growth_mb_per_day

- key: capacity.thresholds.storage_growth_mb_per_day
- type: float
- default_or_configured_value: 10240.0

## 106. capacity.thresholds.worker_saturation

- key: capacity.thresholds.worker_saturation
- type: float
- default_or_configured_value: 0.85

## 107. casm.allow_provisional_entities

- key: casm.allow_provisional_entities
- type: bool
- default_or_configured_value: True

## 108. casm.asset_ttl_seconds

- key: casm.asset_ttl_seconds
- type: int
- default_or_configured_value: 86400

## 109. casm.conflict_policy

- key: casm.conflict_policy
- type: str
- default_or_configured_value: preserve_and_warn

## 110. casm.quality_thresholds.minimum_confidence

- key: casm.quality_thresholds.minimum_confidence
- type: float
- default_or_configured_value: 0.35

## 111. casm.quality_thresholds.minimum_coverage

- key: casm.quality_thresholds.minimum_coverage
- type: float
- default_or_configured_value: 0.2

## 112. casm.quality_thresholds.minimum_freshness

- key: casm.quality_thresholds.minimum_freshness
- type: float
- default_or_configured_value: 0.35

## 113. casm.relationship_ttl_seconds

- key: casm.relationship_ttl_seconds
- type: int
- default_or_configured_value: 3600

## 114. casm.source_precedence.active_directory

- key: casm.source_precedence.active_directory
- type: int
- default_or_configured_value: 90

## 115. casm.source_precedence.asset_inventory

- key: casm.source_precedence.asset_inventory
- type: int
- default_or_configured_value: 70

## 116. casm.source_precedence.authoritative_inventory

- key: casm.source_precedence.authoritative_inventory
- type: int
- default_or_configured_value: 100

## 117. casm.source_precedence.edr

- key: casm.source_precedence.edr
- type: int
- default_or_configured_value: 80

## 118. casm.source_precedence.generic_jsonl

- key: casm.source_precedence.generic_jsonl
- type: int
- default_or_configured_value: 40

## 119. casm.source_precedence.iam

- key: casm.source_precedence.iam
- type: int
- default_or_configured_value: 90

## 120. casm.source_precedence.netflow

- key: casm.source_precedence.netflow
- type: int
- default_or_configured_value: 45

## 121. casm.source_precedence.sysmon

- key: casm.source_precedence.sysmon
- type: int
- default_or_configured_value: 75

## 122. casm.source_precedence.vulnerability_scanner

- key: casm.source_precedence.vulnerability_scanner
- type: int
- default_or_configured_value: 70

## 123. casm.source_precedence.zeek

- key: casm.source_precedence.zeek
- type: int
- default_or_configured_value: 50

## 124. connectors.allowed_lateness_seconds

- key: connectors.allowed_lateness_seconds
- type: int
- default_or_configured_value: 300

## 125. connectors.backoff.initial_seconds

- key: connectors.backoff.initial_seconds
- type: float
- default_or_configured_value: 1.0

## 126. connectors.backoff.max_seconds

- key: connectors.backoff.max_seconds
- type: float
- default_or_configured_value: 30.0

## 127. connectors.checkpoint_state_path

- key: connectors.checkpoint_state_path
- type: str
- default_or_configured_value: artifacts/connectors_state.json

## 128. connectors.dead_letter_state_path

- key: connectors.dead_letter_state_path
- type: str
- default_or_configured_value: artifacts/dead_letter_state.json

## 129. connectors.deduplication_window_seconds

- key: connectors.deduplication_window_seconds
- type: int
- default_or_configured_value: 86400

## 130. connectors.default_batch_size

- key: connectors.default_batch_size
- type: int
- default_or_configured_value: 100

## 131. connectors.definitions

- key: connectors.definitions
- type: list
- default_or_configured_value: []

## 132. connectors.enabled

- key: connectors.enabled
- type: bool
- default_or_configured_value: True

## 133. connectors.maximum_buffered_events

- key: connectors.maximum_buffered_events
- type: int
- default_or_configured_value: 1000

## 134. connectors.redaction.redact_command_line

- key: connectors.redaction.redact_command_line
- type: bool
- default_or_configured_value: True

## 135. connectors.redaction.redact_raw_payload

- key: connectors.redaction.redact_raw_payload
- type: bool
- default_or_configured_value: True

## 136. connectors.retry.max_attempts

- key: connectors.retry.max_attempts
- type: int
- default_or_configured_value: 3

## 137. detection.api_timeline_limit

- key: detection.api_timeline_limit
- type: int
- default_or_configured_value: 100

## 138. detection.approved_admin_hosts

- key: detection.approved_admin_hosts
- type: list
- default_or_configured_value: ["admin-jump-01"]

## 139. detection.approved_service_accounts

- key: detection.approved_service_accounts
- type: list
- default_or_configured_value: ["svc-backup", "svc-monitor"]

## 140. detection.compromise_threshold

- key: detection.compromise_threshold
- type: float
- default_or_configured_value: 0.35

## 141. detection.correlation_window_seconds

- key: detection.correlation_window_seconds
- type: int
- default_or_configured_value: 3600

## 142. detection.evidence_decay_seconds

- key: detection.evidence_decay_seconds
- type: int
- default_or_configured_value: 3600

## 143. detection.evidence_ttl_seconds

- key: detection.evidence_ttl_seconds
- type: int
- default_or_configured_value: 3600

## 144. detection.graph_propagation_decay

- key: detection.graph_propagation_decay
- type: float
- default_or_configured_value: 0.45

## 145. detection.graph_propagation_depth

- key: detection.graph_propagation_depth
- type: int
- default_or_configured_value: 1

## 146. detection.high_confidence_deception_threshold

- key: detection.high_confidence_deception_threshold
- type: float
- default_or_configured_value: 0.85

## 147. detection.maintenance_windows

- key: detection.maintenance_windows
- type: list
- default_or_configured_value: []

## 148. detection.rules.R001_SUSPICIOUS_SCRIPT.enabled

- key: detection.rules.R001_SUSPICIOUS_SCRIPT.enabled
- type: bool
- default_or_configured_value: True

## 149. detection.rules.R001_SUSPICIOUS_SCRIPT.score

- key: detection.rules.R001_SUSPICIOUS_SCRIPT.score
- type: float
- default_or_configured_value: 0.65

## 150. detection.rules.R002_INTERNAL_DISCOVERY_BURST.enabled

- key: detection.rules.R002_INTERNAL_DISCOVERY_BURST.enabled
- type: bool
- default_or_configured_value: True

## 151. detection.rules.R002_INTERNAL_DISCOVERY_BURST.score

- key: detection.rules.R002_INTERNAL_DISCOVERY_BURST.score
- type: float
- default_or_configured_value: 0.55

## 152. detection.rules.R003_SMB_LATERAL_PATTERN.enabled

- key: detection.rules.R003_SMB_LATERAL_PATTERN.enabled
- type: bool
- default_or_configured_value: True

## 153. detection.rules.R003_SMB_LATERAL_PATTERN.score

- key: detection.rules.R003_SMB_LATERAL_PATTERN.score
- type: float
- default_or_configured_value: 0.65

## 154. detection.rules.R004_AUTH_SPRAY.enabled

- key: detection.rules.R004_AUTH_SPRAY.enabled
- type: bool
- default_or_configured_value: True

## 155. detection.rules.R004_AUTH_SPRAY.score

- key: detection.rules.R004_AUTH_SPRAY.score
- type: float
- default_or_configured_value: 0.7

## 156. detection.rules.R005_SUCCESS_AFTER_FAILURES.enabled

- key: detection.rules.R005_SUCCESS_AFTER_FAILURES.enabled
- type: bool
- default_or_configured_value: True

## 157. detection.rules.R005_SUCCESS_AFTER_FAILURES.score

- key: detection.rules.R005_SUCCESS_AFTER_FAILURES.score
- type: float
- default_or_configured_value: 0.75

## 158. detection.rules.R006_IDENTITY_FANOUT.enabled

- key: detection.rules.R006_IDENTITY_FANOUT.enabled
- type: bool
- default_or_configured_value: True

## 159. detection.rules.R006_IDENTITY_FANOUT.score

- key: detection.rules.R006_IDENTITY_FANOUT.score
- type: float
- default_or_configured_value: 0.55

## 160. detection.rules.R007_CREDENTIAL_TO_REMOTE.enabled

- key: detection.rules.R007_CREDENTIAL_TO_REMOTE.enabled
- type: bool
- default_or_configured_value: <redacted>

## 161. detection.rules.R007_CREDENTIAL_TO_REMOTE.score

- key: detection.rules.R007_CREDENTIAL_TO_REMOTE.score
- type: float
- default_or_configured_value: <redacted>

## 162. detection.rules.R008_DECEPTION_INTERACTION.enabled

- key: detection.rules.R008_DECEPTION_INTERACTION.enabled
- type: bool
- default_or_configured_value: True

## 163. detection.rules.R008_DECEPTION_INTERACTION.score

- key: detection.rules.R008_DECEPTION_INTERACTION.score
- type: float
- default_or_configured_value: 0.98

## 164. detection.rules.R009_CRITICAL_ASSET_APPROACH.enabled

- key: detection.rules.R009_CRITICAL_ASSET_APPROACH.enabled
- type: bool
- default_or_configured_value: True

## 165. detection.rules.R009_CRITICAL_ASSET_APPROACH.score

- key: detection.rules.R009_CRITICAL_ASSET_APPROACH.score
- type: float
- default_or_configured_value: 0.68

## 166. detection.rules.R010_BENIGN_ADMIN_SUPPRESSION.enabled

- key: detection.rules.R010_BENIGN_ADMIN_SUPPRESSION.enabled
- type: bool
- default_or_configured_value: True

## 167. detection.rules.R010_BENIGN_ADMIN_SUPPRESSION.score

- key: detection.rules.R010_BENIGN_ADMIN_SUPPRESSION.score
- type: float
- default_or_configured_value: -0.45

## 168. detection.stage_priors.collection

- key: detection.stage_priors.collection
- type: float
- default_or_configured_value: 0.03

## 169. detection.stage_priors.credential_access

- key: detection.stage_priors.credential_access
- type: float
- default_or_configured_value: <redacted>

## 170. detection.stage_priors.discovery

- key: detection.stage_priors.discovery
- type: float
- default_or_configured_value: 0.05

## 171. detection.stage_priors.execution

- key: detection.stage_priors.execution
- type: float
- default_or_configured_value: 0.04

## 172. detection.stage_priors.initial_access

- key: detection.stage_priors.initial_access
- type: float
- default_or_configured_value: 0.04

## 173. detection.stage_priors.lateral_movement

- key: detection.stage_priors.lateral_movement
- type: float
- default_or_configured_value: 0.04

## 174. detection.stage_priors.normal

- key: detection.stage_priors.normal
- type: float
- default_or_configured_value: 0.7

## 175. detection.stage_priors.reconnaissance

- key: detection.stage_priors.reconnaissance
- type: float
- default_or_configured_value: 0.02

## 176. detection.stage_transition_weight

- key: detection.stage_transition_weight
- type: float
- default_or_configured_value: 0.15

## 177. detection.timeline_retention_seconds

- key: detection.timeline_retention_seconds
- type: int
- default_or_configured_value: 86400

## 178. detection.windows

- key: detection.windows
- type: list
- default_or_configured_value: [60, 300, 900, 3600]

## 179. drift.automatic_suspension_enabled

- key: drift.automatic_suspension_enabled
- type: bool
- default_or_configured_value: True

## 180. drift.critical_threshold

- key: drift.critical_threshold
- type: float
- default_or_configured_value: 0.7

## 181. drift.shadow_mode_preserved

- key: drift.shadow_mode_preserved
- type: bool
- default_or_configured_value: True

## 182. drift.warning_threshold

- key: drift.warning_threshold
- type: float
- default_or_configured_value: 0.35

## 183. execution.action_budget

- key: execution.action_budget
- type: float
- default_or_configured_value: 6.0

## 184. execution.action_tiers.add_decoy_service

- key: execution.action_tiers.add_decoy_service
- type: int
- default_or_configured_value: 1

## 185. execution.action_tiers.block_egress

- key: execution.action_tiers.block_egress
- type: int
- default_or_configured_value: 3

## 186. execution.action_tiers.block_flow

- key: execution.action_tiers.block_flow
- type: int
- default_or_configured_value: 3

## 187. execution.action_tiers.block_subnet

- key: execution.action_tiers.block_subnet
- type: int
- default_or_configured_value: 4

## 188. execution.action_tiers.create_fake_dns_record

- key: execution.action_tiers.create_fake_dns_record
- type: int
- default_or_configured_value: 1

## 189. execution.action_tiers.create_soc_ticket

- key: execution.action_tiers.create_soc_ticket
- type: int
- default_or_configured_value: 0

## 190. execution.action_tiers.deploy_decoy_database

- key: execution.action_tiers.deploy_decoy_database
- type: int
- default_or_configured_value: 1

## 191. execution.action_tiers.deploy_decoy_host

- key: execution.action_tiers.deploy_decoy_host
- type: int
- default_or_configured_value: 1

## 192. execution.action_tiers.deploy_fake_share

- key: execution.action_tiers.deploy_fake_share
- type: int
- default_or_configured_value: 1

## 193. execution.action_tiers.disable_privileged_identity

- key: execution.action_tiers.disable_privileged_identity
- type: int
- default_or_configured_value: 4

## 194. execution.action_tiers.enable_auth_auditing

- key: execution.action_tiers.enable_auth_auditing
- type: int
- default_or_configured_value: 0

## 195. execution.action_tiers.enable_limited_packet_capture

- key: execution.action_tiers.enable_limited_packet_capture
- type: int
- default_or_configured_value: 0

## 196. execution.action_tiers.increase_endpoint_logging

- key: execution.action_tiers.increase_endpoint_logging
- type: int
- default_or_configured_value: 0

## 197. execution.action_tiers.increase_network_telemetry

- key: execution.action_tiers.increase_network_telemetry
- type: int
- default_or_configured_value: 0

## 198. execution.action_tiers.isolate_database

- key: execution.action_tiers.isolate_database
- type: int
- default_or_configured_value: 4

## 199. execution.action_tiers.isolate_host

- key: execution.action_tiers.isolate_host
- type: int
- default_or_configured_value: 3

## 200. execution.action_tiers.request_analyst_review

- key: execution.action_tiers.request_analyst_review
- type: int
- default_or_configured_value: 0

## 201. execution.action_tiers.restrict_smb

- key: execution.action_tiers.restrict_smb
- type: int
- default_or_configured_value: 2

## 202. execution.action_tiers.revoke_session

- key: execution.action_tiers.revoke_session
- type: int
- default_or_configured_value: 3

## 203. execution.action_tiers.scatter_honey_credential

- key: execution.action_tiers.scatter_honey_credential
- type: int
- default_or_configured_value: <redacted>

## 204. execution.action_tiers.temporary_segmentation

- key: execution.action_tiers.temporary_segmentation
- type: int
- default_or_configured_value: 2

## 205. execution.action_tiers.throttle_edge

- key: execution.action_tiers.throttle_edge
- type: int
- default_or_configured_value: 2

## 206. execution.adapters.docker_decoy

- key: execution.adapters.docker_decoy
- type: bool
- default_or_configured_value: True

## 207. execution.adapters.mock_dns

- key: execution.adapters.mock_dns
- type: bool
- default_or_configured_value: True

## 208. execution.adapters.mock_edr

- key: execution.adapters.mock_edr
- type: bool
- default_or_configured_value: True

## 209. execution.adapters.mock_firewall

- key: execution.adapters.mock_firewall
- type: bool
- default_or_configured_value: True

## 210. execution.adapters.mock_iam

- key: execution.adapters.mock_iam
- type: bool
- default_or_configured_value: True

## 211. execution.adapters.mock_telemetry

- key: execution.adapters.mock_telemetry
- type: bool
- default_or_configured_value: True

## 212. execution.adapters.mock_ticket

- key: execution.adapters.mock_ticket
- type: bool
- default_or_configured_value: True

## 213. execution.approval_ttl_seconds

- key: execution.approval_ttl_seconds
- type: int
- default_or_configured_value: 900

## 214. execution.audit_path

- key: execution.audit_path
- type: str
- default_or_configured_value: artifacts/execution_audit.jsonl

## 215. execution.blast_radius_limit

- key: execution.blast_radius_limit
- type: int
- default_or_configured_value: 5

## 216. execution.canary_timeout_seconds

- key: execution.canary_timeout_seconds
- type: int
- default_or_configured_value: 60

## 217. execution.confidence_thresholds.critical

- key: execution.confidence_thresholds.critical
- type: float
- default_or_configured_value: 0.95

## 218. execution.confidence_thresholds.high

- key: execution.confidence_thresholds.high
- type: float
- default_or_configured_value: 0.7

## 219. execution.confidence_thresholds.low

- key: execution.confidence_thresholds.low
- type: float
- default_or_configured_value: 0.2

## 220. execution.confidence_thresholds.medium

- key: execution.confidence_thresholds.medium
- type: float
- default_or_configured_value: 0.35

## 221. execution.default_ttl_seconds

- key: execution.default_ttl_seconds
- type: int
- default_or_configured_value: 3600

## 222. execution.docker_templates.decoy_database

- key: execution.docker_templates.decoy_database
- type: str
- default_or_configured_value: mirage-decoy-db-template

## 223. execution.docker_templates.fake_smb

- key: execution.docker_templates.fake_smb
- type: str
- default_or_configured_value: mirage-fake-smb-template

## 224. execution.execution_timeout_seconds

- key: execution.execution_timeout_seconds
- type: int
- default_or_configured_value: 300

## 225. execution.graph_coverage_threshold

- key: execution.graph_coverage_threshold
- type: float
- default_or_configured_value: 0.2

## 226. execution.kill_switch.default_enabled

- key: execution.kill_switch.default_enabled
- type: bool
- default_or_configured_value: False

## 227. execution.lab_networks.control

- key: execution.lab_networks.control
- type: str
- default_or_configured_value: mirage-control

## 228. execution.lab_networks.decoy

- key: execution.lab_networks.decoy
- type: str
- default_or_configured_value: mirage-decoy

## 229. execution.lab_networks.workload

- key: execution.lab_networks.workload
- type: str
- default_or_configured_value: mirage-workload

## 230. execution.managed_environments

- key: execution.managed_environments
- type: list
- default_or_configured_value: ["lab", "test", "dev", ""]

## 231. execution.management_channel_ids

- key: execution.management_channel_ids
- type: list
- default_or_configured_value: []

## 232. execution.maximum_ttl_seconds

- key: execution.maximum_ttl_seconds
- type: int
- default_or_configured_value: 14400

## 233. execution.policy_version

- key: execution.policy_version
- type: str
- default_or_configured_value: safety-v1

## 234. execution.protected_asset_ids

- key: execution.protected_asset_ids
- type: list
- default_or_configured_value: []

## 235. execution.protected_asset_types

- key: execution.protected_asset_types
- type: list
- default_or_configured_value: ["database", "dc", "domain_controller"]

## 236. execution.protected_criticality_threshold

- key: execution.protected_criticality_threshold
- type: float
- default_or_configured_value: 0.85

## 237. execution.retries

- key: execution.retries
- type: int
- default_or_configured_value: 1

## 238. execution.reversible_required_tier

- key: execution.reversible_required_tier
- type: int
- default_or_configured_value: 2

## 239. execution.rollback_required_tier

- key: execution.rollback_required_tier
- type: int
- default_or_configured_value: 2

## 240. execution.rollback_retries

- key: execution.rollback_retries
- type: int
- default_or_configured_value: 2

## 241. execution.tier3_auto_confidence

- key: execution.tier3_auto_confidence
- type: float
- default_or_configured_value: 0.98

## 242. execution.twin_freshness_threshold

- key: execution.twin_freshness_threshold
- type: float
- default_or_configured_value: 0.35

## 243. federation.allowed_data_classes

- key: federation.allowed_data_classes
- type: list
- default_or_configured_value: ["SUMMARY_INCIDENT", "PSEUDONYMIZED_ENTITY_DATA", "ASSURANCE_EVIDENCE_METADATA", "SLO_STATUS", "CAPACITY_SUMMARY", "READINESS_SUMMARY"]

## 244. federation.central_governance_unavailable_behavior

- key: federation.central_governance_unavailable_behavior
- type: str
- default_or_configured_value: fail_closed_for_expansion

## 245. federation.denied_field_markers

- key: federation.denied_field_markers
- type: list
- default_or_configured_value: ["password", "passwd", "secret", "token", "api_key", "apikey", "credential", "private_key", "raw_event", "raw_payload", "command_line", "cookie", "authorization"]

## 246. federation.encrypted_transport_required

- key: federation.encrypted_transport_required
- type: bool
- default_or_configured_value: True

## 247. federation.max_queue_messages

- key: federation.max_queue_messages
- type: int
- default_or_configured_value: 1000

## 248. federation.mode

- key: federation.mode
- type: str
- default_or_configured_value: disabled

## 249. federation.pseudonymization_required

- key: federation.pseudonymization_required
- type: bool
- default_or_configured_value: True

## 250. federation.residency_routes.local

- key: federation.residency_routes.local
- type: list
- default_or_configured_value: ["local"]

## 251. federation.retry.backoff_seconds

- key: federation.retry.backoff_seconds
- type: float
- default_or_configured_value: 1.0

## 252. federation.retry.max_attempts

- key: federation.retry.max_attempts
- type: int
- default_or_configured_value: 3

## 253. federation.site_disconnection_behavior

- key: federation.site_disconnection_behavior
- type: str
- default_or_configured_value: local_shadow_only

## 254. general.budget_limit

- key: general.budget_limit
- type: float
- default_or_configured_value: 6.0

## 255. general.discount_factor

- key: general.discount_factor
- type: float
- default_or_configured_value: 0.95

## 256. general.enforcement_enabled

- key: general.enforcement_enabled
- type: bool
- default_or_configured_value: False

## 257. general.operating_mode

- key: general.operating_mode
- type: str
- default_or_configured_value: shadow

## 258. general.rl_execution_enabled

- key: general.rl_execution_enabled
- type: bool
- default_or_configured_value: False

## 259. general.rl_operating_mode

- key: general.rl_operating_mode
- type: str
- default_or_configured_value: shadow

## 260. gnn.default_operating_mode

- key: gnn.default_operating_mode
- type: str
- default_or_configured_value: gnn_shadow

## 261. gnn.dropout

- key: gnn.dropout
- type: float
- default_or_configured_value: 0.2

## 262. gnn.embedding_dim

- key: gnn.embedding_dim
- type: int
- default_or_configured_value: 64

## 263. gnn.feature_schema_version

- key: gnn.feature_schema_version
- type: str
- default_or_configured_value: v1

## 264. gnn.gnn_type

- key: gnn.gnn_type
- type: str
- default_or_configured_value: graphsage

## 265. gnn.gnn_weight

- key: gnn.gnn_weight
- type: float
- default_or_configured_value: 0.3

## 266. gnn.heuristic_weight

- key: gnn.heuristic_weight
- type: float
- default_or_configured_value: 0.7

## 267. gnn.low_coverage_threshold

- key: gnn.low_coverage_threshold
- type: float
- default_or_configured_value: 0.25

## 268. gnn.max_edges

- key: gnn.max_edges
- type: int
- default_or_configured_value: 400

## 269. gnn.max_edges_train

- key: gnn.max_edges_train
- type: int
- default_or_configured_value: 160

## 270. gnn.max_nodes

- key: gnn.max_nodes
- type: int
- default_or_configured_value: 200

## 271. gnn.max_nodes_train

- key: gnn.max_nodes_train
- type: int
- default_or_configured_value: 80

## 272. gnn.missing_feature_threshold

- key: gnn.missing_feature_threshold
- type: float
- default_or_configured_value: 0.3

## 273. gnn.model_path

- key: gnn.model_path
- type: str
- default_or_configured_value: 

## 274. gnn.n_layers

- key: gnn.n_layers
- type: int
- default_or_configured_value: 2

## 275. gnn.prediction_state_path

- key: gnn.prediction_state_path
- type: str
- default_or_configured_value: artifacts/gnn_predictions.json

## 276. gnn.random_seed

- key: gnn.random_seed
- type: int
- default_or_configured_value: 42

## 277. gnn.registry_path

- key: gnn.registry_path
- type: str
- default_or_configured_value: models/gnn_registry.json

## 278. gnn.uncertainty_threshold

- key: gnn.uncertainty_threshold
- type: float
- default_or_configured_value: 0.4

## 279. governance.approval_roles

- key: governance.approval_roles
- type: list
- default_or_configured_value: ["soc_analyst", "incident_commander", "system_owner", "security_engineer", "governance_reviewer"]

## 280. governance.artifact_review_days

- key: governance.artifact_review_days
- type: int
- default_or_configured_value: 90

## 281. governance.audit_path

- key: governance.audit_path
- type: str
- default_or_configured_value: artifacts/governance_audit.jsonl

## 282. governance.registry_path

- key: governance.registry_path
- type: str
- default_or_configured_value: models/governance_registry.json

## 283. governance.release_gate_thresholds.calibration_error_max

- key: governance.release_gate_thresholds.calibration_error_max
- type: float
- default_or_configured_value: 0.25

## 284. governance.release_gate_thresholds.latency_ms_max

- key: governance.release_gate_thresholds.latency_ms_max
- type: float
- default_or_configured_value: 250.0

## 285. governance.release_gate_thresholds.unseen_topology_return

- key: governance.release_gate_thresholds.unseen_topology_return
- type: float
- default_or_configured_value: 0.0

## 286. governance.release_gate_thresholds.worst_case_return

- key: governance.release_gate_thresholds.worst_case_return
- type: float
- default_or_configured_value: 0.0

## 287. governance.separation_of_duties

- key: governance.separation_of_duties
- type: bool
- default_or_configured_value: True

## 288. governance.training_and_promotion_api_enabled

- key: governance.training_and_promotion_api_enabled
- type: bool
- default_or_configured_value: False

## 289. layer1.event_history_limit

- key: layer1.event_history_limit
- type: int
- default_or_configured_value: 1000

## 290. layer1.hmm_weight

- key: layer1.hmm_weight
- type: float
- default_or_configured_value: 0.6

## 291. layer1.max_tracked_hosts

- key: layer1.max_tracked_hosts
- type: int
- default_or_configured_value: 10000

## 292. layer2.decoy_realism

- key: layer2.decoy_realism
- type: float
- default_or_configured_value: 0.8

## 293. layer3.deception_actions.deploy_decoy_database.business_impact

- key: layer3.deception_actions.deploy_decoy_database.business_impact
- type: float
- default_or_configured_value: 0.05

## 294. layer3.deception_actions.deploy_decoy_database.cost

- key: layer3.deception_actions.deploy_decoy_database.cost
- type: float
- default_or_configured_value: 1.5

## 295. layer3.deception_actions.deploy_decoy_database.realism_score

- key: layer3.deception_actions.deploy_decoy_database.realism_score
- type: float
- default_or_configured_value: 0.85

## 296. layer3.deception_actions.deploy_decoy_database.reward_delta

- key: layer3.deception_actions.deploy_decoy_database.reward_delta
- type: float
- default_or_configured_value: 0.9

## 297. layer3.deception_actions.deploy_decoy_database.risk_score

- key: layer3.deception_actions.deploy_decoy_database.risk_score
- type: float
- default_or_configured_value: 0.1

## 298. layer3.deception_actions.deploy_decoy_router.business_impact

- key: layer3.deception_actions.deploy_decoy_router.business_impact
- type: float
- default_or_configured_value: 0.08

## 299. layer3.deception_actions.deploy_decoy_router.cost

- key: layer3.deception_actions.deploy_decoy_router.cost
- type: float
- default_or_configured_value: 1.2

## 300. layer3.deception_actions.deploy_decoy_router.edge_cost_delta

- key: layer3.deception_actions.deploy_decoy_router.edge_cost_delta
- type: float
- default_or_configured_value: 0.3

## 301. layer3.deception_actions.deploy_decoy_router.realism_score

- key: layer3.deception_actions.deploy_decoy_router.realism_score
- type: float
- default_or_configured_value: 0.75

## 302. layer3.deception_actions.deploy_decoy_router.reward_delta

- key: layer3.deception_actions.deploy_decoy_router.reward_delta
- type: float
- default_or_configured_value: 0.7

## 303. layer3.deception_actions.deploy_decoy_router.risk_score

- key: layer3.deception_actions.deploy_decoy_router.risk_score
- type: float
- default_or_configured_value: 0.15

## 304. layer3.deception_actions.increase_edge_cost.business_impact

- key: layer3.deception_actions.increase_edge_cost.business_impact
- type: float
- default_or_configured_value: 0.03

## 305. layer3.deception_actions.increase_edge_cost.cost

- key: layer3.deception_actions.increase_edge_cost.cost
- type: float
- default_or_configured_value: 0.5

## 306. layer3.deception_actions.increase_edge_cost.edge_cost_delta

- key: layer3.deception_actions.increase_edge_cost.edge_cost_delta
- type: float
- default_or_configured_value: 0.5

## 307. layer3.deception_actions.increase_edge_cost.realism_score

- key: layer3.deception_actions.increase_edge_cost.realism_score
- type: float
- default_or_configured_value: 1.0

## 308. layer3.deception_actions.increase_edge_cost.reward_delta

- key: layer3.deception_actions.increase_edge_cost.reward_delta
- type: float
- default_or_configured_value: 0.0

## 309. layer3.deception_actions.increase_edge_cost.risk_score

- key: layer3.deception_actions.increase_edge_cost.risk_score
- type: float
- default_or_configured_value: 0.05

## 310. layer3.deception_actions.scatter_honey_credential.business_impact

- key: layer3.deception_actions.scatter_honey_credential.business_impact
- type: float
- default_or_configured_value: <redacted>

## 311. layer3.deception_actions.scatter_honey_credential.cost

- key: layer3.deception_actions.scatter_honey_credential.cost
- type: float
- default_or_configured_value: <redacted>

## 312. layer3.deception_actions.scatter_honey_credential.realism_score

- key: layer3.deception_actions.scatter_honey_credential.realism_score
- type: float
- default_or_configured_value: <redacted>

## 313. layer3.deception_actions.scatter_honey_credential.reward_delta

- key: layer3.deception_actions.scatter_honey_credential.reward_delta
- type: float
- default_or_configured_value: <redacted>

## 314. layer3.deception_actions.scatter_honey_credential.risk_score

- key: layer3.deception_actions.scatter_honey_credential.risk_score
- type: float
- default_or_configured_value: <redacted>

## 315. layer3.max_actions_per_type

- key: layer3.max_actions_per_type
- type: int
- default_or_configured_value: 40

## 316. layer5.protected_asset_types

- key: layer5.protected_asset_types
- type: list
- default_or_configured_value: ["database", "dc"]

## 317. layer5.protected_nodes

- key: layer5.protected_nodes
- type: list
- default_or_configured_value: [10, 13]

## 318. marl.blue_execution_mode

- key: marl.blue_execution_mode
- type: str
- default_or_configured_value: shadow

## 319. marl.checkpoint_path

- key: marl.checkpoint_path
- type: str
- default_or_configured_value: models/marl_self_play

## 320. marl.cyber_range_only

- key: marl.cyber_range_only
- type: bool
- default_or_configured_value: True

## 321. marl.default_episodes

- key: marl.default_episodes
- type: int
- default_or_configured_value: 6

## 322. marl.max_scenarios_per_job

- key: marl.max_scenarios_per_job
- type: int
- default_or_configured_value: 20

## 323. marl.max_steps

- key: marl.max_steps
- type: int
- default_or_configured_value: 12

## 324. marl.opponent_profiles

- key: marl.opponent_profiles
- type: list
- default_or_configured_value: ["random", "shortest_path", "highest_value", "credential_focused", "stealth", "speed", "deception_naive", "deception_aware", "risk_sensitive", "goal_switching"]

## 325. marl.production_connectivity

- key: marl.production_connectivity
- type: bool
- default_or_configured_value: False

## 326. marl.random_seed

- key: marl.random_seed
- type: int
- default_or_configured_value: 42

## 327. marl.real_exploitation_enabled

- key: marl.real_exploitation_enabled
- type: bool
- default_or_configured_value: False

## 328. marl.red_agent_external_network

- key: marl.red_agent_external_network
- type: bool
- default_or_configured_value: False

## 329. marl.registry_path

- key: marl.registry_path
- type: str
- default_or_configured_value: models/marl_policy_registry.json

## 330. marl.scenario_path

- key: marl.scenario_path
- type: str
- default_or_configured_value: artifacts/marl_scenarios

## 331. marl.training_api_enabled

- key: marl.training_api_enabled
- type: bool
- default_or_configured_value: False

## 332. maturity.block_on_documented_only_safety_claims

- key: maturity.block_on_documented_only_safety_claims
- type: bool
- default_or_configured_value: True

## 333. maturity.block_on_failed_restore

- key: maturity.block_on_failed_restore
- type: bool
- default_or_configured_value: True

## 334. maturity.minimum_category_score

- key: maturity.minimum_category_score
- type: float
- default_or_configured_value: 0.7

## 335. milestone11.inventory.artifact_path

- key: milestone11.inventory.artifact_path
- type: str
- default_or_configured_value: artifacts/inventory/system_inventory.json

## 336. milestone11.inventory.deterministic_generated_at

- key: milestone11.inventory.deterministic_generated_at
- type: str
- default_or_configured_value: 1970-01-01T00:00:00Z

## 337. milestone11.inventory.yaml_artifact_path

- key: milestone11.inventory.yaml_artifact_path
- type: str
- default_or_configured_value: artifacts/inventory/system_inventory.yaml

## 338. offline_rl.action_schema_version

- key: offline_rl.action_schema_version
- type: str
- default_or_configured_value: rl_action_v1

## 339. offline_rl.action_support_threshold

- key: offline_rl.action_support_threshold
- type: float
- default_or_configured_value: 0.05

## 340. offline_rl.advantage_temperature

- key: offline_rl.advantage_temperature
- type: float
- default_or_configured_value: 1.0

## 341. offline_rl.api_training_enabled

- key: offline_rl.api_training_enabled
- type: bool
- default_or_configured_value: False

## 342. offline_rl.batch_size

- key: offline_rl.batch_size
- type: int
- default_or_configured_value: 32

## 343. offline_rl.bc_model_path

- key: offline_rl.bc_model_path
- type: str
- default_or_configured_value: 

## 344. offline_rl.dataset_path

- key: offline_rl.dataset_path
- type: str
- default_or_configured_value: artifacts/rl_dataset

## 345. offline_rl.discount_factor

- key: offline_rl.discount_factor
- type: float
- default_or_configured_value: 0.95

## 346. offline_rl.dropout

- key: offline_rl.dropout
- type: float
- default_or_configured_value: 0.0

## 347. offline_rl.early_stopping_patience

- key: offline_rl.early_stopping_patience
- type: int
- default_or_configured_value: 5

## 348. offline_rl.ensemble_size

- key: offline_rl.ensemble_size
- type: int
- default_or_configured_value: 1

## 349. offline_rl.evaluation_attacker_profiles

- key: offline_rl.evaluation_attacker_profiles
- type: list
- default_or_configured_value: ["shortest_path", "greedy_asset_value", "stealthy", "deception_aware", "credential_focused", "randomly_perturbed", "unseen_path_selection"]

## 350. offline_rl.expectile

- key: offline_rl.expectile
- type: float
- default_or_configured_value: 0.7

## 351. offline_rl.fallback_order

- key: offline_rl.fallback_order
- type: list
- default_or_configured_value: ["offline_rl", "hierarchical_behavior_cloning", "robust_decision_engine", "heuristic_ranker", "observe_or_analyst_review"]

## 352. offline_rl.feature_schema_version

- key: offline_rl.feature_schema_version
- type: str
- default_or_configured_value: rl_state_v1

## 353. offline_rl.learning_rate

- key: offline_rl.learning_rate
- type: float
- default_or_configured_value: 0.001

## 354. offline_rl.max_candidate_actions

- key: offline_rl.max_candidate_actions
- type: int
- default_or_configured_value: 100

## 355. offline_rl.maximum_candidate_actions

- key: offline_rl.maximum_candidate_actions
- type: int
- default_or_configured_value: 100

## 356. offline_rl.model_path

- key: offline_rl.model_path
- type: str
- default_or_configured_value: 

## 357. offline_rl.ood_thresholds.low_twin_quality

- key: offline_rl.ood_thresholds.low_twin_quality
- type: float
- default_or_configured_value: 0.25

## 358. offline_rl.ood_thresholds.missing_features

- key: offline_rl.ood_thresholds.missing_features
- type: float
- default_or_configured_value: 0.3

## 359. offline_rl.ood_thresholds.unknown_action_type

- key: offline_rl.ood_thresholds.unknown_action_type
- type: float
- default_or_configured_value: 1.0

## 360. offline_rl.prediction_state_path

- key: offline_rl.prediction_state_path
- type: str
- default_or_configured_value: artifacts/rl_predictions.json

## 361. offline_rl.registry_path

- key: offline_rl.registry_path
- type: str
- default_or_configured_value: models/rl_policy_registry.json

## 362. offline_rl.reward_model_version

- key: offline_rl.reward_model_version
- type: str
- default_or_configured_value: defense_reward_v1

## 363. offline_rl.rl_execution_enabled

- key: offline_rl.rl_execution_enabled
- type: bool
- default_or_configured_value: False

## 364. offline_rl.rl_operating_mode

- key: offline_rl.rl_operating_mode
- type: str
- default_or_configured_value: rl_shadow

## 365. offline_rl.tactic_vocabulary

- key: offline_rl.tactic_vocabulary
- type: list
- default_or_configured_value: ["OBSERVE", "DECEIVE", "DELAY", "LIMITED_CONTAIN", "ESCALATE", "NO_OP"]

## 366. offline_rl.target_update_rate

- key: offline_rl.target_update_rate
- type: float
- default_or_configured_value: 0.01

## 367. offline_rl.training_seeds

- key: offline_rl.training_seeds
- type: list
- default_or_configured_value: [42]

## 368. offline_rl.uncertainty_threshold

- key: offline_rl.uncertainty_threshold
- type: float
- default_or_configured_value: 0.65

## 369. performance.max_fixture_events

- key: performance.max_fixture_events
- type: int
- default_or_configured_value: 100000

## 370. performance.synthetic_event_sizes

- key: performance.synthetic_event_sizes
- type: list
- default_or_configured_value: [1000, 10000]

## 371. pilot.allowed_action_types

- key: pilot.allowed_action_types
- type: list
- default_or_configured_value: ["increase_endpoint_logging", "increase_network_telemetry", "enable_limited_packet_capture", "scatter_honey_credential", "deploy_decoy_database", "deploy_fake_share", "add_decoy_service", "create_fake_dns_record", "throttle_edge", "create_soc_ticket", "request_analyst_review"]

## 372. pilot.approval_expiry_seconds

- key: pilot.approval_expiry_seconds
- type: int
- default_or_configured_value: 900

## 373. pilot.governance_audit_path

- key: pilot.governance_audit_path
- type: str
- default_or_configured_value: artifacts/governance_audit.jsonl

## 374. pilot.health_thresholds.availability_min

- key: pilot.health_thresholds.availability_min
- type: float
- default_or_configured_value: 0.99

## 375. pilot.health_thresholds.error_rate_max

- key: pilot.health_thresholds.error_rate_max
- type: float
- default_or_configured_value: 0.02

## 376. pilot.health_thresholds.health_success_min

- key: pilot.health_thresholds.health_success_min
- type: float
- default_or_configured_value: 0.99

## 377. pilot.health_thresholds.latency_ms_max

- key: pilot.health_thresholds.latency_ms_max
- type: float
- default_or_configured_value: 500.0

## 378. pilot.high_risk_automation_enabled

- key: pilot.high_risk_automation_enabled
- type: bool
- default_or_configured_value: False

## 379. pilot.human_approval_required_for_medium_and_high_risk

- key: pilot.human_approval_required_for_medium_and_high_risk
- type: bool
- default_or_configured_value: True

## 380. pilot.level4_enabled

- key: pilot.level4_enabled
- type: bool
- default_or_configured_value: False

## 381. pilot.management_channels

- key: pilot.management_channels
- type: list
- default_or_configured_value: ["soc-control-plane"]

## 382. pilot.maximum_affected_entities

- key: pilot.maximum_affected_entities
- type: int
- default_or_configured_value: 5

## 383. pilot.maximum_concurrent_actions

- key: pilot.maximum_concurrent_actions
- type: int
- default_or_configured_value: 1

## 384. pilot.maximum_ttl_seconds

- key: pilot.maximum_ttl_seconds
- type: int
- default_or_configured_value: 3600

## 385. pilot.operating_mode

- key: pilot.operating_mode
- type: str
- default_or_configured_value: controlled_pilot

## 386. pilot.pilot_execution_enabled

- key: pilot.pilot_execution_enabled
- type: bool
- default_or_configured_value: False

## 387. pilot.pilot_rollout_level

- key: pilot.pilot_rollout_level
- type: int
- default_or_configured_value: 0

## 388. pilot.pilot_scopes

- key: pilot.pilot_scopes
- type: list
- default_or_configured_value: []

## 389. pilot.prohibited_action_types

- key: pilot.prohibited_action_types
- type: list
- default_or_configured_value: ["isolate_database", "disable_privileged_identity", "block_subnet", "modify_critical_database", "block_all_traffic", "change_core_routing", "change_domain_controller_policy"]

## 390. pilot.rollback_channels

- key: pilot.rollback_channels
- type: list
- default_or_configured_value: ["rollback-controller"]

## 391. production.action_mask_required

- key: production.action_mask_required
- type: bool
- default_or_configured_value: True

## 392. production.allowed_automatic_action_types

- key: production.allowed_automatic_action_types
- type: list
- default_or_configured_value: ["increase_endpoint_logging", "increase_network_telemetry", "enable_limited_packet_capture", "enable_auth_auditing", "create_soc_ticket", "request_analyst_review", "deploy_decoy_host", "deploy_decoy_database", "deploy_fake_share", "add_decoy_service", "scatter_honey_credential", "create_fake_dns_record", "throttle_edge"]

## 393. production.api_gateway.cors_policy

- key: production.api_gateway.cors_policy
- type: str
- default_or_configured_value: explicit

## 394. production.api_gateway.max_page_size

- key: production.api_gateway.max_page_size
- type: int
- default_or_configured_value: 1000

## 395. production.api_gateway.openapi_public

- key: production.api_gateway.openapi_public
- type: bool
- default_or_configured_value: False

## 396. production.api_gateway.rate_limit_per_minute

- key: production.api_gateway.rate_limit_per_minute
- type: int
- default_or_configured_value: 600

## 397. production.api_gateway.require_correlation_id

- key: production.api_gateway.require_correlation_id
- type: bool
- default_or_configured_value: True

## 398. production.api_gateway.timeout_seconds

- key: production.api_gateway.timeout_seconds
- type: int
- default_or_configured_value: 30

## 399. production.api_gateway.training_endpoints_enabled

- key: production.api_gateway.training_endpoints_enabled
- type: bool
- default_or_configured_value: False

## 400. production.audit.fail_closed_for_execution

- key: production.audit.fail_closed_for_execution
- type: bool
- default_or_configured_value: True

## 401. production.audit.immutable_export_uri

- key: production.audit.immutable_export_uri
- type: str
- default_or_configured_value: artifacts/production/audit_exports

## 402. production.audit.path

- key: production.audit.path
- type: str
- default_or_configured_value: artifacts/production/audit.jsonl

## 403. production.audit.retention_days

- key: production.audit.retention_days
- type: int
- default_or_configured_value: 365

## 404. production.audit.write_only_identity

- key: production.audit.write_only_identity
- type: str
- default_or_configured_value: mirage-audit-writer

## 405. production.auth.api_tokens_enabled

- key: production.auth.api_tokens_enabled
- type: bool
- default_or_configured_value: <redacted>

## 406. production.auth.default_credentials_allowed

- key: production.auth.default_credentials_allowed
- type: bool
- default_or_configured_value: <redacted>

## 407. production.auth.enabled

- key: production.auth.enabled
- type: bool
- default_or_configured_value: False

## 408. production.auth.oidc_audience

- key: production.auth.oidc_audience
- type: str
- default_or_configured_value: mirage-api

## 409. production.auth.oidc_issuer

- key: production.auth.oidc_issuer
- type: str
- default_or_configured_value: 

## 410. production.auth.revocation_list_path

- key: production.auth.revocation_list_path
- type: str
- default_or_configured_value: artifacts/revoked_service_tokens.json

## 411. production.auth.service_identity_required

- key: production.auth.service_identity_required
- type: bool
- default_or_configured_value: False

## 412. production.auth.token_ttl_seconds

- key: production.auth.token_ttl_seconds
- type: int
- default_or_configured_value: <redacted>

## 413. production.deployment_level

- key: production.deployment_level
- type: str
- default_or_configured_value: SHADOW_ONLY

## 414. production.deployment_mode

- key: production.deployment_mode
- type: str
- default_or_configured_value: modular_monolith

## 415. production.event_transport.backend

- key: production.event_transport.backend
- type: str
- default_or_configured_value: local_durable

## 416. production.event_transport.broker_url

- key: production.event_transport.broker_url
- type: str
- default_or_configured_value: 

## 417. production.event_transport.max_queue_depth

- key: production.event_transport.max_queue_depth
- type: int
- default_or_configured_value: 100000

## 418. production.event_transport.max_retries

- key: production.event_transport.max_retries
- type: int
- default_or_configured_value: 3

## 419. production.event_transport.poll_lease_seconds

- key: production.event_transport.poll_lease_seconds
- type: int
- default_or_configured_value: 30

## 420. production.event_transport.sqlite_path

- key: production.event_transport.sqlite_path
- type: str
- default_or_configured_value: artifacts/production/events.db

## 421. production.formal_verification_required

- key: production.formal_verification_required
- type: bool
- default_or_configured_value: True

## 422. production.governance_gate_required

- key: production.governance_gate_required
- type: bool
- default_or_configured_value: True

## 423. production.high_risk_automation_enabled

- key: production.high_risk_automation_enabled
- type: bool
- default_or_configured_value: False

## 424. production.operating_mode

- key: production.operating_mode
- type: str
- default_or_configured_value: shadow

## 425. production.production_execution_enabled

- key: production.production_execution_enabled
- type: bool
- default_or_configured_value: False

## 426. production.profile

- key: production.profile
- type: str
- default_or_configured_value: shadow

## 427. production.profiles.controlled_pilot.allowed_action_tiers

- key: production.profiles.controlled_pilot.allowed_action_tiers
- type: list
- default_or_configured_value: [0, 1, 2]

## 428. production.profiles.controlled_pilot.audit_retention_days

- key: production.profiles.controlled_pilot.audit_retention_days
- type: int
- default_or_configured_value: 365

## 429. production.profiles.controlled_pilot.authentication_required

- key: production.profiles.controlled_pilot.authentication_required
- type: bool
- default_or_configured_value: True

## 430. production.profiles.controlled_pilot.backup_policy.enabled

- key: production.profiles.controlled_pilot.backup_policy.enabled
- type: bool
- default_or_configured_value: True

## 431. production.profiles.controlled_pilot.backup_policy.encryption_required

- key: production.profiles.controlled_pilot.backup_policy.encryption_required
- type: bool
- default_or_configured_value: True

## 432. production.profiles.controlled_pilot.backup_policy.frequency

- key: production.profiles.controlled_pilot.backup_policy.frequency
- type: str
- default_or_configured_value: daily

## 433. production.profiles.controlled_pilot.backup_policy.retention_days

- key: production.profiles.controlled_pilot.backup_policy.retention_days
- type: int
- default_or_configured_value: 7

## 434. production.profiles.controlled_pilot.backup_policy.rpo_minutes

- key: production.profiles.controlled_pilot.backup_policy.rpo_minutes
- type: int
- default_or_configured_value: 1440

## 435. production.profiles.controlled_pilot.backup_policy.rto_minutes

- key: production.profiles.controlled_pilot.backup_policy.rto_minutes
- type: int
- default_or_configured_value: 240

## 436. production.profiles.controlled_pilot.connector_permissions

- key: production.profiles.controlled_pilot.connector_permissions
- type: str
- default_or_configured_value: read_only

## 437. production.profiles.controlled_pilot.enforcement_permissions

- key: production.profiles.controlled_pilot.enforcement_permissions
- type: str
- default_or_configured_value: allowlisted_low_risk

## 438. production.profiles.controlled_pilot.event_transport_backend

- key: production.profiles.controlled_pilot.event_transport_backend
- type: str
- default_or_configured_value: local_durable

## 439. production.profiles.controlled_pilot.logging_level

- key: production.profiles.controlled_pilot.logging_level
- type: str
- default_or_configured_value: INFO

## 440. production.profiles.controlled_pilot.model_operating_modes.gnn

- key: production.profiles.controlled_pilot.model_operating_modes.gnn
- type: str
- default_or_configured_value: hybrid_recommendation

## 441. production.profiles.controlled_pilot.model_operating_modes.marl

- key: production.profiles.controlled_pilot.model_operating_modes.marl
- type: str
- default_or_configured_value: shadow

## 442. production.profiles.controlled_pilot.model_operating_modes.rl

- key: production.profiles.controlled_pilot.model_operating_modes.rl
- type: str
- default_or_configured_value: rl_robust_hybrid

## 443. production.profiles.controlled_pilot.pilot_scopes

- key: production.profiles.controlled_pilot.pilot_scopes
- type: list
- default_or_configured_value: []

## 444. production.profiles.controlled_pilot.profile

- key: production.profiles.controlled_pilot.profile
- type: str
- default_or_configured_value: controlled_pilot

## 445. production.profiles.controlled_pilot.resource_limits.cpu

- key: production.profiles.controlled_pilot.resource_limits.cpu
- type: str
- default_or_configured_value: 500m

## 446. production.profiles.controlled_pilot.resource_limits.memory

- key: production.profiles.controlled_pilot.resource_limits.memory
- type: str
- default_or_configured_value: 512Mi

## 447. production.profiles.controlled_pilot.resource_limits.replicas_max

- key: production.profiles.controlled_pilot.resource_limits.replicas_max
- type: int
- default_or_configured_value: 1

## 448. production.profiles.controlled_pilot.resource_limits.replicas_min

- key: production.profiles.controlled_pilot.resource_limits.replicas_min
- type: int
- default_or_configured_value: 1

## 449. production.profiles.controlled_pilot.storage_backend

- key: production.profiles.controlled_pilot.storage_backend
- type: str
- default_or_configured_value: sqlite

## 450. production.profiles.controlled_pilot.tls_required

- key: production.profiles.controlled_pilot.tls_required
- type: bool
- default_or_configured_value: True

## 451. production.profiles.cyber_range.allowed_action_tiers

- key: production.profiles.cyber_range.allowed_action_tiers
- type: list
- default_or_configured_value: [0, 1, 2]

## 452. production.profiles.cyber_range.audit_retention_days

- key: production.profiles.cyber_range.audit_retention_days
- type: int
- default_or_configured_value: 30

## 453. production.profiles.cyber_range.authentication_required

- key: production.profiles.cyber_range.authentication_required
- type: bool
- default_or_configured_value: False

## 454. production.profiles.cyber_range.backup_policy.enabled

- key: production.profiles.cyber_range.backup_policy.enabled
- type: bool
- default_or_configured_value: True

## 455. production.profiles.cyber_range.backup_policy.encryption_required

- key: production.profiles.cyber_range.backup_policy.encryption_required
- type: bool
- default_or_configured_value: True

## 456. production.profiles.cyber_range.backup_policy.frequency

- key: production.profiles.cyber_range.backup_policy.frequency
- type: str
- default_or_configured_value: daily

## 457. production.profiles.cyber_range.backup_policy.retention_days

- key: production.profiles.cyber_range.backup_policy.retention_days
- type: int
- default_or_configured_value: 7

## 458. production.profiles.cyber_range.backup_policy.rpo_minutes

- key: production.profiles.cyber_range.backup_policy.rpo_minutes
- type: int
- default_or_configured_value: 1440

## 459. production.profiles.cyber_range.backup_policy.rto_minutes

- key: production.profiles.cyber_range.backup_policy.rto_minutes
- type: int
- default_or_configured_value: 240

## 460. production.profiles.cyber_range.connector_permissions

- key: production.profiles.cyber_range.connector_permissions
- type: str
- default_or_configured_value: synthetic_only

## 461. production.profiles.cyber_range.enforcement_permissions

- key: production.profiles.cyber_range.enforcement_permissions
- type: str
- default_or_configured_value: range_only

## 462. production.profiles.cyber_range.event_transport_backend

- key: production.profiles.cyber_range.event_transport_backend
- type: str
- default_or_configured_value: local_durable

## 463. production.profiles.cyber_range.logging_level

- key: production.profiles.cyber_range.logging_level
- type: str
- default_or_configured_value: INFO

## 464. production.profiles.cyber_range.model_operating_modes.gnn

- key: production.profiles.cyber_range.model_operating_modes.gnn
- type: str
- default_or_configured_value: gnn_shadow

## 465. production.profiles.cyber_range.model_operating_modes.marl

- key: production.profiles.cyber_range.model_operating_modes.marl
- type: str
- default_or_configured_value: shadow

## 466. production.profiles.cyber_range.model_operating_modes.rl

- key: production.profiles.cyber_range.model_operating_modes.rl
- type: str
- default_or_configured_value: rl_shadow

## 467. production.profiles.cyber_range.pilot_scopes

- key: production.profiles.cyber_range.pilot_scopes
- type: list
- default_or_configured_value: []

## 468. production.profiles.cyber_range.profile

- key: production.profiles.cyber_range.profile
- type: str
- default_or_configured_value: cyber_range

## 469. production.profiles.cyber_range.resource_limits.cpu

- key: production.profiles.cyber_range.resource_limits.cpu
- type: str
- default_or_configured_value: 500m

## 470. production.profiles.cyber_range.resource_limits.memory

- key: production.profiles.cyber_range.resource_limits.memory
- type: str
- default_or_configured_value: 512Mi

## 471. production.profiles.cyber_range.resource_limits.replicas_max

- key: production.profiles.cyber_range.resource_limits.replicas_max
- type: int
- default_or_configured_value: 1

## 472. production.profiles.cyber_range.resource_limits.replicas_min

- key: production.profiles.cyber_range.resource_limits.replicas_min
- type: int
- default_or_configured_value: 1

## 473. production.profiles.cyber_range.storage_backend

- key: production.profiles.cyber_range.storage_backend
- type: str
- default_or_configured_value: sqlite

## 474. production.profiles.cyber_range.tls_required

- key: production.profiles.cyber_range.tls_required
- type: bool
- default_or_configured_value: False

## 475. production.profiles.development.allowed_action_tiers

- key: production.profiles.development.allowed_action_tiers
- type: list
- default_or_configured_value: [0, 1]

## 476. production.profiles.development.audit_retention_days

- key: production.profiles.development.audit_retention_days
- type: int
- default_or_configured_value: 7

## 477. production.profiles.development.authentication_required

- key: production.profiles.development.authentication_required
- type: bool
- default_or_configured_value: False

## 478. production.profiles.development.backup_policy.enabled

- key: production.profiles.development.backup_policy.enabled
- type: bool
- default_or_configured_value: False

## 479. production.profiles.development.backup_policy.encryption_required

- key: production.profiles.development.backup_policy.encryption_required
- type: bool
- default_or_configured_value: True

## 480. production.profiles.development.backup_policy.frequency

- key: production.profiles.development.backup_policy.frequency
- type: str
- default_or_configured_value: manual

## 481. production.profiles.development.backup_policy.retention_days

- key: production.profiles.development.backup_policy.retention_days
- type: int
- default_or_configured_value: 7

## 482. production.profiles.development.backup_policy.rpo_minutes

- key: production.profiles.development.backup_policy.rpo_minutes
- type: int
- default_or_configured_value: 1440

## 483. production.profiles.development.backup_policy.rto_minutes

- key: production.profiles.development.backup_policy.rto_minutes
- type: int
- default_or_configured_value: 240

## 484. production.profiles.development.connector_permissions

- key: production.profiles.development.connector_permissions
- type: str
- default_or_configured_value: fixture_read_only

## 485. production.profiles.development.enforcement_permissions

- key: production.profiles.development.enforcement_permissions
- type: str
- default_or_configured_value: disabled

## 486. production.profiles.development.event_transport_backend

- key: production.profiles.development.event_transport_backend
- type: str
- default_or_configured_value: in_memory

## 487. production.profiles.development.logging_level

- key: production.profiles.development.logging_level
- type: str
- default_or_configured_value: DEBUG

## 488. production.profiles.development.model_operating_modes.gnn

- key: production.profiles.development.model_operating_modes.gnn
- type: str
- default_or_configured_value: gnn_shadow

## 489. production.profiles.development.model_operating_modes.marl

- key: production.profiles.development.model_operating_modes.marl
- type: str
- default_or_configured_value: shadow

## 490. production.profiles.development.model_operating_modes.rl

- key: production.profiles.development.model_operating_modes.rl
- type: str
- default_or_configured_value: rl_shadow

## 491. production.profiles.development.pilot_scopes

- key: production.profiles.development.pilot_scopes
- type: list
- default_or_configured_value: []

## 492. production.profiles.development.profile

- key: production.profiles.development.profile
- type: str
- default_or_configured_value: development

## 493. production.profiles.development.resource_limits.cpu

- key: production.profiles.development.resource_limits.cpu
- type: str
- default_or_configured_value: 500m

## 494. production.profiles.development.resource_limits.memory

- key: production.profiles.development.resource_limits.memory
- type: str
- default_or_configured_value: 512Mi

## 495. production.profiles.development.resource_limits.replicas_max

- key: production.profiles.development.resource_limits.replicas_max
- type: int
- default_or_configured_value: 1

## 496. production.profiles.development.resource_limits.replicas_min

- key: production.profiles.development.resource_limits.replicas_min
- type: int
- default_or_configured_value: 1

## 497. production.profiles.development.storage_backend

- key: production.profiles.development.storage_backend
- type: str
- default_or_configured_value: in_memory

## 498. production.profiles.development.tls_required

- key: production.profiles.development.tls_required
- type: bool
- default_or_configured_value: False

## 499. production.profiles.lab.allowed_action_tiers

- key: production.profiles.lab.allowed_action_tiers
- type: list
- default_or_configured_value: [0, 1, 2]

## 500. production.profiles.lab.audit_retention_days

- key: production.profiles.lab.audit_retention_days
- type: int
- default_or_configured_value: 30

## 501. production.profiles.lab.authentication_required

- key: production.profiles.lab.authentication_required
- type: bool
- default_or_configured_value: False

## 502. production.profiles.lab.backup_policy.enabled

- key: production.profiles.lab.backup_policy.enabled
- type: bool
- default_or_configured_value: True

## 503. production.profiles.lab.backup_policy.encryption_required

- key: production.profiles.lab.backup_policy.encryption_required
- type: bool
- default_or_configured_value: True

## 504. production.profiles.lab.backup_policy.frequency

- key: production.profiles.lab.backup_policy.frequency
- type: str
- default_or_configured_value: daily

## 505. production.profiles.lab.backup_policy.retention_days

- key: production.profiles.lab.backup_policy.retention_days
- type: int
- default_or_configured_value: 7

## 506. production.profiles.lab.backup_policy.rpo_minutes

- key: production.profiles.lab.backup_policy.rpo_minutes
- type: int
- default_or_configured_value: 1440

## 507. production.profiles.lab.backup_policy.rto_minutes

- key: production.profiles.lab.backup_policy.rto_minutes
- type: int
- default_or_configured_value: 240

## 508. production.profiles.lab.connector_permissions

- key: production.profiles.lab.connector_permissions
- type: str
- default_or_configured_value: fixture_read_only

## 509. production.profiles.lab.enforcement_permissions

- key: production.profiles.lab.enforcement_permissions
- type: str
- default_or_configured_value: lab_mock_only

## 510. production.profiles.lab.event_transport_backend

- key: production.profiles.lab.event_transport_backend
- type: str
- default_or_configured_value: local_durable

## 511. production.profiles.lab.logging_level

- key: production.profiles.lab.logging_level
- type: str
- default_or_configured_value: INFO

## 512. production.profiles.lab.model_operating_modes.gnn

- key: production.profiles.lab.model_operating_modes.gnn
- type: str
- default_or_configured_value: gnn_shadow

## 513. production.profiles.lab.model_operating_modes.marl

- key: production.profiles.lab.model_operating_modes.marl
- type: str
- default_or_configured_value: shadow

## 514. production.profiles.lab.model_operating_modes.rl

- key: production.profiles.lab.model_operating_modes.rl
- type: str
- default_or_configured_value: rl_shadow

## 515. production.profiles.lab.pilot_scopes

- key: production.profiles.lab.pilot_scopes
- type: list
- default_or_configured_value: []

## 516. production.profiles.lab.profile

- key: production.profiles.lab.profile
- type: str
- default_or_configured_value: lab

## 517. production.profiles.lab.resource_limits.cpu

- key: production.profiles.lab.resource_limits.cpu
- type: str
- default_or_configured_value: 500m

## 518. production.profiles.lab.resource_limits.memory

- key: production.profiles.lab.resource_limits.memory
- type: str
- default_or_configured_value: 512Mi

## 519. production.profiles.lab.resource_limits.replicas_max

- key: production.profiles.lab.resource_limits.replicas_max
- type: int
- default_or_configured_value: 1

## 520. production.profiles.lab.resource_limits.replicas_min

- key: production.profiles.lab.resource_limits.replicas_min
- type: int
- default_or_configured_value: 1

## 521. production.profiles.lab.storage_backend

- key: production.profiles.lab.storage_backend
- type: str
- default_or_configured_value: sqlite

## 522. production.profiles.lab.tls_required

- key: production.profiles.lab.tls_required
- type: bool
- default_or_configured_value: False

## 523. production.profiles.production.allowed_action_tiers

- key: production.profiles.production.allowed_action_tiers
- type: list
- default_or_configured_value: [0, 1, 2]

## 524. production.profiles.production.audit_retention_days

- key: production.profiles.production.audit_retention_days
- type: int
- default_or_configured_value: 365

## 525. production.profiles.production.authentication_required

- key: production.profiles.production.authentication_required
- type: bool
- default_or_configured_value: True

## 526. production.profiles.production.backup_policy.enabled

- key: production.profiles.production.backup_policy.enabled
- type: bool
- default_or_configured_value: True

## 527. production.profiles.production.backup_policy.encryption_required

- key: production.profiles.production.backup_policy.encryption_required
- type: bool
- default_or_configured_value: True

## 528. production.profiles.production.backup_policy.frequency

- key: production.profiles.production.backup_policy.frequency
- type: str
- default_or_configured_value: hourly

## 529. production.profiles.production.backup_policy.retention_days

- key: production.profiles.production.backup_policy.retention_days
- type: int
- default_or_configured_value: 90

## 530. production.profiles.production.backup_policy.rpo_minutes

- key: production.profiles.production.backup_policy.rpo_minutes
- type: int
- default_or_configured_value: 15

## 531. production.profiles.production.backup_policy.rto_minutes

- key: production.profiles.production.backup_policy.rto_minutes
- type: int
- default_or_configured_value: 60

## 532. production.profiles.production.connector_permissions

- key: production.profiles.production.connector_permissions
- type: str
- default_or_configured_value: read_only

## 533. production.profiles.production.enforcement_permissions

- key: production.profiles.production.enforcement_permissions
- type: str
- default_or_configured_value: approved_pilot_scope_only

## 534. production.profiles.production.event_transport_backend

- key: production.profiles.production.event_transport_backend
- type: str
- default_or_configured_value: kafka_compatible

## 535. production.profiles.production.logging_level

- key: production.profiles.production.logging_level
- type: str
- default_or_configured_value: INFO

## 536. production.profiles.production.model_operating_modes.gnn

- key: production.profiles.production.model_operating_modes.gnn
- type: str
- default_or_configured_value: hybrid_recommendation

## 537. production.profiles.production.model_operating_modes.marl

- key: production.profiles.production.model_operating_modes.marl
- type: str
- default_or_configured_value: shadow

## 538. production.profiles.production.model_operating_modes.rl

- key: production.profiles.production.model_operating_modes.rl
- type: str
- default_or_configured_value: rl_robust_hybrid

## 539. production.profiles.production.pilot_scopes

- key: production.profiles.production.pilot_scopes
- type: list
- default_or_configured_value: []

## 540. production.profiles.production.profile

- key: production.profiles.production.profile
- type: str
- default_or_configured_value: production

## 541. production.profiles.production.resource_limits.cpu

- key: production.profiles.production.resource_limits.cpu
- type: str
- default_or_configured_value: 1000m

## 542. production.profiles.production.resource_limits.memory

- key: production.profiles.production.resource_limits.memory
- type: str
- default_or_configured_value: 1Gi

## 543. production.profiles.production.resource_limits.replicas_max

- key: production.profiles.production.resource_limits.replicas_max
- type: int
- default_or_configured_value: 12

## 544. production.profiles.production.resource_limits.replicas_min

- key: production.profiles.production.resource_limits.replicas_min
- type: int
- default_or_configured_value: 3

## 545. production.profiles.production.storage_backend

- key: production.profiles.production.storage_backend
- type: str
- default_or_configured_value: postgres

## 546. production.profiles.production.tls_required

- key: production.profiles.production.tls_required
- type: bool
- default_or_configured_value: True

## 547. production.profiles.shadow.allowed_action_tiers

- key: production.profiles.shadow.allowed_action_tiers
- type: list
- default_or_configured_value: [0]

## 548. production.profiles.shadow.audit_retention_days

- key: production.profiles.shadow.audit_retention_days
- type: int
- default_or_configured_value: 180

## 549. production.profiles.shadow.authentication_required

- key: production.profiles.shadow.authentication_required
- type: bool
- default_or_configured_value: True

## 550. production.profiles.shadow.backup_policy.enabled

- key: production.profiles.shadow.backup_policy.enabled
- type: bool
- default_or_configured_value: True

## 551. production.profiles.shadow.backup_policy.encryption_required

- key: production.profiles.shadow.backup_policy.encryption_required
- type: bool
- default_or_configured_value: True

## 552. production.profiles.shadow.backup_policy.frequency

- key: production.profiles.shadow.backup_policy.frequency
- type: str
- default_or_configured_value: daily

## 553. production.profiles.shadow.backup_policy.retention_days

- key: production.profiles.shadow.backup_policy.retention_days
- type: int
- default_or_configured_value: 7

## 554. production.profiles.shadow.backup_policy.rpo_minutes

- key: production.profiles.shadow.backup_policy.rpo_minutes
- type: int
- default_or_configured_value: 1440

## 555. production.profiles.shadow.backup_policy.rto_minutes

- key: production.profiles.shadow.backup_policy.rto_minutes
- type: int
- default_or_configured_value: 240

## 556. production.profiles.shadow.connector_permissions

- key: production.profiles.shadow.connector_permissions
- type: str
- default_or_configured_value: read_only

## 557. production.profiles.shadow.enforcement_permissions

- key: production.profiles.shadow.enforcement_permissions
- type: str
- default_or_configured_value: disabled

## 558. production.profiles.shadow.event_transport_backend

- key: production.profiles.shadow.event_transport_backend
- type: str
- default_or_configured_value: local_durable

## 559. production.profiles.shadow.logging_level

- key: production.profiles.shadow.logging_level
- type: str
- default_or_configured_value: INFO

## 560. production.profiles.shadow.model_operating_modes.gnn

- key: production.profiles.shadow.model_operating_modes.gnn
- type: str
- default_or_configured_value: gnn_shadow

## 561. production.profiles.shadow.model_operating_modes.marl

- key: production.profiles.shadow.model_operating_modes.marl
- type: str
- default_or_configured_value: shadow

## 562. production.profiles.shadow.model_operating_modes.rl

- key: production.profiles.shadow.model_operating_modes.rl
- type: str
- default_or_configured_value: rl_shadow

## 563. production.profiles.shadow.pilot_scopes

- key: production.profiles.shadow.pilot_scopes
- type: list
- default_or_configured_value: []

## 564. production.profiles.shadow.profile

- key: production.profiles.shadow.profile
- type: str
- default_or_configured_value: shadow

## 565. production.profiles.shadow.resource_limits.cpu

- key: production.profiles.shadow.resource_limits.cpu
- type: str
- default_or_configured_value: 500m

## 566. production.profiles.shadow.resource_limits.memory

- key: production.profiles.shadow.resource_limits.memory
- type: str
- default_or_configured_value: 512Mi

## 567. production.profiles.shadow.resource_limits.replicas_max

- key: production.profiles.shadow.resource_limits.replicas_max
- type: int
- default_or_configured_value: 1

## 568. production.profiles.shadow.resource_limits.replicas_min

- key: production.profiles.shadow.resource_limits.replicas_min
- type: int
- default_or_configured_value: 1

## 569. production.profiles.shadow.storage_backend

- key: production.profiles.shadow.storage_backend
- type: str
- default_or_configured_value: sqlite

## 570. production.profiles.shadow.tls_required

- key: production.profiles.shadow.tls_required
- type: bool
- default_or_configured_value: True

## 571. production.profiles.test.allowed_action_tiers

- key: production.profiles.test.allowed_action_tiers
- type: list
- default_or_configured_value: [0, 1]

## 572. production.profiles.test.audit_retention_days

- key: production.profiles.test.audit_retention_days
- type: int
- default_or_configured_value: 14

## 573. production.profiles.test.authentication_required

- key: production.profiles.test.authentication_required
- type: bool
- default_or_configured_value: False

## 574. production.profiles.test.backup_policy.enabled

- key: production.profiles.test.backup_policy.enabled
- type: bool
- default_or_configured_value: False

## 575. production.profiles.test.backup_policy.encryption_required

- key: production.profiles.test.backup_policy.encryption_required
- type: bool
- default_or_configured_value: True

## 576. production.profiles.test.backup_policy.frequency

- key: production.profiles.test.backup_policy.frequency
- type: str
- default_or_configured_value: manual

## 577. production.profiles.test.backup_policy.retention_days

- key: production.profiles.test.backup_policy.retention_days
- type: int
- default_or_configured_value: 7

## 578. production.profiles.test.backup_policy.rpo_minutes

- key: production.profiles.test.backup_policy.rpo_minutes
- type: int
- default_or_configured_value: 1440

## 579. production.profiles.test.backup_policy.rto_minutes

- key: production.profiles.test.backup_policy.rto_minutes
- type: int
- default_or_configured_value: 240

## 580. production.profiles.test.connector_permissions

- key: production.profiles.test.connector_permissions
- type: str
- default_or_configured_value: fixture_read_only

## 581. production.profiles.test.enforcement_permissions

- key: production.profiles.test.enforcement_permissions
- type: str
- default_or_configured_value: mock_only

## 582. production.profiles.test.event_transport_backend

- key: production.profiles.test.event_transport_backend
- type: str
- default_or_configured_value: in_memory

## 583. production.profiles.test.logging_level

- key: production.profiles.test.logging_level
- type: str
- default_or_configured_value: DEBUG

## 584. production.profiles.test.model_operating_modes.gnn

- key: production.profiles.test.model_operating_modes.gnn
- type: str
- default_or_configured_value: gnn_shadow

## 585. production.profiles.test.model_operating_modes.marl

- key: production.profiles.test.model_operating_modes.marl
- type: str
- default_or_configured_value: shadow

## 586. production.profiles.test.model_operating_modes.rl

- key: production.profiles.test.model_operating_modes.rl
- type: str
- default_or_configured_value: rl_shadow

## 587. production.profiles.test.pilot_scopes

- key: production.profiles.test.pilot_scopes
- type: list
- default_or_configured_value: []

## 588. production.profiles.test.profile

- key: production.profiles.test.profile
- type: str
- default_or_configured_value: test

## 589. production.profiles.test.resource_limits.cpu

- key: production.profiles.test.resource_limits.cpu
- type: str
- default_or_configured_value: 500m

## 590. production.profiles.test.resource_limits.memory

- key: production.profiles.test.resource_limits.memory
- type: str
- default_or_configured_value: 512Mi

## 591. production.profiles.test.resource_limits.replicas_max

- key: production.profiles.test.resource_limits.replicas_max
- type: int
- default_or_configured_value: 1

## 592. production.profiles.test.resource_limits.replicas_min

- key: production.profiles.test.resource_limits.replicas_min
- type: int
- default_or_configured_value: 1

## 593. production.profiles.test.storage_backend

- key: production.profiles.test.storage_backend
- type: str
- default_or_configured_value: in_memory

## 594. production.profiles.test.tls_required

- key: production.profiles.test.tls_required
- type: bool
- default_or_configured_value: False

## 595. production.prohibited_action_types

- key: production.prohibited_action_types
- type: list
- default_or_configured_value: ["isolate_host", "isolate_database", "disable_privileged_identity", "block_subnet", "modify_critical_database", "change_core_routing", "block_all_traffic", "delete_credentials"]

## 596. production.protected_assets

- key: production.protected_assets
- type: list
- default_or_configured_value: []

## 597. production.required_model_versions

- key: production.required_model_versions
- type: list
- default_or_configured_value: []

## 598. production.required_policy_versions

- key: production.required_policy_versions
- type: list
- default_or_configured_value: ["safety-v1", "formal-safety-v1"]

## 599. production.rollback_configured_actions

- key: production.rollback_configured_actions
- type: list
- default_or_configured_value: ["increase_endpoint_logging", "increase_network_telemetry", "enable_limited_packet_capture", "enable_auth_auditing", "create_soc_ticket", "request_analyst_review", "deploy_decoy_host", "deploy_decoy_database", "deploy_fake_share", "add_decoy_service", "scatter_honey_credential", "create_fake_dns_record", "throttle_edge"]

## 600. production.safety_gate_required

- key: production.safety_gate_required
- type: bool
- default_or_configured_value: True

## 601. production.storage.backend

- key: production.storage.backend
- type: str
- default_or_configured_value: sqlite

## 602. production.storage.object_storage_uri

- key: production.storage.object_storage_uri
- type: str
- default_or_configured_value: artifacts/production/object_store

## 603. production.storage.postgres_dsn

- key: production.storage.postgres_dsn
- type: str
- default_or_configured_value: 

## 604. production.storage.schema_compatibility_window

- key: production.storage.schema_compatibility_window
- type: int
- default_or_configured_value: 1

## 605. production.storage.sqlite_path

- key: production.storage.sqlite_path
- type: str
- default_or_configured_value: artifacts/production/mirage.db

## 606. production.tenants

- key: production.tenants
- type: list
- default_or_configured_value: ["default"]

## 607. production.tls.ca_bundle

- key: production.tls.ca_bundle
- type: str
- default_or_configured_value: 

## 608. production.tls.cert_file

- key: production.tls.cert_file
- type: str
- default_or_configured_value: 

## 609. production.tls.enabled

- key: production.tls.enabled
- type: bool
- default_or_configured_value: False

## 610. production.tls.insecure_skip_verify

- key: production.tls.insecure_skip_verify
- type: bool
- default_or_configured_value: False

## 611. production.tls.key_file

- key: production.tls.key_file
- type: str
- default_or_configured_value: 

## 612. production.tls.mtls_required

- key: production.tls.mtls_required
- type: bool
- default_or_configured_value: False

## 613. production.tls.verify_hostname

- key: production.tls.verify_hostname
- type: bool
- default_or_configured_value: True

## 614. readiness.auto_promote_deployment_level

- key: readiness.auto_promote_deployment_level
- type: bool
- default_or_configured_value: False

## 615. readiness.deployment_level_reduction_rules.critical_assurance_failure

- key: readiness.deployment_level_reduction_rules.critical_assurance_failure
- type: str
- default_or_configured_value: SHADOW_ONLY

## 616. readiness.deployment_level_reduction_rules.critical_drift

- key: readiness.deployment_level_reduction_rules.critical_drift
- type: str
- default_or_configured_value: SHADOW_ONLY

## 617. readiness.deployment_level_reduction_rules.slo_exhausted

- key: readiness.deployment_level_reduction_rules.slo_exhausted
- type: str
- default_or_configured_value: SHADOW_ONLY

## 618. readiness.maturity_threshold

- key: readiness.maturity_threshold
- type: float
- default_or_configured_value: 0.8

## 619. realtime.analysis_debounce_seconds

- key: realtime.analysis_debounce_seconds
- type: int
- default_or_configured_value: 30

## 620. realtime.event_trigger_compromise_threshold

- key: realtime.event_trigger_compromise_threshold
- type: float
- default_or_configured_value: 0.85

## 621. realtime.max_events_per_poll

- key: realtime.max_events_per_poll
- type: int
- default_or_configured_value: 1000

## 622. rl.backend

- key: rl.backend
- type: str
- default_or_configured_value: numpy

## 623. rl.cost_weight

- key: rl.cost_weight
- type: float
- default_or_configured_value: 0.015

## 624. rl.hidden_size

- key: rl.hidden_size
- type: int
- default_or_configured_value: 128

## 625. rl.max_actions

- key: rl.max_actions
- type: int
- default_or_configured_value: 200

## 626. rl.max_steps

- key: rl.max_steps
- type: int
- default_or_configured_value: 5

## 627. rl.model_path

- key: rl.model_path
- type: str
- default_or_configured_value: models/mirage_dqn.npz

## 628. rl.n_attacker_episodes

- key: rl.n_attacker_episodes
- type: int
- default_or_configured_value: 12

## 629. shadow.enabled

- key: shadow.enabled
- type: bool
- default_or_configured_value: True

## 630. shadow.feedback_state_path

- key: shadow.feedback_state_path
- type: str
- default_or_configured_value: artifacts/shadow_feedback.json

## 631. shadow.recommendation_state_path

- key: shadow.recommendation_state_path
- type: str
- default_or_configured_value: artifacts/shadow_recommendations.json

## 632. shadow.recommendation_ttl_seconds

- key: shadow.recommendation_ttl_seconds
- type: int
- default_or_configured_value: 3600

## 633. sites.local.allow_central_governance

- key: sites.local.allow_central_governance
- type: bool
- default_or_configured_value: False

## 634. sites.local.data_residency_zone

- key: sites.local.data_residency_zone
- type: str
- default_or_configured_value: local

## 635. sites.local.display_name

- key: sites.local.display_name
- type: str
- default_or_configured_value: Local MIRAGE Site

## 636. sites.local.endpoint

- key: sites.local.endpoint
- type: str
- default_or_configured_value: 

## 637. sites.local.policy_version

- key: sites.local.policy_version
- type: str
- default_or_configured_value: federation-policy-v1

## 638. sites.local.public_identity

- key: sites.local.public_identity
- type: str
- default_or_configured_value: local-site-identity

## 639. sites.local.site_id

- key: sites.local.site_id
- type: str
- default_or_configured_value: site-local

## 640. sites.local.tenant_id

- key: sites.local.tenant_id
- type: str
- default_or_configured_value: default

## 641. sites.registered

- key: sites.registered
- type: list
- default_or_configured_value: []

## 642. slo.error_budget_policy.release_block_on_exhaustion

- key: slo.error_budget_policy.release_block_on_exhaustion
- type: bool
- default_or_configured_value: True

## 643. slo.error_budget_policy.safety_budget_exhaustion_behavior

- key: slo.error_budget_policy.safety_budget_exhaustion_behavior
- type: str
- default_or_configured_value: force_shadow

## 644. slo.targets.api_availability

- key: slo.targets.api_availability
- type: float
- default_or_configured_value: 0.99

## 645. slo.targets.audit_write_success

- key: slo.targets.audit_write_success
- type: float
- default_or_configured_value: 0.999

## 646. slo.targets.event_ingestion_success

- key: slo.targets.event_ingestion_success
- type: float
- default_or_configured_value: 0.995

## 647. slo.targets.rollback_success

- key: slo.targets.rollback_success
- type: float
- default_or_configured_value: 0.99

## 648. slo.targets.twin_freshness

- key: slo.targets.twin_freshness
- type: float
- default_or_configured_value: 0.95

## 649. topology.format

- key: topology.format
- type: str
- default_or_configured_value: mirage

## 650. topology.path

- key: topology.path
- type: str
- default_or_configured_value: examples/enterprise_topology.json

## 651. topology.source

- key: topology.source
- type: str
- default_or_configured_value: builtin

## 652. twin.allow_provisional_entities

- key: twin.allow_provisional_entities
- type: bool
- default_or_configured_value: True

## 653. twin.ingestion_strict

- key: twin.ingestion_strict
- type: bool
- default_or_configured_value: False

## 654. twin.logging_level

- key: twin.logging_level
- type: str
- default_or_configured_value: INFO

## 655. twin.max_batch_size

- key: twin.max_batch_size
- type: int
- default_or_configured_value: 1000

## 656. twin.relationship_ttls.accessed_file_on

- key: twin.relationship_ttls.accessed_file_on
- type: int
- default_or_configured_value: 3600

## 657. twin.relationship_ttls.auth_failed_to

- key: twin.relationship_ttls.auth_failed_to
- type: int
- default_or_configured_value: 3600

## 658. twin.relationship_ttls.authenticated_to

- key: twin.relationship_ttls.authenticated_to
- type: int
- default_or_configured_value: 86400

## 659. twin.relationship_ttls.connects_to

- key: twin.relationship_ttls.connects_to
- type: int
- default_or_configured_value: 3600

## 660. twin.relationship_ttls.has_vulnerability

- key: twin.relationship_ttls.has_vulnerability
- type: int
- default_or_configured_value: 604800

## 661. twin.relationship_ttls.interacted_with_decoy

- key: twin.relationship_ttls.interacted_with_decoy
- type: int
- default_or_configured_value: 604800

## 662. twin.relationship_ttls.ran_process_on

- key: twin.relationship_ttls.ran_process_on
- type: int
- default_or_configured_value: 3600

## 663. twin.relationship_ttls.resolved_dns_to

- key: twin.relationship_ttls.resolved_dns_to
- type: int
- default_or_configured_value: 3600

## 664. twin.relationship_ttls.uses_credential_on

- key: twin.relationship_ttls.uses_credential_on
- type: int
- default_or_configured_value: <redacted>

## 665. twin.replay_ordering

- key: twin.replay_ordering
- type: str
- default_or_configured_value: event_time

## 666. twin.snapshot_path

- key: twin.snapshot_path
- type: str
- default_or_configured_value: artifacts/twin_snapshot.json

## 667. validation.allowed_chaos_environments

- key: validation.allowed_chaos_environments
- type: list
- default_or_configured_value: ["dev", "test", "staging", "lab", "cyber_range"]

## 668. validation.chaos_enabled

- key: validation.chaos_enabled
- type: bool
- default_or_configured_value: True

## 669. validation.ci_max_soak_seconds

- key: validation.ci_max_soak_seconds
- type: int
- default_or_configured_value: 60

## 670. validation.default_soak_duration

- key: validation.default_soak_duration
- type: str
- default_or_configured_value: 6h

## 671. validation.max_memory_growth_mb

- key: validation.max_memory_growth_mb
- type: float
- default_or_configured_value: 64.0

## 672. validation.max_queue_depth

- key: validation.max_queue_depth
- type: int
- default_or_configured_value: 1000

## 673. validation.production_chaos_approved

- key: validation.production_chaos_approved
- type: bool
- default_or_configured_value: False

## 674. validation.synthetic_event_rate

- key: validation.synthetic_event_rate
- type: int
- default_or_configured_value: 100

## 675. verification.formal_verification_required

- key: verification.formal_verification_required
- type: bool
- default_or_configured_value: True

## 676. verification.invariant_policy_version

- key: verification.invariant_policy_version
- type: str
- default_or_configured_value: formal-safety-v1

## 677. verification.maximum_model_uncertainty

- key: verification.maximum_model_uncertainty
- type: float
- default_or_configured_value: 0.65

## 678. verification.minimum_twin_coverage

- key: verification.minimum_twin_coverage
- type: float
- default_or_configured_value: 0.2

## 679. verification.minimum_twin_freshness

- key: verification.minimum_twin_freshness
- type: float
- default_or_configured_value: 0.35

## 680. verification.reachability_max_depth

- key: verification.reachability_max_depth
- type: int
- default_or_configured_value: 8

## 681. verification.smt_solver_enabled

- key: verification.smt_solver_enabled
- type: bool
- default_or_configured_value: False

## 682. verification.solver_timeout_ms

- key: verification.solver_timeout_ms
- type: int
- default_or_configured_value: 50
