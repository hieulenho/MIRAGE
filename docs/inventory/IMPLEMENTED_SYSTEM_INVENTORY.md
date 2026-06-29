# Implemented System Inventory

This file is generated from repository evidence. A capability is not marked implemented merely because it is documented.

## Totals

- Capabilities: 41
- Source files: 216
- Test files: 41
- API routes: 122
- CLI commands: 115

## Status Counts

- MOCK_ONLY: 4
- PARTIAL: 37

## Verified System Summary Diagram

```text
Telemetry Sources [MOCK_ONLY]
        ->
Read-only Connectors [MOCK_ONLY]
        ->
Normalization, Validation, Deduplication, Ordering [PARTIAL]
        ->
Durable Event Transport [PARTIAL]
        ->
CASM and Entity Resolution [PARTIAL]
        ->
Real-time Digital Twin [PARTIAL]
        ->
Entity Timelines and Contextual Detection [PARTIAL]
        ->
Belief Engine [PARTIAL]
        ->
Local Attack Graph and Path Risk [PARTIAL]
        ->
Candidate Defense Actions [PARTIAL]
        ->
Heuristic / Robust / GNN / BC / Offline RL / MARL Recommendations [PARTIAL]
        ->
Action Masks [PARTIAL]
        ->
Safety Gate [PARTIAL]
        ->
Formal Verification [PARTIAL]
        ->
Governance and Approval [PARTIAL]
        ->
Shadow / Controlled Low-risk Execution [MOCK_ONLY]
        ->
Canary, Monitoring, TTL, Rollback [MOCK_ONLY]
        ->
Audit, SOC Integration, Assurance, and Readiness [PARTIAL]
```

## Capabilities

### M1-CANONICAL-TELEMETRY - Canonical telemetry and SecurityEvent schema

- Status: PARTIAL
- Milestone: Milestone 1
- Layer: Data foundation
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/rl_smoke/manifest.json, artifacts/rl_smoke/trajectories/traj_10dea716f1e8f2d008d8.json, artifacts/rl_smoke/trajectories/traj_32f6a67eb6a3a44bafc3.json, artifacts/rl_smoke/trajectories/traj_386822083ae30d61adfb.json, artifacts/rl_smoke/trajectories/traj_471227c50df793c36fd9.json, artifacts/rl_smoke/trajectories/traj_4b6e090f8cf1ecbe963b.json
- Tests: tests/gnn/test_inference_registry_hybrid.py, tests/layer6/__init__.py, tests/layer6/test_digital_twin_v1.py, tests/layer6/test_evaluation.py, tests/marl/test_milestone8_marl.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/gnn/training.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M1-INGESTION-REPLAY - JSONL ingestion, replay, validation, ordering, deduplication, and dead-letter handling

- Status: PARTIAL
- Milestone: Milestone 1
- Layer: Ingestion
- Evidence files: artifacts/connectors_state.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, mirage/analysis/evaluation.py, mirage/analysis/paths.py, mirage/analysis/seeds.py, mirage/api/server.py, mirage/config.py
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/detection/test_contextual_detection_v1.py, tests/layer6/__init__.py, tests/layer6/test_digital_twin_v1.py, tests/layer6/test_evaluation.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M1-ENTITY-RESOLUTION - Entity resolution and normalization

- Status: PARTIAL
- Milestone: Milestone 1
- Layer: Digital Twin
- Evidence files: artifacts/audit_twin.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/m3_twin_db.json, artifacts/m5_replay_twin.json, artifacts/rl_smoke/trajectories/traj_10dea716f1e8f2d008d8.json, artifacts/rl_smoke/trajectories/traj_32f6a67eb6a3a44bafc3.json, artifacts/rl_smoke/trajectories/traj_386822083ae30d61adfb.json
- Tests: tests/layer6/__init__.py, tests/layer6/test_digital_twin_v1.py, tests/layer6/test_evaluation.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M1-DIGITAL-TWIN - Digital Twin entities, relationships, TTLs, snapshots, and incremental updates

- Status: PARTIAL
- Milestone: Milestone 1
- Layer: Digital Twin
- Evidence files: artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_detections.jsonl, artifacts/audit_twin.json, artifacts/belief_snapshot_deception.json, artifacts/detections_benign.jsonl, artifacts/detections_deception.jsonl, artifacts/detections_m2_a.jsonl
- Tests: test_agents.py, tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/api/test_twin_api.py, tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_inference_registry_hybrid.py, tests/gnn/test_torch_model_optional.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M1-STORAGE - Storage abstractions and backend separation

- Status: PARTIAL
- Milestone: Milestone 1/10
- Layer: Storage
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, mirage/api/server.py, mirage/m5_cli.py, mirage/production/cli.py, mirage/production/config.py, mirage/production/schema.py, mirage/production/storage.py
- Tests: tests/milestone10/__init__.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M2-TIMELINES - Entity timelines and evidence windows

- Status: PARTIAL
- Milestone: Milestone 2
- Layer: Detection
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_belief.json, artifacts/audit_detections.jsonl, artifacts/audit_twin.json, artifacts/belief_snapshot_benign.json, artifacts/belief_snapshot_deception.json
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_api.py, tests/gnn/test_dataset_and_hierarchy.py, tests/gnn/test_inference_registry_hybrid.py, tests/gnn/test_torch_model_optional.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M2-DETECTION-RULES - Contextual detection rules and stage classification

- Status: PARTIAL
- Milestone: Milestone 2
- Layer: Detection
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_belief.json, artifacts/audit_detections.jsonl, artifacts/audit_twin.json, artifacts/belief_snapshot_benign.json, artifacts/belief_snapshot_deception.json
- Tests: test_agents.py, tests/api/test_api_server.py, tests/api/test_twin_api.py, tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_inference_registry_hybrid.py, tests/layer5/test_safe_control.py, tests/layer6/test_digital_twin_v1.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M2-BELIEF-ENGINE - Belief Engine probability updates and decay

- Status: PARTIAL
- Milestone: Milestone 2
- Layer: Detection
- Evidence files: artifacts/audit_analysis.json, artifacts/audit_belief.json, artifacts/audit_detections.jsonl, artifacts/belief_snapshot_benign.json, artifacts/belief_snapshot_deception.json, artifacts/belief_snapshot_m2_a.json, artifacts/belief_snapshot_m2_b.json, artifacts/connectors_state.json
- Tests: tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/layer2/test_graph_parser.py, tests/layer6/test_digital_twin_v1.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone11/test_milestone11_operational_maturity.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/gnn/baselines.py:raise\s+NotImplementedError; documentation exists but implementation evidence is incomplete

### M2-EXPLANATIONS - Detection explanations and warnings

- Status: PARTIAL
- Milestone: Milestone 2
- Layer: Detection
- Evidence files: artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_belief.json, artifacts/audit_detections.jsonl, artifacts/audit_twin.json, artifacts/belief_snapshot_benign.json, artifacts/belief_snapshot_deception.json, artifacts/belief_snapshot_m2_a.json
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/detection/test_contextual_detection_v1.py, tests/gnn/test_dataset_and_hierarchy.py, tests/layer5/test_safe_control.py, tests/layer6/test_digital_twin_v1.py, tests/rl/test_milestone7_offline_rl.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M3-GRAPH-ANALYSIS - Local attack graph extraction and path-risk scoring

- Status: PARTIAL
- Milestone: Milestone 3
- Layer: Attack analysis
- Evidence files: artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_detections.jsonl, artifacts/audit_twin.json, artifacts/belief_snapshot_deception.json, artifacts/detections_benign.jsonl, artifacts/detections_deception.jsonl, artifacts/detections_m2_a.jsonl
- Tests: test_agents.py, tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/api/test_twin_api.py, tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_dataset_and_hierarchy.py, tests/gnn/test_torch_model_optional.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M3-CANDIDATE-ACTIONS - Candidate defense action generation

- Status: PARTIAL
- Milestone: Milestone 3
- Layer: Action recommendation
- Evidence files: artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/execution_audit.jsonl, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/m3_actions_db.json, artifacts/m3_actions_db_a.json, artifacts/m3_actions_db_b.json
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/execution/test_milestone4_execution.py, tests/milestone9/test_milestone9_formal_governance_pilot.py, tests/rl/test_milestone7_offline_rl.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M3-ACTION-MASKS - Action Mask generation and constraints

- Status: PARTIAL
- Milestone: Milestone 3
- Layer: Safety
- Evidence files: artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_detections.jsonl, artifacts/connectors_state.json, artifacts/detections_benign.jsonl, artifacts/detections_deception.jsonl, artifacts/detections_m2_a.jsonl, artifacts/detections_m2_b.jsonl
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_inference_registry_hybrid.py, tests/layer2/test_graph_parser.py, tests/layer6/test_digital_twin_v1.py, tests/milestone10/test_milestone10_production_hardening.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M3-RANKING - Deterministic ranking and robust adapter fallback

- Status: MOCK_ONLY
- Milestone: Milestone 3
- Layer: Decision support
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/execution_audit.jsonl, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/m3_actions_db.json, artifacts/m3_actions_db_a.json
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/gnn/test_api.py, tests/gnn/test_inference_registry_hybrid.py, tests/layer4/test_rl_agent.py, tests/marl/test_milestone8_marl.py, tests/rl/test_milestone7_offline_rl.py, tests/shared/test_reward_design.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is MOCK_ONLY; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$

### M4-SAFETY-GATE - Safety Gate and hard policy checks

- Status: PARTIAL
- Milestone: Milestone 4
- Layer: Safety
- Evidence files: artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/execution_audit.jsonl, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/m3_actions_db.json, artifacts/m3_actions_db_a.json, artifacts/m3_actions_db_b.json
- Tests: tests/api/test_api_server.py, tests/execution/__init__.py, tests/execution/test_milestone4_execution.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/test_milestone5_shadow_connectors.py, tests/milestone9/test_milestone9_formal_governance_pilot.py, tests/rl/test_milestone7_offline_rl.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M4-EXECUTION-LIFECYCLE - Execution lifecycle, idempotency, retries, timeout, and rollback

- Status: PARTIAL
- Milestone: Milestone 4/10
- Layer: Execution
- Evidence files: artifacts/assurance/backups/assurance_rehearsal.json, artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_detections.jsonl, artifacts/connectors_state.json, artifacts/detections_benign.jsonl, artifacts/detections_deception.jsonl, artifacts/detections_m2_a.jsonl
- Tests: tests/api/test_api_server.py, tests/detection/test_contextual_detection_v1.py, tests/execution/__init__.py, tests/execution/test_milestone4_execution.py, tests/layer2/test_graph_parser.py, tests/layer6/test_digital_twin_v1.py, tests/milestone10/__init__.py, tests/milestone10/test_milestone10_production_hardening.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M4-ADAPTERS - Execution adapters and adapter classification

- Status: MOCK_ONLY
- Milestone: Milestone 4
- Layer: Execution
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/execution_audit.jsonl, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, configs/pilot_v1.yaml, mirage/analysis/actions.py, mirage/analysis/robust_adapter.py, mirage/config.py
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/execution/__init__.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_inference_registry_hybrid.py, tests/layer5/test_safe_control.py, tests/marl/test_milestone8_marl.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone9/test_milestone9_formal_governance_pilot.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is MOCK_ONLY; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation

### M4-DECEPTION-ORCHESTRATION - Deception orchestration and rollback

- Status: PARTIAL
- Milestone: Milestone 4
- Layer: Execution
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_detections.jsonl, artifacts/audit_twin.json, artifacts/belief_snapshot_deception.json, artifacts/detections_benign.jsonl, artifacts/detections_deception.jsonl
- Tests: test_agents.py, tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/api/test_twin_api.py, tests/detection/test_contextual_detection_v1.py, tests/execution/__init__.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_dataset_and_hierarchy.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M5-CONNECTOR-FRAMEWORK - Read-only connector framework

- Status: PARTIAL
- Milestone: Milestone 5
- Layer: Connectors
- Evidence files: artifacts/connectors_state.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, configs/marl_v1.yaml, configs/rl_offline_v1.yaml, mirage/api/server.py, mirage/config.py, mirage/connectors/__init__.py
- Tests: tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py, tests/milestone9/test_milestone9_formal_governance_pilot.py, tests/rl/test_milestone7_offline_rl.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M5-CONNECTOR-IMPLEMENTATIONS - Connector implementations and fixture/live-source boundaries

- Status: MOCK_ONLY
- Milestone: Milestone 5
- Layer: Connectors
- Evidence files: artifacts/audit_twin.json, artifacts/connectors_state.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/m3_twin_db.json, mirage/casm/service.py, mirage/config.py, mirage/connectors/__init__.py
- Tests: tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is MOCK_ONLY; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation

### M5-STREAMING - Streaming ordering, deduplication, watermarks, recovery, and backpressure

- Status: PARTIAL
- Milestone: Milestone 5/10
- Layer: Streaming
- Evidence files: artifacts/connectors_state.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, configs/marl_v1.yaml, configs/rl_offline_v1.yaml, mirage/analysis/paths.py, mirage/analysis/seeds.py, mirage/api/server.py
- Tests: tests/detection/test_contextual_detection_v1.py, tests/layer6/test_digital_twin_v1.py, tests/milestone10/__init__.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M5-CASM - CASM discovery, reconciliation, conflicts, provenance, and quality

- Status: PARTIAL
- Milestone: Milestone 5
- Layer: CASM
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/rl_smoke/trajectories/traj_618e84b7c7df14b75385.json, mirage/api/server.py, mirage/casm/__init__.py, mirage/casm/service.py, mirage/config.py, mirage/domain/__init__.py
- Tests: tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M5-SHADOW-MODE - Shadow Mode recommendations and feedback

- Status: PARTIAL
- Milestone: Milestone 5
- Layer: Shadow operations
- Evidence files: artifacts/audit_analysis.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/m3_analysis_db.json, artifacts/m3_analysis_db_a.json, artifacts/m3_analysis_db_b.json, artifacts/rl_smoke/trajectories/traj_10dea716f1e8f2d008d8.json, artifacts/rl_smoke/trajectories/traj_32f6a67eb6a3a44bafc3.json
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/api/test_api_server.py, tests/gnn/test_inference_registry_hybrid.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone11/test_milestone11_operational_maturity.py, tests/milestone5/__init__.py, tests/milestone5/test_milestone5_shadow_connectors.py, tests/shared/test_policy_cache.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M6-GRAPH-SCHEMA-FEATURES - Hierarchical graph schema and feature processing

- Status: PARTIAL
- Milestone: Milestone 6
- Layer: ML features
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/execution_audit.jsonl, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/m3_actions_db.json, artifacts/m3_actions_db_a.json
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_dataset_and_hierarchy.py, tests/gnn/test_inference_registry_hybrid.py, tests/gnn/test_torch_model_optional.py, tests/layer4/test_rl_agent.py, tests/marl/test_milestone8_marl.py, tests/milestone10/test_milestone10_production_hardening.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M6-DATASET-GENERATION - GNN dataset generation, labels, splits, hashes, and leakage controls

- Status: PARTIAL
- Milestone: Milestone 6
- Layer: ML data
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/rl_smoke/manifest.json, artifacts/rl_smoke/trajectories/traj_10dea716f1e8f2d008d8.json, artifacts/rl_smoke/trajectories/traj_32f6a67eb6a3a44bafc3.json, artifacts/rl_smoke/trajectories/traj_386822083ae30d61adfb.json, artifacts/rl_smoke/trajectories/traj_471227c50df793c36fd9.json, artifacts/rl_smoke/trajectories/traj_4b6e090f8cf1ecbe963b.json
- Tests: tests/gnn/__init__.py, tests/gnn/test_api.py, tests/gnn/test_dataset_and_hierarchy.py, tests/gnn/test_inference_registry_hybrid.py, tests/gnn/test_torch_model_optional.py, tests/rl/test_milestone7_offline_rl.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M6-MODELS-INFERENCE - GNN and baseline models with registry and shadow inference

- Status: PARTIAL
- Milestone: Milestone 6
- Layer: ML inference
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/audit_actions.json, artifacts/audit_analysis.json, artifacts/audit_belief.json, artifacts/audit_detections.jsonl, artifacts/belief_snapshot_benign.json, artifacts/belief_snapshot_deception.json, artifacts/belief_snapshot_m2_a.json
- Tests: tests/api/test_api_server.py, tests/api/test_twin_api.py, tests/execution/test_milestone4_execution.py, tests/gnn/__init__.py, tests/gnn/test_api.py, tests/gnn/test_dataset_and_hierarchy.py, tests/gnn/test_inference_registry_hybrid.py, tests/gnn/test_torch_model_optional.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M7-OFFLINE-RL-DATA - Offline RL dataset, trajectories, rewards, and constraints

- Status: PARTIAL
- Milestone: Milestone 7
- Layer: RL data
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/rl_smoke/manifest.json, artifacts/rl_smoke/trajectories/traj_10dea716f1e8f2d008d8.json, artifacts/rl_smoke/trajectories/traj_32f6a67eb6a3a44bafc3.json, artifacts/rl_smoke/trajectories/traj_386822083ae30d61adfb.json, artifacts/rl_smoke/trajectories/traj_471227c50df793c36fd9.json, artifacts/rl_smoke/trajectories/traj_4b6e090f8cf1ecbe963b.json
- Tests: tests/layer2/test_attack_graph.py, tests/layer4/test_rl_agent.py, tests/layer6/test_evaluation.py, tests/marl/test_milestone8_marl.py, tests/rl/__init__.py, tests/rl/test_milestone7_offline_rl.py, tests/shared/test_reward_design.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M7-POLICIES-RUNTIME - Behavior Cloning, conservative offline RL, policy registry, and shadow runtime

- Status: PARTIAL
- Milestone: Milestone 7
- Layer: RL policy
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/rl_smoke/trajectories/traj_10dea716f1e8f2d008d8.json, artifacts/rl_smoke/trajectories/traj_32f6a67eb6a3a44bafc3.json, artifacts/rl_smoke/trajectories/traj_386822083ae30d61adfb.json, artifacts/rl_smoke/trajectories/traj_471227c50df793c36fd9.json, artifacts/rl_smoke/trajectories/traj_4b6e090f8cf1ecbe963b.json, artifacts/rl_smoke/trajectories/traj_5078f850d964e65bc37b.json
- Tests: tests/rl/test_milestone7_offline_rl.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M8-CYBER-RANGE - Cyber Range isolation, reset, masks, replay, and terminal conditions

- Status: PARTIAL
- Milestone: Milestone 8
- Layer: Cyber Range
- Evidence files: artifacts/assurance/backups/assurance_rehearsal.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/production/backups/smoke_m10.json, artifacts/rl_smoke/trajectories/traj_10dea716f1e8f2d008d8.json, artifacts/rl_smoke/trajectories/traj_32f6a67eb6a3a44bafc3.json, artifacts/rl_smoke/trajectories/traj_386822083ae30d61adfb.json, artifacts/rl_smoke/trajectories/traj_471227c50df793c36fd9.json
- Tests: tests/analysis/test_attack_analysis_v1.py, tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_dataset_and_hierarchy.py, tests/gnn/test_inference_registry_hybrid.py, tests/layer4/test_rl_agent.py, tests/layer6/test_digital_twin_v1.py, tests/marl/__init__.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M8-RED-BLUE-SELFPLAY - Red/Blue agent policies and self-play evaluation

- Status: PARTIAL
- Milestone: Milestone 8
- Layer: MARL
- Evidence files: artifacts/assurance/backups/assurance_rehearsal.json, artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/connectors_state.json, artifacts/execution_audit.jsonl, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, configs/marl_eval.yaml, configs/marl_v1.yaml
- Tests: tests/detection/test_contextual_detection_v1.py, tests/execution/test_milestone4_execution.py, tests/gnn/test_dataset_and_hierarchy.py, tests/layer4/test_rl_agent.py, tests/layer6/test_digital_twin_v1.py, tests/marl/test_milestone8_marl.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone11/test_milestone11_operational_maturity.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M9-FORMAL-VERIFICATION - Formal safety verification and invariant registry

- Status: PARTIAL
- Milestone: Milestone 9
- Layer: Formal safety
- Evidence files: artifacts/audit_analysis.json, artifacts/audit_belief.json, artifacts/audit_twin.json, artifacts/belief_snapshot_benign.json, artifacts/belief_snapshot_deception.json, artifacts/belief_snapshot_m2_a.json, artifacts/belief_snapshot_m2_b.json, artifacts/inventory/system_inventory.json
- Tests: tests/api/test_api_server.py, tests/detection/test_contextual_detection_v1.py, tests/gnn/test_dataset_and_hierarchy.py, tests/layer1/test_hmm_classifier.py, tests/milestone9/__init__.py, tests/milestone9/test_milestone9_formal_governance_pilot.py, tests/rl/test_milestone7_offline_rl.py, tests/shared/test_attacker_agents.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M9-GOVERNANCE - Governance registry, cards, release gates, hashes, pilot scopes, and approvals

- Status: PARTIAL
- Milestone: Milestone 9
- Layer: Governance
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, configs/governance_v1.yaml, mirage/api/server.py, mirage/config.py, mirage/governance/__init__.py, mirage/governance/audit.py
- Tests: tests/milestone9/__init__.py, tests/milestone9/test_milestone9_formal_governance_pilot.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M9-AUDIT - Hash-chained audit and tamper detection

- Status: PARTIAL
- Milestone: Milestone 9
- Layer: Audit
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, deploy/iac/terraform/main.tf.example, mirage/api/server.py, mirage/detection/pipeline.py, mirage/detection/timeline.py, mirage/domain/schemas.py
- Tests: tests/execution/test_milestone4_execution.py, tests/milestone10/__init__.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone11/test_milestone11_operational_maturity.py, tests/milestone9/__init__.py, tests/milestone9/test_milestone9_formal_governance_pilot.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M10-PROFILES-PERSISTENCE - Deployment profiles, persistence, migrations, leases, and idempotency

- Status: PARTIAL
- Milestone: Milestone 10
- Layer: Production architecture
- Evidence files: artifacts/assurance/backups/assurance_rehearsal.json, artifacts/execution_audit.jsonl, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, artifacts/production/backups/smoke_m10.json, deploy/helm/mirage/values-production.yaml, deploy/helm/mirage/values.schema.json, deploy/iac/terraform/main.tf.example
- Tests: tests/milestone10/__init__.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone9/test_milestone9_formal_governance_pilot.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation; documentation exists but implementation evidence is incomplete

### M10-EVENT-TRANSPORT-HA - Durable event transport and high availability controls

- Status: PARTIAL
- Milestone: Milestone 10
- Layer: Production architecture
- Evidence files: artifacts/connectors_state.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, mirage/api/server.py, mirage/domain/schemas.py, mirage/production/events.py, mirage/production/ha.py, mirage/streaming/coordinator.py
- Tests: tests/milestone10/__init__.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M10-SECURITY-OBSERVABILITY-DR - Production security, observability, disaster recovery, and SOC integration

- Status: MOCK_ONLY
- Milestone: Milestone 10
- Layer: Operations
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, deploy/kubernetes/mirage-production.yaml, mirage/api/server.py, mirage/production/backup.py, mirage/production/cli.py, mirage/production/deployment.py, mirage/production/observability.py
- Tests: tests/milestone10/__init__.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone9/test_milestone9_formal_governance_pilot.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is MOCK_ONLY; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$

### M10-DEPLOYMENT-RESOURCES - Container, Kubernetes, Helm, CI/CD, SBOM, and scanning resources

- Status: PARTIAL
- Milestone: Milestone 10
- Layer: Deployment
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, deploy/container/Dockerfile, deploy/helm/mirage/Chart.yaml, deploy/helm/mirage/templates/validation.yaml, deploy/helm/mirage/values-controlled-pilot.yaml, deploy/helm/mirage/values-production.yaml, deploy/helm/mirage/values-shadow.yaml
- Tests: tests/milestone10/test_milestone10_production_hardening.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation; documentation exists but implementation evidence is incomplete

### M11-INVENTORY - Verified repository inventory and status matrix

- Status: PARTIAL
- Milestone: Milestone 11
- Layer: Continuous assurance
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, mirage/api/server.py, mirage/milestone11/__init__.py, mirage/milestone11/assurance.py, mirage/milestone11/cli.py, mirage/milestone11/inventory.py, mirage/milestone11/readiness.py
- Tests: tests/milestone11/test_milestone11_operational_maturity.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M11-FEDERATION - Multi-site registration, federation policy, residency, and pseudonymized transfer

- Status: PARTIAL
- Milestone: Milestone 11
- Layer: Federation
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/audit_detections.jsonl, artifacts/connectors_state.json, artifacts/detections_benign.jsonl, artifacts/detections_deception.jsonl, artifacts/detections_m2_a.jsonl, artifacts/detections_m2_b.jsonl, artifacts/inventory/system_inventory.json
- Tests: tests/detection/test_contextual_detection_v1.py, tests/layer2/test_graph_parser.py, tests/layer6/test_digital_twin_v1.py, tests/milestone10/test_milestone10_production_hardening.py, tests/milestone11/test_milestone11_operational_maturity.py, tests/milestone5/test_milestone5_shadow_connectors.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/milestone11/inventory.py:placeholder implementation; documentation exists but implementation evidence is incomplete

### M11-ASSURANCE - Continuous assurance evidence bundles

- Status: PARTIAL
- Milestone: Milestone 11
- Layer: Continuous assurance
- Evidence files: artifacts/assurance/bundles/assurance_c79ca2b048107395.json, artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, mirage/milestone11/assurance.py, mirage/milestone11/cli.py, mirage/milestone11/inventory.py, mirage/milestone11/readiness.py, mirage/milestone11/schema.py
- Tests: tests/milestone11/test_milestone11_operational_maturity.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/milestone11/inventory.py:placeholder implementation; documentation exists but implementation evidence is incomplete

### M11-VALIDATION - Long-horizon soak and chaos validation

- Status: PARTIAL
- Milestone: Milestone 11
- Layer: Validation
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, mirage/analysis/evaluation.py, mirage/analysis/paths.py, mirage/analysis/seeds.py, mirage/analysis/subgraph.py, mirage/api/server.py, mirage/dashboard/app.js
- Tests: tests/marl/test_milestone8_marl.py, tests/milestone11/test_milestone11_operational_maturity.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\s*(#\s*(placeholder|stub|todo|not implemented))?$; documentation exists but implementation evidence is incomplete

### M11-SLO-CAPACITY-MATURITY-READINESS - SLO, capacity, maturity, and readiness decision board

- Status: PARTIAL
- Milestone: Milestone 11
- Layer: Operations
- Evidence files: artifacts/inventory/system_inventory.json, artifacts/inventory/system_inventory.yaml, mirage/milestone11/inventory.py, mirage/milestone11/readiness.py
- Tests: tests/milestone11/test_milestone11_operational_maturity.py
- Runtime verification: test_files_discovered_not_executed_by_inventory_scanner
- Limitations: status is PARTIAL; do not treat as complete without remediation; placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/milestone11/inventory.py:placeholder implementation; documentation exists but implementation evidence is incomplete
