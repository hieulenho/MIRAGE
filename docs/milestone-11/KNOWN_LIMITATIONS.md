# Known Limitations

Items: 41

## 1. M5-CONNECTOR-IMPLEMENTATIONS

- capability_id: M5-CONNECTOR-IMPLEMENTATIONS
- capability_name: Connector implementations and fixture/live-source boundaries
- status: MOCK_ONLY
- limitations: ["status is MOCK_ONLY; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation"]
- recommended_next_action: label mock-only in deployment docs and add pilot/production adapter evidence before use

## 2. M4-ADAPTERS

- capability_id: M4-ADAPTERS
- capability_name: Execution adapters and adapter classification
- status: MOCK_ONLY
- limitations: ["status is MOCK_ONLY; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation"]
- recommended_next_action: label mock-only in deployment docs and add pilot/production adapter evidence before use

## 3. M3-RANKING

- capability_id: M3-RANKING
- capability_name: Deterministic ranking and robust adapter fallback
- status: MOCK_ONLY
- limitations: ["status is MOCK_ONLY; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$"]
- recommended_next_action: label mock-only in deployment docs and add pilot/production adapter evidence before use

## 4. M10-SECURITY-OBSERVABILITY-DR

- capability_id: M10-SECURITY-OBSERVABILITY-DR
- capability_name: Production security, observability, disaster recovery, and SOC integration
- status: MOCK_ONLY
- limitations: ["status is MOCK_ONLY; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$"]
- recommended_next_action: label mock-only in deployment docs and add pilot/production adapter evidence before use

## 5. M9-GOVERNANCE

- capability_id: M9-GOVERNANCE
- capability_name: Governance registry, cards, release gates, hashes, pilot scopes, and approvals
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 6. M9-FORMAL-VERIFICATION

- capability_id: M9-FORMAL-VERIFICATION
- capability_name: Formal safety verification and invariant registry
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 7. M9-AUDIT

- capability_id: M9-AUDIT
- capability_name: Hash-chained audit and tamper detection
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 8. M8-RED-BLUE-SELFPLAY

- capability_id: M8-RED-BLUE-SELFPLAY
- capability_name: Red/Blue agent policies and self-play evaluation
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 9. M8-CYBER-RANGE

- capability_id: M8-CYBER-RANGE
- capability_name: Cyber Range isolation, reset, masks, replay, and terminal conditions
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 10. M7-POLICIES-RUNTIME

- capability_id: M7-POLICIES-RUNTIME
- capability_name: Behavior Cloning, conservative offline RL, policy registry, and shadow runtime
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 11. M7-OFFLINE-RL-DATA

- capability_id: M7-OFFLINE-RL-DATA
- capability_name: Offline RL dataset, trajectories, rewards, and constraints
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 12. M6-MODELS-INFERENCE

- capability_id: M6-MODELS-INFERENCE
- capability_name: GNN and baseline models with registry and shadow inference
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 13. M6-GRAPH-SCHEMA-FEATURES

- capability_id: M6-GRAPH-SCHEMA-FEATURES
- capability_name: Hierarchical graph schema and feature processing
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 14. M6-DATASET-GENERATION

- capability_id: M6-DATASET-GENERATION
- capability_name: GNN dataset generation, labels, splits, hashes, and leakage controls
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 15. M5-STREAMING

- capability_id: M5-STREAMING
- capability_name: Streaming ordering, deduplication, watermarks, recovery, and backpressure
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 16. M5-SHADOW-MODE

- capability_id: M5-SHADOW-MODE
- capability_name: Shadow Mode recommendations and feedback
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 17. M5-CONNECTOR-FRAMEWORK

- capability_id: M5-CONNECTOR-FRAMEWORK
- capability_name: Read-only connector framework
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 18. M5-CASM

- capability_id: M5-CASM
- capability_name: CASM discovery, reconciliation, conflicts, provenance, and quality
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 19. M4-SAFETY-GATE

- capability_id: M4-SAFETY-GATE
- capability_name: Safety Gate and hard policy checks
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 20. M4-EXECUTION-LIFECYCLE

- capability_id: M4-EXECUTION-LIFECYCLE
- capability_name: Execution lifecycle, idempotency, retries, timeout, and rollback
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 21. M4-DECEPTION-ORCHESTRATION

- capability_id: M4-DECEPTION-ORCHESTRATION
- capability_name: Deception orchestration and rollback
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 22. M3-GRAPH-ANALYSIS

- capability_id: M3-GRAPH-ANALYSIS
- capability_name: Local attack graph extraction and path-risk scoring
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 23. M3-CANDIDATE-ACTIONS

- capability_id: M3-CANDIDATE-ACTIONS
- capability_name: Candidate defense action generation
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 24. M3-ACTION-MASKS

- capability_id: M3-ACTION-MASKS
- capability_name: Action Mask generation and constraints
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 25. M2-TIMELINES

- capability_id: M2-TIMELINES
- capability_name: Entity timelines and evidence windows
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 26. M2-EXPLANATIONS

- capability_id: M2-EXPLANATIONS
- capability_name: Detection explanations and warnings
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 27. M2-DETECTION-RULES

- capability_id: M2-DETECTION-RULES
- capability_name: Contextual detection rules and stage classification
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 28. M2-BELIEF-ENGINE

- capability_id: M2-BELIEF-ENGINE
- capability_name: Belief Engine probability updates and decay
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/gnn/baselines.py:raise\\s+NotImplementedError", "documentation exists but implementation evidence is incomplete"]
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 29. M11-VALIDATION

- capability_id: M11-VALIDATION
- capability_name: Long-horizon soak and chaos validation
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 30. M11-SLO-CAPACITY-MATURITY-READINESS

- capability_id: M11-SLO-CAPACITY-MATURITY-READINESS
- capability_name: SLO, capacity, maturity, and readiness decision board
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/milestone11/inventory.py:placeholder implementation", "documentation exists but implementation evidence is incomple...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 31. M11-INVENTORY

- capability_id: M11-INVENTORY
- capability_name: Verified repository inventory and status matrix
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 32. M11-FEDERATION

- capability_id: M11-FEDERATION
- capability_name: Multi-site registration, federation policy, residency, and pseudonymized transfer
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/milestone11/inventory.py:placeholder implementation", "documentation exists but implementation evidence is incomple...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 33. M11-ASSURANCE

- capability_id: M11-ASSURANCE
- capability_name: Continuous assurance evidence bundles
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/milestone11/inventory.py:placeholder implementation", "documentation exists but implementation evidence is incomple...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 34. M10-PROFILES-PERSISTENCE

- capability_id: M10-PROFILES-PERSISTENCE
- capability_name: Deployment profiles, persistence, migrations, leases, and idempotency
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation", "documentation exists but implementation evidence is incomplete"]
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 35. M10-EVENT-TRANSPORT-HA

- capability_id: M10-EVENT-TRANSPORT-HA
- capability_name: Durable event transport and high availability controls
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 36. M10-DEPLOYMENT-RESOURCES

- capability_id: M10-DEPLOYMENT-RESOURCES
- capability_name: Container, Kubernetes, Helm, CI/CD, SBOM, and scanning resources
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation", "documentation exists but implementation evidence is incomplete"]
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 37. M1-STORAGE

- capability_id: M1-STORAGE
- capability_name: Storage abstractions and backend separation
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 38. M1-INGESTION-REPLAY

- capability_id: M1-INGESTION-REPLAY
- capability_name: JSONL ingestion, replay, validation, ordering, deduplication, and dead-letter handling
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 39. M1-ENTITY-RESOLUTION

- capability_id: M1-ENTITY-RESOLUTION
- capability_name: Entity resolution and normalization
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 40. M1-DIGITAL-TWIN

- capability_id: M1-DIGITAL-TWIN
- capability_name: Digital Twin entities, relationships, TTLs, snapshots, and incremental updates
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/api/server.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation e...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification

## 41. M1-CANONICAL-TELEMETRY

- capability_id: M1-CANONICAL-TELEMETRY
- capability_name: Canonical telemetry and SecurityEvent schema
- status: PARTIAL
- limitations: ["status is PARTIAL; do not treat as complete without remediation", "placeholder or TODO markers were found: artifacts/inventory/system_inventory.json:placeholder implementation, artifacts/inventory/system_inventory.json:stub implementation, artifacts/inventory/system_inventory.yaml:placeholder implementation, artifacts/inventory/system_inventory.yaml:stub implementation, mirage/gnn/training.py:pass\\s*(#\\s*(placeholder|stub|todo|not implemented))?$", "documentation exists but implementation...
- recommended_next_action: complete missing integration, persistence, docs, tests, or runtime verification
