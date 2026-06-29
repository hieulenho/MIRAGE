# Implementation Status Matrix

| Capability ID | Name | Status | Source Evidence | Test Evidence | Next Action |
| --- | --- | --- | ---: | ---: | --- |
| M1-CANONICAL-TELEMETRY | Canonical telemetry and SecurityEvent schema | PARTIAL | 44 | 8 | complete missing integration, persistence, docs, tests, or runtime verification |
| M1-INGESTION-REPLAY | JSONL ingestion, replay, validation, ordering, deduplication, and dead-letter handling | PARTIAL | 22 | 8 | complete missing integration, persistence, docs, tests, or runtime verification |
| M1-ENTITY-RESOLUTION | Entity resolution and normalization | PARTIAL | 44 | 6 | complete missing integration, persistence, docs, tests, or runtime verification |
| M1-DIGITAL-TWIN | Digital Twin entities, relationships, TTLs, snapshots, and incremental updates | PARTIAL | 120 | 17 | complete missing integration, persistence, docs, tests, or runtime verification |
| M1-STORAGE | Storage abstractions and backend separation | PARTIAL | 11 | 3 | complete missing integration, persistence, docs, tests, or runtime verification |
| M2-TIMELINES | Entity timelines and evidence windows | PARTIAL | 142 | 14 | complete missing integration, persistence, docs, tests, or runtime verification |
| M2-DETECTION-RULES | Contextual detection rules and stage classification | PARTIAL | 106 | 11 | complete missing integration, persistence, docs, tests, or runtime verification |
| M2-BELIEF-ENGINE | Belief Engine probability updates and decay | PARTIAL | 50 | 7 | complete missing integration, persistence, docs, tests, or runtime verification |
| M2-EXPLANATIONS | Detection explanations and warnings | PARTIAL | 111 | 7 | complete missing integration, persistence, docs, tests, or runtime verification |
| M3-GRAPH-ANALYSIS | Local attack graph extraction and path-risk scoring | PARTIAL | 115 | 17 | complete missing integration, persistence, docs, tests, or runtime verification |
| M3-CANDIDATE-ACTIONS | Candidate defense action generation | PARTIAL | 57 | 4 | complete missing integration, persistence, docs, tests, or runtime verification |
| M3-ACTION-MASKS | Action Mask generation and constraints | PARTIAL | 97 | 12 | complete missing integration, persistence, docs, tests, or runtime verification |
| M3-RANKING | Deterministic ranking and robust adapter fallback | MOCK_ONLY | 65 | 8 | label mock-only in deployment docs and add pilot/production adapter evidence before use |
| M4-SAFETY-GATE | Safety Gate and hard policy checks | PARTIAL | 57 | 7 | complete missing integration, persistence, docs, tests, or runtime verification |
| M4-EXECUTION-LIFECYCLE | Execution lifecycle, idempotency, retries, timeout, and rollback | PARTIAL | 87 | 12 | complete missing integration, persistence, docs, tests, or runtime verification |
| M4-ADAPTERS | Execution adapters and adapter classification | MOCK_ONLY | 47 | 9 | label mock-only in deployment docs and add pilot/production adapter evidence before use |
| M4-DECEPTION-ORCHESTRATION | Deception orchestration and rollback | PARTIAL | 150 | 19 | complete missing integration, persistence, docs, tests, or runtime verification |
| M5-CONNECTOR-FRAMEWORK | Read-only connector framework | PARTIAL | 27 | 5 | complete missing integration, persistence, docs, tests, or runtime verification |
| M5-CONNECTOR-IMPLEMENTATIONS | Connector implementations and fixture/live-source boundaries | MOCK_ONLY | 11 | 2 | label mock-only in deployment docs and add pilot/production adapter evidence before use |
| M5-STREAMING | Streaming ordering, deduplication, watermarks, recovery, and backpressure | PARTIAL | 25 | 6 | complete missing integration, persistence, docs, tests, or runtime verification |
| M5-CASM | CASM discovery, reconciliation, conflicts, provenance, and quality | PARTIAL | 19 | 3 | complete missing integration, persistence, docs, tests, or runtime verification |
| M5-SHADOW-MODE | Shadow Mode recommendations and feedback | PARTIAL | 71 | 8 | complete missing integration, persistence, docs, tests, or runtime verification |
| M6-GRAPH-SCHEMA-FEATURES | Hierarchical graph schema and feature processing | PARTIAL | 95 | 11 | complete missing integration, persistence, docs, tests, or runtime verification |
| M6-DATASET-GENERATION | GNN dataset generation, labels, splits, hashes, and leakage controls | PARTIAL | 37 | 6 | complete missing integration, persistence, docs, tests, or runtime verification |
| M6-MODELS-INFERENCE | GNN and baseline models with registry and shadow inference | PARTIAL | 123 | 14 | complete missing integration, persistence, docs, tests, or runtime verification |
| M7-OFFLINE-RL-DATA | Offline RL dataset, trajectories, rewards, and constraints | PARTIAL | 61 | 7 | complete missing integration, persistence, docs, tests, or runtime verification |
| M7-POLICIES-RUNTIME | Behavior Cloning, conservative offline RL, policy registry, and shadow runtime | PARTIAL | 30 | 1 | complete missing integration, persistence, docs, tests, or runtime verification |
| M8-CYBER-RANGE | Cyber Range isolation, reset, masks, replay, and terminal conditions | PARTIAL | 93 | 13 | complete missing integration, persistence, docs, tests, or runtime verification |
| M8-RED-BLUE-SELFPLAY | Red/Blue agent policies and self-play evaluation | PARTIAL | 65 | 9 | complete missing integration, persistence, docs, tests, or runtime verification |
| M9-FORMAL-VERIFICATION | Formal safety verification and invariant registry | PARTIAL | 72 | 8 | complete missing integration, persistence, docs, tests, or runtime verification |
| M9-GOVERNANCE | Governance registry, cards, release gates, hashes, pilot scopes, and approvals | PARTIAL | 23 | 2 | complete missing integration, persistence, docs, tests, or runtime verification |
| M9-AUDIT | Hash-chained audit and tamper detection | PARTIAL | 16 | 6 | complete missing integration, persistence, docs, tests, or runtime verification |
| M10-PROFILES-PERSISTENCE | Deployment profiles, persistence, migrations, leases, and idempotency | PARTIAL | 23 | 3 | complete missing integration, persistence, docs, tests, or runtime verification |
| M10-EVENT-TRANSPORT-HA | Durable event transport and high availability controls | PARTIAL | 9 | 3 | complete missing integration, persistence, docs, tests, or runtime verification |
| M10-SECURITY-OBSERVABILITY-DR | Production security, observability, disaster recovery, and SOC integration | MOCK_ONLY | 13 | 3 | label mock-only in deployment docs and add pilot/production adapter evidence before use |
| M10-DEPLOYMENT-RESOURCES | Container, Kubernetes, Helm, CI/CD, SBOM, and scanning resources | PARTIAL | 12 | 1 | complete missing integration, persistence, docs, tests, or runtime verification |
| M11-INVENTORY | Verified repository inventory and status matrix | PARTIAL | 9 | 1 | complete missing integration, persistence, docs, tests, or runtime verification |
| M11-FEDERATION | Multi-site registration, federation policy, residency, and pseudonymized transfer | PARTIAL | 35 | 6 | complete missing integration, persistence, docs, tests, or runtime verification |
| M11-ASSURANCE | Continuous assurance evidence bundles | PARTIAL | 8 | 1 | complete missing integration, persistence, docs, tests, or runtime verification |
| M11-VALIDATION | Long-horizon soak and chaos validation | PARTIAL | 29 | 2 | complete missing integration, persistence, docs, tests, or runtime verification |
| M11-SLO-CAPACITY-MATURITY-READINESS | SLO, capacity, maturity, and readiness decision board | PARTIAL | 4 | 1 | complete missing integration, persistence, docs, tests, or runtime verification |
