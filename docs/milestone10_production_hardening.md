# Milestone 10: Production Hardening, HA, SOC Integration, and Limited Deployment V1

Milestone 10 adds a production-ready architecture surface around the existing
MIRAGE research and controlled-pilot workflows.  It does not enable
unrestricted autonomous production defense.  Default operation remains Shadow
Mode, production execution is disabled, high-risk automation is disabled, and
Action Mask, Safety Gate, formal verification, governance, rollback, and audit
checks remain mandatory.

## Architecture

```text
Security Data Sources
-> Highly Available Connector and Ingestion Layer
-> Durable Event Transport and Processing
-> CASM + Real-time Digital Twin
-> Detection + Belief + Attack Analysis
-> Heuristic / Robust / GNN / RL / MARL Recommendations
-> Action Mask + Safety Gate + Formal Verification
-> Governance and Pilot Scope
-> Low-risk Execution or SOC Approval
-> Runtime Monitoring + Rollback + Audit
```

The implementation keeps existing domain modules independent from
infrastructure-specific code.  Production concerns live under
`mirage.production`:

- `schema` defines environment profiles, deployment levels, health reports,
  authentication/TLS/storage/event settings, and low-risk/prohibited actions.
- `config` validates production startup.  The `production` profile rejects
  disabled auth or TLS, default credentials, in-memory storage, missing broker
  details, governance/Safety Gate bypasses, missing protected assets, and
  rollback gaps.
- `storage` provides tenant/environment-scoped repository interfaces with
  in-memory and SQLite backends.  Production config requires a PostgreSQL
  compatible backend and object storage for large artifacts.
- `migrations` adds version tracking, dry-run, rollback, compatibility status,
  and migration locking.
- `events` adds an event-bus abstraction with at-least-once delivery,
  idempotency keys, retries, dead-letter queues, lag, backpressure, and schema
  version rejection.
- `ha` provides lease-backed leader election for schedulers, connector
  ownership, TTL expiry, snapshots, drift evaluation, and backup scheduling.
- `execution` persists intent before adapter calls, uses leases, revalidates
  deployment level, persists adapter results, and records idempotency.
- `security` implements deny-by-default RBAC, separation of duties, and
  short-lived signed service tokens for controlled machine integrations.
- `secrets` defines `SecretProvider` and recursive diagnostic redaction.
- `observability` provides structured JSON logs, trace/correlation propagation,
  and Prometheus-style metrics.
- `health` backs `/health/live`, `/health/ready`, `/health/dependencies`,
  `/health/security`, and `/metrics`.
- `backup` creates, verifies, lists, and dry-run restores logical snapshots.
- `soc` defines vendor-neutral SOC adapters plus mock and generic webhook
  implementations.
- `deployment` stores and enforces the limited deployment level:
  `SHADOW_ONLY`, `READ_ONLY_PRODUCTION`, `LOW_RISK_PILOT`, and
  `LIMITED_REVERSIBLE_CONTROL`.

## Deployment Profiles

Supported profiles are `development`, `test`, `cyber_range`, `lab`, `shadow`,
`controlled_pilot`, and `production`.  Each profile defines storage backend,
event transport, connector permissions, enforcement permissions,
authentication/TLS requirements, audit retention, logging, model modes,
allowed tiers, pilot scopes, resource limits, and backup policy.

Production must provide real OIDC or compatible authentication, service
identity, TLS or mTLS, PostgreSQL-compatible storage, a Kafka/Redpanda
compatible broker, durable audit storage, protected assets, and rollback
configuration for every enabled low-risk action.

## Limited Automation

Eligible automatic actions are limited to telemetry/logging increases, SOC
ticket or analyst-review creation, isolated decoys, synthetic honey
credentials, fake DNS records in deception zones, and reversible temporary
throttling.  High-risk actions such as isolating protected assets, disabling
privileged identities, modifying production databases, changing core routing,
broad firewall changes, irreversible actions, stale-context actions, and
ML-only proposals remain recommendation-only or prohibited.

No policy, model, administrator approval, or governance status may override a
false Action Mask or violated hard invariant.

## Operational Runbooks

Each production incident starts by confirming health endpoints, deployment
level, audit-chain status, and whether the kill switch is active.

1. Service startup/shutdown: check `/health/ready`, migration status, leader
   lease, and audit writer.  Stop workers before control plane only when
   pending rollback is empty.
2. Connector failure: disable the connector, preserve checkpoint, inspect
   dead-letter records, and resume from the last acknowledged event.
3. Broker lag: route alert to SOC/platform operations, pause low-risk
   automation, increase consumers, and verify no silent event loss.
4. Database failure: readiness must fail, execution must stop, and Shadow
   recommendations may continue only from safe cached state.
5. Audit-store failure: sensitive execution is blocked.  Restore audit path or
   fail over to append-only storage before resuming.
6. Model-service failure: use heuristic and robust fallback; do not promote or
   execute ML-only recommendations.
7. Safety-verifier failure: reject or hold actions requiring verification.
8. Rollback failure: prioritize rollback channel health, open SOC ticket, and
   keep deployment level at `SHADOW_ONLY`.
9. Kill switch activation: no new execution; active rollback may continue.
10. Critical drift: deployment level automatically reduces to Shadow Mode.
11. Suspicious privileged API use: verify RBAC, audit identity, token
    revocation, and tenant/environment scope.
12. Cross-tenant access alert: deny access, verify tenant-scoped cache keys and
    repository queries, and create a security audit event.
13. Backup failure: route alert, run `python -m mirage backup verify`, and
    confirm retention and object storage.
14. Restore procedure: run `restore validate`, rehearse in isolated namespace,
    verify audit chain, then run authorized restore.
15. Policy suspension: suspend in governance registry, verify release gate, and
    keep prior active policy pinned.
16. Model rollback: pin prior model version, verify artifact hash and card, and
    run canary before traffic shift.
17. Controlled-pilot rollback: prioritize rollback channels and preserve
    execution evidence.
18. Cyber Range isolation failure: stop range jobs, verify deny-all network
    policies, and do not route range traffic to production.

## Kubernetes, Helm, and IaC

`deploy/kubernetes` contains production-oriented manifests for service
accounts, RBAC, Deployments, Services, NetworkPolicies, PodDisruptionBudgets,
HorizontalPodAutoscalers, PVCs, and backup/verification CronJobs.
`deploy/helm/mirage` provides templated values for development, shadow,
controlled pilot, and production.  Dangerous combinations such as
`production + execution enabled + no pilot scope` are rejected by schema and
template validation.  `deploy/iac/terraform` contains provider-neutral
examples for network, database, broker, identity, and object storage
dependencies.

## SLOs and Alerts

Initial SLIs cover API availability, event-ingestion success, broker lag, Twin
freshness, recommendation latency, execution-state durability, rollback
success, audit-write success, backup success, and model-inference
availability.  Alerts route to SOC or platform operations for ingestion stop,
broker lag, Twin freshness, audit outage, database replication issue, repeated
verification timeouts, rollback failure, unexpected enforcement, policy hash
mismatch, critical drift, Cyber Range isolation failure, and protected-asset
action attempts.

## Limitations

Production-ready architecture does not imply proven protection against all
attacks.  ML and MARL policies remain governed.  Low-risk automation is
explicitly scoped.  High-risk actions remain recommendation-only.  Incomplete
Twin data reduces safe automation.  Formal verification covers only modeled
properties.  Controlled deployment must expand gradually using measured
evidence.

## Recommended Milestone 11

Milestone 11 should focus on measured production-scale validation: external
PostgreSQL and broker integration tests, signed artifact verification against
real key management, load testing at larger event rates, deeper SOC vendor
adapters, and independent security review.
