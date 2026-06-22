# Milestone 9: Formal Safety Verification, Policy Governance, and Controlled Pilot V1

Milestone 9 adds a governed control plane between MIRAGE recommendations and
any controlled pilot action.  It does not enable broad autonomous production
response.  Pilot execution remains disabled by default, high-risk automation is
disabled, and every controlled-pilot action must be reversible, scoped,
audited, and formally verified against bounded invariants.

```text
Recommendation
-> Action Mask + Safety Gate
-> Formal Safety Verification
-> Policy-as-Code + Release Gate
-> Approval when required
-> Controlled Pilot Plan
-> Canary + Runtime Monitor
-> Commit, Hold, or Rollback
-> Governance Audit Report
```

## Boundaries

Allowed pilot action families are low-risk observation, bounded telemetry,
synthetic honey credentials, isolated decoys, fake DNS in a managed lab or
pilot zone, limited packet capture, temporary throttling on allowlisted
non-critical flows, and SOC ticket updates. Higher-risk actions remain
recommendation-only unless future milestones add separately approved controls.

Default configuration:

```yaml
pilot:
  operating_mode: controlled_pilot
  pilot_execution_enabled: false
  high_risk_automation_enabled: false
  human_approval_required_for_medium_and_high_risk: true
verification:
  formal_verification_required: true
```

Startup validation fails safely if pilot execution is enabled without explicit
pilot scopes, formal verification, rollback channels, audit path, and approval
configuration.

## Components

- `mirage.verification.schema`: `SafetyInvariant`,
  `FormalVerificationContext`, `VerificationFinding`,
  `FormalVerificationReport`, `BlastRadiusEstimate`, and solver result models.
- `mirage.verification.invariants`: configurable default catalog of 15 safety
  invariants.
- `mirage.verification.solver`: replaceable bounded solver interface.  The
  built-in deterministic backend returns `UNKNOWN` on timeout.
- `mirage.verification.reachability`: copied graph reachability checks for
  management channels, rollback channels, and decoy isolation.
- `mirage.verification.blast_radius`: conservative dependency-aware blast
  radius estimates.
- `mirage.verification.rollback`: rollback readiness verification.
- `mirage.verification.temporal`: explicit state-machine lifecycle checks.
- `mirage.governance`: artifact registry, model/policy cards, release gate,
  policy-as-code, integrity hashes, and hash-chained governance audit.
- `mirage.pilot`: pilot scope registry, controlled-pilot controller, canary
  decision controller, runtime safety monitor, rollout levels, and scenarios.
- `mirage.drift`: data, model, and policy drift monitor.

## Invariant Catalog

The default catalog includes:

1. Protected assets cannot be automatically modified.
2. Management and rollback channels remain reachable.
3. Decoys cannot initiate communication to protected production assets.
4. Blast radius remains bounded.
5. Medium and high-risk actions require rollback.
6. Action remains inside enabled pilot scope.
7. Masked actions are never executable.
8. Required approval cannot be bypassed.
9. Kill switch blocks new execution.
10. Twin quality constrains automation.
11. TTL is mandatory for temporary actions.
12. Evidence and decision provenance are complete.
13. Unknown dependencies force approval or rejection.
14. Business health gates drive rollback.
15. Model uncertainty and OOD restrict disruptive actions.

Formal verification covers only bounded, explicitly modeled properties.
Incomplete Twin data can produce `UNKNOWN` or inconclusive verification.
Absence of a discovered violation is not automatically proof of complete
system safety.

## CLI

```bash
python -m mirage verify invariants
python -m mirage verify plan --plan artifacts/execution_plan.json --twin artifacts/twin_snapshot.json
python -m mirage verify audit-chain --audit artifacts/governance_audit.jsonl

python -m mirage governance artifacts
python -m mirage governance model-card --artifact-id POLICY_ID
python -m mirage governance policy-card --artifact-id POLICY_ID
python -m mirage governance release-check --artifact-id POLICY_ID --target-status PILOT_CANDIDATE

python -m mirage pilot scopes
python -m mirage pilot prepare --recommendation-id REC_ID
python -m mirage pilot canary --execution-id EXEC_ID
python -m mirage pilot monitor --execution-id EXEC_ID
python -m mirage pilot rollback --execution-id EXEC_ID --reason "operator requested"
```

## API

```text
GET  /api/v1/governance/artifacts
GET  /api/v1/governance/artifacts/{id}
GET  /api/v1/governance/artifacts/{id}/model-card
GET  /api/v1/governance/artifacts/{id}/policy-card
POST /api/v1/governance/artifacts/{id}/release-check
POST /api/v1/governance/artifacts/{id}/approve
POST /api/v1/governance/artifacts/{id}/suspend

POST /api/v1/verification/plans
GET  /api/v1/verification/reports/{id}
GET  /api/v1/verification/invariants
POST /api/v1/verification/invariants/validate

GET  /api/v1/pilot/scopes
POST /api/v1/pilot/prepare
POST /api/v1/pilot/executions/{id}/approve
POST /api/v1/pilot/executions/{id}/canary
POST /api/v1/pilot/executions/{id}/monitor
POST /api/v1/pilot/executions/{id}/rollback
GET  /api/v1/pilot/executions/{id}
GET  /api/v1/pilot/executions

GET  /api/v1/drift/status
GET  /api/v1/drift/reports
GET  /api/v1/governance/audit
GET  /api/v1/governance/audit/verify
```

## Limitations

- The built-in solver is deterministic and bounded; z3 can be integrated later
  behind the existing solver interface.
- Verification reports are only as complete as the modeled Twin, dependency,
  policy, and approval facts.
- Runtime monitors evaluate supplied health evidence; they do not claim
  complete production observability.
- MARL policies remain governed and cannot override masks, Safety Gate,
  formal verification, pilot scope, approval, or kill switch.
- Medium and high-risk production automation remains restricted.

## Recommended Milestone 10

Milestone 10 should add durable multi-tenant governance storage, optional
digital signatures, richer dependency discovery, a replaceable z3-backed
solver package, and a human review workflow for pilot evidence. It should not
weaken the Milestone 9 mask, Safety Gate, verification, approval, or audit
requirements.
