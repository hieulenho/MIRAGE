# MIRAGE Docker Lab

Milestone 4 uses this lab only as an isolated synthetic environment. The
Python execution adapters in `mirage.execution` remain mock/lab adapters and do
not call real Docker, firewall, EDR, IAM, DNS, cloud, or production systems.

## Services

- `mirage-control-plane`
- `attacker-simulator`
- `workstation`
- `application-server`
- `real-database`
- `decoy-database-template`
- `fake-smb-template`
- `mock-firewall`
- `mock-dns`
- `telemetry-collector`

All containers use synthetic data only, no privileged mode, no hard-coded
secrets, and small resource limits. The `mirage-decoy` network is separate from
`mirage-protected`, so decoy templates cannot reach protected services by
default.

## Commands

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml ps
docker compose -f lab/docker-compose.yml down -v
```

Suggested scenario:

1. Replay `examples/events/analysis_lateral_critical_db.jsonl`.
2. Run `python -m mirage analyze-paths`.
3. Pick the recommended `deploy_decoy_database` candidate.
4. Run `python -m mirage safety-check`.
5. Run `python -m mirage execute-plan --lab`.
6. Verify audit JSONL and execution state.
7. Roll back manually or wait for TTL expiry in tests.
