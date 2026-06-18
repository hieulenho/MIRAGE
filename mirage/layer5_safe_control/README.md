# Layer 5 — Safe Control (Provable Safety)

## Mục đích
Đảm bảo mọi action của Layer 4 đều an toàn trước khi thực thi — không làm gián đoạn luồng business.

## Trạng thái hiện tại
- `v1`: Human-in-the-loop approval cho high-risk actions

## Roadmap → v2
- [ ] `formal_verifier.py` — Formal methods / model checking (TLA+, Dafny wrapper)
- [ ] `microsegmentation.py` — Kernel/Hypervisor-level process isolation tự động

## Input / Output Interface
- **Input**: `DefenderAction` từ Layer 4
- **Output**: `SafeAction` (approved với formal proof) hoặc `BLOCKED` (với lý do)

## Files
| File | Mô tả |
|---|---|
| `safe_control.py` | Safety constraints checker, escalation logic |
| `formal_verifier.py` | [NEW] Provable safety verification engine |
| `microsegmentation.py` | [NEW] Automated network microsegmentation |

## Dependencies
```
# hiện tại: không có external deps đặc biệt
# v2: z3-solver, ebpf (Linux), Hyper-V API (Windows)
```

## Milestone 4 Safety Gate V1

Milestone 4 adds a separate production-oriented lab execution path in
`mirage.execution`. The original `safe_control.py` remains for static
research-simulator compatibility.

```text
CandidateDefenseAction + ActionMask
  -> SafetyPolicyEngine / SafetyGate
  -> ExecutionPlan
  -> DeceptionOrchestrator
  -> mock/lab adapter prepare
  -> canary
  -> execute
  -> verify
  -> commit or rollback
  -> append-only audit + Digital Twin update
```

Execution states:

```text
PROPOSED -> VALIDATED -> AWAITING_APPROVAL -> PREPARED
  -> CANARY_RUNNING -> EXECUTING -> VERIFYING -> SUCCEEDED -> EXPIRED

FAILED -> ROLLING_BACK -> ROLLED_BACK
CANCELLED / DENIED
```

Milestone 4 adapters are mock/lab-only:

- `DockerDecoyAdapter`
- `MockFirewallAdapter`
- `MockEDRAdapter`
- `MockIAMAdapter`
- `MockDNSAdapter`
- `MockTelemetryAdapter`
- `MockTicketAdapter`

They never call real production infrastructure. High-risk containment remains
denied or approval-gated, canary failures roll back automatically, TTL expiry
triggers rollback, and audit output is sanitized.
