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
