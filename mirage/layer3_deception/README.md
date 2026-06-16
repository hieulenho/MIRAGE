# Layer 3 — Deception (Hyper-Realism GenAI)

## Mục đích
Tạo và quản lý mạng lưới mồi nhử (honeypots/decoys) có độ thực tế cao để dẫn dụ kẻ tấn công.

## Trạng thái hiện tại
- `v1`: Static decoy placement (chỉ cấu hình node rỗng)

## Roadmap → v2
- [ ] `genai_content.py` — GenAI sinh email giả, file rác, log access có nội dung hợp lý
- [ ] `traffic_simulator.py` — Fake network traffic để decoy trông "sống"
- [ ] `fingerprint_evasion.py` — Kỹ thuật chống fingerprinting (OS/service masquerading)

## Input / Output Interface
- **Input**: `GraphState` từ Layer 2, defender budget
- **Output**: `DeceptionPlan(decoy_placements, fake_content_schedule)`

## Files
| File | Mô tả |
|---|---|
| `deception_fabric.py` | Core deception engine, honeytoken placement |
| `genai_content.py` | [NEW] LLM-powered fake content generator |
| `traffic_simulator.py` | [NEW] Background traffic simulator |
| `fingerprint_evasion.py` | [NEW] Anti-fingerprinting module |

## Dependencies
```
# hiện tại: không có external deps đặc biệt
# v2: openai / anthropic SDK, scapy
```
