# Layer 6 — Digital Twin / CASM (Continuous Attack Surface Management)

## Mục đích
Duy trì một bản sao số (digital twin) chính xác và liên tục cập nhật của toàn bộ hạ tầng IT/OT/Cloud.

## Trạng thái hiện tại
- `v1`: Static topology JSON + manual graph build + offline evaluation

## Roadmap → v2
- [ ] `casm_scanner.py` — Auto scan hạ tầng (nmap, cloud API, AD enumeration)
- [ ] `twin_builder.py` — Real-time digital twin builder từ scan results
- [ ] `asset_discovery.py` — Tự động phát hiện IT/OT/Cloud assets mới

## Input / Output Interface
- **Input**: Network scans, Cloud APIs (AWS/Azure/GCP), AD/LDAP
- **Output**: `LiveGraphState` → cung cấp cho tất cả các layer

## Files
| File | Mô tả |
|---|---|
| `evaluation.py` | Benchmark, simulation runner, metrics |
| `casm_scanner.py` | [NEW] Continuous attack surface scanner |
| `twin_builder.py` | [NEW] Real-time digital twin builder |
| `asset_discovery.py` | [NEW] Auto asset discovery engine |

## Dependencies
```
matplotlib, pandas
# v2: python-nmap, boto3, azure-sdk, ldap3
```
