# Layer 1 — Contextual AI (Threat Detection)

## Mục đích
Phát hiện và phân loại giai đoạn tấn công từ luồng log/command-line theo chuỗi thời gian thực.

## Trạng thái hiện tại
- `v1` (Rule-based): HMM + static MITRE ATT&CK rule mapping

## Roadmap → v2
- [ ] `sequence_model.py` — RNN/Transformer phân tích chuỗi lệnh theo context
- [ ] `threat_intel.py` — connector tới MISP / OpenCTI / VirusTotal

## Input / Output Interface
- **Input**: Raw log stream, command-line events, network flows
- **Output**: `ThreatObservation(stage, confidence, ioc_list)`

## Files
| File | Mô tả |
|---|---|
| `attack_modeling.py` | Feature extraction từ raw log |
| `hmm_classifier.py` | HMM-based attack stage classifier |
| `mitre_mapper.py` | Mapping sang MITRE ATT&CK tactics/techniques |
| `sequence_model.py` | [NEW] Deep sequence model |
| `threat_intel.py` | [NEW] Threat Intelligence integration |

## Dependencies
```
hmmlearn, scikit-learn
# v2: torch, transformers
```
