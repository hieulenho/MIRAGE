# MIRAGE — Multi-stage Intelligent Robust Adaptive Graph-based Engagement

<div align="center">

```
╔═══════════════════════════════════════════════════════════════════╗
║   ███╗   ███╗██╗██████╗  █████╗  ██████╗ ███████╗               ║
║   ████╗ ████║██║██╔══██╗██╔══██╗██╔════╝ ██╔════╝               ║
║   ██╔████╔██║██║██████╔╝███████║██║  ███╗█████╗                 ║
║   ██║╚██╔╝██║██║██╔══██╗██╔══██║██║   ██║██╔══╝                 ║
║   ██║ ╚═╝ ██║██║██║  ██║██║  ██║╚██████╔╝███████╗               ║
║   ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝               ║
║                                                                   ║
║   Multi-stage Intelligent Robust Adaptive Graph-based Engagement  ║
║   Version 2.0 — Production-oriented Research Platform             ║
╚═══════════════════════════════════════════════════════════════════╝
```

**Hệ thống Phòng thủ Chủ động (Active Defense) dựa trên AI, Game Theory và POMDP**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0.0-orange)
![Framework](https://img.shields.io/badge/Framework-Production--oriented-purple)

</div>

---

## 📋 Mục lục

- [Giới thiệu](#-giới-thiệu)
- [Kiến trúc hệ thống](#-kiến-trúc-hệ-thống-6-lớp)
- [Cấu trúc thư mục](#-cấu-trúc-thư-mục)
- [Yêu cầu hệ thống](#-yêu-cầu-hệ-thống)
- [Cài đặt](#-cài-đặt)
- [Hướng dẫn chạy](#-hướng-dẫn-chạy)
- [Chi tiết từng Layer](#-chi-tiết-từng-layer)
- [Kết quả Benchmark](#-kết-quả-benchmark)
- [Cơ sở lý thuyết](#-cơ-sở-lý-thuyết)
- [Mô hình đồ thị tấn công](#-mô-hình-đồ-thị-tấn-công)

---

## 🎯 Giới thiệu

**MIRAGE** là một framework nghiên cứu mô phỏng hệ thống **Phòng thủ Chủ động (Active Defense)** cho mạng doanh nghiệp. Thay vì chỉ phát hiện và chặn tấn công thụ động, MIRAGE sử dụng AI để **chủ động đánh lừa** kẻ tấn công bằng cách triển khai các tài sản mồi (decoys), honey credentials và bẫy kỹ thuật số.

### Điểm nổi bật

| Tính năng | Mô tả |
|-----------|-------|
| 🎭 **Deception-first** | AI tự động triển khai Fake Database, Router giả, Honey Credential |
| 🔐 **Robust Decision Making** | So sánh `expected`, `pure_pessimistic`, `cost_aware_robust` |
| 🧠 **POMDP-based** | Mô hình trạng thái tin tưởng (belief state) về vị trí kẻ tấn công |
| 🛡️ **Safety Gate** | Kiểm soát 7 tầng bảo vệ trước khi thực thi bất kỳ hành động nào |
| 📊 **Multi-attacker Benchmark** | Đánh giá 6 profile, gồm Deception Aware và MITRE Evasion |
| 🔍 **MITRE ATT&CK** | Phân loại giai đoạn tấn công theo framework chuẩn quốc tế |
| 🤖 **Deep RL** | DQN backend với Gymnasium environment, PyTorch tùy chọn và NumPy MLP fallback |
| 📡 **Real-time API** | FastAPI REST/WebSocket ingestion cho Splunk, Elastic và Wazuh |
| 🖥️ **Dashboard** | Attack Graph, belief state, active defenses và decision log thời gian thực |

### Research simulator invariants

- `decoy_sites` là slot tiềm năng; chỉ `active_decoy_sites` mới được tính là decoy outcome.
- Action `deploy_decoy_*` chỉ được target decoy slot, không biến tài sản thật thành decoy.
- Clean no-defense graph không có transition đi vào decoy slot.
- Portfolio rỗng tạo đúng cùng runtime graph và kết quả với no-defense.
- Reward intervention chỉ đổi bait reward; edge-cost action mới được đổi transition probability.
- Simulation và exact MDP solver luôn nhận cùng runtime graph đã áp portfolio.
- `standard_rl` và `robust_mirage` dùng cùng engine, catalog, budget và composite cost model.
- Optimizer chạy offline/background; online path dùng `PolicyCache` để lookup rồi qua safety gate trước khi deploy.

---

## 🏗️ Kiến trúc hệ thống 6 lớp

```
┌─────────────────────────────────────────────────────────────────┐
│                         MIRAGE System                          │
├─────────────────────────────────────────────────────────────────┤
│  Layer 1: Multi-Stage Attack Modeling                          │
│           Phân loại giai đoạn tấn công theo MITRE ATT&CK       │
│           [Recon → Initial Access → Discovery → Lateral Move   │
│            → Credential Access → Collection → Exfiltration]    │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2: Enterprise Attack Graph / POMDP Core                 │
│           Đồ thị tấn công 15 node + Belief State Update        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3: Deception Fabric                                     │
│           Triển khai Fake DB, Fake Router, Honey Credentials   │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4: Robust Decision Engine                               │
│           Tối ưu Pessimistic Defender Value (Game Theory)      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5: Safe Response & Real-Time Control                    │
│           Safety Gate 7 guardrails + Audit Log + Fail-Safe     │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6: Evaluation, Digital Twin & Benchmark                 │
│           So sánh 6 phương pháp phòng thủ + Ablation Study     │
└─────────────────────────────────────────────────────────────────┘
```

### Luồng hoạt động (Data Flow)

```
Telemetry Events
      │
      ▼
[Layer 1] Attack Stage Classifier
      │  stage_context (stage, confidence)
      ▼
[Layer 2] Attack Graph + Belief Update
      │  belief_state {node: probability}
      ▼
[Layer 3] Deception Fabric
      │  available_actions[]
      ▼
[Layer 4] Robust Decision Engine ──────► [Layer 5] Safety Gate
      │                                        │
      │  ActionPlan (if safe)                  │ BLOCKED / ALLOWED
      ▼                                        ▼
   Deploy Action                         Audit Log (.jsonl)
      │
      ▼
[Layer 6] Evaluation & Monitoring
```

---

## 📁 Cấu trúc thư mục

```
MIRAGE/
│
├── run_mirage.py                   # Entry point chính — chạy mọi mode
├── test_agents.py                  # Test nhanh attacker agents
├── config.json                     # Topology, budget, reward/cost và API config
├── requirements.txt                # Thư viện phụ thuộc
├── requirements-dev.txt            # Pytest, Ruff và công cụ phát triển
├── tests/                          # Unit/integration tests cho các layer
├── .gitignore
│
└── mirage/                         # Package chính
    ├── __init__.py                 # Package metadata (v2.0.0)
    ├── config.py                   # Configuration loader trung tâm
    ├── dashboard/                  # Web dashboard (index.html, app.js, style.css)
    │
    ├── layer1_contextual_ai/       # Layer 1: Attack modeling & HMM classifier
    │   ├── attack_modeling.py      # Phân loại giai đoạn tấn công (8 stages)
    │   └── hmm_classifier.py      # HMM + Ensemble telemetry classifier
    │
    ├── layer2_graph_engine/        # Layer 2: Attack Graph & MDP core
    │   ├── attack_graph.py         # Đồ thị tấn công POMDP 15 node
    │   ├── graph_parser.py         # Parser MIRAGE/BloodHound/Nmap JSON
    │   └── mdp_solver.py           # Exact MDP math và scaling utilities
    │
    ├── layer3_deception/           # Layer 3: Deception Fabric
    │   └── deception_fabric.py     # Fake DB, Router, Honey Credential
    │
    ├── layer4_decision/            # Layer 4: Decision Engine & RL
    │   ├── decision_engine.py      # Robust Decision Engine
    │   ├── rl_agent.py             # Deep Q-Network + Gymnasium environment
    │   └── policy_cache.py         # Cache policy cho đường xử lý online
    │
    ├── layer5_safe_control/        # Layer 5: Safety Gate
    │   └── safe_control.py         # 7 guardrails + audit log + fail-safe
    │
    ├── layer6_twin/                # Layer 6: Evaluation & Benchmark
    │   └── evaluation.py           # So sánh 6 phương pháp + Ablation Study
    │
    ├── api/                        # FastAPI REST/WebSocket server
    │   └── server.py               # Orchestration, ingestion, dashboard serve
    │
    └── shared/                     # Shared utilities
        ├── attacker_agents.py      # Mô phỏng 6 loại kẻ tấn công
        └── models/
            ├── mdp_model.py        # Portable AttackGraphMDP model
            └── robust_reward.py    # Bounded reward allocation solver
```

---

## ⚙️ Yêu cầu hệ thống

- **Python**: 3.10 hoặc mới hơn
- **OS**: Windows / Linux / macOS
- **RAM**: Tối thiểu 4 GB (khuyến nghị 8 GB cho benchmark đầy đủ)

### Thư viện phụ thuộc

| Thư viện | Phiên bản | Mục đích |
|----------|-----------|---------|
| `numpy` | ≥ 1.24.0 | Tính toán ma trận, xác suất |
| `matplotlib` | ≥ 3.7.0 | Vẽ biểu đồ kết quả benchmark |
| `gymnasium` | ≥ 1.0.0 | Chuẩn environment cho Deep RL |
| `fastapi`, `pydantic` | phiên bản trong `requirements.txt` | API schema và ingestion |
| `uvicorn` | ≥ 0.30.0 | ASGI production server |

---

## 🚀 Cài đặt

### 1. Clone repository

```bash
git clone https://github.com/<your-username>/MIRAGE.git
cd MIRAGE
```

### 2. (Khuyến nghị) Tạo môi trường ảo

```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### 3. Cài đặt thư viện

```bash
pip install -r requirements.txt
```

Để phát triển và chạy test:

```bash
pip install -r requirements-dev.txt
python -m pytest -q
```

---

## ▶️ Hướng dẫn chạy

Tất cả chế độ được chạy qua file `run_mirage.py`:

```bash
python run_mirage.py [--mode <mode>]
```

### Các chế độ chạy

| Lệnh | Mô tả | Thời gian ước tính |
|------|-------|-------------------|
| `python run_mirage.py` | Demo đầy đủ end-to-end (mặc định) | ~30 giây |
| `python run_mirage.py --mode demo` | Giống lệnh trên | ~30 giây |
| `python run_mirage.py --mode step1` | Bước 1: Khung xương MVP (Layer 2+4) | ~5 giây |
| `python run_mirage.py --mode step2` | Bước 2: Đắp thịt (Layer 3+6+Attackers) | ~15 giây |
| `python run_mirage.py --mode step3` | Bước 3: Gắn mắt phanh (Layer 1+5) | ~5 giây |
| `python run_mirage.py --mode benchmark` | Benchmark đầy đủ 6 phương pháp | ~2-3 phút |
| `python run_mirage.py --mode benchmark_a` | Benchmark A: attacker bắt đầu từ Internet/Entry Point | ~1-2 phút |
| `python run_mirage.py --mode benchmark_b` | Benchmark B: belief-conditioned response, attacker đã ở giữa mạng | ~1-2 phút |
| `python run_mirage.py --mode multi_seed` | Benchmark A+B qua nhiều seed để lấy mean/std và confidence interval | ~20-40 phút |
| `python run_mirage.py --mode scaling` | Scaling benchmark trên synthetic graph 100/500/1000 node | ~3-10 phút |
| `python run_mirage.py --mode train_rl --episodes 200` | Train DQN và lưu `models/mirage_dqn.npz` | phụ thuộc số episode |
| `python run_mirage.py --mode ablation` | Ablation study phân tích đóng góp từng component | ~1 phút |
| `python run_mirage.py --mode graph` | Hiển thị thông tin đồ thị tấn công | < 1 giây |

> Thời gian chạy là ước tính trên máy phát triển thông thường. Các mode `multi_seed` và `scaling` có thể lâu hơn nếu CPU chậm hoặc số episode/candidate được tăng lên.

### Giai đoạn 3: Deep RL, API và Dashboard

Train model DQN:

```bash
python run_mirage.py --mode train_rl --episodes 200
```

Khởi động API:

```bash
python -m mirage.api.server
```

ASGI command một process:

```bash
uvicorn mirage.api.server:create_app --factory --host 0.0.0.0 --port 8000
```

State telemetry, decision và WebSocket hiện được giữ trong memory của process.
Không chạy nhiều worker nếu chưa bổ sung Redis/database làm shared state. Khi
public ra Internet, đặt API sau TLS reverse proxy và cơ chế authentication/RBAC
thay vì chỉ dựa vào một static API key.

Sau đó mở:

- Dashboard: `http://localhost:8000/dashboard`
- OpenAPI: `http://localhost:8000/docs`
- Health check: `http://localhost:8000/healthz`

Các endpoint ingestion chính:

```text
POST /api/telemetry
POST /api/telemetry/batch
POST /api/ingest/splunk
POST /api/ingest/elastic
POST /api/ingest/wazuh
POST /api/decisions/{decision_id}/approve
WS   /ws
```

`POST /api/decide` hỗ trợ `backend: "robust"` hoặc `backend: "rl"`. Mọi
portfolio đều đi qua Safety Gate; action cần human approval hoặc bị block sẽ
không được deploy và không bị trừ budget.

Thiết lập biến môi trường `MIRAGE_API_KEY` để yêu cầu header `X-API-Key` cho
các REST endpoint `/api/*`. Dashboard giữ key trong `sessionStorage` và truyền
WebSocket credential qua subprotocol, không đưa secret vào URL.

Nếu dashboard hiện `Disconnected`, graph trống và `/api/graph` trả `401`:

1. Cài lại dependency để có WebSocket backend: `pip install -r requirements.txt`.
2. Nếu không cần API key, xóa biến trước khi chạy:
   `$env:MIRAGE_API_KEY = $null`.
3. Nếu dùng API key, nhập cùng giá trị vào ô `API key` ở thanh dưới dashboard
   rồi nhấn `Apply key`.
4. Khởi động lại server và hard-refresh trình duyệt bằng `Ctrl+F5`.

### Configuration

MIRAGE đọc `config.json` qua `mirage/config.py`. Có thể trỏ sang file khác:

```bash
set MIRAGE_CONFIG=C:\path\to\config.json
```

Để dùng topology import thay vì graph 15 node:

```json
{
  "topology": {
    "source": "file",
    "path": "examples/enterprise_topology.json",
    "format": "mirage"
  }
}
```

Các mode `demo`, `step1`, `step2`, `step3`, benchmark, ablation, graph, API và
train RL đều dùng topology đã cấu hình. Các giới hạn production quan trọng:

```json
{
  "layer1": {
    "event_history_limit": 1000,
    "max_tracked_hosts": 10000
  },
  "rl": {
    "backend": "numpy"
  },
  "api": {
    "max_batch_size": 1000,
    "max_request_bytes": 2097152,
    "decision_history_limit": 1000,
    "pending_decision_limit": 100
  }
}
```

`rl.backend` nhận `numpy`, `torch` hoặc `auto`. Model lưu kèm signature của
graph và action catalog; sau thay đổi topology/catalog cần train lại model.

### Ví dụ output — `--mode step2`

```
[Layer 3] Triển khai Deception Fabric...
  [🪤 Deception] Fake Database deployed at Node 11 (DB_FAKE_Backup) | Reward bait: +0.9
  [🪤 Deception] Fake Router deployed at Node 12 (Router_FAKE_Gateway) | Edge cost +0.3
  [🍯 Honey] Honey Credential planted at Node 4 (Workstation_Finance) | Trigger reward: +0.5
  → 3 deception actions deployed (budget remaining: 0.12/6.00)

[Attackers] Simulating 6 attacker types (100 episodes each)...
  random              : Hit True Goal=18.0%  |  Decoy Hit=21.0%  |  Avg Steps=3.6
  greedy              : Hit True Goal=47.0%  |  Decoy Hit=53.0%  |  Avg Steps=4.9
  shortest_path       : Hit True Goal=87.0%  |  Decoy Hit=13.0%  |  Avg Steps=4.9
  stealthy            : Hit True Goal=50.0%  |  Decoy Hit=41.0%  |  Avg Steps=4.7
  deception_aware     : Hit True Goal=62.0%  |  Decoy Hit=38.0%  |  Avg Steps=5.0
  mitre_evasion       : Hit True Goal=62.0%  |  Decoy Hit=37.0%  |  Avg Steps=4.8

Quick Comparison (3 methods):
  Method                    |   Intercept% |     Pess.Val
  no_defense                |        0.0% |     -1.9695
  static_honeypot           |       29.7% |     -1.4275
  robust_mirage             |       28.0% |     -1.4275 ← MIRAGE
```

### Output files (thư mục `results/`)

| File | Nội dung |
|------|----------|
| `mirage_benchmark.png` | Biểu đồ so sánh 6 phương pháp phòng thủ |
| `mirage_benchmark_results.json` | Kết quả benchmark dạng JSON |
| `benchmark_a_results.json` | Kết quả Benchmark A: entry-point attack |
| `benchmark_b_results.json` | Kết quả Benchmark B: belief-conditioned response |
| `multi_seed_benchmark_a_results.json` | Kết quả multi-seed cho Benchmark A |
| `multi_seed_benchmark_b_results.json` | Kết quả multi-seed cho Benchmark B |
| `scaling_benchmark_results.json` | Kết quả scaling benchmark trên graph 100/500/1000 node |
| `mirage_audit_log.jsonl` | Nhật ký kiểm toán (audit log) từ Safety Gate |

---

## 🔬 Chi tiết từng Layer

### Layer 1 — Multi-Stage Attack Modeling (`layer1_contextual_ai/attack_modeling.py`, `layer1_contextual_ai/hmm_classifier.py`)

Kết hợp classifier rule-based với **Hidden Markov Model** theo chuỗi thời gian.
Ensemble mặc định dùng trọng số HMM `0.6`, cấu hình tại `layer1.hmm_weight`.

**8 giai đoạn tấn công được hỗ trợ:**

| Stage ID | Tên | MITRE Tactic |
|----------|-----|-------------|
| 0 | Unknown | — |
| 1 | Recon | TA0043 - Reconnaissance |
| 2 | Initial Access | TA0001 - Initial Access |
| 3 | Discovery | TA0007 - Discovery |
| 4 | Lateral Movement | TA0008 - Lateral Movement |
| 5 | Credential Access | TA0006 - Credential Access |
| 6 | Collection | TA0009 - Collection |
| 7 | Exfiltration | TA0010 - Exfiltration |

**Các loại telemetry event được xử lý:**

- `port_scan` — Quét cổng
- `login_attempt` — Đăng nhập (thất bại/thành công)
- `smb_connect` — Kết nối SMB FileShare
- `rdp_connect` — Kết nối Remote Desktop
- `dns_query` — Truy vấn DNS nội bộ
- `file_access` — Truy cập tệp
- `data_transfer` — Truyền dữ liệu
- `credential_use` — Sử dụng thông tin xác thực
- `honey_credential_use` — Sử dụng honey credential (tín hiệu nguy hiểm cao!)
- `decoy_touch` — Chạm vào decoy asset

**3 kịch bản telemetry giả lập có sẵn:**

```python
from mirage.layer1_attack_modeling import simulate_attack_telemetry

events = simulate_attack_telemetry("lateral_movement")  # Kẻ tấn công đang di chuyển ngang
events = simulate_attack_telemetry("exfiltration")      # Kẻ tấn công đang đánh cắp dữ liệu
events = simulate_attack_telemetry("honey_trap")        # Kẻ tấn công dính bẫy honey credential
```

---

### Layer 2 — Enterprise Attack Graph / POMDP (`layer2_graph_engine/attack_graph.py`)

Mô hình mạng doanh nghiệp **15 node** dưới dạng **Markov Decision Process (MDP)**.

**Cấu trúc mạng:**

```
[INTERNET] (Node 0)
    │
    ├── [WEB DMZ] (Node 1)          ─── expose_web, smb_move, rdp_move
    └── [MAIL DMZ] (Node 2)         ─── phish_email, smb_move, rdp_move
              │
    ┌─────────┼──────────┐
    │         │          │
[WS_Eng]  [WS_Fin]   [WS_IT]       ← Workstations (Nodes 3,4,5)
(Node 3)  (Node 4)   (Node 5)
              │
    ┌─────────┴──────────┐
    │                    │
[SMB_Share]         [DNS_Internal]  ← Internal Services (Nodes 6,7)
 (Node 6)            (Node 7)
    │
    ├── [Admin_Credential] (Node 8)  ← Value: 0.7
    └── [ServiceAcct_Cred] (Node 9)  ← Value: 0.5
              │
    ┌─────────┼──────────┐
    │         │          │
[DB_REAL] [DB_FAKE]  [RTR_FAKE]    ← Data Layer (Nodes 10,11,12)
(🎯GOAL)  (🪤DECOY)  (🪤DECOY)
    │
[DomainController] (Node 13)        ← Critical Asset (Value: 0.9)
    │
  [SINK] (Node 14)
```

**3 đường tấn công rủi ro cao:**
1. `Internet → WebServer → WS_Finance → ServiceAcct_Cred → DB_REAL`
2. `Internet → MailServer → WS_Eng → Admin_Cred → DomainController → DB_REAL`
3. `Internet → WebServer → SMB_FileShare → ServiceAcct_Cred → DB_REAL`

**Belief State (POMDP):**

Hệ thống duy trì phân phối xác suất về vị trí của kẻ tấn công và cập nhật theo Bayes:

```
b'(s) ∝ P(obs | s) × b(s)
```

---

### Layer 3 — Deception Fabric (`layer3_deception/deception_fabric.py`)

Triển khai và quản lý các tài sản mồi (deception assets).

**4 loại hành động đánh lừa:**

| Action Type | Mô tả | Chi phí | Reward Bait |
|-------------|-------|---------|-------------|
| `deploy_decoy_database` | Triển khai database giả hấp dẫn | 1.5 | +0.9 |
| `deploy_decoy_router` | Triển khai router giả, tăng edge cost | 1.2 | +0.7 |
| `scatter_honey_credential` | Rải thông tin xác thực giả | 0.8 | +0.5 |
| `increase_edge_cost` | Tăng chi phí di chuyển qua một cạnh cụ thể | 0.5 | N/A |

**Ví dụ sử dụng:**

```python
from mirage.layer2_graph_engine.attack_graph import build_enterprise_attack_graph
from mirage.layer3_deception.deception_fabric import DeceptionFabric, DeceptionActionType

graph = build_enterprise_attack_graph()
fabric = DeceptionFabric(graph)

# Lấy danh sách actions trong ngân sách
actions = fabric.get_available_actions(budget_remaining=5.0)

# Triển khai action
action = next(a for a in actions if a.action_type == DeceptionActionType.DEPLOY_DECOY_DATABASE)
decoy = fabric.deploy_action(action)
print(f"Deployed: {decoy.decoy_id}")
```

---

### Layer 4 — Robust Decision Engine (`layer4_decision/decision_engine.py`)

**"Bộ não"** của MIRAGE — chọn hành động tối ưu theo nguyên tắc **Robust Optimization** (tối đa hóa worst-case defender value).

**Workflow tại mỗi bước quyết định:**

1. Nhận `belief_state` từ Layer 2
2. Lấy danh sách `available_actions` từ Layer 3
3. Simulate mỗi action với **6 loại kẻ tấn công**
4. Tính `pessimistic_value = min(defender_values)` ← Robust criterion
5. Sắp xếp theo pessimistic value, chọn action tốt nhất qua Safety Gate

**Output — `ActionPlan`:**

```
══════════════════════════════════════════════════════════════════
🤖 MIRAGE Decision Plan
══════════════════════════════════════════════════════════════════
Action:      deploy_decoy_database
Target:      Node 11 — DB_FAKE_Backup
─────────────────────────────────────────────────────────────────
Opt. Value:  +0.3500  (Best case for defender)
Pess. Value: -0.2000  (Worst case — ROBUST target)
Exp. Value:  +0.1200  (Average case)
─────────────────────────────────────────────────────────────────
Risk:        0.10 / 1.0
Confidence:  85.0%
Approval:    ✅ Auto-approved
```

---

### Layer 5 — Safety Gate (`layer5_safe_control/safe_control.py`)

**7 guardrails bắt buộc** kiểm tra trước khi bất kỳ hành động nào được thực thi:

| # | Guardrail | Hành động khi vi phạm |
|---|-----------|----------------------|
| 1 | **Fail-Safe Mode** | Block tất cả, chỉ quan sát |
| 2 | **Forbidden Actions** | Block ngay (hack_back, isolate_production_db...) |
| 3 | **Budget Limit** | Block nếu vượt ngân sách cho phép |
| 4 | **Protected Nodes** | Tăng risk level, yêu cầu human approval |
| 5 | **Risk-based Approval** | LOW=auto, MEDIUM=log, HIGH=SOC, CRITICAL=block |
| 6 | **Confidence Threshold** | Block action nguy hiểm nếu độ tin cậy thấp |
| 7 | **Pessimistic Value Sanity** | Cảnh báo nếu worst-case quá tệ |

**Phân cấp rủi ro:**

| Risk Level | Score | Hành động |
|------------|-------|-----------|
| ✅ LOW | 0.0 – 0.2 | Tự động triển khai |
| ⚠️ MEDIUM | 0.2 – 0.5 | Log cảnh báo, cho phép |
| 🔴 HIGH | 0.5 – 0.8 | Yêu cầu SOC analyst xác nhận |
| 🚫 CRITICAL | 0.8 – 1.0 | Block hoàn toàn |

**Protected Nodes (không được tự động can thiệp):**
- `Node 10: DB_REAL_Finance` — Database tài chính thật
- `Node 13: DomainController` — Domain Controller

---

### Layer 6 — Evaluation & Benchmark (`layer6_twin/evaluation.py`)

So sánh hiệu quả của **6 phương pháp phòng thủ**:

| Phương pháp | Mô tả |
|-------------|-------|
| `no_defense` | Không có biện pháp phòng thủ nào |
| `random_deception` | Triển khai deception ngẫu nhiên |
| `static_honeypot` | Honeypot tĩnh truyền thống |
| `greedy_top_k` | Chọn các mục tiêu deception có giá trị cao |
| `standard_rl` | Tối ưu expected value bằng cùng decision engine |
| `robust_mirage` | MIRAGE với Robust Optimization ✅ |

**Metrics đánh giá:**
- `interception_rate` — Tỷ lệ kẻ tấn công bị dẫn vào decoy
- `hit_true_goal_rate` — Tỷ lệ kẻ tấn công đạt được mục tiêu thật
- `pessimistic_value` — Defender value trong worst-case
- `avg_steps_to_terminal` — Số bước trung bình đến trạng thái kết thúc

---

## 🤺 Mô phỏng Kẻ tấn công (`shared/attacker_agents.py`)

6 loại kẻ tấn công với chiến thuật khác nhau:

| Loại | Chiến thuật | Đặc điểm |
|------|-------------|----------|
| `random` | Ngẫu nhiên hoàn toàn | Baseline, không biết topology |
| `greedy` | Chọn action có reward cao nhất ngay lập tức | Tham lam, dễ bị bẫy decoy reward |
| `shortest_path` | Đi đường ngắn nhất đến true goal | Nguy hiểm nhất với defense truyền thống |
| `stealthy` | Né tránh các node có nhiều traffic | Khó phát hiện, tốn nhiều bước |
| `deception_aware` | Đánh giá realism và dấu hiệu giả mạo | Chủ động né deception dễ nhận biết |
| `mitre_evasion` | Kết hợp kỹ thuật MITRE ATT&CK evasion | Thích nghi với telemetry và bẫy đang hoạt động |

---

## 📊 Kết quả Benchmark

Benchmark A, seed `42`, 500 episodes/method:

```
Method              Intercept   Hit True Goal   Pess.Val   FP Cost   Total Cost
no_defense              0.0%          84.5%      -1.9696     0.000        0.0
random_deception       28.5%          58.8%      -1.5333     0.068        2.0
static_honeypot        32.3%          56.6%      -1.5333     0.332        4.4
greedy_top_k           28.5%          58.8%      -1.5333     0.408        3.9
standard_rl            37.6%          51.0%      -1.5333     0.399        4.9
robust_mirage          26.7%          60.6%      -1.5333     0.068        2.0
```

Kết quả này được giữ nguyên trung thực: `standard_rl` có interception tốt nhất
trong seed trên; `robust_mirage` chọn portfolio rẻ và false-positive thấp hơn.
Các phương pháp deception cùng bị chặn ở pessimistic value `-1.5333` bởi profile
`shortest_path`, nên chưa thể kết luận MIRAGE thắng tuyệt đối từ một seed.

**Ablation Study (`--mode ablation`, seed `42`, 75 evaluation episodes/variant, 6 attacker profiles):**

```
Variant                  Cost    Pess.Val    Robustness Gap   Portfolio
full_mirage              2.030    -1.2311        0.5456       deploy_decoy_database@node11
no_robust_objective      2.030    -1.2311        0.5456       deploy_decoy_database@node11
no_belief                2.030    -1.2311        0.5456       deploy_decoy_database@node11
no_edge_cost             2.030    -1.2311        0.5456       deploy_decoy_database@node11
no_deception_variety     2.030    -1.2311        0.5456       deploy_decoy_database@node11
no_cost_model            5.220    -1.2186        0.5912       node11 + edge4->9 + edge6->9
no_deception_aware       2.030    -1.2311        0.5456       deploy_decoy_database@node11
```

> Số liệu trên từ lần chạy mới nhất với 6 attacker profiles (thêm `mitre_evasion`). `no_cost_model` mở rộng portfolio sang 3 action vì không bị penalise bởi cost model — đây là hành vi kỳ vọng. Chạy `--mode multi_seed` (3 seeds, 200 eps/method) để lấy mean ± std trước khi dùng cho kết luận nghiên cứu.

---

## 📖 Cơ sở lý thuyết

MIRAGE được xây dựng trên các nền tảng lý thuyết:

### 1. Robust Reward Design (MDP)

Bài toán Robust Reward Design tìm phân phối reward `r` để tối đa hóa **pessimistic defender value** dưới mọi chiến lược của kẻ tấn công:

```
max   min  V_D(π*, r + δ)
 δ    π∈Π

s.t.  ||δ||₁ ≤ B        (budget constraint)
      δ(s,a) ≥ 0         (non-negative modifications)
```

Các module tương thích đã nằm hoàn toàn trong package, không cần repository
solver bên ngoài:

```python
from mirage.layer2_graph_engine.attack_graph import build_enterprise_attack_graph
from mirage.shared.models.mdp_model import AttackGraphMDP
from mirage.shared.models.robust_reward import solve_max_margin_reward_design

graph = build_enterprise_attack_graph()
model = AttackGraphMDP.from_mirage_graph(graph)
result = solve_max_margin_reward_design(model)

print(result.x_ip, result.c_star, result.solver_status)
```

Solver giới hạn budget, timeout và số objective evaluations. Với action space lớn,
trạng thái `HEURISTIC_ENUMERATED` được báo rõ thay vì gắn nhãn MILP-optimal.

### 2. POMDP (Partially Observable MDP)

Defender không biết chính xác vị trí của kẻ tấn công. Thay vào đó, duy trì **belief state** `b(s) = P(attacker at node s | observations)` và cập nhật theo Bayes:

```
b'(s') ∝ Σ_s P(s'|s,a) · b(s) · P(obs|s')
```

### 3. Deception-as-Intervention

Các hành động deception được mô hình hóa như **reward interventions** — thay đổi reward nhận được khi kẻ tấn công thực hiện action tại một node:

```
r'(s, a) = r(s, a) + δ(s, a)
```

Bằng cách tăng reward tại decoy nodes, AI hướng kẻ tấn công vào bẫy.

### 4. Safety via Human-in-the-Loop

Mọi hành động của AI đều qua **Safety Gate** với 7 guardrails. Hành động rủi ro cao bắt buộc có human approval, tránh AI tự ý tác động vào tài sản quan trọng.

---

## 🗺️ Mô hình đồ thị tấn công

Chi tiết topology dựng sẵn của Enterprise Attack Graph v2:

| Node | Tên | Layer | Giá trị | Ghi chú |
|------|-----|-------|---------|---------|
| 0 | Internet/Entry | external | 0.0 | Entry point |
| 1 | WebServer_DMZ | dmz | 0.2 | |
| 2 | MailServer_DMZ | dmz | 0.2 | |
| 3 | Workstation_Eng | internal | 0.3 | |
| 4 | Workstation_Finance | internal | 0.4 | High-value target |
| 5 | Workstation_IT | internal | 0.3 | |
| 6 | SMB_FileShare | services | 0.4 | |
| 7 | DNS_Internal | services | 0.3 | |
| 8 | Admin_Credential | credentials | 0.7 | |
| 9 | ServiceAcct_Credential | credentials | 0.5 | |
| 10 | **DB_REAL_Finance** | data | **1.0** | 🎯 **TRUE GOAL** |
| 11 | DB_FAKE_Backup | data | 0.0 | 🪤 Decoy Slot 1 |
| 12 | Router_FAKE_Gateway | services | 0.0 | 🪤 Decoy Slot 2 |
| 13 | DomainController | critical | 0.9 | Protected |
| 14 | Sink | sink | 0.0 | Terminal state |

---

## 📄 License

Dự án này được phát hành theo giấy phép **MIT License**.

---

## 👥 Tác giả

**MIRAGE Research Team**

> *"The best defense is a good deception."*
---

## Milestone 1: Digital Twin V1 and Canonical Events

MIRAGE now includes the first production-oriented event foundation while
preserving the original static research simulator. The new flow is:

```text
Telemetry JSONL
  -> event normalization
  -> entity resolution
  -> asset and identity registry
  -> Digital Twin state update
  -> current MIRAGE attack graph export
  -> JSON snapshot storage
  -> deterministic replay
```

### What Digital Twin V1 Does

- Defines canonical Pydantic schemas for `SecurityEvent`, `Asset`,
  `Identity`, `Relationship`, and `TwinSnapshot`.
- Streams local JSONL events without loading the full file into memory.
- Supports tolerant and strict ingestion modes.
- Resolves assets and identities deterministically using explicit IDs first,
  then agent/cloud IDs, hostname/domain, IP, and provisional IDs.
- Updates an in-memory twin registry with versioning, duplicate-event
  handling, relationship TTL/expiry, warnings, and JSON snapshots.
- Exports active twin relationships into the existing `MIRAGEAttackGraph`
  representation via `MIRAGEAttackGraph.from_twin_snapshot(snapshot)`.
- Adds FastAPI endpoints under `/api/v1/*` for canonical event ingestion,
  twin status, snapshots, assets, subgraphs, and replay.

### What It Does Not Do Yet

- No Kafka, SIEM, EDR, cloud, Neo4j, Redis, or Kubernetes connectors.
- No production authentication/RBAC for the new twin API beyond any existing
  deployment wrapper. Put the API behind trusted controls before real use.
- No LLM, GNN, contextual-AI upgrade, or MARL implementation in this milestone.
- The twin is in-memory by design; snapshots are JSON files.
- The twin may be incomplete or stale because it only knows what ingested
  events say.

### Canonical JSONL Example

```json
{"event_id":"evt-001","event_time":"2026-06-17T08:00:00Z","ingest_time":"2026-06-17T08:00:01Z","source":"synthetic-edr","event_type":"asset_discovered","asset_id":"asset:host:ws-fin-01","src_ip":"10.10.20.15","confidence":0.98,"attributes":{"hostname":"ws-fin-01","asset_type":"workstation","environment":"finance"}}
```

Supported generic event mappings include `process_start`,
`authentication_success`, `authentication_failure`, `network_connection`,
`dns_query`, `file_access`, `credential_use`, `deception_interaction`,
`asset_discovered`, and `vulnerability_observed`.

### Replay CLI

```bash
python -m mirage replay \
  --events examples/events/sample_attack.jsonl \
  --snapshot-out artifacts/twin_snapshot.json \
  --graph-out artifacts/twin_attack_graph.json
```

Example output:

```text
MIRAGE Digital Twin replay complete
  events processed:          10
  invalid events:            0
  assets created/updated:    6/10
  identities created/updated: 2/2
  relationships created/updated: 10/0
  expired relationships:     0
  final twin version:        10
```

Replay ordering defaults to `(event_time, event_id)` for deterministic output.
Use `--preserve-file-order` when file order is intentional.

### API Examples

Start the API:

```bash
python -m mirage.api_server
```

Ingest one canonical event:

```bash
curl -X POST http://localhost:8000/api/v1/events \
  -H "Content-Type: application/json" \
  -d '{"event_id":"evt-doc-1","event_time":"2026-06-17T08:00:00Z","ingest_time":"2026-06-17T08:00:01Z","source":"docs","event_type":"asset_discovered","asset_id":"asset:host:doc-ws","confidence":0.9,"attributes":{"hostname":"doc-ws","asset_type":"workstation"}}'
```

Example response:

```json
{
  "event_id": "evt-doc-1",
  "event_type": "asset_discovered",
  "duplicate": false,
  "assets_created": ["asset:host:doc-ws"],
  "twin_version": 1
}
```

Check status:

```bash
curl http://localhost:8000/api/v1/twin/status
```

### Configuration

Digital Twin V1 uses the existing `config.json` and `mirage.config` loader:

```json
"twin": {
  "relationship_ttls": {
    "connects_to": 3600,
    "authenticated_to": 86400
  },
  "snapshot_path": "artifacts/twin_snapshot.json",
  "ingestion_strict": false,
  "max_batch_size": 1000,
  "replay_ordering": "event_time",
  "allow_provisional_entities": true,
  "logging_level": "INFO"
}
```

### Migration Notes

- Static topology remains the default path through `build_configured_attack_graph()`.
- Twin-based topology is opt-in through replay/API and graph export.
- Existing Layer 1-6 simulator behavior and benchmarks are not replaced.
- Use the twin graph for event-derived topology; use the static graph for
  reproducible research benchmarks.

### Tests

```bash
python -m pytest -q
python -m ruff check .
python -m compileall -q mirage run_mirage.py tests
node --check mirage/dashboard/app.js
```

Known limitations:

- In-memory API state is not shared across multiple workers.
- Relationship TTL defaults are simple heuristics.
- Entity resolution is deterministic but conservative; ambiguous IP matches
  produce warnings instead of automatic merges.
- Persistent storage, real connectors, stronger auth/RBAC, GNN, contextual AI,
  and MARL are planned for later milestones.

## Milestone 2: Contextual Detection V1

MIRAGE now includes a deterministic, explainable detection and belief layer on
top of canonical `SecurityEvent` ingestion and Digital Twin V1:

```text
SecurityEvent stream
  -> entity timelines
  -> explainable feature extraction
  -> high-precision rules
  -> temporal correlation
  -> probabilistic attack-stage scoring
  -> entity belief and attacker-location distribution
  -> attack graph contextual-risk metadata
  -> CLI and API audit output
```

### What Contextual Detection V1 Does

- Stores multi-entity timelines for assets, identities, credentials,
  communications, sessions, and incidents.
- Extracts named single-event, temporal-window, and simple baseline-deviation
  features without storing full command lines as feature values.
- Evaluates 10 deterministic rules: suspicious script, discovery burst, SMB
  lateral pattern, auth spray, success after failures, identity fan-out,
  credential-to-remote, deception interaction, critical-asset approach, and
  benign admin suppression.
- Correlates local evidence into partial stage progressions such as execution
  -> discovery -> credential access -> lateral movement.
- Estimates attack-stage probabilities over stable stage names from priors,
  weighted evidence, decay, suppression, and soft transition hints.
- Maintains `EntityBelief`, `IncidentBelief`, `BeliefSnapshot`, evidence,
  uncertainty, and an attacker-location distribution that always keeps
  `unknown` probability mass.
- Propagates graph risk only one configurable hop by default, marks propagated
  evidence as inferred, and keeps direct evidence distinguishable.
- Preserves the original research simulator, static attack graph, HMM
  classifier, MDP solver, dashboard, and decision pipeline behavior.

### CLI

```bash
python -m mirage detect \
  --events examples/events/contextual_discovery_lateral.jsonl \
  --belief-out artifacts/belief_snapshot.json \
  --detections-out artifacts/detections.jsonl
```

Example output:

```text
MIRAGE contextual detection replay complete
  events processed:          9
  rule matches:              19
  correlations created:      37
  suspicious entities:       20
  highest compromise:       1.0000
  most likely stage:        lateral_movement
  deception interactions:    0
  invalid events:            0
  final belief version:      51
```

Use `--verbose` to print rule/evidence explanations. The default audit output
does not include raw command lines, passwords, tokens, or raw credentials.

### API

Start the API:

```bash
python -m mirage.api_server
```

Contextual Detection V1 endpoints:

```text
POST /api/v1/detection/events
POST /api/v1/detection/events/batch
GET  /api/v1/detection/entities/{entity_id}
GET  /api/v1/detection/entities/{entity_id}/timeline
GET  /api/v1/detection/entities/{entity_id}/evidence
GET  /api/v1/detection/suspicious
GET  /api/v1/detection/incidents
GET  /api/v1/detection/incidents/{incident_id}
GET  /api/v1/belief/snapshot
POST /api/v1/belief/recompute
```

Example event:

```bash
curl -X POST http://localhost:8000/api/v1/detection/events \
  -H "Content-Type: application/json" \
  -d '{"event_id":"evt-detect-1","event_time":"2026-06-17T10:00:00Z","ingest_time":"2026-06-17T10:00:01Z","source":"docs","event_type":"deception_interaction","asset_id":"asset:decoy:fake-db","user_id":"identity:user:mallory","credential_id":"honey-token","src_ip":"10.10.20.45","dst_ip":"10.10.99.10","confidence":0.99,"attributes":{"hostname":"fake-db","asset_type":"decoy_db","is_decoy":true}}'
```

### Synthetic Scenarios

The repository includes deterministic synthetic JSONL datasets:

- `examples/events/contextual_benign_admin.jsonl`
- `examples/events/contextual_discovery_lateral.jsonl`
- `examples/events/contextual_auth_spray.jsonl`
- `examples/events/contextual_deception.jsonl`
- `examples/events/contextual_stale_evidence.jsonl`

Expected behavior:

- benign admin maintenance is suppressed below the compromise threshold;
- discovery and lateral movement raise discovery/lateral stage probabilities;
- auth spray creates credential-access/initial-access evidence;
- deception interaction creates high-confidence evidence;
- stale evidence remains auditable while active risk decays or is capped by
  later benign context.

### Evaluation

Use `mirage.detection.evaluation.evaluate_scenarios(...)` for synthetic-only
metrics: rule precision/recall, stage accuracy, macro-F1 style summary, Brier
score, detection latency, false positives per benign scenario, evidence
coverage, deterministic consistency, correlated events, and processing time.
These metrics validate implementation behavior on synthetic data only. They
are not production detection-accuracy claims.

### Configuration

`config.json` has a `detection` section for retention, windows, rule weights,
stage priors, evidence decay/TTL, correlation windows, compromise thresholds,
allowlists, approved service accounts, graph propagation, and API timeline
limits. Override via `MIRAGE_CONFIG` as with earlier milestones.

### Method Notes

Stage estimation uses a deterministic score model:

```text
stage_score = prior + decayed(rule_score * confidence) + soft transition hints
posterior   = softmax(stage_score)
uncertainty = normalized entropy(posterior)
```

Compromise probability uses bounded evidence accumulation:

```text
P(compromise) = 1 - exp(-(direct + 0.5 * inferred - suppression))
```

Deception interaction can raise probability to a high-confidence configured
floor. Benign administrative suppression cannot hide deception evidence and
caps non-deception compromise below the configured suspicious threshold.

### Limitations and Migration Notes

- This is an explainable baseline, not a trained AI model.
- No zero-day detection, LLM, Transformer, GNN, deep RL, or MARL is claimed in
  this milestone.
- Probabilities depend on configured priors, evidence quality, and incomplete
  Digital Twin data.
- Timeline, evidence, and belief state are in memory; use snapshots for replay
  and audit.
- High-risk response actions are not automated by this detection layer.
- The old research-simulator HMM/stage classifier remains available for the
  original dashboard and decision flow; Contextual Detection V1 is additive.

Recommended Milestone 3:

```text
Dynamic Local Subgraph Retrieval
+ Attack-Path Risk Engine
+ Candidate Defense Action Generation
```

## Milestone 3: Attack-Path Analysis and Candidate Actions

Milestone 3 turns Digital Twin and belief snapshots into bounded local attack
paths and non-executing candidate defense actions:

```text
Belief Snapshot
      +
Digital Twin
      +
Attack Graph
      ->
Seed Entity Selector
      ->
Local Subgraph Extractor
      ->
Attack-Path Finder
      ->
Path Risk Scorer
      ->
Deception Position Analyzer
      ->
Candidate Action Generator
      ->
Constraint Evaluator
      ->
Action Mask Builder
      ->
Candidate Action Ranker
      ->
Robust Decision Adapter
```

### What It Does

- Selects seed entities from compromise probability, attacker-location
  probability, evidence recency, stage severity, deception evidence, and
  uncertainty.
- Extracts bounded local operational subgraphs from active Digital Twin
  relationships with hop, node, edge, freshness, confidence, and relationship
  filters.
- Finds bounded paths by type: shortest critical path, highest-success path,
  high-risk, credential-driven, recently observed, decoy path, unprotected
  path, and high-blast-radius path.
- Scores paths using an explicit heuristic formula with source compromise,
  path success, target criticality, stage compatibility, evidence recency,
  relationship confidence, credential feasibility, exposure, direct-observation
  bonuses, inferred/stale penalties, and uncertainty.
- Identifies deception placement opportunities at shared branch points and
  risky edges.
- Generates allowlisted candidate actions only. Examples: increase telemetry,
  enable auth auditing, deploy fake share, scatter honey credential, throttle
  edge, require MFA, temporary segmentation, and isolate host.
- Evaluates constraints and builds masks. Blocked actions keep explicit reasons;
  approval-required actions remain visible but are not treated as directly
  executable.
- Produces a compatibility payload for future robust-decision integration
  without rewriting the existing robust decision engine.

### CLI

First create snapshots:

```bash
python -m mirage replay \
  --events examples/events/analysis_lateral_critical_db.jsonl \
  --snapshot-out artifacts/m3_twin.json

python -m mirage detect \
  --events examples/events/analysis_lateral_critical_db.jsonl \
  --belief-out artifacts/m3_belief.json \
  --detections-out artifacts/m3_detections.jsonl
```

Then run attack-path analysis:

```bash
python -m mirage analyze-paths \
  --twin-snapshot artifacts/m3_twin.json \
  --belief-snapshot artifacts/m3_belief.json \
  --analysis-out artifacts/attack_analysis.json \
  --actions-out artifacts/candidate_actions.json \
  --verbose
```

Example output:

```text
MIRAGE attack-path analysis complete
  selected seed entities:    10
  subgraph nodes/edges:      11/6
  coverage/freshness:        1.000/0.999
  attack paths found:        5
  critical assets at risk:   1
  deception positions:       1
  actions generated:         12
  allowed actions:           9
  blocked actions:           3
  approval-required actions: 9
```

### API

Milestone 3 endpoints:

```text
POST /api/v1/analysis/run
GET  /api/v1/analysis/{analysis_id}
GET  /api/v1/analysis/{analysis_id}/subgraph
GET  /api/v1/analysis/{analysis_id}/paths
GET  /api/v1/analysis/{analysis_id}/critical-assets
GET  /api/v1/analysis/{analysis_id}/deception-positions
GET  /api/v1/analysis/{analysis_id}/actions
GET  /api/v1/analysis/{analysis_id}/masks
POST /api/v1/analysis/recompute
```

Minimal request:

```bash
curl -X POST http://localhost:8000/api/v1/analysis/run \
  -H "Content-Type: application/json" \
  -d '{"max_hops":3,"max_nodes":80,"max_paths":60}'
```

The API analyzes the current in-memory Twin and belief state created by the
existing ingestion/detection endpoints.

### Formulas

Seed priority:

```text
0.38 * compromise
+ 0.25 * attacker_location
+ 0.12 * evidence_confidence
+ 0.10 * evidence_recency
+ 0.15 * stage_severity
+ deception_bonus
- uncertainty_penalty
- inferred_only_penalty
```

Path risk:

```text
risk =
  source_compromise
* path_success
* target_criticality
* stage_compatibility
* evidence_recency
* relationship_confidence
* credential_feasibility
* exposure_modifier
+ direct_observation_bonus
+ credential_bonus
+ protected_asset_bonus
- decoy_modifier
- inferred/stale/uncertainty penalties
```

Candidate ranking:

```text
score =
  expected_risk_reduction
+ information_gain_weight * expected_information_gain
+ path_coverage_weight * affected_path_coverage
- operational_cost_weight * operational_cost
- deployment_cost_weight * deployment_cost
- business_risk_weight * business_risk
- uncertainty_weight * uncertainty
```

### Synthetic Scenarios

Milestone 3 adds deterministic synthetic scenarios:

- `analysis_discovery_low_risk.jsonl`
- `analysis_lateral_critical_db.jsonl`
- `analysis_decoy_interaction.jsonl`
- `analysis_stale_twin.jsonl`
- `analysis_protected_asset.jsonl`
- `analysis_overlapping_paths.jsonl`
- `analysis_inferred_only.jsonl`

Use `mirage.analysis.evaluation.evaluate_analysis_scenarios(...)` for
synthetic-only metrics such as seed correctness, path recall, critical-asset
identification, candidate-action coverage, invalid-action rejection, protected
asset safety, deterministic replay consistency, average local subgraph size,
average path/action counts, and blocked-action explanation coverage.

### Limitations

- This remains a research prototype.
- Risk scores are heuristic and explainable; they are not calibrated production
  probabilities.
- Candidate actions are recommendations only and do not execute firewall, EDR,
  IAM, Kubernetes, or host changes.
- Action masks are preliminary constraints, not the full Safety Gate.
- No GNN, LLM, RL training, MARL, or real enforcement exists in this milestone.
- Stale or incomplete Twin data reduces confidence and blocks disruptive
  recommendations.

Recommended Milestone 4:

```text
Safety Gate V1
+ Deception Orchestrator
+ Mock Enforcement Adapters
+ Docker/Kubernetes Lab Deployment
+ Canary Execution
+ Rollback and Audit
```

## Milestone 4: Safety Gate V1 and Lab Execution

Milestone 4 converts a ranked `CandidateDefenseAction` and its `ActionMask`
into a safe, auditable, reversible lab execution workflow:

```text
Candidate Action + Action Mask + Twin/Belief/Graph versions
  -> Safety Gate V1
  -> ExecutionPlan
  -> prepare
  -> canary
  -> execute
  -> verify
  -> commit or rollback
  -> audit + Digital Twin update
```

### What It Does

- Adds canonical Pydantic models for `SafetyDecision`, `ExecutionPlan`,
  `ExecutionRecord`, `ApprovalRecord`, kill-switch state, adapter results,
  health checks, state transitions, and sanitized audit events.
- Evaluates configurable Safety Gate V1 policies: masks, protected assets,
  managed environment boundaries, confidence thresholds, Twin freshness,
  graph coverage, blast radius, rollback/TTL requirements, budget, duplicate
  active actions, adapter availability, attack-stage compatibility,
  management-channel protection, and external/hack-back prevention.
- Supports action tiers:
  - Tier 0 observe: automatic.
  - Tier 1 deception: automatic with monitoring.
  - Tier 2 delay: strong confidence, TTL, rollback.
  - Tier 3 limited containment: approval required in Milestone 4.
  - Tier 4 high-risk containment: denied or recommendation-only.
- Implements a deterministic execution state machine:
  `PROPOSED -> VALIDATED -> AWAITING_APPROVAL -> PREPARED ->
  CANARY_RUNNING -> EXECUTING -> VERIFYING -> SUCCEEDED -> EXPIRED`,
  with failure rollback states `FAILED -> ROLLING_BACK -> ROLLED_BACK`.
- Adds mock/lab adapters: `DockerDecoyAdapter`, `MockFirewallAdapter`,
  `MockEDRAdapter`, `MockIAMAdapter`, `MockDNSAdapter`,
  `MockTelemetryAdapter`, and `MockTicketAdapter`.
- Runs canary checks before full execution. Canary or verification failure
  triggers rollback automatically.
- Adds TTL expiry, rollback manager, global/scoped kill switch, append-only
  sanitized JSONL audit export, API endpoints, CLI commands, synthetic
  scenarios, and a Docker Compose lab skeleton.
- Updates the Digital Twin after successful lab execution and after rollback
  or expiry. Updates are idempotent and retain provenance.

### What It Does Not Do

- No real firewall, EDR, IAM, Active Directory, cloud, Kubernetes, or Docker
  daemon enforcement is called by the Python adapters.
- No automatic high-risk containment.
- No hack-back or external actions.
- No Milestone 5 connectors.

### CLI

Evaluate safety:

```bash
python -m mirage safety-check \
  --action artifacts/candidate_actions.json \
  --twin artifacts/m3_twin.json \
  --belief artifacts/m3_belief.json
```

Execute in the mock lab:

```bash
python -m mirage execute-plan \
  --action artifacts/candidate_actions.json \
  --twin artifacts/m3_twin.json \
  --belief artifacts/m3_belief.json \
  --lab \
  --audit-out artifacts/execution_audit.jsonl
```

Status, rollback, and kill switch:

```bash
python -m mirage execution-status --execution-id <id>
python -m mirage rollback --execution-id <id>
python -m mirage kill-switch enable --actor soc --reason "maintenance"
python -m mirage kill-switch disable --actor soc --reason "resume"
```

### API

Milestone 4 endpoints:

```text
POST /api/v1/safety/evaluate
POST /api/v1/executions/prepare
POST /api/v1/executions/{id}/approve
POST /api/v1/executions/{id}/execute
POST /api/v1/executions/{id}/rollback
GET  /api/v1/executions/{id}
GET  /api/v1/executions
GET  /api/v1/audit
GET  /api/v1/kill-switch
POST /api/v1/kill-switch/enable
POST /api/v1/kill-switch/disable
```

Approval-required actions cannot execute until a valid non-expired
`ApprovalRecord` exists. Repeated execute requests are idempotent.

### Docker Lab

The isolated lab is in `lab/docker-compose.yml`:

```bash
docker compose -f lab/docker-compose.yml up -d
docker compose -f lab/docker-compose.yml down -v
```

The lab contains synthetic control-plane, attacker, workload, protected,
decoy, mock-firewall, mock-DNS, and telemetry services. The decoy network does
not connect to the protected database network by default.

### Tests

```bash
python -m pytest -q
python -m ruff check .
python -m compileall -q mirage run_mirage.py tests
node --check mirage/dashboard/app.js
```

The Milestone 4 test suite covers all verdict classes, protected assets,
freshness/coverage restrictions, state-machine transitions, idempotency,
canary failure, adapter failure, rollback failure, TTL expiry, kill switch,
approval expiry, API, CLI, audit sanitization, and Digital Twin execution
updates.

## Milestone 5: Real-time Digital Twin, CASM, and Shadow Mode

Milestone 5 moves MIRAGE from file replay and lab-only execution toward
continuous read-only visibility. The enforced operating mode is `shadow` and
`enforcement_enabled` must remain `false`.

```text
Read-only Connectors
        ->
Normalization
        ->
Checkpoint + Dedup + Ordering
        ->
CASM and Entity Resolution
        ->
Real-time Digital Twin
        ->
Contextual Detection and Belief
        ->
Local Attack-Path Analysis
        ->
Candidate Actions
        ->
Safety Gate
        ->
Shadow Recommendations
        ->
Analyst Feedback and Metrics
```

### Connector Architecture

Connectors live under `mirage.connectors` and are read-only. They emit
`RawConnectorRecord` objects and normalize through the canonical
`SecurityEvent` schema. A connector never updates the attack graph, beliefs, or
execution adapters directly.

Supported fixture-driven connector types:

- `sysmon` / `windows_event`
- `zeek` / `netflow`
- `active_directory` / `iam`
- `asset_inventory` / `vulnerability_scanner`
- `generic_jsonl`

The streaming coordinator handles batching, stable ordering, deduplication,
late-event marking, checkpoint commits, and sanitized dead-letter records.
Checkpoints advance only after processing succeeds.

### CASM V1

`mirage.casm.CASMService` reconciles `DiscoveryObservation` records from
inventory, endpoint, network, identity, and vulnerability sources. It uses
configurable source precedence, preserves provenance in asset attributes,
creates `AssetConflict` records for unsafe disagreements, avoids low-confidence
automatic merges, and never reduces business criticality solely from a weaker
source.

Twin quality metrics include coverage, freshness, confidence, source diversity,
conflict count, duplicate candidates, provisional assets, stale assets, and
unknown asset rate. These are engineering indicators, not proof of complete
visibility.

### Realtime Twin

`RealtimeTwinService` reuses the existing `DigitalTwin` and
`ContextualDetectionPipeline` for incremental processing. It supports:

- `process_event(SecurityEvent)`
- `process_observation(DiscoveryObservation)`
- `process_batch(...)`
- consistent snapshots
- Twin quality reports

No full graph rebuild is required per connector record. Analysis remains
bounded and explicit through existing analysis APIs.

### Shadow Mode

`ShadowModeController` evaluates analysis outputs and Safety Gate decisions to
produce `ShadowRecommendation` records. Shadow Mode never calls enforcement
adapters and never creates a real execution plan. Recommendations include
evidence/version provenance, safety verdict, would-execute reasoning, predicted
benefit, business risk, uncertainty, and expiry.

Analyst feedback supports `ACCEPT`, `REJECT`, `DEFER`, `DUPLICATE`,
`INSUFFICIENT_EVIDENCE`, `UNSAFE`, and `IRRELEVANT`. Feedback is stored for
offline evaluation only; it does not retrain or modify models automatically.

### CLI

```bash
python -m mirage connectors list
python -m mirage connectors validate --config examples/connectors.json
python -m mirage connectors poll-once --config examples/connectors.json
python -m mirage connectors health --config examples/connectors.json

python -m mirage casm quality --observations examples/casm_observations.jsonl
python -m mirage casm conflicts --observations examples/casm_observations.jsonl

python -m mirage twin realtime-status
python -m mirage twin snapshot --out artifacts/realtime_twin.json

python -m mirage shadow recommendations
python -m mirage shadow feedback --recommendation-id <id> --decision ACCEPT
```

### API

Milestone 5 endpoints:

```text
GET  /api/v1/connectors
POST /api/v1/connectors
POST /api/v1/connectors/{id}/validate
POST /api/v1/connectors/{id}/start
POST /api/v1/connectors/{id}/stop
POST /api/v1/connectors/poll
GET  /api/v1/connectors/{id}/health
GET  /api/v1/connectors/health

GET  /api/v1/casm/status
GET  /api/v1/casm/assets
GET  /api/v1/casm/conflicts
GET  /api/v1/casm/quality
POST /api/v1/casm/reconcile
POST /api/v1/casm/expire-stale

GET  /api/v1/twin/realtime/status
GET  /api/v1/twin/realtime/quality
POST /api/v1/twin/realtime/snapshot

POST /api/v1/shadow/run
GET  /api/v1/shadow/recommendations
GET  /api/v1/shadow/recommendations/{id}
POST /api/v1/shadow/recommendations/{id}/feedback
GET  /api/v1/shadow/metrics

GET  /api/v1/dead-letter
POST /api/v1/dead-letter/{id}/retry
```

### Synthetic Fixtures

Fixtures live in `examples/connectors/`:

- `sysmon_lateral.jsonl`
- `zeek_flows.jsonl`
- `ad_iam_lab.jsonl`
- `inventory_vuln.jsonl`
- `duplicate_events.jsonl`
- `out_of_order.jsonl`
- `malformed.jsonl`

`examples/m5_scenarios.json` documents scenarios A-J: normal activity,
lateral movement, duplicates, out-of-order events, very late events, identity
conflict, stale assets, decoy interaction, connector restart, and analyst
rejection.

### Security Boundaries

- Connectors are read-only.
- Source fixtures are synthetic.
- No plaintext secrets are stored in connector configuration.
- Raw command lines are redacted or hashed by default.
- No packet payload storage.
- No production enforcement, active scanning, exploit code, or hack-back.
- Shadow Mode remains active even when automation kill switch is enabled.
- CASM and Twin quality do not guarantee complete visibility.

Recommended Milestone 6:

```text
Durable storage and multi-worker state
+ RBAC and stronger audit authorization
+ real read-only SIEM/EDR/cloud connectors
+ calibrated evaluation on larger labeled datasets
+ optional GNN/MARL research tracks
```
