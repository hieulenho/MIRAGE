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

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
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
├── requirements.txt                # Thư viện phụ thuộc
├── .gitignore
│
└── mirage/                         # Package chính
    ├── __init__.py                 # Package metadata (v2.0.0)
    ├── config.py                   # Configuration loader trung tâm
    │
    ├── layer1_attack_modeling.py   # Layer 1: Phân loại giai đoạn tấn công
    ├── layer1_hmm.py               # HMM + ensemble telemetry classifier
    ├── layer2_attack_graph.py      # Layer 2: Đồ thị tấn công POMDP 15 node
    ├── graph_parser.py             # Parser MIRAGE/BloodHound/Nmap JSON
    ├── layer3_deception.py         # Layer 3: Deception Fabric
    ├── layer4_decision_engine.py   # Layer 4: Robust Decision Engine
    ├── rl_agent.py                 # Deep Q-Network + Gymnasium environment
    ├── layer5_safe_control.py      # Layer 5: Safety Gate
    ├── layer6_evaluation.py        # Layer 6: Benchmark & Evaluation
    ├── api_server.py               # FastAPI REST/WebSocket orchestration
    ├── attacker_mitre.py           # MITRE ATT&CK evasion attacker
    ├── dashboard/                  # Web dashboard
    │
    └── attacker_agents.py          # Mô phỏng 5 loại kẻ tấn công
```

---

## ⚙️ Yêu cầu hệ thống

- **Python**: 3.9 hoặc mới hơn
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
python -m mirage.api_server
```

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
các REST endpoint `/api/*`.

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

### Ví dụ output — `--mode step2`

```
[Layer 3] Triển khai Deception Fabric...
  [🪤 Deception] Fake Database deployed at Node 11 (DB_FAKE_Backup) | Reward bait: +0.9
  [🪤 Deception] Fake Router deployed at Node 12 (Router_FAKE_Gateway) | Edge cost +0.3
  [🍯 Honey] Honey Credential planted at Node 4 (Workstation_Finance) | Trigger reward: +0.5

[Attackers] Simulating 4 attacker types (100 episodes each)...
  random              : Hit True Goal=20.0%  |  Decoy Hit=20.0%  |  Avg Steps=3.6
  greedy              : Hit True Goal=47.0%  |  Decoy Hit=53.0%  |  Avg Steps=4.9
  shortest_path       : Hit True Goal=88.0%  |  Decoy Hit=12.0%  |  Avg Steps=4.9
  stealthy            : Hit True Goal=53.0%  |  Decoy Hit=40.0%  |  Avg Steps=4.7

Quick Comparison (3 methods):
  Method                    |   Intercept% |     Pess.Val
  no_defense                |       33.0% |     -1.4875
  static_honeypot           |       32.0% |     -1.3675
  robust_mirage             |       38.5% |     -1.3075 ← MIRAGE
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

### Layer 1 — Multi-Stage Attack Modeling (`layer1_attack_modeling.py`, `layer1_hmm.py`)

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

### Layer 2 — Enterprise Attack Graph / POMDP (`layer2_attack_graph.py`)

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

### Layer 3 — Deception Fabric (`layer3_deception.py`)

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
from mirage.layer2_attack_graph import build_enterprise_attack_graph
from mirage.layer3_deception import DeceptionFabric, DeceptionActionType

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

### Layer 4 — Robust Decision Engine (`layer4_decision_engine.py`)

**"Bộ não"** của MIRAGE — chọn hành động tối ưu theo nguyên tắc **Robust Optimization** (tối đa hóa worst-case defender value).

**Workflow tại mỗi bước quyết định:**

1. Nhận `belief_state` từ Layer 2
2. Lấy danh sách `available_actions` từ Layer 3
3. Simulate mỗi action với **4 loại kẻ tấn công**
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

### Layer 5 — Safety Gate (`layer5_safe_control.py`)

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

### Layer 6 — Evaluation & Benchmark (`layer6_evaluation.py`)

So sánh hiệu quả của **6 phương pháp phòng thủ**:

| Phương pháp | Mô tả |
|-------------|-------|
| `no_defense` | Không có biện pháp phòng thủ nào |
| `static_honeypot` | Honeypot tĩnh truyền thống |
| `robust_mirage` | MIRAGE với Robust Optimization ✅ |
| `random_deception` | Triển khai ngẫu nhiên |
| `greedy_deception` | Chọn action có expected value cao nhất |
| `milp_optimal` | MILP Optimization lý tưởng |

**Metrics đánh giá:**
- `interception_rate` — Tỷ lệ kẻ tấn công bị dẫn vào decoy
- `hit_true_goal_rate` — Tỷ lệ kẻ tấn công đạt được mục tiêu thật
- `pessimistic_value` — Defender value trong worst-case
- `avg_steps_to_terminal` — Số bước trung bình đến trạng thái kết thúc

---

## 🤺 Mô phỏng Kẻ tấn công (`attacker_agents.py`)

4 loại kẻ tấn công với chiến thuật khác nhau:

| Loại | Chiến thuật | Đặc điểm |
|------|-------------|----------|
| `random` | Ngẫu nhiên hoàn toàn | Baseline, không biết topology |
| `greedy` | Chọn action có reward cao nhất ngay lập tức | Tham lam, dễ bị bẫy decoy reward |
| `shortest_path` | Đi đường ngắn nhất đến true goal | Nguy hiểm nhất với defense truyền thống |
| `stealthy` | Né tránh các node có nhiều traffic | Khó phát hiện, tốn nhiều bước |

---

## 📊 Kết quả Benchmark

Kết quả từ simulation thực tế (100-500 episodes):

```
Method                    |   Intercept% |     Pess.Val
----------------------------------------------------------
no_defense                |       33.0% |     -1.4875
static_honeypot           |       32.0% |     -1.3675
robust_mirage             |       38.5% |     -1.3075 ← MIRAGE ✅
```

**Ablation Study — Đóng góp của từng thành phần:**

```
Component                 |   Pess.Val |   Intercept%
Full MIRAGE               |    -1.1288 |       30.0%  ← FULL ✅
- Robust Term             |    -1.1288 |       32.0%
- Stage Modeling          |    -1.1288 |       28.0%
- Deception Variety       |    -1.1288 |       28.0%
- Safety Cost             |    -1.3653 |       25.0%
No Components             |    -1.1288 |       32.0%
```

> **Nhận xét:** Safety Cost (Layer 5) đóng góp lớn nhất — loại bỏ Safety Cost làm giảm Intercept Rate từ 30% xuống còn 25%.

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

Chi tiết topology của Enterprise Attack Graph v1:

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
