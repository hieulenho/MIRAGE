# Layer 2 — Graph Engine (Attack Graph + GNN)

## Mục đích
Biểu diễn trạng thái mạng dưới dạng đồ thị và giải quyết bài toán tối ưu phòng thủ.

## Trạng thái hiện tại
- `v1`: Attack Graph + POMDP/MDP solver (hoạt động tốt tới ~10k nodes)

## Roadmap → v2
- [ ] `gnn_encoder.py` — GNN embeddings cho node/edge states (scale tới 500k nodes)
- [ ] `hierarchical_graph.py` — Phân cấp đồ thị theo subnet/domain để RL tính toán real-time

## Input / Output Interface
- **Input**: `ThreatObservation` từ Layer 1, topology JSON
- **Output**: `GraphState(node_embeddings, adjacency, belief_vector)`

## Files
| File | Mô tả |
|---|---|
| `attack_graph.py` | Xây dựng và quản lý attack graph |
| `graph_parser.py` | Parser topology JSON → nx.Graph |
| `mdp_solver.py` | POMDP/MDP solver (value iteration) |
| `gnn_encoder.py` | [NEW] GNN-based state embedding |
| `hierarchical_graph.py` | [NEW] Hierarchical graph for large-scale |

## Dependencies
```
networkx, numpy, scipy
# v2: torch-geometric, dgl
```
