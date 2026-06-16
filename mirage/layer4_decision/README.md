# Layer 4 — Decision Engine (MARL)

## Mục đích
Ra quyết định phòng thủ tối ưu. Sử dụng Reinforcement Learning để chọn action phản ứng.

## Trạng thái hiện tại
- `v1`: Single-agent DQN với Robust Reward Design (minimax)

## Roadmap → v2
- [ ] `red_team_agent.py` — Adversarial AI liên tục tiến hóa tìm lỗ hổng mới
- [ ] `blue_team_agent.py` — Defensive AI (MIRAGE defender)
- [ ] `marl_coordinator.py` — Multi-Agent coordinator, shared replay buffer, communication protocol

## Input / Output Interface
- **Input**: `GraphState` từ Layer 2, `DeceptionPlan` từ Layer 3
- **Output**: `DefenderAction(action_type, target_node, confidence)`

## Files
| File | Mô tả |
|---|---|
| `decision_engine.py` | Orchestrator: nhận state, chạy policy, trả action |
| `rl_agent.py` | DQN agent (network, training loop) |
| `policy_cache.py` | Cache policy đã học để tái sử dụng |
| `red_team_agent.py` | [NEW] Red Team AI (adversarial) |
| `blue_team_agent.py` | [NEW] Blue Team AI (defender) |
| `marl_coordinator.py` | [NEW] MARL training coordinator |

## Trained Models
Weights được lưu tại `models/dqn/` (v1) và `models/gnn/` (v2).

## Dependencies
```
numpy, jax / flax
# v2: ray[rllib], stable-baselines3, pettingzoo
```
