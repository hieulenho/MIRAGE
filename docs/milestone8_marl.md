# Milestone 8: Adversarial Red-Blue Self-Play and MARL Cyber Range V1

Milestone 8 adds a synthetic, isolated red-blue cyber range for self-play and
policy evaluation.  The range is a graph simulator only.  Red actions are
abstract state transitions such as discovering a neighboring node, moving along
a known edge, reducing synthetic noise, or collecting a synthetic objective.
They do not contain commands, payloads, scanners, sockets, exploit modules, or
network clients.

## Safety Boundaries

- `marl.cyber_range_only=true`
- `marl.red_agent_external_network=false`
- `marl.production_connectivity=false`
- `marl.real_exploitation_enabled=false`
- `marl.blue_execution_mode=shadow`
- `marl.training_api_enabled=false` by default

Startup config validation and `RangeIsolationConfig` both fail closed when
these boundaries are violated.  Blue actions are synthetic
`CandidateDefenseAction` records under normal `ActionMask`s; they mutate only
range state and never call execution adapters.

## Modules

- `mirage.marl.schema`: isolation, scenario, observation, action, trajectory,
  reward, policy, health, and evaluation schemas.
- `mirage.marl.actions`: `RedActionCatalog` and `BlueActionAdapter`.
- `mirage.marl.observations`: red partial-observation and blue observation
  adapters.
- `mirage.marl.environment`: `CyberRangeEnvironment` reset, step, snapshot,
  restore, and replay.
- `mirage.marl.policies`: scripted red policies, masked trainable red policy,
  and `BlueMARLPolicyAdapter`.
- `mirage.marl.population`: opponent population metadata and sampling.
- `mirage.marl.curriculum`: staged scenario curriculum.
- `mirage.marl.randomizer`: bounded synthetic scenario variants.
- `mirage.marl.rewards`: separate red and blue reward components plus hard
  violations.
- `mirage.marl.training`: `SelfPlayTrainer` for compact CPU-only self-play.
- `mirage.marl.evaluation`: approximate exploitability and robustness reports.
- `mirage.marl.registry`: file-backed MARL policy registry.
- `mirage.marl.cli`: CLI for range checks, scenarios, self-play, evaluation,
  population, replay, and policy listing.

## CLI

```bash
python -m mirage marl range-check
python -m mirage marl generate-scenarios --output artifacts/marl_scenarios
python -m mirage marl train-red --episodes 4 --output models/marl_red_v1
python -m mirage marl train-blue --episodes 4 --output models/marl_blue_v1
python -m mirage marl self-play --episodes 6 --output models/marl_self_play
python -m mirage marl evaluate --scenarios 6
python -m mirage marl population
python -m mirage marl compare-blue --scenarios 6
```

Replay accepts a JSON list of abstract action IDs:

```json
[
  {"red_action_id": "red:recon:s0:entry", "blue_action_id": "blue:noop"}
]
```

## API

```text
GET  /api/v1/marl/range-health
POST /api/v1/marl/train
POST /api/v1/marl/evaluate
POST /api/v1/marl/replay
GET  /api/v1/marl/jobs/{job_id}
GET  /api/v1/marl/population
GET  /api/v1/marl/policies
GET  /api/v1/marl/policies/{policy_id}
GET  /api/v1/marl/comparisons/{analysis_id}
```

`/train` is disabled unless `marl.training_api_enabled=true` is explicitly set
while all isolation flags remain safe.  Evaluation and replay are synthetic
range operations.

## Limitations

- This is a compact deterministic MARL V1 implementation, not a distributed
  deep-RL framework.
- Exploitability is an approximate scripted best-response score inside the
  graph simulator.
- Scenario telemetry is synthetic and not calibrated production evidence.
- Milestone 8 does not implement real exploitation, live red-team tooling,
  production containment, automatic policy promotion, distributed training, or
  Milestone 9.
