# Milestone 7: Offline Reinforcement Learning and Hierarchical Blue-Team Policy V1

Milestone 7 adds an offline-only Blue-Team policy pipeline.  The policy is
trained from historical, synthetic, simulator, lab, robust-planner, and shadow
trajectories.  It never learns by trial and error in production and never
invokes enforcement adapters.

```text
Digital Twin + Belief + Local Attack Graph
+ GNN/Heuristic Risk Features
+ Candidate Defense Actions
+ Action Masks + Safety Context
        ->
Offline Trajectory Dataset
        ->
Behavior Cloning Baseline
        ->
Conservative Hierarchical Offline RL
        ->
RL Shadow Recommendation
        ->
Action Mask Revalidation + Safety Gate
```

## Safety Boundaries

- Default config is `offline_rl.rl_operating_mode=rl_shadow`.
- `offline_rl.rl_execution_enabled=false` and `general.rl_execution_enabled=false`.
- RL recommendations are shadow/recommendation only.
- The policy selects only from Milestone 3 candidate actions.
- Action masks are applied during training, inference, and evaluation.
- Safety Gate remains authoritative after policy selection.
- Training and dataset-build API endpoints are disabled unless
  `offline_rl.api_training_enabled=true`.
- Analyst feedback is preserved as preference/evaluation context, not automatic
  ground truth.
- Simulator return and replay agreement are offline indicators, not production
  effectiveness claims.

## Schemas

New RL schemas live in `mirage.rl.schema`:

- `RLStateReference`
- `CandidateActionFeature`
- `RewardBreakdown`
- `RLTransition`
- `RLTrajectory`
- `OfflineRLDatasetManifest`
- `PolicyInferenceResult`
- `PolicyMetadata`

Existing MIRAGE schemas are reused for Twin snapshots, beliefs, attack analysis,
candidate actions, action masks, Safety Gate decisions, Shadow recommendations,
and analyst feedback.

## Encoders

`RLStateEncoder` produces a deterministic feature vector with explicit masks.
Feature groups cover incident state, belief uncertainty, path-risk statistics,
Twin quality, graph summaries, optional GNN output, operational context, and
candidate-action summaries.

`ActionFeatureEncoder` encodes only explicit action properties such as tactic,
action type category, risk reduction, information gain, path coverage, costs,
business risk, confidence, uncertainty, reversibility, TTL, risk tier, approval
requirement, Safety Gate verdict, and action-mask state.  Target IDs are not
used as semantic features.

## Reward Model

`DefenseRewardModel` stores each component separately:

```text
asset_protection + interception + delay + information_gain
+ risk_reduction + safe_deception + analyst_acceptance
- asset_loss - business_impact - operational_cost
- false_positive - unnecessary_action - instability
- irreversible_action - stale_recommendation - analyst_rejection
```

Hard constraints are recorded separately and force a non-positive learning
signal.  They include masked action selection, protected-asset modification
without approval, external or hack-back action, missing rollback, blast-radius
violation, managed-boundary violation, kill-switch bypass, and execution without
required approval.

## Policies

Implemented baselines:

- heuristic candidate ranker;
- random safe action;
- always observe/escalate;
- flat behavior cloning;
- hierarchical behavior cloning.

`OfflineBlueTeamPolicy` is a compact discrete, IQL-style conservative policy:

- behavior-cloning initialization;
- empirical Q/value estimates over logged discrete actions;
- tactic manager plus action selector;
- action-support model;
- uncertainty and low-support fallback;
- mask-aware ranking and deterministic evaluation.

Fallback order:

```text
Offline RL
-> Hierarchical Behavior Cloning
-> Robust Decision Engine / robust-compatible recommendation
-> Heuristic Ranker
-> Observe / Analyst Review
```

## CLI

```bash
python -m mirage rl build-dataset --sources simulator,robust,shadow,lab --output artifacts/rl_dataset
python -m mirage rl analyze-dataset --dataset artifacts/rl_dataset
python -m mirage rl train-bc --dataset artifacts/rl_dataset --config configs/rl_bc_v1.yaml --output models/rl_bc_v1
python -m mirage rl train-offline --dataset artifacts/rl_dataset --init-policy models/rl_bc_v1 --config configs/rl_offline_v1.yaml --output models/rl_offline_v1
python -m mirage rl evaluate --policy models/rl_offline_v1 --dataset artifacts/rl_dataset --simulator-config configs/rl_eval.yaml
```

## API

Milestone 7 endpoints:

```text
POST /api/v1/rl/datasets/build
GET  /api/v1/rl/datasets
GET  /api/v1/rl/datasets/{id}
POST /api/v1/rl/train
POST /api/v1/rl/evaluate
POST /api/v1/rl/recommend
GET  /api/v1/rl/policies
GET  /api/v1/rl/policies/{id}
GET  /api/v1/rl/health
GET  /api/v1/rl/comparisons/{analysis_id}
```

`/recommend` is read-only.  It returns policy confidence, uncertainty, fallback
status, OOD warnings, action rankings, robust comparison, and Safety Gate
context.

## Limitations

- This is a compact deterministic offline-RL implementation, not a large neural
  RL framework.
- The synthetic scenarios are designed for regression and safety testing; they
  are not calibrated enterprise security evidence.
- Off-policy estimators report `not_applicable` when behavior probabilities are
  unavailable.
- Milestone 7 does not implement online exploration, production containment,
  Red-Team AI, adversarial MARL, automatic promotion, or Milestone 8.

## Recommended Milestone 8

Durable multi-worker storage for RL datasets/policies, richer calibrated
trajectory sources, stronger policy-promotion governance, and optional temporal
graph policy research after offline shadow validation.

