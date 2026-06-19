# Milestone 6: Hierarchical Graph Representation and GNN State Encoder V1

Milestone 6 adds an optional learned graph encoder to MIRAGE. It converts a
Digital Twin snapshot, belief snapshot, evidence-derived local subgraph, and
Shadow feedback labels into versioned graph samples, embeddings, and risk
predictions. The learned model enhances the existing attack-path scorer and
robust decision adapter; it does not replace heuristic path scoring, POMDP
logic, robust optimization, action masks, Safety Gate checks, Shadow Mode, or
static simulator behavior.

## Pipeline

```text
Digital Twin Snapshot
+ Belief Snapshot
+ Evidence
+ Local Attack Subgraph
+ Shadow/Synthetic Labels
        ->
GraphDatasetBuilder
        ->
HierarchicalGraphBuilder
        ->
GNNStateEncoder or baseline
        ->
Node, Edge, and Subgraph Embeddings
        ->
Risk Predictions
        ->
Hybrid Path Risk Adapter
+ Robust Decision optional features
```

## Graph Schema

Node vocabulary v1 includes:

- `unknown`, `asset`, `host`, `identity`, `credential`, `service`, `process`
- `database`, `subnet`, `domain`, `vulnerability`, `decoy`
- `business_service`, `application`, `enterprise`

Edge vocabulary v1 includes:

- `communicates_with`, `authenticated_to`, `runs_on`, `member_of`
- `has_privilege`, `uses_credential`, `uses_credential_on`, `depends_on`
- `contains_vulnerability`, `can_connect_to`, `connects_to`
- `observed_lateral_movement`, `protected_by`, `deployed_as_decoy`
- `belongs_to_subnet`, `belongs_to_domain`, `asset_supports_application`
- `application_supports_business_service`, `belongs_to_enterprise`
- `interacted_with_decoy`, `accessed_file_on`

Unknown node and edge types are supported and produce OOD warnings.

## Feature Schema

`GraphFeatureSchema` defines deterministic v1 feature ordering and a schema
hash. Node features include entity type index, compromise probability,
attacker-location probability, belief confidence and uncertainty, stage
distribution, business criticality, protected/decoy/seed/critical flags,
privilege level, vulnerability placeholders, evidence counts, recency,
source diversity, Twin confidence and freshness, degree features, weighted
degree features, and distances to critical assets and active decoys.

Edge features include relationship type index, confidence, direct/inferred
status, recency, protocol category, authentication and credential flags,
privilege requirement, movement likelihood, evidence count, stale/active
status, protected-path, existing-control, and decoy-path flags.

Missing values use explicit mask matrices. Raw usernames, hostnames, IP
addresses, command lines, and credentials are not encoded as numeric features.
Feature scaling statistics are recorded in model metadata during training.

## Hierarchy

`HierarchicalGraphBuilder` deterministically groups bounded local operational
graphs into application/workload, subnet, domain/site, and optional enterprise
summary levels. It does not rebuild the complete enterprise graph per event.
Aggregation mappings are serialized with each `GraphSample`.

## Dataset and Labels

`GraphDatasetBuilder` creates deterministic `GraphSample` JSON artifacts under
`samples/` plus a manifest. Samples contain node IDs, edge IDs, type lists,
feature matrices, masks, COO edge indices, hierarchy mappings, labels,
provenance, split, warnings, and schema versions.

Supported labels are independent:

- node compromise/suspicion labels;
- edge lateral-movement labels;
- graph critical-target reachability labels.

Labels may come from deterministic synthetic scenarios, simulator state,
confirmed deception interactions, confirmed incidents, or analyst-confirmed
Shadow recommendations. Unreviewed beliefs are not treated as perfect ground
truth.

Splitting is scenario/time based to prevent neighboring snapshots from the same
incident leaking across train and test. Evaluation fixtures include known
topology later time, unseen topology, unseen sequence, stale Twin, noisy or
missing features, decoy-rich graphs, unknown types, inferred-only paths, and
large hierarchical graphs.

## Models and Baselines

Baselines use the same graph features:

- heuristic belief/path features;
- logistic regression when scikit-learn is installed, otherwise deterministic
  fallback probabilities;
- MLP when scikit-learn is installed, otherwise deterministic fallback
  probabilities.

`GNNStateEncoder` is a pure PyTorch GraphSAGE-style encoder with type
embeddings, edge-feature message projection, residual layers, layer
normalization, dropout, and node, edge, and graph heads. PyTorch Geometric is
not required. PyTorch is optional for the base MIRAGE install; training and
model loading clearly fail if it is absent.

## Training and Evaluation

Build a deterministic synthetic dataset:

```bash
python -m mirage gnn build-dataset --snapshots scenarios --output artifacts/gnn_dataset
```

Train when optional GNN dependencies are installed:

```bash
python -m mirage gnn train --dataset artifacts/gnn_dataset --config configs/gnn_v1.yaml --output models/gnn_v1
```

Evaluate baselines and an optional model:

```bash
python -m mirage gnn evaluate --dataset artifacts/gnn_dataset --model models/gnn_v1/best_model.pt
```

Metrics include node precision/recall/F1, ROC-AUC when valid, PR-AUC, Brier
score, calibration error, edge precision/recall/F1, top-k movement-edge recall,
edge PR-AUC, graph accuracy/F1/Brier/ranking indicators, and latency.

## Inference, OOD, and Integration

`GNNInferenceService` is read-only. It loads a model, checks feature-schema
compatibility, bounds graph size, returns embeddings and risk predictions, and
emits OOD warnings for unseen types, out-of-range features, missing features,
low Twin coverage, and topology size drift. Missing or incompatible models
activate heuristic fallback.

Operating modes:

- `heuristic_only`: learned scores are ignored;
- `gnn_shadow`: default; learned predictions are logged but do not alter
  recommendations;
- `hybrid_recommendation`: heuristic and learned edge/path scores are combined.

Hybrid scoring uses:

```text
hybrid = heuristic_weight * heuristic_risk + gnn_weight * learned_risk
```

The GNN weight becomes zero when no model is available, schema/OOD checks fail,
or uncertainty is high. GNN predictions cannot override protected-asset rules,
decoy constraints, action masks, Safety Gate verdicts, or Shadow Mode.

The robust decision adapter can optionally attach subgraph embeddings,
node-risk values, edge-movement values, graph risk, uncertainty, and OOD flags.
It does not change robust optimization mathematics.

## API

```text
POST /api/v1/gnn/encode
GET  /api/v1/gnn/models
GET  /api/v1/gnn/models/{id}
GET  /api/v1/gnn/health
POST /api/v1/gnn/evaluate
GET  /api/v1/gnn/predictions/{analysis_id}
```

## Limitations

- GNN predictions are not automatically trusted.
- Training labels may be synthetic or weakly supervised.
- Unseen environments may reduce performance and trigger fallback.
- Graph quality depends on Digital Twin quality.
- Heuristic scoring, robust optimization, Safety Gate, action masks, rollback,
  and Shadow Mode remain mandatory.
- Milestone 6 does not implement reinforcement learning, offline RL, MARL,
  Red Team AI, LLM decision making, production enforcement, or automatic
  retraining from analyst feedback.

## Recommended Milestone 7

Milestone 7 should focus on durable multi-worker model/prediction storage,
larger calibrated datasets, stronger RBAC/audit controls for model promotion,
and optional temporal graph research after the v1 encoder has been validated
against baselines.
