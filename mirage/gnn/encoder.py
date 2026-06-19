"""GNN State Encoder V1 — GraphSAGE-based model for MIRAGE.

Architecture:
  - Type embedding lookup for node and edge types
  - Edge-feature projection into message augmentation
  - 2-layer GraphSAGE with residual connections
  - Layer normalisation + dropout at each layer
  - Node, edge, and graph prediction heads (in heads.py)
  - Optional MC dropout for uncertainty (controlled via mc_samples)

The encoder is isolated behind a clean interface.  If PyTorch is unavailable
the module raises ImportError at instantiation time — all callers must handle
this gracefully and fall back to heuristic-only mode.

Usage
-----
>>> encoder = GNNStateEncoder(node_feature_dim=42, edge_feature_dim=16)
>>> out = encoder(node_features, edge_index, edge_features,
...               node_types, edge_types)
>>> out.node_risk_probabilities  # list[float]
"""

from __future__ import annotations

from dataclasses import dataclass

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False

from mirage.gnn.schema import (
    EDGE_RELATIONSHIP_TYPES_V1,
    NODE_ENTITY_TYPES_V1,
    GraphFeatureSchema,
    GNNOutput,
)


def _require_torch() -> None:
    if not _TORCH_AVAILABLE:
        raise ImportError(
            "PyTorch is required for GNNStateEncoder. "
            "Install it with: pip install -r requirements-gnn.txt"
        )


class SAGEConv(nn.Module):
    """Minimal GraphSAGE convolution layer (pure PyTorch, no PyG needed).

    Aggregation: mean of neighbour features, concatenated with self features.
    """

    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        edge_dim: int = 0,
    ) -> None:
        super().__init__()
        combined = in_channels + edge_dim
        self.lin_neigh = nn.Linear(combined, out_channels)
        self.lin_self = nn.Linear(in_channels, out_channels)

    def forward(
        self,
        x: "torch.Tensor",           # [N, in_channels]
        edge_index: "torch.Tensor",   # [2, E]
        edge_attr: "torch.Tensor | None" = None,  # [E, edge_dim]
    ) -> "torch.Tensor":             # [N, out_channels]
        num_nodes = x.size(0)
        src, dst = edge_index[0], edge_index[1]

        if edge_attr is not None:
            # Gather source features and concat edge attributes
            neigh_feats = torch.cat([x[src], edge_attr], dim=-1)  # [E, in+edge_dim]
        else:
            neigh_feats = x[src]  # [E, in]

        # Mean aggregation per target node
        agg = torch.zeros(num_nodes, neigh_feats.size(-1), device=x.device)
        counts = torch.zeros(num_nodes, 1, device=x.device)
        agg.scatter_add_(0, dst.unsqueeze(-1).expand_as(neigh_feats), neigh_feats)
        counts.scatter_add_(0, dst.unsqueeze(-1), torch.ones(src.size(0), 1, device=x.device))
        counts = counts.clamp(min=1.0)
        agg = agg / counts

        out = self.lin_neigh(agg) + self.lin_self(x)
        return out


@dataclass
class GNNTensorOutput:
    """Differentiable tensor output used internally by training."""

    node_embeddings: "torch.Tensor"
    graph_embedding: "torch.Tensor"
    node_logits: "torch.Tensor"
    edge_logits: "torch.Tensor"
    graph_logits: "torch.Tensor"
    node_probabilities: "torch.Tensor"
    edge_probabilities: "torch.Tensor"
    graph_probabilities: "torch.Tensor"


class GNNStateEncoder(nn.Module):
    """GraphSAGE-based encoder for MIRAGE local attack subgraphs.

    Parameters
    ----------
    node_feature_dim:
        Dimension of input node features (from GraphFeatureSchema).
    edge_feature_dim:
        Dimension of input edge features.
    hidden_dim:
        Hidden dimension for message-passing layers.
    out_dim:
        Output embedding dimension.
    n_layers:
        Number of GraphSAGE message-passing layers (2 or 3).
    dropout:
        Dropout probability (applied between layers and in MC mode).
    num_node_types:
        Vocabulary size for node-type embedding lookup.
    num_edge_types:
        Vocabulary size for edge-type embedding lookup.
    type_embed_dim:
        Dimension of type embedding vectors.
    mc_samples:
        If > 1, use MC Dropout for uncertainty estimation.  During eval mode,
        dropout is activated for mc_samples forward passes and predictions are
        averaged.
    """

    def __init__(
        self,
        node_feature_dim: int = 42,
        edge_feature_dim: int = 16,
        hidden_dim: int = 64,
        out_dim: int = 64,
        n_layers: int = 2,
        dropout: float = 0.2,
        num_node_types: int = len(NODE_ENTITY_TYPES_V1),
        num_edge_types: int = len(EDGE_RELATIONSHIP_TYPES_V1),
        type_embed_dim: int = 8,
        mc_samples: int = 1,
    ) -> None:
        _require_torch()
        super().__init__()

        self.node_feature_dim = node_feature_dim
        self.edge_feature_dim = edge_feature_dim
        self.hidden_dim = hidden_dim
        self.out_dim = out_dim
        self.n_layers = n_layers
        self.dropout_p = dropout
        self.mc_samples = mc_samples

        # Type embeddings
        self.node_type_embed = nn.Embedding(num_node_types + 1, type_embed_dim, padding_idx=0)
        self.edge_type_embed = nn.Embedding(num_edge_types + 1, type_embed_dim, padding_idx=0)

        # Initial node projection: raw features + type embedding → hidden
        self.node_input_proj = nn.Linear(node_feature_dim + type_embed_dim, hidden_dim)

        # Edge feature projection for message augmentation
        self.edge_proj = nn.Linear(edge_feature_dim + type_embed_dim, hidden_dim)

        # GraphSAGE layers
        self.convs = nn.ModuleList()
        self.norms = nn.ModuleList()
        self.residuals = nn.ModuleList()
        for i in range(n_layers):
            in_ch = hidden_dim
            self.convs.append(SAGEConv(in_ch, hidden_dim, edge_dim=hidden_dim))
            self.norms.append(nn.LayerNorm(hidden_dim))
            self.residuals.append(nn.Identity())

        # Output node projector
        self.node_out_proj = nn.Linear(hidden_dim, out_dim)

        # Node risk head (binary)
        self.node_risk_head = nn.Linear(out_dim, 1)

        # Edge risk head (binary; applied to edge embeddings derived from node pairs)
        self.edge_risk_head = nn.Linear(out_dim * 2, 1)

        # Graph risk head (mean-pool then classify)
        self.graph_risk_head = nn.Sequential(
            nn.Linear(out_dim, out_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(out_dim // 2, 1),
        )

        self.dropout = nn.Dropout(dropout)

    def forward(
        self,
        node_features: "torch.Tensor",    # [N, node_feature_dim]
        edge_index: "torch.Tensor",        # [2, E]
        edge_features: "torch.Tensor",     # [E, edge_feature_dim]
        node_types: "torch.Tensor",        # [N] long
        edge_types: "torch.Tensor",        # [E] long
        batch: "torch.Tensor | None" = None,  # [N] for graph-level pooling
    ) -> GNNOutput:
        """Run one forward pass and return GNNOutput (Pydantic model)."""
        if self.mc_samples > 1 and not self.training:
            return self._mc_forward(
                node_features, edge_index, edge_features,
                node_types, edge_types, batch,
            )
        return self._single_forward(
            node_features, edge_index, edge_features,
            node_types, edge_types, batch,
        )

    def _single_forward(
        self,
        node_features: "torch.Tensor",
        edge_index: "torch.Tensor",
        edge_features: "torch.Tensor",
        node_types: "torch.Tensor",
        edge_types: "torch.Tensor",
        batch: "torch.Tensor | None",
    ) -> GNNOutput:
        tensor_out = self.forward_tensors(
            node_features,
            edge_index,
            edge_features,
            node_types,
            edge_types,
            batch,
        )
        node_emb = tensor_out.node_embeddings
        graph_emb = tensor_out.graph_embedding
        edge_risk_probs = tensor_out.edge_probabilities

        graph_embedding = graph_emb.detach().cpu()
        if graph_embedding.size(0) == 1:
            graph_embedding_payload = graph_embedding.squeeze(0).tolist()
        else:
            graph_embedding_payload = graph_embedding.mean(dim=0).tolist()

        return GNNOutput(
            node_embeddings=node_emb.detach().cpu().tolist(),
            graph_embedding=graph_embedding_payload,
            node_risk_probabilities=tensor_out.node_probabilities.detach().cpu().tolist(),
            edge_movement_probabilities=edge_risk_probs.detach().cpu().tolist(),
            graph_risk_probability=float(
                tensor_out.graph_probabilities.detach().cpu().mean().item()
            ),
            node_uncertainty=[0.0] * node_emb.size(0),
            graph_uncertainty=0.0,
            embedding_dim=self.out_dim,
            num_nodes=int(node_emb.size(0)),
            num_edges=int(edge_index.size(1)),
        )

    def forward_tensors(
        self,
        node_features: "torch.Tensor",
        edge_index: "torch.Tensor",
        edge_features: "torch.Tensor",
        node_types: "torch.Tensor",
        edge_types: "torch.Tensor",
        batch: "torch.Tensor | None" = None,
    ) -> GNNTensorOutput:
        """Run a differentiable forward pass and return tensors.

        The public ``forward`` method returns serializable Pydantic output for
        inference. Training uses this tensor method so losses retain gradients.
        """
        # Type embeddings
        n_type_emb = self.node_type_embed(node_types)   # [N, type_dim]
        e_type_emb = self.edge_type_embed(edge_types)    # [E, type_dim]

        # Initial node representation
        x = torch.cat([node_features, n_type_emb], dim=-1)   # [N, feat+type]
        x = F.relu(self.node_input_proj(x))
        x = self.dropout(x)

        # Edge representation for augmented messages
        if edge_features.size(0) > 0:
            e_in = torch.cat([edge_features, e_type_emb], dim=-1)  # [E, efeat+type]
            e_h = F.relu(self.edge_proj(e_in))                      # [E, hidden]
        else:
            e_h = torch.zeros(0, self.hidden_dim, device=x.device)

        # Message-passing layers with residuals
        for i, (conv, norm) in enumerate(zip(self.convs, self.norms)):
            x_res = x
            x = conv(x, edge_index, e_h)
            x = norm(x)
            x = F.relu(x)
            x = self.dropout(x)
            x = x + x_res   # residual

        # Node embeddings
        node_emb = self.node_out_proj(x)   # [N, out_dim]

        # Node risk probabilities
        node_risk_logits = self.node_risk_head(node_emb).squeeze(-1)  # [N]
        node_risk_probs = torch.sigmoid(node_risk_logits)

        # Edge risk probabilities (concatenate src+dst node embeddings)
        if edge_index.size(1) > 0:
            src, dst = edge_index[0], edge_index[1]
            edge_emb = torch.cat([node_emb[src], node_emb[dst]], dim=-1)  # [E, 2*out]
            edge_risk_logits = self.edge_risk_head(edge_emb).squeeze(-1)
            edge_risk_probs = torch.sigmoid(edge_risk_logits)
        else:
            edge_risk_probs = torch.zeros(0, device=x.device)

        # Graph-level pooling and risk
        if batch is not None:
            # Batch-aware mean pooling
            num_graphs = int(batch.max().item()) + 1
            graph_emb = torch.zeros(num_graphs, node_emb.size(-1), device=x.device)
            graph_emb.scatter_add_(0, batch.unsqueeze(-1).expand_as(node_emb), node_emb)
            counts = torch.bincount(batch, minlength=num_graphs).unsqueeze(-1).float()
            graph_emb = graph_emb / counts.clamp(min=1.0)
        else:
            graph_emb = node_emb.mean(dim=0, keepdim=True)  # [1, out_dim]

        graph_risk_logit = self.graph_risk_head(graph_emb).squeeze(-1)
        graph_risk_prob = torch.sigmoid(graph_risk_logit)

        return GNNTensorOutput(
            node_embeddings=node_emb,
            graph_embedding=graph_emb,
            node_logits=node_risk_logits,
            edge_logits=edge_risk_logits if edge_index.size(1) > 0 else torch.zeros(0, device=x.device),
            graph_logits=graph_risk_logit,
            node_probabilities=node_risk_probs,
            edge_probabilities=edge_risk_probs,
            graph_probabilities=graph_risk_prob,
        )

    def _mc_forward(
        self,
        node_features: "torch.Tensor",
        edge_index: "torch.Tensor",
        edge_features: "torch.Tensor",
        node_types: "torch.Tensor",
        edge_types: "torch.Tensor",
        batch: "torch.Tensor | None",
    ) -> GNNOutput:
        """MC Dropout: multiple stochastic forward passes for uncertainty."""
        # Enable dropout even in eval mode for MC sampling
        self.train()
        all_node_probs: list[list[float]] = []
        all_graph_probs: list[float] = []
        for _ in range(self.mc_samples):
            with torch.no_grad():
                out = self._single_forward(
                    node_features, edge_index, edge_features,
                    node_types, edge_types, batch,
                )
            all_node_probs.append(out.node_risk_probabilities)
            all_graph_probs.append(out.graph_risk_probability)
        self.eval()

        # Average predictions
        n = len(all_node_probs[0]) if all_node_probs else 0
        mean_node = [
            sum(run[i] for run in all_node_probs) / self.mc_samples
            for i in range(n)
        ]
        # Uncertainty = std across MC samples (predictive entropy proxy)
        var_node = [
            sum((run[i] - mean_node[i]) ** 2 for run in all_node_probs) / self.mc_samples
            for i in range(n)
        ]
        uncertainty_node = [v ** 0.5 for v in var_node]
        mean_graph = sum(all_graph_probs) / self.mc_samples
        var_graph = sum((p - mean_graph) ** 2 for p in all_graph_probs) / self.mc_samples
        uncertainty_graph = var_graph ** 0.5

        # Final deterministic pass for embeddings
        self.eval()
        with torch.no_grad():
            base_out = self._single_forward(
                node_features, edge_index, edge_features,
                node_types, edge_types, batch,
            )

        return GNNOutput(
            node_embeddings=base_out.node_embeddings,
            graph_embedding=base_out.graph_embedding,
            node_risk_probabilities=mean_node,
            edge_movement_probabilities=base_out.edge_movement_probabilities,
            graph_risk_probability=mean_graph,
            node_uncertainty=uncertainty_node,
            graph_uncertainty=float(uncertainty_graph),
            embedding_dim=self.out_dim,
            num_nodes=base_out.num_nodes,
            num_edges=base_out.num_edges,
        )

    def save(self, path: str) -> None:
        """Save model weights to *path*."""
        torch.save(self.state_dict(), path)

    @classmethod
    def load(
        cls,
        path: str,
        schema: GraphFeatureSchema | None = None,
        **kwargs: object,
    ) -> "GNNStateEncoder":
        """Load model from *path*."""
        _require_torch()
        schema = schema or GraphFeatureSchema()
        model = cls(
            node_feature_dim=schema.node_feature_dim,
            edge_feature_dim=schema.edge_feature_dim,
            **kwargs,
        )
        state = torch.load(path, map_location="cpu", weights_only=True)
        model.load_state_dict(state)
        model.eval()
        return model


def sample_to_tensors(
    sample: "object | None" = None,
    schema: GraphFeatureSchema | None = None,
    graph_sample: "object | None" = None,
) -> "dict[str, torch.Tensor]":
    """Convert a GraphSample to input tensors for GNNStateEncoder.

    This is a helper to avoid repeating boilerplate in training and inference.
    """
    _require_torch()
    from mirage.gnn.schema import GraphSample as _GraphSample

    if graph_sample is None:
        graph_sample = sample

    if not isinstance(graph_sample, _GraphSample):
        raise TypeError("graph_sample must be a GraphSample")

    gs: "_GraphSample" = graph_sample  # type: ignore[assignment]
    sc = schema or GraphFeatureSchema()

    def _type_idx(type_str: str, vocab: list[str]) -> int:
        try:
            return vocab.index(type_str)
        except ValueError:
            return 0

    node_feats = torch.tensor(gs.node_feature_matrix, dtype=torch.float32)
    node_types_t = torch.tensor(
        [_type_idx(t, sc.node_entity_types) for t in gs.node_types],
        dtype=torch.long,
    )

    src = gs.edge_index[0] if gs.edge_index else []
    dst = gs.edge_index[1] if len(gs.edge_index) > 1 else []
    edge_index_t = torch.tensor([src, dst], dtype=torch.long)

    if gs.edge_feature_matrix:
        edge_feats = torch.tensor(gs.edge_feature_matrix, dtype=torch.float32)
    else:
        edge_feats = torch.zeros((0, sc.edge_feature_dim), dtype=torch.float32)

    edge_types_t = torch.tensor(
        [_type_idx(t, sc.edge_relationship_types) for t in gs.edge_types],
        dtype=torch.long,
    )

    return {
        "node_features": node_feats,
        "edge_index": edge_index_t,
        "edge_features": edge_feats,
        "node_types": node_types_t,
        "edge_types": edge_types_t,
    }
