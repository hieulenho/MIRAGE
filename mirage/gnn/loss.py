"""Multi-task loss functions for MIRAGE GNN training.

Total Loss =
  node_loss_weight   × node_classification_loss   (Task A)
+ edge_loss_weight   × edge_classification_loss   (Task B)
+ graph_loss_weight  × graph_classification_loss  (Task C)
+ l2_weight          × L2 regularisation

Supported:
  - Weighted Binary Cross-Entropy
  - Focal Loss (optional; controlled by focal_gamma > 0)
  - Balanced sampling weights from label counts

Class weights are stored in model metadata for audit purposes.
"""

from __future__ import annotations

try:
    import torch
    import torch.nn as nn
    _TORCH_AVAILABLE = True
except ImportError:
    _TORCH_AVAILABLE = False


def _require_torch() -> None:
    if not _TORCH_AVAILABLE:
        raise ImportError("PyTorch required for loss functions.")


class FocalLoss(nn.Module):
    """Binary focal loss for imbalanced classification.

    FL(p) = −α(1−pₜ)^γ log(pₜ)

    Parameters
    ----------
    gamma: float
        Focusing parameter (0 = standard BCE).
    pos_weight: float
        Weight for positive class (imbalance handling).
    """

    def __init__(self, gamma: float = 2.0, pos_weight: float = 1.0) -> None:
        _require_torch()
        super().__init__()
        self.gamma = gamma
        self.pos_weight = pos_weight

    def forward(
        self,
        logits: "torch.Tensor",   # [N]
        targets: "torch.Tensor",  # [N] float 0/1
    ) -> "torch.Tensor":
        bce_loss = nn.functional.binary_cross_entropy_with_logits(
            logits, targets,
            pos_weight=torch.tensor(self.pos_weight, device=logits.device),
            reduction="none",
        )
        probs = torch.sigmoid(logits)
        p_t = probs * targets + (1 - probs) * (1 - targets)
        focal_weight = (1 - p_t) ** self.gamma
        loss = focal_weight * bce_loss
        return loss.mean()


class WeightedBCELoss(nn.Module):
    """Weighted BCE loss for class-imbalanced binary classification."""

    def __init__(self, pos_weight: float = 1.0) -> None:
        _require_torch()
        super().__init__()
        self.pos_weight = pos_weight

    def forward(
        self,
        logits: "torch.Tensor",
        targets: "torch.Tensor",
    ) -> "torch.Tensor":
        return nn.functional.binary_cross_entropy_with_logits(
            logits, targets,
            pos_weight=torch.tensor(self.pos_weight, device=logits.device),
        )


class MultiTaskLoss(nn.Module):
    """Configurable multi-task loss for GNN training.

    Parameters
    ----------
    node_loss_weight: float
        Weight for node compromise-risk task.
    edge_loss_weight: float
        Weight for edge lateral-movement task.
    graph_loss_weight: float
        Weight for graph reachability task.
    l2_weight: float
        L2 regularisation weight applied to model parameters.
    focal_gamma: float
        If > 0, use focal loss instead of BCE.
    node_pos_weight: float
        Positive class weight for node task (handle imbalance).
    edge_pos_weight: float
        Positive class weight for edge task.
    graph_pos_weight: float
        Positive class weight for graph task.
    """

    def __init__(
        self,
        node_loss_weight: float = 1.0,
        edge_loss_weight: float = 0.5,
        graph_loss_weight: float = 0.3,
        l2_weight: float = 1e-4,
        focal_gamma: float = 0.0,
        node_pos_weight: float = 1.0,
        edge_pos_weight: float = 1.0,
        graph_pos_weight: float = 1.0,
    ) -> None:
        _require_torch()
        super().__init__()
        self.node_w = node_loss_weight
        self.edge_w = edge_loss_weight
        self.graph_w = graph_loss_weight
        self.l2_w = l2_weight
        self.focal_gamma = focal_gamma

        if focal_gamma > 0:
            self._node_loss = FocalLoss(focal_gamma, node_pos_weight)
            self._edge_loss = FocalLoss(focal_gamma, edge_pos_weight)
            self._graph_loss = FocalLoss(focal_gamma, graph_pos_weight)
        else:
            self._node_loss = WeightedBCELoss(node_pos_weight)
            self._edge_loss = WeightedBCELoss(edge_pos_weight)
            self._graph_loss = WeightedBCELoss(graph_pos_weight)

    def forward(
        self,
        node_logits: "torch.Tensor | None",    # [N] node raw logits
        node_targets: "torch.Tensor | None",   # [N] float 0/1
        edge_logits: "torch.Tensor | None",    # [E]
        edge_targets: "torch.Tensor | None",   # [E]
        graph_logits: "torch.Tensor | None",   # [1] or scalar
        graph_targets: "torch.Tensor | None",  # [1] float
        model_params: "list[torch.Tensor] | None" = None,
    ) -> "tuple[torch.Tensor, dict[str, float]]":
        """Compute total loss and return (loss_tensor, breakdown_dict)."""
        import torch

        device = None
        for tensor in (node_logits, edge_logits, graph_logits):
            if tensor is not None:
                device = tensor.device
                break
        total = torch.tensor(0.0, device=device, requires_grad=True)
        breakdown: dict[str, float] = {}

        if node_logits is not None and node_targets is not None and node_targets.numel() > 0:
            node_loss = self._node_loss(node_logits, node_targets)
            total = total + self.node_w * node_loss
            breakdown["node_loss"] = float(node_loss.item())
        else:
            breakdown["node_loss"] = 0.0

        if edge_logits is not None and edge_targets is not None and edge_targets.numel() > 0:
            edge_loss = self._edge_loss(edge_logits, edge_targets)
            total = total + self.edge_w * edge_loss
            breakdown["edge_loss"] = float(edge_loss.item())
        else:
            breakdown["edge_loss"] = 0.0

        if graph_logits is not None and graph_targets is not None and graph_targets.numel() > 0:
            graph_loss = self._graph_loss(graph_logits, graph_targets)
            total = total + self.graph_w * graph_loss
            breakdown["graph_loss"] = float(graph_loss.item())
        else:
            breakdown["graph_loss"] = 0.0

        if model_params and self.l2_w > 0:
            l2 = sum(p.pow(2).sum() for p in model_params)
            total = total + self.l2_w * l2
            breakdown["l2_reg"] = float(l2.item())
        else:
            breakdown["l2_reg"] = 0.0

        breakdown["total_loss"] = float(total.item())
        return total, breakdown


def compute_pos_weight(labels: list[int]) -> float:
    """Compute positive class weight for BCE from a label list."""
    n_pos = sum(labels)
    n_neg = len(labels) - n_pos
    if n_pos == 0 or n_neg == 0:
        return 1.0
    return n_neg / n_pos
