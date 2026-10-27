import argparse

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GCNConv


class GCNBaseline(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 32, output_dim: int = 16,
                 num_layers: int = 2, dropout: float = 0.5):
        super().__init__()
        if num_layers < 1:
            raise ValueError("num_layers must be >= 1")

        self.dropout = dropout
        self.convs = nn.ModuleList()

        if num_layers == 1:
            self.convs.append(GCNConv(input_dim, output_dim))
        else:
            self.convs.append(GCNConv(input_dim, hidden_dim))
            for _ in range(num_layers - 2):
                self.convs.append(GCNConv(hidden_dim, hidden_dim))
            self.convs.append(GCNConv(hidden_dim, output_dim))

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_weight: torch.Tensor = None) -> torch.Tensor:
        h = x
        for i, conv in enumerate(self.convs):
            h = conv(h, edge_index, edge_weight)
            is_last = (i == len(self.convs) - 1)
            if not is_last:
                h = F.relu(h)
                h = F.dropout(h, p=self.dropout, training=self.training)
        return h


def edge_weight_from_edge_attr(edge_attr: torch.Tensor) -> torch.Tensor:
    if edge_attr is None or edge_attr.numel() == 0:
        return None
    return edge_attr[:, -1].contiguous()


def _smoke_test(data_path: str, hidden_dim: int, output_dim: int,
                 num_layers: int, dropout: float):
    data = torch.load(data_path, weights_only=False)

    model = GCNBaseline(
        input_dim=data.num_node_features,
        hidden_dim=hidden_dim,
        output_dim=output_dim,
        num_layers=num_layers,
        dropout=dropout,
    )
    model.eval()  

    edge_weight = edge_weight_from_edge_attr(data.edge_attr)

    with torch.no_grad():
        out = model(data.x, data.edge_index, edge_weight)

    print(f"Loaded {data_path}: {data}")
    print(f"Model: input_dim={data.num_node_features} hidden_dim={hidden_dim} "
          f"output_dim={output_dim} num_layers={num_layers} dropout={dropout}")
    print(f"Forward pass output shape: {tuple(out.shape)}  "
          f"(expected: ({data.num_nodes}, {output_dim}))")
    print(f"Output contains NaN: {bool(torch.isnan(out).any())}   "
          f"contains Inf: {bool(torch.isinf(out).any())}")
    print(f"Output value range: [{out.min().item():.4f}, {out.max().item():.4f}]")
    print("This is an untrained, architecture-only forward pass -- the numbers above "
          "confirm the model and data shapes are compatible, not that they mean anything "
          "yet. Training happens in Phase 8, once Phase 7 defines a real target.")


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens Phase 5 - GCN baseline architecture smoke test on a real PyG Data object."
    )
    parser.add_argument("--data", default="outputs/pyg_data.pt",
                         help="Path to a PyG Data .pt file from Phase 4.")
    parser.add_argument("--hidden-dim", type=int, default=32)
    parser.add_argument("--output-dim", type=int, default=16)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--dropout", type=float, default=0.5)
    args = parser.parse_args()

    _smoke_test(args.data, args.hidden_dim, args.output_dim, args.num_layers, args.dropout)


if __name__ == "__main__":
    main()
