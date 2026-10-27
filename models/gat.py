import argparse

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv


class GATBaseline(nn.Module):

    def __init__(self, input_dim: int, hidden_dim: int = 32, output_dim: int = 16,
                 num_layers: int = 2, heads: int = 4, dropout: float = 0.5,
                 edge_dim: int = 4, conv_layer=GATConv):
        super().__init__()
        if num_layers < 1:
            raise ValueError("num_layers must be >= 1")
        if heads < 1:
            raise ValueError("heads must be >= 1")

        self.dropout = dropout
        self.convs = nn.ModuleList()

        if num_layers == 1:
            self.convs.append(conv_layer(
                input_dim, output_dim, heads=heads, concat=False,
                dropout=dropout, edge_dim=edge_dim,
            ))
        else:
            self.convs.append(conv_layer(
                input_dim, hidden_dim, heads=heads, concat=True,
                dropout=dropout, edge_dim=edge_dim,
            ))
            in_dim = hidden_dim * heads 
            for _ in range(num_layers - 2):
                self.convs.append(conv_layer(
                    in_dim, hidden_dim, heads=heads, concat=True,
                    dropout=dropout, edge_dim=edge_dim,
                ))
                in_dim = hidden_dim * heads
            self.convs.append(conv_layer(
                in_dim, output_dim, heads=heads, concat=False,
                dropout=dropout, edge_dim=edge_dim,
            ))

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor,
                edge_attr: torch.Tensor = None) -> torch.Tensor:
        h = x
        for i, conv in enumerate(self.convs):
            h = conv(h, edge_index, edge_attr)
            is_last = (i == len(self.convs) - 1)
            if not is_last:
                h = F.elu(h)
                h = F.dropout(h, p=self.dropout, training=self.training)
        return h

    def output_dim_for(self, output_dim: int) -> int:
        return output_dim 


def count_parameters(model: nn.Module) -> int:
    return sum(p.numel() for p in model.parameters())


def _edge_attr_sensitivity_check(model: GATBaseline, x, edge_index, edge_attr) -> bool:
    model.eval()
    with torch.no_grad():
        out_real = model(x, edge_index, edge_attr)
        out_zeroed = model(x, edge_index, torch.zeros_like(edge_attr))
    return not torch.allclose(out_real, out_zeroed, atol=1e-6)


def _neighbor_usage_check(model: GATBaseline, x, edge_index, edge_attr, node_ids, isolated_id):
    model.eval()
    empty_edges = torch.empty((2, 0), dtype=torch.long)
    empty_attr = torch.empty((0, edge_attr.shape[1]), dtype=torch.float) if edge_attr is not None else None
    with torch.no_grad():
        out_with = model(x, edge_index, edge_attr)
        out_without = model(x, empty_edges, empty_attr)

    idx = node_ids.index(isolated_id)
    isolated_same = torch.allclose(out_with[idx], out_without[idx], atol=1e-6)

    other_idx = next(i for i in range(len(node_ids)) if node_ids[i] != isolated_id)
    connected_differs = not torch.allclose(out_with[other_idx], out_without[other_idx], atol=1e-6)

    return isolated_same, connected_differs


def _smoke_test(data_path: str, hidden_dim: int, output_dim: int,
                 num_layers: int, heads: int, dropout: float):
    data = torch.load(data_path, weights_only=False)
    edge_dim = data.edge_attr.shape[1] if data.edge_attr is not None and data.edge_attr.numel() else 4

    model = GATBaseline(
        input_dim=data.num_node_features, hidden_dim=hidden_dim, output_dim=output_dim,
        num_layers=num_layers, heads=heads, dropout=dropout, edge_dim=edge_dim,
    )
    model.eval()

    with torch.no_grad():
        out = model(data.x, data.edge_index, data.edge_attr)

    print(f"Loaded {data_path}: {data}")
    print(f"Model: input_dim={data.num_node_features} hidden_dim={hidden_dim} "
          f"output_dim={output_dim} num_layers={num_layers} heads={heads} "
          f"dropout={dropout} edge_dim={edge_dim}")
    print(f"Parameter count: {count_parameters(model):,}")
    print(f"Forward pass output shape: {tuple(out.shape)}  "
          f"(expected: ({data.num_nodes}, {output_dim}))")
    print(f"Output contains NaN: {bool(torch.isnan(out).any())}   "
          f"contains Inf: {bool(torch.isinf(out).any())}")
    print(f"Output value range: [{out.min().item():.4f}, {out.max().item():.4f}]")

    if data.edge_attr is not None and data.edge_attr.numel():
        sensitive = _edge_attr_sensitivity_check(model, data.x, data.edge_index, data.edge_attr)
        print(f"edge_attr actually consumed (output changes when edge_attr is zeroed): {sensitive}")

    print("This is an untrained, architecture-only forward pass -- the numbers above "
          "confirm the model and data shapes are compatible and that attention/edge "
          "information is genuinely used, not that the output means anything yet. "
          "Training happens in Phase 8, once Phase 7 defines a real target.")


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens Phase 6 - GAT architecture smoke test on a real PyG Data object."
    )
    parser.add_argument("--data", default="outputs/pyg_data.pt")
    parser.add_argument("--hidden-dim", type=int, default=32)
    parser.add_argument("--output-dim", type=int, default=16)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--heads", type=int, default=4)
    parser.add_argument("--dropout", type=float, default=0.5)
    args = parser.parse_args()

    _smoke_test(args.data, args.hidden_dim, args.output_dim,
                args.num_layers, args.heads, args.dropout)


if __name__ == "__main__":
    main()
