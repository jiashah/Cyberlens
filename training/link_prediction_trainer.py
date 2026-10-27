import argparse
import hashlib
import json
import os
import random
import sys

import torch
import torch.nn.functional as F
from torch_geometric.data import Data, Batch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "models"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "pyg"))
from gcn import GCNBaseline, edge_weight_from_edge_attr  # noqa: E402
from gat import GATBaseline  # noqa: E402
from pyg_converter import EDGE_TYPE_VOCAB, SYMMETRIC_EDGE_TYPES  # noqa: E402

DATASETS = [
    "sample_scan_output", "bwapp_all_layers", "crapi_full_scan",
    "dvga_all_layers", "dvwa_all_layers", "multillidae_scan",
    "nodegoat_all_layers", "owasp_juice_shop_scan",
    "security_shepherd_all_layers", "vulnerableapp_full_scan",
    "webgoat_all_layers",
]


def set_seed(seed: int):
    random.seed(seed)
    torch.manual_seed(seed)


def _deterministic_seed(*parts) -> int:
    s = "|".join(str(p) for p in parts)
    return int(hashlib.md5(s.encode()).hexdigest(), 16) & 0xffffffff


# ---------------------------------------------------------------------------
# Loading + logical-edge splitting
# ---------------------------------------------------------------------------
def load_graph_and_features(graph_path: str, features_path: str):
    with open(graph_path) as f:
        graph = json.load(f)
    with open(features_path) as f:
        features = json.load(f)
    node_ids = [n["node_id"] for n in graph["nodes"]]
    node_index = {nid: i for i, nid in enumerate(node_ids)}
    feat_by_id = {r["node_id"]: r["features"] for r in features["node_features"]}
    x = torch.tensor([feat_by_id[nid] for nid in node_ids], dtype=torch.float)
    return graph, node_ids, node_index, x


def split_logical_edges(edges: list, val_ratio: float, test_ratio: float, seed: int):
    rng = random.Random(seed)
    shuffled = list(edges)
    rng.shuffle(shuffled)

    if len(shuffled) < 6:
        return shuffled, [], []

    n = len(shuffled)
    n_test = max(1, round(n * test_ratio))
    n_val = max(1, round(n * val_ratio))
    test = shuffled[:n_test]
    val = shuffled[n_test:n_test + n_val]
    train = shuffled[n_test + n_val:]
    return train, val, test


def expand_edges_locally(edges: list, node_index: dict):
    
    src, dst, edge_types, weights = [], [], [], []
    for e in edges:
        if e["source"] not in node_index or e["target"] not in node_index:
            continue
        s, t = node_index[e["source"]], node_index[e["target"]]
        etype = e["type"]
        if etype not in EDGE_TYPE_VOCAB:
            continue
        src.append(s); dst.append(t); edge_types.append(etype); weights.append(e["weight"])
        if etype in SYMMETRIC_EDGE_TYPES:
            src.append(t); dst.append(s); edge_types.append(etype); weights.append(e["weight"])

    edge_index = torch.tensor([src, dst], dtype=torch.long) if src else torch.empty((2, 0), dtype=torch.long)
    edge_attr_rows = [
        [1.0 if et == v else 0.0 for v in EDGE_TYPE_VOCAB] + [float(w)]
        for et, w in zip(edge_types, weights)
    ]
    edge_attr = (torch.tensor(edge_attr_rows, dtype=torch.float) if edge_attr_rows
                 else torch.empty((0, len(EDGE_TYPE_VOCAB) + 1), dtype=torch.float))
    return edge_index, edge_attr


def sample_negative_pairs(num_nodes: int, forbidden_pairs: set, count: int, seed: int):
    
    rng = random.Random(seed)
    negatives = []
    attempts = 0
    max_attempts = count * 50 + 100
    while len(negatives) < count and attempts < max_attempts and num_nodes >= 2:
        i = rng.randrange(num_nodes)
        j = rng.randrange(num_nodes)
        attempts += 1
        if i == j:
            continue
        pair = (i, j)
        if pair in forbidden_pairs or (j, i) in forbidden_pairs:
            continue
        negatives.append(pair)
        forbidden_pairs.add(pair)
    return negatives


# ---------------------------------------------------------------------------
# Per-dataset preparation
# ---------------------------------------------------------------------------
class PreparedGraph:
    def __init__(self, name, x, train_edge_index, train_edge_attr,
                 pos_pairs, neg_pairs):
        self.name = name
        self.data = Data(x=x, edge_index=train_edge_index, edge_attr=train_edge_attr)
        self.pos_pairs = pos_pairs
        self.neg_pairs = neg_pairs


def prepare_dataset(name: str, val_ratio: float, test_ratio: float, seed: int) -> PreparedGraph:
    graph_path = f"outputs/graph_{name}.json"
    features_path = f"outputs/features_{name}.json"
    graph, node_ids, node_index, x = load_graph_and_features(graph_path, features_path)

    train_e, val_e, test_e = split_logical_edges(graph["edges"], val_ratio, test_ratio, seed)
    train_edge_index, train_edge_attr = expand_edges_locally(train_e, node_index)

    def local_pairs(edges):
        return [(node_index[e["source"]], node_index[e["target"]]) for e in edges
                if e["source"] in node_index and e["target"] in node_index]

    pos = {"train": local_pairs(train_e), "val": local_pairs(val_e), "test": local_pairs(test_e)}

    all_logical_pairs = set()
    for split_edges in (train_e, val_e, test_e):
        for e in split_edges:
            if e["source"] in node_index and e["target"] in node_index:
                all_logical_pairs.add((node_index[e["source"]], node_index[e["target"]]))
                all_logical_pairs.add((node_index[e["target"]], node_index[e["source"]]))

    neg = {}
    for split_name, positives in pos.items():
        neg[split_name] = sample_negative_pairs(
            len(node_ids), set(all_logical_pairs), len(positives), seed=_deterministic_seed(name, split_name, seed)
        )

    return PreparedGraph(name, x, train_edge_index, train_edge_attr, pos, neg)


def combine_datasets(prepared: list):
    batch = Batch.from_data_list([p.data for p in prepared])
    offsets = batch.ptr[:-1].tolist()

    global_pos = {"train": [], "val": [], "test": []}
    global_neg = {"train": [], "val": [], "test": []}
    for p, offset in zip(prepared, offsets):
        for split in ("train", "val", "test"):
            global_pos[split].extend((i + offset, j + offset) for i, j in p.pos_pairs[split])
            global_neg[split].extend((i + offset, j + offset) for i, j in p.neg_pairs[split])

    return batch, global_pos, global_neg


# ---------------------------------------------------------------------------
# Model wrapper: encoder (GCN or GAT) + parameter-free dot-product decoder
# ---------------------------------------------------------------------------
def encode(model, encoder_kind: str, data: Data):
    if encoder_kind == "gcn":
        ew = edge_weight_from_edge_attr(data.edge_attr)
        return model(data.x, data.edge_index, ew)
    else:
        return model(data.x, data.edge_index, data.edge_attr)


def decode(z: torch.Tensor, pairs: list) -> torch.Tensor:
    if not pairs:
        return torch.empty(0)
    idx = torch.tensor(pairs, dtype=torch.long)
    return (z[idx[:, 0]] * z[idx[:, 1]]).sum(dim=-1)


def bce_loss(pos_scores: torch.Tensor, neg_scores: torch.Tensor) -> torch.Tensor:
    scores = torch.cat([pos_scores, neg_scores])
    labels = torch.cat([torch.ones_like(pos_scores), torch.zeros_like(neg_scores)])
    return F.binary_cross_entropy_with_logits(scores, labels)


def compute_auc_ap(pos_scores: torch.Tensor, neg_scores: torch.Tensor):
    scores = torch.cat([pos_scores, neg_scores]).detach()
    labels = torch.cat([torch.ones_like(pos_scores), torch.zeros_like(neg_scores)]).detach()
    if labels.sum() == 0 or labels.sum() == len(labels):
        return float("nan"), float("nan")

    order = torch.argsort(scores, descending=True)
    labels_sorted = labels[order]

    n_pos = int(labels.sum().item())
    n_neg = len(labels) - n_pos
    ranks = torch.argsort(torch.argsort(scores)).float() + 1
    sum_ranks_pos = ranks[labels == 1].sum()
    auc = (sum_ranks_pos - n_pos * (n_pos + 1) / 2) / (n_pos * n_neg)

    cum_tp = torch.cumsum(labels_sorted, dim=0)
    precision_at_k = cum_tp / torch.arange(1, len(labels_sorted) + 1, dtype=torch.float)
    ap = (precision_at_k * labels_sorted).sum() / n_pos

    return float(auc), float(ap)


# ---------------------------------------------------------------------------
# Training loop
# ---------------------------------------------------------------------------
def train(encoder_kind: str, hidden_dim: int, embedding_dim: int, num_layers: int,
          heads: int, dropout: float, lr: float, epochs: int, patience: int,
          val_ratio: float, test_ratio: float, seed: int, checkpoint_path: str):
    set_seed(seed)

    prepared = [prepare_dataset(name, val_ratio, test_ratio, seed) for name in DATASETS]
    for p in prepared:
        print(f"  {p.name}: train={len(p.pos_pairs['train'])} val={len(p.pos_pairs['val'])} "
              f"test={len(p.pos_pairs['test'])} logical edges "
              f"({'all-train, too few edges to split' if not p.pos_pairs['val'] and not p.pos_pairs['test'] else 'split'})")

    batch, pos, neg = combine_datasets(prepared)
    print(f"Combined graph: {batch.num_nodes} nodes (block-diagonal across {len(prepared)} datasets), "
          f"{batch.edge_index.shape[1]} directed train edges")
    print(f"Positive pairs -- train: {len(pos['train'])}  val: {len(pos['val'])}  test: {len(pos['test'])}")
    print(f"Negative pairs -- train: {len(neg['train'])}  val: {len(neg['val'])}  test: {len(neg['test'])}")

    input_dim = batch.num_node_features
    edge_dim = batch.edge_attr.shape[1] if batch.edge_attr is not None and batch.edge_attr.numel() else 4

    if encoder_kind == "gcn":
        model = GCNBaseline(input_dim=input_dim, hidden_dim=hidden_dim, output_dim=embedding_dim,
                             num_layers=num_layers, dropout=dropout)
    elif encoder_kind == "gat":
        model = GATBaseline(input_dim=input_dim, hidden_dim=hidden_dim, output_dim=embedding_dim,
                             num_layers=num_layers, heads=heads, dropout=dropout, edge_dim=edge_dim)
    else:
        raise ValueError(f"Unknown encoder '{encoder_kind}', expected 'gcn' or 'gat'")

    optimizer = torch.optim.Adam(model.parameters(), lr=lr)

    best_val_auc = -1.0
    best_state = None
    epochs_without_improvement = 0
    history = []

    have_val = len(pos["val"]) > 0

    for epoch in range(1, epochs + 1):
        model.train()
        optimizer.zero_grad()
        z = encode(model, encoder_kind, batch)
        pos_scores = decode(z, pos["train"])
        neg_scores = decode(z, neg["train"])
        loss = bce_loss(pos_scores, neg_scores)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            z_eval = encode(model, encoder_kind, batch)
            train_auc, train_ap = compute_auc_ap(decode(z_eval, pos["train"]), decode(z_eval, neg["train"]))
            if have_val:
                val_auc, val_ap = compute_auc_ap(decode(z_eval, pos["val"]), decode(z_eval, neg["val"]))
            else:
                val_auc, val_ap = float("nan"), float("nan")

        history.append({"epoch": epoch, "train_loss": float(loss.item()),
                         "train_auc": train_auc, "train_ap": train_ap,
                         "val_auc": val_auc, "val_ap": val_ap})

        if epoch % max(1, epochs // 10) == 0 or epoch == 1:
            print(f"  epoch {epoch:4d}  loss={loss.item():.4f}  train_auc={train_auc:.3f}  "
                  f"val_auc={val_auc if have_val else float('nan'):.3f}")

        monitor_metric = val_auc if have_val else train_auc
        if monitor_metric > best_val_auc:
            best_val_auc = monitor_metric
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
            epochs_without_improvement = 0
        else:
            epochs_without_improvement += 1
            if epochs_without_improvement >= patience:
                print(f"  early stopping at epoch {epoch} (no improvement in "
                      f"{patience} epochs on {'val' if have_val else 'train'} AUC)")
                break

    if best_state is not None:
        model.load_state_dict(best_state)
        os.makedirs(os.path.dirname(checkpoint_path) or ".", exist_ok=True)
        torch.save({"encoder_kind": encoder_kind, "state_dict": best_state,
                    "config": {"input_dim": input_dim, "hidden_dim": hidden_dim,
                               "embedding_dim": embedding_dim, "num_layers": num_layers,
                               "heads": heads, "dropout": dropout, "edge_dim": edge_dim}},
                   checkpoint_path)
        print(f"Saved best checkpoint ({'val' if have_val else 'train'}_auc={best_val_auc:.3f}) to {checkpoint_path}")

    model.eval()
    with torch.no_grad():
        z_final = encode(model, encoder_kind, batch)
        test_auc, test_ap = compute_auc_ap(decode(z_final, pos["test"]), decode(z_final, neg["test"]))

    return {
        "encoder": encoder_kind,
        "config": {"hidden_dim": hidden_dim, "embedding_dim": embedding_dim, "num_layers": num_layers,
                   "heads": heads if encoder_kind == "gat" else None, "dropout": dropout,
                   "lr": lr, "seed": seed, "epochs_run": len(history)},
        "parameter_count": sum(p.numel() for p in model.parameters()),
        "best_val_auc": best_val_auc if have_val else None,
        "test_auc": test_auc, "test_ap": test_ap,
        "test_pair_counts": {"positive": len(pos["test"]), "negative": len(neg["test"])},
        "history": history,
        "dataset_split_summary": [
            {"name": p.name, "train": len(p.pos_pairs["train"]), "val": len(p.pos_pairs["val"]),
             "test": len(p.pos_pairs["test"])}
            for p in prepared
        ],
    }


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens relationship-prediction training for GCN/GAT."
    )
    parser.add_argument("--encoder", choices=["gcn", "gat"], required=True)
    parser.add_argument("--hidden-dim", type=int, default=32)
    parser.add_argument("--embedding-dim", type=int, default=16)
    parser.add_argument("--num-layers", type=int, default=2)
    parser.add_argument("--heads", type=int, default=4, help="GAT only")
    parser.add_argument("--dropout", type=float, default=0.3)
    parser.add_argument("--lr", type=float, default=0.01)
    parser.add_argument("--epochs", type=int, default=200)
    parser.add_argument("--patience", type=int, default=30)
    parser.add_argument("--val-ratio", type=float, default=0.15)
    parser.add_argument("--test-ratio", type=float, default=0.15)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--checkpoint", default=None,
                         help="Default: outputs/checkpoint_<encoder>.pt")
    parser.add_argument("--results-output", default=None,
                         help="Default: outputs/training_results_<encoder>.json")
    args = parser.parse_args()

    checkpoint_path = args.checkpoint or f"outputs/checkpoint_{args.encoder}.pt"
    results_path = args.results_output or f"outputs/training_results_{args.encoder}.json"

    print(f"=== Phase 8: self-supervised link-prediction training -- encoder={args.encoder} ===")
    print(f"Datasets: {DATASETS}")
    print(f"Seed: {args.seed}  (reproducible: same seed -> same split, same negatives, same init)")
    print()

    results = train(
        encoder_kind=args.encoder, hidden_dim=args.hidden_dim, embedding_dim=args.embedding_dim,
        num_layers=args.num_layers, heads=args.heads, dropout=args.dropout, lr=args.lr,
        epochs=args.epochs, patience=args.patience, val_ratio=args.val_ratio,
        test_ratio=args.test_ratio, seed=args.seed, checkpoint_path=checkpoint_path,
    )

    os.makedirs(os.path.dirname(results_path) or ".", exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(results, f, indent=2)

    print()
    print(f"=== Results ({args.encoder}) ===")
    print(f"Parameter count: {results['parameter_count']:,}")
    print(f"Best val AUC during training: {results['best_val_auc']}")
    print(f"Test AUC: {results['test_auc']:.4f}   Test AP: {results['test_ap']:.4f}   "
          f"(test pairs: {results['test_pair_counts']})")
    print(f"Wrote {checkpoint_path}")
    print(f"Wrote {results_path}")


if __name__ == "__main__":
    main()
