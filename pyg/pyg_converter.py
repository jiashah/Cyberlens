import argparse
import json
import os
import sys

import torch
from torch_geometric.data import Data

EDGE_TYPE_VOCAB = ["chaining", "co_context", "shared_root_cause"]

SYMMETRIC_EDGE_TYPES = {"co_context", "shared_root_cause"}


def _load_json(path: str, hint: str) -> dict:
    if not os.path.exists(path):
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        print(hint, file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def build_pyg_data(graph: dict, features: dict):
    warnings = []
    nodes = graph.get("nodes", [])
    node_ids = [n["node_id"] for n in nodes]
    node_index = {nid: i for i, nid in enumerate(node_ids)} 

    feat_by_id = {row["node_id"]: row["features"] for row in features.get("node_features", [])}

    missing = [nid for nid in node_ids if nid not in feat_by_id]
    if missing:
        raise ValueError(
            f"{len(missing)} node(s) from the graph have no matching feature vector "
            f"in {features!r} -- graph and features files are out of sync. "
            f"Missing: {missing[:5]}{'...' if len(missing) > 5 else ''}"
        )
    extra = [nid for nid in feat_by_id if nid not in node_index]
    if extra:
        warnings.append(f"{len(extra)} feature row(s) reference node ids not present in "
                         f"the graph -- ignored: {extra[:5]}{'...' if len(extra) > 5 else ''}")

    feature_dim = features["feature_metadata"]["feature_dim"]
    x = torch.tensor([feat_by_id[nid] for nid in node_ids], dtype=torch.float)
    assert x.shape == (len(node_ids), feature_dim), \
        f"x shape {tuple(x.shape)} does not match expected ({len(node_ids)}, {feature_dim})"

    src, dst, edge_types, edge_weights = [], [], [], []
    for e in graph.get("edges", []):
        if e["source"] not in node_index or e["target"] not in node_index:
            warnings.append(f"Edge {e['source']}->{e['target']} references an unknown node id "
                             f"-- skipped.")
            continue
        s, t = node_index[e["source"]], node_index[e["target"]]
        etype = e["type"]
        if etype not in EDGE_TYPE_VOCAB:
            warnings.append(f"Unrecognized edge type '{etype}' on edge "
                             f"{e['source']}->{e['target']} -- skipped (not in {EDGE_TYPE_VOCAB}).")
            continue

        src.append(s); dst.append(t); edge_types.append(etype); edge_weights.append(e["weight"])

        if etype in SYMMETRIC_EDGE_TYPES:
            src.append(t); dst.append(s); edge_types.append(etype); edge_weights.append(e["weight"])

    edge_index = torch.tensor([src, dst], dtype=torch.long) if src else torch.empty((2, 0), dtype=torch.long)

    edge_attr_rows = []
    for etype, w in zip(edge_types, edge_weights):
        onehot = [1.0 if etype == v else 0.0 for v in EDGE_TYPE_VOCAB]
        edge_attr_rows.append(onehot + [float(w)])
    edge_attr = (torch.tensor(edge_attr_rows, dtype=torch.float) if edge_attr_rows
                 else torch.empty((0, len(EDGE_TYPE_VOCAB) + 1), dtype=torch.float))

    data = Data(x=x, edge_index=edge_index, edge_attr=edge_attr, y=None)

    data.node_ids = node_ids

    return data, node_index, warnings


def summarize(data: Data, node_index: dict, graph_meta: dict, features_meta: dict,
              source_graph: str, source_features: str, warnings: list) -> dict:
    type_counts = {t: 0 for t in EDGE_TYPE_VOCAB}
    for row in data.edge_attr.tolist():
        onehot = row[:len(EDGE_TYPE_VOCAB)]
        etype = EDGE_TYPE_VOCAB[onehot.index(1.0)]
        type_counts[etype] += 1

    isolated = [nid for nid, idx in node_index.items()
                if idx not in data.edge_index[0].tolist() and idx not in data.edge_index[1].tolist()]

    return {
        "source_graph": source_graph,
        "source_features": source_features,
        "num_nodes": data.num_nodes,
        "feature_dim": data.num_node_features,
        "num_directed_edges_in_edge_index": data.num_edges,
        "directed_edge_count_by_type": type_counts,
        "edge_attr_dim": data.edge_attr.shape[1] if data.edge_attr is not None else 0,
        "edge_attr_layout": EDGE_TYPE_VOCAB + ["weight"],
        "symmetric_edge_types_expanded_to_both_directions": sorted(SYMMETRIC_EDGE_TYPES),
        "directional_edge_types_kept_single_direction": [t for t in EDGE_TYPE_VOCAB if t not in SYMMETRIC_EDGE_TYPES],
        "isolated_node_ids": isolated,
        "y_status": "not set (None) -- see module docstring 'Why there is no y yet'; "
                    "requires Phase 7 (Training Target) to be done first",
        "original_graph_node_count": graph_meta.get("node_count"),
        "original_graph_edge_count": graph_meta.get("edge_count"),
        "original_graph_edge_count_by_type": graph_meta.get("edge_count_by_type"),
        "conversion_warnings": warnings,
    }


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens Phase 4 - convert the vulnerability graph + node features into a PyTorch Geometric Data object."
    )
    parser.add_argument("--graph", default="outputs/vulnerability_graph.json",
                         help="Path to the vulnerability graph JSON from Phase 2.")
    parser.add_argument("--features", default="outputs/node_features.json",
                         help="Path to the node feature matrix JSON from Phase 3.")
    parser.add_argument("--output", default="outputs/pyg_data.pt",
                         help="Path to write the serialized PyG Data object (.pt).")
    parser.add_argument("--summary-output", default="outputs/pyg_data_summary.json",
                         help="Path to write a human-readable JSON summary of the conversion.")
    args = parser.parse_args()

    graph = _load_json(args.graph, "Hint: run graph/graph_builder.py first (Phase 2).")
    features = _load_json(args.features, "Hint: run features/feature_engineering.py first (Phase 3).")

    data, node_index, warnings = build_pyg_data(graph, features)

    try:
        data.validate(raise_on_error=True)
        validation_status = "passed"
    except Exception as exc: 
        validation_status = f"FAILED: {exc}"

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    torch.save(data, args.output)

    summary = summarize(data, node_index, graph.get("graph_metadata", {}),
                         features.get("feature_metadata", {}),
                         args.graph, args.features, warnings)
    summary["pyg_validate"] = validation_status

    os.makedirs(os.path.dirname(args.summary_output) or ".", exist_ok=True)
    with open(args.summary_output, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Built PyG Data object from {args.graph} + {args.features}")
    print(f"  {data}")
    print(f"Nodes: {summary['num_nodes']}   Feature dim: {summary['feature_dim']}")
    print(f"Directed edges in edge_index: {summary['num_directed_edges_in_edge_index']}  "
          f"{summary['directed_edge_count_by_type']}")
    print(f"edge_attr dim: {summary['edge_attr_dim']}  layout: {summary['edge_attr_layout']}")
    print(f"PyG data.validate(): {validation_status}")
    if summary["isolated_node_ids"]:
        print(f"Isolated nodes (no edges either direction): {summary['isolated_node_ids']}")
    if warnings:
        print(f"WARNINGS ({len(warnings)}):")
        for w in warnings:
            print(f"  - {w}")
    print(f"Wrote {args.output}")
    print(f"Wrote {args.summary_output}")
    print(f"Note: load this file later with torch.load(path, weights_only=False) -- "
          f"PyTorch 2.6+ defaults to weights_only=True, which cannot unpickle a PyG Data object.")


if __name__ == "__main__":
    main()
