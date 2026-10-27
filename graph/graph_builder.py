import argparse
import json
import os
import sys
from collections import Counter
from datetime import datetime, timezone

from relationship_rules import build_all_edges, DEFAULT_CO_CONTEXT_TOP_K

try:
    import networkx as nx
    HAVE_NETWORKX = True
except ImportError:
    HAVE_NETWORKX = False


def build_nodes(normalized_findings: list) -> list:
    nodes = []
    for i, nf in enumerate(normalized_findings, start=1):
        node_id = f"VULN_{i:03d}"
        f = nf["F"]
        nodes.append({
            "node_id": node_id,
            "original_id": nf.get("id"),
            "name": nf.get("name"),
            "description": nf.get("description"),
            "target": nf.get("target"),
            "timestamp": nf.get("timestamp"),
            "F": f,
        })
    return nodes


def compute_graph_stats(nodes: list, edges: list) -> dict:
    edge_type_counts = Counter(e["type"] for e in edges)
    connected_node_ids = {e["source"] for e in edges} | {e["target"] for e in edges}
    isolated_nodes = [n["node_id"] for n in nodes if n["node_id"] not in connected_node_ids]

    stats = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "edge_count_by_type": dict(edge_type_counts),
        "isolated_node_count": len(isolated_nodes),
        "isolated_node_ids": isolated_nodes,
    }

    if HAVE_NETWORKX:
        g = nx.MultiDiGraph()
        for n in nodes:
            g.add_node(n["node_id"])
        for e in edges:
            g.add_edge(e["source"], e["target"], type=e["type"], weight=e["weight"])

        undirected = g.to_undirected()
        components = list(nx.connected_components(undirected))
        degrees = dict(g.degree())
        stats["networkx_check"] = {
            "connected_component_count": len(components),
            "largest_component_size": max((len(c) for c in components), default=0),
            "max_node_degree": max(degrees.values(), default=0),
            "avg_node_degree": round(sum(degrees.values()) / len(degrees), 2) if degrees else 0,
        }
    else:
        stats["networkx_check"] = None

    return stats


def build_graph(normalized_data: dict, source_file: str,
                 co_context_top_k: int = DEFAULT_CO_CONTEXT_TOP_K) -> dict:
    normalized_findings = normalized_data.get("normalized_findings", [])
    nodes = build_nodes(normalized_findings)
    edges = build_all_edges(nodes, co_context_top_k=co_context_top_k)
    stats = compute_graph_stats(nodes, edges)

    return {
        "graph_metadata": {
            "source_file": source_file,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "schema": "G = (V, E, X, W) -- V: vulnerability nodes only; "
                      "E: chaining | co_context | shared_root_cause; "
                      "X: per-node F_i attributes (T,S,A,L,C,W,E); "
                      "W: per-edge 'weight' field",
            "co_context_top_k": co_context_top_k,
            "networkx_representation": "MultiDiGraph (Multi: a pair may carry edges of "
                      "several different types; Directed: chaining is directional, "
                      "co_context/shared_root_cause are symmetric but stored once and "
                      "treated as undirected via to_undirected() for connectivity checks)",
            "pyg_directionality_plan": "chaining -> single (source,target) edge_index entry; "
                      "co_context / shared_root_cause -> expanded to both (source,target) and "
                      "(target,source) entries at PyG conversion time (Phase 4, not yet implemented)",
            **stats,
        },
        "nodes": nodes,
        "edges": edges,
    }


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens Phase 2 - build the vulnerability graph from normalized findings."
    )
    parser.add_argument(
        "--input", default="outputs/normalized_findings.json",
        help="Path to normalized findings JSON from Phase 1 (default: outputs/normalized_findings.json)",
    )
    parser.add_argument(
        "--output", default="outputs/vulnerability_graph.json",
        help="Path to write the vulnerability graph JSON (default: outputs/vulnerability_graph.json)",
    )
    parser.add_argument(
        "--co-context-top-k", type=int, default=DEFAULT_CO_CONTEXT_TOP_K, dest="co_context_top_k",
        help=f"Max Tier-3 ('same asset only') co-context neighbors per node "
             f"(default: {DEFAULT_CO_CONTEXT_TOP_K}). Does not affect Tier 1 (same target) "
             f"or Tier 2 (same asset+layer), which are exhaustive within their tier.",
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        print("Hint: run normalization/normalizer.py first (Phase 1).", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        normalized_data = json.load(f)

    graph = build_graph(normalized_data, source_file=args.input, co_context_top_k=args.co_context_top_k)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(graph, f, indent=2)

    meta = graph["graph_metadata"]
    print(f"Built graph from {args.input}  (co_context_top_k={args.co_context_top_k})")
    print(f"Nodes: {meta['node_count']}   Edges: {meta['edge_count']}  {meta['edge_count_by_type']}")
    if meta["isolated_node_count"]:
        print(f"WARNING: {meta['isolated_node_count']} isolated node(s) with no edges: "
              f"{meta['isolated_node_ids']}")
    if meta.get("networkx_check"):
        nc = meta["networkx_check"]
        print(f"NetworkX check: {nc['connected_component_count']} connected component(s), "
              f"largest={nc['largest_component_size']}, "
              f"max_degree={nc['max_node_degree']}, avg_degree={nc['avg_node_degree']}")
    else:
        print("NetworkX not installed -- skipped connectivity sanity check "
              "(install with: pip install networkx)")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
