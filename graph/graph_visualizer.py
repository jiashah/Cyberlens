import argparse
import glob
import json
import os
import sys
from collections import Counter

from pyvis.network import Network

SEVERITY_COLORS = {
    "critical": "#8B0000",
    "high": "#E3342F",
    "medium": "#F6993F",
    "low": "#FFED4A",
    "info": "#A0AEC0",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

EDGE_TYPE_COLORS = {
    "chaining": "#E3342F",
    "co_context": "#3490DC",
    "shared_root_cause": "#9561E2",
}


def _load_graph(path: str) -> dict:
    if not os.path.exists(path):
        print(f"ERROR: input file not found: {path}", file=sys.stderr)
        print("Hint: run graph/graph_builder.py first (Phase 2).", file=sys.stderr)
        sys.exit(1)
    with open(path) as f:
        return json.load(f)


def _node_degrees(nodes: list, edges: list) -> dict:
    deg = {n["node_id"]: 0 for n in nodes}
    for e in edges:
        deg[e["source"]] = deg.get(e["source"], 0) + 1
        deg[e["target"]] = deg.get(e["target"], 0) + 1
    return deg


def _node_tooltip(node: dict) -> str:
    f = node["F"]
    cve = f["C"].get("cve_id") or "none"
    evidence = (f.get("W") or "")[:160]
    return (
        f"<b>{node['node_id']}</b> -- {node.get('name', '')}<br>"
        f"Type: {f['T']}<br>"
        f"Severity (scanner-reported): {f['S']}<br>"
        f"Layer: {f['L']}<br>"
        f"Asset: {f['A']}<br>"
        f"CVE: {cve}<br>"
        f"Evidence: {evidence}"
    )


def _edge_tooltip(edge: dict) -> str:
    return (
        f"<b>{edge['type']}</b> (weight {edge['weight']})<br>"
        f"{edge['source']} &rarr; {edge['target']}<br>"
        f"Reason: {edge['reason']}"
    )


LEGEND_HTML = """
<div style="position:fixed; top:12px; right:12px; background:#ffffffee; border:1px solid #ccc;
            border-radius:8px; padding:12px 16px; font-family:Arial, sans-serif; font-size:13px;
            max-width:280px; z-index:1000; box-shadow:0 2px 8px rgba(0,0,0,0.15);">
  <div style="font-weight:bold; margin-bottom:6px;">Node color -- scanner-reported severity</div>
  <div style="margin-bottom:2px;"><span style="display:inline-block;width:12px;height:12px;background:#8B0000;border-radius:50%;margin-right:6px;"></span>Critical</div>
  <div style="margin-bottom:2px;"><span style="display:inline-block;width:12px;height:12px;background:#E3342F;border-radius:50%;margin-right:6px;"></span>High</div>
  <div style="margin-bottom:2px;"><span style="display:inline-block;width:12px;height:12px;background:#F6993F;border-radius:50%;margin-right:6px;"></span>Medium</div>
  <div style="margin-bottom:2px;"><span style="display:inline-block;width:12px;height:12px;background:#FFED4A;border-radius:50%;margin-right:6px;"></span>Low</div>
  <div style="margin-bottom:8px;"><span style="display:inline-block;width:12px;height:12px;background:#A0AEC0;border-radius:50%;margin-right:6px;"></span>Info</div>
  <div style="font-weight:bold; margin-bottom:6px;">Edge color -- relationship type</div>
  <div style="margin-bottom:2px;"><span style="display:inline-block;width:20px;height:3px;background:#E3342F;margin-right:6px;"></span>Chaining (directional)</div>
  <div style="margin-bottom:2px;"><span style="display:inline-block;width:20px;height:3px;background:#3490DC;margin-right:6px;"></span>Co-context</div>
  <div style="margin-bottom:8px;"><span style="display:inline-block;width:20px;height:3px;background:#9561E2;margin-right:6px;"></span>Shared root cause</div>
  <div style="font-size:11px; color:#666;">Node size = graph degree. Edge width = relationship weight.</div>
</div>
"""


def build_visualization(graph: dict, source_path: str) -> Network:
    nodes = graph["nodes"]
    edges = graph["edges"]
    degrees = _node_degrees(nodes, edges)

    net = Network(height="800px", width="100%", directed=True, bgcolor="#ffffff",
                   font_color="#222222", notebook=False, cdn_resources="in_line")
    net.barnes_hut(gravity=-3000, central_gravity=0.3, spring_length=140, spring_strength=0.03)

    for n in nodes:
        sev = n["F"]["S"]
        color = SEVERITY_COLORS.get(sev, "#CBD5E0")
        deg = degrees.get(n["node_id"], 0)
        size = 14 + min(deg, 15) * 2
        net.add_node(
            n["node_id"],
            label=f"{n['node_id']}\n{n['F']['T']}",
            title=_node_tooltip(n),
            color=color,
            size=size,
        )

    edge_type_counts = Counter()
    for e in edges:
        etype = e["type"]
        edge_type_counts[etype] += 1
        color = EDGE_TYPE_COLORS.get(etype, "#999999")
        width = 1 + float(e["weight"]) * 4
        arrows = "to" if etype == "chaining" else ""
        net.add_edge(
            e["source"], e["target"],
            title=_edge_tooltip(e),
            color=color,
            width=width,
            arrows=arrows,
        )

    net.set_options("""
    {
      "interaction": {"hover": true, "tooltipDelay": 100},
      "physics": {"stabilization": {"iterations": 150}}
    }
    """)

    return net, edge_type_counts


def render(graph_path: str, output_path: str):
    graph = _load_graph(graph_path)
    net, edge_type_counts = build_visualization(graph, graph_path)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    html_str = net.generate_html(notebook=False)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_str)

    meta = graph.get("graph_metadata", {})
    title_bar = f"""
    <div style="position:fixed; top:12px; left:12px; background:#1F3864; color:white;
                border-radius:8px; padding:10px 16px; font-family:Arial, sans-serif;
                font-size:13px; z-index:1000; box-shadow:0 2px 8px rgba(0,0,0,0.25);">
      <b>CyberLens Vulnerability Graph</b> -- {os.path.basename(graph_path)}<br>
      {meta.get('node_count', len(graph['nodes']))} nodes,
      {meta.get('edge_count', len(graph['edges']))} edges
      ({', '.join(f"{k}: {v}" for k, v in edge_type_counts.items())})
    </div>
    """
    with open(output_path, encoding="utf-8") as f:
        html = f.read()
    html = html.replace("</body>", title_bar + LEGEND_HTML + "</body>")
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"Rendered {graph_path} -> {output_path}  "
          f"({len(graph['nodes'])} nodes, {len(graph['edges'])} edges: {dict(edge_type_counts)})")


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens Phase 12 - render an interactive HTML visualization of a vulnerability graph."
    )
    parser.add_argument("--graph", help="Path to a single outputs/graph_*.json file.")
    parser.add_argument("--output", help="Output HTML path (default: alongside input, .html extension).")
    parser.add_argument("--all", action="store_true",
                         help="Render every outputs/graph_*.json found, ignoring --graph/--output.")
    args = parser.parse_args()

    if args.all:
        paths = sorted(glob.glob("outputs/graph_*.json"))
        if not paths:
            print("No outputs/graph_*.json files found -- run graph/graph_builder.py first.", file=sys.stderr)
            sys.exit(1)
        for p in paths:
            out = p.replace(".json", ".html")
            render(p, out)
        return

    if not args.graph:
        print("Provide --graph <path> or use --all.", file=sys.stderr)
        sys.exit(1)
    output = args.output or args.graph.replace(".json", ".html")
    render(args.graph, output)


if __name__ == "__main__":
    main()
