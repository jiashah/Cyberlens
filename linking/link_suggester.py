import sys
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parents[1]
for sub in ("models", "scoring"):
    sys.path.insert(0, str(ROOT / sub))
from gcn import GCNBaseline, edge_weight_from_edge_attr  # noqa: E402
from gat import GATBaseline  # noqa: E402
from project_config import PROJECT_ROOT  # noqa: E402


def load_link_model(cfg, input_dim):
    lc = cfg.get("link_suggestions", {})
    if not lc.get("enabled"):
        return None, "link suggestions disabled in config"
    path = PROJECT_ROOT / lc["checkpoint"]
    if not path.exists():
        return None, f"link-prediction checkpoint not found: {lc['checkpoint']}"
    ck = torch.load(path, weights_only=False)
    c = ck["config"]
    if c["input_dim"] != input_dim:
        return None, (f"link checkpoint expects {c['input_dim']} features, got {input_dim} "
                      "(vocabulary changed) - retrain link prediction")
    if ck["encoder_kind"] == "gcn":
        model = GCNBaseline(c["input_dim"], c["hidden_dim"], c["embedding_dim"], c["num_layers"], c["dropout"])
    else:
        model = GATBaseline(c["input_dim"], c["hidden_dim"], c["embedding_dim"], c["num_layers"],
                            c["heads"], c["dropout"], c["edge_dim"])
    model.load_state_dict(ck["state_dict"]); model.eval()
    model.kind = ck["encoder_kind"]
    return model, ck["encoder_kind"]


def suggest_links(data, graph, model, cfg):
    lc = cfg["link_suggestions"]
    with torch.no_grad():
        z = (model(data.x, data.edge_index, edge_weight_from_edge_attr(data.edge_attr))
             if model.kind == "gcn" else model(data.x, data.edge_index, data.edge_attr))
        prob = torch.sigmoid(z @ z.T)
    ids = list(data.node_ids)
    pos = {nid: i for i, nid in enumerate(ids)}
    linked = {frozenset((pos[e["source"]], pos[e["target"]])) for e in graph["edges"]
              if e["source"] in pos and e["target"] in pos}
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    out = {nid: [] for nid in ids}
    for i in range(len(ids)):
        for j in range(i + 1, len(ids)):
            p = float(prob[i, j])
            if p >= lc["min_probability"] and frozenset((i, j)) not in linked:
                for a, b in ((i, j), (j, i)):
                    out[ids[a]].append({"node_id": ids[b], "name": nodes[ids[b]]["name"],
                                        "vuln_type": nodes[ids[b]]["F"]["T"], "probability": round(p, 3)})
    for nid in out:
        out[nid] = sorted(out[nid], key=lambda s: -s["probability"])[: lc["max_per_vuln"]]
    return out
