import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import torch

ROOT = Path(__file__).resolve().parents[1]
for sub in ("training", "models", "pyg", "scoring"):
    sys.path.insert(0, str(ROOT / sub))
from score_prediction_trainer import ScoreRegressor, load_dataset, predict  # noqa: E402
from project_config import (OUTPUTS_DIR, load_score_config, discover_datasets,  # noqa: E402
                            config_fingerprint)
from risk_target import priority_tier  # noqa: E402


def load_model(ckpt_path):
    ck = torch.load(ckpt_path, weights_only=False)
    model = ScoreRegressor(ck["hparams"], ck["input_dim"], ck["edge_dim"], ck["max_score"],
                           ck["severity_prior"], ck["min_score"])
    res = model.load_state_dict(ck["state_dict"], strict=False)
    unexpected = list(res.unexpected_keys) + [k for k in res.missing_keys if k not in ("x_mean", "x_std")]
    if unexpected:
        raise RuntimeError(f"checkpoint does not match model definition: {unexpected}")
    model.eval()
    return model, ck


def build_report(name, data, graph, model, cfg, warnings=None, cvss=None, suggestions=None):
    score = dict(zip(data.node_ids, predict(model, data).tolist()))
    nodes = {n["node_id"]: n for n in graph["nodes"]}

    links = defaultdict(list)
    for e in graph["edges"]:
        links[e["source"]].append((e["target"], e))
        links[e["target"]].append((e["source"], e))

    items = []
    for nid, n in nodes.items():
        linked = []
        for other_id, e in sorted(links[nid], key=lambda le: (-le[1]["weight"], -score[le[0]])):
            o = nodes[other_id]
            linked.append({"node_id": other_id, "name": o["name"], "vuln_type": o["F"]["T"],
                           "type": e["type"], "weight": e["weight"], "reason": e["reason"],
                           "predicted_score": round(score[other_id], 2)})
        items.append({
            "node_id": nid, "name": n["name"], "type": n["F"]["T"], "layer": n["F"]["L"],
            "scanner_severity": n["F"]["S"], "asset": n["F"]["A"],
            "scanner_cvss": (cvss or {}).get(n.get("original_id")),
            "predicted_score": round(score[nid], 2),
            "priority": priority_tier(score[nid], cfg),
            "linked_vulnerabilities": linked,
            "suggested_links": [{**sg, "predicted_score": round(score[sg["node_id"]], 2)}
                                for sg in (suggestions or {}).get(nid, [])],
            "fix_hint": cfg["fix_hints"].get(n["F"]["T"], cfg["default_fix_hint"]),
        })
    items.sort(key=lambda i: -i["predicted_score"])
    for rank, it in enumerate(items, 1):
        it["rank"] = rank
    tiers = defaultdict(int)
    for it in items:
        tiers[it["priority"]] += 1
    return {"dataset": name, "vulnerability_count": len(items),
            "priority_summary": {t["label"]: tiers.get(t["label"], 0) for t in cfg["priority_tiers"]},
            "score_scale": cfg["score_scale"], "score_config_fingerprint": config_fingerprint(cfg),
            "warnings": warnings or [], "vulnerabilities": items}


def to_markdown(rep, cfg, max_links=5):
    lo, hi = rep["score_scale"]["min"], rep["score_scale"]["max"]
    L = [f"# Vulnerability Priority Report - `{rep['dataset']}`", "",
         f"{rep['vulnerability_count']} vulnerabilities ordered by predicted risk score "
         f"({lo:g}-{hi:g}, higher = fix first). Scores account for attack-chain context from the "
         "vulnerability graph.", "", "**Priority summary:** "
         + ", ".join(f"{k}: {v}" for k, v in rep["priority_summary"].items()), ""]
    if rep["warnings"]:
        L += ["**Warnings:**"] + [f"- {w}" for w in rep["warnings"]] + [""]
    L += ["| Rank | ID | Vulnerability | Score | Priority |", "|---|---|---|---|---|"]
    for v in rep["vulnerabilities"]:
        L.append(f"| {v['rank']} | {v['node_id']} | {v['name']} | {v['predicted_score']:.2f} | {v['priority']} |")
    L += ["", "## Details", ""]
    for v in rep["vulnerabilities"]:
        L += [f"### {v['rank']}. {v['node_id']} - {v['name']}", "",
              f"- **Predicted score:** {v['predicted_score']:.2f} / {hi:g} -> **{v['priority']}**",
              f"- **Type / layer:** {v['type']} / {v['layer']} (scanner severity: {v['scanner_severity']})",
              f"- **Asset:** {v['asset']}"
              + (f" | **Scanner CVSS:** {v['scanner_cvss']}" if v.get("scanner_cvss") is not None else ""),
              f"- **Suggested fix:** {v['fix_hint']}"]
        if v["linked_vulnerabilities"]:
            L.append(f"- **Linked vulnerabilities ({len(v['linked_vulnerabilities'])}):**")
            for l in v["linked_vulnerabilities"][:max_links]:
                L.append(f"  - {cfg['edge_phrases'].get(l['type'], l['type'])} {l['node_id']} "
                         f"({l['name']}, score {l['predicted_score']:.2f}) "
                         f"[{l['type']}, weight {l['weight']}] - {l['reason']}")
            extra = len(v["linked_vulnerabilities"]) - max_links
            if extra > 0:
                L.append(f"  - ...and {extra} more (see JSON report)")
        else:
            L.append("- **Linked vulnerabilities:** none")
        if v.get("suggested_links"):
            L.append("- **Possible additional links (model-suggested, unverified - not seen in the scan):**")
            for sg in v["suggested_links"]:
                L.append(f"  - {sg['node_id']} ({sg['name']}, score {sg['predicted_score']:.2f}) "
                         f"- link probability {sg['probability']:.2f}")
        L.append("")
    return "\n".join(L)


def write_report(rep, cfg, out_dir):
    out_dir = Path(out_dir); out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"priority_report_{rep['dataset']}"
    (out_dir / f"{stem}.json").write_text(json.dumps(rep, indent=2), encoding="utf-8")
    (out_dir / f"{stem}.md").write_text(to_markdown(rep, cfg), encoding="utf-8")
    return out_dir / f"{stem}.md"


def main():
    ap = argparse.ArgumentParser(description="CyberLens priority report generator.")
    ap.add_argument("--dataset", required=True, help="dataset name from outputs/, or 'all'")
    ap.add_argument("--checkpoint", default=None, help="default: outputs/score_checkpoint_<encoder in hparams>.pt")
    ap.add_argument("--out-dir", default=str(OUTPUTS_DIR / "reports"))
    args = ap.parse_args()

    cfg = load_score_config()
    ckpt = args.checkpoint
    if ckpt is None:
        from project_config import load_hparams
        ckpt = OUTPUTS_DIR / f"score_checkpoint_{load_hparams()['encoder']}.pt"
    model, ck = load_model(ckpt)
    if ck.get("score_config_fingerprint") != config_fingerprint(cfg):
        print("WARNING: score_config.json changed since this checkpoint was trained -- retrain.")
    names = discover_datasets() if args.dataset == "all" else [args.dataset]
    for name in names:
        data, graph = load_dataset(name, cfg)
        rep = build_report(name, data, graph, model, cfg)
        write_report(rep, cfg, args.out_dir)
        top = rep["vulnerabilities"][0]
        print(f"{name}: {rep['vulnerability_count']} vulns; top = {top['node_id']} {top['name']} "
              f"({top['predicted_score']:.2f}, {top['priority']})")


if __name__ == "__main__":
    main()
