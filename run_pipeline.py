import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for sub in ("normalization", "graph", "features", "training", "models", "pyg", "scoring", "reporting", "linking"):
    sys.path.insert(0, str(ROOT / sub))
from normalizer import normalize_scan_output  # noqa: E402
from graph_builder import build_graph  # noqa: E402
from feature_engineering import build_node_features  # noqa: E402
from score_prediction_trainer import make_data  # noqa: E402
from priority_report import load_model, build_report, write_report  # noqa: E402
from link_suggester import load_link_model, suggest_links  # noqa: E402
from project_config import OUTPUTS_DIR, load_json, load_score_config, load_hparams  # noqa: E402
from risk_target import cvss_by_original_id  # noqa: E402


class ScanError(ValueError):
    pass


def load_assets(checkpoint=None, score_config=None):
    cfg = load_score_config(score_config)
    checkpoint = checkpoint or OUTPUTS_DIR / f"score_checkpoint_{load_hparams()['encoder']}.pt"
    model, ck = load_model(checkpoint)
    link_model, link_note = load_link_model(cfg, ck["input_dim"])
    return {"cfg": cfg, "model": model, "ck": ck, "link_model": link_model, "link_note": link_note}


def analyze_scan(scan, name, assets, source="uploaded"):
    if not isinstance(scan, dict) or not isinstance(scan.get("findings"), list):
        raise ScanError("scan must be a JSON object with a 'findings' list")
    cfg, ck = assets["cfg"], assets["ck"]
    try:
        normalized = normalize_scan_output(scan, source_file=source)
        graph = build_graph(normalized, source_file=source)
        features = build_node_features(graph)
    except Exception as e:
        raise ScanError(f"could not process scan: {type(e).__name__}: {e}") from e
    if not graph["nodes"]:
        raise ScanError("scan contains no findings")
    cvss = cvss_by_original_id(normalized)
    data, warnings = make_data(graph, features, cfg, cvss, name, with_target=False)
    if data.num_node_features != ck["input_dim"]:
        raise ScanError(f"feature dimension {data.num_node_features} != checkpoint's {ck['input_dim']}: "
                        "the type/layer vocabulary changed since training - retrain the model")
    suggestions = None
    if assets["link_model"] is not None:
        suggestions = suggest_links(data, graph, assets["link_model"], cfg)
    elif cfg.get("link_suggestions", {}).get("enabled"):
        warnings = list(warnings) + [f"link suggestions skipped: {assets['link_note']}"]
    return build_report(name, data, graph, assets["model"], cfg, warnings, cvss, suggestions)


def run(scan_path, checkpoint=None, out_dir=None, name=None, score_config=None):
    scan_path = Path(scan_path)
    assets = load_assets(checkpoint, score_config)
    rep = analyze_scan(load_json(scan_path), name or scan_path.stem, assets, str(scan_path))
    return rep, write_report(rep, assets["cfg"], out_dir or OUTPUTS_DIR / "reports"), assets["cfg"]


def main():
    ap = argparse.ArgumentParser(description="CyberLens: raw scan -> prioritised vulnerability report.")
    ap.add_argument("--scan", required=True)
    ap.add_argument("--checkpoint", default=None)
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--name", default=None)
    args = ap.parse_args()
    try:
        rep, path, _ = run(args.scan, args.checkpoint, args.out_dir, args.name)
    except ScanError as e:
        sys.exit(f"error: {e}")
    print(f"{rep['vulnerability_count']} vulnerabilities; {rep['priority_summary']}")
    for v in rep["vulnerabilities"][:5]:
        print(f"  #{v['rank']} {v['node_id']} {v['predicted_score']:.2f} {v['priority']}  {v['name']}")
    for w in rep["warnings"][:3]:
        print(f"  note: {w}")
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
