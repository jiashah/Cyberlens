import argparse
import json
import random
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Batch

ROOT = Path(__file__).resolve().parents[1]
for sub in ("models", "pyg", "scoring", "features"):
    sys.path.insert(0, str(ROOT / sub))
from gcn import GCNBaseline, edge_weight_from_edge_attr  # noqa: E402
from gat import GATBaseline  # noqa: E402
from pyg_converter import build_pyg_data  # noqa: E402
from project_config import (OUTPUTS_DIR, HPARAM_KEYS, load_json, load_score_config,  # noqa: E402
                            load_hparams, discover_datasets, config_fingerprint, load_labels)
from risk_target import compute_target_scores, cvss_by_original_id  # noqa: E402
from feature_engineering import SEVERITY_ORDINAL  # noqa: E402

ENCODERS = ("gcn", "gat", "none")


def severity_prior_from_cfg(cfg):
    size = max(SEVERITY_ORDINAL.values()) + 1
    prior = [cfg["unknown_severity_score"]] * size
    for name, ordinal in SEVERITY_ORDINAL.items():
        prior[ordinal] = cfg["severity_to_score"].get(name, cfg["unknown_severity_score"])
    return prior


class ScoreRegressor(nn.Module):

    def __init__(self, hp, input_dim, edge_dim, max_score, severity_prior, min_score=0.0):
        super().__init__()
        self.kind, self.max_score, self.min_score = hp["encoder"], float(max_score), float(min_score)
        self.max_delta = float(hp.get("residual_max_delta", 0.0))
        self.standardize = bool(hp.get("standardize", False))
        self.register_buffer("x_mean", torch.zeros(input_dim))
        self.register_buffer("x_std", torch.ones(input_dim))
        self.register_buffer("severity_prior", torch.tensor(severity_prior, dtype=torch.float))
        h, e = hp["hidden_dim"], hp["embedding_dim"]
        if self.kind == "gcn":
            self.encoder = GCNBaseline(input_dim, h, e, hp["num_layers"], hp["dropout"])
            head_in = e + input_dim
        elif self.kind == "gat":
            self.encoder = GATBaseline(input_dim, h, e, hp["num_layers"], hp["heads"],
                                       hp["dropout"], edge_dim)
            head_in = e + input_dim
        elif self.kind == "none":
            self.encoder, head_in = None, input_dim
        else:
            raise ValueError(f"encoder must be one of {ENCODERS}, got {self.kind!r}")
        self.head = nn.Sequential(nn.Linear(head_in, h), nn.ReLU(),
                                  nn.Dropout(hp["dropout"]), nn.Linear(h, 1))

    def forward(self, x_raw, edge_index, edge_attr):
        x = (x_raw - self.x_mean) / self.x_std if self.standardize else x_raw
        if self.kind == "gcn":
            feats = torch.cat([self.encoder(x, edge_index, edge_weight_from_edge_attr(edge_attr)), x], -1)
        elif self.kind == "gat":
            feats = torch.cat([self.encoder(x, edge_index, edge_attr), x], -1)
        else:
            feats = x
        raw = self.head(feats).squeeze(-1)
        if self.max_delta > 0:
            ordinal = x_raw[:, 0].round().long().clamp(0, len(self.severity_prior) - 1)
            self.last_delta = self.max_delta * torch.tanh(raw)
            return (self.severity_prior[ordinal] + self.last_delta).clamp(self.min_score, self.max_score)
        return self.max_score * torch.sigmoid(raw)


def set_seed(seed):
    random.seed(seed); np.random.seed(seed); torch.manual_seed(seed)


# ----------------------------------------------------------------- data
def make_data(graph, features, cfg, cvss=None, name="scan", with_target=True, labels=None):
    data, _, warnings = build_pyg_data(graph, features)
    warnings = list(warnings) + list(features.get("feature_metadata", {}).get("warnings", []))
    if with_target:
        target = compute_target_scores(graph, cfg, cvss, labels)
        data.n_real_labels = sum(1 for n in graph["nodes"] if (labels or {}).get(n.get("original_id")) is not None)
        data.y = torch.tensor([target[nid] for nid in data.node_ids], dtype=torch.float)
    data.severity = [n["F"]["S"] for n in graph["nodes"]]
    data.dataset_name = name
    return data, warnings


def load_dataset(name, cfg, outputs_dir=None, labels=None):
    d = Path(outputs_dir or OUTPUTS_DIR)
    graph = load_json(d / f"graph_{name}.json")
    feats = load_json(d / f"features_{name}.json")
    norm = d / f"normalized_{name}.json"
    cvss = cvss_by_original_id(load_json(norm)) if norm.exists() else {}
    data, _ = make_data(graph, feats, cfg, cvss, name, labels=(labels or {}).get(name))
    return data, graph


def load_all(cfg, outputs_dir=None, names=None, labels=None):
    names = names or discover_datasets(outputs_dir)
    if not names:
        raise FileNotFoundError("No graph_<name>.json + features_<name>.json pairs found in outputs/")
    return [load_dataset(n, cfg, outputs_dir, labels)[0] for n in names]


# ------------------------------------------------------------ train/predict
def train_model(train_datas, hp, cfg, seed):
    set_seed(seed)
    batch = Batch.from_data_list(train_datas)
    model = ScoreRegressor(hp, batch.num_node_features, batch.edge_attr.shape[1],
                           cfg["score_scale"]["max"], severity_prior_from_cfg(cfg), cfg["score_scale"]["min"])
    if model.standardize:
        model.x_mean.copy_(batch.x.mean(0)); model.x_std.copy_(batch.x.std(0).clamp_min(1e-6))
    loss_fn = {"smooth_l1": F.smooth_l1_loss, "mse": F.mse_loss}[hp.get("loss", "smooth_l1")]
    opt = torch.optim.Adam(model.parameters(), lr=hp["lr"], weight_decay=hp["weight_decay"])
    losses = []
    for _ in range(hp["epochs"]):
        model.train(); opt.zero_grad()
        loss = loss_fn(model(batch.x, batch.edge_index, batch.edge_attr), batch.y)
        if hp.get("delta_l2", 0.0) > 0 and model.max_delta > 0:
            loss = loss + hp["delta_l2"] * (model.last_delta ** 2).mean()
        loss.backward(); opt.step()
        losses.append(float(loss.item()))
    model.eval()
    return model, losses


def predict(model, data):
    model.eval()
    with torch.no_grad():
        return model(data.x, data.edge_index, data.edge_attr).numpy()


def spearman(a, b):
    if len(a) < 3:
        return float("nan")
    ra, rb = np.argsort(np.argsort(a)).astype(float), np.argsort(np.argsort(b)).astype(float)
    return float("nan") if ra.std() == 0 or rb.std() == 0 else float(np.corrcoef(ra, rb)[0, 1])


def metrics(pred, true):
    pred, true = np.asarray(pred), np.asarray(true)
    return {"mae": float(np.abs(pred - true).mean()),
            "rmse": float(np.sqrt(((pred - true) ** 2).mean())),
            "spearman": spearman(pred, true)}


def severity_baseline(train_datas, test_data):
    by = defaultdict(list)
    for d in train_datas:
        for s, y in zip(d.severity, d.y.tolist()):
            by[s].append(y)
    overall = float(np.mean([y for v in by.values() for y in v]))
    return np.array([np.mean(by[s]) if by.get(s) else overall for s in test_data.severity])


def evaluate_holdout(train_datas, test_datas, hp, cfg, seeds, with_baseline=True):
    preds = [[] for _ in test_datas]
    for s in seeds:
        model, _ = train_model(train_datas, hp, cfg, s)
        for i, td in enumerate(test_datas):
            preds[i].append(predict(model, td))
    P = [np.mean(p, axis=0) for p in preds]
    T = [td.y.numpy() for td in test_datas]
    out = {"model": metrics(np.concatenate(P), np.concatenate(T)),
           "per_app": [{"app": td.dataset_name, "n": len(t), "mae": metrics(p, t)["mae"]}
                       for td, p, t in zip(test_datas, P, T)]}
    out["_pred"] = P
    if with_baseline:
        B = [severity_baseline(train_datas, td) for td in test_datas]
        out["severity_baseline"] = metrics(np.concatenate(B), np.concatenate(T))
        out["_base"] = B
    return out


def leave_one_app_out(datas, hp, cfg, seeds, verbose=False):
    folds, P, T, B = [], [], [], []
    for i, td in enumerate(datas):
        train = datas[:i] + datas[i + 1:]
        r = evaluate_holdout(train, [td], hp, cfg, seeds, with_baseline=True)
        p = r.pop("_pred")[0]; b = r.pop("_base")[0]; t = td.y.numpy()
        folds.append({"held_out": td.dataset_name, "n": td.num_nodes, "model": r["model"],
                      "severity_baseline": r["severity_baseline"]})
        P.append(p); T.append(t); B.append(b)
        if verbose:
            print(f"  held-out {td.dataset_name:30s} n={td.num_nodes:2d}  model MAE="
                  f"{r['model']['mae']:.2f}  baseline MAE={r['severity_baseline']['mae']:.2f}")
    T = np.concatenate(T)
    return folds, {"model": metrics(np.concatenate(P), T), "severity_baseline": metrics(np.concatenate(B), T)}


# --------------------------------------------------------------------- CLI
def resolve_hparams(args):
    hp = load_hparams(args.hparams)
    for k in HPARAM_KEYS:
        v = getattr(args, k, None)
        if v is not None:
            hp[k] = v
    return hp


def main():
    ap = argparse.ArgumentParser(description="CyberLens vulnerability score prediction.")
    ap.add_argument("--hparams", default=None, help="hyperparameter JSON (default config/hparams.json)")
    ap.add_argument("--score-config", default=None)
    ap.add_argument("--outputs-dir", default=None)
    ap.add_argument("--labels", default=None, help="real labels (.json/.csv) that replace the proxy target; see project_config.load_labels")
    ap.add_argument("--encoder", choices=ENCODERS)
    ap.add_argument("--hidden_dim", type=int); ap.add_argument("--embedding_dim", type=int)
    ap.add_argument("--num_layers", type=int); ap.add_argument("--heads", type=int)
    ap.add_argument("--dropout", type=float); ap.add_argument("--lr", type=float)
    ap.add_argument("--weight_decay", type=float); ap.add_argument("--epochs", type=int)
    ap.add_argument("--residual_max_delta", type=float)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--cv-seeds", type=int, default=3)
    ap.add_argument("--skip-cv", action="store_true")
    ap.add_argument("--checkpoint", default=None)
    ap.add_argument("--results-output", default=None)
    args = ap.parse_args()

    cfg, hp = load_score_config(args.score_config), resolve_hparams(args)
    out_dir = Path(args.outputs_dir) if args.outputs_dir else OUTPUTS_DIR
    ckpt = Path(args.checkpoint) if args.checkpoint else out_dir / f"score_checkpoint_{hp['encoder']}.pt"
    res = Path(args.results_output) if args.results_output else out_dir / f"score_training_results_{hp['encoder']}.json"

    names = discover_datasets(out_dir)
    labels = load_labels(args.labels, cfg) if args.labels else None
    datas = load_all(cfg, out_dir, names, labels)
    total = sum(d.num_nodes for d in datas)
    print(f"=== Score prediction -- hparams: {hp} ===")
    print(f"Discovered {len(datas)} apps: {names}\n{total} vulnerabilities; "
          f"score range [{min(d.y.min() for d in datas):.2f}, {max(d.y.max() for d in datas):.2f}]; "
          f"real labels used for {sum(getattr(d, 'n_real_labels', 0) for d in datas)} nodes (rest = proxy target)")

    results = {"hparams": hp, "datasets": names, "score_config_fingerprint": config_fingerprint(cfg)}
    seeds = [args.seed + i for i in range(args.cv_seeds)]
    if not args.skip_cv:
        print("Leave-one-application-out CV (trained on the other apps, tested on the unseen one):")
        folds, pooled = leave_one_app_out(datas, hp, cfg, seeds, verbose=True)
        results["cv_folds"], results["cv_pooled"] = folds, pooled
        print(f"CV model:    {pooled['model']}\nCV baseline: {pooled['severity_baseline']}")

    print("Training final model on all apps...")
    model, losses = train_model(datas, hp, cfg, args.seed)
    fit = metrics(np.concatenate([predict(model, d) for d in datas]), np.concatenate([d.y.numpy() for d in datas]))
    results["train_fit"], results["loss_first_last"] = fit, [losses[0], losses[-1]]
    print(f"loss {losses[0]:.4f} -> {losses[-1]:.4f}; in-sample {fit}")

    b = Batch.from_data_list(datas)
    ckpt.parent.mkdir(parents=True, exist_ok=True)
    torch.save({"hparams": hp, "state_dict": model.state_dict(), "input_dim": b.num_node_features,
                "edge_dim": b.edge_attr.shape[1], "max_score": cfg["score_scale"]["max"],
                "min_score": cfg["score_scale"]["min"], "severity_prior": severity_prior_from_cfg(cfg),
                "score_config_fingerprint": config_fingerprint(cfg), "datasets": names}, ckpt)
    with open(res, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Wrote {ckpt}\nWrote {res}")


if __name__ == "__main__":
    main()
