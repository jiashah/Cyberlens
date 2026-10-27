import csv
import hashlib
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_DIR = PROJECT_ROOT / "config"
OUTPUTS_DIR = PROJECT_ROOT / "outputs"

_REQUIRED = ["score_scale", "severity_to_score", "unknown_severity_score", "type_prior",
             "severity_weight", "chain_gain", "chain_enabler_share", "cluster_bump",
             "cluster_bump_cap", "priority_tiers", "edge_phrases", "fix_hints",
             "default_fix_hint"]
HPARAM_KEYS = ["encoder", "hidden_dim", "embedding_dim", "num_layers", "heads",
               "dropout", "lr", "weight_decay", "epochs", "residual_max_delta", "standardize", "loss", "delta_l2"]


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_score_config(path=None):
    cfg = load_json(path or CONFIG_DIR / "score_config.json")
    missing = [k for k in _REQUIRED if k not in cfg]
    if missing:
        raise ValueError(f"score config is missing keys: {missing}")
    lo, hi = cfg["score_scale"]["min"], cfg["score_scale"]["max"]
    if not lo < hi:
        raise ValueError("score_scale.min must be < score_scale.max")
    if not 0.0 <= cfg["severity_weight"] <= 1.0:
        raise ValueError("severity_weight must be in [0, 1]")
    mins = [t["min_score"] for t in cfg["priority_tiers"]]
    if mins != sorted(mins, reverse=True) or mins[-1] > lo:
        raise ValueError("priority_tiers must be sorted by min_score descending and the "
                         "last tier must start at or below score_scale.min")
    return cfg


def load_hparams(path=None):
    hp = load_json(path or CONFIG_DIR / "hparams.json")
    missing = [k for k in HPARAM_KEYS if k not in hp]
    if missing:
        raise ValueError(f"hparams file is missing keys: {missing}")
    return hp


def discover_datasets(outputs_dir=None):
    d = Path(outputs_dir or OUTPUTS_DIR)
    return [g.stem[len("graph_"):] for g in sorted(d.glob("graph_*.json"))
            if (d / f"features_{g.stem[len('graph_'):]}.json").exists()]


def config_fingerprint(cfg):
    return hashlib.md5(json.dumps(cfg, sort_keys=True).encode()).hexdigest()[:12]


def load_labels(path, cfg=None):
    path = Path(path)
    labels = {}
    if path.suffix.lower() == ".json":
        labels = {d: {str(k): float(v) for k, v in m.items()} for d, m in load_json(path).items()}
    else:
        with open(path, newline="", encoding="utf-8-sig") as f:
            for row in csv.DictReader(f):
                labels.setdefault(row["dataset"], {})[str(row["original_id"])] = float(row["score"])
    if cfg is not None:
        lo, hi = cfg["score_scale"]["min"], cfg["score_scale"]["max"]
        bad = [(d, k, v) for d, m in labels.items() for k, v in m.items() if not lo <= v <= hi]
        if bad:
            raise ValueError(f"labels outside score scale [{lo}, {hi}]: {bad[:3]}")
    return labels
