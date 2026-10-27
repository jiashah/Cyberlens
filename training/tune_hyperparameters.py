import argparse
import json
import os
import random
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import torch  # noqa: E402
from score_prediction_trainer import load_all, leave_one_app_out, evaluate_holdout  # noqa: E402
from project_config import (CONFIG_DIR, OUTPUTS_DIR, HPARAM_KEYS, load_json,  # noqa: E402
                            load_score_config, load_hparams, load_labels)


def split_apps(names, fraction, seed, explicit=None):
    if explicit:
        unknown = set(explicit) - set(names)
        if unknown:
            raise ValueError(f"unknown holdout apps: {sorted(unknown)}")
        return sorted(set(names) - set(explicit)), sorted(explicit)
    shuffled = sorted(names)
    random.Random(seed).shuffle(shuffled)
    n = max(1, round(len(shuffled) * fraction))
    return sorted(shuffled[n:]), sorted(shuffled[:n])


def key(hp):
    enc = hp["encoder"]
    return tuple(hp.get(k) for k in HPARAM_KEYS if not (k == "heads" and enc != "gat"))


def objective(m, obj):
    rho = m["spearman"] if m["spearman"] == m["spearman"] else 0.0
    return obj["mae_weight"] * m["mae"] + obj["rank_weight"] * (1.0 - rho)


def main():
    ap = argparse.ArgumentParser(description="CyberLens hyperparameter tuning.")
    ap.add_argument("--space", default=str(CONFIG_DIR / "tuning_space.json"))
    ap.add_argument("--trials", type=int, default=None)
    ap.add_argument("--final", action="store_true", help="tune on all apps (no hold-out)")
    ap.add_argument("--split-seed", type=int, default=None, help="seed for the tune/hold-out split")
    ap.add_argument("--holdout", default=None, help="comma-separated app names to hold out")
    ap.add_argument("--labels", default=None)
    ap.add_argument("--threads", type=int, default=1)
    ap.add_argument("--apply", action="store_true", help="write the winner to config/hparams.json")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    torch.set_num_threads(args.threads)

    space, cfg, start_hp = load_json(args.space), load_score_config(), load_hparams()
    obj = space["objective"]
    datas = load_all(cfg, labels=load_labels(args.labels, cfg) if args.labels else None)
    by_name = {d.dataset_name: d for d in datas}
    split_seed = args.split_seed if args.split_seed is not None else space["seed"]
    if args.final:
        tune, hold, tune_names, hold_names = datas, [], sorted(by_name), []
    else:
        tune_names, hold_names = split_apps(list(by_name), space["holdout_fraction"], split_seed,
                                            args.holdout.split(",") if args.holdout else None)
        tune, hold = [by_name[n] for n in tune_names], [by_name[n] for n in hold_names]
    print(f"mode={'final (all apps)' if args.final else 'nested'}  TUNE apps ({len(tune)}): {tune_names}")
    if hold:
        print(f"HOLD-OUT apps ({len(hold)}): {hold_names} ({sum(d.num_nodes for d in hold)} vulnerabilities)")

    rng = random.Random(space["seed"] + split_seed)
    trials, seen = [dict(start_hp)], {key(start_hp)}
    n_trials, guard = args.trials or space["n_trials"], 0
    while len(trials) < n_trials and guard < n_trials * 100:
        guard += 1
        hp = {k: rng.choice(v) for k, v in space["search"].items()}
        if key(hp) not in seen:
            seen.add(key(hp)); trials.append(hp)

    t0, rows = time.time(), []
    a_seeds = [space["seed"] + i for i in range(space["cv_seeds"])]
    print(f"--- Stage A: {len(trials)} configs x LOAO ---")
    for i, hp in enumerate(trials):
        _, pooled = leave_one_app_out(tune, hp, cfg, a_seeds)
        m = pooled["model"]
        rows.append({"trial": i, "is_start": i == 0, "hparams": hp, "cv": m, "objective": objective(m, obj),
                     "cv_severity_baseline_mae": pooled["severity_baseline"]["mae"]})
        print(f"[{i + 1:2d}/{len(trials)}] obj={rows[-1]['objective']:.3f} MAE={m['mae']:.3f} rho={m['spearman']:.3f} "
              f"{hp['encoder']} h{hp['hidden_dim']} e{hp['embedding_dim']} L{hp['num_layers']} lr{hp['lr']} "
              f"ep{hp['epochs']} d{hp['residual_max_delta']} std{hp['standardize']} {hp['loss']} "
              f"({time.time() - t0:.0f}s)", flush=True)

    top = sorted(rows, key=lambda r: r["objective"])[: space["stage_b_top_k"]]
    if all(r["trial"] != 0 for r in top):
        top.append(rows[0])
    b_seeds = [space["seed"] + 50 + i for i in range(space["stage_b_seeds"])]
    print(f"--- Stage B: {len(top)} finalists x {len(b_seeds)} seeds ---")
    for r in top:
        _, pooled = leave_one_app_out(tune, r["hparams"], cfg, b_seeds)
        r["stage_b_cv"], r["stage_b_objective"] = pooled["model"], objective(pooled["model"], obj)
        r["stage_b_baseline"] = pooled["severity_baseline"]
        print(f"  trial {r['trial']:2d}: obj={r['stage_b_objective']:.3f} MAE={pooled['model']['mae']:.3f} "
              f"rho={pooled['model']['spearman']:.3f}  (stage A obj {r['objective']:.3f})"
              f"{'  <- starting config' if r['trial'] == 0 else ''}", flush=True)
    best = min(top, key=lambda r: r["stage_b_objective"])
    print(f"\nWINNER: trial {best['trial']}  {best['hparams']}")

    result = {"mode": "final" if args.final else "nested", "split_seed": split_seed,
              "objective_weights": obj, "tune_apps": tune_names, "holdout_apps": hold_names,
              "trials": rows, "finalists": [t["trial"] for t in top], "best": best,
              "starting_config_stage_b": next(r for r in top if r["trial"] == 0)["stage_b_cv"]}
    if hold:
        f_seeds = [space["seed"] + 100 + i for i in range(space["final_seeds"])]
        res = {}
        print("--- Hold-out evaluation (never used for selection) ---")
        for label, hp in (("winner", best["hparams"]), ("starting_config", start_hp),
                          ("features_only_ablation", {**best["hparams"], "encoder": "none"})):
            r = evaluate_holdout(tune, hold, hp, cfg, f_seeds)
            res[label] = {"hparams": hp, "model": r["model"], "per_app": r["per_app"]}
            if label == "winner":
                res["severity_baseline"] = r["severity_baseline"]
            print(f"  {label:24s} MAE={r['model']['mae']:.3f} RMSE={r['model']['rmse']:.3f} rho={r['model']['spearman']:.3f}")
        sb = res["severity_baseline"]
        print(f"  {'severity_baseline':24s} MAE={sb['mae']:.3f} RMSE={sb['rmse']:.3f} rho={sb['spearman']:.3f}")
        result["holdout"] = res
    else:
        f_seeds = [space["seed"] + 100 + i for i in range(space["final_seeds"])]
        _, pooled = leave_one_app_out(tune, best["hparams"], cfg, f_seeds)
        result["final_cv_optimistic"] = pooled
        print(f"Final LOAO (all apps, {len(f_seeds)} seeds; optimistic - apps were used for selection): "
              f"MAE={pooled['model']['mae']:.3f} rho={pooled['model']['spearman']:.3f} "
              f"(baseline MAE={pooled['severity_baseline']['mae']:.3f} rho={pooled['severity_baseline']['spearman']:.3f})")

    out = Path(args.out) if args.out else OUTPUTS_DIR / ("tuning_final.json" if args.final else f"tuning_nested_split{split_seed}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Wrote {out}")
    if args.apply:
        target = CONFIG_DIR / "hparams.json"
        shutil.copy(target, CONFIG_DIR / "hparams.previous.json")
        target.write_text(json.dumps({k: best["hparams"][k] for k in HPARAM_KEYS}, indent=1), encoding="utf-8")
        print(f"Applied winner to {target} (previous saved as hparams.previous.json)")


if __name__ == "__main__":
    main()
