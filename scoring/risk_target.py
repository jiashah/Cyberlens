def priority_tier(score, cfg):
    for tier in cfg["priority_tiers"]:
        if score >= tier["min_score"]:
            return tier["label"]
    return cfg["priority_tiers"][-1]["label"]


def cvss_by_original_id(normalized):
    out = {}
    for nf in normalized.get("normalized_findings", []):
        v = (nf.get("raw") or {}).get("cvss_score")
        if v is not None:
            out[nf.get("id")] = float(v)
    return out


def base_score(node, cfg, cvss=None):
    lo, hi = cfg["score_scale"]["min"], cfg["score_scale"]["max"]
    real = (cvss or {}).get(node.get("original_id"))
    if real is not None:
        return max(lo, min(hi, float(real)))
    f = node["F"]
    sev = cfg["severity_to_score"].get(f.get("S"), cfg["unknown_severity_score"])
    prior = cfg["type_prior"].get(f.get("T"), sev)
    w = cfg["severity_weight"]
    return w * sev + (1 - w) * prior


def compute_target_scores(graph, cfg, cvss=None, labels=None):
    lo, hi = cfg["score_scale"]["min"], cfg["score_scale"]["max"]
    nodes = {n["node_id"]: n for n in graph["nodes"]}
    base = {nid: base_score(n, cfg, cvss) for nid, n in nodes.items()}
    amp = dict.fromkeys(nodes, 0.0)
    cluster_n = dict.fromkeys(nodes, 0)

    for e in graph["edges"]:
        s, t, w = e["source"], e["target"], float(e["weight"])
        if s not in nodes or t not in nodes:
            continue
        if e["type"] == "chaining":
            amp[s] += cfg["chain_gain"] * w * base[t] / hi
            amp[t] += cfg["chain_gain"] * cfg["chain_enabler_share"] * w * base[s] / hi
        elif e["type"] == "shared_root_cause":
            cluster_n[s] += 1
            cluster_n[t] += 1

    out = {}
    for nid, n in nodes.items():
        real = (labels or {}).get(n.get("original_id"))
        if real is not None:
            out[nid] = max(lo, min(hi, float(real)))
        else:
            bump = min(cfg["cluster_bump_cap"], cfg["cluster_bump"] * cluster_n[nid])
            out[nid] = max(lo, min(hi, base[nid] + amp[nid] + bump))
    return out
