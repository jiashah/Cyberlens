from collections import defaultdict
from itertools import combinations
import re

# 1. CHAINING
CHAIN_PATTERNS = [
    ("xss", "missing_csp", 0.90,
     "A Content-Security-Policy is a primary mitigation against XSS payload "
     "execution; its absence directly increases the impact of the XSS finding."),
    ("xss", "cookie_missing_httponly", 0.85,
     "Without the HttpOnly flag, a successful XSS payload can read the session "
     "cookie directly, escalating XSS impact to session hijacking."),
    ("xss", "missing_xfo", 0.45,
     "Missing X-Frame-Options can be combined with XSS for clickjacking-assisted "
     "exploitation of the same page."),
    ("sqli", "verbose_error", 0.80,
     "Verbose error / stack-trace leakage on the same target helps an attacker "
     "refine SQL Injection payloads (classic error-based SQLi workflow)."),
    ("broken_auth", "idor", 0.85,
     "Successfully authenticating with default/weak credentials grants a valid "
     "session that can then be used to probe IDOR-vulnerable endpoints."),
    ("missing_rate_limit", "broken_auth", 0.80,
     "Absence of rate limiting on an auth endpoint enables brute-forcing of the "
     "same weak/default credentials flagged by the broken-auth finding."),
    ("weak_cipher_tls_version", "cookie_missing_secure", 0.70,
     "A weak/downgradable TLS channel combined with a cookie missing the Secure "
     "flag increases the practical chance of cookie interception."),
    ("missing_tls_cert", "cookie_missing_secure", 0.60,
     "An untrusted or absent TLS certificate undermines the confidentiality "
     "guarantee the Secure cookie flag depends on."),
    ("outdated_service_banner", "weak_protocol", 0.50,
     "An outdated service version combined with a weak/unencrypted protocol on "
     "the same port expands the exploitable surface of that service."),
    ("missing_hsts", "missing_tls_cert", 0.55,
     "Missing HSTS combined with TLS certificate issues increases exposure to "
     "protocol-downgrade / MITM attacks on the same host."),
    ("vulnerable_dependency", "outdated_js_library", 0.40,
     "Multiple outdated/vulnerable client-side components compound the overall "
     "client-side attack surface of the same application."),
]

# 2. CO_CONTEXT
CO_CONTEXT_WEIGHTS = {
    "same_target": 0.85,
    "same_asset_and_layer": 0.55,
    "same_asset_top_k": 0.30,
}

DEFAULT_CO_CONTEXT_TOP_K = 2

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# 3. SHARED_ROOT_CAUSE
ROOT_CAUSE_GROUPS = {
    "cookie_hardening_gap": {
        "cookie_missing_secure", "cookie_missing_httponly",
    },
    "header_hardening_gap": {
        "missing_csp", "missing_xfo", "missing_xcto",
    },
    "transport_security_gap": {
        "missing_tls_cert", "weak_cipher_tls_version", "missing_hsts",
    },
    "outdated_component_gap": {
        "outdated_service_banner", "outdated_js_library",
        "vulnerable_dependency", "outdated_fingerprint",
    },
    "exposed_surface_gap": {
        "open_port", "weak_protocol",
    },
    "input_validation_gap": {
        "xss", "sqli",
    },
    "access_control_gap": {
        "broken_auth", "idor", "missing_rate_limit",
    },
}

SHARED_ROOT_CAUSE_WEIGHT = 0.6


def _asset_of(node: dict) -> str:
    return node["F"]["A"]


def _type_of(node: dict) -> str:
    return node["F"]["T"]


def _layer_of(node: dict) -> str:
    return node["F"]["L"]


def _target_of(node: dict) -> str:
    return node.get("target")


_URL_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/]+)(/.*)?$')
_BARE_HOST_PORT_PATTERN = re.compile(r'^[^/:\s]+:\d+$')
_PACKAGE_SPEC_PATTERN = re.compile(r'^\S+(==|@)\S+$')


def _is_specific_target(target: str) -> bool:
    if not target:
        return False
    t = target.strip()

    m = _URL_PATTERN.match(t)
    if m:
        path_part = m.group(2) or ""
        return path_part not in ("", "/")

    if _BARE_HOST_PORT_PATTERN.match(t):
        return True

    if _PACKAGE_SPEC_PATTERN.match(t):
        return True

    return False


def _severity_of(node: dict) -> str:
    return node["F"]["S"]


def _root_cause_groups_for(finding_type: str) -> set:
    return {g for g, types in ROOT_CAUSE_GROUPS.items() if finding_type in types}


def _shares_root_cause_family(node_a: dict, node_b: dict) -> bool:
    return bool(_root_cause_groups_for(_type_of(node_a)) & _root_cause_groups_for(_type_of(node_b)))


# 1. CHAINING
def build_chaining_edges(nodes: list) -> list:
    edges = []
    pattern_lookup = {(src, dst): (w, reason) for src, dst, w, reason in CHAIN_PATTERNS}

    for a, b in combinations(nodes, 2):
        if _asset_of(a) != _asset_of(b):
            continue

        for src, dst in ((a, b), (b, a)):
            key = (_type_of(src), _type_of(dst))
            if key in pattern_lookup:
                weight, reason = pattern_lookup[key]
                edges.append({
                    "source": src["node_id"],
                    "target": dst["node_id"],
                    "type": "chaining",
                    "weight": weight,
                    "reason": reason,
                })
    return edges


# 2. CO_CONTEXT
def build_co_context_edges(nodes: list, top_k: int = DEFAULT_CO_CONTEXT_TOP_K,
                            weights: dict = None) -> list:
    weights = weights or CO_CONTEXT_WEIGHTS
    node_by_id = {n["node_id"]: n for n in nodes}

    by_asset = defaultdict(list)
    for n in nodes:
        asset = _asset_of(n)
        if asset:
            by_asset[asset].append(n)

    edges = []
    resolved_pairs = set()
    tier3_candidates = []

    for asset, group in by_asset.items():
        if len(group) < 2:
            continue
        for a, b in combinations(group, 2):
            pair_key = frozenset((a["node_id"], b["node_id"]))

            if _target_of(a) and _target_of(a) == _target_of(b) and _is_specific_target(_target_of(a)):
                edges.append({
                    "source": a["node_id"],
                    "target": b["node_id"],
                    "type": "co_context",
                    "weight": weights["same_target"],
                    "reason": f"Both findings share the exact same target "
                              f"('{_target_of(a)}'), which contains fine-grained "
                              f"endpoint/service/component evidence (a path, port, or "
                              f"package identifier) -- the strongest evidence available "
                              f"in the current scanner data.",
                })
                resolved_pairs.add(pair_key)
            elif _layer_of(a) == _layer_of(b):
                edges.append({
                    "source": a["node_id"],
                    "target": b["node_id"],
                    "type": "co_context",
                    "weight": weights["same_asset_and_layer"],
                    "reason": f"Both findings share asset '{asset}' and the same "
                              f"security layer ('{_layer_of(a)}').",
                })
                resolved_pairs.add(pair_key)
            else:
                tier3_candidates.append((a, b))

    candidates_by_node = defaultdict(list)
    for a, b in tier3_candidates:
        pair_key = frozenset((a["node_id"], b["node_id"]))
        if pair_key in resolved_pairs:
            continue
        candidates_by_node[a["node_id"]].append(b)
        candidates_by_node[b["node_id"]].append(a)

    def rank_key(anchor: dict, candidate: dict):
        shares_family = _shares_root_cause_family(anchor, candidate)
        severity_rank = SEVERITY_RANK.get(_severity_of(candidate), -1)
        return (0 if shares_family else 1, -severity_rank, candidate["node_id"])

    selected_pairs = set()
    for node_id, candidates in candidates_by_node.items():
        anchor = node_by_id[node_id]
        ranked = sorted(candidates, key=lambda c: rank_key(anchor, c))
        for c in ranked[:top_k]:
            selected_pairs.add(frozenset((node_id, c["node_id"])))

    for pair_key in selected_pairs:
        a_id, b_id = tuple(pair_key)
        a, b = node_by_id[a_id], node_by_id[b_id]
        edges.append({
            "source": a["node_id"],
            "target": b["node_id"],
            "type": "co_context",
            "weight": weights["same_asset_top_k"],
            "reason": f"Both findings share asset '{_asset_of(a)}' with no stronger "
                      f"endpoint or layer evidence available; selected as a "
                      f"top-{top_k} contextual neighbor (tie-break: shared "
                      f"root-cause family, then severity, then node id).",
        })

    return edges


# 3. SHARED_ROOT_CAUSE
def build_shared_root_cause_edges(nodes: list) -> list:
    edges = []
    for a, b in combinations(nodes, 2):
        ta, tb = _type_of(a), _type_of(b)
        if ta == tb:
            continue
        shared = _root_cause_groups_for(ta) & _root_cause_groups_for(tb)
        if shared:
            group_name = sorted(shared)[0]
            edges.append({
                "source": a["node_id"],
                "target": b["node_id"],
                "type": "shared_root_cause",
                "weight": SHARED_ROOT_CAUSE_WEIGHT,
                "reason": f"Both finding types belong to the '{group_name}' "
                          f"configuration-weakness family.",
            })
    return edges


def build_all_edges(nodes: list, co_context_top_k: int = DEFAULT_CO_CONTEXT_TOP_K) -> list:
    edges = []
    edges.extend(build_chaining_edges(nodes))
    edges.extend(build_co_context_edges(nodes, top_k=co_context_top_k))
    edges.extend(build_shared_root_cause_edges(nodes))
    return edges