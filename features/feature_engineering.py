import argparse
import json
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

SEVERITY_ORDINAL = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

LAYER_VOCAB = [
    "network", "ssl", "client", "application", "api", "fingerprint", "dependency",
]

TYPE_VOCAB = [
    "open_port", "outdated_service_banner", "weak_protocol",
    "missing_tls_cert", "weak_cipher_tls_version", "missing_hsts",
    "missing_csp", "missing_xfo", "missing_xcto",
    "cookie_missing_secure", "cookie_missing_httponly",
    "xss", "sqli", "broken_auth", "idor",
    "missing_rate_limit", "verbose_error",
    "outdated_js_library", "vulnerable_dependency", "outdated_fingerprint",
]

FEATURE_NAMES = (
    ["severity_ordinal"]
    + [f"layer_onehot__{l}" for l in LAYER_VOCAB]
    + [f"type_onehot__{t}" for t in TYPE_VOCAB]
    + ["has_cve", "has_cwe", "has_exploitability_info"]
    + ["asset_finding_count_log", "graph_degree_log"]
)
FEATURE_DIM = len(FEATURE_NAMES)


def _one_hot(value: str, vocab: list, warnings: list, warning_label: str) -> list:
    vec = [0.0] * len(vocab)
    if value in vocab:
        vec[vocab.index(value)] = 1.0
    else:
        warnings.append(f"Unrecognized {warning_label} '{value}' -- not in vocabulary, "
                         f"encoded as all-zero. Update feature_engineering.py's vocab list "
                         f"if this is a legitimate new value.")
    return vec


def _compute_asset_counts(nodes: list) -> Counter:
    counts = Counter()
    for n in nodes:
        asset = n["F"].get("A")
        if asset:
            counts[asset] += 1
    return counts


def _compute_graph_degrees(nodes: list, edges: list) -> dict:
    degree = defaultdict(int)
    for n in nodes:
        degree[n["node_id"]] = 0
    for e in edges:
        degree[e["source"]] += 1
        degree[e["target"]] += 1
    return degree


def build_node_features(graph_data: dict) -> dict:
    nodes = graph_data.get("nodes", [])
    edges = graph_data.get("edges", [])

    asset_counts = _compute_asset_counts(nodes)
    degrees = _compute_graph_degrees(nodes, edges)

    warnings = []
    feature_rows = []

    for n in nodes:
        f = n["F"]
        severity = f.get("S")
        layer = f.get("L")
        vtype = f.get("T")
        cve_present = bool(f.get("C", {}).get("cve_id"))
        cwe_present = bool(f.get("C", {}).get("cwe_id"))
        exploit_present = f.get("E") is not None

        if severity in SEVERITY_ORDINAL:
            severity_val = float(SEVERITY_ORDINAL[severity])
        else:
            severity_val = 0.0
            warnings.append(f"Node {n['node_id']}: unrecognized severity '{severity}' -- "
                             f"defaulted to 0.0 (info-level). Update SEVERITY_ORDINAL if this "
                             f"is a legitimate new severity value.")

        layer_vec = _one_hot(layer, LAYER_VOCAB, warnings, f"layer (node {n['node_id']})")
        type_vec = _one_hot(vtype, TYPE_VOCAB, warnings, f"finding type (node {n['node_id']})")

        asset = f.get("A")
        asset_count = asset_counts.get(asset, 0) if asset else 0
        degree = degrees.get(n["node_id"], 0)

        vector = (
            [severity_val]
            + layer_vec
            + type_vec
            + [1.0 if cve_present else 0.0,
               1.0 if cwe_present else 0.0,
               1.0 if exploit_present else 0.0]
            + [math.log1p(asset_count), math.log1p(degree)]
        )

        assert len(vector) == FEATURE_DIM, \
            f"feature vector length mismatch for {n['node_id']}: {len(vector)} != {FEATURE_DIM}"

        feature_rows.append({
            "node_id": n["node_id"],
            "features": vector,
        })

    return {
        "feature_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "feature_dim": FEATURE_DIM,
            "feature_names": FEATURE_NAMES,
            "severity_ordinal_map": SEVERITY_ORDINAL,
            "layer_vocab": LAYER_VOCAB,
            "type_vocab": TYPE_VOCAB,
            "excluded_raw_fields": {
                "name": "free text -- not encoded",
                "description": "free text -- not encoded",
                "evidence (W)": "free text -- not encoded; no embedding model introduced "
                                "to avoid adding an unvetted dependency/complexity for a "
                                "single free-text field",
                "asset (A) raw string": "excluded as a direct categorical/one-hot feature -- "
                                "cardinality is dataset-specific and one-hot encoding it "
                                "would leak node identity rather than a generalizable "
                                "pattern; only its DERIVED count (asset_finding_count_log) "
                                "is used",
            },
            "always_zero_today": {
                "has_cwe": "schema.py has no CWE field anywhere upstream -- always 0.0 "
                           "until CWE enrichment is added to a scanner",
                "has_exploitability_info": "schema.py has no exploitability field anywhere "
                           "upstream -- always 0.0 until such a field is added",
            },
            "warnings": warnings,
        },
        "node_features": feature_rows,
    }


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens Phase 3 - encode vulnerability graph nodes into numeric feature vectors."
    )
    parser.add_argument(
        "--input", default="outputs/vulnerability_graph.json",
        help="Path to the vulnerability graph JSON from Phase 2 (default: outputs/vulnerability_graph.json)",
    )
    parser.add_argument(
        "--output", default="outputs/node_features.json",
        help="Path to write the node feature matrix JSON (default: outputs/node_features.json)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        print("Hint: run graph/graph_builder.py first (Phase 2).", file=sys.stderr)
        sys.exit(1)

    with open(args.input) as f:
        graph_data = json.load(f)

    result = build_node_features(graph_data)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    meta = result["feature_metadata"]
    print(f"Encoded {len(result['node_features'])} node(s) from {args.input}")
    print(f"Feature dimension: {meta['feature_dim']}")
    print(f"Wrote {args.output}")
    if meta["warnings"]:
        print(f"WARNINGS ({len(meta['warnings'])}):")
        for w in meta["warnings"]:
            print(f"  - {w}")
    else:
        print("No unrecognized severity/layer/type values encountered.")


if __name__ == "__main__":
    main()