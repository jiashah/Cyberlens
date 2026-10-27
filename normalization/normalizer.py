import argparse
import json
import os
import sys
from datetime import datetime, timezone

KNOWN_SEVERITIES = ("critical", "high", "medium", "low", "info")


def normalize_finding(raw: dict) -> dict:
    asset = raw.get("asset")
    if not asset or asset == "unknown":
        asset = raw.get("target")

    cve_id = raw.get("cve_id")  

    f_i = {
        "T": raw.get("type"),
        "S": raw.get("severity"),
        "A": asset,
        "L": raw.get("layer"),
        "C": {
            "cve_id": cve_id,
            "cwe_id": None,  
        },
        "W": raw.get("evidence"),
        "E": None,
    }

    return {
        "id": raw.get("id"),
        "name": raw.get("name"),
        "description": raw.get("description"),
        "target": raw.get("target"),
        "timestamp": raw.get("timestamp"),
        "F": f_i,
        "raw": raw,  
    }


def normalize_scan_output(scan_output: dict, source_file: str) -> dict:
    findings = scan_output.get("findings", [])
    normalized = [normalize_finding(f) for f in findings]

    severity_counts = {s: 0 for s in KNOWN_SEVERITIES}
    unknown_severities = set()
    missing_cve = 0
    missing_asset_fallback = 0

    for raw in findings:
        sev = raw.get("severity")
        if sev in severity_counts:
            severity_counts[sev] += 1
        else:
            unknown_severities.add(sev)
        if not raw.get("cve_id"):
            missing_cve += 1
        if not raw.get("asset") or raw.get("asset") == "unknown":
            missing_asset_fallback += 1

    return {
        "normalization_metadata": {
            "source_file": source_file,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "finding_count": len(findings),
            "severity_distribution": severity_counts,
            "unknown_severities_seen": sorted(s for s in unknown_severities if s is not None),
            "findings_without_cve": missing_cve,
            "findings_with_asset_fallback_to_target": missing_asset_fallback,
            "cwe_available": False,   
            "exploitability_available": False, 
        },
        "scan_metadata": scan_output.get("scan_metadata", {}),
        "normalized_findings": normalized,
    }


def main():
    parser = argparse.ArgumentParser(
        description="CyberLens Phase 1 - normalize raw scan_output.json into F_i representation."
    )
    parser.add_argument(
        "--input", default="output/scan_output.json",
        help="Path to the raw scanner output JSON (default: output/scan_output.json)",
    )
    parser.add_argument(
        "--output", default="outputs/normalized_findings.json",
        help="Path to write the normalized findings JSON (default: outputs/normalized_findings.json)",
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"ERROR: input file not found: {args.input}", file=sys.stderr)
        print(
            "Hint: output/scan_output.json is only created by running orchestrator.py "
            "against a live target. Until then, point --input at one of the existing "
            "fixture/scan files, e.g.:\n"
            "  output/sample_scan_output.json\n"
            "  output/webgoat_scan.json\n"
            "  output/owasp_juice_shop_scan.json\n"
            "  output/crapi_root_scan.json\n"
            "  output/crapi_full_scan.json",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(args.input) as f:
        scan_output = json.load(f)

    result = normalize_scan_output(scan_output, source_file=args.input)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(result, f, indent=2)

    meta = result["normalization_metadata"]
    print(f"Normalized {meta['finding_count']} findings from {args.input}")
    print(f"Wrote {args.output}")
    print(f"Severity distribution: {meta['severity_distribution']}")
    if meta["unknown_severities_seen"]:
        print(f"WARNING: unrecognized severity values seen: {meta['unknown_severities_seen']}")
    print(f"Findings without a CVE: {meta['findings_without_cve']} / {meta['finding_count']}")
    print("CWE field: unavailable in current scanner schema (kept null, not invented)")
    print("Exploitability field: unavailable in current scanner schema (kept null, not invented)")


if __name__ == "__main__":
    main()
