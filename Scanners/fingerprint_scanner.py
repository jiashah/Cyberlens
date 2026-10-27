import re
import requests
from schema import Finding, Layer, Severity, FindingType

KNOWN_STACK_SIGNATURES = {
    "PHP":     (r"PHP/([\d.]+)", "7.4"),
    "Apache":  (r"Apache/([\d.]+)", "2.4.50"),
    "nginx":   (r"nginx/([\d.]+)", "1.20.0"),
    "Node.js": (r"Express|Node\.js", None),
}


def _version_lt(v1: str, v2: str) -> bool:
    parts1 = [int(x) for x in re.findall(r"\d+", v1)]
    parts2 = [int(x) for x in re.findall(r"\d+", v2)]
    return parts1 < parts2


def scan_fingerprint(target_url: str) -> list[Finding]:
    findings = []
    try:
        resp = requests.get(target_url, timeout=10)
    except requests.RequestException:
        return findings

    banner_sources = " ".join([
        resp.headers.get("Server", ""),
        resp.headers.get("X-Powered-By", ""),
    ])

    for tech, (pattern, min_safe) in KNOWN_STACK_SIGNATURES.items():
        match = re.search(pattern, banner_sources, re.IGNORECASE)
        if not match:
            continue

        version = match.group(1) if match.groups() else None

        if version and min_safe and _version_lt(version, min_safe):
            findings.append(
                Finding(
                    layer=Layer.FINGERPRINT,
                    target=target_url,
                    name=f"Outdated {tech} version detected: {version}",
                    type=FindingType.OUTDATED_FINGERPRINT.value,
                    severity=Severity.MEDIUM,
                    description=f"{tech} {version} is below recommended minimum {min_safe}.",
                    evidence=f"banner={banner_sources.strip()}",
                    asset=target_url,
                )
            )
        elif version is None and tech == "Node.js":
            findings.append(
                Finding(
                    layer=Layer.FINGERPRINT,
                    target=target_url,
                    name=f"Technology fingerprint: {tech}",
                    type=FindingType.OUTDATED_FINGERPRINT.value,
                    severity=Severity.INFO,
                    description=f"Detected {tech} in use (version undetermined).",
                    evidence=f"banner={banner_sources.strip()}",
                    asset=target_url,
                )
            )

    return findings


if __name__ == "__main__":
    results = scan_fingerprint("http://localhost:3000")
    for f in results:
        print(f.to_dict())
