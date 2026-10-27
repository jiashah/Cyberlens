import json
import subprocess
from schema import Finding, Layer, Severity, FindingType

NPM_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def scan_python_dependencies(project_path: str) -> list[Finding]:
    findings = []
    try:
        result = subprocess.run(
            ["pip-audit", "-r", f"{project_path}/requirements.txt", "-f", "json"],
            capture_output=True, text=True, timeout=300,
        )
        data = json.loads(result.stdout or "[]")
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"pip-audit failed: {e}")
        return findings

    for dep in data:
        pkg_name = dep.get("name", "unknown")
        version = dep.get("version", "")
        for vuln in dep.get("vulns", []):
            findings.append(
                Finding(
                    layer=Layer.DEPENDENCY,
                    target=f"{pkg_name}=={version}",
                    name=f"Vulnerable dependency: {pkg_name} {version}",
                    type=FindingType.VULNERABLE_DEPENDENCY.value,
                    severity=Severity.HIGH,
                    description=vuln.get("description", ""),
                    evidence=f"fix_versions={vuln.get('fix_versions', [])}",
                    asset=project_path,
                    cve_id=vuln.get("id"),
                )
            )
    return findings


def scan_node_dependencies(project_path: str) -> list[Finding]:
    findings = []
    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=project_path, capture_output=True, text=True, timeout=300,
        )
        data = json.loads(result.stdout or "{}")
    except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"npm audit failed: {e}")
        return findings

    vulnerabilities = data.get("vulnerabilities", {})
    for pkg_name, info in vulnerabilities.items():
        severity = NPM_SEVERITY_MAP.get(info.get("severity", "info"), Severity.INFO)
        via = info.get("via", [])
        cve_ids = [v.get("url", "") for v in via if isinstance(v, dict)]

        findings.append(
            Finding(
                layer=Layer.DEPENDENCY,
                target=pkg_name,
                name=f"Vulnerable dependency: {pkg_name}",
                type=FindingType.VULNERABLE_DEPENDENCY.value,
                severity=severity,
                description=f"npm audit flagged {pkg_name} ({info.get('range', '')})",
                evidence=json.dumps(via)[:500],
                asset=project_path,
                cve_id=cve_ids[0] if cve_ids else None,
            )
        )
    return findings


def scan_dependencies(project_path: str, ecosystem: str = "python") -> list[Finding]:
    if ecosystem == "python":
        return scan_python_dependencies(project_path)
    elif ecosystem == "node":
        return scan_node_dependencies(project_path)
    else:
        raise ValueError(f"Unsupported ecosystem: {ecosystem}")


if __name__ == "__main__":
    results = scan_dependencies("./sample_target_project", ecosystem="python")
    for f in results:
        print(f.to_dict())
