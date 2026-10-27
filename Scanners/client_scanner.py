import re
import requests
from bs4 import BeautifulSoup
from schema import Finding, Layer, Severity, FindingType

EXPECTED_HEADERS = {
    "Content-Security-Policy": (Severity.MEDIUM, FindingType.MISSING_CSP),
    "X-Frame-Options": (Severity.MEDIUM, FindingType.MISSING_XFO),
    "X-Content-Type-Options": (Severity.LOW, FindingType.MISSING_XCTO),
}

KNOWN_VULNERABLE_JS = {
    "jquery": {"max_safe_version": "3.5.0"},
    "angular": {"max_safe_version": "1.8.0"},
    "lodash": {"max_safe_version": "4.17.21"},
}


def _check_headers(url: str, headers: dict) -> list[Finding]:
    findings = []
    for header, (severity, finding_type) in EXPECTED_HEADERS.items():
        if header not in headers:
            findings.append(
                Finding(
                    layer=Layer.CLIENT,
                    target=url,
                    name=f"Missing security header: {header}",
                    type=finding_type.value,
                    severity=severity,
                    description=f"Response does not set the {header} header.",
                    evidence=f"headers_present={list(headers.keys())}",
                    asset=url,
                )
            )
    return findings


def _check_cookies(url: str, response: requests.Response) -> list[Finding]:
    findings = []
    for cookie in response.cookies:
        flags_missing = []
        if not cookie.secure:
            flags_missing.append("Secure")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags_missing.append("HttpOnly")

        if "Secure" in flags_missing:
            findings.append(
                Finding(
                    layer=Layer.CLIENT, target=url,
                    name=f"Cookie '{cookie.name}' missing Secure flag",
                    type=FindingType.COOKIE_MISSING_SECURE.value,
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{cookie.name}' can be sent over unencrypted connections.",
                    evidence=f"cookie={cookie.name}", asset=url,
                )
            )
        if "HttpOnly" in flags_missing:
            findings.append(
                Finding(
                    layer=Layer.CLIENT, target=url,
                    name=f"Cookie '{cookie.name}' missing HttpOnly flag",
                    type=FindingType.COOKIE_MISSING_HTTPONLY.value,
                    severity=Severity.MEDIUM,
                    description=f"Cookie '{cookie.name}' is accessible via JavaScript (XSS-exploitable).",
                    evidence=f"cookie={cookie.name}", asset=url,
                )
            )
    return findings


def _check_js_libraries(url: str, html: str) -> list[Finding]:
    findings = []
    soup = BeautifulSoup(html, "html.parser")
    scripts = [tag.get("src", "") for tag in soup.find_all("script") if tag.get("src")]

    for src in scripts:
        for lib, info in KNOWN_VULNERABLE_JS.items():
            match = re.search(rf"{lib}[-.]?([\d.]+)", src, re.IGNORECASE)
            if match:
                version = match.group(1)
                if version < info["max_safe_version"]:
                    findings.append(
                        Finding(
                            layer=Layer.CLIENT,
                            target=url,
                            name=f"Outdated JS library: {lib} {version}",
                            type=FindingType.OUTDATED_JS_LIBRARY.value,
                            severity=Severity.MEDIUM,
                            description=f"{lib} version {version} is below "
                                        f"known-safe {info['max_safe_version']}.",
                            evidence=f"script_src={src}",
                            asset=url,
                        )
                    )
    return findings


def scan_client(target_url: str) -> list[Finding]:
    findings = []
    response = requests.get(target_url, timeout=10)

    findings.extend(_check_headers(target_url, response.headers))
    findings.extend(_check_cookies(target_url, response))
    findings.extend(_check_js_libraries(target_url, response.text))

    return findings


if __name__ == "__main__":
    results = scan_client("http://localhost:3000")
    for f in results:
        print(f.to_dict())
