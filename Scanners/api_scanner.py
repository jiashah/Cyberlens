import re
import requests
from schema import Finding, Layer, Severity, FindingType

STACK_TRACE_PATTERNS = [
    r"Traceback \(most recent call last\)",
    r"at\s+\w+(\.\w+)+\(.*:\d+:\d+\)",
    r"Exception in thread",
    r"Fatal error:.*on line \d+",
    r"System\.\w+Exception",
    r"org\.\w+\.\w+Exception",
]


def authenticate(login_url: str, email: str, password: str, token_field: str = "token"):
    try:
        resp = requests.post(login_url, json={"email": email, "password": password}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            return data.get(token_field) or data.get("access_token") or data.get("jwt")
    except (requests.RequestException, ValueError):
        pass
    return None


def check_rate_limiting(
    target_url: str,
    method: str = "GET",
    json_body: dict = None,
    burst_count: int = 20,
) -> list[Finding]:
    findings = []
    throttled = False
    method = method.upper()

    for _ in range(burst_count):
        try:
            if method == "POST":
                resp = requests.post(target_url, json=json_body, timeout=5)
            else:
                resp = requests.get(target_url, timeout=5)

            if resp.status_code == 429 or "Retry-After" in resp.headers:
                throttled = True
                break
        except requests.RequestException:
            break

    if not throttled:
        findings.append(
            Finding(
                layer=Layer.API,
                target=target_url,
                name="No rate limiting detected on endpoint",
                type=FindingType.MISSING_RATE_LIMIT.value,
                severity=Severity.MEDIUM,
                description=f"Sent {burst_count} rapid {method} requests "
                            f"with no throttling response (429/Retry-After).",
                evidence=f"method={method}, requests_sent={burst_count}, throttled=False",
                asset=target_url,
            )
        )
    return findings


def check_verbose_errors(target_url: str, malformed_paths: list = None,
                          headers: dict = None) -> list[Finding]:
    findings = []
    malformed_paths = malformed_paths or [
        "/%00", "/../../etc/passwd", "/?id=", "/nonexistent_endpoint_xyz",
    ]

    for path in malformed_paths:
        try:
            resp = requests.get(target_url.rstrip("/") + path, headers=headers, timeout=5)
            for pattern in STACK_TRACE_PATTERNS:
                if re.search(pattern, resp.text):
                    findings.append(
                        Finding(
                            layer=Layer.API,
                            target=target_url + path,
                            name="Verbose error / stack trace leakage",
                            type=FindingType.VERBOSE_ERROR.value,
                            severity=Severity.MEDIUM,
                            description="Server response contains stack-trace-like content, "
                                        "leaking implementation details.",
                            evidence=resp.text[:300],
                            asset=target_url,
                        )
                    )
                    break
        except requests.RequestException:
            continue

    return findings


def check_idor(
    target_url: str,
    id_param: str = "id",
    id_range: range = range(1, 6),
    auth_token: str = None,
    id_in_path: bool = False,
) -> list[Finding]:
    findings = []
    responses = []
    headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else {}

    for i in id_range:
        try:
            if id_in_path:
                url = f"{target_url.rstrip('/')}/{i}"
                resp = requests.get(url, headers=headers, timeout=5)
            else:
                resp = requests.get(target_url, params={id_param: i}, headers=headers, timeout=5)
            responses.append((i, resp.status_code, len(resp.text)))
        except requests.RequestException:
            continue

    successful = [r for r in responses if r[1] == 200]
    if len(successful) >= 3:
        findings.append(
            Finding(
                layer=Layer.API,
                target=target_url,
                name=f"Potential IDOR/BOLA via sequential object IDs"
                     f"{' (authenticated)' if auth_token else ''}",
                type=FindingType.IDOR.value,
                severity=Severity.HIGH if auth_token else Severity.MEDIUM,
                description=f"{len(successful)} sequential object IDs returned 200 OK "
                            f"using a single user's session — flag for manual verification.",
                evidence=f"tested_ids={[r[0] for r in responses]}, results={responses}",
                asset=target_url,
            )
        )
    return findings


def check_broken_auth(login_url: str, default_creds: list = None) -> list[Finding]:
    findings = []
    default_creds = default_creds or [
        ("admin@juice-sh.op", "admin123"),
        ("admin@example.com", "admin"),
        ("test@test.com", "test"),
    ]

    for email, password in default_creds:
        try:
            resp = requests.post(login_url, json={"email": email, "password": password}, timeout=5)
            if resp.status_code == 200 and ("token" in resp.text.lower()
                                             or "jwt" in resp.text.lower()):
                findings.append(
                    Finding(
                        layer=Layer.API,
                        target=login_url,
                        name="Default/weak credentials accepted",
                        type=FindingType.BROKEN_AUTH.value,
                        severity=Severity.CRITICAL,
                        description=f"Login succeeded with default credentials '{email}'.",
                        evidence=f"email={email}, password={'*' * len(password)}",
                        asset=login_url,
                    )
                )
                break
        except requests.RequestException:
            continue

    return findings


def scan_api(
    target_url: str,
    login_url: str = None,
    rate_limit_method: str = "GET",
    rate_limit_body: dict = None,
    idor_url: str = None,
    idor_in_path: bool = False,
    auth_email: str = None,
    auth_password: str = None,
) -> list[Finding]:
    findings = []
    findings.extend(check_rate_limiting(target_url, method=rate_limit_method, json_body=rate_limit_body))
    findings.extend(check_verbose_errors(target_url))

    token = None
    if login_url and auth_email and auth_password:
        token = authenticate(login_url, auth_email, auth_password)

    if idor_url:
        findings.extend(check_idor(idor_url, auth_token=token, id_in_path=idor_in_path))

    if login_url:
        findings.extend(check_broken_auth(login_url))

    return findings


if __name__ == "__main__":
    results = scan_api(
        target_url="http://localhost:8888/identity/api/auth/login",
        rate_limit_method="POST",
        rate_limit_body={"email": "test@test.com", "password": "wrongpass"},
        login_url="http://localhost:8888/identity/api/auth/login",
        idor_url="http://localhost:8888/workshop/api/shop/orders",
        idor_in_path=True,
        auth_email="victim@example.com",
        auth_password="victimpass",
    )
    for f in results:
        print(f.to_dict())
