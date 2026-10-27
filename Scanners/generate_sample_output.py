import json
from schema import Finding, Layer, Severity, FindingType

HOST = "192.168.56.101"
APP_URL = "http://localhost:3000"

findings = [
    # Network (#1-#3)
    Finding(layer=Layer.NETWORK, target=HOST, name="Open port 21/tcp (ftp)",
            type=FindingType.OPEN_PORT.value, severity=Severity.MEDIUM,
            description="FTP service exposed.", evidence="port=21, service=ftp", asset=HOST),
    Finding(layer=Layer.NETWORK, target=HOST, name="Outdated vsftpd banner: 2.3.4",
            type=FindingType.OUTDATED_SERVICE_BANNER.value, severity=Severity.HIGH,
            description="vsftpd 2.3.4 is below known-safe 3.0.3.",
            evidence="product=vsftpd, version=2.3.4", asset=HOST, cve_id="CVE-2011-2523"),
    Finding(layer=Layer.NETWORK, target=HOST, name="Weak/unencrypted protocol in use: ftp",
            type=FindingType.WEAK_PROTOCOL.value, severity=Severity.MEDIUM,
            description="ftp transmits data without encryption.", evidence="service=ftp, port=21", asset=HOST),

    # SSL/TLS (#4-#6)
    Finding(layer=Layer.SSL, target=f"{HOST}:443", name="Invalid/untrusted TLS certificate",
            type=FindingType.MISSING_TLS_CERT.value, severity=Severity.HIGH,
            description="Self-signed certificate not trusted by client.", evidence="issuer=self-signed", asset=HOST),
    Finding(layer=Layer.SSL, target=f"{HOST}:443", name="Weak TLS version negotiated: TLSv1.1",
            type=FindingType.WEAK_CIPHER_TLS_VERSION.value, severity=Severity.HIGH,
            description="Server negotiated outdated protocol TLSv1.1.", evidence="tls_version=TLSv1.1", asset=HOST),
    Finding(layer=Layer.SSL, target=APP_URL, name="Missing HSTS header",
            type=FindingType.MISSING_HSTS.value, severity=Severity.MEDIUM,
            description="Response does not set Strict-Transport-Security.",
            evidence="headers_present=['Content-Type']", asset=APP_URL),

    # Headers (#7-#9)
    Finding(layer=Layer.CLIENT, target=APP_URL, name="Missing security header: Content-Security-Policy",
            type=FindingType.MISSING_CSP.value, severity=Severity.MEDIUM,
            description="Response does not set Content-Security-Policy.",
            evidence="headers_present=['Content-Type','Server']", asset=APP_URL),
    Finding(layer=Layer.CLIENT, target=APP_URL, name="Missing security header: X-Frame-Options",
            type=FindingType.MISSING_XFO.value, severity=Severity.MEDIUM,
            description="Response does not set X-Frame-Options.", evidence="headers_present=[...]", asset=APP_URL),
    Finding(layer=Layer.CLIENT, target=APP_URL, name="Missing security header: X-Content-Type-Options",
            type=FindingType.MISSING_XCTO.value, severity=Severity.LOW,
            description="Response does not set X-Content-Type-Options.", evidence="headers_present=[...]", asset=APP_URL),

    # Cookies (#10-#11)
    Finding(layer=Layer.CLIENT, target=APP_URL, name="Cookie 'session' missing Secure flag",
            type=FindingType.COOKIE_MISSING_SECURE.value, severity=Severity.MEDIUM,
            description="Cookie 'session' can be sent over unencrypted connections.",
            evidence="cookie=session", asset=APP_URL),
    Finding(layer=Layer.CLIENT, target=APP_URL, name="Cookie 'session' missing HttpOnly flag",
            type=FindingType.COOKIE_MISSING_HTTPONLY.value, severity=Severity.MEDIUM,
            description="Cookie 'session' is accessible via JavaScript.",
            evidence="cookie=session", asset=APP_URL),

    # Application/Injection (#12-#13)
    Finding(layer=Layer.APPLICATION, target=f"{APP_URL}/#/login", name="Cross Site Scripting (Reflected)",
            type=FindingType.XSS.value, severity=Severity.HIGH,
            description="Reflected XSS in login redirect parameter.",
            evidence="redirect param unsanitized", asset=APP_URL),
    Finding(layer=Layer.APPLICATION, target=f"{APP_URL}/rest/products/search", name="SQL Injection",
            type=FindingType.SQLI.value, severity=Severity.HIGH,
            description="Parameter 'q' is vulnerable to SQL Injection.",
            evidence="q param unsanitized", asset=APP_URL),

    # API (#14-#17)
    Finding(layer=Layer.API, target=f"{APP_URL}/rest/user/login", name="Default/weak credentials accepted",
            type=FindingType.BROKEN_AUTH.value, severity=Severity.CRITICAL,
            description="Login succeeded with default credentials 'admin'.",
            evidence="username=admin", asset=APP_URL),
    Finding(layer=Layer.API, target=f"{APP_URL}/rest/basket", name="Potential IDOR via sequential 'id' parameter",
            type=FindingType.IDOR.value, severity=Severity.MEDIUM,
            description="4 sequential IDs returned 200 OK with no apparent access control.",
            evidence="tested_ids=[1,2,3,4]", asset=APP_URL),
    Finding(layer=Layer.API, target=f"{APP_URL}/rest/products/search", name="No rate limiting detected on endpoint",
            type=FindingType.MISSING_RATE_LIMIT.value, severity=Severity.MEDIUM,
            description="Sent 20 rapid requests with no throttling response.",
            evidence="requests_sent=20, throttled=False", asset=APP_URL),
    Finding(layer=Layer.API, target=f"{APP_URL}/nonexistent_endpoint_xyz", name="Verbose error / stack trace leakage",
            type=FindingType.VERBOSE_ERROR.value, severity=Severity.MEDIUM,
            description="Server response contains stack-trace-like content.",
            evidence="at handleError (app.js:245:12)", asset=APP_URL),

    # Dependency / Fingerprint (#18-#20)
    Finding(layer=Layer.CLIENT, target=APP_URL, name="Outdated JS library: jquery 3.1.1",
            type=FindingType.OUTDATED_JS_LIBRARY.value, severity=Severity.MEDIUM,
            description="jquery version 3.1.1 is below known-safe 3.5.0.",
            evidence="script_src=/assets/jquery-3.1.1.min.js", asset=APP_URL),
    Finding(layer=Layer.DEPENDENCY, target="lodash==4.17.11", name="Vulnerable dependency: lodash 4.17.11",
            type=FindingType.VULNERABLE_DEPENDENCY.value, severity=Severity.HIGH,
            description="Prototype pollution vulnerability in lodash < 4.17.21.",
            evidence="fix_versions=['4.17.21']", asset="./sample_target_project", cve_id="CVE-2020-8203"),
    Finding(layer=Layer.FINGERPRINT, target=APP_URL, name="Outdated PHP version detected: 7.2.1",
            type=FindingType.OUTDATED_FINGERPRINT.value, severity=Severity.MEDIUM,
            description="PHP 7.2.1 is below recommended minimum 7.4.",
            evidence="banner=PHP/7.2.1", asset=APP_URL),
]

result = {
    "scan_metadata": {
        "target_url": APP_URL,
        "target_host": HOST,
        "project_path": "./sample_target_project",
        "layers_scanned": ["network", "ssl", "client", "application", "api", "fingerprint", "dependency"],
        "timestamp": "2026-08-14T10:00:00Z",
        "errors": []
    },
    "findings": [f.to_dict() for f in findings]
}

import os
os.makedirs("output", exist_ok=True)
with open("output/sample_scan_output.json", "w") as f:
    json.dump(result, f, indent=2)

print(f"Generated {len(findings)} sample findings covering all 20 catalog items")
