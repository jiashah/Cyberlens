import ssl
import socket
import requests
from datetime import datetime
from schema import Finding, Layer, Severity, FindingType

WEAK_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}
WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "MD5", "NULL", "EXPORT")


def _check_certificate(host: str, port: int = 443) -> list[Finding]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.utcnow():
                    findings.append(
                        Finding(
                            layer=Layer.SSL,
                            target=f"{host}:{port}",
                            name="Expired TLS certificate",
                            type=FindingType.MISSING_TLS_CERT.value,
                            severity=Severity.HIGH,
                            description=f"Certificate expired on {cert['notAfter']}.",
                            evidence=f"notAfter={cert['notAfter']}",
                            asset=host,
                        )
                    )
    except ssl.SSLCertVerificationError as e:
        findings.append(
            Finding(
                layer=Layer.SSL,
                target=f"{host}:{port}",
                name="Invalid/untrusted TLS certificate",
                type=FindingType.MISSING_TLS_CERT.value,
                severity=Severity.HIGH,
                description=f"Certificate verification failed: {e}",
                evidence=str(e),
                asset=host,
            )
        )
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        findings.append(
            Finding(
                layer=Layer.SSL,
                target=f"{host}:{port}",
                name="No TLS/HTTPS listener",
                type=FindingType.MISSING_TLS_CERT.value,
                severity=Severity.MEDIUM,
                description=f"Could not establish TLS connection: {e}",
                evidence=str(e),
                asset=host,
            )
        )
    return findings


def _check_protocol_and_cipher(host: str, port: int = 443) -> list[Finding]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                version = ssock.version()
                cipher_name, _, _ = ssock.cipher()

                if version in WEAK_TLS_VERSIONS:
                    findings.append(
                        Finding(
                            layer=Layer.SSL,
                            target=f"{host}:{port}",
                            name=f"Weak TLS version negotiated: {version}",
                            type=FindingType.WEAK_CIPHER_TLS_VERSION.value,
                            severity=Severity.HIGH,
                            description=f"Server negotiated outdated protocol {version}.",
                            evidence=f"tls_version={version}",
                            asset=host,
                        )
                    )

                if any(weak in cipher_name for weak in WEAK_CIPHER_KEYWORDS):
                    findings.append(
                        Finding(
                            layer=Layer.SSL,
                            target=f"{host}:{port}",
                            name=f"Weak cipher suite negotiated: {cipher_name}",
                            type=FindingType.WEAK_CIPHER_TLS_VERSION.value,
                            severity=Severity.MEDIUM,
                            description=f"Server allows weak cipher {cipher_name}.",
                            evidence=f"cipher={cipher_name}",
                            asset=host,
                        )
                    )
    except (socket.timeout, ConnectionRefusedError, ssl.SSLError, OSError):
        pass
    return findings


def _check_hsts(target_url: str) -> list[Finding]:
    findings = []
    try:
        resp = requests.get(target_url, timeout=10)
        if "Strict-Transport-Security" not in resp.headers:
            findings.append(
                Finding(
                    layer=Layer.SSL,
                    target=target_url,
                    name="Missing HSTS header",
                    type=FindingType.MISSING_HSTS.value,
                    severity=Severity.MEDIUM,
                    description="Response does not set Strict-Transport-Security.",
                    evidence=f"headers_present={list(resp.headers.keys())}",
                    asset=target_url,
                )
            )
    except requests.RequestException:
        pass
    return findings


def scan_ssl(host: str, target_url: str = None, port: int = 443) -> list[Finding]:
    findings = []
    findings.extend(_check_certificate(host, port))
    findings.extend(_check_protocol_and_cipher(host, port))
    if target_url:
        findings.extend(_check_hsts(target_url))
    return findings


if __name__ == "__main__":
    results = scan_ssl("localhost", target_url="https://localhost:3000")
    for f in results:
        print(f.to_dict())
