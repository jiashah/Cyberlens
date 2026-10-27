from dataclasses import dataclass, asdict, field
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
import uuid


class Layer(str, Enum):
    NETWORK = "network"
    SSL = "ssl"
    CLIENT = "client"
    APPLICATION = "application"
    API = "api"
    FINGERPRINT = "fingerprint"
    DEPENDENCY = "dependency"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    # Network
    OPEN_PORT = "open_port"
    OUTDATED_SERVICE_BANNER = "outdated_service_banner"
    WEAK_PROTOCOL = "weak_protocol"
    # SSL/TLS
    MISSING_TLS_CERT = "missing_tls_cert"
    WEAK_CIPHER_TLS_VERSION = "weak_cipher_tls_version"
    MISSING_HSTS = "missing_hsts"
    # HTTP Headers
    MISSING_CSP = "missing_csp"
    MISSING_XFO = "missing_xfo"
    MISSING_XCTO = "missing_xcto"
    # Cookies
    COOKIE_MISSING_SECURE = "cookie_missing_secure"
    COOKIE_MISSING_HTTPONLY = "cookie_missing_httponly"
    # Application / Injection
    XSS = "xss"
    SQLI = "sqli"
    BROKEN_AUTH = "broken_auth"
    IDOR = "idor"
    # API
    MISSING_RATE_LIMIT = "missing_rate_limit"
    VERBOSE_ERROR = "verbose_error"
    # Dependency / Fingerprint
    OUTDATED_JS_LIBRARY = "outdated_js_library"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    OUTDATED_FINGERPRINT = "outdated_fingerprint"


@dataclass
class Finding:
    layer: Layer
    target: str
    name: str
    type: str
    severity: Severity
    description: str
    evidence: str
    asset: str = "unknown"
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["severity"] = self.severity.value
        return d


def new_finding_batch() -> list:
    return []
