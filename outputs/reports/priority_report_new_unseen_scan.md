# Vulnerability Priority Report - `new_unseen_scan`

6 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 2, P2 - Fix soon: 0, P3 - Schedule: 4, P4 - Low / monitor: 0

**Warnings:**
- Unrecognized finding type (node VULN_001) 'ssrf' -- not in vocabulary, encoded as all-zero. Update feature_engineering.py's vocab list if this is a legitimate new value.

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_002 | Weak/unencrypted protocol in use: http | 9.55 | P1 - Fix immediately |
| 2 | VULN_001 | Server-side request forgery | 7.64 | P1 - Fix immediately |
| 3 | VULN_003 | No TLS/HTTPS listener | 5.37 | P3 - Schedule |
| 4 | VULN_005 | Missing security header: Content-Security-Policy | 5.26 | P3 - Schedule |
| 5 | VULN_004 | Missing HSTS header | 5.20 | P3 - Schedule |
| 6 | VULN_006 | Missing security header: X-Frame-Options | 5.17 | P3 - Schedule |

## Details

### 1. VULN_002 - Weak/unencrypted protocol in use: http

- **Predicted score:** 9.55 / 10 -> **P1 - Fix immediately**
- **Type / layer:** weak_protocol / network (scanner severity: critical)
- **Asset:** 127.0.0.1 | **Scanner CVSS:** 9.8
- **Suggested fix:** Replace the cleartext protocol with its encrypted equivalent.
- **Linked vulnerabilities (2):**
  - shares context with VULN_001 (Server-side request forgery, score 7.64) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.37) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 2. VULN_001 - Server-side request forgery

- **Predicted score:** 7.64 / 10 -> **P1 - Fix immediately**
- **Type / layer:** ssrf / application (scanner severity: high)
- **Asset:** 127.0.0.1
- **Suggested fix:** Review and remediate per vendor guidance.
- **Linked vulnerabilities (2):**
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 9.55) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.37) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 3. VULN_003 - No TLS/HTTPS listener

- **Predicted score:** 5.37 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: medium)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_004 (Missing HSTS header, score 5.20) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 9.55) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_001 (Server-side request forgery, score 7.64) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 4. VULN_005 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.26 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://shop.internal:8081/WebGoat
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (3):**
  - shares context with VULN_004 (Missing HSTS header, score 5.20) [co_context, weight 0.85] - Both findings share the exact same target ('http://shop.internal:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.17) [co_context, weight 0.85] - Both findings share the exact same target ('http://shop.internal:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.17) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.

### 5. VULN_004 - Missing HSTS header

- **Predicted score:** 5.20 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_hsts / ssl (scanner severity: medium)
- **Asset:** http://shop.internal:8081/WebGoat
- **Suggested fix:** Send Strict-Transport-Security with a long max-age.
- **Linked vulnerabilities (3):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.26) [co_context, weight 0.85] - Both findings share the exact same target ('http://shop.internal:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.17) [co_context, weight 0.85] - Both findings share the exact same target ('http://shop.internal:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_003 (No TLS/HTTPS listener, score 5.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.

### 6. VULN_006 - Missing security header: X-Frame-Options

- **Predicted score:** 5.17 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / client (scanner severity: medium)
- **Asset:** http://shop.internal:8081/WebGoat
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (3):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.26) [co_context, weight 0.85] - Both findings share the exact same target ('http://shop.internal:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.20) [co_context, weight 0.85] - Both findings share the exact same target ('http://shop.internal:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.26) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
