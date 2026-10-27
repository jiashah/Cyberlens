# Vulnerability Priority Report - `webgoat_all_layers`

13 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 1, P2 - Fix soon: 2, P3 - Schedule: 8, P4 - Low / monitor: 2

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_012 | SQL Injection | 8.21 | P1 - Fix immediately |
| 2 | VULN_009 | Content Security Policy (CSP) Header Not Set | 5.91 | P2 - Fix soon |
| 3 | VULN_005 | Missing security header: Content-Security-Policy | 5.56 | P2 - Fix soon |
| 4 | VULN_003 | No TLS/HTTPS listener | 5.46 | P3 - Schedule |
| 5 | VULN_008 | Missing Anti-clickjacking Header | 5.44 | P3 - Schedule |
| 6 | VULN_013 | No rate limiting detected on endpoint | 5.38 | P3 - Schedule |
| 7 | VULN_006 | Missing security header: X-Frame-Options | 5.30 | P3 - Schedule |
| 8 | VULN_004 | Missing HSTS header | 5.21 | P3 - Schedule |
| 9 | VULN_011 | User Controllable HTML Element Attribute (Potential XSS) | 3.63 | P3 - Schedule |
| 10 | VULN_002 | Weak/unencrypted protocol in use: http | 3.55 | P3 - Schedule |
| 11 | VULN_010 | X-Content-Type-Options Header Missing | 3.52 | P3 - Schedule |
| 12 | VULN_007 | Missing security header: X-Content-Type-Options | 3.31 | P4 - Low / monitor |
| 13 | VULN_001 | Open port 8081/tcp (http) | 2.97 | P4 - Low / monitor |

## Details

### 1. VULN_012 - SQL Injection

- **Predicted score:** 8.21 / 10 -> **P1 - Fix immediately**
- **Type / layer:** sqli / application (scanner severity: high)
- **Asset:** http://host.docker.internal:8081/WebGoat
- **Suggested fix:** Use parameterised queries / an ORM; validate and escape all input.
- **Linked vulnerabilities (5):**
  - shares context with VULN_011 (User Controllable HTML Element Attribute (Potential XSS), score 3.63) [co_context, weight 0.85] - Both findings share the exact same target ('http://host.docker.internal:8081/WebGoat/register.mvc'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_011 (User Controllable HTML Element Attribute (Potential XSS), score 3.63) [shared_root_cause, weight 0.6] - Both finding types belong to the 'input_validation_gap' configuration-weakness family.
  - shares context with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:8081/WebGoat' and the same security layer ('application').
  - shares context with VULN_008 (Missing Anti-clickjacking Header, score 5.44) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:8081/WebGoat' and the same security layer ('application').
  - shares context with VULN_010 (X-Content-Type-Options Header Missing, score 3.52) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:8081/WebGoat' and the same security layer ('application').

### 2. VULN_009 - Content Security Policy (CSP) Header Not Set

- **Predicted score:** 5.91 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_csp / application (scanner severity: medium)
- **Asset:** http://host.docker.internal:8081/WebGoat
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (9):**
  - can be chained with VULN_011 (User Controllable HTML Element Attribute (Potential XSS), score 3.63) [chaining, weight 0.9] - A Content-Security-Policy is a primary mitigation against XSS payload execution; its absence directly increases the impact of the XSS finding.
  - shares context with VULN_008 (Missing Anti-clickjacking Header, score 5.44) [co_context, weight 0.85] - Both findings share the exact same target ('http://host.docker.internal:8081/WebGoat/login'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_008 (Missing Anti-clickjacking Header, score 5.44) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.30) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_010 (X-Content-Type-Options Header Missing, score 3.52) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 4 more (see JSON report)

### 3. VULN_005 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.56 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://localhost:8081/WebGoat
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (8):**
  - shares context with VULN_013 (No rate limiting detected on endpoint, score 5.38) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.30) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.21) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_008 (Missing Anti-clickjacking Header, score 5.44) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 3 more (see JSON report)

### 4. VULN_003 - No TLS/HTTPS listener

- **Predicted score:** 5.46 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: medium)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_004 (Missing HSTS header, score 5.21) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_001 (Open port 8081/tcp (http), score 2.97) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 5. VULN_008 - Missing Anti-clickjacking Header

- **Predicted score:** 5.44 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / application (scanner severity: medium)
- **Asset:** http://host.docker.internal:8081/WebGoat
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (9):**
  - shares context with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [co_context, weight 0.85] - Both findings share the exact same target ('http://host.docker.internal:8081/WebGoat/login'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.56) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_010 (X-Content-Type-Options Header Missing, score 3.52) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_007 (Missing security header: X-Content-Type-Options, score 3.31) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 4 more (see JSON report)

### 6. VULN_013 - No rate limiting detected on endpoint

- **Predicted score:** 5.38 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:8081/WebGoat
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities (4):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.56) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.30) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.21) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.

### 7. VULN_006 - Missing security header: X-Frame-Options

- **Predicted score:** 5.30 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / client (scanner severity: medium)
- **Asset:** http://localhost:8081/WebGoat
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (8):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.56) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_013 (No rate limiting detected on endpoint, score 5.38) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.21) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 3 more (see JSON report)

### 8. VULN_004 - Missing HSTS header

- **Predicted score:** 5.21 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_hsts / ssl (scanner severity: medium)
- **Asset:** http://localhost:8081/WebGoat
- **Suggested fix:** Send Strict-Transport-Security with a long max-age.
- **Linked vulnerabilities (5):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.56) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_013 (No rate limiting detected on endpoint, score 5.38) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.30) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_003 (No TLS/HTTPS listener, score 5.46) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.

### 9. VULN_011 - User Controllable HTML Element Attribute (Potential XSS)

- **Predicted score:** 3.63 / 10 -> **P3 - Schedule**
- **Type / layer:** xss / application (scanner severity: info)
- **Asset:** http://host.docker.internal:8081/WebGoat
- **Suggested fix:** Context-aware output encoding, input validation and a strict CSP.
- **Linked vulnerabilities (7):**
  - can be chained with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [chaining, weight 0.9] - A Content-Security-Policy is a primary mitigation against XSS payload execution; its absence directly increases the impact of the XSS finding.
  - shares context with VULN_012 (SQL Injection, score 8.21) [co_context, weight 0.85] - Both findings share the exact same target ('http://host.docker.internal:8081/WebGoat/register.mvc'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_012 (SQL Injection, score 8.21) [shared_root_cause, weight 0.6] - Both finding types belong to the 'input_validation_gap' configuration-weakness family.
  - shares context with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:8081/WebGoat' and the same security layer ('application').
  - shares context with VULN_008 (Missing Anti-clickjacking Header, score 5.44) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:8081/WebGoat' and the same security layer ('application').
  - ...and 2 more (see JSON report)

### 10. VULN_002 - Weak/unencrypted protocol in use: http

- **Predicted score:** 3.55 / 10 -> **P3 - Schedule**
- **Type / layer:** weak_protocol / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Replace the cleartext protocol with its encrypted equivalent.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_001 (Open port 8081/tcp (http), score 2.97) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_001 (Open port 8081/tcp (http), score 2.97) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.46) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 11. VULN_010 - X-Content-Type-Options Header Missing

- **Predicted score:** 3.52 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xcto / application (scanner severity: low)
- **Asset:** http://host.docker.internal:8081/WebGoat
- **Suggested fix:** Send X-Content-Type-Options: nosniff.
- **Linked vulnerabilities (8):**
  - shares a root cause with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.56) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_008 (Missing Anti-clickjacking Header, score 5.44) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.30) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_012 (SQL Injection, score 8.21) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:8081/WebGoat' and the same security layer ('application').
  - ...and 3 more (see JSON report)

### 12. VULN_007 - Missing security header: X-Content-Type-Options

- **Predicted score:** 3.31 / 10 -> **P4 - Low / monitor**
- **Type / layer:** missing_xcto / client (scanner severity: low)
- **Asset:** http://localhost:8081/WebGoat
- **Suggested fix:** Send X-Content-Type-Options: nosniff.
- **Linked vulnerabilities (8):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.56) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_013 (No rate limiting detected on endpoint, score 5.38) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.30) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.21) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8081/WebGoat'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_009 (Content Security Policy (CSP) Header Not Set, score 5.91) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 3 more (see JSON report)

### 13. VULN_001 - Open port 8081/tcp (http)

- **Predicted score:** 2.97 / 10 -> **P4 - Low / monitor**
- **Type / layer:** open_port / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Close or firewall services that do not need to be exposed.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.46) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
