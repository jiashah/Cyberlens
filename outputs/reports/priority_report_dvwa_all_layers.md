# Vulnerability Priority Report - `dvwa_all_layers`

13 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 0, P2 - Fix soon: 2, P3 - Schedule: 8, P4 - Low / monitor: 3

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_010 | Content Security Policy (CSP) Header Not Set | 5.64 | P2 - Fix soon |
| 2 | VULN_005 | Missing security header: Content-Security-Policy | 5.61 | P2 - Fix soon |
| 3 | VULN_003 | No TLS/HTTPS listener | 5.47 | P3 - Schedule |
| 4 | VULN_013 | No rate limiting detected on endpoint | 5.44 | P3 - Schedule |
| 5 | VULN_011 | Missing Anti-clickjacking Header | 5.37 | P3 - Schedule |
| 6 | VULN_009 | Cookie 'PHPSESSID' missing HttpOnly flag | 5.36 | P3 - Schedule |
| 7 | VULN_008 | Cookie 'PHPSESSID' missing Secure flag | 5.30 | P3 - Schedule |
| 8 | VULN_006 | Missing security header: X-Frame-Options | 5.29 | P3 - Schedule |
| 9 | VULN_004 | Missing HSTS header | 5.21 | P3 - Schedule |
| 10 | VULN_002 | Weak/unencrypted protocol in use: http | 3.55 | P3 - Schedule |
| 11 | VULN_012 | X-Content-Type-Options Header Missing | 3.41 | P4 - Low / monitor |
| 12 | VULN_007 | Missing security header: X-Content-Type-Options | 3.37 | P4 - Low / monitor |
| 13 | VULN_001 | Open port 4280/tcp (http) | 2.97 | P4 - Low / monitor |

## Details

### 1. VULN_010 - Content Security Policy (CSP) Header Not Set

- **Predicted score:** 5.64 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_csp / application (scanner severity: medium)
- **Asset:** http://host.docker.internal:4280
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_011 (Missing Anti-clickjacking Header, score 5.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.29) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_012 (X-Content-Type-Options Header Missing, score 3.41) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_007 (Missing security header: X-Content-Type-Options, score 3.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_011 (Missing Anti-clickjacking Header, score 5.37) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:4280' and the same security layer ('application').
  - ...and 1 more (see JSON report)

### 2. VULN_005 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.61 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://localhost:4280
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (10):**
  - shares a root cause with VULN_011 (Missing Anti-clickjacking Header, score 5.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.29) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_012 (X-Content-Type-Options Header Missing, score 3.41) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_007 (Missing security header: X-Content-Type-Options, score 3.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_009 (Cookie 'PHPSESSID' missing HttpOnly flag, score 5.36) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - ...and 5 more (see JSON report)

### 3. VULN_003 - No TLS/HTTPS listener

- **Predicted score:** 5.47 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: medium)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_004 (Missing HSTS header, score 5.21) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_001 (Open port 4280/tcp (http), score 2.97) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 4. VULN_013 - No rate limiting detected on endpoint

- **Predicted score:** 5.44 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:4280
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities (6):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_009 (Cookie 'PHPSESSID' missing HttpOnly flag, score 5.36) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_008 (Cookie 'PHPSESSID' missing Secure flag, score 5.30) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.29) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_004 (Missing HSTS header, score 5.21) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 5. VULN_011 - Missing Anti-clickjacking Header

- **Predicted score:** 5.37 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / application (scanner severity: medium)
- **Asset:** http://host.docker.internal:4280
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_010 (Content Security Policy (CSP) Header Not Set, score 5.64) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_012 (X-Content-Type-Options Header Missing, score 3.41) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_007 (Missing security header: X-Content-Type-Options, score 3.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_010 (Content Security Policy (CSP) Header Not Set, score 5.64) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:4280' and the same security layer ('application').
  - ...and 1 more (see JSON report)

### 6. VULN_009 - Cookie 'PHPSESSID' missing HttpOnly flag

- **Predicted score:** 5.36 / 10 -> **P3 - Schedule**
- **Type / layer:** cookie_missing_httponly / client (scanner severity: medium)
- **Asset:** http://localhost:4280
- **Suggested fix:** Set the HttpOnly flag on session cookies.
- **Linked vulnerabilities (7):**
  - shares a root cause with VULN_008 (Cookie 'PHPSESSID' missing Secure flag, score 5.30) [shared_root_cause, weight 0.6] - Both finding types belong to the 'cookie_hardening_gap' configuration-weakness family.
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - shares context with VULN_008 (Cookie 'PHPSESSID' missing Secure flag, score 5.30) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.29) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.37) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - ...and 2 more (see JSON report)

### 7. VULN_008 - Cookie 'PHPSESSID' missing Secure flag

- **Predicted score:** 5.30 / 10 -> **P3 - Schedule**
- **Type / layer:** cookie_missing_secure / client (scanner severity: medium)
- **Asset:** http://localhost:4280
- **Suggested fix:** Set the Secure flag on session cookies.
- **Linked vulnerabilities (7):**
  - shares a root cause with VULN_009 (Cookie 'PHPSESSID' missing HttpOnly flag, score 5.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'cookie_hardening_gap' configuration-weakness family.
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - shares context with VULN_009 (Cookie 'PHPSESSID' missing HttpOnly flag, score 5.36) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.29) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.37) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - ...and 2 more (see JSON report)

### 8. VULN_006 - Missing security header: X-Frame-Options

- **Predicted score:** 5.29 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / client (scanner severity: medium)
- **Asset:** http://localhost:4280
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (10):**
  - shares a root cause with VULN_010 (Content Security Policy (CSP) Header Not Set, score 5.64) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_012 (X-Content-Type-Options Header Missing, score 3.41) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_007 (Missing security header: X-Content-Type-Options, score 3.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - ...and 5 more (see JSON report)

### 9. VULN_004 - Missing HSTS header

- **Predicted score:** 5.21 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_hsts / ssl (scanner severity: medium)
- **Asset:** http://localhost:4280
- **Suggested fix:** Send Strict-Transport-Security with a long max-age.
- **Linked vulnerabilities (7):**
  - shares a root cause with VULN_003 (No TLS/HTTPS listener, score 5.47) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_013 (No rate limiting detected on endpoint, score 5.44) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_009 (Cookie 'PHPSESSID' missing HttpOnly flag, score 5.36) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_008 (Cookie 'PHPSESSID' missing Secure flag, score 5.30) [co_context, weight 0.3] - Both findings share asset 'http://localhost:4280' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 2 more (see JSON report)

### 10. VULN_002 - Weak/unencrypted protocol in use: http

- **Predicted score:** 3.55 / 10 -> **P3 - Schedule**
- **Type / layer:** weak_protocol / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Replace the cleartext protocol with its encrypted equivalent.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_001 (Open port 4280/tcp (http), score 2.97) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_001 (Open port 4280/tcp (http), score 2.97) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.47) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 11. VULN_012 - X-Content-Type-Options Header Missing

- **Predicted score:** 3.41 / 10 -> **P4 - Low / monitor**
- **Type / layer:** missing_xcto / application (scanner severity: low)
- **Asset:** http://host.docker.internal:4280
- **Suggested fix:** Send X-Content-Type-Options: nosniff.
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_010 (Content Security Policy (CSP) Header Not Set, score 5.64) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_011 (Missing Anti-clickjacking Header, score 5.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.29) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_010 (Content Security Policy (CSP) Header Not Set, score 5.64) [co_context, weight 0.55] - Both findings share asset 'http://host.docker.internal:4280' and the same security layer ('application').
  - ...and 1 more (see JSON report)

### 12. VULN_007 - Missing security header: X-Content-Type-Options

- **Predicted score:** 3.37 / 10 -> **P4 - Low / monitor**
- **Type / layer:** missing_xcto / client (scanner severity: low)
- **Asset:** http://localhost:4280
- **Suggested fix:** Send X-Content-Type-Options: nosniff.
- **Linked vulnerabilities (10):**
  - shares a root cause with VULN_010 (Content Security Policy (CSP) Header Not Set, score 5.64) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_011 (Missing Anti-clickjacking Header, score 5.37) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.29) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.61) [co_context, weight 0.55] - Both findings share asset 'http://localhost:4280' and the same security layer ('client').
  - ...and 5 more (see JSON report)

### 13. VULN_001 - Open port 4280/tcp (http)

- **Predicted score:** 2.97 / 10 -> **P4 - Low / monitor**
- **Type / layer:** open_port / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Close or firewall services that do not need to be exposed.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.47) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
