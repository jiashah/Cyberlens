# Vulnerability Priority Report - `sample_scan_output`

20 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 6, P2 - Fix soon: 9, P3 - Schedule: 4, P4 - Low / monitor: 1

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_014 | Default/weak credentials accepted | 10.00 | P1 - Fix immediately |
| 2 | VULN_012 | Cross Site Scripting (Reflected) | 9.87 | P1 - Fix immediately |
| 3 | VULN_013 | SQL Injection | 8.75 | P1 - Fix immediately |
| 4 | VULN_002 | Outdated vsftpd banner: 2.3.4 | 8.28 | P1 - Fix immediately |
| 5 | VULN_019 | Vulnerable dependency: lodash 4.17.11 | 8.02 | P1 - Fix immediately |
| 6 | VULN_005 | Weak TLS version negotiated: TLSv1.1 | 7.50 | P1 - Fix immediately |
| 7 | VULN_004 | Invalid/untrusted TLS certificate | 7.35 | P2 - Fix soon |
| 8 | VULN_015 | Potential IDOR via sequential 'id' parameter | 6.76 | P2 - Fix soon |
| 9 | VULN_016 | No rate limiting detected on endpoint | 6.73 | P2 - Fix soon |
| 10 | VULN_007 | Missing security header: Content-Security-Policy | 5.80 | P2 - Fix soon |
| 11 | VULN_011 | Cookie 'session' missing HttpOnly flag | 5.72 | P2 - Fix soon |
| 12 | VULN_018 | Outdated JS library: jquery 3.1.1 | 5.72 | P2 - Fix soon |
| 13 | VULN_003 | Weak/unencrypted protocol in use: ftp | 5.66 | P2 - Fix soon |
| 14 | VULN_017 | Verbose error / stack trace leakage | 5.57 | P2 - Fix soon |
| 15 | VULN_020 | Outdated PHP version detected: 7.2.1 | 5.52 | P2 - Fix soon |
| 16 | VULN_008 | Missing security header: X-Frame-Options | 5.36 | P3 - Schedule |
| 17 | VULN_010 | Cookie 'session' missing Secure flag | 5.32 | P3 - Schedule |
| 18 | VULN_006 | Missing HSTS header | 5.29 | P3 - Schedule |
| 19 | VULN_001 | Open port 21/tcp (ftp) | 4.96 | P3 - Schedule |
| 20 | VULN_009 | Missing security header: X-Content-Type-Options | 3.35 | P4 - Low / monitor |

## Details

### 1. VULN_014 - Default/weak credentials accepted

- **Predicted score:** 10.00 / 10 -> **P1 - Fix immediately**
- **Type / layer:** broken_auth / api (scanner severity: critical)
- **Asset:** http://localhost:3000
- **Suggested fix:** Remove default credentials, enforce strong passwords and MFA.
- **Linked vulnerabilities (17):**
  - can be chained with VULN_015 (Potential IDOR via sequential 'id' parameter, score 6.76) [chaining, weight 0.85] - Successfully authenticating with default/weak credentials grants a valid session that can then be used to probe IDOR-vulnerable endpoints.
  - can be chained with VULN_016 (No rate limiting detected on endpoint, score 6.73) [chaining, weight 0.8] - Absence of rate limiting on an auth endpoint enables brute-forcing of the same weak/default credentials flagged by the broken-auth finding.
  - shares a root cause with VULN_015 (Potential IDOR via sequential 'id' parameter, score 6.76) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares a root cause with VULN_016 (No rate limiting detected on endpoint, score 6.73) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares context with VULN_015 (Potential IDOR via sequential 'id' parameter, score 6.76) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - ...and 12 more (see JSON report)

### 2. VULN_012 - Cross Site Scripting (Reflected)

- **Predicted score:** 9.87 / 10 -> **P1 - Fix immediately**
- **Type / layer:** xss / application (scanner severity: high)
- **Asset:** http://localhost:3000
- **Suggested fix:** Context-aware output encoding, input validation and a strict CSP.
- **Linked vulnerabilities (15):**
  - can be chained with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [chaining, weight 0.9] - A Content-Security-Policy is a primary mitigation against XSS payload execution; its absence directly increases the impact of the XSS finding.
  - can be chained with VULN_011 (Cookie 'session' missing HttpOnly flag, score 5.72) [chaining, weight 0.85] - Without the HttpOnly flag, a successful XSS payload can read the session cookie directly, escalating XSS impact to session hijacking.
  - shares a root cause with VULN_013 (SQL Injection, score 8.75) [shared_root_cause, weight 0.6] - Both finding types belong to the 'input_validation_gap' configuration-weakness family.
  - shares context with VULN_013 (SQL Injection, score 8.75) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('application').
  - can be chained with VULN_008 (Missing security header: X-Frame-Options, score 5.36) [chaining, weight 0.45] - Missing X-Frame-Options can be combined with XSS for clickjacking-assisted exploitation of the same page.
  - ...and 10 more (see JSON report)

### 3. VULN_013 - SQL Injection

- **Predicted score:** 8.75 / 10 -> **P1 - Fix immediately**
- **Type / layer:** sqli / application (scanner severity: high)
- **Asset:** http://localhost:3000
- **Suggested fix:** Use parameterised queries / an ORM; validate and escape all input.
- **Linked vulnerabilities (8):**
  - shares context with VULN_016 (No rate limiting detected on endpoint, score 6.73) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:3000/rest/products/search'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - can be chained with VULN_017 (Verbose error / stack trace leakage, score 5.57) [chaining, weight 0.8] - Verbose error / stack-trace leakage on the same target helps an attacker refine SQL Injection payloads (classic error-based SQLi workflow).
  - shares a root cause with VULN_012 (Cross Site Scripting (Reflected), score 9.87) [shared_root_cause, weight 0.6] - Both finding types belong to the 'input_validation_gap' configuration-weakness family.
  - shares context with VULN_012 (Cross Site Scripting (Reflected), score 9.87) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('application').
  - shares context with VULN_014 (Default/weak credentials accepted, score 10.00) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 3 more (see JSON report)

### 4. VULN_002 - Outdated vsftpd banner: 2.3.4

- **Predicted score:** 8.28 / 10 -> **P1 - Fix immediately**
- **Type / layer:** outdated_service_banner / network (scanner severity: high)
- **Asset:** 192.168.56.101
- **Suggested fix:** Upgrade the service and hide version banners.
- **Linked vulnerabilities (8):**
  - shares a root cause with VULN_019 (Vulnerable dependency: lodash 4.17.11, score 8.02) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_020 (Outdated PHP version detected: 7.2.1, score 5.52) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares context with VULN_003 (Weak/unencrypted protocol in use: ftp, score 5.66) [co_context, weight 0.55] - Both findings share asset '192.168.56.101' and the same security layer ('network').
  - shares context with VULN_001 (Open port 21/tcp (ftp), score 4.96) [co_context, weight 0.55] - Both findings share asset '192.168.56.101' and the same security layer ('network').
  - ...and 3 more (see JSON report)

### 5. VULN_019 - Vulnerable dependency: lodash 4.17.11

- **Predicted score:** 8.02 / 10 -> **P1 - Fix immediately**
- **Type / layer:** vulnerable_dependency / dependency (scanner severity: high)
- **Asset:** ./sample_target_project
- **Suggested fix:** Upgrade the dependency to a fixed version.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_020 (Outdated PHP version detected: 7.2.1, score 5.52) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.

### 6. VULN_005 - Weak TLS version negotiated: TLSv1.1

- **Predicted score:** 7.50 / 10 -> **P1 - Fix immediately**
- **Type / layer:** weak_cipher_tls_version / ssl (scanner severity: high)
- **Asset:** 192.168.56.101
- **Suggested fix:** Disable TLS<1.2 and weak ciphers.
- **Linked vulnerabilities (6):**
  - shares context with VULN_004 (Invalid/untrusted TLS certificate, score 7.35) [co_context, weight 0.85] - Both findings share the exact same target ('192.168.56.101:443'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_004 (Invalid/untrusted TLS certificate, score 7.35) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing HSTS header, score 5.29) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [co_context, weight 0.3] - Both findings share asset '192.168.56.101' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_003 (Weak/unencrypted protocol in use: ftp, score 5.66) [co_context, weight 0.3] - Both findings share asset '192.168.56.101' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 7. VULN_004 - Invalid/untrusted TLS certificate

- **Predicted score:** 7.35 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: high)
- **Asset:** 192.168.56.101
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (6):**
  - shares context with VULN_005 (Weak TLS version negotiated: TLSv1.1, score 7.50) [co_context, weight 0.85] - Both findings share the exact same target ('192.168.56.101:443'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_005 (Weak TLS version negotiated: TLSv1.1, score 7.50) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares a root cause with VULN_006 (Missing HSTS header, score 5.29) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [co_context, weight 0.3] - Both findings share asset '192.168.56.101' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_003 (Weak/unencrypted protocol in use: ftp, score 5.66) [co_context, weight 0.3] - Both findings share asset '192.168.56.101' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 8. VULN_015 - Potential IDOR via sequential 'id' parameter

- **Predicted score:** 6.76 / 10 -> **P2 - Fix soon**
- **Type / layer:** idor / api (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Enforce server-side object-level authorisation on every request.
- **Linked vulnerabilities (8):**
  - can be chained with VULN_014 (Default/weak credentials accepted, score 10.00) [chaining, weight 0.85] - Successfully authenticating with default/weak credentials grants a valid session that can then be used to probe IDOR-vulnerable endpoints.
  - shares a root cause with VULN_014 (Default/weak credentials accepted, score 10.00) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares a root cause with VULN_016 (No rate limiting detected on endpoint, score 6.73) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares context with VULN_014 (Default/weak credentials accepted, score 10.00) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - shares context with VULN_016 (No rate limiting detected on endpoint, score 6.73) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - ...and 3 more (see JSON report)

### 9. VULN_016 - No rate limiting detected on endpoint

- **Predicted score:** 6.73 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities (9):**
  - shares context with VULN_013 (SQL Injection, score 8.75) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:3000/rest/products/search'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - can be chained with VULN_014 (Default/weak credentials accepted, score 10.00) [chaining, weight 0.8] - Absence of rate limiting on an auth endpoint enables brute-forcing of the same weak/default credentials flagged by the broken-auth finding.
  - shares a root cause with VULN_014 (Default/weak credentials accepted, score 10.00) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares a root cause with VULN_015 (Potential IDOR via sequential 'id' parameter, score 6.76) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares context with VULN_014 (Default/weak credentials accepted, score 10.00) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - ...and 4 more (see JSON report)

### 10. VULN_007 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.80 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (10):**
  - can be chained with VULN_012 (Cross Site Scripting (Reflected), score 9.87) [chaining, weight 0.9] - A Content-Security-Policy is a primary mitigation against XSS payload execution; its absence directly increases the impact of the XSS finding.
  - shares a root cause with VULN_008 (Missing security header: X-Frame-Options, score 5.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_009 (Missing security header: X-Content-Type-Options, score 3.35) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_011 (Cookie 'session' missing HttpOnly flag, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - ...and 5 more (see JSON report)

### 11. VULN_011 - Cookie 'session' missing HttpOnly flag

- **Predicted score:** 5.72 / 10 -> **P2 - Fix soon**
- **Type / layer:** cookie_missing_httponly / client (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Set the HttpOnly flag on session cookies.
- **Linked vulnerabilities (9):**
  - can be chained with VULN_012 (Cross Site Scripting (Reflected), score 9.87) [chaining, weight 0.85] - Without the HttpOnly flag, a successful XSS payload can read the session cookie directly, escalating XSS impact to session hijacking.
  - shares a root cause with VULN_010 (Cookie 'session' missing Secure flag, score 5.32) [shared_root_cause, weight 0.6] - Both finding types belong to the 'cookie_hardening_gap' configuration-weakness family.
  - shares context with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_008 (Missing security header: X-Frame-Options, score 5.36) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - ...and 4 more (see JSON report)

### 12. VULN_018 - Outdated JS library: jquery 3.1.1

- **Predicted score:** 5.72 / 10 -> **P2 - Fix soon**
- **Type / layer:** outdated_js_library / client (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Upgrade the client-side library to a patched release.
- **Linked vulnerabilities (10):**
  - shares a root cause with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_019 (Vulnerable dependency: lodash 4.17.11, score 8.02) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_020 (Outdated PHP version detected: 7.2.1, score 5.52) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares context with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_011 (Cookie 'session' missing HttpOnly flag, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - ...and 5 more (see JSON report)

### 13. VULN_003 - Weak/unencrypted protocol in use: ftp

- **Predicted score:** 5.66 / 10 -> **P2 - Fix soon**
- **Type / layer:** weak_protocol / network (scanner severity: medium)
- **Asset:** 192.168.56.101
- **Suggested fix:** Replace the cleartext protocol with its encrypted equivalent.
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_001 (Open port 21/tcp (ftp), score 4.96) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [co_context, weight 0.55] - Both findings share asset '192.168.56.101' and the same security layer ('network').
  - shares context with VULN_001 (Open port 21/tcp (ftp), score 4.96) [co_context, weight 0.55] - Both findings share asset '192.168.56.101' and the same security layer ('network').
  - can be chained with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [chaining, weight 0.5] - An outdated service version combined with a weak/unencrypted protocol on the same port expands the exploitable surface of that service.
  - shares context with VULN_005 (Weak TLS version negotiated: TLSv1.1, score 7.50) [co_context, weight 0.3] - Both findings share asset '192.168.56.101' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 14. VULN_017 - Verbose error / stack trace leakage

- **Predicted score:** 5.57 / 10 -> **P2 - Fix soon**
- **Type / layer:** verbose_error / api (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Return generic error pages; log stack traces server-side only.
- **Linked vulnerabilities (6):**
  - can be chained with VULN_013 (SQL Injection, score 8.75) [chaining, weight 0.8] - Verbose error / stack-trace leakage on the same target helps an attacker refine SQL Injection payloads (classic error-based SQLi workflow).
  - shares context with VULN_014 (Default/weak credentials accepted, score 10.00) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - shares context with VULN_015 (Potential IDOR via sequential 'id' parameter, score 6.76) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - shares context with VULN_016 (No rate limiting detected on endpoint, score 6.73) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - shares context with VULN_012 (Cross Site Scripting (Reflected), score 9.87) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 15. VULN_020 - Outdated PHP version detected: 7.2.1

- **Predicted score:** 5.52 / 10 -> **P2 - Fix soon**
- **Type / layer:** outdated_fingerprint / fingerprint (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Upgrade the detected component to a supported version.
- **Linked vulnerabilities (5):**
  - shares a root cause with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_019 (Vulnerable dependency: lodash 4.17.11, score 8.02) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares a root cause with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [shared_root_cause, weight 0.6] - Both finding types belong to the 'outdated_component_gap' configuration-weakness family.
  - shares context with VULN_014 (Default/weak credentials accepted, score 10.00) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 16. VULN_008 - Missing security header: X-Frame-Options

- **Predicted score:** 5.36 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / client (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (10):**
  - shares a root cause with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_009 (Missing security header: X-Content-Type-Options, score 3.35) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_011 (Cookie 'session' missing HttpOnly flag, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - ...and 5 more (see JSON report)

### 17. VULN_010 - Cookie 'session' missing Secure flag

- **Predicted score:** 5.32 / 10 -> **P3 - Schedule**
- **Type / layer:** cookie_missing_secure / client (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Set the Secure flag on session cookies.
- **Linked vulnerabilities (8):**
  - shares a root cause with VULN_011 (Cookie 'session' missing HttpOnly flag, score 5.72) [shared_root_cause, weight 0.6] - Both finding types belong to the 'cookie_hardening_gap' configuration-weakness family.
  - shares context with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_011 (Cookie 'session' missing HttpOnly flag, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_008 (Missing security header: X-Frame-Options, score 5.36) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - ...and 3 more (see JSON report)

### 18. VULN_006 - Missing HSTS header

- **Predicted score:** 5.29 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_hsts / ssl (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Send Strict-Transport-Security with a long max-age.
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_005 (Weak TLS version negotiated: TLSv1.1, score 7.50) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares a root cause with VULN_004 (Invalid/untrusted TLS certificate, score 7.35) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_014 (Default/weak credentials accepted, score 10.00) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_012 (Cross Site Scripting (Reflected), score 9.87) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_013 (SQL Injection, score 8.75) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 19. VULN_001 - Open port 21/tcp (ftp)

- **Predicted score:** 4.96 / 10 -> **P3 - Schedule**
- **Type / layer:** open_port / network (scanner severity: medium)
- **Asset:** 192.168.56.101
- **Suggested fix:** Close or firewall services that do not need to be exposed.
- **Linked vulnerabilities (5):**
  - shares a root cause with VULN_003 (Weak/unencrypted protocol in use: ftp, score 5.66) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_002 (Outdated vsftpd banner: 2.3.4, score 8.28) [co_context, weight 0.55] - Both findings share asset '192.168.56.101' and the same security layer ('network').
  - shares context with VULN_003 (Weak/unencrypted protocol in use: ftp, score 5.66) [co_context, weight 0.55] - Both findings share asset '192.168.56.101' and the same security layer ('network').
  - shares context with VULN_005 (Weak TLS version negotiated: TLSv1.1, score 7.50) [co_context, weight 0.3] - Both findings share asset '192.168.56.101' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_004 (Invalid/untrusted TLS certificate, score 7.35) [co_context, weight 0.3] - Both findings share asset '192.168.56.101' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 20. VULN_009 - Missing security header: X-Content-Type-Options

- **Predicted score:** 3.35 / 10 -> **P4 - Low / monitor**
- **Type / layer:** missing_xcto / client (scanner severity: low)
- **Asset:** http://localhost:3000
- **Suggested fix:** Send X-Content-Type-Options: nosniff.
- **Linked vulnerabilities (9):**
  - shares a root cause with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_008 (Missing security header: X-Frame-Options, score 5.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_007 (Missing security header: Content-Security-Policy, score 5.80) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_018 (Outdated JS library: jquery 3.1.1, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - shares context with VULN_011 (Cookie 'session' missing HttpOnly flag, score 5.72) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('client').
  - ...and 4 more (see JSON report)
