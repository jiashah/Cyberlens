# Vulnerability Priority Report - `multillidae_scan`

8 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 0, P2 - Fix soon: 1, P3 - Schedule: 5, P4 - Low / monitor: 2

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_003 | Invalid/untrusted TLS certificate | 7.36 | P2 - Fix soon |
| 2 | VULN_006 | Missing security header: Content-Security-Policy | 5.36 | P3 - Schedule |
| 3 | VULN_005 | No rate limiting detected on endpoint | 5.32 | P3 - Schedule |
| 4 | VULN_004 | Missing HSTS header | 5.19 | P3 - Schedule |
| 5 | VULN_007 | Missing security header: X-Frame-Options | 5.16 | P3 - Schedule |
| 6 | VULN_002 | Weak/unencrypted protocol in use: http | 3.54 | P3 - Schedule |
| 7 | VULN_008 | Missing security header: X-Content-Type-Options | 3.16 | P4 - Low / monitor |
| 8 | VULN_001 | Open port 8888/tcp (http) | 2.96 | P4 - Low / monitor |

## Details

### 1. VULN_003 - Invalid/untrusted TLS certificate

- **Predicted score:** 7.36 / 10 -> **P2 - Fix soon**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: high)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_004 (Missing HSTS header, score 5.19) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.54) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_001 (Open port 8888/tcp (http), score 2.96) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 2. VULN_006 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.36 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://localhost:8888
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_007 (Missing security header: X-Frame-Options, score 5.16) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_008 (Missing security header: X-Content-Type-Options, score 3.16) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_007 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.55] - Both findings share asset 'http://localhost:8888' and the same security layer ('client').
  - shares context with VULN_008 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.55] - Both findings share asset 'http://localhost:8888' and the same security layer ('client').
  - shares context with VULN_005 (No rate limiting detected on endpoint, score 5.32) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 3. VULN_005 - No rate limiting detected on endpoint

- **Predicted score:** 5.32 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:8888
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities (4):**
  - shares context with VULN_006 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_004 (Missing HSTS header, score 5.19) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_007 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_008 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 4. VULN_004 - Missing HSTS header

- **Predicted score:** 5.19 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_hsts / ssl (scanner severity: medium)
- **Asset:** http://localhost:8888
- **Suggested fix:** Send Strict-Transport-Security with a long max-age.
- **Linked vulnerabilities (5):**
  - shares a root cause with VULN_003 (Invalid/untrusted TLS certificate, score 7.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_006 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_005 (No rate limiting detected on endpoint, score 5.32) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_007 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_008 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 5. VULN_007 - Missing security header: X-Frame-Options

- **Predicted score:** 5.16 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / client (scanner severity: medium)
- **Asset:** http://localhost:8888
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_006 (Missing security header: Content-Security-Policy, score 5.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_008 (Missing security header: X-Content-Type-Options, score 3.16) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_006 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.55] - Both findings share asset 'http://localhost:8888' and the same security layer ('client').
  - shares context with VULN_008 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.55] - Both findings share asset 'http://localhost:8888' and the same security layer ('client').
  - shares context with VULN_005 (No rate limiting detected on endpoint, score 5.32) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 6. VULN_002 - Weak/unencrypted protocol in use: http

- **Predicted score:** 3.54 / 10 -> **P3 - Schedule**
- **Type / layer:** weak_protocol / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Replace the cleartext protocol with its encrypted equivalent.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_001 (Open port 8888/tcp (http), score 2.96) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_001 (Open port 8888/tcp (http), score 2.96) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (Invalid/untrusted TLS certificate, score 7.36) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 7. VULN_008 - Missing security header: X-Content-Type-Options

- **Predicted score:** 3.16 / 10 -> **P4 - Low / monitor**
- **Type / layer:** missing_xcto / client (scanner severity: low)
- **Asset:** http://localhost:8888
- **Suggested fix:** Send X-Content-Type-Options: nosniff.
- **Linked vulnerabilities (6):**
  - shares a root cause with VULN_006 (Missing security header: Content-Security-Policy, score 5.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares a root cause with VULN_007 (Missing security header: X-Frame-Options, score 5.16) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - shares context with VULN_006 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.55] - Both findings share asset 'http://localhost:8888' and the same security layer ('client').
  - shares context with VULN_007 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.55] - Both findings share asset 'http://localhost:8888' and the same security layer ('client').
  - shares context with VULN_005 (No rate limiting detected on endpoint, score 5.32) [co_context, weight 0.3] - Both findings share asset 'http://localhost:8888' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - ...and 1 more (see JSON report)

### 8. VULN_001 - Open port 8888/tcp (http)

- **Predicted score:** 2.96 / 10 -> **P4 - Low / monitor**
- **Type / layer:** open_port / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Close or firewall services that do not need to be exposed.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_002 (Weak/unencrypted protocol in use: http, score 3.54) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.54) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (Invalid/untrusted TLS certificate, score 7.36) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
