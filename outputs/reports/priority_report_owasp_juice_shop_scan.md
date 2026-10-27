# Vulnerability Priority Report - `owasp_juice_shop_scan`

6 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 0, P2 - Fix soon: 1, P3 - Schedule: 4, P4 - Low / monitor: 1

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_006 | Potential IDOR via sequential 'id' parameter | 5.97 | P2 - Fix soon |
| 2 | VULN_002 | No TLS/HTTPS listener | 5.45 | P3 - Schedule |
| 3 | VULN_005 | No rate limiting detected on endpoint | 5.45 | P3 - Schedule |
| 4 | VULN_003 | Missing HSTS header | 5.24 | P3 - Schedule |
| 5 | VULN_004 | Missing security header: Content-Security-Policy | 5.21 | P3 - Schedule |
| 6 | VULN_001 | Open port 3000/tcp (ppp) | 1.35 | P4 - Low / monitor |

## Details

### 1. VULN_006 - Potential IDOR via sequential 'id' parameter

- **Predicted score:** 5.97 / 10 -> **P2 - Fix soon**
- **Type / layer:** idor / api (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Enforce server-side object-level authorisation on every request.
- **Linked vulnerabilities (4):**
  - shares a root cause with VULN_005 (No rate limiting detected on endpoint, score 5.45) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares context with VULN_005 (No rate limiting detected on endpoint, score 5.45) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - shares context with VULN_003 (Missing HSTS header, score 5.24) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_004 (Missing security header: Content-Security-Policy, score 5.21) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 2. VULN_002 - No TLS/HTTPS listener

- **Predicted score:** 5.45 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: medium)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (2):**
  - shares a root cause with VULN_003 (Missing HSTS header, score 5.24) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_001 (Open port 3000/tcp (ppp), score 1.35) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 3. VULN_005 - No rate limiting detected on endpoint

- **Predicted score:** 5.45 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities (4):**
  - shares a root cause with VULN_006 (Potential IDOR via sequential 'id' parameter, score 5.97) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.
  - shares context with VULN_006 (Potential IDOR via sequential 'id' parameter, score 5.97) [co_context, weight 0.55] - Both findings share asset 'http://localhost:3000' and the same security layer ('api').
  - shares context with VULN_003 (Missing HSTS header, score 5.24) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_004 (Missing security header: Content-Security-Policy, score 5.21) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 4. VULN_003 - Missing HSTS header

- **Predicted score:** 5.24 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_hsts / ssl (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Send Strict-Transport-Security with a long max-age.
- **Linked vulnerabilities (4):**
  - shares a root cause with VULN_002 (No TLS/HTTPS listener, score 5.45) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_006 (Potential IDOR via sequential 'id' parameter, score 5.97) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_005 (No rate limiting detected on endpoint, score 5.45) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_004 (Missing security header: Content-Security-Policy, score 5.21) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 5. VULN_004 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.21 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://localhost:3000
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (3):**
  - shares context with VULN_006 (Potential IDOR via sequential 'id' parameter, score 5.97) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_005 (No rate limiting detected on endpoint, score 5.45) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_003 (Missing HSTS header, score 5.24) [co_context, weight 0.3] - Both findings share asset 'http://localhost:3000' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 6. VULN_001 - Open port 3000/tcp (ppp)

- **Predicted score:** 1.35 / 10 -> **P4 - Low / monitor**
- **Type / layer:** open_port / network (scanner severity: info)
- **Asset:** 127.0.0.1
- **Suggested fix:** Close or firewall services that do not need to be exposed.
- **Linked vulnerabilities (1):**
  - shares context with VULN_002 (No TLS/HTTPS listener, score 5.45) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
