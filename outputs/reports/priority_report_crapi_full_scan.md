# Vulnerability Priority Report - `crapi_full_scan`

4 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 0, P2 - Fix soon: 1, P3 - Schedule: 3, P4 - Low / monitor: 0

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_004 | Potential IDOR/BOLA via sequential object IDs | 5.96 | P2 - Fix soon |
| 2 | VULN_003 | No rate limiting detected on endpoint | 5.49 | P3 - Schedule |
| 3 | VULN_001 | No TLS/HTTPS listener | 5.27 | P3 - Schedule |
| 4 | VULN_002 | Missing security header: Content-Security-Policy | 5.15 | P3 - Schedule |

## Details

### 1. VULN_004 - Potential IDOR/BOLA via sequential object IDs

- **Predicted score:** 5.96 / 10 -> **P2 - Fix soon**
- **Type / layer:** idor / api (scanner severity: medium)
- **Asset:** http://localhost:8888/workshop/api/shop/orders
- **Suggested fix:** Enforce server-side object-level authorisation on every request.
- **Linked vulnerabilities (1):**
  - shares a root cause with VULN_003 (No rate limiting detected on endpoint, score 5.49) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.

### 2. VULN_003 - No rate limiting detected on endpoint

- **Predicted score:** 5.49 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:8888/identity/api/auth/login
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities (2):**
  - shares context with VULN_002 (Missing security header: Content-Security-Policy, score 5.15) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8888/identity/api/auth/login'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_004 (Potential IDOR/BOLA via sequential object IDs, score 5.96) [shared_root_cause, weight 0.6] - Both finding types belong to the 'access_control_gap' configuration-weakness family.

### 3. VULN_001 - No TLS/HTTPS listener

- **Predicted score:** 5.27 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: medium)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities:** none

### 4. VULN_002 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.15 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://localhost:8888/identity/api/auth/login
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (1):**
  - shares context with VULN_003 (No rate limiting detected on endpoint, score 5.49) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8888/identity/api/auth/login'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
