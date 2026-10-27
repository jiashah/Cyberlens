# Vulnerability Priority Report - `dvga_all_layers`

3 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 0, P2 - Fix soon: 0, P3 - Schedule: 2, P4 - Low / monitor: 1

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_002 | No TLS/HTTPS listener | 5.34 | P3 - Schedule |
| 2 | VULN_003 | No rate limiting detected on endpoint | 5.34 | P3 - Schedule |
| 3 | VULN_001 | Open port 8092/tcp (tcpwrapped) | 1.38 | P4 - Low / monitor |

## Details

### 1. VULN_002 - No TLS/HTTPS listener

- **Predicted score:** 5.34 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: medium)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (1):**
  - shares context with VULN_001 (Open port 8092/tcp (tcpwrapped), score 1.38) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 2. VULN_003 - No rate limiting detected on endpoint

- **Predicted score:** 5.34 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:8092
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities:** none

### 3. VULN_001 - Open port 8092/tcp (tcpwrapped)

- **Predicted score:** 1.38 / 10 -> **P4 - Low / monitor**
- **Type / layer:** open_port / network (scanner severity: info)
- **Asset:** 127.0.0.1
- **Suggested fix:** Close or firewall services that do not need to be exposed.
- **Linked vulnerabilities (1):**
  - shares context with VULN_002 (No TLS/HTTPS listener, score 5.34) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
