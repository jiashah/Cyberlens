# Vulnerability Priority Report - `vulnerableapp_full_scan`

8 vulnerabilities ordered by predicted risk score (0-10, higher = fix first). Scores account for attack-chain context from the vulnerability graph.

**Priority summary:** P1 - Fix immediately: 0, P2 - Fix soon: 0, P3 - Schedule: 6, P4 - Low / monitor: 2

| Rank | ID | Vulnerability | Score | Priority |
|---|---|---|---|---|
| 1 | VULN_003 | No TLS/HTTPS listener | 5.44 | P3 - Schedule |
| 2 | VULN_005 | Missing security header: Content-Security-Policy | 5.36 | P3 - Schedule |
| 3 | VULN_008 | No rate limiting detected on endpoint | 5.31 | P3 - Schedule |
| 4 | VULN_004 | Missing HSTS header | 5.19 | P3 - Schedule |
| 5 | VULN_006 | Missing security header: X-Frame-Options | 5.16 | P3 - Schedule |
| 6 | VULN_002 | Weak/unencrypted protocol in use: http | 3.55 | P3 - Schedule |
| 7 | VULN_007 | Missing security header: X-Content-Type-Options | 3.16 | P4 - Low / monitor |
| 8 | VULN_001 | Open port 8091/tcp (http) | 2.97 | P4 - Low / monitor |

## Details

### 1. VULN_003 - No TLS/HTTPS listener

- **Predicted score:** 5.44 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_tls_cert / ssl (scanner severity: medium)
- **Asset:** 127.0.0.1
- **Suggested fix:** Install a valid, trusted TLS certificate.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_004 (Missing HSTS header, score 5.19) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
  - shares context with VULN_001 (Open port 8091/tcp (http), score 2.97) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 2. VULN_005 - Missing security header: Content-Security-Policy

- **Predicted score:** 5.36 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_csp / client (scanner severity: medium)
- **Asset:** http://localhost:8091/VulnerableApp
- **Suggested fix:** Add a restrictive Content-Security-Policy header.
- **Linked vulnerabilities (6):**
  - shares context with VULN_008 (No rate limiting detected on endpoint, score 5.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.19) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_006 (Missing security header: X-Frame-Options, score 5.16) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 1 more (see JSON report)

### 3. VULN_008 - No rate limiting detected on endpoint

- **Predicted score:** 5.31 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_rate_limit / api (scanner severity: medium)
- **Asset:** http://localhost:8091/VulnerableApp
- **Suggested fix:** Add rate limiting / lockout on authentication and sensitive endpoints.
- **Linked vulnerabilities (4):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.19) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.

### 4. VULN_004 - Missing HSTS header

- **Predicted score:** 5.19 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_hsts / ssl (scanner severity: medium)
- **Asset:** http://localhost:8091/VulnerableApp
- **Suggested fix:** Send Strict-Transport-Security with a long max-age.
- **Linked vulnerabilities (5):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_008 (No rate limiting detected on endpoint, score 5.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_003 (No TLS/HTTPS listener, score 5.44) [shared_root_cause, weight 0.6] - Both finding types belong to the 'transport_security_gap' configuration-weakness family.

### 5. VULN_006 - Missing security header: X-Frame-Options

- **Predicted score:** 5.16 / 10 -> **P3 - Schedule**
- **Type / layer:** missing_xfo / client (scanner severity: medium)
- **Asset:** http://localhost:8091/VulnerableApp
- **Suggested fix:** Send X-Frame-Options: DENY (or CSP frame-ancestors).
- **Linked vulnerabilities (6):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_008 (No rate limiting detected on endpoint, score 5.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.19) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_007 (Missing security header: X-Content-Type-Options, score 3.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 1 more (see JSON report)

### 6. VULN_002 - Weak/unencrypted protocol in use: http

- **Predicted score:** 3.55 / 10 -> **P3 - Schedule**
- **Type / layer:** weak_protocol / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Replace the cleartext protocol with its encrypted equivalent.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_001 (Open port 8091/tcp (http), score 2.97) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_001 (Open port 8091/tcp (http), score 2.97) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.44) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).

### 7. VULN_007 - Missing security header: X-Content-Type-Options

- **Predicted score:** 3.16 / 10 -> **P4 - Low / monitor**
- **Type / layer:** missing_xcto / client (scanner severity: low)
- **Asset:** http://localhost:8091/VulnerableApp
- **Suggested fix:** Send X-Content-Type-Options: nosniff.
- **Linked vulnerabilities (6):**
  - shares context with VULN_005 (Missing security header: Content-Security-Policy, score 5.36) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_008 (No rate limiting detected on endpoint, score 5.31) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_004 (Missing HSTS header, score 5.19) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares context with VULN_006 (Missing security header: X-Frame-Options, score 5.16) [co_context, weight 0.85] - Both findings share the exact same target ('http://localhost:8091/VulnerableApp'), which contains fine-grained endpoint/service/component evidence (a path, port, or package identifier) -- the strongest evidence available in the current scanner data.
  - shares a root cause with VULN_005 (Missing security header: Content-Security-Policy, score 5.36) [shared_root_cause, weight 0.6] - Both finding types belong to the 'header_hardening_gap' configuration-weakness family.
  - ...and 1 more (see JSON report)

### 8. VULN_001 - Open port 8091/tcp (http)

- **Predicted score:** 2.97 / 10 -> **P4 - Low / monitor**
- **Type / layer:** open_port / network (scanner severity: low)
- **Asset:** 127.0.0.1
- **Suggested fix:** Close or firewall services that do not need to be exposed.
- **Linked vulnerabilities (3):**
  - shares a root cause with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [shared_root_cause, weight 0.6] - Both finding types belong to the 'exposed_surface_gap' configuration-weakness family.
  - shares context with VULN_002 (Weak/unencrypted protocol in use: http, score 3.55) [co_context, weight 0.55] - Both findings share asset '127.0.0.1' and the same security layer ('network').
  - shares context with VULN_003 (No TLS/HTTPS listener, score 5.44) [co_context, weight 0.3] - Both findings share asset '127.0.0.1' with no stronger endpoint or layer evidence available; selected as a top-2 contextual neighbor (tie-break: shared root-cause family, then severity, then node id).
