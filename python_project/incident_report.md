# SentinelLog Security Incident Report

## Executive Summary
- **Total Lines Scanned:** 39
- **Normalized Events:** 39
- **Unparsed Lines:** 0
- **Alerts Triggered:** 10
- **Analysis Duration:** 4.15 ms

## Findings by Severity
- **CRITICAL**: 2
- **HIGH**: 4
- **MEDIUM**: 4

## Detailed Security Alerts

### 1. [CRITICAL] Successful SSH Login Following Failed Attempts
- **Source IP:** `91.240.118.172`
- **MITRE ATT&CK:** T1078.003 — Valid Accounts: Local Accounts (Persistence / Privilege Escalation)
- **Events:** 6 (2026-11-17T09:05:10+00:00 to 2026-11-17T09:05:42+00:00)
- **Summary:** Source 91.240.118.172 authenticated as 'root' after 5 prior failed login attempts.
- **Remediation:** Immediately isolate host, revoke active SSH sessions, rotate credentials, and inspect bash history/persistence.

### 2. [CRITICAL] SQL Injection Payload Detected
- **Source IP:** `198.51.100.42`
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application (SQLi) (Initial Access)
- **Events:** 2 (2026-11-17T09:15:03+00:00 to 2026-11-17T09:15:05+00:00)
- **Summary:** Detected 2 HTTP request(s) from 198.51.100.42 containing SQL injection syntax after URL normalization.
- **Remediation:** Verify parameterized queries on affected endpoints, inspect WAF logs, and audit database query logs for data exfiltration.

### 3. [HIGH] Distributed Username Spraying / Credential Stuffing
- **Source IP:** `185.220.101.4`
- **MITRE ATT&CK:** T1110.004 — Brute Force: Credential Stuffing (Credential Access)
- **Events:** 7 (2026-11-17T09:04:01+00:00 to 2026-11-17T09:04:44+00:00)
- **Summary:** 7 failed SSH attempts from 185.220.101.4 within 120s window targeting 6 account(s): admin, oracle, postgres, root, test.
- **Remediation:** Block offending IP at perimeter firewall, enforce key-only SSH auth, and verify targeted accounts for compromise.

### 4. [HIGH] SSH Brute-Force Authentication Burst
- **Source IP:** `91.240.118.172`
- **MITRE ATT&CK:** T1110.001 — Brute Force: Password Guessing (Credential Access)
- **Events:** 5 (2026-11-17T09:05:10+00:00 to 2026-11-17T09:05:30+00:00)
- **Summary:** 5 failed SSH attempts from 91.240.118.172 within 120s window targeting 1 account(s): root.
- **Remediation:** Block offending IP at perimeter firewall, enforce key-only SSH auth, and verify targeted accounts for compromise.

### 5. [HIGH] Cross-Site Scripting (XSS) Probe
- **Source IP:** `192.0.2.88`
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application (XSS) (Initial Access)
- **Events:** 1 (2026-11-17T09:16:20+00:00 to 2026-11-17T09:16:20+00:00)
- **Summary:** Detected 1 HTTP request(s) from 192.0.2.88 injecting script or DOM event-handler payloads.
- **Remediation:** Validate output encoding and Content-Security-Policy headers on targeted routes.

### 6. [HIGH] Path Traversal / Local File Inclusion Attempt
- **Source IP:** `192.0.2.88`
- **MITRE ATT&CK:** T1083 — File and Directory Discovery (LFI/Traversal) (Discovery)
- **Events:** 1 (2026-11-17T09:16:25+00:00 to 2026-11-17T09:16:25+00:00)
- **Summary:** Detected 1 request(s) from 192.0.2.88 attempting directory traversal or sensitive OS file disclosure.
- **Remediation:** Enforce canonical path allowlists in file-serving handlers and verify web root permissions.

### 7. [MEDIUM] Multi-Port Reconnaissance Scan
- **Source IP:** `45.155.205.91`
- **MITRE ATT&CK:** T1046 — Network Service Discovery (Discovery)
- **Events:** 9 (2026-11-17T09:18:10+00:00 to 2026-11-17T09:18:16+00:00)
- **Summary:** Source 45.155.205.91 triggered 9 firewall blocks across 9 distinct destination ports (21, 22, 23, 80, 443, 445, 3389, 5432, 6379).
- **Remediation:** Add dynamic block rule for scanning source IP and confirm no unintended services are exposed.

### 8. [MEDIUM] Automated Web Vulnerability Scanning
- **Source IP:** `198.51.100.42`
- **MITRE ATT&CK:** T1595.002 — Active Scanning: Vulnerability Scanning (Reconnaissance)
- **Events:** 5 (2026-11-17T09:15:03+00:00 to 2026-11-17T09:15:14+00:00)
- **Summary:** Source 198.51.100.42 probed 5 sensitive paths or used known offensive scanner signatures.
- **Remediation:** Rate-limit or block scanner IP/ASN and ensure sensitive dotfiles (.env, .git) are non-routable.

### 9. [MEDIUM] Automated Web Vulnerability Scanning
- **Source IP:** `45.83.220.14`
- **MITRE ATT&CK:** T1595.002 — Active Scanning: Vulnerability Scanning (Reconnaissance)
- **Events:** 3 (2026-11-17T09:17:01+00:00 to 2026-11-17T09:17:03+00:00)
- **Summary:** Source 45.83.220.14 probed 3 sensitive paths or used known offensive scanner signatures.
- **Remediation:** Rate-limit or block scanner IP/ASN and ensure sensitive dotfiles (.env, .git) are non-routable.

### 10. [MEDIUM] Repeated Probing of Administrative / Database Ports
- **Source IP:** `103.42.91.18`
- **MITRE ATT&CK:** T1021 — Remote Services Probing (Lateral Movement)
- **Events:** 3 (2026-11-17T09:19:02+00:00 to 2026-11-17T09:19:14+00:00)
- **Summary:** Source 103.42.91.18 repeatedly probed sensitive service port(s): 3389.
- **Remediation:** Restrict administrative and database ports to VPN/bastion CIDR ranges.
