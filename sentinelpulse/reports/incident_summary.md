# SentinelPulse SOC Incident Triage Report

- **Generated:** 2026-11-24 23:25:09
- **Total Events Analyzed:** 34 (SSH: 16, Web: 18)
- **Correlated Incidents:** 5

## Prioritized Incidents

### [CRITICAL] INC-001 — CRITICAL Compromise Chain from 185.220.101.42 (Risk: 100/100)
- **Source IP:** `185.220.101.42` (MALICIOUS | DE | Tor Exit Node / SSH Brute-Forcer)
- **Kill Chain Stages:** Account Compromise -> Credential Access -> Reconnaissance -> Privilege Escalation
- **MITRE ATT&CK:** T1078 - Valid Accounts, T1078.003 - Valid Accounts: Local Accounts, T1087 - Account Discovery, T1110.001 - Brute Force: Password Guessing, T1595.003 - Active Scanning: Wordlist Scanning
- **Window:** `2026-11-24 14:10:30` to `2026-11-24 14:12:40`
- **Recommended Actions:**
  - ESCALATE IMMEDIATELY (P1): Confirmed SSH login after brute-force from 185.220.101.42. Treat target account as compromised.
  - Terminate active SSH sessions for the affected user and rotate SSH keys/passwords.
  - Audit recent sudo history (~/.bash_history, /var/log/syslog) for persistence or lateral movement.
  - Block external offending IP 185.220.101.42 at host firewall / perimeter WAF.
  - Harden SSH: disable password authentication, enforce key-only login, and enable Fail2Ban.
  - Confirm .env, .git, and backup files are blocked at Nginx/Apache level (return 404/403).

### [HIGH] INC-002 — Multi-Vector Attack (4 Rules Triggered) from 45.155.205.9 (Risk: 92/100)
- **Source IP:** `45.155.205.9` (MALICIOUS | RU | Automated Web Vulnerability Scanner)
- **Kill Chain Stages:** Reconnaissance -> Exploitation / Initial Access
- **MITRE ATT&CK:** T1190 - Exploit Public-Facing Application, T1595 - Active Scanning, T1595.002 - Active Scanning: Vulnerability Scanning, T1595.003 - Active Scanning: Wordlist Scanning
- **Window:** `2026-11-24 14:10:40` to `2026-11-24 14:11:08`
- **Recommended Actions:**
  - Block external offending IP 45.155.205.9 at host firewall / perimeter WAF.
  - Review WAF/reverse-proxy logs for HTTP 200/500 responses on injection/LFI payloads.
  - Verify parameterized queries (SQLi) and strict path sanitization (LFI) in application code.
  - Confirm .env, .git, and backup files are blocked at Nginx/Apache level (return 404/403).

### [HIGH] INC-003 — Multi-Vector Attack (2 Rules Triggered) from 194.26.135.71 (Risk: 52/100)
- **Source IP:** `194.26.135.71` (SUSPICIOUS | NL | Bulletproof Hosting / Recon Scanner)
- **Kill Chain Stages:** Exploitation / Collection -> Reconnaissance
- **MITRE ATT&CK:** T1005 - Data from Local System, T1595 - Active Scanning
- **Window:** `2026-11-24 14:11:35` to `2026-11-24 14:11:38`
- **Recommended Actions:**
  - Block external offending IP 194.26.135.71 at host firewall / perimeter WAF.
  - Review WAF/reverse-proxy logs for HTTP 200/500 responses on injection/LFI payloads.
  - Verify parameterized queries (SQLi) and strict path sanitization (LFI) in application code.

### [HIGH] INC-004 — SSH Brute-Force Attempt (91.240.118.168) (Risk: 45/100)
- **Source IP:** `91.240.118.168` (MALICIOUS | BG | Known Credential Stuffing Infrastructure)
- **Kill Chain Stages:** Credential Access
- **MITRE ATT&CK:** T1110.001 - Brute Force: Password Guessing
- **Window:** `2026-11-24 14:12:00` to `2026-11-24 14:12:16`
- **Recommended Actions:**
  - Block external offending IP 91.240.118.168 at host firewall / perimeter WAF.
  - Harden SSH: disable password authentication, enforce key-only login, and enable Fail2Ban.

### [MEDIUM] INC-005 — Cross-Site Scripting (XSS) Probe Detected (103.145.254.11) (Risk: 25/100)
- **Source IP:** `103.145.254.11` (SUSPICIOUS | SG | Exposed Proxy / Automated Crawler)
- **Kill Chain Stages:** Exploitation / Execution
- **MITRE ATT&CK:** T1059.007 - Command and Scripting Interpreter: JavaScript
- **Window:** `2026-11-24 14:12:20` to `2026-11-24 14:12:25`
- **Recommended Actions:**
  - Block external offending IP 103.145.254.11 at host firewall / perimeter WAF.
  - Review WAF/reverse-proxy logs for HTTP 200/500 responses on injection/LFI payloads.
  - Verify parameterized queries (SQLi) and strict path sanitization (LFI) in application code.
