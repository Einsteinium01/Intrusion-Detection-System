# Brute Force / Credential Stuffing — Response Playbook

**Source:** Project Detection Team  
**Applies to:** `BruteForce`, `SSHBruteForce`, `FTPBruteForce`, `CredentialStuffing` alerts  
**Detectors:** `XGBoostDetector`  
**MITRE ATT&CK:** T1110 (Brute Force), T1078 (Valid Accounts)

---

## Overview

A brute force alert indicates repeated authentication attempts from a single source to a single destination service. The XGBoost model detects this via features including `connection_rate`, `failed_auth_ratio`, `packet_size_consistency`, `inter_arrival_variance`, and protocol-specific flow patterns.

**The primary risk is credential compromise.** A successful brute force gives the attacker valid credentials that can be used for persistent access, lateral movement, and data exfiltration.

---

## Alert Triage (First 5 minutes)

### Step 1 — Validate the alert

- Confirm destination port:
  - **22 (SSH):** High value target — direct shell access
  - **3389 (RDP):** High value target — graphical session
  - **21 (FTP):** File access
  - **25 (SMTP):** Email account takeover / spam relay
  - **80/443 (HTTP/HTTPS):** Web application login brute force
  - **1433/3306/5432:** Database direct access
- Check `confidence` — brute force patterns are distinctive; high confidence (>0.85) is reliable

### Step 2 — Determine if any logins succeeded

This is the CRITICAL question. A brute force in progress is far less dangerous than one that already succeeded.

- **Look for established sessions** from `source_ip` to `destination_ip` on the same port AFTER the alert time
- Check authentication logs on the destination server for successful logins from `source_ip`
- Check for any post-authentication activity (file access, command execution) from the source

### Step 3 — Classify the attacker

| Pattern | Attacker Type |
|---------|--------------|
| Sequential usernames (admin, administrator, root, user) | Automated dictionary attack |
| Known credential pairs from breach databases | Credential stuffing |
| Very slow rate (1 attempt/minute) | Low-and-slow to evade rate limiting |
| High rate (>100 attempts/min) | Aggressive automated tool |
| Internal source IP | Insider threat or lateral movement |

---

## Investigation Steps

### If NO successful login detected

1. **Block source IP** at the firewall (at least temporarily)
2. **Check other targets:** Is this source attacking other services/hosts on your network?
3. **Review account lockout policy:** Were targeted accounts locked out?
4. **Check for weak accounts:** Were default credentials (admin/admin, root/root) targeted?

### If successful login IS detected or suspected

**⚠️ TREAT AS INCIDENT — ESCALATE IMMEDIATELY**

1. **Disable the compromised account** immediately
2. **Force password reset** on all accounts that were targeted (not just the one that succeeded)
3. **Review all actions taken** under the compromised account since the successful login:
   - Files accessed or modified
   - Commands executed
   - New accounts created
   - Outbound connections made
4. **Check for persistence mechanisms:**
   - New SSH authorized_keys added
   - New scheduled tasks or cron jobs
   - New user accounts
   - Installed backdoors or web shells
5. **Contain the affected system:** Network isolation if activity is confirmed

---

## Evidence to Collect

- [ ] Authentication log from destination server (`/var/log/auth.log`, Windows Event Log 4625/4624)
- [ ] List of all usernames attempted
- [ ] Source IP WHOIS/ASN information
- [ ] Timeline of attempts vs. successes
- [ ] Commands/activities performed by the source IP after the alert
- [ ] Any lateral movement from the destination host after potential compromise

---

## MITRE ATT&CK Mapping

| Technique | ID | Stage | Notes |
|-----------|-----|-------|-------|
| Brute Force: Password Spraying | T1110.003 | Credential Access | Low attempts per account, many accounts |
| Brute Force: Credential Stuffing | T1110.004 | Credential Access | Known credential pairs from data breaches |
| Brute Force: Password Guessing | T1110.001 | Credential Access | Dictionary attack on single account |
| Valid Accounts | T1078 | Multiple stages | If credentials obtained successfully |
| Remote Services: SSH | T1021.004 | Lateral Movement | SSH access with stolen credentials |
| Remote Services: Remote Desktop Protocol | T1021.001 | Lateral Movement | RDP access with stolen credentials |

---

## Recommended Actions

> ⚠️ Defensive guidance only — requires analyst review before acting.

1. **Active brute force, no success:** Block source IP. Review account lockout thresholds.
2. **Active brute force from internal IP:** Investigate host for malware. Check for lateral movement.
3. **Successful compromise suspected:** Full incident response. Isolate system. Force credential rotation.
4. **Pattern of multiple services targeted:** Full network sweep from source IP. Coordinated attack underway.

---

## Hardening Recommendations

These are long-term fixes to reduce brute force risk — review with system owners:

- Enable multi-factor authentication (MFA) on all remote access services
- Implement account lockout policy (5 attempts → 15-minute lockout)
- Use fail2ban or equivalent for SSH/RDP
- Disable password authentication for SSH (key-only)
- Change default ports for SSH (security through obscurity — partial mitigation)
- Implement geographic IP restrictions for RDP/SSH if access patterns allow
