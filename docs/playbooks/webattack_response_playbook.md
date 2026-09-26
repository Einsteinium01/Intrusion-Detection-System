# Web Attack / SQL Injection / XSS — Response Playbook

**Source:** Project Detection Team  
**Applies to:** `WebAttack`, `SQLInjection`, `XSS`, `PathTraversal`, `CommandInjection` alerts  
**Detectors:** `XGBoostDetector`  
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059 (Command and Scripting Interpreter)

---

## Overview

Web attack alerts indicate exploitation attempts targeting web application vulnerabilities. The XGBoost model detects anomalous HTTP traffic patterns, unusual payload sizes, and high-rate request patterns characteristic of automated exploitation tools (sqlmap, nikto, dirb, burpsuite automated scans).

**Risk:** Successful exploitation can result in unauthorized data access, code execution, or complete application compromise.

---

## Alert Triage (First 5 minutes)

### Step 1 — Validate the alert

- Confirm `destination_port` is a web port (80, 443, 8080, 8443)
- Review `evidence` fields for attack indicators:
  - High `bytes_per_second` or `packet_rate` (scanner)
  - Unusual `packet_size_variance` (mixed payload sizes typical of automated tools)

### Step 2 — Identify attack type (from flow context)

| Indicator | Attack Type |
|-----------|------------|
| Many small requests to same endpoint | SQL injection or fuzzing |
| Requests with unusual HTTP verbs (OPTIONS, TRACE) | Recon/vulnerability scan |
| Large number of 404/500 responses | Directory brute force |
| POST requests with large payloads | File upload / RCE attempt |
| Rapid sequential URL enumeration | Content discovery (gobuster, dirbuster) |

---

## Investigation Steps

### Check for successful exploitation

1. **Review web server access logs** for `source_ip` in the time window:
   - Were any requests successful (HTTP 200) that look suspicious?
   - Were any file uploads accepted?
   - Were any admin/debug endpoints accessed?
   
2. **Check for error logs** revealing stack traces or internal paths (information disclosure)

3. **Database query logs** — were any unusual queries executed?

4. **Application logs** — any authentication bypasses or privilege escalation?

### If exploitation appears successful

- **Isolate the web application** if possible (maintenance mode or firewall block)
- **Preserve all logs** immediately
- **Check for web shells:** Look for recently created PHP/ASP/JSP files
- **Database integrity check:** Were any records modified, deleted, or exfiltrated?
- **Escalate to incident response**

---

## Evidence to Collect

- [ ] Full web server access log for the attack window
- [ ] Application error log
- [ ] Database query log
- [ ] List of recently modified files in web root
- [ ] WAF logs (if applicable)
- [ ] Source IP WHOIS/reputation

---

## MITRE ATT&CK Mapping

| Technique | ID | Stage | Notes |
|-----------|-----|-------|-------|
| Exploit Public-Facing Application | T1190 | Initial Access | Web application exploitation |
| Command and Scripting Interpreter: Unix Shell | T1059.004 | Execution | OS command injection |
| OS Credential Dumping | T1003 | Credential Access | DB credential harvesting |
| Data from Information Repositories | T1213 | Collection | Database exfiltration via SQLi |

---

## Recommended Actions

1. **Active scan, no success:** Block source IP. Review WAF rules. Assess patch status.
2. **Possible successful SQLi:** Audit database for unauthorized access. Review exfiltrated data scope.
3. **Web shell uploaded:** Full incident response. Assume complete application compromise.
4. **RCE achieved:** Host isolation. Full forensic investigation. Regulatory notification if PII involved.
