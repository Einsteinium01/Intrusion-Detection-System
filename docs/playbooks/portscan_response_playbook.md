# Port Scan / Network Reconnaissance — Response Playbook

**Source:** Project Detection Team  
**Applies to:** `PortScan`, `NetworkScan`, `ReconScan` alerts  
**Detectors:** `ScanDetector`, `XGBoostDetector`  
**MITRE ATT&CK:** T1046 (Network Service Discovery), T1595 (Active Scanning)

---

## Overview

A port scan alert indicates that a single source IP sent a high volume of TCP SYN probes to multiple destination ports or hosts in a short time window. The ScanDetector fires when `distinct_ports >= PORTSCAN_THRESHOLD` (default 15) from a single source within the observation window. The XGBoost classifier independently classifies flows using 70 extracted features.

**This is a reconnaissance technique.** The attacker is mapping open services before attempting exploitation.

---

## Alert Triage (First 5 minutes)

### Step 1 — Validate the alert

- Confirm `detector = ScanDetector` or `detector = XGBoostDetector`
- Check `confidence` field — values above 0.85 are high confidence
- Review `evidence` list:
  - `distinct_ports` — how many unique ports were probed
  - `syn_count` — number of SYN probes sent
  - `scan_type` — `vertical` (one host, many ports) or `horizontal` (one port, many hosts)
- Review `flow_statistics.duration_seconds` — fast scans (<5s) indicate automated tools (nmap, masscan)

### Step 2 — Classify the scanner

| Indicator | Likely Source |
|-----------|--------------|
| `distinct_ports` > 1000, duration < 10s | masscan / automated scanner |
| Sequential port pattern (1,2,3,...) | nmap default SYN scan |
| Random port order, high rate | Fast automated recon |
| `distinct_ports` 15-30, slow pace | Manual or low-and-slow scan |
| Source IP in internal subnet | **Insider threat or compromised host** — HIGH PRIORITY |
| Source IP external | Internet-facing attack |

### Step 3 — Check source IP context

- Is `source_ip` internal (RFC 1918: 10.x, 172.16.x, 192.168.x)?
  - If **yes**: potentially compromised internal host — treat as HIGH severity
  - If **no**: external attacker probing exposed services
- Has this source IP triggered alerts before? (check alert history)
- Is this IP in any threat intelligence feeds?

---

## Investigation Steps

### For external scanners

1. **Identify what was probed:**
   - Which `destination_port` values were targeted?
   - Were any sensitive ports in the list? (22=SSH, 3389=RDP, 1433=MSSQL, 5432=PostgreSQL, 8080=web)
   
2. **Determine if any ports are open:**
   - Review firewall logs for SYN-ACK responses from your network
   - Check if attacker got responses indicating open services
   
3. **Assess attack surface:**
   - What services are legitimately exposed on the destination IP?
   - Are those services patched and hardened?

4. **Block or rate-limit the source:**
   - Add source IP to firewall block list (temporary — 24-72 hours)
   - Enable stricter rate limiting for TCP SYN packets from that subnet
   - Consider geo-blocking if source is from unexpected region

### For internal scanners (compromised host)

1. **Isolate the source host immediately**
2. **Check for lateral movement indicators:**
   - Review all flows from `source_ip` in the last 24 hours
   - Look for successful connections after the scan (established sessions to open ports)
   - Check for credential access or privilege escalation events
3. **Preserve evidence:**
   - Collect memory dump if possible
   - Capture network traffic from the host
   - Do NOT shutdown — preserve volatile evidence
4. **Escalate to incident response**

---

## Evidence to Collect

- [ ] Source IP WHOIS/ASN information
- [ ] Firewall logs showing packets from source IP (1 hour window around alert)
- [ ] DNS queries from/to source IP
- [ ] Any established TCP sessions from source IP after the scan
- [ ] Authentication logs on destination systems if ports were open
- [ ] Threat intelligence check on source IP (AbuseIPDB, VirusTotal)

---

## MITRE ATT&CK Mapping

| Technique | ID | Stage | Notes |
|-----------|-----|-------|-------|
| Network Service Discovery | T1046 | Discovery | Port scanning to enumerate services |
| Active Scanning: Scanning IP Blocks | T1595.001 | Reconnaissance | Horizontal scan |
| Active Scanning: Vulnerability Scanning | T1595.002 | Reconnaissance | Service version probing |
| Gather Victim Network Information | T1590 | Reconnaissance | Learning network topology |

---

## Recommended Actions

> ⚠️ These are investigative guidance steps only. No automated action should be taken without analyst review.

1. **LOW confidence / external / few ports probed:** Log and monitor. Add to watchlist.
2. **HIGH confidence / external / many ports probed:** Block source IP at perimeter firewall. Review exposed services.
3. **Any confidence / internal source:** Immediate host isolation, incident response escalation.
4. **Followed by exploitation attempt:** Escalate severity to CRITICAL. Engage IR team.

---

## False Positive Indicators

The following may trigger false positives:

- **Vulnerability scanners** (Nessus, OpenVAS, Qualys) run by your own security team
- **Network monitoring tools** (nagios, zabbix) performing service checks
- **Load balancers** performing health checks
- **Application servers** doing port discovery for service mesh

To suppress: whitelist known scanner IPs in `TRUSTED_SCANNER_IPS` configuration.
