# Botnet C2 / Command-and-Control — Response Playbook

**Source:** Project Detection Team  
**Applies to:** `BotnetC2`, `C2Communication`, `BeaconingTraffic`, `Infiltration` alerts  
**Detectors:** `XGBoostDetector`  
**MITRE ATT&CK:** T1071 (Application Layer Protocol C2), T1095 (Non-Application Layer Protocol)

---

## Overview

A botnet/C2 alert indicates that a host on your network is communicating with a remote command-and-control infrastructure. The XGBoost model detects this via regular beaconing patterns: consistent `inter_arrival_time`, fixed `packet_size`, periodic connection bursts, and unusual port/protocol combinations.

**This is a HIGH severity event.** A host communicating with C2 is likely already compromised. Focus on containment and forensics.

---

## Alert Triage (First 5 minutes)

### Step 1 — Validate the alert

- Check `destination_ip` against threat intelligence:
  - Is it in known C2 IP blocklists?
  - Is it in an unexpected geographic region?
  - Is the destination a known hosting/VPS provider often used for malware?
- Review `flow_statistics`:
  - Regular `inter_arrival_time` (consistent beaconing interval) is highly indicative
  - Fixed `packet_size` (same bytes every call-home)
  - Encrypted traffic on non-standard ports (unusual)

### Step 2 — Determine scope of compromise

- When did C2 communication START? (check historical flow data before the alert)
- How long has the host been communicating? (minutes vs. hours vs. days changes severity)
- Has the source host been connecting to other internal hosts? (lateral movement)
- Has any data been transferred OUT? (exfiltration)

---

## Investigation Steps

### Immediate containment

1. **Network-isolate the affected host** — remove from network but keep powered on
2. **Preserve volatile evidence:**
   - Memory dump (before power cycle)
   - Running process list
   - Active network connections (`netstat -anp`)
   - Recently modified files
3. **Block the C2 IP** at the firewall for all internal hosts

### Forensic investigation

1. **Identify the malware:**
   - Check running processes for unusual names or locations
   - Look for persistence mechanisms: startup entries, cron jobs, scheduled tasks, registry run keys
   - Check for web shells if the host is a web server
   
2. **Determine initial infection vector:**
   - Recent email attachments opened?
   - Recent downloads?
   - Recently exploited vulnerabilities (check patch status)
   - Recently changed credentials or new accounts?
   
3. **Determine what the malware has done:**
   - What data did it access? (keylogger output, clipboard capture, credential dumps)
   - What commands were issued by the C2?
   - Were other hosts targeted for lateral movement?
   - Was any data exfiltrated to the C2 or staging server?

4. **Identify all compromised assets:**
   - Are there other hosts communicating with the same C2 IP?
   - Were any credentials stolen and used elsewhere?

---

## Evidence to Collect

- [ ] Memory dump of compromised host
- [ ] Full packet capture from affected host (retroactive from logging system)
- [ ] Process list and parent-child relationships
- [ ] Persistence mechanism details (registry, cron, startup, services)
- [ ] Network connections (netstat/ss output)
- [ ] Full list of files modified in last 30 days
- [ ] Authentication logs (who logged in, when, from where)
- [ ] Malware sample (for analysis and signature development)

---

## MITRE ATT&CK Mapping

| Technique | ID | Stage | Notes |
|-----------|-----|-------|-------|
| Application Layer Protocol: Web Protocols | T1071.001 | C2 | HTTP/HTTPS C2 |
| Application Layer Protocol: DNS | T1071.004 | C2 | DNS tunneling C2 |
| Non-Application Layer Protocol | T1095 | C2 | Raw TCP/UDP C2 |
| Scheduled Task/Job | T1053 | Persistence | Malware persistence |
| Boot/Logon Autostart Execution | T1547 | Persistence | Startup persistence |
| Data Exfiltration over C2 Channel | T1041 | Exfiltration | Data sent to C2 |
| Lateral Movement | T1021 | Lateral Movement | Using stolen credentials |

---

## Recommended Actions

> ⚠️ Incident response actions — requires coordination with IR team.

1. **Immediate:** Isolate compromised host from network (maintain power for forensics).
2. **Short-term:** Block C2 IP/domain across entire network. Identify all infected hosts.
3. **Medium-term:** Rebuild compromised host from clean image. Force credential rotation for all accounts that touched the host.
4. **Long-term:** Patch initial infection vector. Improve endpoint detection. Implement network segmentation.
