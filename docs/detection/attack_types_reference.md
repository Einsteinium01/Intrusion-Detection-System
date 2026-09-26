# Network Attack Types and Detection Reference

**Source:** Detection Engineering Team  
**Covers:** All attack classes detected by this IDS  
**Detectors:** ScanDetector (rule-based) + XGBoost (ML-based)

---

## Attack Classes by Category

### 1. Reconnaissance Attacks

#### Port Scan (PortScan)
- **What:** Systematic probing of TCP/UDP ports to identify open services
- **Technique:** Send SYN packets; note which ports respond with SYN-ACK
- **Tools:** nmap (`-sS`), masscan, unicornscan, zmap
- **Flow signature:** Many short flows from same source, all to one destination IP, different destination ports, SYN-only (no ACK)
- **MITRE:** T1046 (Network Service Discovery)
- **Detectors:** ScanDetector (primary), XGBoost

#### Network Sweep (Horizontal Scan)
- **What:** Probing the same port across many IP addresses to find live hosts
- **Tools:** nmap (`-sn`, `-PS`), ping sweep
- **Flow signature:** Same source, many destination IPs, same destination port or ICMP echo
- **MITRE:** T1595.001 (Active Scanning: Scanning IP Blocks)
- **Detectors:** ScanDetector

#### Vulnerability Scan
- **What:** Automated probing to identify vulnerable service versions
- **Tools:** Nessus, OpenVAS, Qualys, Metasploit auxiliary modules
- **Flow signature:** Many services probed, mixed ports, service banner requests, unusual HTTP requests
- **MITRE:** T1595.002 (Active Scanning: Vulnerability Scanning)
- **Detectors:** XGBoost

---

### 2. Denial of Service Attacks

#### DDoS — UDP Flood
- **What:** Overwhelming a target with UDP packets; destination port varies or is fixed
- **Tools:** LOIC, hping3, custom scripts
- **Flow signature:** Extremely high `flow_packets_per_second`, zero TCP flags, uniform packet size, no bidirectional traffic
- **MITRE:** T1498.001 (Network Denial of Service: Direct Network Flood)
- **Detectors:** XGBoost

#### DDoS — SYN Flood
- **What:** Sending many TCP SYN packets to exhaust server connection table (half-open connections)
- **Tools:** hping3, scapy, Metasploit
- **Flow signature:** Very high `syn_flag_count`, near-zero `ack_flag_count`, many flows to port 80/443, high rate
- **MITRE:** T1499.002 (Endpoint Denial of Service: Service Exhaustion Flood)
- **Detectors:** XGBoost, ScanDetector (partial — SYN-only detection)

#### DoS — Slowloris
- **What:** Keeps many HTTP connections open by sending partial requests slowly, exhausting connection pool
- **Tools:** Slowloris, SlowHTTPTest, RUDY
- **Flow signature:** Many long-lived connections, very low packet rate, small payloads, port 80/443
- **MITRE:** T1499.001 (Endpoint Denial of Service: OS Exhaustion Flood)
- **Detectors:** XGBoost

#### DoS — GoldenEye
- **What:** HTTP-based DoS tool using KeepAlive with randomized headers to bypass caches
- **Tools:** GoldenEye
- **Flow signature:** Many GET/POST requests, randomized User-Agent, high connection rate, port 80/443
- **MITRE:** T1499.002
- **Detectors:** XGBoost

#### DoS — Hulk
- **What:** HTTP flood DoS tool generating unique URLs to bypass caching
- **Tools:** Hulk
- **Flow signature:** High `fwd_packets_per_second`, randomized URLs, consistent packet size, port 80
- **MITRE:** T1499.002
- **Detectors:** XGBoost

---

### 3. Credential and Access Attacks

#### Brute Force — FTP
- **What:** Repeated login attempts to FTP service with different passwords
- **Tools:** Hydra, Medusa, ncrack
- **Flow signature:** Many short flows to port 21, consistent `fwd_packet_length_mean`, periodic `fwd_iat_mean`, many RST flags (failed logins)
- **MITRE:** T1110.001 (Brute Force: Password Guessing), T1110.003 (Password Spraying)
- **Detectors:** XGBoost

#### Brute Force — SSH
- **What:** Repeated SSH login attempts
- **Tools:** Hydra, Medusa, Patator, ncrack
- **Flow signature:** Many flows to port 22, two-packet handshake (SYN + RST on failure), consistent timing
- **MITRE:** T1110.001, T1021.004 (Remote Services: SSH)
- **Detectors:** XGBoost

#### Heartbleed (OpenSSL)
- **What:** Exploit of CVE-2014-0160 — reading arbitrary server memory via malformed TLS heartbeat extension
- **Tools:** Metasploit `auxiliary/scanner/ssl/openssl_heartbleed`
- **Flow signature:** TLS traffic on port 443, unusual `fwd_packet_length_max` (large heartbeat request), small response
- **MITRE:** T1190 (Exploit Public-Facing Application), T1005 (Data from Local System)
- **Detectors:** XGBoost

---

### 4. Malware and C2 Attacks

#### Infiltration / Botnet Beaconing
- **What:** Compromised host communicating with C2 server on regular intervals
- **Tools:** ARES botnet, Metasploit Meterpreter, Cobalt Strike
- **Flow signature:** Very regular `flow_iat_std` (consistent timing), fixed `packet_length_variance`, long `flow_duration`, encrypted traffic on unusual ports
- **MITRE:** T1071 (Application Layer Protocol), T1095 (Non-Application Layer Protocol)
- **Detectors:** XGBoost

#### Bot Traffic
- **What:** Automated traffic from botnet-infected hosts performing tasks (spam, scanning, DDoS)
- **Flow signature:** Machine-like regularity in timing, high volume from distributed sources
- **MITRE:** T1584 (Compromise Infrastructure), T1498 (Network Denial of Service)
- **Detectors:** XGBoost

---

### 5. Web Application Attacks

#### SQL Injection
- **What:** Injecting SQL code into web application input fields to manipulate database queries
- **Tools:** sqlmap, manual testing, OWASP ZAP
- **Flow signature:** Many POST requests to same endpoint, varying `fwd_packet_length`, high request rate
- **MITRE:** T1190 (Exploit Public-Facing Application), T1213 (Data from Information Repositories)
- **Detectors:** XGBoost

#### XSS (Cross-Site Scripting)
- **What:** Injecting malicious scripts into web pages to execute in victim browsers
- **Flow signature:** GET requests with encoded parameters, multiple probes to different endpoints
- **MITRE:** T1059.007 (JavaScript)
- **Detectors:** XGBoost

---

## Confidence Thresholds

| Confidence Range | Recommended Action |
|-----------------|-------------------|
| 0.90 – 1.00 | High confidence — prioritize investigation |
| 0.80 – 0.90 | Medium-high — investigate within 1 hour |
| 0.70 – 0.80 | Medium — review within 4 hours |
| Below 0.70 | Not reported (below alert threshold) |

ScanDetector alerts do not have a confidence score below threshold — rule-based detection is binary. Confidence reported represents how far above threshold the scan was.
