# DDoS / Volumetric Flooding — Response Playbook

**Source:** Project Detection Team  
**Applies to:** `DDoS`, `FloodAttack`, `UDPFlood`, `SYNFlood`, `ICMPFlood` alerts  
**Detectors:** `XGBoostDetector`  
**MITRE ATT&CK:** T1498 (Network Denial of Service), T1499 (Endpoint Denial of Service)

---

## Overview

A flooding or DDoS alert indicates abnormally high packet or byte rates directed at a target. The XGBoost classifier detects this pattern using flow-level features including `packets_per_second`, `bytes_per_second`, `packet_size_variance`, `inter_arrival_time`, and protocol-specific flags.

**Flooding attacks aim to exhaust resources:** bandwidth, CPU, connection tables, or memory.

---

## Alert Triage (First 5 minutes)

### Step 1 — Validate the alert

- Confirm high `packets_per_second` or `bytes_per_second` in `flow_statistics`
- Check protocol:
  - **TCP SYN flood:** High `syn_count`, low `ack_count`, many half-open connections
  - **UDP flood:** High byte rate, variable port, no connection state
  - **ICMP flood:** High packet rate, fixed packet size
  - **HTTP flood:** Many requests, all targeting same endpoint (application layer)
- Confirm destination — is it a critical service (web server, DNS, firewall)?

### Step 2 — Assess impact

| Metric | Low Impact | Medium Impact | High Impact |
|--------|-----------|--------------|-------------|
| Packets/sec | < 10K | 10K – 100K | > 100K |
| Bytes/sec | < 100 MB | 100 MB – 1 GB | > 1 GB |
| Service degradation | None visible | Slow responses | Service down |
| Duration | < 1 minute | 1–10 minutes | > 10 minutes |

### Step 3 — Distinguish DDoS from legitimate traffic spike

- Is there a scheduled event? (product launch, planned load test?)
- Is the traffic from diverse source IPs (botnet) or a few?
- Is the traffic pattern regular/synthetic vs. irregular/human?

---

## Investigation Steps

### Immediate (first 10 minutes)

1. **Confirm service impact:**
   - Can the destination service still respond to legitimate requests?
   - Check application response times and error rates
   
2. **Identify traffic source pattern:**
   - Single source IP: likely volumetric test or misconfigured device
   - Many source IPs, same network: botnet or amplification attack
   - Many source IPs, diverse regions: DDoS botnet
   
3. **Check for amplification vectors:**
   - Large UDP responses to small queries (DNS amplification, NTP amplification)
   - `byte_count` >> `packet_count` ratio suggests amplification
   - Destination port 53 (DNS), 123 (NTP), 19 (chargen) are common amplification targets

### Mitigation steps (coordinate with network team)

1. **Rate limiting:** Apply rate limits at the ingress firewall for the offending traffic signature
2. **Null routing:** Route the destination IP to null if the service can be temporarily taken offline
3. **Upstream filtering:** Contact ISP or CDN provider for upstream scrubbing
4. **Protocol-specific mitigations:**
   - SYN flood: Enable SYN cookies at the OS level
   - UDP flood: Block UDP traffic on affected port at firewall
   - DNS amplification: Apply ingress filtering (BCP38); contact upstream

---

## Evidence to Collect

- [ ] Capture packet sample (first 100MB) for analysis
- [ ] Flow logs showing source IP distribution
- [ ] `packets_per_second` and `bytes_per_second` over time
- [ ] Destination service availability metrics (latency, error rate)
- [ ] Firewall/router interface counters before, during, and after attack
- [ ] ISP contact record (if upstream mitigation is needed)

---

## MITRE ATT&CK Mapping

| Technique | ID | Stage | Notes |
|-----------|-----|-------|-------|
| Network Denial of Service: Direct Network Flood | T1498.001 | Impact | UDP/ICMP/TCP flooding |
| Network Denial of Service: Reflection Amplification | T1498.002 | Impact | DNS/NTP amplification |
| Endpoint Denial of Service: Service Exhaustion Flood | T1499.002 | Impact | SYN flood exhausting TCP state |
| Resource Hijacking | T1496 | Impact | If DDoS is cover for other activity |

---

## Recommended Actions

> ⚠️ Defensive guidance only. Automated blocking requires operator review.

1. **Low volume / external:** Monitor, log, watchlist source IPs.
2. **High volume / service degraded:** Enable rate limiting; contact network operations.
3. **Service down / sustained attack:** Engage DDoS mitigation service; contact ISP for upstream scrubbing.
4. **Amplification attack:** Apply egress/ingress filtering; notify affected open resolvers.
5. **Internal source:** Investigate for botnet infection on the internal host.

---

## Post-Incident Review

- Was the attack detected promptly?
- Did the detection system correctly classify the traffic?
- Was the mitigation effective and how quickly was it applied?
- Were any other attacks conducted under cover of the DDoS?
- Update rate-limiting thresholds if false positives were generated.
