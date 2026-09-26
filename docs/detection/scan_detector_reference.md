# ScanDetector — Technical Reference

**Component:** `ScanDetector`  
**Module:** `backend/scan_detector.py`  
**Type:** Rule-based, stateful detector  
**Primary Detection:** Port scans, network sweeps, TCP SYN reconnaissance

---

## Purpose

The ScanDetector identifies network reconnaissance activity by tracking TCP SYN probe patterns from individual source IPs. It operates independently of the XGBoost classifier and provides complementary, rule-based detection that is explainable and deterministic.

---

## Detection Algorithm

### Core Logic

For each incoming flow, ScanDetector checks whether the flow is a **probe**:

```
is_probe(flow) = True if:
    protocol == TCP
    AND tcp_flags contains SYN
    AND tcp_flags does NOT contain ACK  (not an established session)
    AND tcp_flags does NOT contain FIN  (not a connection teardown)
    AND flow has very few packets       (not an established data transfer)
```

### Probe Accumulation

Probes are accumulated per `source_ip`. The detector tracks:

- `probe_set[source_ip]` = set of `(destination_ip, destination_port)` tuples
- `syn_count[source_ip]` = total SYN probe count
- `first_probe_time[source_ip]` = timestamp of first probe

### Threshold Detection

A **PortScan** alert is generated when:

```
len(probe_set[source_ip]) >= PORTSCAN_THRESHOLD
```

Default `PORTSCAN_THRESHOLD` = 15 distinct (ip, port) combinations.

A **NetworkSweep** (horizontal scan) alert is generated when:

```
len(distinct_destination_ips[source_ip]) >= SWEEP_THRESHOLD
```

Default `SWEEP_THRESHOLD` = 10 distinct destination hosts.

### Scan Type Classification

| Scan Type | Definition | Detection Method |
|-----------|-----------|-----------------|
| **vertical** | One target host, many ports | High `distinct_ports` on same `destination_ip` |
| **horizontal** | Many target hosts, one port | High `distinct_hosts` with same `destination_port` |
| **distributed** | Many hosts, many ports | Both `distinct_ports` and `distinct_hosts` exceed thresholds |

### Cooldown and Deduplication

After generating an alert for a source IP, a **cooldown period** prevents repeated alerts for the same scanner. Default cooldown: 60 seconds.

---

## Alert Evidence Fields

When ScanDetector fires, the generated `AlertContext` contains:

```json
{
  "detector": "ScanDetector",
  "attack_type": "PortScan",
  "evidence": [
    "20 SYN-only probes to distinct destination ports",
    "scan_type=vertical",
    "probe_count=20 distinct_ports=20",
    "No established connections observed (no SYN-ACK responses)"
  ],
  "flow_statistics": {
    "distinct_ports": 20,
    "syn_count": 20,
    "scan_type": "vertical",
    "distinct_hosts": 1
  }
}
```

---

## Configuration Parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `PORTSCAN_THRESHOLD` | 15 | Distinct (host, port) pairs to trigger alert |
| `SWEEP_THRESHOLD` | 10 | Distinct hosts to trigger horizontal sweep |
| `SCAN_WINDOW_SECONDS` | 60 | Time window to accumulate probes |
| `COOLDOWN_SECONDS` | 60 | Minimum time between alerts for same source |
| `MAX_PROBE_HISTORY` | 10000 | Max entries in probe tracking table |

---

## Known Limitations

1. **Encrypted SYN probes:** Cannot distinguish legitimate connection attempts from scans at the TCP flag level alone for encrypted flows.
2. **Low-and-slow scans:** Scans that stay below the threshold window rate may evade detection (XGBoost provides complementary coverage).
3. **Distributed source scans:** If an attacker uses many source IPs, each below the threshold, ScanDetector will not fire. The XGBoost model provides complementary detection.
4. **False positives from legitimate scanners:** Network monitoring tools (nagios, zabbix) may trigger false alerts. Whitelist known scanner IPs.

---

## Integration with XGBoost

ScanDetector and the XGBoost classifier operate independently:

- ScanDetector fires **immediately** when threshold is crossed (real-time)
- XGBoost fires on each **individual flow** after feature extraction (per-flow)
- Both detectors can fire for the same underlying scan event
- The AlertAnalyzer treats both detector outputs the same way

---

## Testing

Unit tests: `tests/test_scan_detector.py`

Key test cases:
- `test_vertical_portscan_is_detected` — threshold crossing
- `test_just_below_threshold_is_not_detected` — boundary condition
- `test_established_session_is_not_a_probe` — SYN+ACK flows excluded
- `test_cooldown_suppresses_repeat_alerts` — cooldown behavior
- `test_two_sources_scanning_are_reported_separately` — source IP isolation
