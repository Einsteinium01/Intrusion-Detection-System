# Network Flow Aggregation and Feature Extraction — Technical Reference

**Component:** `FlowAggregator` + `FeatureExtractor`  
**Module:** `backend/flow_aggregator.py`, `feature_extraction/`  
**Purpose:** Converts raw packets into statistical flow features for XGBoost classification

---

## Overview

The network traffic analyzer does not perform deep packet inspection. Instead, it groups packets into **flows** based on the 5-tuple key, accumulates statistical summaries using Welford's online algorithm, and extracts 70 features at flow completion (or timeout) for XGBoost classification.

This approach:
- Preserves user privacy (no payload content is processed or stored)
- Operates in real-time with O(1) memory per flow
- Works with encrypted traffic (TLS/HTTPS)
- Matches the feature space of the CIC-IDS training datasets

---

## Flow Definition

A **network flow** is a bidirectional sequence of packets sharing the same:
- `source_ip` and `destination_ip` (or their reverse)
- `source_port` and `destination_port`
- `protocol` (TCP, UDP, ICMP)

Flows are identified by a canonical 5-tuple key:
```
(min(src_ip, dst_ip), max(src_ip, dst_ip),
 min(src_port, dst_port), max(src_port, dst_port),
 protocol)
```

### Flow Lifetime

| Condition | Action |
|-----------|--------|
| TCP FIN/RST received | Flow completed — extract features + classify |
| `FLOW_TIMEOUT` seconds without packet | Flow expired — extract features + classify |
| Maximum packet count reached | Flow forced — extract features + classify |

Default `FLOW_TIMEOUT`: 60 seconds  
Default `MAX_FLOW_PACKETS`: 10,000

---

## Packet Capture

Packets are captured using **Npcap** (Windows) via the `scapy` or `pyshark` interface. Only the packet header is processed:

- **IP header:** source/dest IP, TTL, protocol
- **TCP header:** source/dest port, flags (SYN/ACK/FIN/RST/PSH/URG), window size, sequence number
- **UDP header:** source/dest port, length
- **ICMP header:** type, code

**Payload bytes are counted but not inspected.**

---

## Welford Online Statistics

For each flow, the following statistics are maintained using Welford's algorithm:

### What Welford tracks

For each time-series metric (inter-arrival time, packet length, etc.):

```python
class WelfordAccumulator:
    def __init__(self):
        self.count = 0
        self.mean = 0.0
        self.M2 = 0.0  # running sum of squared deviations

    def update(self, value: float):
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        delta2 = value - self.mean
        self.M2 += delta * delta2

    @property
    def variance(self):
        if self.count < 2:
            return 0.0
        return self.M2 / (self.count - 1)

    @property
    def std(self):
        return math.sqrt(self.variance)
```

### Metrics tracked per flow

| Metric | Welford tracks |
|--------|---------------|
| `flow_iat` | Inter-arrival time between consecutive packets |
| `fwd_iat` | Inter-arrival time for forward packets only |
| `bwd_iat` | Inter-arrival time for backward packets only |
| `fwd_packet_length` | Byte length of forward packets |
| `bwd_packet_length` | Byte length of backward packets |
| `active_time` | Active (transmitting) subflow durations |
| `idle_time` | Idle (pausing) subflow durations |

---

## Feature Extraction

At flow completion, 70 features are extracted:

### Directional Split

Every packet is classified as **forward** (client → server) or **backward** (server → client) based on which endpoint initiated the connection:

- For TCP: the endpoint that sent the first SYN is the **forward** direction
- For UDP/ICMP: the first packet defines the **forward** direction

### Key Features

**Duration:**
- `flow_duration` = (last_packet_time − first_packet_time) in microseconds

**Volume:**
- `total_fwd_packets`, `total_bwd_packets`
- `total_length_fwd_packets`, `total_length_bwd_packets`

**Packet length statistics (Welford):**
- `fwd_packet_length_max`, `fwd_packet_length_min`, `fwd_packet_length_mean`, `fwd_packet_length_std`
- Same for backward direction

**IAT statistics (Welford):**
- `flow_iat_mean`, `flow_iat_std`, `flow_iat_max`, `flow_iat_min`
- `fwd_iat_total`, `fwd_iat_mean`, `fwd_iat_std`, `fwd_iat_max`, `fwd_iat_min`
- `bwd_iat_total`, `bwd_iat_mean`, `bwd_iat_std`, `bwd_iat_max`, `bwd_iat_min`

**TCP flags:**
- `fin_flag_count`, `syn_flag_count`, `rst_flag_count`
- `psh_flag_count`, `ack_flag_count`, `urg_flag_count`

**Derived rates:**
- `flow_bytes_per_second` = total_bytes / flow_duration
- `flow_packets_per_second` = total_packets / flow_duration

**Window sizes:**
- `init_win_bytes_fwd` — initial TCP window size from client
- `init_win_bytes_bwd` — initial TCP window size from server

---

## Attack Signatures in Feature Space

Different attack types create distinct feature patterns:

| Attack | Key Features |
|--------|-------------|
| **PortScan** | High `syn_flag_count`, zero `ack_flag_count`, very short `flow_duration`, low `total_fwd_packets` |
| **DDoS UDP Flood** | Extremely high `flow_packets_per_second`, zero TCP flags, uniform `packet_length` |
| **SYN Flood** | High `syn_flag_count`, zero `ack_flag_count`, high rate, low `fwd_packet_length_mean` |
| **Brute Force** | Many short flows to same port, periodic `fwd_iat_mean`, low `bwd_packet_length` (failed auth) |
| **Botnet C2** | Very regular `flow_iat_std` (beaconing), fixed `packet_length_variance`, long `flow_duration` |
| **Slowloris DoS** | Very few packets, extremely large `flow_iat_max`, small payloads, many flows to port 80 |

---

## Memory and Performance

- **Per-flow memory:** ~2 KB (accumulators + counters)
- **Max concurrent flows:** Configurable (default: 100,000)
- **Feature extraction time:** <1 ms per flow on modern hardware
- **Packet processing latency:** <5 ms end-to-end (capture → classification → alert)

All statistics are computed in a single pass — no packet buffering required.
