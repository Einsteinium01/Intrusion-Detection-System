# XGBoost Network Intrusion Classifier — Technical Reference

**Component:** XGBoost Gradient Boosting Classifier  
**Module:** `backend/xgboost_detector.py` / `feature_extraction/`  
**Type:** Supervised machine learning (binary + multiclass classification)  
**Trained on:** CIC-IDS-2017 / CIC-IDS-2018 datasets  
**Input:** 70 network flow features  
**Output:** Attack classification + confidence score

---

## Purpose

The XGBoost classifier provides flow-level intrusion detection by analyzing 70 statistical and protocol features extracted from completed or ongoing network flows. It detects a broad range of attack categories that the rule-based ScanDetector does not cover, including DDoS, brute force, botnet C2, and web attacks.

---

## Detection Pipeline

```
Network packets (libpcap / Npcap)
    ↓
Flow Aggregation (FlowAggregator)
    ↓  groups packets by 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol
    ↓  maintains Welford online statistics for each flow
Feature Extraction (FeatureExtractor)
    ↓  computes 70 flow-level features
    ↓  no raw packet content used
XGBoost Classifier
    ↓  predicts attack class
    ↓  returns confidence score (0.0 – 1.0)
AlertContext (if confidence ≥ ALERT_CONFIDENCE_THRESHOLD)
    ↓
AlertAnalyzer + RAG + Groq LLM
    ↓
AlertAnalysis
```

---

## Feature Engineering (70 Features)

Features are grouped into 8 categories:

### 1. Flow Duration and Volume (8 features)
- `flow_duration` — total flow duration in microseconds
- `total_fwd_packets` — packets sent forward (client → server)
- `total_bwd_packets` — packets sent backward (server → client)
- `total_length_fwd_packets` — total bytes, forward direction
- `total_length_bwd_packets` — total bytes, backward direction
- `fwd_packet_length_max/min/mean` — forward packet size statistics

### 2. Inter-Arrival Time Statistics (8 features)
Uses **Welford's online algorithm** for running mean/variance without storing all values:
- `flow_iat_mean` — mean inter-arrival time (ms) across all packets
- `flow_iat_std` — standard deviation of inter-arrival time
- `flow_iat_max` — maximum inter-arrival gap
- `flow_iat_min` — minimum inter-arrival gap
- `fwd_iat_mean/std/max/min` — same for forward direction only

### 3. TCP Flag Counts (6 features)
- `fin_flag_count` — FIN packets (connection teardown)
- `syn_flag_count` — SYN packets (connection initiation)
- `rst_flag_count` — RST packets (connection reset — forced closure)
- `psh_flag_count` — PSH packets (push data without buffering)
- `ack_flag_count` — ACK packets (acknowledgment)
- `urg_flag_count` — URG packets (urgent data — rare in normal traffic)

### 4. Packet Length Statistics (10 features)
- `packet_length_mean` — mean packet size
- `packet_length_std` — packet size standard deviation
- `packet_length_variance` — packet size variance
- `fwd_header_length` — mean header length for forward packets
- `bwd_header_length` — mean header length for backward packets
- ... (additional min/max/median features)

### 5. Rate Features (6 features)
- `flow_bytes_per_second` — overall byte rate
- `flow_packets_per_second` — overall packet rate
- `fwd_packets_per_second` — forward packet rate
- `bwd_packets_per_second` — backward packet rate
- `down_up_ratio` — ratio of backward to forward bytes

### 6. Active/Idle Time Features (4 features)
- `active_mean/std` — time the flow was actively transmitting
- `idle_mean/std` — time the flow was idle between bursts

### 7. Subflow Statistics (4 features)
- `subflow_fwd_packets/bytes` — average packets/bytes per forward subflow
- `subflow_bwd_packets/bytes` — average packets/bytes per backward subflow

### 8. Protocol-Specific Features (remaining features)
- `init_win_bytes_fwd/bwd` — initial TCP window size
- `act_data_pkt_fwd` — count of forward data packets (with payload)
- `min_seg_size_fwd` — minimum TCP segment size forward

---

## Attack Classes

| Class | Description | Example |
|-------|-------------|---------|
| `BENIGN` | Normal network traffic | Web browsing, file transfer |
| `PortScan` | TCP SYN port scanning | nmap, masscan |
| `DDoS` | Volumetric flooding | UDP flood, SYN flood |
| `DoS Hulk` | HTTP flood DoS | Hulk tool |
| `DoS GoldenEye` | HTTP DoS tool | GoldenEye |
| `DoS Slowloris` | Slow HTTP connection DoS | Slowloris |
| `BruteForce` | Credential brute force | SSH/FTP brute force |
| `Infiltration` | Exfiltration / C2 beaconing | Botnet communication |
| `Bot` | Botnet traffic | ARES botnet |
| `Web Attack` | SQL injection, XSS | Web app attacks |
| `Heartbleed` | OpenSSL Heartbleed exploit | TLS vulnerability |

---

## Model Training

- **Dataset:** CIC-IDS-2017 and CIC-IDS-2018 (Canadian Institute for Cybersecurity)
- **Algorithm:** XGBoost `XGBClassifier`
- **Objective:** `multi:softprob` (multiclass probability output)
- **Features:** 70 flow-level features (no packet payload content)
- **Validation:** 80/20 train-test split; cross-validation
- **Model file:** `models/xgboost_model.pkl`

---

## Confidence Scoring

The classifier outputs probability scores for each class. The **confidence** reported in the alert is:

```
confidence = max(class_probabilities)
```

A flow is only reported as an alert if:
```
confidence >= ALERT_CONFIDENCE_THRESHOLD (default: 0.70)
AND predicted_class != BENIGN
```

---

## Welford Online Statistics

The IDS uses **Welford's algorithm** for computing running mean and variance of flow statistics without storing all packets. This is critical for real-time operation:

```
For each new value x:
  count += 1
  delta = x - mean
  mean += delta / count
  delta2 = x - mean
  M2 += delta * delta2

variance = M2 / (count - 1)   # sample variance
std = sqrt(variance)
```

This enables computing `flow_iat_std`, `packet_length_std`, `active_std`, and `idle_std` in O(1) memory per flow.

---

## Limitations

1. **Novel attack patterns:** XGBoost only detects patterns seen in training data. Zero-day attacks may be missed.
2. **Adversarial evasion:** An attacker who knows the feature set can craft flows to evade detection (e.g., inserting padding to normalize packet sizes).
3. **Encrypted traffic:** Features are purely statistical — no deep packet inspection. Detection relies on behavioral signatures.
4. **Imbalanced classes:** Rare attack types may have lower detection rates due to training set imbalance.
