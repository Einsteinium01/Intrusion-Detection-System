# Intelligent Real-time Network Traffic Analyzer for Intrusion Detection using Machine Learning 

UNDER DEVELOPMENT

**Real-Time Intrusion Detection using Machine Learning**

A web-based application that captures live network traffic from the local machine, extracts
network-flow features, classifies each flow as *Normal* or *Malicious* using a trained
Machine Learning model, and streams the results to a live dashboard in the browser.

Final Year Engineering Project.

---
Images:
<img width="1917" height="902" alt="nids" src="https://github.com/user-attachments/assets/ac58968a-acc7-4e21-a814-5a213766562a" />
<img width="1607" height="890" alt="threats dashboard" src="https://github.com/user-attachments/assets/aa6a9edb-c62c-406d-80c1-9b89064facf7" />
<img width="1602" height="902" alt="threats module" src="https://github.com/user-attachments/assets/faecfa49-88ba-4ee8-bdc4-784486964972" />
<img width="1591" height="882" alt="threats-2" src="https://github.com/user-attachments/assets/36597bdd-4893-4b6d-ab49-25f39794f067" />


## 1. What this project demonstrates

| Domain | Where it appears |
|---|---|
| Networking | Live packet capture, TCP/UDP/ICMP parsing, flow reconstruction |
| Machine Learning | Random Forest / Decision Tree / XGBoost trained on CICIDS2017 |
| Cybersecurity | Intrusion detection, attack classification, alerting |
| Backend Development | Flask REST API + Flask-SocketIO WebSocket server |
| Frontend Development | React (Vite) + Tailwind CSS dashboard |
| Data Visualization | Chart.js traffic timelines and attack-distribution charts |

---

## 2. Technology stack

| Layer | Technology | Why this choice |
|---|---|---|
| Language | Python 3.12+ | One language for capture, ML, and backend |
| Packet capture | **Scapy** | Pure Python, no Wireshark install needed, gives direct access to header fields. (See §7 for why not PyShark.) |
| ML | scikit-learn, XGBoost, pandas, NumPy, joblib | Standard, well-documented, CPU-friendly |
| Backend | Flask + Flask-SocketIO | Flask for REST, SocketIO for pushing live data to the browser |
| Frontend | React (Vite) + Tailwind CSS | Component model suits a dashboard; Vite gives instant hot reload |
| Charts | Chart.js (via react-chartjs-2) | Lightweight, good real-time updates |
| Database | SQLite | Zero-configuration, single file, ships with Python |
| Version control | Git | — |

---

## 3. Project structure

```
network-traffic-analyzer/
│
├── config/                  # Central settings shared by every module
│   ├── __init__.py
│   └── settings.py          # Paths, ports, thresholds, capture options
│
├── dataset/                 # CICIDS2017 CSVs  (YOU paste these here)
│   └── README.md            # Instructions + expected filenames
│
├── models/                  # Trained artefacts written by Phase 2
│   ├── model.pkl            #   the serialised classifier
│   ├── feature_columns.pkl  #   exact feature order the model expects
│   └── label_encoder.pkl    #   maps class numbers back to attack names
│
├── packet_capture/          # Phase 3 + 4: sniffing and feature extraction
│
├── backend/                 # Phase 5 + 6: Flask app, REST API, detection engine
│   ├── api/                 #   route blueprints (/start, /stop, /status, ...)
│   └── services/            #   detection, database access, statistics
│
├── frontend/                # Phase 7: React (Vite) dashboard source
│
├── templates/               # Server-rendered HTML fallback page
├── static/                  # Static assets served directly by Flask
│   ├── css/
│   └── js/
│
├── database/                # Phase 8: traffic.db (SQLite file, git-ignored)
├── logs/                    # Runtime application logs (git-ignored)
├── tests/                   # Phase 9: pytest suite
├── reports/                 # Phase 9: evaluation report, confusion matrix images
├── scripts/                 # Helper scripts (setup verification, retraining)
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## 4. Setup instructions

### Step 1 — Prerequisites

- **Python 3.12 or newer.** Check with `python --version`.
- **Npcap** (Windows only) — the driver Scapy needs to read packets off the wire.
  Download from <https://npcap.com/#download> and tick *"Install Npcap in WinPcap API-compatible Mode"*.
  On Linux/macOS `libpcap` is already present.
- **Node.js 18+** — needed from Phase 7 onward for the React frontend. Not required yet.

### Step 2 — Create and activate a virtual environment

A virtual environment is a private copy of Python for this project only. Without one,
`pip install` writes into your system Python and different projects fight over versions.

**Windows (PowerShell):**
```powershell
cd C:\network-traffic-analyzer
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
If PowerShell blocks the activation script, run this once:
```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

**Windows (Git Bash / bash):**
```bash
cd /c/network-traffic-analyzer
python -m venv .venv
source .venv/Scripts/activate
```

**Linux / macOS:**
```bash
cd network-traffic-analyzer
python3 -m venv .venv
source .venv/bin/activate
```

Your prompt should now start with `(.venv)`. To leave it later, type `deactivate`.

### Step 3 — Install dependencies

```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4 — Paste the dataset

Copy your downloaded CICIDS2017 CSV files into `dataset/`. See `dataset/README.md`
for the expected filenames.

### Step 5 — Verify the setup

```bash
python scripts/verify_setup.py
```

Every line should read `[ OK ]`. A `[WARN]` on the dataset check simply means
you have not pasted the CSVs yet.

---

## 5. Architecture

### 5.1 High-level flow

```
                    ┌─────────────────────────────┐
                    │        Browser (React)      │
                    │   Dashboard · Charts · Logs │
                    └──────────┬──────────▲───────┘
                     REST/HTTP │          │ WebSocket (Socket.IO)
                               ▼          │
                    ┌─────────────────────┴───────┐
                    │       Flask Backend         │
                    │  /start /stop /status       │
                    │  /alerts /logs              │
                    └──────────┬──────────────────┘
                               │ starts / stops
                               ▼
                    ┌─────────────────────────────┐
                    │   Packet Capture Module     │  ← Scapy sniffs the NIC
                    │      (background thread)    │
                    └──────────┬──────────────────┘
                               │ raw packets
                               ▼
                    ┌─────────────────────────────┐
                    │  Feature Extraction Module  │  ← groups packets into flows
                    │   packets → flow features   │
                    └──────────┬──────────────────┘
                               │ feature vector
                               ▼
                    ┌─────────────────────────────┐
                    │     ML Model (model.pkl)    │  ← Random Forest
                    │  predict + confidence score │
                    └──────────┬──────────────────┘
                               │ verdict
                    ┌──────────┴──────────┐
                    ▼                     ▼
        ┌───────────────────┐   ┌─────────────────────┐
        │  SQLite Database  │   │  Socket.IO emit     │
        │ alerts·statistics │   │  → live dashboard   │
        └───────────────────┘   └─────────────────────┘
```

### 5.2 Two independent pipelines

The project has an **offline** pipeline and an **online** pipeline. They meet at `model.pkl`.

**Offline (runs once, Phase 2):**
```
CICIDS2017 CSVs → clean → select features → encode labels
  → train/test split → train Random Forest → evaluate
  → save model.pkl + feature_columns.pkl
```

**Online (runs every time you click *Start Monitoring*):**
```
Live packets → group into flows → compute the same features
  → load model.pkl → predict → store + broadcast
```

The critical constraint tying them together: the online pipeline must produce
features **in the same order, with the same meaning and units** as the offline
one. That is exactly why `feature_columns.pkl` is saved alongside the model —
it is the contract between the two halves of the project.

---

## 6. Project workflow

| Phase | Deliverable | Status |
|---|---|---|
| 1 | Project setup — structure, venv, dependencies, docs | **Complete** |
| 2 | Machine learning — train and evaluate on CICIDS2017 | Pending |
| 3 | Packet capture — Scapy sniffer for TCP/UDP/ICMP | Pending |
| 4 | Feature extraction — packets → flow feature vectors | Pending |
| 5 | Detection engine — capture + features + model integration | Pending |
| 6 | Flask backend — REST API and Socket.IO server | Pending |
| 7 | Frontend — React + Tailwind + Chart.js dashboard | Pending |
| 8 | Database — SQLite schema and automatic logging | Pending |
| 9 | Testing — ping, port scan, browsing; metrics report | Pending |
| 10 | Documentation — diagrams, screenshots, presentation notes | Pending |

Each phase is built and tested on its own before being wired into the next.

---

## 7. How the modules communicate

Understanding *how data moves between modules* matters more than any single file.

**1. Config is imported, never passed around.**
Every module does `from config import settings`. There is exactly one place to
change a port number or a file path.

**2. Capture → Feature Extraction: a callback.**
Scapy's `sniff()` calls a function once per packet. The capture module does not
know what feature extraction is; it just calls the callback it was handed. This
keeps the two testable in isolation — Phase 3 works with a callback that only
prints packets.

**3. Feature Extraction → Detection: a queue.**
Packet capture runs in a background thread and can produce bursts faster than
the model can score them. A thread-safe `queue.Queue` sits between them so a
burst of traffic never blocks the sniffer or drops packets.

**4. Detection → Database: direct write.**
When a flow is classified as an attack with confidence above
`ALERT_CONFIDENCE_THRESHOLD`, the detection engine writes a row to the `alerts`
table. The database is the durable record; memory holds only the recent buffer.

**5. Backend → Browser: two channels, on purpose.**
- **REST** (`/status`, `/alerts`, `/logs`) answers "what is the situation right now?"
  Used on page load and on manual refresh. Request/response, stateless.
- **WebSocket** (Socket.IO) pushes `new_packet`, `new_alert`, and `stats_update`
  events as they happen. The browser never polls; the server speaks first.

Polling for live packets would mean either high latency or hammering the server
with requests, which is precisely the problem WebSockets solve.

### Why Scapy and not PyShark

Both were candidates. Scapy wins here because:

- **No external dependency.** PyShark is a wrapper that shells out to `tshark`
  (Wireshark's CLI); every user of the project would need Wireshark installed.
  Scapy talks to Npcap/libpcap directly.
- **Faster.** PyShark serialises packets to XML/JSON through a subprocess pipe.
  Scapy keeps everything in-process as Python objects.
- **Direct field access.** `packet[TCP].flags` is exactly what feature
  extraction needs in Phase 4.

PyShark's advantage — Wireshark's enormous protocol dissector library — does not
help us, because CICIDS2017 features are computed from IP/TCP/UDP headers only.

---

## 8. Running the project

Phase 1 has no application to run yet. The only command available now is:

```bash
python scripts/verify_setup.py
```

From Phase 6 onward the backend will start with `python backend/app.py`, and from
Phase 7 the frontend dev server with `npm run dev` inside `frontend/`.

---

## 9. Important note on privileges

Packet capture requires administrator/root privileges — reading raw frames off a
network card is an OS-level privileged operation.

- **Windows:** run your terminal as Administrator (right-click → *Run as administrator*).
- **Linux/macOS:** run with `sudo`, or grant the capability once with
  `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python))`.

This matters from Phase 3 onward.

---

## 10. Ethical and legal use

This tool captures traffic on the machine it runs on. Only ever run it on a
network you own or have written permission to test. The Phase 9 attack
simulations (Nmap port scans, ping floods) must be performed against your own
machine or an isolated lab VM. Scanning third-party networks without
authorisation is illegal in most jurisdictions.

---

## 11. Suggested commit message for this phase

```
chore: scaffold project structure and Phase 1 setup

- Add folder structure for dataset, models, capture, backend, frontend,
  database, logs, tests and reports
- Add requirements.txt pinning Flask, Scapy, scikit-learn and tooling
- Add config/settings.py as the single source of paths and tunables
- Add scripts/verify_setup.py to validate the environment
- Document architecture, module communication and setup in README
```
