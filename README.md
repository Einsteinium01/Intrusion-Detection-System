<div align="center">

# 🛡️ NetIntel — AI-Augmented Real-Time Network Intrusion Detection System

**Next-Generation Network Security Monitoring combining Live Packet Capture, Hybrid Machine Learning (XGBoost + ScanDetector), Local MITRE ATT&CK RAG Knowledge, and Groq-Powered LLM Reasoning.**

[![Python Version](https://img.shields.io/badge/python-3.12+-blue.svg?logo=python&logoColor=white)](https://python.org)
[![React](https://img.shields.io/badge/frontend-React%2019%20%7C%20Vite%20%7C%20Tailwind-61DAFB.svg?logo=react&logoColor=black)](https://react.dev)
[![Backend](https://img.shields.io/badge/backend-Flask%20%7C%20Socket.IO-black.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Machine Learning](https://img.shields.io/badge/ML-XGBoost%20%7C%20Scikit--Learn-F7931E.svg?logo=scikit-learn&logoColor=white)](https://xgboost.readthedocs.io/)
[![RAG Vector Store](https://img.shields.io/badge/RAG-FAISS%20%7C%20MiniLM--L6--v2-7B1FA2.svg?logo=meta&logoColor=white)](https://github.com/facebookresearch/faiss)
[![AI Engine](https://img.shields.io/badge/LLM-Groq%20Cloud%20API-F55036.svg)](https://groq.com)
[![Tests](https://img.shields.io/badge/tests-180%20passed-brightgreen.svg?logo=pytest&logoColor=white)](https://pytest.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

<br />

[Features](#-key-features) • [Video & Screenshots](#-visual-walkthrough--media) • [Architecture](#-system-architecture) • [Quickstart](#-quickstart-guide) • [Simulating Attacks](#-simulating--validating-attacks) • [Project Structure](#-project-structure)

</div>

---

## 📺 Visual Walkthrough & Media

### 📹 Full Live Demo Video
Watch the end-to-end system in action — from live packet sniffing, XGBoost threat detection, to on-demand Groq AI forensic analysis and copilot interaction:

https://github.com/user-attachments/assets/01f1b036-f95d-423e-92c3-0e5e805685b8

<br/>

### 📸 Application Interface Gallery

<table>
  <tr>
    <td width="50%">
      <h4 align="center">📊 Real-Time Operations Dashboard</h4>
      <a href="https://github.com/user-attachments/assets/ac58968a-acc7-4e21-a814-5a213766562a">
        <img src="https://github.com/user-attachments/assets/ac58968a-acc7-4e21-a814-5a213766562a" alt="Real-Time Dashboard" width="100%"/>
      </a>
      <p align="center"><em>Live packet capture metrics, interface controls, protocol breakdown, and active flow statistics.</em></p>
    </td>
    <td width="50%">
      <h4 align="center">🚨 Threat Incident Intelligence</h4>
      <a href="https://github.com/user-attachments/assets/aa6a9edb-c62c-406d-80c1-9b89064facf7">
        <img src="https://github.com/user-attachments/assets/aa6a9edb-c62c-406d-80c1-9b89064facf7" alt="Threat Intelligence Overview" width="100%"/>
      </a>
      <p align="center"><em>Unified threat feed with severity badges, detection confidence %, and on-demand AI analysis buttons.</em></p>
    </td>
  </tr>
  <tr>
    <td width="50%">
      <h4 align="center">🔍 Forensic Incident Inspection</h4>
      <a href="https://github.com/user-attachments/assets/faecfa49-88ba-4ee8-bdc4-784486964972">
        <img src="https://github.com/user-attachments/assets/faecfa49-88ba-4ee8-bdc4-784486964972" alt="Threat Module Diagnostics" width="100%"/>
      </a>
      <p align="center"><em>Detailed attribution drawer displaying IP addresses, ports, transport flags, and model diagnostics.</em></p>
    </td>
    <td width="50%">
      <h4 align="center">🤖 Grounded AI Security Analysis & Playbook</h4>
      <a href="https://github.com/user-attachments/assets/36597bdd-4893-4b6d-ab49-25f39794f067">
        <img src="https://github.com/user-attachments/assets/36597bdd-4893-4b6d-ab49-25f39794f067" alt="AI Threat Analysis" width="100%"/>
      </a>
      <p align="center"><em>RAG-grounded MITRE ATT&CK technique mapping, observed evidence breakdown, and response actions.</em></p>
    </td>
  </tr>
</table>

---

## ⚡ Key Features

- **🌐 Non-Blocking Packet Capture Engine**
  - High-performance live capture powered by **Scapy** and **Npcap/libpcap**.
  - Multi-threaded, non-blocking pipeline: sniffing, flow tracking, ML inference, and AI analysis run in isolated threads to prevent packet drops.

- **🧠 Dual-Engine Hybrid Detection (ML + Heuristic)**
  - **XGBoost Classifier**: Multi-class ML model trained on the standard **CICIDS2017** benchmark, extracting 70 bi-directional flow features computed incrementally via Welford's algorithm.
  - **Heuristic ScanDetector**: Catches stealth single-packet SYN scans and fast horizontal sweeps that traditionally evade flow-based ML classifiers.

- **📚 Local Grounded RAG Knowledge System**
  - Fully local **FAISS vector store** powered by `sentence-transformers/all-MiniLM-L6-v2` (runs 100% on CPU, zero cloud embedding cost).
  - Ingests official **MITRE ATT&CK Enterprise STIX 2.1** techniques, incident response playbooks, and internal detection architecture documentation.
  - Strict prompt-injection guardrails mark all retrieved knowledge as untrusted reference material.

- **🤖 On-Demand AI Threat Intelligence**
  - Dedicated **"AI Analysis"** button on every threat in the dashboard.
  - Invokes ultra-fast **Groq Cloud LLM inference** (`openai/gpt-oss-120b`, `llama-3.3-70b-versatile`) *strictly on user demand* to conserve tokens.
  - Outputs structured executive summaries, technical mechanics, MITRE technique IDs (`T1046`, `T1059`), observed forensic evidence, and step-by-step mitigation playbooks.

- **💬 Floating AI Security Copilot (Dashboard Chat Overlay)**
  - Global floating action assistant button accessible across the entire application.
  - Query active network threats, inquire about specific IP behavior, or ask for immediate mitigation playbooks.
  - Supports both targeted single-alert investigations and global network posture queries.

- **📊 High-Frequency Cyber-Ops React Dashboard**
  - Built with **React 19**, **Vite**, and **Tailwind CSS** featuring a clean cyberpunk dark theme.
  - Live bidirectional streaming via **Flask-SocketIO** (zero polling latency).
  - Interactive throughput charts, protocol visualizers, active flow inspectors, and CSV export capabilities.

---

## 🏗️ System Architecture

```
                    ┌────────────────────────────────────────────────────────┐
                    │            Network Interface (Wire Traffic)            │
                    └───────────────────────────┬────────────────────────────┘
                                                │ Npcap / libpcap (Scapy)
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │               Live Packet Sniffer Thread               │
                    └───────────────────────────┬────────────────────────────┘
                                                │ Raw Packets (TCP/UDP/ICMP)
                                                ▼
                    ┌────────────────────────────────────────────────────────┐
                    │         Welford Incremental Flow Aggregator            │
                    │        (70 Statistical Flow Features Computed)         │
                    └─────────────────────┬──────────────────┬───────────────┘
                                          │                  │
                Full Bi-directional Flows │                  │ Single SYN / Probe Packets
                                          ▼                  ▼
                    ┌───────────────────────────┐  ┌─────────────────────────┐
                    │    XGBoost Classifier     │  │  Heuristic ScanDetector │
                    │ (Trained on CICIDS2017)   │  │   (Stealth SYN Scans)   │
                    └─────────────┬─────────────┘  └────────────┬────────────┘
                                  │ Attack Verdict               │ Scan Verdict
                                  └──────────────┬───────────────┘
                                                 │
                                                 ▼
                    ┌────────────────────────────────────────────────────────┐
                    │                  Alert Normalization                   │
                    │         (Standardized AlertContext Model)              │
                    └───────────┬────────────────────────────────────────────┘
                                │
                                ├─────────────────────────┐
                                │ Socket.IO Broadcast     │ (On-Demand User Click)
                                ▼                         ▼
         ┌───────────────────────────────┐     ┌─────────────────────────────────────┐
         │       React Dashboard         │     │     AI Analysis Manager (Queue)     │
         │ (Threat Table / Charts / Logs)│     └──────────────────┬──────────────────┘
         └──────────────▲────────────────┘                        │
                        │                                         ▼
                        │                      ┌─────────────────────────────────────┐
                        │                      │      Local FAISS Vector Store       │
                        │                      │   (MITRE ATT&CK STIX + Playbooks)   │
                        │                      └──────────────────┬──────────────────┘
                        │                                         │ Retrieved Knowledge
                        │                                         ▼
                        │                      ┌─────────────────────────────────────┐
                        │                      │       Groq Cloud LLM Service        │
                        │                      │  (Structured AlertAnalysis Schema)  │
                        │                      └──────────────────┬──────────────────┘
                        │                                         │
                        └─────────────────── Socket.IO ───────────┘
                                (ai_analysis_started / completed)
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites
- **Python 3.12+**: Check with `python --version`
- **Node.js 18+ & npm**: Check with `node --version`
- **Npcap (Windows only)**: Required for raw packet sniffing.
  - Download from [npcap.com](https://npcap.com/#download)
  - During installation, check: **"Install Npcap in WinPcap API-compatible Mode"**
  - *(On Linux / macOS, `libpcap` is pre-installed)*

---

### 2. Clone the Repository
```bash
git clone https://github.com/your-username/network-traffic-analyzer.git
cd network-traffic-analyzer
```

---

### 3. Backend Setup

1. **Create and activate a Python virtual environment:**

   **Windows (PowerShell):**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

   **Linux / macOS:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

2. **Install Python dependencies:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

3. **Configure Environment Variables:**
   Copy the example environment configuration:
   ```bash
   cp .env.example .env
   ```
   Open `.env` and configure your settings:
   ```ini
   # Activate AI Layer
   AI_ENABLED=true
   AI_AUTO_ANALYZE_ALERTS=false

   # Groq Cloud API Settings (Get free API key at https://console.groq.com/keys)
   GROQ_API_KEY=gsk_your_groq_api_key_here
   GROQ_MODEL=openai/gpt-oss-120b
   GROQ_REASONING_EFFORT=medium

   # Local RAG Settings
   RAG_ENABLED=true
   RAG_EMBEDDING_MODEL=all-MiniLM-L6-v2
   ```

4. **Verify System Setup:**
   Run the setup verification diagnostic:
   ```bash
   python scripts/verify_setup.py
   ```

5. **Start the Flask + Socket.IO Backend Server:**
   *(Note: Packet capture requires administrator privileges)*
   ```bash
   python backend/app.py
   ```
   The backend server will start at `http://localhost:5000`.

---

### 4. Frontend Setup

1. **Open a new terminal and navigate to the frontend directory:**
   ```bash
   cd frontend
   ```

2. **Install frontend dependencies:**
   ```bash
   npm install
   ```

3. **Start the Vite development server:**
   ```bash
   npm run dev
   ```
   Open your browser at **`http://localhost:5173`**.

---

## 🧪 Simulating & Validating Attacks

You can test and validate the end-to-end detection and AI analysis pipeline without requiring a secondary machine:

### Option A: Internal Port Scan Simulation (No Admin Rights Needed)
Run the built-in validator to simulate single-packet stealth SYN probes:
```bash
python scripts/validate_portscan.py --ports 50
```
- The validator injects 50 SYN probes into the detection engine.
- `ScanDetector` flags the vertical port scan within seconds.
- The alert appears live in the **Threats Dashboard**.
- Click the **"AI Analysis"** button next to the threat to trigger Groq LLM forensic analysis.

### Option B: Live Nmap Scan (Local Machine)
In an Administrator terminal, run an actual SYN scan against your machine:
```bash
nmap -sS -p 1-100 127.0.0.1
```
The real-time sniffer will capture the frames, the detection engine will issue an alert, and the React UI will update dynamically.

### Option C: Asking the AI Copilot
Click the **"AI Assistant"** floating button at the bottom right of the dashboard:
- Ask: *"Summarize all active threats"*
- Ask: *"Why was host 10.0.0.99 flagged?"*
- Ask: *"What firewall rules should I implement right now?"*

---

## 📁 Project Structure

```
network-traffic-analyzer/
├── backend/                       # Python Flask API & Engine
│   ├── ai/                        # AI & LLM Integration Layer
│   │   ├── alert_analyzer.py      # Core AI analysis orchestrator
│   │   ├── config.py              # AI configuration & SecretStr security
│   │   ├── llm_service.py         # Groq provider & JSON Schema enforcement
│   │   ├── prompt_builder.py      # Grounded prompt construction & guardrails
│   │   ├── queue.py               # Asynchronous bounded analysis queue
│   │   └── schemas.py             # Pydantic models (AlertContext, AlertAnalysis)
│   ├── rag/                       # Local Retrieval-Augmented Generation
│   │   ├── chunking.py            # Deterministic document chunker
│   │   ├── embeddings.py          # Sentence-transformers local embedding service
│   │   ├── retriever.py           # FAISS query and similarity scorer
│   │   ├── vector_store.py        # Persistent FAISS index manager
│   │   └── sources/               # MITRE STIX & project document adapters
│   ├── app.py                     # Flask entrypoint & Socket.IO emitter
│   ├── detection_engine.py        # Orchestrates capture, features, and ML
│   ├── feature_extraction.py      # Welford 70-feature flow aggregator
│   ├── model_service.py           # Serialized XGBoost model predictor
│   └── scan_detector.py           # Heuristic stealth port-scan detector
│
├── frontend/                      # React 19 + Vite Dashboard
│   ├── src/
│   │   ├── components/
│   │   │   ├── AiAnalysisPanel.jsx    # Interactive Cyberpunk AI forensic panel
│   │   │   ├── AiChatOverlay.jsx      # Floating Security Copilot Chat Modal
│   │   │   ├── InvestigationChat.jsx  # In-drawer technical Q&A component
│   │   │   ├── LiveTrafficChart.jsx   # Real-time traffic timelines
│   │   │   └── Sidebar.jsx / TopBar.jsx
│   │   ├── context/
│   │   │   └── MonitoringContext.jsx  # Global Socket.IO event store
│   │   ├── pages/
│   │   │   ├── DashboardPage.jsx      # Main operations cockpit
│   │   │   ├── ThreatsPage.jsx        # Threat table & incident drawer
│   │   │   ├── LiveTrafficPage.jsx    # Packet streams & protocols
│   │   │   └── NetworkFlowsPage.jsx   # Bi-directional active flow inspector
│   │   └── App.jsx
│   └── package.json
│
├── data/rag/                      # Local FAISS index & metadata (git-ignored)
├── docs/                          # Knowledge base for RAG indexing
│   ├── detection/                 # Detection engine architecture docs
│   └── playbooks/                 # Incident response playbooks (DDoS, PortScan...)
├── models/                        # Pre-trained models (XGBoost, encoders)
├── scripts/                       # Validation & diagnostic utilities
│   ├── validate_portscan.py       # Heuristic scan validator
│   ├── verify_rag_retrieval.py    # RAG vector search tester
│   └── verify_setup.py            # System environment inspector
├── tests/                         # Pytest test suite (180+ tests)
├── requirements.txt               # Pinned Python dependencies
├── .env.example                   # Environment configuration template
└── README.md
```

---

## 🛠️ Technology Stack Breakdown

| Layer | Technologies | Role & Purpose |
|---|---|---|
| **Capture Layer** | Scapy, Npcap / libpcap | Wire-level raw packet sniffing for TCP, UDP, ICMP |
| **Telemetry & Features** | NumPy, Pandas, Welford Alg. | Incremental computation of 70 statistical bi-directional flow features |
| **Detection Layer** | XGBoost, Scikit-Learn | Supervised multi-class attack classification + heuristic scan detection |
| **Vector Store & RAG** | FAISS, `sentence-transformers` | Local semantic embeddings (`all-MiniLM-L6-v2`) over MITRE ATT&CK & playbooks |
| **AI / LLM Provider** | Groq Cloud API, Pydantic | Sub-second JSON-schema compliant threat analysis and mitigation synthesis |
| **Server & Streaming** | Flask, Flask-SocketIO | RESTful management endpoints and low-latency WebSocket event broadcaster |
| **Client UI** | React 19, Vite, Tailwind CSS, Lucide | Modern cyber-ops security dashboard with real-time reactive updates |

---

## 🧪 Testing & Quality Assurance

The codebase includes an extensive automated test suite covering unit, integration, and security edge cases:

```bash
# Run the complete test suite (180 tests)
python -m pytest tests/ -v
```

### Test Coverage Highlights:
- **ML & Scan Detection** (`test_scan_detector.py`, `test_detection.py`): Validates single-packet probes, SYN/FIN transitions, horizontal sweeps, and false-positive suppression.
- **RAG & Vector Retrieval** (`test_rag_layer.py`): Validates deterministic chunking, embedding normalization, score thresholding, and prompt-injection guardrails.
- **AI Queue & Provider** (`test_ai_layer.py`, `test_ai_queue.py`): Validates schema validation, rate-limiting duplicate suppression, bounded queue overflow, and mock fallbacks.
- **Backend API & Sockets** (`test_backend_api.py`): Validates REST routes, security headers, CSV exports, and alert injection.

To verify frontend compilation:
```bash
cd frontend
npm run build
```

---

## ⚖️ Ethical & Legal Disclaimer

> [!WARNING]
> NetIntel captures and inspects live network traffic on the host interface. It is designed strictly for **educational, defensive, and authorized research purposes**.
> 
> Only run this system on networks and hardware you own or have explicit, written authorization to monitor. Performing unauthorized packet sniffing or penetration testing against external systems is illegal in most jurisdictions.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
Feel free to use, modify, and distribute this software for educational and research initiatives.
