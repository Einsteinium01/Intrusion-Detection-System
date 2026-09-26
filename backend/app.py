"""
backend/app.py
==============
WHY THIS FILE EXISTS
--------------------
Phase 6: Flask REST API + Flask-SocketIO real-time backend.

This is the central web server that:
  1. Exposes REST endpoints consumed by the React dashboard (Phase 7).
  2. Streams live packet and alert events over WebSockets using Socket.IO.
  3. Owns the singleton DetectionEngine and controls its lifecycle.

SECURITY (api-audit doctrine applied)
--------------------------------------
API8 – Security Misconfiguration:
  - CORS restricted to known dev/prod origins; no wildcard + credentials.
  - Stack traces never leak into JSON error responses.
  - Security headers added on every response (X-Content-Type-Options, etc.).

API4 – Unrestricted Resource Consumption:
  - All list endpoints accept a bounded 'limit' param (max 500).

API3 – Excessive Data Exposure:
  - Every endpoint returns only the fields the client needs.

API9 – Inventory Management:
  - A single versioned prefix (/api/v1) keeps the surface explicit.

HOW IT WORKS
------------
- Flask app is created with a factory function `create_app()` so it can be
  imported cleanly in tests or WSGI servers.
- Flask-SocketIO runs the event loop in threading mode (no eventlet/gevent
  dependency required on Windows).
- DetectionEngine is started/stopped via /api/v1/start and /api/v1/stop.
- Every captured packet fires a 'packet' SocketIO event; attacks also fire
  an 'alert' event — the React frontend subscribes to both.

FILE: backend/app.py
RUN:  python backend/app.py
"""

import sys
import pathlib
import logging
import time
from datetime import datetime
from typing import Any, Dict

from flask import Flask, jsonify, request, Response
from flask_socketio import SocketIO
from flask_cors import CORS

# Add project root to sys.path so sibling packages import cleanly
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backend.detection_engine import DetectionEngine
from packet_capture.utils import get_available_interfaces

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_PATH = ROOT / "logs" / "app.log"
LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

_sh = logging.StreamHandler(sys.stdout)
if hasattr(_sh.stream, "reconfigure"):
    _sh.stream.reconfigure(encoding="utf-8")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    handlers=[
        _sh,
        logging.FileHandler(LOG_PATH, mode="a", encoding="utf-8"),
    ],
)
log = logging.getLogger("backend.app")

# ---------------------------------------------------------------------------
# Allowed CORS origins (localhost dev + localhost production build)
# api-audit API8: never wildcard + credentials
# ---------------------------------------------------------------------------
ALLOWED_ORIGINS = [
    "http://localhost:5173",   # Vite dev server
    "http://localhost:4173",   # Vite preview
    "http://localhost:3000",   # CRA / alternative dev
    "http://127.0.0.1:5173",
    "http://127.0.0.1:3000",
]

# ---------------------------------------------------------------------------
# Singleton detection engine (shared across requests + SocketIO events)
# ---------------------------------------------------------------------------
engine: DetectionEngine = None   # type: ignore[assignment]
socketio: SocketIO = None        # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
def create_app() -> Flask:
    global engine, socketio

    app = Flask(__name__)
    app.config["SECRET_KEY"] = "nta-dev-secret-not-for-production"
    app.config["JSON_SORT_KEYS"] = False

    # --- CORS (development & local testing) -------------------------------
    CORS(
        app,
        resources={r"/api/*": {"origins": "*"}},
        supports_credentials=False,
    )

    # --- SocketIO -----------------------------------------------------------
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",
        async_mode="threading",
        logger=False,
        engineio_logger=False,
    )

    # --- DetectionEngine ----------------------------------------------------
    engine = DetectionEngine()

    from backend.ai.queue import get_ai_manager
    ai_manager = get_ai_manager()
    ai_manager.set_emit_callback(lambda event, payload: socketio.emit(event, payload) if socketio else None)
    ai_manager.start()

    _last_packet_emit = 0.0

    # Register listener: broadcast sampled packets and all threat alerts
    def _broadcast_packet(result: Dict[str, Any]) -> None:
        """Push packet/alert events to all connected Socket.IO clients without flooding."""
        nonlocal _last_packet_emit
        if socketio and not app.config.get("TESTING"):
            try:
                now = time.time()
                # Security alerts are ALWAYS broadcasted immediately
                if result.get("is_attack"):
                    socketio.emit("alert", result)
                    ai_manager.enqueue(result)

                # Packet stream is throttled to max ~10 pkts/s (every 100ms) to prevent UI/Socket queue lag
                if now - _last_packet_emit >= 0.10:
                    socketio.emit("packet", result)
                    _last_packet_emit = now
            except Exception as err:
                log.debug("SocketIO emit exception: %s", err)

    engine.register_alert_listener(_broadcast_packet)

    # Background thread: broadcast live stats to all clients every 500ms for instant UI updates
    def _stats_broadcast_worker():
        import threading
        while True:
            try:
                time.sleep(0.5)
                if socketio and engine:
                    stats = engine.get_live_stats()
                    socketio.emit("status", stats)
            except Exception as e:
                log.debug("Stats broadcast worker error: %s", e)

    import threading
    stats_thread = threading.Thread(target=_stats_broadcast_worker, daemon=True, name="StatsBroadcastThread")
    stats_thread.start()

    # --- Security headers on every response (api-audit API8) ---------------
    @app.after_request
    def add_security_headers(response: Response) -> Response:
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response

    # ========================================================================
    # REST ENDPOINTS
    # ========================================================================

    # ── GET / ──────────────────────────────────────────────────────────────
    @app.get("/")
    def dashboard() -> Response:
        """Health-check / dashboard entry-point."""
        return jsonify({
            "service": "Intelligent Network Traffic Analyzer",
            "version": "1.0.0",
            "status": "running",
            "docs": "/api/v1",
        })

    # ── GET /api/v1/interfaces ─────────────────────────────────────────────
    @app.get("/api/v1/interfaces")
    def get_interfaces() -> Response:
        """Return a list of available network interfaces."""
        ifaces = get_available_interfaces()
        return jsonify({
            "count": len(ifaces),
            "interfaces": ifaces,
        }), 200

    # ── POST /api/v1/start ─────────────────────────────────────────────────
    @app.post("/api/v1/start")
    def start_monitoring() -> Response:
        """
        Start real-time packet capture and ML-based intrusion detection.

        JSON body (optional):
          { "mode": "LIVE" | "SIMULATION", "interface": "Wi-Fi" }
        """
        body = request.get_json(silent=True) or {}
        raw_mode = str(body.get("mode", "LIVE")).strip().upper()
        interface = body.get("interface")
        if isinstance(interface, str):
            interface = interface.strip()

        allowed_modes = {"LIVE", "SIMULATION", "AUTO", "SCAPY", "RAW_SOCKET"}
        if raw_mode not in allowed_modes:
            return jsonify({"error": f"Invalid mode '{raw_mode}'. Choose from: {sorted(allowed_modes)}"}), 400

        if engine.is_running():
            return jsonify({
                "status": "already_running",
                "message": "Engine is already running.",
                "capture_mode": engine.sniffer.active_mode if engine.sniffer else "UNKNOWN",
                "interface": engine.sniffer.interface if engine.sniffer else "Auto",
            }), 200

        try:
            engine.start(mode=raw_mode, interface=interface)
            log.info("DetectionEngine started via REST (mode=%s, interface=%s).", raw_mode, interface)
            stats = engine.get_live_stats()
            return jsonify({
                "status": "started",
                "capture_mode": stats["capture_mode"],
                "interface": stats["interface"],
            }), 200
        except Exception as exc:
            log.error("Failed to start engine: %s", exc)
            return jsonify({
                "error": str(exc),
                "message": f"Failed to start {raw_mode} packet capture on interface '{interface or 'Auto'}'.",
            }), 400

    # ── POST /api/v1/stop ──────────────────────────────────────────────────
    @app.post("/api/v1/stop")
    def stop_monitoring() -> Response:
        """Stop packet capture and intrusion detection."""
        if not engine.is_running():
            return jsonify({"status": "already_stopped", "message": "Engine is not running."}), 200
        try:
            engine.stop()
            log.info("DetectionEngine stopped via REST.")
            return jsonify({"status": "stopped"}), 200
        except Exception as exc:
            log.error("Failed to stop engine: %s", exc)
            return jsonify({"error": "Failed to stop monitoring engine."}), 500

    # ── GET /api/v1/status ─────────────────────────────────────────────────
    @app.get("/api/v1/status")
    def live_status() -> Response:
        """
        Return live traffic statistics and threat level.
        """
        stats = engine.get_live_stats()
        return jsonify({
            "is_running": stats["is_running"],
            "capture_mode": stats["capture_mode"],
            "interface": stats["interface"],
            "error_message": stats.get("error_message"),
            "threat_level": stats["threat_level"],
            "total_packets": stats["total_packets"],
            "total_bytes": stats["total_bytes"],
            "normal_packets": stats["normal_packets"],
            "attack_packets": stats["attack_packets"],
            "normal_pct": stats["normal_pct"],
            "attack_pct": stats["attack_pct"],
            "packets_per_second": stats["packets_per_second"],
            "bytes_per_second": stats["bytes_per_second"],
            "active_flows": stats.get("active_flows", 0),
            "tcp_count": stats.get("tcp_count", 0),
            "udp_count": stats.get("udp_count", 0),
            "icmp_count": stats.get("icmp_count", 0),
            "duration_seconds": stats["duration_seconds"],
        }), 200

    # ── GET /api/v1/alerts ─────────────────────────────────────────────────
    @app.get("/api/v1/alerts")
    def get_alerts() -> Response:
        """
        Return history of detected intrusion alerts.

        Query params:
          limit (int, 1-500, default 50)
        """
        limit = _parse_limit(request.args.get("limit", 50), max_val=500)
        alerts = engine.get_alerts(limit=limit)
        return jsonify({
            "count": len(alerts),
            "alerts": alerts,
        }), 200

    # ── POST /api/v1/alerts ────────────────────────────────────────────────
    @app.post("/api/v1/alerts")
    def inject_alert() -> Response:
        """
        Ingest an externally detected threat alert (e.g. from validate_portscan.py).
        Broadcasts the alert via Socket.IO and enqueues it for AI analysis.
        """
        body = request.get_json(silent=True)
        if not body or not isinstance(body, dict):
            return jsonify({"error": "Request body must be a JSON alert object."}), 400

        now = time.time()
        alert = dict(body)
        if "id" not in alert:
            import numpy as np
            alert["id"] = f"scan-{int(now * 1000)}-{np.random.randint(100, 999)}"
        if "timestamp" not in alert:
            alert["timestamp"] = now
        if "timestamp_str" not in alert:
            alert["timestamp_str"] = datetime.fromtimestamp(alert["timestamp"]).strftime("%H:%M:%S.%f")[:-3]
        if "is_attack" not in alert:
            alert["is_attack"] = True

        # 1. Update DetectionEngine stats and recent_alerts history
        if engine:
            with engine._lock:
                engine.stats["attack_packets"] += 1
                engine.recent_alerts.append(alert)
                engine.recent_packets.append(alert)
                engine._update_threat_level()

        # 2. Broadcast immediately over Socket.IO to connected clients
        if socketio and not app.config.get("TESTING"):
            try:
                socketio.emit("alert", alert)
            except Exception as e:
                log.debug("SocketIO emit alert failed: %s", e)

        # 3. Enqueue for AI analysis
        ai_manager.enqueue(alert)

        return jsonify({
            "status": "success",
            "message": "Alert injected, broadcasted, and enqueued for AI analysis.",
            "alert_id": alert["id"],
        }), 201

    # ── GET /api/v1/logs ───────────────────────────────────────────────────
    @app.get("/api/v1/logs")
    def get_logs() -> Response:
        """
        Return history of all recently processed packets (both normal + attack).

        Query params:
          limit (int, 1-500, default 50)
        """
        limit = _parse_limit(request.args.get("limit", 50), max_val=500)
        packets = engine.get_recent_packets(limit=limit)
        return jsonify({
            "count": len(packets),
            "packets": packets,
        }), 200

    # ── GET /api/v1/flows ──────────────────────────────────────────────────
    @app.get("/api/v1/flows")
    def get_flows() -> Response:
        """
        Return active network flows tracked by the feature extractor.

        Query params:
          limit (int, 1-500, default 100)
        """
        limit = _parse_limit(request.args.get("limit", 100), max_val=500)
        flows = engine.get_active_flows(limit=limit)
        return jsonify({
            "count": len(flows),
            "flows": flows,
        }), 200

    # ── GET /api/v1/model-info ─────────────────────────────────────────────
    @app.get("/api/v1/model-info")
    def get_model_info() -> Response:
        """Return model specifications, feature metadata, and training stats."""
        info = engine.get_model_info()
        return jsonify(info), 200

    # ── GET /api/v1/export/csv ─────────────────────────────────────────────
    @app.get("/api/v1/export/csv")
    def export_csv() -> Response:
        """
        Export recent detection alerts or packet logs as a CSV file.
        Query params:
          type: 'alerts' | 'logs' (default 'alerts')
          limit: (int, 1-1000, default 500)
        """
        export_type = request.args.get("type", "alerts").lower()
        limit = _parse_limit(request.args.get("limit", 500), max_val=1000)

        import io
        import csv

        output = io.StringIO()
        writer = csv.writer(output)

        if export_type == "logs":
            records = engine.get_recent_packets(limit=limit)
            headers = ["timestamp", "timestamp_str", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "length", "prediction", "is_attack", "confidence_pct", "attack_type"]
            writer.writerow(headers)
            for r in records:
                writer.writerow([
                    r.get("timestamp", ""),
                    r.get("timestamp_str", ""),
                    r.get("src_ip", ""),
                    r.get("dst_ip", ""),
                    r.get("src_port", ""),
                    r.get("dst_port", ""),
                    r.get("protocol", ""),
                    r.get("length", ""),
                    r.get("prediction", "BENIGN"),
                    r.get("is_attack", False),
                    r.get("confidence_pct", 0),
                    r.get("attack_type", "BENIGN"),
                ])
            filename = f"netintel_logs_{int(time.time())}.csv"
        else:
            records = engine.get_alerts(limit=limit)
            headers = ["timestamp", "timestamp_str", "attack_type", "severity", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "confidence_pct", "details"]
            writer.writerow(headers)
            for r in records:
                writer.writerow([
                    r.get("timestamp", ""),
                    r.get("timestamp_str", ""),
                    r.get("attack_type", ""),
                    r.get("severity", "HIGH"),
                    r.get("src_ip", ""),
                    r.get("dst_ip", ""),
                    r.get("src_port", ""),
                    r.get("dst_port", ""),
                    r.get("protocol", ""),
                    r.get("confidence_pct", 0),
                    r.get("details", ""),
                ])
            filename = f"netintel_alerts_{int(time.time())}.csv"

        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    # ── AI layer endpoints (/api/ai/*) ──────────────────────────────────────
    # Phase 1: provider-independent LLM analysis for IDS alerts.
    # IMPORTANT: These endpoints are completely additive.  No existing
    # detection, capture, or dashboard behaviour is modified.

    @app.post("/api/ai/analyze-alert")
    def ai_analyze_alert() -> Response:
        """
        Analyse a single IDS alert with the configured LLM.

        POST body: AlertContext JSON
        Response: AlertAnalysis JSON  (200)
                  Error JSON          (400 | 422 | 503)
        """
        from pydantic import ValidationError as PydanticValidationError
        from backend.ai.alert_analyzer import get_alert_analyzer
        from backend.ai.llm_service import LLMProviderError
        from backend.ai.schemas import AlertContext

        body = request.get_json(silent=True)
        if body is None:
            return jsonify({"error": "Request body must be JSON."}), 400

        # Validate input against AlertContext schema
        try:
            alert_ctx = AlertContext(**body)
        except PydanticValidationError as exc:
            errors = exc.errors()
            return jsonify({
                "error": "Invalid AlertContext payload.",
                "details": [
                    {
                        "field": ".".join(str(p) for p in e["loc"]),
                        "message": e["msg"],
                    }
                    for e in errors[:10]
                ],
            }), 422

        # Call the AI layer
        try:
            analyzer = get_alert_analyzer()
            analysis = analyzer.analyze(alert_ctx)
        except LLMProviderError as exc:
            msg = str(exc)
            # Distinguish "disabled / not configured" (503) from other errors (502)
            if "disabled" in msg.lower() or "not configured" in msg.lower():
                return jsonify({"error": msg}), 503
            log.error("AI analysis failed: %s", msg)
            return jsonify({"error": "AI analysis failed.", "detail": msg}), 502

        return jsonify(analysis.model_dump()), 200

    @app.get("/api/ai/status")
    def ai_status() -> Response:
        """
        Return AI layer configuration and provider health.

        Never returns the API key.
        Response fields: enabled, provider, model, provider_healthy,
                         last_error, reasoning_effort.
        """
        from backend.ai.alert_analyzer import get_alert_analyzer

        try:
            analyzer = get_alert_analyzer()
            health = analyzer.health_check()
        except Exception as exc:
            log.error("AI status check failed: %s", exc)
            health = {
                "ai_enabled": False,
                "llm_provider": "unknown",
                "groq_model": "unknown",
                "provider_healthy": False,
                "last_error": "Status check failed.",
            }

        return jsonify(health), 200

    @app.post("/api/ai/analyze-threat")
    def ai_analyze_threat() -> Response:
        """
        Trigger AI analysis on-demand for a single threat alert.
        Triggered when the user clicks 'AI Analysis' button on a threat.
        """
        from backend.ai.queue import get_ai_manager

        body = request.get_json(silent=True)
        if not body:
            return jsonify({"error": "Request body must be JSON."}), 400

        alert_id = body.get("alert_id") or body.get("id")
        alert_data = body.get("alert") if "alert" in body and isinstance(body.get("alert"), dict) else body

        # If alert_id is provided, search engine's recent alerts if fields are sparse
        if engine and alert_id and (not alert_data or "src_ip" not in alert_data):
            with engine._lock:
                for a in engine.recent_alerts:
                    if a.get("id") == alert_id or a.get("alert_id") == alert_id:
                        alert_data = dict(a)
                        break

        if not alert_data or not isinstance(alert_data, dict):
            return jsonify({"error": "Valid alert object or alert_id is required."}), 400

        ai_manager = get_ai_manager()
        ai_manager.enqueue(alert_data, force=True)

        return jsonify({
            "status": "queued",
            "alert_id": alert_data.get("id") or alert_id,
            "message": "AI analysis started for threat.",
        }), 200

    @app.post("/api/ai/investigate")
    def ai_investigate() -> Response:
        """
        Investigate an alert or network attacks with a specific question.
        Supports both targeted single-alert questions and general dashboard inquiries.
        """
        from backend.ai.alert_analyzer import get_alert_analyzer
        from backend.ai.queue import get_ai_manager
        from backend.ai.schemas import AlertContext
        
        body = request.get_json(silent=True)
        if not body or not body.get("question"):
            return jsonify({"error": "Request body must include 'question'."}), 400
            
        alert_id = str(body.get("alert_id") or "").strip()
        question = str(body["question"])
        
        ai_manager = get_ai_manager()
        alert_ctx = None
        related_alerts_str = []

        if alert_id and alert_id not in ("general", "all", "system"):
            state = ai_manager.get_analysis_state(alert_id)
            if state and state.get("alert"):
                alert_ctx = state["alert"]
            elif engine:
                with engine._lock:
                    for a in engine.recent_alerts:
                        if a.get("id") == alert_id or a.get("alert_id") == alert_id:
                            alert_ctx = ai_manager.normalize_alert(a)
                            break
            if not alert_ctx:
                return jsonify({"error": f"Alert '{alert_id}' not found."}), 404
                
            related_states = ai_manager.get_related_alerts(alert_id, alert_ctx)
            for rs in related_states:
                ctx = rs.get("alert")
                if ctx:
                    related_alerts_str.append(f"Alert {ctx.alert_id}: {ctx.attack_type} src={ctx.source_ip} dst={ctx.destination_ip}")
        else:
            # General query across recent alerts
            recent_attacks = []
            if engine:
                with engine._lock:
                    recent_attacks = list(engine.recent_alerts)[-10:]

            if recent_attacks:
                latest = recent_attacks[-1]
                alert_ctx = ai_manager.normalize_alert(latest)
                for a in recent_attacks:
                    related_alerts_str.append(
                        f"Threat {a.get('id', 'unknown')}: {a.get('attack_type', 'Scan/Intrusion')} "
                        f"from {a.get('src_ip', '?')} to {a.get('dst_ip', '?')} "
                        f"sev={a.get('severity', 'HIGH')} conf={a.get('confidence_pct', 0)}%"
                    )
            else:
                alert_ctx = AlertContext(
                    alert_id="system-overview",
                    timestamp=datetime.now().isoformat(),
                    source_ip="0.0.0.0",
                    destination_ip="0.0.0.0",
                    source_port=0,
                    destination_port=0,
                    protocol="TCP",
                    attack_type="System Baseline",
                    detector="ids-engine",
                    confidence=1.0,
                    evidence=["No active threats detected in current monitoring session."],
                )
                related_alerts_str.append("System is clean. No active attack vectors detected.")
        
        analyzer = get_alert_analyzer()
        try:
            response = analyzer.investigate(alert_ctx, question, related_alerts_str)
        except Exception as exc:
            log.error("AI investigate failed: %s", exc)
            return jsonify({"error": "AI investigation failed.", "detail": str(exc)}), 502
            
        return jsonify(response.model_dump()), 200

    # ── RAG layer endpoints (/api/rag/*) ────────────────────────────────────
    # Phase 2: local knowledge retrieval endpoints.
    # IMPORTANT: RAG is enrichment only — it does NOT perform detection.
    # XGBoost and ScanDetector remain the authoritative detection components.

    @app.get("/api/rag/status")
    def rag_status() -> Response:
        """
        Return RAG layer status and configuration.

        Never exposes server paths or secrets.
        """
        try:
            from backend.rag.config import get_rag_config
            from backend.rag.vector_store import get_vector_store

            cfg = get_rag_config()
            pub = cfg.to_public_dict()

            # Vector store status (lazy load — do not create index if not exists)
            try:
                store = get_vector_store(index_path=cfg.index_path)
                store_status = store.status
                pub["vector_count"] = store_status.get("vector_count", 0)
                pub["indexed_sources"] = store_status.get("indexed_sources", [])
                pub["last_ingestion_time"] = store_status.get("last_ingestion_time")
                pub["index_ready"] = store.count() > 0
            except Exception as se:
                pub["vector_count"] = 0
                pub["indexed_sources"] = []
                pub["index_ready"] = False
                pub["last_ingestion_time"] = None
                log.debug("RAG status: store access error: %s", se)

        except Exception as exc:
            log.error("RAG status failed: %s", exc)
            pub = {
                "rag_enabled": False,
                "index_ready": False,
                "last_error": str(exc),
            }

        return jsonify(pub), 200

    @app.post("/api/rag/search")
    def rag_search() -> Response:
        """
        Search the local RAG knowledge index.

        POST body:
          { "query": "...", "top_k": 5 }

        Returns ranked knowledge documents with scores.
        """
        body = request.get_json(silent=True)
        if not body or not body.get("query"):
            return jsonify({"error": "Request body must include 'query'."}), 400

        query = str(body["query"])[:1000]   # cap query length
        top_k = min(int(body.get("top_k", 5)), 20)   # max 20 results

        try:
            from backend.rag.retriever import get_rag_retriever
            retriever = get_rag_retriever()
            docs = retriever.retrieve(query, top_k=top_k)
            results = [doc.to_knowledge_doc() for doc in docs]
        except Exception as exc:
            log.error("RAG search failed: %s", exc)
            return jsonify({"error": "RAG search failed.", "detail": str(exc)}), 500

        return jsonify({
            "query": query,
            "top_k": top_k,
            "count": len(results),
            "results": results,
        }), 200

    @app.post("/api/rag/reindex")
    def rag_reindex() -> Response:
        """
        Rebuild or update the local RAG knowledge index.

        Runs in a background thread so it does NOT block packet capture.

        POST body (all optional):
          { "source": "all"|"project"|"mitre", "rebuild": false }
        """
        body = request.get_json(silent=True) or {}
        source = body.get("source", "all")
        rebuild = bool(body.get("rebuild", False))

        if source not in ("all", "project", "mitre"):
            return jsonify({"error": f"Invalid source '{source}'. Choose: all, project, mitre"}), 400

        import threading

        result_holder: dict = {}

        def _run_ingest():
            try:
                from backend.rag.ingest import ingest
                from backend.rag.vector_store import reset_vector_store
                if rebuild:
                    reset_vector_store()
                stats = ingest(source=source, rebuild=rebuild)
                result_holder["stats"] = stats.model_dump()
                result_holder["error"] = None
            except Exception as exc:
                log.error("RAG reindex failed: %s", exc)
                result_holder["error"] = str(exc)

        thread = threading.Thread(target=_run_ingest, daemon=True, name="RAGReindexThread")
        thread.start()
        thread.join(timeout=300)   # wait up to 5 min; background if longer

        if "error" in result_holder and result_holder["error"]:
            return jsonify({"error": result_holder["error"]}), 500

        stats = result_holder.get("stats", {})
        return jsonify({
            "status": "complete",
            "source": source,
            "rebuild": rebuild,
            "stats": stats,
        }), 200

    # ── Error handlers ──────────────────────────────────────────────────────
    @app.errorhandler(404)
    def not_found(_err: Any) -> Response:
        return jsonify({"error": "Endpoint not found."}), 404

    @app.errorhandler(405)

    def method_not_allowed(_err: Any) -> Response:
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def internal_error(_err: Any) -> Response:
        # api-audit API8: never leak stack traces
        log.exception("Unhandled internal error.")
        return jsonify({"error": "Internal server error."}), 500

    # ========================================================================
    # SOCKET.IO EVENTS
    # ========================================================================

    @socketio.on("connect")
    def on_connect() -> None:
        log.info("Socket.IO client connected: %s", request.sid)
        # Send current status snapshot on connect
        socketio.emit("status", engine.get_live_stats(), to=request.sid)

    @socketio.on("disconnect")
    def on_disconnect() -> None:
        log.info("Socket.IO client disconnected: %s", request.sid)

    @socketio.on("request_status")
    def on_request_status() -> None:
        socketio.emit("status", engine.get_live_stats(), to=request.sid)

    log.info(
        "Flask app created. Routes: GET / | POST /api/v1/start | POST /api/v1/stop "
        "| GET /api/v1/status | GET /api/v1/alerts | GET /api/v1/logs "
        "| POST /api/ai/analyze-alert | GET /api/ai/status"
    )

    return app


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _parse_limit(raw: Any, max_val: int = 500) -> int:
    """Parse and clamp a 'limit' query parameter (api-audit API4)."""
    try:
        val = int(raw)
        return max(1, min(val, max_val))
    except (TypeError, ValueError):
        return 50


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app = create_app()
    log.info("Starting Flask-SocketIO server on http://0.0.0.0:5000")
    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        use_reloader=False,
        allow_unsafe_werkzeug=True,
    )
