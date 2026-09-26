"""
tests/test_backend_api.py
==========================
Pytest suite for Phase 6 – Flask REST API + Socket.IO backend.

Applied skills:
  - testing-boss: test behaviour, not implementation; lowest layer that catches failures.
  - api-audit: verify security boundaries (CORS, input validation, error shapes).
  - verification-before-completion: evidence before claims.
"""

import time
import pytest
from backend.app import create_app, engine


@pytest.fixture(scope="module")
def client():
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c
        if engine and engine.is_running():
            engine.stop()


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
def test_root_health_check(client):
    r = client.get("/")
    assert r.status_code == 200
    data = r.get_json()
    assert data["status"] == "running"
    assert "version" in data


# ---------------------------------------------------------------------------
# /api/v1/status — before engine starts
# ---------------------------------------------------------------------------
def test_status_before_start(client):
    client.post("/api/v1/stop")
    r = client.get("/api/v1/status")
    assert r.status_code == 200
    data = r.get_json()
    assert data["is_running"] is False
    assert "threat_level" in data
    assert "total_packets" in data


# ---------------------------------------------------------------------------
# /api/v1/start → /api/v1/status → /api/v1/stop lifecycle
# ---------------------------------------------------------------------------
def test_start_stop_lifecycle(client):
    client.post("/api/v1/stop")
    # Start
    r = client.post("/api/v1/start", json={"mode": "simulation"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["status"] == "started"

    # Status should show running
    time.sleep(0.3)
    r = client.get("/api/v1/status")
    data = r.get_json()
    assert data["is_running"] is True
    assert data["total_packets"] >= 0

    # Stop
    r = client.post("/api/v1/stop")
    assert r.status_code == 200
    assert r.get_json()["status"] == "stopped"


# ---------------------------------------------------------------------------
# /api/v1/start — input validation (api-audit API4 whitelist)
# ---------------------------------------------------------------------------
def test_start_invalid_mode_rejected(client):
    client.post("/api/v1/stop")
    r = client.post("/api/v1/start", json={"mode": "evil_mode; rm -rf /"})
    assert r.status_code == 400
    assert "error" in r.get_json()


# ---------------------------------------------------------------------------
# /api/v1/alerts and /api/v1/logs — limit clamping (api-audit API4)
# ---------------------------------------------------------------------------
def test_alerts_endpoint(client):
    r = client.get("/api/v1/alerts")
    assert r.status_code == 200
    data = r.get_json()
    assert "alerts" in data
    assert "count" in data


def test_logs_endpoint(client):
    r = client.get("/api/v1/logs")
    assert r.status_code == 200
    data = r.get_json()
    assert "packets" in data
    assert "count" in data


def test_logs_limit_clamped(client):
    # api-audit API4: unbounded limit must be clamped to max 500
    r = client.get("/api/v1/logs?limit=999999")
    assert r.status_code == 200


# ---------------------------------------------------------------------------
# Security headers present (api-audit API8)
# ---------------------------------------------------------------------------
def test_security_headers_present(client):
    r = client.get("/api/v1/status")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("Cache-Control") == "no-store"


# ---------------------------------------------------------------------------
# 404 and 405 return clean JSON (api-audit API8 — no stack traces)
# ---------------------------------------------------------------------------
def test_404_returns_json(client):
    r = client.get("/api/v1/nonexistent")
    assert r.status_code == 404
    data = r.get_json()
    assert "error" in data
    assert "Traceback" not in str(data)


def test_405_returns_json(client):
    r = client.get("/api/v1/start")   # GET on a POST-only route
    assert r.status_code == 405
    data = r.get_json()
    assert "error" in data


# ---------------------------------------------------------------------------
# /api/v1/flows, /api/v1/model-info, /api/v1/export/csv
# ---------------------------------------------------------------------------
def test_flows_endpoint(client):
    r = client.get("/api/v1/flows")
    assert r.status_code == 200
    data = r.get_json()
    assert "flows" in data
    assert "count" in data


def test_model_info_endpoint(client):
    r = client.get("/api/v1/model-info")
    assert r.status_code == 200
    data = r.get_json()
    assert data["model_type"] == "XGBoost Classifier"
    assert data["feature_count"] == 70
    assert "features" in data
    assert len(data["features"]) == 70


def test_export_csv_alerts(client):
    r = client.get("/api/v1/export/csv?type=alerts")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in r.headers.get("Content-Disposition", "")


def test_export_csv_logs(client):
    r = client.get("/api/v1/export/csv?type=logs")
    assert r.status_code == 200
    assert r.headers["Content-Type"].startswith("text/csv")
    assert "attachment" in r.headers.get("Content-Disposition", "")


# ---------------------------------------------------------------------------
# POST /api/v1/alerts — alert injection for external tools (e.g. validate_portscan.py)
# ---------------------------------------------------------------------------
def test_inject_alert_success(client):
    alert_payload = {
        "id": "test-alert-001",
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "attack_type": "PortScan (vertical)",
        "detector": "heuristic-scan",
        "confidence_pct": 95.0,
        "distinct_ports": 25,
        "is_attack": True,
    }
    r = client.post("/api/v1/alerts", json=alert_payload)
    assert r.status_code == 201
    data = r.get_json()
    assert data["status"] == "success"
    assert data["alert_id"] == "test-alert-001"

    # Verify alert appears in GET /api/v1/alerts
    r_get = client.get("/api/v1/alerts")
    assert r_get.status_code == 200
    alerts = r_get.get_json()["alerts"]
    matched = [a for a in alerts if a.get("id") == "test-alert-001"]
    assert len(matched) == 1
    assert matched[0]["attack_type"] == "PortScan (vertical)"


def test_inject_alert_invalid_payload(client):
    # Non-JSON or missing body
    r = client.post("/api/v1/alerts", data="not json", content_type="text/plain")
    assert r.status_code == 400
    assert "error" in r.get_json()


def test_inject_alert_auto_fields(client):
    # Minimal body without id, timestamp, or is_attack
    r = client.post("/api/v1/alerts", json={
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.5",
        "attack_type": "PortScan",
    })
    assert r.status_code == 201
    data = r.get_json()
    assert data["status"] == "success"
    assert data["alert_id"].startswith("scan-")


