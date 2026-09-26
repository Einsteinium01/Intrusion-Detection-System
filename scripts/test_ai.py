#!/usr/bin/env python3
"""
scripts/test_ai.py
==================
Manual integration smoke-test for the Phase 1 AI layer.

This script sends a synthetic PortScan AlertContext to the running
backend and prints the AlertAnalysis response.

USAGE
-----
1. Ensure the backend is running:
       python backend/app.py

2. Set your Groq key and enable AI in .env (or environment):
       AI_ENABLED=true
       GROQ_API_KEY=gsk_...

3. Run this script:
       python scripts/test_ai.py

   Optional flags:
       --url   Backend base URL (default: http://localhost:5000)
       --json  Pretty-print the full JSON response only (no formatting)

EXIT CODES
----------
0  Success – AlertAnalysis received and validated
1  HTTP error or non-200 status
2  Response is not valid AlertAnalysis JSON
3  Connection error (backend not running)
"""

from __future__ import annotations

import argparse
import json
import sys
import textwrap
from datetime import datetime, timezone
from typing import Any, Dict

try:
    import urllib.request
    import urllib.error
except ImportError:
    print("[FATAL] urllib is not available. This is a standard library module.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Synthetic alert payload (PortScan)
# ---------------------------------------------------------------------------

SYNTHETIC_PORTSCAN_ALERT: Dict[str, Any] = {
    "alert_id": f"manual-test-{int(datetime.now(timezone.utc).timestamp())}",
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "source_ip": "192.168.100.99",
    "destination_ip": "10.0.0.1",
    "source_port": 54321,
    "destination_port": 0,          # vertical scan — no single target port
    "protocol": "TCP",
    "attack_type": "PortScan",
    "detector": "ScanDetector",
    "confidence": 0.92,
    "evidence": [
        "22 SYN-only probes observed from source IP within 2.1 seconds",
        "Distinct destination ports: 22, 23, 25, 53, 80, 110, 135, 139, 143, "
        "443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 27017, 27018",
        "No SYN-ACK responses from destination",
        "All probes: SYN flag only, no payload",
        "probe_count=22 distinct_ports=22 scan_type=vertical",
    ],
    "flow_statistics": {
        "packet_count": 22,
        "byte_count": 1320,
        "duration_seconds": 2.1,
        "packets_per_second": 10.48,
        "mean_packet_size": 60.0,
        "distinct_ports": 22,
        "distinct_hosts": 1,
        "syn_count": 22,
        "scan_type": "vertical",
    },
}


# ---------------------------------------------------------------------------
# HTTP helper (stdlib only — no requests dependency)
# ---------------------------------------------------------------------------

def post_json(url: str, payload: Dict[str, Any], timeout: int = 90) -> Dict[str, Any]:
    """POST JSON to *url* and return the parsed response body."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return {"status": resp.status, "body": json.loads(raw)}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            body_json = json.loads(raw)
        except json.JSONDecodeError:
            body_json = {"raw": raw[:500]}
        return {"status": exc.code, "body": body_json}
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"Cannot connect to backend at {url}: {exc.reason}"
        ) from exc


def get_json(url: str, timeout: int = 15) -> Dict[str, Any]:
    """GET *url* and return the parsed JSON body."""
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
            return {"status": resp.status, "body": json.loads(raw)}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        return {"status": exc.code, "body": {"raw": raw[:200]}}
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"Cannot connect to backend at {url}: {exc.reason}"
        ) from exc


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
RED = "\033[31m"
CYAN = "\033[36m"
RESET = "\033[0m"


def print_section(title: str, content: str, color: str = CYAN) -> None:
    print(f"\n{color}{BOLD}── {title} {'─' * (60 - len(title))}{RESET}")
    print(textwrap.indent(content, "  "))


def severity_color(severity: str) -> str:
    return {
        "LOW": GREEN,
        "MEDIUM": YELLOW,
        "HIGH": "\033[91m",
        "CRITICAL": RED,
    }.get(severity.upper(), RESET)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manual AI layer smoke-test – sends a synthetic PortScan alert."
    )
    parser.add_argument(
        "--url",
        default="http://localhost:5000",
        help="Backend base URL (default: http://localhost:5000)",
    )
    parser.add_argument(
        "--json",
        dest="raw_json",
        action="store_true",
        help="Print the raw JSON response only (no formatting).",
    )
    args = parser.parse_args()

    base = args.url.rstrip("/")
    analyze_url = f"{base}/api/ai/analyze-alert"
    status_url = f"{base}/api/ai/status"

    print(f"{BOLD}=== AI Layer Manual Smoke-Test ==={RESET}")
    print(f"Backend: {base}")

    # ── 1. Check AI status ──────────────────────────────────────────────────
    print(f"\n{CYAN}[1/2]{RESET} Checking AI status …")
    try:
        status_resp = get_json(status_url)
    except ConnectionError as exc:
        print(f"\n{RED}[ERROR]{RESET} {exc}")
        print("Make sure the backend is running: python backend/app.py")
        return 3

    status_body = status_resp["body"]
    print(f"      AI enabled : {status_body.get('ai_enabled')}")
    print(f"      Provider   : {status_body.get('llm_provider')}")
    print(f"      Model      : {status_body.get('groq_model')}")
    print(f"      Healthy    : {status_body.get('provider_healthy')}")
    if status_body.get("last_error"):
        print(f"      Last error : {status_body['last_error']}")

    # ── 2. Send synthetic alert ─────────────────────────────────────────────
    print(f"\n{CYAN}[2/2]{RESET} Sending synthetic PortScan alert …")
    print(f"      Alert ID : {SYNTHETIC_PORTSCAN_ALERT['alert_id']}")
    print(f"      Source   : {SYNTHETIC_PORTSCAN_ALERT['source_ip']}")
    print(f"      Detector : {SYNTHETIC_PORTSCAN_ALERT['detector']}")
    print(f"      Evidence : {len(SYNTHETIC_PORTSCAN_ALERT['evidence'])} items")

    try:
        resp = post_json(analyze_url, SYNTHETIC_PORTSCAN_ALERT, timeout=90)
    except ConnectionError as exc:
        print(f"\n{RED}[ERROR]{RESET} {exc}")
        return 3

    http_status = resp["status"]
    body = resp["body"]

    if args.raw_json:
        print(json.dumps(body, indent=2))
        return 0 if http_status == 200 else 1

    if http_status != 200:
        print(f"\n{RED}[FAILED]{RESET} HTTP {http_status}")
        print(json.dumps(body, indent=2))
        return 1

    # ── Display AlertAnalysis ───────────────────────────────────────────────
    sev = body.get("severity", "UNKNOWN")
    sev_col = severity_color(sev)

    print(f"\n{GREEN}[SUCCESS]{RESET} HTTP 200 – AlertAnalysis received\n")
    print(f"  {'Severity':<22} {sev_col}{BOLD}{sev}{RESET}")
    print(f"  {'Attack type':<22} {body.get('attack_type', '-')}")

    print_section("Summary", body.get("summary", "-"))
    print_section("Technical Analysis", body.get("technical_analysis", "-"))

    evidence = body.get("evidence", [])
    print_section("Evidence", "\n".join(f"• {e}" for e in evidence) or "(none)")

    mitre = body.get("mitre_attack", [])
    if mitre:
        mitre_lines = "\n".join(
            f"• {t['technique_id']} – {t['technique_name']}\n"
            f"  {t['rationale']}"
            for t in mitre
        )
        print_section("MITRE ATT&CK", mitre_lines)

    steps = body.get("investigation_steps", [])
    print_section(
        "Investigation Steps",
        "\n".join(f"{i + 1}. {s}" for i, s in enumerate(steps)) or "(none)",
    )

    actions = body.get("recommended_actions", [])
    print_section(
        "Recommended Actions",
        "\n".join(f"{i + 1}. {a}" for i, a in enumerate(actions)) or "(none)",
    )

    sources = body.get("sources", [])
    if sources:
        src_lines = "\n".join(
            f"• [{s['source_id']}] {s['title']} – {s['relevance']}"
            for s in sources
        )
        print_section("Sources", src_lines)

    print(f"\n{GREEN}Smoke-test complete.{RESET}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
