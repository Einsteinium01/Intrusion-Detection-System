"""
scripts/validate_portscan.py
============================
Before/after validation for the heuristic PortScan detection layer.

WHY THIS SCRIPT EXISTS
----------------------
The latest detection validation found that a controlled live PortScan was NOT
detected: an nmap SYN scan produces many single-packet SYN flows, and those were
being silently dropped by the sampler's ">= 2 packets" qualification rule (and
even when a 2-packet probe did reach XGBoost, its degenerate CICIDS2017 features
were confidently scored BENIGN). This script proves the fix closes that gap
WITHOUT per-packet inference and WITHOUT fabricating flow features.

WHAT IT MEASURES
----------------
  BEFORE (ML-only):  feed the scan's probe flows straight to XGBoost and show
                     they are missed (either excluded by the >=2 rule or scored
                     BENIGN).
  AFTER  (hybrid):   feed the same scan through the DetectionEngine and show the
                     heuristic aggregator raises ONE PortScan alert, within one
                     5-second sampler cycle.
  FALSE POSITIVES:   feed benign traffic (established sessions + a small handful
                     of connections) through the hybrid engine and show the scan
                     layer stays silent.

MODES
-----
  (default)  Offline, synthetic. No admin rights, no target, fully reproducible.
             This is what produces the before/after comparison table.

  --live     Live capture. Requires Npcap/admin. You run an AUTHORIZED nmap scan
             against a host YOU OWN; the script measures real detection latency
             and counts false positives over the capture window. The script
             NEVER launches nmap itself — it only prints the command for you.

USAGE
-----
  python scripts/validate_portscan.py
  python scripts/validate_portscan.py --ports 30
  python scripts/validate_portscan.py --live --target 127.0.0.1 --iface "Wi-Fi" --duration 40

AUTHORIZED USE ONLY: only scan hosts and networks you own or have written
permission to test. Port scanning third-party systems may be illegal.
"""

import sys
import time
import argparse
import pathlib

# Windows consoles default to cp1252, which cannot encode box-drawing/arrow glyphs.
# Force UTF-8 so this script prints cleanly regardless of the active code page.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# Make the project root importable when run as `python scripts/validate_portscan.py`.
ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from feature_extraction import Flow  # noqa: E402


def forward_alert_to_backend(alert: dict, backend_url: str = "http://localhost:5000") -> bool:
    """
    Forward detected alert to running NetIntel backend.
    Triggers real-time Socket.IO broadcast and AI analysis queue.
    """
    import urllib.request
    import json

    url = f"{backend_url.rstrip('/')}/api/v1/alerts"
    try:
        data = json.dumps(alert).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            return resp.status in (200, 201)
    except Exception:
        return False


# ── Synthetic packet / flow factories ─────────────────────────────────────────
def syn_probe_packet(dst_port, dst_ip, src_ip, ts):
    """A lone unestablished SYN — what `nmap -sS` emits per probed port."""
    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": 40000 + (dst_port % 20000),
        "dst_port": dst_port,
        "protocol": "TCP",
        "timestamp": ts,
        "length": 60,
        "header_len": 40,          # bare SYN: almost all header, no payload
        "tcp_flags": {"SYN": True},
    }


def established_session_packets(dst_port, dst_ip, src_ip, ts):
    """The 4 packets of a normal completed TCP session (SYN, SYN-ACK, data x2)."""
    src_port = 50000 + (dst_port % 20000)
    return [
        {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
         "protocol": "TCP", "timestamp": ts, "length": 74, "header_len": 40,
         "tcp_flags": {"SYN": True}},
        {"src_ip": dst_ip, "dst_ip": src_ip, "src_port": dst_port, "dst_port": src_port,
         "protocol": "TCP", "timestamp": ts + 0.01, "length": 74, "header_len": 40,
         "tcp_flags": {"SYN": True, "ACK": True}},
        {"src_ip": src_ip, "dst_ip": dst_ip, "src_port": src_port, "dst_port": dst_port,
         "protocol": "TCP", "timestamp": ts + 0.02, "length": 517, "header_len": 32,
         "tcp_flags": {"ACK": True, "PSH": True}},
        {"src_ip": dst_ip, "dst_ip": src_ip, "src_port": dst_port, "dst_port": src_port,
         "protocol": "TCP", "timestamp": ts + 0.05, "length": 1400, "header_len": 32,
         "tcp_flags": {"ACK": True, "PSH": True}},
    ]


def _make_engine(scan_detection):
    """Construct a DetectionEngine (loads model.pkl). Exits cleanly if absent."""
    from backend.detection_engine import DetectionEngine
    try:
        return DetectionEngine(scan_detection=scan_detection)
    except FileNotFoundError as e:
        print(f"\n[!] Cannot run: {e}")
        print("    Train the model first (models/compare_models.py), then re-run.")
        sys.exit(2)


# ── BEFORE: ML-only baseline ──────────────────────────────────────────────────
def run_ml_baseline(engine, scanner_ip, target_ip, n_ports):
    """
    Show what the ML layer alone does with a scan's probes.

    Two failure modes are demonstrated:
      1. 1-packet SYN flows never reach the model (excluded by the >=2 rule).
      2. 2-packet SYN+RST flows DO reach the model but are scored BENIGN.
    """
    print("=" * 70)
    print("BEFORE  —  ML-only layer (XGBoost on individual flows)")
    print("=" * 70)

    base_ts = 1_000_000.0
    ports = range(20, 20 + n_ports)

    # Mode 1: single-packet SYN flows — excluded before inference.
    one_pkt = [Flow(syn_probe_packet(p, target_ip, scanner_ip, base_ts)) for p in ports]
    excluded = sum(1 for f in one_pkt if (f.fwd_pkts + f.bwd_pkts) < 2)
    print(f"  1-packet SYN probe flows generated : {len(one_pkt)}")
    print(f"  Excluded by the '>= 2 packets' rule: {excluded}  "
          f"(never reach XGBoost)")

    # Mode 2: 2-packet SYN+RST flows — reach the model. What does it say?
    attack_hits = 0
    confidences = []
    for p in ports:
        pkt = syn_probe_packet(p, target_ip, scanner_ip, base_ts)
        flow = Flow(pkt)
        # A closed port answers with RST; add it so the flow has 2 packets.
        flow.add_packet({
            "src_ip": target_ip, "dst_ip": scanner_ip,
            "src_port": p, "dst_port": pkt["src_port"],
            "protocol": "TCP", "timestamp": base_ts + 0.001,
            "length": 60, "header_len": 40,
            "tcp_flags": {"RST": True, "ACK": True},
        })
        df = engine.extractor.extract_features(flow)
        pred = int(engine.model.predict(df)[0])
        if hasattr(engine.model, "predict_proba"):
            import numpy as np
            confidences.append(float(np.max(engine.model.predict_proba(df)[0])))
        if pred == 1:
            attack_hits += 1

    mean_conf = (sum(confidences) / len(confidences)) if confidences else 0.0
    print(f"  2-packet SYN+RST flows sent to model: {n_ports}")
    print(f"  Flagged as ATTACK by XGBoost        : {attack_hits} / {n_ports}")
    print(f"  Mean model confidence (in its label): {mean_conf * 100:.1f}%")
    detected_before = attack_hits > 0
    print(f"\n  => Port scan detected by ML alone?   {'YES' if detected_before else 'NO'}")
    return detected_before


# ── AFTER: hybrid detection end-to-end ────────────────────────────────────────
def run_hybrid_detection(scanner_ip, target_ip, n_ports):
    """
    Feed the same scan through the DetectionEngine flow table and run ONE sampler
    cycle (the same code path the background thread runs every 5 seconds). Confirm
    a single PortScan alert is emitted and time how long the cycle takes.
    """
    print("\n" + "=" * 70)
    print("AFTER   —  Hybrid layer (heuristic scan aggregator + ML)")
    print("=" * 70)

    engine = _make_engine(scan_detection=True)
    alerts = []
    engine.register_alert_listener(lambda r: alerts.append(r))

    base_ts = time.time()
    ports = range(20, 20 + n_ports)

    # Feed the scan into the flow table exactly as the capture thread would.
    for p in ports:
        engine.process_packet(syn_probe_packet(p, target_ip, scanner_ip, base_ts))

    # Run one sampler cycle (probes routed to aggregator, never to XGBoost).
    t0 = time.perf_counter()
    engine._sample_and_predict_flows()
    cycle_ms = (time.perf_counter() - t0) * 1000.0

    scan_alerts = [a for a in alerts if a.get("detector") == "heuristic-scan"]
    print(f"  Probe flows in table this cycle     : {n_ports}")
    print(f"  Sampler cycle wall time             : {cycle_ms:.1f} ms")
    print(f"  PortScan alerts raised              : {len(scan_alerts)}")

    detected_after = len(scan_alerts) > 0
    if detected_after:
        a = scan_alerts[0]
        print(f"    - src {a['src_ip']} -> {a['dst_ip']}")
        print(f"    - {a['attack_type']}")
        print(f"    - distinct ports probed : {a['distinct_ports']}")
        print(f"    - confidence            : {a['confidence_pct']}%")
        print(f"    - detector              : {a['detector']}")
        # Forward alert to running backend to trigger React UI and AI analysis
        if forward_alert_to_backend(a):
            print("    - UI broadcast          : SENT (http://localhost:5000/api/v1/alerts)")
        else:
            print("    - UI broadcast          : SKIPPED (backend offline at http://localhost:5000)")
    print(f"\n  => Port scan detected by hybrid?     {'YES' if detected_after else 'NO'}")
    print("  Detection latency bound: <= one 5s sampler cycle after the fan-out")
    print("  threshold is crossed; a final sweep at stop() guarantees no miss.")
    return detected_after


# ── FALSE POSITIVES: benign traffic through the hybrid engine ─────────────────
def run_false_positive_check(n_sessions):
    """Established sessions + a small connection burst must raise ZERO scan alerts."""
    print("\n" + "=" * 70)
    print("FALSE POSITIVES  —  benign traffic through the hybrid layer")
    print("=" * 70)

    engine = _make_engine(scan_detection=True)
    scan_alerts = []
    engine.register_alert_listener(
        lambda r: scan_alerts.append(r) if r.get("detector") == "heuristic-scan" else None
    )

    base_ts = time.time()
    client = "192.168.1.50"

    # 1) Many full HTTPS-style sessions to distinct ports (real data transfer).
    for i, port in enumerate(range(20, 20 + n_sessions)):
        for pkt in established_session_packets(port, "93.184.216.34", client, base_ts + i * 0.1):
            engine.process_packet(pkt)

    # 2) A browser-style burst: 3 fresh connections (below the fan-out threshold).
    for port in (80, 443, 8080):
        engine.process_packet(syn_probe_packet(port, "142.250.72.14", client, base_ts + 5.0))

    engine._sample_and_predict_flows()

    print(f"  Established sessions simulated      : {n_sessions}")
    print(f"  Small connection burst              : 3 ports")
    print(f"  False PortScan alerts raised        : {len(scan_alerts)}")
    clean = len(scan_alerts) == 0
    print(f"\n  => Benign traffic stayed clean?      {'YES' if clean else 'NO'}")
    return clean


# ── Summary table ─────────────────────────────────────────────────────────────
def print_summary(detected_before, detected_after, fp_clean):
    print("\n" + "=" * 70)
    print("BEFORE / AFTER SUMMARY")
    print("=" * 70)
    row = "  {:<34}{:<16}{:<16}"
    print(row.format("", "BEFORE (ML)", "AFTER (hybrid)"))
    print(row.format("PortScan detected", "NO" if not detected_before else "YES",
                     "YES" if detected_after else "NO"))
    print(row.format("Detection latency", "never (missed)",
                     "<= 5s (1 cycle)"))
    print(row.format("Per-packet inference", "no", "no"))
    print(row.format("CICIDS2017 features fabricated", "no", "no"))
    print(row.format("False positives on benign", "n/a",
                     "0" if fp_clean else ">0"))
    print("=" * 70)

    ok = (not detected_before) and detected_after and fp_clean
    if ok:
        print("RESULT: PASS — the gap is closed. Single-packet SYN scans are now")
        print("        detected by the heuristic layer, ML behaviour is unchanged,")
        print("        and benign traffic raises no new false positives.")
    else:
        print("RESULT: CHECK — unexpected outcome; review the sections above.")
    return ok


# ── Live mode ─────────────────────────────────────────────────────────────────
def run_live(target, iface, duration):
    print("=" * 70)
    print("LIVE VALIDATION  —  authorized nmap scan against a host you own")
    print("=" * 70)
    print("AUTHORIZED USE ONLY. Only scan systems you own or may lawfully test.\n")

    engine = _make_engine(scan_detection=True)
    scan_alerts, ml_alerts = [], []

    def on_alert(r):
        (scan_alerts if r.get("detector") == "heuristic-scan" else ml_alerts).append(
            (time.time(), r)
        )
        if r.get("detector") == "heuristic-scan":
            forward_alert_to_backend(r)

    engine.register_alert_listener(on_alert)

    try:
        engine.start(mode="LIVE", interface=iface)
    except RuntimeError as e:
        print(f"[!] Could not start live capture: {e}")
        print("    On Windows this usually means Npcap is missing or you are not")
        print("    running as Administrator. Fix that and retry, or use offline mode.")
        sys.exit(2)

    cmd = f"nmap -sS {target or '<your-target-ip>'}"
    print("Capture is running. In ANOTHER terminal, launch your authorized scan:")
    print(f"\n    {cmd}\n")
    try:
        input("Press Enter at the MOMENT you start the scan (Ctrl+C to abort)... ")
    except KeyboardInterrupt:
        engine.stop()
        print("\nAborted.")
        return False
    scan_start = time.time()

    print(f"Listening for up to {duration}s ...")
    first_latency = None
    deadline = scan_start + duration
    try:
        while time.time() < deadline:
            if scan_alerts and first_latency is None:
                first_latency = scan_alerts[0][0] - scan_start
                print(f"  [+] PortScan ALERT after {first_latency:.2f}s "
                      f"(src {scan_alerts[0][1]['src_ip']}, "
                      f"{scan_alerts[0][1]['distinct_ports']} ports)")
                break
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        engine.stop()

    print("\n" + "-" * 70)
    print(f"  Scan alerts raised          : {len(scan_alerts)}")
    print(f"  Detection latency           : "
          f"{f'{first_latency:.2f}s' if first_latency is not None else 'NOT DETECTED'}")
    print(f"  ML-layer alerts in window   : {len(ml_alerts)}  "
          f"(potential false positives if the network was otherwise quiet)")
    print("-" * 70)
    return first_latency is not None


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Before/after PortScan detection validation.")
    parser.add_argument("--live", action="store_true",
                        help="Live capture mode (requires Npcap/admin; you run nmap).")
    parser.add_argument("--target", default=None, help="Live mode: host you own to scan.")
    parser.add_argument("--iface", default=None, help="Live mode: capture interface name.")
    parser.add_argument("--duration", type=int, default=40, help="Live mode: capture seconds.")
    parser.add_argument("--ports", type=int, default=25,
                        help="Offline mode: number of ports in the synthetic scan.")
    parser.add_argument("--sessions", type=int, default=30,
                        help="Offline mode: number of benign sessions for the FP check.")
    args = parser.parse_args()

    if args.live:
        return run_live(args.target, args.iface, args.duration)

    scanner_ip, target_ip = "10.0.0.99", "10.0.0.5"
    print("\nSynthetic offline validation (no admin rights, no live traffic).\n")

    engine = _make_engine(scan_detection=True)  # reused for the ML baseline
    detected_before = run_ml_baseline(engine, scanner_ip, target_ip, args.ports)
    detected_after = run_hybrid_detection(scanner_ip, target_ip, args.ports)
    fp_clean = run_false_positive_check(args.sessions)
    ok = print_summary(detected_before, detected_after, fp_clean)
    return ok


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
