import time
import logging
import threading
from queue import Queue, Full, Empty
from typing import Dict, Any, Optional, List, Callable
from collections import deque
from datetime import datetime

from backend.ai.config import get_ai_config
from backend.ai.schemas import AlertContext, FlowStatistics, AlertAnalysis
from backend.ai.alert_analyzer import get_alert_analyzer

log = logging.getLogger(__name__)

class AIAnalysisState:
    PENDING = "PENDING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    DISABLED = "DISABLED"

class AIAnalysisManager:
    """
    Manages the async queue for AI analysis of IDS alerts.
    """
    def __init__(self):
        self._config = get_ai_config()
        self._queue = Queue(maxsize=self._config.ai_queue_max_size)
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
        # In-memory storage for AI results and states
        # Key: alert_id, Value: dict with state, analysis, timestamp
        self._alert_states: Dict[str, Dict[str, Any]] = {}
        # Key: dedup signature, Value: timestamp
        self._recent_alerts: Dict[str, float] = {}
        self._signature_analyses: Dict[str, Dict[str, Any]] = {}
        self._recent_alerts_lock = threading.Lock()
        
        # Socket.IO callback
        self._emit_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None

        # Bounded state cleanup
        self._max_stored_results = 1000

    def set_emit_callback(self, callback: Callable[[str, Dict[str, Any]], None]):
        """Register a callback for Socket.IO events."""
        self._emit_callback = callback

    def _emit(self, event_name: str, payload: Dict[str, Any]):
        if self._emit_callback:
            try:
                self._emit_callback(event_name, payload)
            except Exception as e:
                log.error(f"Failed to emit {event_name}: {e}")

    def normalize_alert(self, raw_alert: Dict[str, Any]) -> AlertContext:
        """Convert a raw IDS alert into an AlertContext."""
        # Convert timestamp to ISO-8601 if needed
        ts = raw_alert.get("timestamp", time.time())
        if isinstance(ts, float) or isinstance(ts, int):
            ts_iso = datetime.fromtimestamp(ts).isoformat()
        else:
            ts_iso = str(ts)
            
        evidence = []
        detector = str(raw_alert.get("detector", "unknown"))
        if detector == "xgboost":
            evidence.append(f"Model prediction confidence: {raw_alert.get('confidence_pct', 0.0)}%")
            evidence.append(f"Flow packets: {raw_alert.get('flow_packets', 0)}")
        elif detector == "heuristic-scan":
            evidence.append(f"Distinct ports probed: {raw_alert.get('distinct_ports', 0)}")
            evidence.append(f"Distinct hosts probed: {raw_alert.get('distinct_hosts', 0)}")
            scan_type = raw_alert.get("scan_type")
            if scan_type:
                evidence.append(f"Scan type: {scan_type}")

        flow_stats = None
        # Basic flow stats mapping
        if "distinct_ports" in raw_alert or "flow_packets" in raw_alert:
            flow_stats = FlowStatistics(
                packet_count=raw_alert.get("flow_packets"),
                distinct_ports=raw_alert.get("distinct_ports"),
                distinct_hosts=raw_alert.get("distinct_hosts"),
                scan_type=raw_alert.get("scan_type"),
            )
            
        return AlertContext(
            alert_id=str(raw_alert.get("id", f"alert-{time.time()}")),
            timestamp=ts_iso,
            source_ip=str(raw_alert.get("src_ip", "0.0.0.0")),
            destination_ip=str(raw_alert.get("dst_ip", "0.0.0.0")),
            source_port=int(raw_alert.get("src_port", 0)),
            destination_port=int(raw_alert.get("dst_port", 0)),
            protocol=str(raw_alert.get("protocol", "TCP")),
            attack_type=str(raw_alert.get("attack_type", "UNKNOWN")),
            detector=detector,
            confidence=float(raw_alert.get("confidence", 0.0)),
            evidence=evidence,
            flow_statistics=flow_stats
        )

    def is_duplicate(self, alert_ctx: AlertContext) -> bool:
        """Check if a similar alert was analyzed recently."""
        sig = f"{alert_ctx.source_ip}:{alert_ctx.destination_ip}:{alert_ctx.attack_type}"
        now = time.time()
        
        with self._recent_alerts_lock:
            # Cleanup old entries
            window = self._config.ai_duplicate_window
            stale = [k for k, v in self._recent_alerts.items() if now - v > window]
            for k in stale:
                del self._recent_alerts[k]
                self._signature_analyses.pop(k, None)
                
            if sig in self._recent_alerts:
                return True
            self._recent_alerts[sig] = now
            return False

    def get_analysis_state(self, alert_id: str) -> Optional[Dict[str, Any]]:
        return self._alert_states.get(alert_id)
        
    def get_related_alerts(self, current_alert_id: str, alert_ctx: AlertContext, limit: int = 5) -> List[Dict[str, Any]]:
        """Retrieve related alerts for context."""
        related = []
        for aid, state in self._alert_states.items():
            if aid == current_alert_id:
                continue
            ctx = state.get("alert")
            if not ctx:
                continue
            if ctx.source_ip == alert_ctx.source_ip or ctx.destination_ip == alert_ctx.destination_ip:
                related.append(state)
            if len(related) >= limit:
                break
        return related

    def enqueue(self, raw_alert: Dict[str, Any], force: bool = False):
        """Enqueue a raw alert for AI analysis if conditions are met."""
        if not self._config.ai_enabled:
            alert_id = str(raw_alert.get("id"))
            if alert_id:
                self._alert_states[alert_id] = {
                    "alert_id": alert_id,
                    "state": AIAnalysisState.DISABLED,
                    "timestamp": time.time(),
                }
            return

        if not force and not self._config.ai_auto_analyze_alerts:
            # Automatic background analysis is disabled; requires explicit user trigger
            return

        if not raw_alert.get("is_attack"):
            return

        try:
            alert_ctx = self.normalize_alert(raw_alert)
        except Exception as e:
            log.error(f"Failed to normalize alert for AI queue: {e}")
            return

        sig = f"{alert_ctx.source_ip}:{alert_ctx.destination_ip}:{alert_ctx.attack_type}"
        is_dup = self.is_duplicate(alert_ctx) and not force and not raw_alert.get("force_ai", False)
        if is_dup:
            log.debug(f"Skipping duplicate alert analysis for {alert_ctx.alert_id}")
            with self._recent_alerts_lock:
                cached_analysis = self._signature_analyses.get(sig)
            if cached_analysis:
                self._alert_states[alert_ctx.alert_id] = {
                    "alert_id": alert_ctx.alert_id,
                    "state": AIAnalysisState.COMPLETED,
                    "timestamp": time.time(),
                    "analysis": cached_analysis,
                    "alert": alert_ctx,
                    "raw_alert": raw_alert,
                }
                self._emit("ai_analysis_completed", {
                    "alert_id": alert_ctx.alert_id,
                    "state": AIAnalysisState.COMPLETED,
                    "analysis": cached_analysis,
                    "timestamp": time.time(),
                })
            return

        self._alert_states[alert_ctx.alert_id] = {
            "alert_id": alert_ctx.alert_id,
            "state": AIAnalysisState.PENDING,
            "timestamp": time.time(),
            "alert": alert_ctx,
            "raw_alert": raw_alert
        }
        
        try:
            self._queue.put_nowait(alert_ctx)
            # Emit started event slightly earlier here or in the worker when it pops?
            # Standard is when popped, but the frontend needs to know it's PENDING.
            # We'll emit 'ai_analysis_started' when it's popped to 'ANALYZING'.
        except Full:
            log.warning(f"AI analysis queue is full. Dropping alert {alert_ctx.alert_id}")
            self._alert_states[alert_ctx.alert_id]["state"] = AIAnalysisState.FAILED
            self._alert_states[alert_ctx.alert_id]["error"] = "Queue full"
            self._emit("ai_analysis_failed", {
                "alert_id": alert_ctx.alert_id,
                "state": AIAnalysisState.FAILED,
                "timestamp": time.time(),
                "error": "Queue full"
            })

    def start(self):
        if not self._worker_thread or not self._worker_thread.is_alive():
            self._stop_event.clear()
            self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="AIAnalysisWorker")
            self._worker_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)

    def _worker_loop(self):
        analyzer = get_alert_analyzer()
        while not self._stop_event.is_set():
            try:
                alert_ctx: AlertContext = self._queue.get(timeout=1.0)
            except Empty:
                continue

            alert_id = alert_ctx.alert_id
            
            # Update state to ANALYZING
            if alert_id in self._alert_states:
                self._alert_states[alert_id]["state"] = AIAnalysisState.ANALYZING
                self._alert_states[alert_id]["timestamp"] = time.time()
                
            self._emit("ai_analysis_started", {
                "alert_id": alert_id,
                "state": AIAnalysisState.ANALYZING,
                "timestamp": time.time()
            })
            
            try:
                analysis = analyzer.analyze(alert_ctx)
                analysis_dict = analysis.model_dump()
                if alert_id in self._alert_states:
                    self._alert_states[alert_id]["state"] = AIAnalysisState.COMPLETED
                    self._alert_states[alert_id]["analysis"] = analysis_dict
                    self._alert_states[alert_id]["timestamp"] = time.time()

                sig = f"{alert_ctx.source_ip}:{alert_ctx.destination_ip}:{alert_ctx.attack_type}"
                with self._recent_alerts_lock:
                    self._signature_analyses[sig] = analysis_dict

                self._emit("ai_analysis_completed", {
                    "alert_id": alert_id,
                    "state": AIAnalysisState.COMPLETED,
                    "analysis": analysis_dict,
                    "timestamp": time.time()
                })
            except Exception as e:
                log.error(f"AI analysis failed for {alert_id}: {e}")
                if alert_id in self._alert_states:
                    self._alert_states[alert_id]["state"] = AIAnalysisState.FAILED
                    self._alert_states[alert_id]["timestamp"] = time.time()
                    self._alert_states[alert_id]["error"] = str(e)
                    
                self._emit("ai_analysis_failed", {
                    "alert_id": alert_id,
                    "state": AIAnalysisState.FAILED,
                    "error": str(e),
                    "timestamp": time.time()
                })
                
            finally:
                self._queue.task_done()
                self._cleanup_states()

    def _cleanup_states(self):
        """Keep bounded state storage."""
        if len(self._alert_states) > self._max_stored_results:
            # Sort by timestamp and remove oldest
            sorted_keys = sorted(self._alert_states.keys(), key=lambda k: self._alert_states[k]["timestamp"])
            to_remove = sorted_keys[:-self._max_stored_results]
            for k in to_remove:
                del self._alert_states[k]

_manager: Optional[AIAnalysisManager] = None

def get_ai_manager() -> AIAnalysisManager:
    global _manager
    if _manager is None:
        _manager = AIAnalysisManager()
    return _manager
