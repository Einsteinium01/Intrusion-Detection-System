import pytest
import time
from unittest.mock import Mock, patch

from backend.ai.queue import AIAnalysisManager, AIAnalysisState
from backend.ai.schemas import AlertContext
from backend.ai.config import AIConfig

@pytest.fixture
def mock_config():
    return AIConfig(
        ai_enabled=True,
        ai_auto_analyze_alerts=True,
        ai_queue_max_size=2,
        ai_duplicate_window=1.0
    )

@pytest.fixture
def ai_manager(mock_config):
    with patch("backend.ai.queue.get_ai_config", return_value=mock_config):
        manager = AIAnalysisManager()
        yield manager
        manager.stop()

def test_alert_normalization_xgboost(ai_manager):
    raw_alert = {
        "id": "alert-123",
        "timestamp": 1690000000.0,
        "src_ip": "1.2.3.4",
        "dst_ip": "5.6.7.8",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "attack_type": "SynFlood",
        "detector": "xgboost",
        "confidence": 0.95,
        "confidence_pct": 95.0,
        "flow_packets": 100
    }
    
    ctx = ai_manager.normalize_alert(raw_alert)
    assert ctx.alert_id == "alert-123"
    assert ctx.source_ip == "1.2.3.4"
    assert ctx.detector == "xgboost"
    assert ctx.confidence == 0.95
    assert len(ctx.evidence) == 2
    assert "Model prediction confidence" in ctx.evidence[0]
    assert ctx.flow_statistics.packet_count == 100

def test_alert_normalization_scandetector(ai_manager):
    raw_alert = {
        "id": "alert-456",
        "timestamp": 1690000000.0,
        "src_ip": "1.2.3.4",
        "dst_ip": "0.0.0.0",
        "protocol": "TCP",
        "attack_type": "PortScan",
        "detector": "heuristic-scan",
        "distinct_ports": 50,
        "scan_type": "SYN Scan"
    }
    
    ctx = ai_manager.normalize_alert(raw_alert)
    assert ctx.alert_id == "alert-456"
    assert ctx.detector == "heuristic-scan"
    assert len(ctx.evidence) == 3
    assert ctx.flow_statistics.distinct_ports == 50
    assert ctx.flow_statistics.scan_type == "SYN Scan"

def test_duplicate_suppression(ai_manager):
    raw_alert = {
        "id": "alert-1",
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "attack_type": "DDoS",
        "is_attack": True
    }
    
    ctx = ai_manager.normalize_alert(raw_alert)
    
    assert ai_manager.is_duplicate(ctx) is False
    assert ai_manager.is_duplicate(ctx) is True
    
    # Wait for duplicate window (1.0s) to expire
    time.sleep(1.1)
    assert ai_manager.is_duplicate(ctx) is False

def test_queue_overflow(ai_manager):
    # Max size is 2
    raw1 = {"id": "a1", "src_ip": "1.1.1.1", "is_attack": True}
    raw2 = {"id": "a2", "src_ip": "1.1.1.2", "is_attack": True}
    raw3 = {"id": "a3", "src_ip": "1.1.1.3", "is_attack": True}
    
    ai_manager.enqueue(raw1)
    ai_manager.enqueue(raw2)
    ai_manager.enqueue(raw3) # This should fail due to Full
    
    state = ai_manager.get_analysis_state("a3")
    assert state is not None
    assert state["state"] == AIAnalysisState.FAILED
    assert state["error"] == "Queue full"

def test_ai_disabled_mode(ai_manager):
    ai_manager._config.ai_enabled = False
    
    raw = {"id": "a1", "src_ip": "1.1.1.1", "is_attack": True}
    ai_manager.enqueue(raw)
    
    state = ai_manager.get_analysis_state("a1")
    assert state is not None
    assert state["state"] == AIAnalysisState.DISABLED

def test_worker_loop_success(ai_manager):
    raw = {"id": "a1", "src_ip": "1.1.1.1", "is_attack": True, "attack_type": "PortScan"}
    
    mock_analyzer = Mock()
    mock_analysis = Mock()
    mock_analysis.model_dump.return_value = {"summary": "All good"}
    mock_analyzer.analyze.return_value = mock_analysis
    
    emit_events = []
    def emit_cb(evt, payload):
        emit_events.append((evt, payload))
        
    ai_manager.set_emit_callback(emit_cb)
    
    with patch("backend.ai.queue.get_alert_analyzer", return_value=mock_analyzer):
        ai_manager.start()
        ai_manager.enqueue(raw)
        
        # Wait for worker to process
        time.sleep(0.5)
        ai_manager.stop()
        
    state = ai_manager.get_analysis_state("a1")
    assert state["state"] == AIAnalysisState.COMPLETED
    assert state["analysis"]["summary"] == "All good"
    
    # Check socket events
    event_names = [e[0] for e in emit_events]
    assert "ai_analysis_started" in event_names
    assert "ai_analysis_completed" in event_names

def test_worker_loop_failure(ai_manager):
    raw = {"id": "a2", "src_ip": "1.1.1.1", "is_attack": True, "attack_type": "PortScan"}
    
    mock_analyzer = Mock()
    mock_analyzer.analyze.side_effect = Exception("Groq is down")
    
    emit_events = []
    def emit_cb(evt, payload):
        emit_events.append((evt, payload))
        
    ai_manager.set_emit_callback(emit_cb)
    
    with patch("backend.ai.queue.get_alert_analyzer", return_value=mock_analyzer):
        ai_manager.start()
        ai_manager.enqueue(raw)
        
        # Wait for worker to process
        time.sleep(0.5)
        ai_manager.stop()
        
    state = ai_manager.get_analysis_state("a2")
    assert state["state"] == AIAnalysisState.FAILED
    assert state["error"] == "Groq is down"
    
    # Check socket events
    event_names = [e[0] for e in emit_events]
    assert "ai_analysis_started" in event_names
    assert "ai_analysis_failed" in event_names


def test_duplicate_analysis_caching(ai_manager):
    ai_manager._config.ai_duplicate_window = 10.0
    raw1 = {"id": "alert-dup-1", "src_ip": "10.0.0.99", "dst_ip": "10.0.0.5", "is_attack": True, "attack_type": "PortScan"}
    raw2 = {"id": "alert-dup-2", "src_ip": "10.0.0.99", "dst_ip": "10.0.0.5", "is_attack": True, "attack_type": "PortScan"}

    mock_analyzer = Mock()
    mock_analysis = Mock()
    mock_analysis.model_dump.return_value = {"summary": "Cached PortScan analysis"}
    mock_analyzer.analyze.return_value = mock_analysis

    emit_events = []
    def emit_cb(evt, payload):
        emit_events.append((evt, payload))

    ai_manager.set_emit_callback(emit_cb)

    with patch("backend.ai.queue.get_alert_analyzer", return_value=mock_analyzer):
        ai_manager.start()
        ai_manager.enqueue(raw1)
        time.sleep(0.5)
        ai_manager.stop()

    # Alert 1 should be COMPLETED
    state1 = ai_manager.get_analysis_state("alert-dup-1")
    assert state1["state"] == AIAnalysisState.COMPLETED

    # Enqueue Alert 2 with identical signature within duplicate window
    ai_manager.enqueue(raw2)

    # Alert 2 should immediately be COMPLETED with cached analysis
    state2 = ai_manager.get_analysis_state("alert-dup-2")
    assert state2 is not None
    assert state2["state"] == AIAnalysisState.COMPLETED
    assert state2["analysis"]["summary"] == "Cached PortScan analysis"

    # Verify ai_analysis_completed was emitted for alert-dup-2
    dup_emits = [p for e, p in emit_events if e == "ai_analysis_completed" and p.get("alert_id") == "alert-dup-2"]
    assert len(dup_emits) == 1
    assert dup_emits[0]["analysis"]["summary"] == "Cached PortScan analysis"


def test_mock_provider_integration():
    from backend.ai.llm_service import MockProvider, get_llm_provider, reset_llm_provider
    from backend.ai.config import AIConfig

    reset_llm_provider()
    cfg = AIConfig(ai_enabled=True, llm_provider="mock")
    provider = get_llm_provider(cfg)
    assert isinstance(provider, MockProvider)
    assert provider.health_check() is True

    analysis = provider.analyze(
        system_prompt="You are a SOC analyst.",
        user_prompt='Analyze this alert: ```json\n{"attack_type": "PortScan", "source_ip": "10.0.0.99", "destination_ip": "10.0.0.5"}\n```'
    )
    assert "PortScan" in analysis.summary
    assert analysis.severity.value == "HIGH"
    assert len(analysis.mitre_attack) >= 1
    assert analysis.mitre_attack[0].technique_id == "T1046"

    reset_llm_provider()


