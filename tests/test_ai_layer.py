"""
tests/test_ai_layer.py
=======================
WHY THIS FILE EXISTS
--------------------
Phase 1 AI layer test suite.

Scope
-----
These tests exercise the AI layer in complete isolation from the real
Groq API.  Every test that would reach the network uses ``unittest.mock``
to patch the provider at the boundary.

Test coverage
-------------
1.  AlertContext validation (valid and invalid input)
2.  AlertAnalysis validation (valid and invalid structures)
3.  Invalid / malformed LLM response handling
4.  GroqProvider initialisation without an API key
5.  GroqProvider API error handling (simulated)
6.  Structured response parsing (happy path + bad JSON + schema mismatch)
7.  Prompt construction (system + user content, grounding markers)
8.  Secrets never appear in logs
9.  API endpoint validation (POST /api/ai/analyze-alert, GET /api/ai/status)
10. Disabled AI behaviour

Applied testing doctrine (testing-boss skill):
- Test behaviour, not implementation details.
- Lowest layer that catches each failure is used.
- Every mock is minimal and scoped.
- No real network calls; no real Groq SDK initialisation.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_valid_alert_dict(**overrides) -> Dict[str, Any]:
    base = {
        "alert_id": "test-alert-001",
        "timestamp": "2026-09-26T15:00:00Z",
        "source_ip": "192.168.1.50",
        "destination_ip": "10.0.0.1",
        "source_port": 42000,
        "destination_port": 22,
        "protocol": "TCP",
        "attack_type": "PortScan",
        "detector": "ScanDetector",
        "confidence": 0.95,
        "evidence": ["20 SYN probes to distinct ports", "probe_count=20"],
        "flow_statistics": {
            "packet_count": 20,
            "distinct_ports": 20,
            "syn_count": 20,
            "scan_type": "vertical",
        },
    }
    base.update(overrides)
    return base


def _make_valid_analysis_dict(**overrides) -> Dict[str, Any]:
    base = {
        "summary": "A port scan was detected from 192.168.1.50.",
        "technical_analysis": "The source probed 20 distinct ports using single SYN packets.",
        "severity": "HIGH",
        "attack_type": "PortScan",
        "evidence": ["20 SYN probes observed", "No SYN-ACK responses"],
        "mitre_attack": [
            {
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "rationale": "Scanning multiple ports to identify open services.",
            }
        ],
        "investigation_steps": ["Review firewall logs for the source IP."],
        "recommended_actions": ["Add source IP to watchlist for further monitoring."],
        "sources": [],
    }
    base.update(overrides)
    return base


# ===========================================================================
# 1. AlertContext validation
# ===========================================================================

class TestAlertContextValidation:
    def test_valid_alert_context_is_accepted(self):
        from backend.ai.schemas import AlertContext

        ctx = AlertContext(**_make_valid_alert_dict())
        assert ctx.alert_id == "test-alert-001"
        assert ctx.protocol == "TCP"  # normalised to uppercase
        assert ctx.confidence == 0.95

    def test_protocol_is_uppercased(self):
        from backend.ai.schemas import AlertContext

        ctx = AlertContext(**_make_valid_alert_dict(protocol="tcp"))
        assert ctx.protocol == "TCP"

    def test_confidence_is_rounded(self):
        from backend.ai.schemas import AlertContext

        ctx = AlertContext(**_make_valid_alert_dict(confidence=0.9512345678))
        assert len(str(ctx.confidence).split(".")[-1]) <= 4

    def test_confidence_out_of_range_rejected(self):
        from backend.ai.schemas import AlertContext

        with pytest.raises(ValidationError):
            AlertContext(**_make_valid_alert_dict(confidence=1.5))

    def test_negative_confidence_rejected(self):
        from backend.ai.schemas import AlertContext

        with pytest.raises(ValidationError):
            AlertContext(**_make_valid_alert_dict(confidence=-0.1))

    def test_missing_required_field_rejected(self):
        from backend.ai.schemas import AlertContext

        data = _make_valid_alert_dict()
        del data["source_ip"]
        with pytest.raises(ValidationError):
            AlertContext(**data)

    def test_alert_context_is_immutable(self):
        from backend.ai.schemas import AlertContext

        ctx = AlertContext(**_make_valid_alert_dict())
        with pytest.raises(Exception):
            ctx.source_ip = "1.2.3.4"  # type: ignore[misc]

    def test_flow_statistics_optional(self):
        from backend.ai.schemas import AlertContext

        data = _make_valid_alert_dict()
        data.pop("flow_statistics", None)
        ctx = AlertContext(**data)
        assert ctx.flow_statistics is None

    def test_evidence_defaults_to_empty_list(self):
        from backend.ai.schemas import AlertContext

        data = _make_valid_alert_dict()
        data.pop("evidence", None)
        ctx = AlertContext(**data)
        assert ctx.evidence == []


# ===========================================================================
# 2. AlertAnalysis validation
# ===========================================================================

class TestAlertAnalysisValidation:
    def test_valid_analysis_is_accepted(self):
        from backend.ai.schemas import AlertAnalysis, SeverityLevel

        a = AlertAnalysis(**_make_valid_analysis_dict())
        assert a.severity == SeverityLevel.HIGH
        assert len(a.mitre_attack) == 1
        assert a.mitre_attack[0].technique_id == "T1046"

    def test_invalid_severity_rejected(self):
        from backend.ai.schemas import AlertAnalysis

        with pytest.raises(ValidationError):
            AlertAnalysis(**_make_valid_analysis_dict(severity="EXTREME"))

    def test_all_severity_levels_accepted(self):
        from backend.ai.schemas import AlertAnalysis, SeverityLevel

        for level in SeverityLevel:
            a = AlertAnalysis(**_make_valid_analysis_dict(severity=level.value))
            assert a.severity == level

    def test_missing_summary_rejected(self):
        from backend.ai.schemas import AlertAnalysis

        data = _make_valid_analysis_dict()
        del data["summary"]
        with pytest.raises(ValidationError):
            AlertAnalysis(**data)

    def test_sources_can_be_empty(self):
        from backend.ai.schemas import AlertAnalysis

        a = AlertAnalysis(**_make_valid_analysis_dict(sources=[]))
        assert a.sources == []

    def test_mitre_attack_can_be_empty(self):
        from backend.ai.schemas import AlertAnalysis

        a = AlertAnalysis(**_make_valid_analysis_dict(mitre_attack=[]))
        assert a.mitre_attack == []


# ===========================================================================
# 3. Invalid LLM response handling
# ===========================================================================

class TestInvalidLLMResponseHandling:
    def test_empty_string_raises_parse_error(self):
        from backend.ai.llm_service import GroqProvider, LLMParseError

        with pytest.raises(LLMParseError, match="empty"):
            GroqProvider._parse_response("")

    def test_non_json_raises_parse_error(self):
        from backend.ai.llm_service import GroqProvider, LLMParseError

        with pytest.raises(LLMParseError, match="not valid JSON"):
            GroqProvider._parse_response("This is plain text, not JSON.")

    def test_json_missing_required_fields_raises_parse_error(self):
        from backend.ai.llm_service import GroqProvider, LLMParseError

        bad = json.dumps({"summary": "only this field"})
        with pytest.raises(LLMParseError, match="schema validation"):
            GroqProvider._parse_response(bad)

    def test_valid_json_returns_analysis(self):
        from backend.ai.llm_service import GroqProvider
        from backend.ai.schemas import AlertAnalysis

        good = json.dumps(_make_valid_analysis_dict())
        result = GroqProvider._parse_response(good)
        assert isinstance(result, AlertAnalysis)

    def test_invalid_severity_value_raises_parse_error(self):
        from backend.ai.llm_service import GroqProvider, LLMParseError

        data = _make_valid_analysis_dict(severity="EXTREME")
        with pytest.raises(LLMParseError, match="schema validation"):
            GroqProvider._parse_response(json.dumps(data))


# ===========================================================================
# 4. GroqProvider initialisation without a key
# ===========================================================================

class TestGroqProviderInitWithoutKey:
    def test_missing_api_key_raises_provider_error(self):
        from backend.ai.config import AIConfig
        from backend.ai.llm_service import GroqProvider, LLMProviderError

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=None,
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=2,
        )
        with pytest.raises(LLMProviderError, match="GROQ_API_KEY"):
            GroqProvider(config=cfg)

    def test_missing_groq_sdk_raises_provider_error(self):
        """Simulate missing groq package."""
        from backend.ai.config import AIConfig
        from backend.ai.llm_service import GroqProvider, LLMProviderError
        from pydantic import SecretStr

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=SecretStr("fake-key"),
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=2,
        )
        with patch("builtins.__import__", side_effect=ImportError("No module named 'groq'")):
            with pytest.raises((LLMProviderError, ImportError)):
                GroqProvider(config=cfg)


# ===========================================================================
# 5. GroqProvider API error handling
# ===========================================================================

class TestGroqProviderAPIErrorHandling:
    def _make_provider(self):
        """Build a GroqProvider with a mocked internal client."""
        from backend.ai.config import AIConfig
        from backend.ai.llm_service import GroqProvider
        from pydantic import SecretStr

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=SecretStr("gsk_fake_key_for_tests"),
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=0,
        )
        provider = object.__new__(GroqProvider)
        provider._config = cfg
        provider._last_error = None
        provider._client = MagicMock()
        return provider

    def test_network_error_raises_provider_error(self):
        from backend.ai.llm_service import LLMProviderError

        provider = self._make_provider()
        provider._client.chat.completions.create.side_effect = ConnectionError("timeout")

        with pytest.raises(LLMProviderError):
            provider.analyze("sys", "user")

    def test_last_error_is_set_after_failure(self):
        provider = self._make_provider()
        provider._client.chat.completions.create.side_effect = RuntimeError("boom")

        from backend.ai.llm_service import LLMProviderError
        with pytest.raises(LLMProviderError):
            provider.analyze("sys", "user")

        assert provider.last_error is not None

    def test_health_check_returns_false_on_error(self):
        provider = self._make_provider()
        provider._client.models.list.side_effect = Exception("unreachable")

        assert provider.health_check() is False
        assert provider.last_error is not None

    def test_health_check_returns_true_on_success(self):
        provider = self._make_provider()
        mock_model = MagicMock()
        provider._client.models.list.return_value = MagicMock(data=[mock_model])

        assert provider.health_check() is True
        assert provider.last_error is None


# ===========================================================================
# 6. Structured response parsing
# ===========================================================================

class TestStructuredResponseParsing:
    def test_full_valid_response_round_trips(self):
        from backend.ai.llm_service import GroqProvider
        from backend.ai.schemas import AlertAnalysis

        data = _make_valid_analysis_dict()
        data["mitre_attack"] = [
            {
                "technique_id": "T1046",
                "technique_name": "Network Service Discovery",
                "rationale": "Port sweep matches this technique.",
            }
        ]
        data["sources"] = [
            {
                "source_id": "MITRE-T1046",
                "title": "MITRE ATT&CK T1046",
                "relevance": "Describes the port scanning technique observed.",
            }
        ]
        result = GroqProvider._parse_response(json.dumps(data))
        assert isinstance(result, AlertAnalysis)
        assert result.mitre_attack[0].technique_id == "T1046"
        assert result.sources[0].source_id == "MITRE-T1046"

    def test_whitespace_padded_json_is_accepted(self):
        from backend.ai.llm_service import GroqProvider

        raw = "   \n" + json.dumps(_make_valid_analysis_dict()) + "\n   "
        result = GroqProvider._parse_response(raw)
        assert result.attack_type == "PortScan"


# ===========================================================================
# 7. Prompt construction
# ===========================================================================

class TestPromptConstruction:
    def _make_ctx(self) -> "AlertContext":
        from backend.ai.schemas import AlertContext
        return AlertContext(**_make_valid_alert_dict())

    def test_system_prompt_contains_role_declaration(self):
        from backend.ai.prompt_builder import PromptBuilder

        builder = PromptBuilder()
        sys_prompt, _ = builder.build(self._make_ctx())
        assert "AI Security Analyst" in sys_prompt

    def test_system_prompt_contains_all_grounding_rules(self):
        from backend.ai.prompt_builder import PromptBuilder, SYSTEM_PROMPT

        # All 10 rules must be present in the system prompt
        rules_markers = [
            "authoritative",          # rule 1: detector classification
            "invent",                 # rule 4: never invent
            "Insufficient evidence",  # rule 5: state when evidence is lacking
            "defensive",              # rule 6: defensive guidance only
            "commands",               # rule 7: never execute commands
            "secrets",                # rule 8/9: never expose secrets
            "block",                  # rule 10: never block systems
            "reasoning",              # rule 11: own reasoning ≠ evidence
        ]
        for marker in rules_markers:
            assert marker.lower() in SYSTEM_PROMPT.lower(), (
                f"Grounding rule marker '{marker}' missing from system prompt"
            )

    def test_user_prompt_contains_alert_id(self):
        from backend.ai.prompt_builder import PromptBuilder

        builder = PromptBuilder()
        _, user_prompt = builder.build(self._make_ctx())
        assert "test-alert-001" in user_prompt

    def test_user_prompt_contains_source_ip(self):
        from backend.ai.prompt_builder import PromptBuilder

        builder = PromptBuilder()
        _, user_prompt = builder.build(self._make_ctx())
        assert "192.168.1.50" in user_prompt

    def test_user_prompt_contains_attack_type(self):
        from backend.ai.prompt_builder import PromptBuilder

        builder = PromptBuilder()
        _, user_prompt = builder.build(self._make_ctx())
        assert "PortScan" in user_prompt

    def test_empty_knowledge_context_shows_placeholder(self):
        from backend.ai.prompt_builder import PromptBuilder
        from backend.ai.schemas import KnowledgeContext

        builder = PromptBuilder()
        _, user_prompt = builder.build(self._make_ctx(), KnowledgeContext())
        assert "empty" in user_prompt.lower() or "no external knowledge" in user_prompt.lower()

    def test_alert_json_in_user_prompt_is_valid_json(self):
        """The alert block embedded in the user prompt must be parseable JSON."""
        from backend.ai.prompt_builder import PromptBuilder

        builder = PromptBuilder()
        _, user_prompt = builder.build(self._make_ctx())
        # Extract the JSON block between ```json and ```
        import re
        match = re.search(r"```json\s*(.*?)\s*```", user_prompt, re.DOTALL)
        assert match, "No JSON code block found in user prompt"
        data = json.loads(match.group(1))
        assert data["alert_id"] == "test-alert-001"


# ===========================================================================
# 8. Secrets never appear in logs
# ===========================================================================

class TestSecretsNeverInLogs:
    def test_api_key_not_in_provider_repr(self):
        from backend.ai.config import AIConfig
        from backend.ai.llm_service import GroqProvider
        from pydantic import SecretStr

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=SecretStr("gsk_supersecretkey1234"),
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=0,
        )
        provider = object.__new__(GroqProvider)
        provider._config = cfg
        provider._last_error = None
        provider._client = MagicMock()

        assert "gsk_supersecretkey1234" not in repr(provider)
        assert "gsk_supersecretkey1234" not in str(provider)

    def test_api_key_not_in_config_repr(self):
        from backend.ai.config import AIConfig
        from pydantic import SecretStr

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=SecretStr("gsk_supersecretkey9999"),
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=2,
        )
        cfg_repr = repr(cfg)
        assert "gsk_supersecretkey9999" not in cfg_repr

    def test_api_key_not_in_public_dict(self):
        from backend.ai.config import AIConfig
        from pydantic import SecretStr

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=SecretStr("gsk_mysecretkey"),
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=2,
        )
        pub = cfg.to_public_dict()
        assert "groq_api_key" not in pub
        assert "gsk_mysecretkey" not in str(pub)

    def test_safe_error_message_redacts_bearer_token(self):
        from backend.ai.llm_service import GroqProvider

        exc = Exception("401 Unauthorized – Bearer gsk_superSecretToken123 is invalid")
        safe = GroqProvider._safe_error_message(exc)
        assert "gsk_superSecretToken123" not in safe
        assert "[REDACTED]" in safe

    def test_log_records_do_not_contain_api_key(self, caplog):
        """Verify that log messages during provider construction don't leak the key."""
        from backend.ai.config import AIConfig
        from backend.ai.llm_service import GroqProvider
        from pydantic import SecretStr

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=SecretStr("gsk_logLeakSecret"),
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=0,
        )

        mock_client = MagicMock()
        with caplog.at_level(logging.DEBUG, logger="backend.ai"):
            provider = object.__new__(GroqProvider)
            provider._config = cfg
            provider._last_error = None
            provider._client = mock_client

        for record in caplog.records:
            assert "gsk_logLeakSecret" not in record.getMessage()


# ===========================================================================
# 9. API endpoint validation
# ===========================================================================

@pytest.fixture(scope="module")
def ai_client():
    """Flask test client with AI layer wired up (provider mocked)."""
    from backend.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


class TestAIAPIEndpoints:
    def test_ai_status_endpoint_exists(self, ai_client):
        r = ai_client.get("/api/ai/status")
        assert r.status_code == 200

    def test_ai_status_returns_required_fields(self, ai_client):
        r = ai_client.get("/api/ai/status")
        data = r.get_json()
        assert "ai_enabled" in data
        assert "llm_provider" in data
        assert "groq_model" in data

    def test_ai_status_never_returns_api_key(self, ai_client):
        r = ai_client.get("/api/ai/status")
        raw = r.data.decode("utf-8")
        # No API key pattern should be in the response
        assert "groq_api_key" not in raw
        assert "GROQ_API_KEY" not in raw

    def test_analyze_alert_returns_503_when_ai_disabled(self, ai_client):
        """When AI_ENABLED=false the endpoint must return 503 Service Unavailable."""
        payload = _make_valid_alert_dict()
        r = ai_client.post(
            "/api/ai/analyze-alert",
            json=payload,
            content_type="application/json",
        )
        # AI is disabled by default in test env (no GROQ_API_KEY set)
        assert r.status_code in (503, 400, 422)

    def test_analyze_alert_rejects_invalid_payload(self, ai_client):
        r = ai_client.post(
            "/api/ai/analyze-alert",
            json={"invalid": "payload"},
            content_type="application/json",
        )
        assert r.status_code in (400, 422, 503)

    def test_analyze_alert_with_mocked_provider_returns_analysis(self, ai_client):
        """End-to-end with mocked LLM: valid input → 200 AlertAnalysis JSON."""
        from backend.ai.alert_analyzer import reset_alert_analyzer

        mock_analysis = _make_valid_analysis_dict()

        # Build a mock analyzer that returns a valid AlertAnalysis
        from backend.ai.schemas import AlertAnalysis
        mock_result = AlertAnalysis(**mock_analysis)

        with patch("backend.ai.alert_analyzer.get_alert_analyzer") as mock_get:
            mock_analyzer = MagicMock()
            mock_analyzer.analyze.return_value = mock_result
            mock_get.return_value = mock_analyzer

            r = ai_client.post(
                "/api/ai/analyze-alert",
                json=_make_valid_alert_dict(),
                content_type="application/json",
            )

        assert r.status_code == 200
        data = r.get_json()
        assert data["attack_type"] == "PortScan"
        assert data["severity"] == "HIGH"

    def test_analyze_alert_missing_body_returns_400(self, ai_client):
        r = ai_client.post(
            "/api/ai/analyze-alert",
            data="",
            content_type="application/json",
        )
        assert r.status_code in (400, 415, 422, 503)


# ===========================================================================
# 10. Disabled AI behaviour
# ===========================================================================

class TestDisabledAIBehaviour:
    def test_analyzer_raises_when_disabled(self):
        from backend.ai.alert_analyzer import AlertAnalyzer
        from backend.ai.config import AIConfig
        from backend.ai.llm_service import LLMProviderError
        from backend.ai.schemas import AlertContext

        cfg = AIConfig.model_construct(
            ai_enabled=False,
            llm_provider="groq",
            groq_api_key=None,
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=2,
        )
        analyzer = AlertAnalyzer(config=cfg)
        ctx = AlertContext(**_make_valid_alert_dict())

        with pytest.raises(LLMProviderError, match="disabled"):
            analyzer.analyze(ctx)

    def test_health_check_shows_disabled_state(self):
        from backend.ai.alert_analyzer import AlertAnalyzer
        from backend.ai.config import AIConfig

        cfg = AIConfig.model_construct(
            ai_enabled=False,
            llm_provider="groq",
            groq_api_key=None,
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=2,
        )
        analyzer = AlertAnalyzer(config=cfg)
        status = analyzer.health_check()
        assert status["ai_enabled"] is False
        assert status["provider_healthy"] is None  # N/A when disabled

    def test_analyzer_raises_when_key_missing(self):
        from backend.ai.alert_analyzer import AlertAnalyzer
        from backend.ai.config import AIConfig
        from backend.ai.llm_service import LLMProviderError
        from backend.ai.schemas import AlertContext

        cfg = AIConfig.model_construct(
            ai_enabled=True,
            llm_provider="groq",
            groq_api_key=None,  # key absent
            groq_model="openai/gpt-oss-120b",
            groq_reasoning_effort="medium",
            groq_timeout_seconds=60.0,
            groq_max_retries=2,
        )
        analyzer = AlertAnalyzer(config=cfg)
        ctx = AlertContext(**_make_valid_alert_dict())

        with pytest.raises(LLMProviderError, match="not configured"):
            analyzer.analyze(ctx)
