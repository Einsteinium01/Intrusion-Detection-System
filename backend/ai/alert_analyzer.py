"""
backend/ai/alert_analyzer.py
=============================
WHY THIS FILE EXISTS
--------------------
``AlertAnalyzer`` is the orchestration layer that wires together:

  AlertContext  →  PromptBuilder  →  LLMProvider  →  AlertAnalysis

It is the only object that consumers (Flask routes, tests, CLI scripts)
need to import; they do not call PromptBuilder or the provider directly.

Error handling strategy
-----------------------
- ``LLMProviderError`` / ``LLMParseError``  → re-raised as-is (callers
  decide how to surface them to clients).
- Unexpected exceptions are logged and re-raised wrapped in
  ``LLMProviderError`` so callers always catch one type.
- ``last_error`` is recorded for the /api/ai/status endpoint.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from backend.ai.config import AIConfig, get_ai_config
from backend.ai.llm_service import (
    LLMProvider,
    LLMProviderError,
    get_llm_provider,
    reset_llm_provider,
)
from backend.ai.prompt_builder import PromptBuilder, get_prompt_builder
from backend.ai.schemas import AlertAnalysis, AlertContext, KnowledgeContext

log = logging.getLogger(__name__)


class AlertAnalyzer:
    """
    Orchestrates the end-to-end pipeline from IDS alert → LLM analysis.

    Lifecycle::

        analyzer = AlertAnalyzer()
        analysis = analyzer.analyze(alert_ctx)  # returns AlertAnalysis

    Thread safety: ``AlertAnalyzer`` is stateless between calls (no
    mutable shared state).  The underlying provider may or may not be
    thread-safe depending on the SDK; the Groq SDK uses httpx which is
    thread-safe for concurrent calls.
    """

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        builder: Optional[PromptBuilder] = None,
        config: Optional[AIConfig] = None,
    ) -> None:
        self._config = config or get_ai_config()
        self._provider = provider  # None → lazy-initialised on first call
        self._builder = builder or get_prompt_builder()
        self._last_error: Optional[str] = None
        self._last_analysis_time: Optional[float] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        alert: AlertContext,
        knowledge: Optional[KnowledgeContext] = None,
    ) -> AlertAnalysis:
        """
        Analyse a single IDS alert and return a structured AlertAnalysis.

        Parameters
        ----------
        alert:
            Grounded AlertContext produced by the IDS pipeline.
        knowledge:
            Optional RAG context.  Phase 1: pass None (empty context used).

        Returns
        -------
        AlertAnalysis
            Validated, structured analysis from the LLM.

        Raises
        ------
        LLMProviderError
            When the AI layer is disabled, not configured, or the
            provider call fails.
        """
        if not self._config.ai_enabled:
            raise LLMProviderError(
                "AI analysis is disabled. Set AI_ENABLED=true to enable it."
            )

        if not self._config.is_configured():
            raise LLMProviderError(
                "AI analysis is not configured. "
                "Ensure GROQ_API_KEY is set and AI_ENABLED=true."
            )

        provider = self._get_provider()
        knowledge = knowledge or KnowledgeContext()

        system_prompt, user_prompt = self._builder.build(alert, knowledge)

        t0 = time.perf_counter()
        try:
            analysis = provider.analyze(system_prompt, user_prompt)
        except LLMProviderError:
            raise
        except Exception as exc:
            # Unexpected errors – wrap and re-raise
            msg = f"Unexpected error in AlertAnalyzer: {type(exc).__name__}"
            self._last_error = msg
            log.exception(msg)
            raise LLMProviderError(msg) from exc

        elapsed = time.perf_counter() - t0
        self._last_analysis_time = elapsed
        self._last_error = None

        log.info(
            "AlertAnalyzer: analysis complete alert_id=%s severity=%s elapsed=%.2fs",
            alert.alert_id,
            analysis.severity,
            elapsed,
        )
        return analysis

    # ------------------------------------------------------------------
    def health_check(self) -> dict:
        """
        Return a health-status dict for the /api/ai/status endpoint.

        Never raises; on provider initialisation failure the dict
        includes ``provider_healthy=false`` and the error message.
        """
        status = self._config.to_public_dict()
        status["last_error"] = self._last_error
        status["last_analysis_seconds"] = self._last_analysis_time

        if not self._config.ai_enabled:
            status["provider_healthy"] = None  # not applicable
            return status

        if not self._config.is_configured():
            status["provider_healthy"] = False
            status["last_error"] = "GROQ_API_KEY is not set."
            return status

        try:
            provider = self._get_provider()
            status["provider_healthy"] = provider.health_check()
            if hasattr(provider, "last_error"):
                status["last_error"] = provider.last_error  # type: ignore[union-attr]
        except LLMProviderError as exc:
            status["provider_healthy"] = False
            status["last_error"] = str(exc)

        return status

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_provider(self) -> LLMProvider:
        """Return the provider, lazy-initialising it on first call."""
        if self._provider is None:
            self._provider = get_llm_provider(self._config)
        return self._provider


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_analyzer: Optional[AlertAnalyzer] = None


def get_alert_analyzer() -> AlertAnalyzer:
    """Return the process-level AlertAnalyzer singleton."""
    global _analyzer
    if _analyzer is None:
        _analyzer = AlertAnalyzer()
    return _analyzer


def reset_alert_analyzer() -> None:
    """Discard the cached singleton.  Intended for tests."""
    global _analyzer
    _analyzer = None
    reset_llm_provider()
