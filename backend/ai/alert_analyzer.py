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

    Phase 2: When a RAGRetriever is configured and RAG is enabled, the
    analyzer automatically populates KnowledgeContext before calling the LLM.

    Pipeline::

        AlertContext
          → RAGRetriever.retrieve_for_alert()  [Phase 2]
          → KnowledgeContext
          → PromptBuilder.build()
          → LLMProvider.analyze()
          → AlertAnalysis

    Thread safety: stateless between calls.  The Groq SDK (httpx) and
    FAISS are both safe for concurrent reads.
    """

    def __init__(
        self,
        provider: Optional[LLMProvider] = None,
        builder: Optional[PromptBuilder] = None,
        config: Optional[AIConfig] = None,
        rag_retriever=None,   # Optional[RAGRetriever] — avoids circular import
        rag_enabled: Optional[bool] = None,
    ) -> None:
        self._config = config or get_ai_config()
        self._provider = provider
        self._builder = builder or get_prompt_builder()
        self._rag_retriever = rag_retriever   # lazy if None
        # rag_enabled=None → follow RAGConfig; rag_enabled=False → skip RAG
        self._rag_enabled = rag_enabled
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

        Phase 2: If *knowledge* is None and RAG is enabled, the analyzer
        automatically retrieves KnowledgeContext from the local RAG index.
        Retrieval failures are non-fatal: analysis continues with an empty
        KnowledgeContext so the LLM call is never blocked by RAG errors.

        Parameters
        ----------
        alert:
            Grounded AlertContext produced by the IDS pipeline.
        knowledge:
            Optional RAG context.  If None, auto-retrieved from RAG.

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

        # ── Phase 2: RAG retrieval ──────────────────────────────────────
        if knowledge is None:
            knowledge = self._retrieve_knowledge(alert)

        # ── Build prompts and call LLM ──────────────────────────────────
        system_prompt, user_prompt = self._builder.build(alert, knowledge)

        t0 = time.perf_counter()
        try:
            analysis = provider.analyze(system_prompt, user_prompt)
        except LLMProviderError:
            raise
        except Exception as exc:
            msg = f"Unexpected error in AlertAnalyzer: {type(exc).__name__}"
            self._last_error = msg
            log.exception(msg)
            raise LLMProviderError(msg) from exc

        elapsed = time.perf_counter() - t0
        self._last_analysis_time = elapsed
        self._last_error = None

        log.info(
            "AlertAnalyzer: analysis complete alert_id=%s severity=%s "
            "rag_docs=%d elapsed=%.2fs",
            alert.alert_id,
            analysis.severity,
            len(knowledge.documents),
            elapsed,
        )
        return analysis

    def investigate(
        self,
        alert: AlertContext,
        question: str,
        related_alerts: list[str],
        knowledge: Optional[KnowledgeContext] = None,
    ):
        if not self._config.ai_enabled:
            raise LLMProviderError("AI analysis is disabled.")

        if not self._config.is_configured():
            raise LLMProviderError("AI analysis is not configured.")

        provider = self._get_provider()

        if knowledge is None:
            knowledge = self._retrieve_knowledge(alert)

        system_prompt, user_prompt = self._builder.build_investigation(
            alert, question, related_alerts, knowledge
        )

        t0 = time.perf_counter()
        try:
            response = provider.investigate(system_prompt, user_prompt)
        except LLMProviderError:
            raise
        except Exception as exc:
            msg = f"Unexpected error in AlertAnalyzer.investigate: {type(exc).__name__}"
            self._last_error = msg
            log.exception(msg)
            raise LLMProviderError(msg) from exc

        elapsed = time.perf_counter() - t0
        self._last_analysis_time = elapsed
        self._last_error = None

        log.info(
            "AlertAnalyzer: investigate complete alert_id=%s elapsed=%.2fs",
            alert.alert_id, elapsed
        )
        return response

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

    def _retrieve_knowledge(self, alert: AlertContext) -> KnowledgeContext:
        """
        Auto-retrieve KnowledgeContext via RAG for the given alert.

        Retrieval failures are non-fatal: returns an empty KnowledgeContext
        so the LLM call is never blocked by RAG errors.

        The RAGRetriever is imported lazily to avoid circular imports and to
        keep the AI layer usable even when the RAG package is not installed.
        """
        try:
            rag_enabled = self._rag_enabled
            if rag_enabled is None:
                # Follow RAGConfig setting
                from backend.rag.config import get_rag_config
                rag_enabled = get_rag_config().rag_enabled

            if not rag_enabled:
                return KnowledgeContext()

            retriever = self._get_rag_retriever()
            if retriever is None:
                return KnowledgeContext()

            return retriever.retrieve_for_alert(alert)

        except Exception as exc:
            log.warning(
                "AlertAnalyzer: RAG retrieval failed (continuing without knowledge): %s",
                exc,
            )
            return KnowledgeContext()

    def _get_rag_retriever(self):
        """Return the RAGRetriever, lazy-initialising it on first call."""
        if self._rag_retriever is None:
            try:
                from backend.rag.retriever import get_rag_retriever
                self._rag_retriever = get_rag_retriever()
            except Exception as exc:
                log.warning("AlertAnalyzer: could not init RAGRetriever: %s", exc)
                return None
        return self._rag_retriever


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
