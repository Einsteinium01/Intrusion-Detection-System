"""
backend/ai/llm_service.py
==========================
WHY THIS FILE EXISTS
--------------------
Defines a provider-independent abstraction (``LLMProvider``) and the
concrete Groq implementation (``GroqProvider``).

The abstraction exists so that adding Ollama or another local-inference
engine in Phase 2+ requires only:
  1. A new ``XyzProvider(LLMProvider)`` class in this file, and
  2. A branch in ``get_llm_provider()`` keyed by ``LLM_PROVIDER``.

No other part of the application needs to change.

SECURITY
--------
- The API key is extracted from ``AIConfig.groq_api_key.get_secret_value()``
  inside the provider and NEVER stored as a plain string attribute.
- ``__repr__`` is overridden to prevent accidental log leakage.
- All exception messages are stripped of raw HTTP bodies before being
  re-raised, so Groq error payloads (which sometimes echo headers)
  never reach application logs.
- Provider health-check failures set ``last_error`` but do not expose
  the underlying exception detail to callers.
"""

from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pydantic import ValidationError

from backend.ai.config import AIConfig, get_ai_config
from backend.ai.schemas import AlertAnalysis

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """
    Provider-independent interface for all LLM backends.

    Subclasses must implement:
      ``analyze(system_prompt, user_prompt) -> AlertAnalysis``
      ``health_check() -> bool``
    """

    @abstractmethod
    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> AlertAnalysis:
        """
        Send the prompts to the LLM and return a validated AlertAnalysis.

        Parameters
        ----------
        system_prompt:
            The role/instruction prompt built by PromptBuilder.
        user_prompt:
            The alert-specific user message built by PromptBuilder.

        Raises
        ------
        LLMProviderError
            On API errors, timeout, schema validation failure, or
            unexpected response structure.
        """
        ...  # pragma: no cover

    @abstractmethod
    def health_check(self) -> bool:
        """
        Return True if the provider is reachable and the API key is valid.

        Should return False (not raise) on failure so callers can handle
        degraded state gracefully.
        """
        ...  # pragma: no cover

    def __repr__(self) -> str:  # safety: never expose key
        return f"<{self.__class__.__name__}>"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LLMProviderError(Exception):
    """Raised when an LLM provider call fails after all retries."""


class LLMParseError(LLMProviderError):
    """Raised when the LLM response cannot be parsed into AlertAnalysis."""


# ---------------------------------------------------------------------------
# Groq implementation
# ---------------------------------------------------------------------------


class GroqProvider(LLMProvider):
    """
    Groq API implementation of LLMProvider.

    Uses:
    - Official ``groq`` Python SDK (synchronous client).
    - Structured JSON output with strict schema enforcement.
    - Configurable reasoning effort (passed via the ``reasoning_effort``
      parameter where supported by the model).
    - Automatic retry on transient errors (handled by the SDK).
    - No plaintext API key in any log statement or exception message.
    """

    # JSON schema derived from AlertAnalysis for Groq strict structured output
    _RESPONSE_SCHEMA: Dict[str, Any] = {
        "type": "object",
        "properties": {
            "summary": {"type": "string"},
            "technical_analysis": {"type": "string"},
            "severity": {
                "type": "string",
                "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            },
            "attack_type": {"type": "string"},
            "evidence": {
                "type": "array",
                "items": {"type": "string"},
            },
            "mitre_attack": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "technique_id": {"type": "string"},
                        "technique_name": {"type": "string"},
                        "rationale": {"type": "string"},
                    },
                    "required": ["technique_id", "technique_name", "rationale"],
                    "additionalProperties": False,
                },
            },
            "investigation_steps": {
                "type": "array",
                "items": {"type": "string"},
            },
            "recommended_actions": {
                "type": "array",
                "items": {"type": "string"},
            },
            "sources": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "source_id": {"type": "string"},
                        "title": {"type": "string"},
                        "relevance": {"type": "string"},
                    },
                    "required": ["source_id", "title", "relevance"],
                    "additionalProperties": False,
                },
            },
        },
        "required": [
            "summary",
            "technical_analysis",
            "severity",
            "attack_type",
            "evidence",
            "mitre_attack",
            "investigation_steps",
            "recommended_actions",
            "sources",
        ],
        "additionalProperties": False,
    }

    def __init__(self, config: Optional[AIConfig] = None) -> None:
        """
        Initialise the Groq client.

        Parameters
        ----------
        config:
            AIConfig instance.  If None, the module-level singleton is used.

        Raises
        ------
        LLMProviderError
            If the Groq SDK cannot be imported or the API key is absent.
        """
        self._config = config or get_ai_config()
        self._client = self._init_client()
        self._last_error: Optional[str] = None

    # ------------------------------------------------------------------
    def _init_client(self):  # type: ignore[return]
        """Create and return the Groq SDK client.  Never log the key."""
        try:
            import groq as groq_sdk  # local import to keep SDK optional
        except ImportError as exc:
            raise LLMProviderError(
                "groq SDK is not installed. Run: pip install groq"
            ) from exc

        if not self._config.groq_api_key:
            raise LLMProviderError(
                "GROQ_API_KEY is not configured. "
                "Set the environment variable or add it to .env."
            )

        # Extract secret value; this is the ONLY place the raw key is accessed.
        api_key = self._config.groq_api_key.get_secret_value()

        client = groq_sdk.Groq(
            api_key=api_key,
            timeout=self._config.groq_timeout_seconds,
            max_retries=self._config.groq_max_retries,
        )
        log.info(
            "GroqProvider initialised: model=%s reasoning_effort=%s",
            self._config.groq_model,
            self._config.groq_reasoning_effort,
        )
        return client

    # ------------------------------------------------------------------
    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> AlertAnalysis:
        """
        Call the Groq Chat Completions API and return a validated AlertAnalysis.

        The model is asked for strict JSON output matching _RESPONSE_SCHEMA.
        The raw JSON is then validated through the Pydantic AlertAnalysis model.
        """
        t0 = time.perf_counter()
        try:
            completion = self._client.chat.completions.create(
                model=self._config.groq_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={
                    "type": "json_schema",
                    "json_schema": {
                        "name": "AlertAnalysis",
                        "strict": True,
                        "schema": self._RESPONSE_SCHEMA,
                    },
                },
                reasoning_effort=self._config.groq_reasoning_effort,
            )
        except Exception as exc:
            # Strip exception repr to avoid leaking HTTP bodies / headers
            safe_msg = self._safe_error_message(exc)
            self._last_error = safe_msg
            log.error("GroqProvider.analyze failed: %s", safe_msg)
            raise LLMProviderError(f"Groq API call failed: {safe_msg}") from None

        elapsed = time.perf_counter() - t0
        raw_content = completion.choices[0].message.content or ""
        log.info(
            "GroqProvider: response received in %.2fs tokens=%s",
            elapsed,
            completion.usage.total_tokens if completion.usage else "?",
        )

        return self._parse_response(raw_content)

    # ------------------------------------------------------------------
    def health_check(self) -> bool:
        """
        Verify connectivity by listing models.

        Returns False (never raises) so status endpoints stay responsive.
        """
        try:
            models = self._client.models.list()
            ok = len(models.data) > 0
            if ok:
                self._last_error = None
            return ok
        except Exception as exc:
            safe_msg = self._safe_error_message(exc)
            self._last_error = safe_msg
            log.warning("GroqProvider.health_check failed: %s", safe_msg)
            return False

    # ------------------------------------------------------------------
    @property
    def last_error(self) -> Optional[str]:
        """Most recent error message; None if last operation succeeded."""
        return self._last_error

    # ------------------------------------------------------------------
    @staticmethod
    def _parse_response(raw_content: str) -> AlertAnalysis:
        """
        Parse and validate the raw LLM response string into AlertAnalysis.

        Raises
        ------
        LLMParseError
            If the content is not valid JSON or fails Pydantic validation.
        """
        if not raw_content.strip():
            raise LLMParseError("LLM returned an empty response.")

        try:
            data = json.loads(raw_content)
        except json.JSONDecodeError as exc:
            raise LLMParseError(
                f"LLM response is not valid JSON: {exc.msg}"
            ) from exc

        try:
            return AlertAnalysis.model_validate(data)
        except ValidationError as exc:
            # Summarise validation errors without leaking raw content
            errors = exc.errors()
            brief = "; ".join(
                f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}"
                for e in errors[:5]
            )
            raise LLMParseError(
                f"LLM response failed schema validation: {brief}"
            ) from exc

    # ------------------------------------------------------------------
    @staticmethod
    def _safe_error_message(exc: Exception) -> str:
        """
        Return a sanitised error message that does not contain API keys,
        HTTP response bodies, or other sensitive data.
        """
        msg = type(exc).__name__
        # Include only the first 200 chars of the exception string,
        # which typically contains just the error code / status.
        detail = str(exc)[:200]
        # Redact anything that looks like a bearer token or API key
        import re
        detail = re.sub(
            r"(Bearer\s+|gsk_|sk-|api[_-]?key[=:\s]+)\S+",
            r"\1[REDACTED]",
            detail,
            flags=re.IGNORECASE,
        )
        return f"{msg}: {detail}"


# ---------------------------------------------------------------------------
# Provider factory
# ---------------------------------------------------------------------------

_provider_instance: Optional[LLMProvider] = None


def get_llm_provider(config: Optional[AIConfig] = None) -> LLMProvider:
    """
    Return (and cache) the configured LLM provider singleton.

    Raises
    ------
    LLMProviderError
        If the configured provider is unknown or cannot be initialised.
    """
    global _provider_instance
    if _provider_instance is not None:
        return _provider_instance

    cfg = config or get_ai_config()

    if cfg.llm_provider == "groq":
        _provider_instance = GroqProvider(cfg)
    else:  # pragma: no cover – validated by AIConfig
        raise LLMProviderError(f"Unknown LLM_PROVIDER: '{cfg.llm_provider}'")

    return _provider_instance


def reset_llm_provider() -> None:
    """Discard the cached provider singleton.  Intended for tests."""
    global _provider_instance
    _provider_instance = None
