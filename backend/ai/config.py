"""
backend/ai/config.py
====================
WHY THIS FILE EXISTS
--------------------
Centralises all AI-layer configuration.  Every value is read from
environment variables so that the API key and model name are never
hardcoded and can be rotated without touching source code.

The singleton ``get_ai_config()`` is called once at startup; the
rest of the AI layer imports the returned object rather than reading
``os.environ`` directly.  This makes the config trivially overridable
in tests (just patch ``get_ai_config``).

SECURITY
--------
- The API key is stored in a ``SecretStr`` field; its ``__repr__``
  and ``__str__`` return ``'**********'`` so it can never leak into
  log messages even if a caller accidentally logs the config object.
- ``to_public_dict()`` omits the key entirely – safe to return to
  clients via the /api/ai/status endpoint.
"""

import os
import logging
from typing import Optional

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)


class AIConfig(BaseSettings):
    """
    Runtime configuration for the AI / LLM layer.

    All values can be overridden via environment variables.  A
    ``.env`` file in the project root is loaded automatically if
    present (via python-dotenv / pydantic-settings).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Feature flag ─────────────────────────────────────────────────────────
    ai_enabled: bool = False
    """Set AI_ENABLED=true to activate the LLM analysis endpoints."""

    # ── Provider selection ───────────────────────────────────────────────────
    llm_provider: str = "groq"
    """LLM provider identifier.  Currently only 'groq' is implemented."""

    # ── Groq settings ────────────────────────────────────────────────────────
    groq_api_key: Optional[SecretStr] = None
    """
    GROQ_API_KEY – loaded from environment / .env.
    Never logged; never returned to callers.
    """

    groq_model: str = "openai/gpt-oss-120b"
    """Model identifier passed to the Groq Chat Completions API."""

    groq_reasoning_effort: str = "medium"
    """
    Reasoning effort hint forwarded to Groq's reasoning-capable models.
    Accepted values: 'none' | 'low' | 'medium' | 'high' | 'default'.
    """

    groq_timeout_seconds: float = 60.0
    """HTTP timeout for each Groq API call (seconds)."""

    groq_max_retries: int = 2
    """Number of automatic retries on transient network errors."""

    # ── Validators ───────────────────────────────────────────────────────────
    @field_validator("llm_provider")
    @classmethod
    def _validate_provider(cls, v: str) -> str:
        allowed = {"groq"}  # extend as new providers are added
        v = v.lower().strip()
        if v not in allowed:
            raise ValueError(f"LLM_PROVIDER must be one of {allowed}, got '{v}'")
        return v

    @field_validator("groq_reasoning_effort")
    @classmethod
    def _validate_reasoning_effort(cls, v: str) -> str:
        allowed = {"none", "low", "medium", "high", "default"}
        v = v.lower().strip()
        if v not in allowed:
            log.warning(
                "GROQ_REASONING_EFFORT='%s' is not a recognised value; "
                "using 'medium' instead.",
                v,
            )
            return "medium"
        return v

    @model_validator(mode="after")
    def _warn_if_enabled_without_key(self) -> "AIConfig":
        if self.ai_enabled and not self.groq_api_key:
            log.warning(
                "AI_ENABLED=true but GROQ_API_KEY is not set. "
                "All /api/ai/* requests will return 503 until the key is configured."
            )
        return self

    # ── Safe public representation ────────────────────────────────────────────
    def to_public_dict(self) -> dict:
        """
        Return a dictionary that is safe to serialise into an API response.
        The API key is intentionally excluded.
        """
        return {
            "ai_enabled": self.ai_enabled,
            "llm_provider": self.llm_provider,
            "groq_model": self.groq_model,
            "groq_reasoning_effort": self.groq_reasoning_effort,
            "groq_timeout_seconds": self.groq_timeout_seconds,
        }

    def is_configured(self) -> bool:
        """True when the AI layer is both enabled and has a provider key."""
        return self.ai_enabled and bool(self.groq_api_key)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_config: Optional[AIConfig] = None


def get_ai_config() -> AIConfig:
    """
    Return the process-level AIConfig singleton.

    Safe to call repeatedly; the object is constructed exactly once.
    Tests can replace ``_config`` directly or patch this function.
    """
    global _config
    if _config is None:
        _config = AIConfig()  # reads .env + environment variables
        log.debug(
            "AIConfig loaded: enabled=%s provider=%s model=%s",
            _config.ai_enabled,
            _config.llm_provider,
            _config.groq_model,
        )
    return _config


def reset_ai_config() -> None:
    """
    Discard the cached singleton.  Intended for use in tests that need
    to exercise different environment-variable combinations.
    """
    global _config
    _config = None
