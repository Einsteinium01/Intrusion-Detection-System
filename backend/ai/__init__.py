"""
backend/ai/__init__.py
======================
AI / RAG layer for the Network Intrusion Detection System.

Phase 1: Provider-independent LLM integration using the Groq API.
Phase 2 (future): RAG context retrieval from a vector store.

Public surface exported from this package:

  AlertContext   – normalized alert model fed to the LLM
  AlertAnalysis  – structured LLM response
  get_ai_config  – returns the runtime AIConfig
  AlertAnalyzer  – orchestrates prompt → LLM → validated response
"""

from backend.ai.schemas import AlertContext, AlertAnalysis, MitreAttack, Source
from backend.ai.config import AIConfig, get_ai_config
from backend.ai.alert_analyzer import AlertAnalyzer

__all__ = [
    "AlertContext",
    "AlertAnalysis",
    "MitreAttack",
    "Source",
    "AIConfig",
    "get_ai_config",
    "AlertAnalyzer",
]
