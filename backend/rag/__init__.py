"""
backend/rag/__init__.py
========================
Local RAG (Retrieval-Augmented Generation) knowledge system.

Phase 2: Enriches IDS alert analysis with locally-indexed cybersecurity
knowledge — MITRE ATT&CK, project documentation, detection playbooks.

The RAG layer is purely an enrichment layer.  It does NOT:
  - perform intrusion detection
  - replace or override XGBoost / ScanDetector classifications
  - make network traffic decisions
  - transmit data to external services

Public surface:

  RAGConfig          – environment-driven configuration
  DocumentChunk      – atomic unit of indexed knowledge
  RetrievedDocument  – chunk + retrieval score
  RAGRetriever       – retrieve(query) → KnowledgeContext
  get_rag_retriever  – process-level singleton retriever
  get_rag_config     – process-level singleton config
"""

from backend.rag.config import RAGConfig, get_rag_config
from backend.rag.schemas import DocumentChunk, RetrievedDocument
from backend.rag.retriever import RAGRetriever, get_rag_retriever

__all__ = [
    "RAGConfig",
    "get_rag_config",
    "DocumentChunk",
    "RetrievedDocument",
    "RAGRetriever",
    "get_rag_retriever",
]
