"""
backend/rag/config.py
======================
Environment-driven configuration for the local RAG knowledge system.

All defaults are chosen to be usable on a CPU-only machine:
  - all-MiniLM-L6-v2 is ~22 MB, fast on CPU, 384-dim embeddings
  - FAISS Flat index is exact (no approximation needed at small corpus size)
  - chunk_size / overlap match typical security document paragraphs

SECURITY
--------
- RAG_INDEX_PATH must resolve inside the project; never serve it via Flask
  static routes.
- The embedding model is loaded locally; no network calls after first download.
- No secrets, .env files, or API keys are ever written to the index.
"""

from __future__ import annotations

import pathlib
import logging
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
_ROOT = pathlib.Path(__file__).resolve().parent.parent.parent  # project root
_DEFAULT_INDEX_PATH = _ROOT / "data" / "rag" / "index"
_DEFAULT_DOCS_PATH = _ROOT / "data" / "rag" / "documents"
_DEFAULT_META_PATH = _ROOT / "data" / "rag" / "metadata"


class RAGConfig(BaseSettings):
    """
    Runtime configuration for the local RAG system.

    Environment variable names match field names (case-insensitive).
    A .env file in the project root is loaded automatically.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Feature flag ─────────────────────────────────────────────────────────
    rag_enabled: bool = True
    """Set RAG_ENABLED=false to bypass retrieval entirely."""

    # ── Embedding model ──────────────────────────────────────────────────────
    rag_embedding_model: str = "all-MiniLM-L6-v2"
    """
    sentence-transformers model name.
    Must be available locally or downloadable on first run.
    all-MiniLM-L6-v2 is recommended: 22 MB, CPU-friendly, 384-dim.
    """

    rag_embedding_batch_size: int = 32
    """Number of texts embedded per batch call."""

    # ── Retrieval ────────────────────────────────────────────────────────────
    rag_top_k: int = 5
    """Default number of documents retrieved per query."""

    rag_min_score: float = 0.0
    """
    Minimum cosine similarity score for a retrieved document to be included.
    Range [0.0, 1.0]; 0.0 = include all top-k results.
    """

    # ── Chunking ─────────────────────────────────────────────────────────────
    rag_chunk_size: int = 512
    """Maximum number of tokens/words per chunk."""

    rag_chunk_overlap: int = 64
    """Number of words overlap between adjacent chunks."""

    # ── Persistence paths ────────────────────────────────────────────────────
    rag_index_path: str = str(_DEFAULT_INDEX_PATH)
    """Directory where the FAISS index files are stored."""

    rag_docs_path: str = str(_DEFAULT_DOCS_PATH)
    """Directory for raw ingested document copies (optional cache)."""

    rag_metadata_path: str = str(_DEFAULT_META_PATH)
    """Directory for chunk metadata JSON files."""

    # ── Source ingestion ─────────────────────────────────────────────────────
    rag_project_root: str = str(_ROOT)
    """Project root used when scanning for local documentation."""

    # ── Properties ───────────────────────────────────────────────────────────
    @property
    def index_path(self) -> pathlib.Path:
        return pathlib.Path(self.rag_index_path)

    @property
    def docs_path(self) -> pathlib.Path:
        return pathlib.Path(self.rag_docs_path)

    @property
    def metadata_path(self) -> pathlib.Path:
        return pathlib.Path(self.rag_metadata_path)

    @property
    def project_root(self) -> pathlib.Path:
        return pathlib.Path(self.rag_project_root)

    def ensure_dirs(self) -> None:
        """Create storage directories if they do not exist."""
        for p in [self.index_path, self.docs_path, self.metadata_path]:
            p.mkdir(parents=True, exist_ok=True)

    def to_public_dict(self) -> dict:
        """Safe dict for API responses — no paths that leak server layout."""
        return {
            "rag_enabled": self.rag_enabled,
            "embedding_model": self.rag_embedding_model,
            "top_k": self.rag_top_k,
            "chunk_size": self.rag_chunk_size,
            "chunk_overlap": self.rag_chunk_overlap,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_config: Optional[RAGConfig] = None


def get_rag_config() -> RAGConfig:
    """Return the process-level RAGConfig singleton."""
    global _config
    if _config is None:
        _config = RAGConfig()
        log.debug(
            "RAGConfig loaded: enabled=%s model=%s top_k=%s",
            _config.rag_enabled,
            _config.rag_embedding_model,
            _config.rag_top_k,
        )
    return _config


def reset_rag_config() -> None:
    """Discard cached singleton. For tests."""
    global _config
    _config = None
