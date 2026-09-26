"""
backend/rag/vector_store.py
============================
FAISS-based persistent vector store for the local RAG knowledge system.

Architecture
------------
- FAISS IndexFlatIP (Inner Product) is used because all embeddings are
  L2-normalized, so inner product = cosine similarity.
- Metadata (chunk text, source, title, …) is stored in a parallel JSON
  file alongside the FAISS binary index.
- The mapping between FAISS integer IDs and chunk metadata is deterministic:
  FAISS ID = insertion order index, recorded in a list that is persisted
  alongside the index.

Files written to rag_index_path/
  faiss.index       – FAISS binary index
  metadata.json     – list of DocumentChunk dicts (JSON)
  status.json       – {vector_count, indexed_sources, last_ingestion_time}

SECURITY
--------
- The index directory must NOT be served via Flask static routes.
- All data is local; no network I/O.
"""

from __future__ import annotations

import json
import logging
import pathlib
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from backend.rag.schemas import DocumentChunk, RetrievedDocument

log = logging.getLogger(__name__)

_INDEX_FILENAME = "faiss.index"
_META_FILENAME = "metadata.json"
_STATUS_FILENAME = "status.json"


class FAISSVectorStore:
    """
    Persistent FAISS vector store with parallel JSON metadata.

    Thread-safe for concurrent reads; writes use an internal lock.
    """

    def __init__(self, index_path: pathlib.Path, embedding_dim: int = 384) -> None:
        self._path = index_path
        self._dim = embedding_dim
        self._lock = threading.RLock()

        # In-memory state
        self._index = None          # faiss.Index
        self._metadata: List[Dict[str, Any]] = []   # parallel to FAISS IDs
        self._status: Dict[str, Any] = {
            "vector_count": 0,
            "indexed_sources": [],
            "last_ingestion_time": None,
        }
        self._is_loaded = False

    # ------------------------------------------------------------------
    # Public CRUD
    # ------------------------------------------------------------------

    def add_documents(self, chunks: List[DocumentChunk], embeddings: np.ndarray) -> int:
        """
        Add chunks and their embeddings to the index.

        Parameters
        ----------
        chunks:
            List of DocumentChunk objects (already deduplicated by caller).
        embeddings:
            float32 ndarray of shape (len(chunks), dim), L2-normalized.

        Returns
        -------
        int
            Number of vectors added.
        """
        if not chunks:
            return 0
        if len(chunks) != len(embeddings):
            raise ValueError(
                f"chunks ({len(chunks)}) and embeddings ({len(embeddings)}) length mismatch"
            )

        with self._lock:
            index = self._ensure_index()
            embeddings_f32 = embeddings.astype(np.float32)
            index.add(embeddings_f32)

            for chunk in chunks:
                self._metadata.append(chunk.model_dump())

            # Update status
            sources = list({c.source for c in chunks})
            existing = set(self._status.get("indexed_sources") or [])
            self._status["indexed_sources"] = sorted(existing | set(sources))
            self._status["vector_count"] = int(index.ntotal)
            self._status["last_ingestion_time"] = datetime.now(timezone.utc).isoformat()

            log.info(
                "FAISSVectorStore: added %d vectors (total=%d)",
                len(chunks),
                index.ntotal,
            )
            return len(chunks)

    def search(
        self,
        query_vector: np.ndarray,
        top_k: int = 5,
        min_score: float = 0.0,
    ) -> List[RetrievedDocument]:
        """
        Retrieve the top-k most similar documents.

        Parameters
        ----------
        query_vector:
            Shape (dim,) float32 L2-normalized query embedding.
        top_k:
            Maximum number of results to return.
        min_score:
            Minimum cosine similarity threshold.

        Returns
        -------
        List[RetrievedDocument]
            Ranked by descending similarity score.
        """
        with self._lock:
            index = self._ensure_index()
            if index.ntotal == 0:
                return []

            k = min(top_k, index.ntotal)
            qv = query_vector.astype(np.float32).reshape(1, -1)
            scores, ids = index.search(qv, k)

            results: List[RetrievedDocument] = []
            for score, idx in zip(scores[0], ids[0]):
                if idx < 0 or idx >= len(self._metadata):
                    continue
                cosine = float(score)
                # FAISS IP with L2-norm may give values slightly outside [0,1]
                cosine = max(0.0, min(1.0, cosine))
                if cosine < min_score:
                    continue
                meta = self._metadata[idx]
                results.append(
                    RetrievedDocument(
                        chunk_id=meta.get("chunk_id", ""),
                        document_id=meta.get("document_id", ""),
                        text=meta.get("text", ""),
                        source=meta.get("source", ""),
                        title=meta.get("title", ""),
                        section=meta.get("section", ""),
                        metadata=meta.get("metadata", {}),
                        score=cosine,
                    )
                )
            return results

    def save(self) -> None:
        """Persist the FAISS index and metadata to disk."""
        with self._lock:
            if self._index is None:
                return

            self._path.mkdir(parents=True, exist_ok=True)

            try:
                import faiss
                faiss.write_index(self._index, str(self._path / _INDEX_FILENAME))
            except Exception as exc:
                log.error("FAISSVectorStore.save: failed to write index: %s", exc)
                raise

            (self._path / _META_FILENAME).write_text(
                json.dumps(self._metadata, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            (self._path / _STATUS_FILENAME).write_text(
                json.dumps(self._status, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            log.info(
                "FAISSVectorStore: saved %d vectors to %s",
                self._index.ntotal,
                self._path,
            )

    def load(self) -> bool:
        """
        Load the FAISS index and metadata from disk.

        Returns True on success, False if no index exists yet.
        """
        with self._lock:
            index_file = self._path / _INDEX_FILENAME
            meta_file = self._path / _META_FILENAME
            status_file = self._path / _STATUS_FILENAME

            if not index_file.exists():
                log.debug("FAISSVectorStore: no saved index at %s", self._path)
                return False

            try:
                import faiss
                self._index = faiss.read_index(str(index_file))
            except Exception as exc:
                log.error("FAISSVectorStore.load: failed to read index: %s", exc)
                return False

            if meta_file.exists():
                raw = meta_file.read_text(encoding="utf-8")
                self._metadata = json.loads(raw)
            else:
                self._metadata = []

            if status_file.exists():
                raw = status_file.read_text(encoding="utf-8")
                self._status = json.loads(raw)

            self._is_loaded = True
            log.info(
                "FAISSVectorStore: loaded %d vectors from %s",
                self._index.ntotal,
                self._path,
            )
            return True

    def count(self) -> int:
        """Return the number of vectors currently in the index."""
        with self._lock:
            if self._index is None:
                return 0
            return int(self._index.ntotal)

    def clear(self) -> None:
        """Reset the in-memory index to empty."""
        with self._lock:
            try:
                import faiss
                self._index = faiss.IndexFlatIP(self._dim)
            except ImportError:
                self._index = None
            self._metadata = []
            self._status = {
                "vector_count": 0,
                "indexed_sources": [],
                "last_ingestion_time": None,
            }
            self._is_loaded = False
            log.info("FAISSVectorStore: cleared in-memory index")

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    @property
    def status(self) -> Dict[str, Any]:
        """Return a copy of the status dict."""
        with self._lock:
            return dict(self._status)

    @property
    def indexed_sources(self) -> List[str]:
        with self._lock:
            return list(self._status.get("indexed_sources") or [])

    @property
    def last_ingestion_time(self) -> Optional[str]:
        with self._lock:
            return self._status.get("last_ingestion_time")

    def get_all_chunk_ids(self) -> List[str]:
        """Return all chunk_ids in insertion order."""
        with self._lock:
            return [m.get("chunk_id", "") for m in self._metadata]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _ensure_index(self):
        """Return the FAISS index, creating it if necessary."""
        if self._index is None:
            try:
                import faiss
                self._index = faiss.IndexFlatIP(self._dim)
            except ImportError as exc:
                raise RuntimeError(
                    "faiss-cpu is not installed. Run: pip install faiss-cpu"
                ) from exc
        return self._index


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_store: Optional[FAISSVectorStore] = None


def get_vector_store(
    index_path: Optional[pathlib.Path] = None,
    embedding_dim: int = 384,
) -> FAISSVectorStore:
    """Return (and cache) the process-level FAISSVectorStore singleton."""
    global _store
    if _store is None:
        if index_path is None:
            from backend.rag.config import get_rag_config
            index_path = get_rag_config().index_path
        _store = FAISSVectorStore(index_path=index_path, embedding_dim=embedding_dim)
        _store.load()   # no-op if no index exists yet
    return _store


def reset_vector_store() -> None:
    """Discard the cached singleton. For tests."""
    global _store
    _store = None
