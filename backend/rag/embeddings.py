"""
backend/rag/embeddings.py
==========================
Local embedding service using sentence-transformers.

Design decisions
----------------
- Lazy loading: the model is only loaded when the first embedding is requested.
  This avoids a slow startup for processes that don't need embeddings (tests,
  API health checks).
- Normalized embeddings: all vectors are L2-normalized so cosine similarity
  can be computed with a simple dot product (FAISS IndexFlatIP).
- Batch processing: encode() calls are batched for efficiency.
- No network calls after the model is locally cached by sentence-transformers.

SECURITY
--------
- The model is loaded from the local sentence-transformers cache.
- No data is sent outside the process.
"""

from __future__ import annotations

import logging
import threading
from typing import List, Optional

import numpy as np

log = logging.getLogger(__name__)


class EmbeddingService:
    """
    Wraps a sentence-transformers model for embedding text chunks.

    Thread-safe: model loading uses a lock; encode() is stateless.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2", batch_size: int = 32) -> None:
        self._model_name = model_name
        self._batch_size = batch_size
        self._model = None
        self._dim: Optional[int] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def encode(self, texts: List[str]) -> np.ndarray:
        """
        Embed a list of texts and return L2-normalized float32 vectors.

        Parameters
        ----------
        texts:
            Non-empty list of strings.

        Returns
        -------
        np.ndarray
            Shape (len(texts), embedding_dim), dtype float32, L2-normalized.

        Raises
        ------
        RuntimeError
            If the sentence-transformers model cannot be loaded.
        ValueError
            If *texts* is empty.
        """
        if not texts:
            raise ValueError("EmbeddingService.encode() requires at least one text.")

        model = self._get_model()

        vectors = model.encode(
            texts,
            batch_size=self._batch_size,
            show_progress_bar=False,
            normalize_embeddings=True,   # L2-normalize at source
            convert_to_numpy=True,
        )

        # Ensure float32 (model may return float16 on some hardware)
        vectors = vectors.astype(np.float32)

        # Double-check normalization (guard against model returning non-unit)
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms = np.where(norms == 0, 1.0, norms)   # avoid /0
        vectors = vectors / norms

        log.debug(
            "EmbeddingService: encoded %d texts → shape %s",
            len(texts),
            vectors.shape,
        )
        return vectors

    def encode_single(self, text: str) -> np.ndarray:
        """Embed a single text; returns shape (dim,) float32 vector."""
        return self.encode([text])[0]

    @property
    def dim(self) -> int:
        """Embedding dimension (loaded lazily)."""
        if self._dim is None:
            self._get_model()
        return self._dim  # type: ignore[return-value]

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def is_loaded(self) -> bool:
        return self._model is not None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_model(self):
        """Load and cache the model (thread-safe, lazy)."""
        if self._model is not None:
            return self._model

        with self._lock:
            if self._model is not None:   # double-checked locking
                return self._model
            try:
                from sentence_transformers import SentenceTransformer
            except ImportError as exc:
                raise RuntimeError(
                    "sentence-transformers is not installed. "
                    "Run: pip install sentence-transformers"
                ) from exc

            log.info("EmbeddingService: loading model '%s' …", self._model_name)
            try:
                model = SentenceTransformer(self._model_name)
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to load embedding model '{self._model_name}': {exc}"
                ) from exc

            self._dim = (
                model.get_embedding_dimension()
                if hasattr(model, "get_embedding_dimension")
                else model.get_sentence_embedding_dimension()
            )
            self._model = model
            log.info(
                "EmbeddingService: model loaded, dim=%d", self._dim
            )
        return self._model


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_service: Optional[EmbeddingService] = None


def get_embedding_service(
    model_name: str = "all-MiniLM-L6-v2",
    batch_size: int = 32,
) -> EmbeddingService:
    """
    Return (and cache) the process-level EmbeddingService.

    Parameters take effect only on first call.
    """
    global _service
    if _service is None:
        _service = EmbeddingService(model_name=model_name, batch_size=batch_size)
    return _service


def reset_embedding_service() -> None:
    """Discard the cached singleton.  For tests."""
    global _service
    _service = None
