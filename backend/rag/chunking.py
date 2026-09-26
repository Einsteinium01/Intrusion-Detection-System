"""
backend/rag/chunking.py
========================
Deterministic document chunking for the local RAG knowledge system.

Design decisions
----------------
- Word-boundary splitting (not byte/character) so tokens stay semantically whole.
- Overlap preserves context across chunk boundaries.
- Chunk IDs are deterministic (see DocumentChunk.make_chunk_id) so repeated
  ingestion produces identical IDs → deduplication is trivially O(1).
- A Deduplicator is provided as a standalone helper for use by the vector store.
"""

from __future__ import annotations

import re
import logging
from typing import Any, Dict, Generator, Iterator, List

from backend.rag.schemas import DocumentChunk

log = logging.getLogger(__name__)


def _tokenise(text: str) -> List[str]:
    """Split text into word tokens, preserving whitespace separation."""
    return text.split()


def _detokenise(tokens: List[str]) -> str:
    """Re-join tokens into a string."""
    return " ".join(tokens)


# ---------------------------------------------------------------------------
# Core chunker
# ---------------------------------------------------------------------------

class TextChunker:
    """
    Splits a document text into overlapping word-boundary chunks.

    Each chunk carries a deterministic ``chunk_id`` derived from:
    ``source + document_id + position_index + first-64-chars-of-text``.

    This makes repeated ingestion of the same document produce the same IDs,
    enabling the vector store to skip already-indexed chunks.
    """

    def __init__(self, chunk_size: int = 512, overlap: int = 64) -> None:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if overlap < 0:
            raise ValueError("overlap must be non-negative")
        if overlap >= chunk_size:
            raise ValueError("overlap must be less than chunk_size")
        self.chunk_size = chunk_size
        self.overlap = overlap

    # ------------------------------------------------------------------
    def chunk(
        self,
        text: str,
        source: str,
        document_id: str,
        title: str,
        section: str = "",
        metadata: Dict[str, Any] | None = None,
    ) -> List[DocumentChunk]:
        """
        Split *text* into DocumentChunk objects.

        Parameters
        ----------
        text:
            Raw document text.
        source:
            Source category string ('mitre_attack', 'project_docs', …).
        document_id:
            Stable identifier for the parent document.
        title:
            Human-readable document title.
        section:
            Section heading within the document (may be empty).
        metadata:
            Additional key-value pairs to store with each chunk.

        Returns
        -------
        List[DocumentChunk]
            Non-empty list of chunks; at least one even for very short text.
        """
        if not text or not text.strip():
            return []

        metadata = metadata or {}
        tokens = _tokenise(text.strip())
        chunks: List[DocumentChunk] = []

        step = self.chunk_size - self.overlap
        if step <= 0:
            step = 1

        position = 0
        i = 0
        while i < len(tokens):
            window = tokens[i : i + self.chunk_size]
            chunk_text = _detokenise(window)

            chunk_id = DocumentChunk.make_chunk_id(
                source=source,
                document_id=document_id,
                position=position,
                text=chunk_text,
            )

            chunks.append(
                DocumentChunk(
                    chunk_id=chunk_id,
                    document_id=document_id,
                    text=chunk_text,
                    source=source,
                    title=title,
                    section=section,
                    metadata=dict(metadata),
                )
            )

            i += step
            position += 1

            # Don't produce a tiny trailing chunk if < 20% of chunk_size
            remaining = len(tokens) - i
            if 0 < remaining < max(1, self.chunk_size // 5):
                break

        log.debug(
            "TextChunker: %d chunks from document_id=%s (%d words)",
            len(chunks),
            document_id,
            len(tokens),
        )
        return chunks

    # ------------------------------------------------------------------
    def chunk_sections(
        self,
        sections: List[Dict[str, Any]],
        source: str,
        document_id: str,
        title: str,
        base_metadata: Dict[str, Any] | None = None,
    ) -> List[DocumentChunk]:
        """
        Chunk a list of ``{"heading": str, "text": str, "metadata": dict}``
        section dicts produced by document parsers.
        """
        all_chunks: List[DocumentChunk] = []
        base_metadata = base_metadata or {}
        for sec in sections:
            heading = sec.get("heading", "")
            text = sec.get("text", "")
            sec_meta = {**base_metadata, **sec.get("metadata", {})}
            chunks = self.chunk(
                text=text,
                source=source,
                document_id=document_id,
                title=title,
                section=heading,
                metadata=sec_meta,
            )
            all_chunks.extend(chunks)
        return all_chunks


# ---------------------------------------------------------------------------
# Deduplicator
# ---------------------------------------------------------------------------

class ChunkDeduplicator:
    """
    Filters out duplicate DocumentChunks based on their deterministic chunk_id.

    Usage::

        dedup = ChunkDeduplicator()
        unique = dedup.filter(chunks)

    The deduplicator maintains state across calls so it can be used
    incrementally during a multi-source ingest run.
    """

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def filter(self, chunks: List[DocumentChunk]) -> List[DocumentChunk]:
        """
        Return only chunks whose chunk_id has not been seen before.

        Thread-safety: not thread-safe; intended for single-threaded ingestion.
        """
        unique: List[DocumentChunk] = []
        for chunk in chunks:
            if chunk.chunk_id not in self._seen:
                self._seen.add(chunk.chunk_id)
                unique.append(chunk)
        return unique

    def already_indexed(self, chunk: DocumentChunk) -> bool:
        """Return True if this chunk_id was already seen."""
        return chunk.chunk_id in self._seen

    def add_known(self, chunk_ids: List[str]) -> None:
        """Register existing chunk_ids (e.g. loaded from the vector store)."""
        self._seen.update(chunk_ids)

    def reset(self) -> None:
        """Clear seen set. Useful when re-indexing from scratch."""
        self._seen.clear()

    @property
    def seen_count(self) -> int:
        return len(self._seen)
