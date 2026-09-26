"""
backend/rag/schemas.py
=======================
Pydantic schemas for the local RAG knowledge system.

DocumentChunk   – atomic unit of indexed text; deterministic chunk_id
RetrievedDocument – chunk returned from the vector store with a score
IngestionStats  – summary returned after a rebuild/ingest operation
RAGStatus       – health/status dict for the /api/rag/status endpoint
"""

from __future__ import annotations

import hashlib
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ---------------------------------------------------------------------------
# Core chunk schema
# ---------------------------------------------------------------------------

class DocumentChunk(BaseModel):
    """
    Atomic unit of indexed knowledge.

    chunk_id is deterministic: SHA-256( source + document_id + position + text[:64] )
    truncated to 16 hex chars.  This makes deduplication and re-ingestion
    idempotent.
    """

    model_config = ConfigDict(frozen=True)

    chunk_id: str = Field(
        description="Deterministic 16-char hex ID derived from content + position."
    )
    document_id: str = Field(
        description="Stable identifier for the parent document."
    )
    text: str = Field(
        description="The chunk text that will be embedded and indexed."
    )
    source: str = Field(
        description=(
            "Source category: 'mitre_attack' | 'project_docs' | "
            "'detection_docs' | 'playbooks' | 'attack_docs'."
        )
    )
    title: str = Field(
        description="Human-readable title of the parent document."
    )
    section: str = Field(
        default="",
        description="Section/heading under which this chunk appears.",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional structured metadata: technique_id, tactic, version, etc."
        ),
    )

    @classmethod
    def make_chunk_id(
        cls,
        source: str,
        document_id: str,
        position: int,
        text: str,
    ) -> str:
        """
        Produce a deterministic 16-char hex chunk ID.

        Input: source + document_id + zero-padded position + first 64 chars of text.
        Hash: SHA-256, first 8 bytes → 16 hex chars.
        """
        key = f"{source}|{document_id}|{position:06d}|{text[:64]}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Retrieved document (chunk + score)
# ---------------------------------------------------------------------------

class RetrievedDocument(BaseModel):
    """
    A DocumentChunk returned from the vector store, annotated with a
    cosine-similarity relevance score in [0.0, 1.0].
    """

    chunk_id: str
    document_id: str
    text: str
    source: str
    title: str
    section: str = ""
    metadata: Dict[str, Any] = Field(default_factory=dict)
    score: float = Field(
        ge=0.0, le=1.0,
        description="Cosine similarity score in [0.0, 1.0].",
    )

    def to_knowledge_doc(self) -> Dict[str, Any]:
        """
        Convert to the dict format expected by KnowledgeContext.documents.

        The source_id is a stable, human-readable reference the LLM can
        cite in its AlertAnalysis.sources list.
        """
        tech_id = self.metadata.get("technique_id", "")
        if tech_id:
            source_id = f"MITRE-{tech_id}"
        else:
            source_id = self.chunk_id

        return {
            "source_id": source_id,
            "title": self.title,
            "text": self.text,
            "relevance_score": round(self.score, 4),
            "source": self.source,
            "section": self.section,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Ingestion / status schemas
# ---------------------------------------------------------------------------

class IngestionStats(BaseModel):
    """Summary returned after an ingest or reindex operation."""

    total_chunks: int = 0
    new_chunks: int = 0
    duplicate_chunks: int = 0
    sources_processed: List[str] = Field(default_factory=list)
    documents_processed: int = 0
    errors: List[str] = Field(default_factory=list)
    duration_seconds: float = 0.0


class RAGStatus(BaseModel):
    """Health and configuration status for the RAG layer."""

    rag_enabled: bool
    embedding_model: str
    vector_count: int = 0
    indexed_sources: List[str] = Field(default_factory=list)
    index_ready: bool = False
    last_ingestion_time: Optional[str] = None
    last_error: Optional[str] = None
    top_k: int = 5
