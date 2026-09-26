"""
backend/rag/retriever.py
=========================
RAG retrieval layer: converts an AlertContext into a KnowledgeContext
containing relevant cybersecurity reference material.

Architecture
------------
  AlertContext → build_query() → embed → FAISS search → RetrievedDocument[]
              → KnowledgeContext (for PromptBuilder / AlertAnalyzer)

The retriever:
  1. Converts the alert into a textual query using relevant fields only
     (attack_type, detector, protocol, evidence summary, flow stats).
     Raw IP addresses and packet payloads are excluded from queries.
  2. Embeds the query using EmbeddingService (lazy-loaded model).
  3. Searches the FAISS index.
  4. Wraps results in KnowledgeContext.

SECURITY / GROUNDING
--------------------
- Retrieved documents are passed to the prompt builder under the label
  "UNTRUSTED KNOWLEDGE CONTEXT" (see prompt_builder.py Phase 2 update).
- Retrieved text is reference material only; the LLM is explicitly
  instructed not to treat it as observed network evidence.
- The retriever never modifies the AlertContext or the detector output.

Performance
-----------
- Retrieval is called once per AI analysis request (not per packet/flow).
- The embedding model is loaded lazily on first retrieval call.
- FAISS search on a small corpus (~thousands of chunks) is <5 ms.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from backend.ai.schemas import AlertContext, KnowledgeContext
from backend.rag.config import RAGConfig, get_rag_config
from backend.rag.embeddings import EmbeddingService, get_embedding_service
from backend.rag.schemas import RetrievedDocument
from backend.rag.vector_store import FAISSVectorStore, get_vector_store

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Query builder
# ---------------------------------------------------------------------------

def build_alert_query(alert: AlertContext) -> str:
    """
    Build a natural-language retrieval query from an AlertContext.

    Uses semantically rich fields while excluding:
    - Raw IP addresses (not useful for semantic search)
    - Port numbers alone (too generic without context)
    - Packet payloads (not present in AlertContext, but excluded by design)

    The resulting query is biased toward the attack type and evidence,
    which are the most useful signals for finding relevant MITRE techniques
    and investigation playbooks.
    """
    parts: List[str] = []

    # Primary classification signal
    parts.append(f"network intrusion {alert.attack_type}")

    # Detector name adds context (e.g. "ScanDetector" vs "XGBoost")
    parts.append(f"detected by {alert.detector}")

    # Protocol is relevant for technique matching
    parts.append(f"protocol {alert.protocol}")

    # Evidence strings are the richest signal
    for ev in alert.evidence[:5]:   # cap at 5 to keep query focused
        parts.append(ev)

    # Flow statistics add quantitative context
    if alert.flow_statistics:
        fs = alert.flow_statistics
        if fs.scan_type:
            parts.append(f"{fs.scan_type} scan")
        if fs.distinct_ports and fs.distinct_ports > 1:
            parts.append(f"{fs.distinct_ports} distinct ports scanned")
        if fs.distinct_hosts and fs.distinct_hosts > 1:
            parts.append(f"{fs.distinct_hosts} distinct hosts contacted")
        if fs.syn_count and fs.syn_count > 1:
            parts.append(f"{fs.syn_count} SYN probes")

    query = " ".join(parts)
    log.debug(
        "RAGRetriever: query for alert_id=%s: %s",
        alert.alert_id,
        query[:120],
    )
    return query


# ---------------------------------------------------------------------------
# Retriever
# ---------------------------------------------------------------------------

class RAGRetriever:
    """
    Retrieves relevant knowledge chunks for a given query or AlertContext.

    Usage::

        retriever = RAGRetriever()
        knowledge = retriever.retrieve_for_alert(alert_ctx, top_k=5)
        # knowledge is a KnowledgeContext ready for AlertAnalyzer.analyze()
    """

    def __init__(
        self,
        config: Optional[RAGConfig] = None,
        embedding_service: Optional[EmbeddingService] = None,
        vector_store: Optional[FAISSVectorStore] = None,
    ) -> None:
        self._config = config or get_rag_config()
        self._embedding_service = embedding_service  # lazy if None
        self._vector_store = vector_store  # lazy if None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def retrieve(
        self,
        query: str,
        top_k: Optional[int] = None,
    ) -> List[RetrievedDocument]:
        """
        Retrieve top-k documents relevant to *query*.

        Parameters
        ----------
        query:
            Free-text search query.
        top_k:
            Number of results; defaults to config's rag_top_k.

        Returns
        -------
        List[RetrievedDocument]
            Ranked by descending cosine similarity.
        """
        if not self._config.rag_enabled:
            log.debug("RAGRetriever: RAG disabled, returning empty results")
            return []

        store = self._get_store()
        if store.count() == 0:
            log.warning(
                "RAGRetriever: vector store is empty. "
                "Run: python -m backend.rag.ingest --source all"
            )
            return []

        top_k = top_k or self._config.rag_top_k
        embedding_svc = self._get_embedding_service()

        try:
            query_vector = embedding_svc.encode_single(query)
        except Exception as exc:
            log.error("RAGRetriever: embedding failed: %s", exc)
            return []

        results = store.search(
            query_vector=query_vector,
            top_k=top_k,
            min_score=self._config.rag_min_score,
        )
        log.info(
            "RAGRetriever: retrieved %d documents for query='%.80s'",
            len(results),
            query,
        )
        return results

    def retrieve_for_alert(
        self,
        alert: AlertContext,
        top_k: Optional[int] = None,
    ) -> KnowledgeContext:
        """
        Retrieve relevant knowledge for an IDS alert and wrap it in
        a KnowledgeContext ready for AlertAnalyzer.analyze().

        The retrieved documents are treated as UNTRUSTED reference material
        (the PromptBuilder labels them accordingly).

        Parameters
        ----------
        alert:
            Grounded AlertContext from the IDS pipeline.
        top_k:
            Number of documents to retrieve.

        Returns
        -------
        KnowledgeContext
            Populated with retrieved documents; empty if RAG is disabled
            or the index is not yet built.
        """
        query = build_alert_query(alert)
        docs = self.retrieve(query, top_k=top_k)

        knowledge_docs = [doc.to_knowledge_doc() for doc in docs]
        return KnowledgeContext(documents=knowledge_docs)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_embedding_service(self) -> EmbeddingService:
        if self._embedding_service is None:
            self._embedding_service = get_embedding_service(
                model_name=self._config.rag_embedding_model,
                batch_size=self._config.rag_embedding_batch_size,
            )
        return self._embedding_service

    def _get_store(self) -> FAISSVectorStore:
        if self._vector_store is None:
            embedding_svc = self._get_embedding_service()
            self._vector_store = get_vector_store(
                index_path=self._config.index_path,
                embedding_dim=embedding_svc.dim,
            )
        return self._vector_store


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_retriever: Optional[RAGRetriever] = None


def get_rag_retriever(config: Optional[RAGConfig] = None) -> RAGRetriever:
    """Return the process-level RAGRetriever singleton."""
    global _retriever
    if _retriever is None:
        _retriever = RAGRetriever(config=config or get_rag_config())
    return _retriever


def reset_rag_retriever() -> None:
    """Discard the cached singleton. For tests."""
    global _retriever
    _retriever = None
