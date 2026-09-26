"""
backend/rag/ingest.py
======================
Ingestion orchestrator for the local RAG knowledge system.

Responsibilities
----------------
1. Load all chunks from configured source adapters.
2. Deduplicate chunks (by chunk_id).
3. Embed chunks in batches using EmbeddingService.
4. Add vectors + metadata to the FAISSVectorStore.
5. Persist the index to disk.
6. Return IngestionStats.

CLI Usage (as module)
---------------------
  python -m backend.rag.ingest --source all
  python -m backend.rag.ingest --source project
  python -m backend.rag.ingest --source mitre
  python -m backend.rag.ingest --source all --rebuild

The --rebuild flag clears the existing index before ingesting.

Performance notes
-----------------
- Embedding is the bottleneck; sentence-transformers is single-threaded
  but processes batches efficiently on CPU.
- FAISS indexing is fast even for tens of thousands of chunks.
- Total ingestion time for project docs: ~5-30 seconds on CPU.
- Total ingestion time for full MITRE ATT&CK: ~1-3 minutes on CPU.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from typing import List, Optional

from backend.rag.chunking import ChunkDeduplicator, TextChunker
from backend.rag.config import RAGConfig, get_rag_config
from backend.rag.embeddings import EmbeddingService, get_embedding_service
from backend.rag.schemas import DocumentChunk, IngestionStats
from backend.rag.sources.mitre import MitreAttackAdapter
from backend.rag.sources.project_docs import ProjectDocsAdapter
from backend.rag.vector_store import FAISSVectorStore, get_vector_store, reset_vector_store

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core ingestion function
# ---------------------------------------------------------------------------

def ingest(
    source: str = "all",
    rebuild: bool = False,
    config: Optional[RAGConfig] = None,
    embedding_service: Optional[EmbeddingService] = None,
    vector_store: Optional[FAISSVectorStore] = None,
    mitre_bundle_path: Optional[str] = None,
) -> IngestionStats:
    """
    Run the ingestion pipeline for one or more sources.

    Parameters
    ----------
    source:
        'all' | 'project' | 'mitre'
    rebuild:
        If True, clear the existing index before ingesting.
    config:
        RAGConfig; uses singleton if None.
    embedding_service:
        EmbeddingService; uses singleton if None.
    vector_store:
        FAISSVectorStore; uses singleton if None.
    mitre_bundle_path:
        Override path for MITRE STIX bundle.

    Returns
    -------
    IngestionStats
    """
    t0 = time.perf_counter()
    cfg = config or get_rag_config()
    cfg.ensure_dirs()

    emb_svc = embedding_service or get_embedding_service(
        model_name=cfg.rag_embedding_model,
        batch_size=cfg.rag_embedding_batch_size,
    )

    if vector_store is None:
        # Need dim to initialise store; load/warm embedding service first
        dim = emb_svc.dim
        store = get_vector_store(
            index_path=cfg.index_path,
            embedding_dim=dim,
        )
    else:
        store = vector_store

    stats = IngestionStats()
    dedup = ChunkDeduplicator()

    # Register already-indexed chunk IDs for deduplication when not rebuilding
    if rebuild:
        store.clear()
        log.info("Ingest: cleared existing index (--rebuild)")
    else:
        dedup.add_known(store.get_all_chunk_ids())
        log.info(
            "Ingest: %d already-indexed chunks registered for dedup",
            dedup.seen_count,
        )

    chunker = TextChunker(
        chunk_size=cfg.rag_chunk_size,
        overlap=cfg.rag_chunk_overlap,
    )

    # ── Project documentation ─────────────────────────────────────────────
    if source in ("all", "project"):
        log.info("Ingest: ingesting project documentation …")
        proj_adapter = ProjectDocsAdapter(project_root=cfg.project_root, chunker=chunker)
        try:
            proj_chunks = proj_adapter.load_chunks()
            _process_source(proj_chunks, dedup, emb_svc, store, stats, "project_docs")
        except Exception as exc:
            msg = f"project_docs: {exc}"
            stats.errors.append(msg)
            log.error("Ingest: %s", msg)

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────
    if source in ("all", "mitre"):
        import pathlib
        bundle_path = pathlib.Path(mitre_bundle_path) if mitre_bundle_path else None
        mitre_adapter = MitreAttackAdapter(bundle_path=bundle_path, chunker=chunker)

        if not mitre_adapter.is_available():
            msg = (
                "MITRE ATT&CK STIX bundle not found. "
                "Download enterprise-attack.json from "
                "https://github.com/mitre/cti and place it at "
                "data/rag/documents/enterprise-attack.json"
            )
            log.warning("Ingest: %s", msg)
            stats.errors.append(f"mitre: {msg}")
        else:
            log.info("Ingest: ingesting MITRE ATT&CK …")
            try:
                mitre_chunks = mitre_adapter.load_chunks()
                _process_source(mitre_chunks, dedup, emb_svc, store, stats, "mitre_attack")
            except Exception as exc:
                msg = f"mitre_attack: {exc}"
                stats.errors.append(msg)
                log.error("Ingest: %s", msg)

    # ── Persist ───────────────────────────────────────────────────────────
    if stats.new_chunks > 0:
        log.info("Ingest: saving index (%d total vectors) …", store.count())
        store.save()
    else:
        log.info("Ingest: no new chunks to persist")

    stats.duration_seconds = round(time.perf_counter() - t0, 2)
    log.info(
        "Ingest: complete — %d new chunks, %d duplicates, %.2fs",
        stats.new_chunks,
        stats.duplicate_chunks,
        stats.duration_seconds,
    )
    return stats


def _process_source(
    chunks: List[DocumentChunk],
    dedup: ChunkDeduplicator,
    emb_svc: EmbeddingService,
    store: FAISSVectorStore,
    stats: IngestionStats,
    source_name: str,
) -> None:
    """Embed and index a list of chunks from a single source."""
    stats.documents_processed += len({c.document_id for c in chunks})
    stats.total_chunks += len(chunks)

    unique = dedup.filter(chunks)
    duplicates = len(chunks) - len(unique)
    stats.duplicate_chunks += duplicates
    stats.new_chunks += len(unique)

    if source_name not in stats.sources_processed:
        stats.sources_processed.append(source_name)

    if not unique:
        log.info("Ingest [%s]: all %d chunks already indexed", source_name, len(chunks))
        return

    log.info(
        "Ingest [%s]: embedding %d new chunks (skipping %d duplicates) …",
        source_name,
        len(unique),
        duplicates,
    )

    texts = [c.text for c in unique]
    embeddings = emb_svc.encode(texts)
    added = store.add_documents(unique, embeddings)
    log.info("Ingest [%s]: added %d vectors to index", source_name, added)


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m backend.rag.ingest",
        description="Build or update the local RAG knowledge index.",
    )
    p.add_argument(
        "--source",
        choices=["all", "project", "mitre"],
        default="all",
        help="Which knowledge source to ingest (default: all).",
    )
    p.add_argument(
        "--rebuild",
        action="store_true",
        help="Clear the existing index and rebuild from scratch.",
    )
    p.add_argument(
        "--mitre-bundle",
        metavar="PATH",
        help="Path to the MITRE ATT&CK STIX bundle JSON (optional override).",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable DEBUG logging.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI main entry-point. Returns exit code."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    )

    print(f"RAG Ingestion -- source={args.source} rebuild={args.rebuild}")
    print("Loading embedding model (may take a moment on first run) ...")

    try:
        stats = ingest(
            source=args.source,
            rebuild=args.rebuild,
            mitre_bundle_path=args.mitre_bundle,
        )
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]")
        return 1
    except Exception as exc:
        print(f"\n[ERROR] {exc}", file=sys.stderr)
        return 1

    print("\n--- Ingestion Results -------------------------------------------")
    print(f"  Sources processed : {', '.join(stats.sources_processed) or 'none'}")
    print(f"  Documents         : {stats.documents_processed}")
    print(f"  Total chunks      : {stats.total_chunks}")
    print(f"  New chunks        : {stats.new_chunks}")
    print(f"  Duplicates        : {stats.duplicate_chunks}")
    print(f"  Duration          : {stats.duration_seconds:.2f}s")
    if stats.errors:
        print("\n  Warnings/Errors:")
        for err in stats.errors:
            print(f"    ! {err}")

    return 0


if __name__ == "__main__":
    # Ensure UTF-8 output on Windows terminals
    import io
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    sys.exit(main())
