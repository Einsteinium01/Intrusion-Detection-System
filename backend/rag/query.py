"""
backend/rag/query.py
====================
CLI tool for querying the local RAG knowledge index.

Usage::

  python -m backend.rag.query "How is a SYN scan detected?"
  python -m backend.rag.query "MITRE T1046 network service discovery"
  python -m backend.rag.query "PortScan detection thresholds" --top-k 10

This module can also be imported and used in test scripts.
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional


def run_query(query: str, top_k: int = 5) -> List[dict]:
    """
    Execute a knowledge query and return results as plain dicts.

    Parameters
    ----------
    query:
        Free-text search query.
    top_k:
        Maximum number of results to return.

    Returns
    -------
    List[dict]
        Each dict contains: title, source, section, score, text excerpt.
    """
    from backend.rag.retriever import RAGRetriever
    retriever = RAGRetriever()
    docs = retriever.retrieve(query, top_k=top_k)
    return [doc.to_knowledge_doc() for doc in docs]


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m backend.rag.query",
        description="Query the local RAG knowledge index.",
    )
    p.add_argument("query", help="Natural language query string.")
    p.add_argument(
        "--top-k", "-k",
        type=int,
        default=5,
        help="Number of results to return (default: 5).",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show full text of each result.",
    )
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry-point."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s  %(message)s",
    )

    print(f"\nRAG Query: '{args.query}' (top_k={args.top_k})\n")

    try:
        results = run_query(args.query, top_k=args.top_k)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        print(
            "\nHint: build the index first with:\n"
            "  python -m backend.rag.ingest --source all",
            file=sys.stderr,
        )
        return 1

    if not results:
        print("No results found.")
        print(
            "\nHint: the index may be empty. Build it with:\n"
            "  python -m backend.rag.ingest --source all"
        )
        return 0

    BOLD = "\033[1m"
    CYAN = "\033[36m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"

    for i, doc in enumerate(results, start=1):
        score = doc.get("relevance_score", 0)
        title = doc.get("title", "Unknown")
        source = doc.get("source", "")
        section = doc.get("section", "")
        text = doc.get("text", "")

        print(f"{CYAN}[{i}]{RESET} {BOLD}{title}{RESET}  {YELLOW}score={score:.4f}{RESET}")
        print(f"     source={source}  section='{section}'")
        if args.verbose:
            safe_text = text[:400].encode("ascii", errors="replace").decode("ascii")
            print(f"     text: {safe_text}{'...' if len(text) > 400 else ''}")
        else:
            excerpt = text[:150].replace("\n", " ")
            safe_excerpt = excerpt.encode("ascii", errors="replace").decode("ascii")
            print(f"     {safe_excerpt}{'...' if len(text) > 150 else ''}")
        print()

    return 0


if __name__ == "__main__":
    # Ensure UTF-8 output on Windows terminals (best effort)
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    sys.exit(main())
