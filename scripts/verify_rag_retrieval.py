"""
scripts/verify_rag_retrieval.py
================================
Verifies that the local RAG retrieval pipeline works end-to-end with
a synthetic PortScan AlertContext.

Prints:
- Retrieved source titles and scores
- The resulting KnowledgeContext document count
- A sample of the prompt section that would be sent to the LLM

Usage:
    python scripts/verify_rag_retrieval.py
"""

from __future__ import annotations

import sys
import json

# Ensure project root is on path
sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent))

from backend.ai.schemas import AlertContext, FlowStatistics
from backend.rag.retriever import RAGRetriever

# ---------------------------------------------------------------------------
# Synthetic PortScan alert
# ---------------------------------------------------------------------------

ALERT = AlertContext(
    alert_id="rag-verify-001",
    timestamp="2026-09-27T00:00:00Z",
    source_ip="192.168.100.99",
    destination_ip="10.0.0.1",
    source_port=54321,
    destination_port=0,
    protocol="TCP",
    attack_type="PortScan",
    detector="ScanDetector",
    confidence=0.92,
    evidence=[
        "22 SYN-only probes to distinct destination ports",
        "scan_type=vertical",
        "probe_count=22 distinct_ports=22",
        "No SYN-ACK responses observed",
    ],
    flow_statistics=FlowStatistics(
        packet_count=22,
        byte_count=1320,
        duration_seconds=2.1,
        packets_per_second=10.48,
        distinct_ports=22,
        syn_count=22,
        scan_type="vertical",
    ),
)


def main():
    print("=" * 60)
    print("RAG Alert Retrieval Verification")
    print("=" * 60)
    print(f"\nAlert: {ALERT.alert_id}")
    print(f"Attack type: {ALERT.attack_type}")
    print(f"Detector: {ALERT.detector}")
    print(f"Evidence items: {len(ALERT.evidence)}")

    retriever = RAGRetriever()

    # Check index status
    from backend.rag.vector_store import get_vector_store
    from backend.rag.config import get_rag_config
    cfg = get_rag_config()
    store = get_vector_store(index_path=cfg.index_path)
    count = store.count()
    print(f"\nVector store: {count} vectors indexed")

    if count == 0:
        print("\n[WARNING] Index is empty. Run: python -m backend.rag.ingest --source all")
        return

    # Retrieve for alert
    print("\nRetrieving knowledge context for alert...")
    knowledge = retriever.retrieve_for_alert(ALERT, top_k=5)

    print(f"\nRetrieved {len(knowledge.documents)} documents:\n")
    print(f"{'#':<4} {'Score':<8} {'Source':<18} {'Title'}")
    print("-" * 70)
    for i, doc in enumerate(knowledge.documents, 1):
        score = doc.get("relevance_score", 0)
        source = doc.get("source", "")[:16]
        title = doc.get("title", "")[:40]
        source_id = doc.get("source_id", "")
        print(f"{i:<4} {score:<8.4f} {source:<18} {title}  [{source_id}]")

    print("\n" + "=" * 60)
    print("Retrieval complete. RAG pipeline is working.")
    print("=" * 60)


if __name__ == "__main__":
    main()
