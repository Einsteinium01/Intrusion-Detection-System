"""
backend/rag/sources/mitre.py
=============================
MITRE ATT&CK Enterprise ingestion adapter.

This adapter processes the official MITRE ATT&CK STIX 2.1 JSON bundle
(available at https://github.com/mitre/cti) and produces DocumentChunks
suitable for the local RAG knowledge system.

What is indexed
---------------
- attack-pattern objects (techniques and sub-techniques)
- description text
- external references (technique IDs, URLs)
- tactic associations
- platform information

What is NOT indexed
-------------------
- Relationship objects (only the technique descriptions are needed)
- Tool/Malware objects (out of scope for Phase 2)
- Course-of-action objects

IMPORTANT NOTES
---------------
1. This adapter does NOT download the STIX bundle automatically.
   The user must place the bundle at data/rag/documents/enterprise-attack.json
   or pass a custom path.

2. For tests, a tiny local fixture is used instead of the full bundle.
   See tests/fixtures/rag/mitre_fixture.json

3. Technique descriptions can be long; the chunker splits them if needed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import re
from typing import Any, Dict, Iterator, List, Optional

from backend.rag.chunking import TextChunker
from backend.rag.schemas import DocumentChunk

log = logging.getLogger(__name__)

SOURCE_NAME = "mitre_attack"
DEFAULT_BUNDLE_PATH = (
    pathlib.Path(__file__).resolve().parent.parent.parent.parent
    / "data" / "rag" / "documents" / "enterprise-attack.json"
)


class MitreAttackAdapter:
    """
    Ingests the MITRE ATT&CK Enterprise STIX JSON bundle into DocumentChunks.

    Usage::

        adapter = MitreAttackAdapter(bundle_path=Path("...enterprise-attack.json"))
        chunks = adapter.load_chunks(chunker)
    """

    def __init__(
        self,
        bundle_path: Optional[pathlib.Path] = None,
        chunker: Optional[TextChunker] = None,
    ) -> None:
        self._bundle_path = bundle_path or DEFAULT_BUNDLE_PATH
        self._chunker = chunker or TextChunker(chunk_size=400, overlap=50)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """Return True if the STIX bundle file exists."""
        return self._bundle_path.exists()

    def load_chunks(self, chunker: Optional[TextChunker] = None) -> List[DocumentChunk]:
        """
        Parse the STIX bundle and return all DocumentChunks.

        Raises
        ------
        FileNotFoundError
            If the bundle does not exist.
        ValueError
            If the bundle is not a valid STIX 2.x bundle.
        """
        if not self.is_available():
            raise FileNotFoundError(
                f"MITRE ATT&CK STIX bundle not found at: {self._bundle_path}\n"
                "Download it from: https://github.com/mitre/cti/raw/master/"
                "enterprise-attack/enterprise-attack.json\n"
                "and place it at data/rag/documents/enterprise-attack.json"
            )

        chunker = chunker or self._chunker
        log.info("MitreAttackAdapter: loading bundle from %s", self._bundle_path)

        with open(self._bundle_path, encoding="utf-8") as f:
            bundle = json.load(f)

        if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
            raise ValueError(
                f"File at {self._bundle_path} is not a STIX 2.x bundle."
            )

        objects = bundle.get("objects", [])
        techniques = [o for o in objects if o.get("type") == "attack-pattern"]
        log.info(
            "MitreAttackAdapter: found %d attack-pattern objects",
            len(techniques),
        )

        all_chunks: List[DocumentChunk] = []
        for technique in techniques:
            chunks = self._process_technique(technique, chunker)
            all_chunks.extend(chunks)

        log.info(
            "MitreAttackAdapter: produced %d chunks from %d techniques",
            len(all_chunks),
            len(techniques),
        )
        return all_chunks

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _process_technique(
        self, obj: Dict[str, Any], chunker: TextChunker
    ) -> List[DocumentChunk]:
        """Extract and chunk a single attack-pattern object."""
        # Technique ID from external_references
        technique_id = ""
        technique_url = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                technique_id = ref.get("external_id", "")
                technique_url = ref.get("url", "")
                break

        if not technique_id:
            return []  # skip techniques without a MITRE ID

        technique_name = obj.get("name", "Unknown Technique")
        description = obj.get("description", "").strip()
        stix_id = obj.get("id", "")
        modified = obj.get("modified", "")

        # Tactics: x_mitre_tactics is a list of phase names in older bundles;
        # in newer bundles we look at kill_chain_phases
        tactics: List[str] = []
        for kcp in obj.get("kill_chain_phases", []):
            if kcp.get("kill_chain_name") == "mitre-attack":
                tactics.append(kcp.get("phase_name", ""))

        # Platforms
        platforms: List[str] = obj.get("x_mitre_platforms", [])

        # Is sub-technique?
        is_subtechnique = "." in technique_id

        # Detection guidance (if present)
        detection = obj.get("x_mitre_detection", "").strip()

        # Build the text to be indexed
        text_parts: List[str] = [
            f"MITRE ATT&CK Technique: {technique_id} - {technique_name}",
        ]
        if tactics:
            text_parts.append(f"Tactics: {', '.join(tactics)}")
        if platforms:
            text_parts.append(f"Platforms: {', '.join(platforms)}")
        if description:
            text_parts.append(f"\nDescription:\n{description}")
        if detection:
            text_parts.append(f"\nDetection:\n{detection}")

        full_text = "\n".join(text_parts)

        document_id = f"mitre-{technique_id.replace('.', '-').lower()}"
        title = f"{technique_id}: {technique_name}"

        metadata: Dict[str, Any] = {
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactics": tactics,
            "platforms": platforms,
            "stix_id": stix_id,
            "is_subtechnique": is_subtechnique,
            "modified": modified,
            "url": technique_url,
        }

        return chunker.chunk(
            text=full_text,
            source=SOURCE_NAME,
            document_id=document_id,
            title=title,
            section=", ".join(tactics) if tactics else "",
            metadata=metadata,
        )
