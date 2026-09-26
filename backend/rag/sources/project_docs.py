"""
backend/rag/sources/project_docs.py
=====================================
Project documentation ingestion adapter.

Scans the repository for human-readable Markdown and text documentation
files and converts them into DocumentChunks for the local RAG index.

WHAT IS INDEXED
---------------
- README.md, DESIGN.md, PROJECT_SPEC.md at project root
- docs/**/*.md (if a docs/ directory exists)
- Any *.md files in detection-related modules
  (feature_extraction/, backend/, packet_capture/)
- reports/*.txt (training reports, comparison reports)

WHAT IS EXPLICITLY EXCLUDED
----------------------------
- .env files (security)
- .git/**
- node_modules/**
- .venv / venv /**
- __pycache__ /**
- *.pkl, *.pyc, *.bin (binary/model files)
- dataset/**/*.csv, dataset/**/*.parquet (training data)
- frontend/dist/**, frontend/node_modules/** (build output)
- logs/** (live log data)
- data/rag/** (our own index files)
- Any file larger than 1 MB (likely not documentation)
- Files containing likely secrets (pattern-matched)
"""

from __future__ import annotations

import logging
import pathlib
import re
from typing import Any, Dict, List, Optional

from backend.rag.chunking import TextChunker
from backend.rag.schemas import DocumentChunk

log = logging.getLogger(__name__)

SOURCE_NAME = "project_docs"
MAX_FILE_BYTES = 1_000_000   # 1 MB — anything larger is not documentation

# ---------------------------------------------------------------------------
# Exclusion patterns (applied to Path.parts for directories, and suffixes)
# ---------------------------------------------------------------------------

_EXCLUDED_DIR_PARTS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".pytest_cache", "dist", "build", "frontend",
    "dataset", "models", "reports",  # binary/training artifacts
}

_EXCLUDED_SUFFIXES = {
    ".pkl", ".pyc", ".pyo", ".bin", ".npy", ".npz",
    ".csv", ".parquet", ".arrow", ".h5", ".hdf5",
    ".png", ".jpg", ".jpeg", ".svg", ".ico",
    ".zip", ".tar", ".gz", ".whl",
    ".log",
}

_INCLUDED_SUFFIXES = {".md", ".txt", ".rst"}

# Pattern for lines that might contain secrets (basic heuristic)
_SECRET_LINE_RE = re.compile(
    r"(api[_-]?key|secret|password|token|bearer|GROQ_API_KEY)\s*[=:]\s*\S+",
    re.IGNORECASE,
)


class ProjectDocsAdapter:
    """
    Scans the project root for local documentation and ingests it.

    Usage::

        adapter = ProjectDocsAdapter(project_root=Path("."))
        chunks = adapter.load_chunks(chunker)
    """

    def __init__(
        self,
        project_root: Optional[pathlib.Path] = None,
        chunker: Optional[TextChunker] = None,
    ) -> None:
        if project_root is None:
            project_root = pathlib.Path(__file__).resolve().parent.parent.parent.parent
        self._root = project_root.resolve()
        self._chunker = chunker or TextChunker(chunk_size=512, overlap=64)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_chunks(self, chunker: Optional[TextChunker] = None) -> List[DocumentChunk]:
        """
        Scan for local documentation and return all DocumentChunks.

        Files are filtered by:
        1. Suffix allowlist (.md, .txt, .rst)
        2. Directory denylist (excludes .git, node_modules, .venv, …)
        3. Size limit (≤1 MB)
        4. Content safety check (no secret patterns indexed)
        """
        chunker = chunker or self._chunker
        log.info("ProjectDocsAdapter: scanning from %s", self._root)

        doc_paths = list(self._discover_docs())
        log.info("ProjectDocsAdapter: found %d documentation files", len(doc_paths))

        all_chunks: List[DocumentChunk] = []
        for path in doc_paths:
            try:
                chunks = self._process_file(path, chunker)
                all_chunks.extend(chunks)
                log.debug(
                    "ProjectDocsAdapter: %d chunks from %s",
                    len(chunks),
                    path.relative_to(self._root),
                )
            except Exception as exc:
                log.warning(
                    "ProjectDocsAdapter: skipping %s due to error: %s",
                    path,
                    exc,
                )

        log.info(
            "ProjectDocsAdapter: produced %d chunks from %d files",
            len(all_chunks),
            len(doc_paths),
        )
        return all_chunks

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _discover_docs(self):
        """Yield Path objects for all eligible documentation files."""
        for path in self._root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in _INCLUDED_SUFFIXES:
                continue
            if self._is_excluded(path):
                continue
            if path.stat().st_size > MAX_FILE_BYTES:
                log.debug("ProjectDocsAdapter: skipping large file %s", path)
                continue
            yield path

    def _is_excluded(self, path: pathlib.Path) -> bool:
        """Return True if any part of the path is in the exclusion list."""
        try:
            rel = path.relative_to(self._root)
        except ValueError:
            return True

        for part in rel.parts[:-1]:   # exclude filename itself
            if part.lower() in _EXCLUDED_DIR_PARTS:
                return True
            if part.startswith("."):
                return True

        # Explicitly exclude .env files
        name = path.name.lower()
        if name.startswith(".env") or name == ".env":
            return True
        if path.suffix.lower() in _EXCLUDED_SUFFIXES:
            return True

        return False

    def _process_file(
        self, path: pathlib.Path, chunker: TextChunker
    ) -> List[DocumentChunk]:
        """Read, sanitise, and chunk a single documentation file."""
        text = path.read_text(encoding="utf-8", errors="replace")

        # Strip potential secret lines
        safe_lines = []
        for line in text.splitlines():
            if _SECRET_LINE_RE.search(line):
                safe_lines.append("[LINE REDACTED: potential secret]")
            else:
                safe_lines.append(line)
        text = "\n".join(safe_lines)

        # Generate stable document_id from path relative to project root
        try:
            rel = path.relative_to(self._root)
        except ValueError:
            rel = path
        document_id = str(rel).replace("\\", "/").replace(" ", "_")

        # Title = filename without extension, formatted
        title = path.stem.replace("_", " ").replace("-", " ").title()

        # Section: parse Markdown heading from first H1 if available
        section = self._extract_first_heading(text) or ""

        # Source category: classify by file location/name
        source_category = self._classify_source(path)

        metadata: Dict[str, Any] = {
            "file_path": str(rel).replace("\\", "/"),
            "file_name": path.name,
        }

        return chunker.chunk(
            text=text,
            source=source_category,
            document_id=document_id,
            title=title,
            section=section,
            metadata=metadata,
        )

    @staticmethod
    def _extract_first_heading(text: str) -> Optional[str]:
        """Extract the first Markdown H1 or H2 heading from text."""
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("# "):
                return stripped[2:].strip()
            if stripped.startswith("## "):
                return stripped[3:].strip()
        return None

    def _classify_source(self, path: pathlib.Path) -> str:
        """Classify a file into a RAG source category."""
        parts = set(p.lower() for p in path.parts)
        name = path.name.lower()

        if "mitre" in name:
            return "attack_docs"
        if any(x in name for x in ("attack", "exploit", "malware")):
            return "attack_docs"
        if any(x in name for x in ("playbook", "response", "remediat", "defend")):
            return "playbooks"
        if any(x in name for x in ("detect", "scan", "feature", "extract")):
            return "detection_docs"
        if any(x in parts for x in ("feature_extraction", "packet_capture")):
            return "detection_docs"
        if any(x in parts for x in ("backend",)):
            return "detection_docs"
        return SOURCE_NAME   # default: project_docs
