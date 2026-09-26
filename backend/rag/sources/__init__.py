"""
backend/rag/sources/__init__.py
================================
Source adapters for the local RAG knowledge ingestion pipeline.

Each adapter is responsible for:
  1. Reading/parsing a specific source type.
  2. Producing a list of DocumentChunk objects.
  3. Attaching appropriate metadata (source, title, section, technique_id, …).

Adapters exported here:
  MitreAttackAdapter  – parses official MITRE ATT&CK Enterprise STIX JSON
  ProjectDocsAdapter  – scans the project repository for local Markdown docs
"""

from backend.rag.sources.mitre import MitreAttackAdapter
from backend.rag.sources.project_docs import ProjectDocsAdapter

__all__ = ["MitreAttackAdapter", "ProjectDocsAdapter"]
