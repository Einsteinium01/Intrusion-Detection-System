"""
backend/ai/schemas.py
=====================
WHY THIS FILE EXISTS
--------------------
Pydantic v2 schemas for all data that crosses the boundary between the
IDS alert pipeline and the LLM layer.

Two families of schemas are defined here:

  INPUT  – AlertContext:  the normalised, grounded alert context handed
                          to the prompt builder.  The LLM may not invent
                          values for this object.

  OUTPUT – AlertAnalysis: the structured response expected from the LLM.
                          Every field is required (Groq strict-mode JSON
                          schema requires no optional fields).

Supporting value objects:
  MitreAttack   – one ATT&CK technique reference
  Source        – one knowledge source citation
  SeverityLevel – the four severity values the LLM may assign

DESIGN NOTES
------------
- All fields carry a ``description`` so that Groq's structured-output
  mode produces a helpful JSON-schema for the model.
- ``AlertContext`` uses ``model_config = ConfigDict(frozen=True)`` to
  make it immutable after construction; this prevents accidental
  mutation in the prompt-builder chain.
- ``AlertAnalysis`` is intentionally mutable so tests can construct
  fixture instances easily.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class SeverityLevel(str, Enum):
    """Severity classification for a detected intrusion event."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Output supporting types
# ---------------------------------------------------------------------------

class MitreAttack(BaseModel):
    """A single MITRE ATT&CK technique reference cited in the analysis."""

    technique_id: str = Field(
        description="ATT&CK technique identifier, e.g. 'T1046'."
    )
    technique_name: str = Field(
        description="Human-readable name of the technique, e.g. 'Network Service Discovery'."
    )
    rationale: str = Field(
        description=(
            "One-sentence explanation of why this technique is relevant "
            "to the observed evidence."
        )
    )


class Source(BaseModel):
    """A knowledge source cited by the analyst in the analysis."""

    source_id: str = Field(
        description="Short stable identifier, e.g. 'MITRE-T1046' or 'CVE-2024-1234'."
    )
    title: str = Field(
        description="Human-readable title of the source document or article."
    )
    relevance: str = Field(
        description="One sentence describing how this source applies to the alert."
    )


# ---------------------------------------------------------------------------
# LLM OUTPUT schema
# ---------------------------------------------------------------------------

class AlertAnalysis(BaseModel):
    """
    Structured AI-generated analysis of a single IDS alert.

    All fields are required because Groq strict structured-output mode
    does not allow optional fields in the JSON schema.
    """

    summary: str = Field(
        description="Two-to-three sentence executive summary of the alert."
    )
    technical_analysis: str = Field(
        description=(
            "Detailed technical analysis of the alert evidence, "
            "limited strictly to the supplied context."
        )
    )
    severity: SeverityLevel = Field(
        description=(
            "Analyst-assessed severity: LOW | MEDIUM | HIGH | CRITICAL. "
            "Must not contradict the detector classification."
        )
    )
    attack_type: str = Field(
        description=(
            "Attack category as classified by the IDS detector. "
            "The LLM must not change this value."
        )
    )
    evidence: List[str] = Field(
        description=(
            "Bullet-point list of concrete observed evidence drawn exclusively "
            "from the supplied AlertContext. Never invent evidence."
        )
    )
    mitre_attack: List[MitreAttack] = Field(
        description=(
            "Relevant MITRE ATT&CK techniques. "
            "Include only techniques supported by the observed evidence."
        )
    )
    investigation_steps: List[str] = Field(
        description=(
            "Ordered list of defensive investigation steps an analyst "
            "should follow next."
        )
    )
    recommended_actions: List[str] = Field(
        description=(
            "Defensive recommendations. Must be investigation guidance only. "
            "Never recommend automated blocking or system modification."
        )
    )
    sources: List[Source] = Field(
        description=(
            "Knowledge sources referenced in this analysis. "
            "Empty list if Phase-1 RAG context was not supplied."
        )
    )


# ---------------------------------------------------------------------------
# INPUT schema
# ---------------------------------------------------------------------------

class FlowStatistics(BaseModel):
    """Optional flow-level statistics attached to an AlertContext."""

    model_config = ConfigDict(frozen=True, extra="allow")

    packet_count: Optional[int] = Field(None, description="Total packets in the flow.")
    byte_count: Optional[int] = Field(None, description="Total bytes in the flow.")
    duration_seconds: Optional[float] = Field(None, description="Flow duration in seconds.")
    packets_per_second: Optional[float] = Field(None, description="Average packet rate.")
    mean_packet_size: Optional[float] = Field(None, description="Mean packet size in bytes.")
    distinct_ports: Optional[int] = Field(None, description="Number of distinct destination ports probed.")
    distinct_hosts: Optional[int] = Field(None, description="Number of distinct destination hosts contacted.")
    syn_count: Optional[int] = Field(None, description="Count of SYN-only probes observed.")
    scan_type: Optional[str] = Field(None, description="Scan variant: 'vertical' | 'horizontal' | 'compound'.")


class AlertContext(BaseModel):
    """
    Normalised, grounded alert context passed to the AI analyst.

    GROUNDING CONTRACT
    ------------------
    This object is constructed exclusively from IDS detector output.
    The LLM must not invent or modify any field values.  The prompt
    builder enforces this via explicit instructions.
    """

    model_config = ConfigDict(frozen=True)

    # Identity
    alert_id: str = Field(description="Unique identifier for this alert instance.")
    timestamp: str = Field(description="ISO-8601 timestamp when the alert was raised.")

    # Network context
    source_ip: str = Field(description="Source IP address observed in the flow.")
    destination_ip: str = Field(description="Destination IP address of the flow.")
    source_port: int = Field(description="Source TCP/UDP port number.")
    destination_port: int = Field(description="Destination TCP/UDP port number.")
    protocol: str = Field(description="Layer-4 protocol: TCP | UDP | ICMP.")

    # Detection metadata
    attack_type: str = Field(
        description="Attack category assigned by the IDS detector (authoritative)."
    )
    detector: str = Field(
        description="Name of the IDS detector component that raised the alert."
    )
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Detector confidence score in the range [0.0, 1.0]."
    )

    # Evidence collected by the detector
    evidence: List[str] = Field(
        default_factory=list,
        description="List of evidence strings collected by the detector.",
    )

    # Optional flow statistics
    flow_statistics: Optional[FlowStatistics] = Field(
        None,
        description="Optional flow-level statistics from the feature extractor.",
    )

    @field_validator("protocol")
    @classmethod
    def _normalise_protocol(cls, v: str) -> str:
        return v.upper()

    @field_validator("confidence")
    @classmethod
    def _round_confidence(cls, v: float) -> float:
        return round(v, 4)


# ---------------------------------------------------------------------------
# Phase 1 RAG placeholder
# ---------------------------------------------------------------------------

class KnowledgeContext(BaseModel):
    """
    Container for retrieved knowledge-base documents.

    Phase 1: always empty.
    Phase 2+: populated by a vector-store retriever.

    The prompt builder accepts this object so that the interface is
    already stable for when RAG is introduced.
    """

    model_config = ConfigDict(frozen=True)

    documents: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Retrieved knowledge documents.  Empty in Phase 1.",
    )
