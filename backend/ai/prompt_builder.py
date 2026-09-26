"""
backend/ai/prompt_builder.py
=============================
WHY THIS FILE EXISTS
--------------------
The prompt builder is the single source of truth for every instruction
sent to the LLM.  Keeping prompts here (rather than inside the provider
or analyzer) means they can be reviewed, unit-tested, and updated
without touching the API plumbing.

GROUNDING RULES (enforced in both system and user prompts)
-----------------------------------------------------------
1.  The existing IDS detector is authoritative – do not change its
    classification.
2.  Analyse only the supplied alert evidence and knowledge context.
3.  Clearly distinguish observed evidence from inference.
4.  Never invent packets, flows, CVEs, ATT&CK techniques, IP behaviour,
    system state, or events.
5.  If evidence is insufficient, explicitly state that.
6.  Recommended actions must be defensive investigation guidance only.
7.  Never execute commands.
8.  Never request or expose secrets.
9.  Never automatically block, disable, or modify systems.
10. Do not treat the LLM's own reasoning as evidence.

PHASE 1 NOTE
------------
RAG context (KnowledgeContext) is accepted by the builder but is
currently always empty.  The user-prompt template reserves a section
for retrieved documents so that Phase 2 can populate it without
changing the builder's interface.
"""

from __future__ import annotations

import json
import logging
from typing import List

from backend.ai.schemas import AlertContext, KnowledgeContext

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are the AI Security Analyst for a network intrusion detection system.

## Your Role
You receive a single structured alert from an automated IDS detector and produce a
detailed, grounded security analysis in strict JSON format.

## Absolute Rules
1. The IDS detector classification is authoritative. You MUST preserve the `attack_type`
   field exactly as provided — never change, soften, or speculate about the classification.
2. Analyse ONLY the evidence and context explicitly supplied in the user message.
   Do not infer information from external knowledge that contradicts the supplied context.
3. Clearly distinguish facts (observed in the alert) from inferences (your reasoning).
   Use language like "the evidence suggests" rather than stating inferences as fact.
4. NEVER invent packets, flows, CVEs, MITRE ATT&CK technique IDs, IP behaviour,
   system state, or events that are not present in the supplied context.
5. If the supplied evidence is insufficient to support a conclusion, explicitly state
   "Insufficient evidence to determine X."
6. Recommended actions must be purely defensive investigation guidance.
   They must never instruct: running commands, blocking firewall rules automatically,
   disabling accounts, or modifying running systems.
7. Never request, reference, or expose API keys, passwords, or secrets of any kind.
8. Never treat your own chain-of-thought reasoning as observed evidence.
9. All MITRE ATT&CK technique citations must be supported by the supplied evidence.
   If no technique is confidently supported, return an empty mitre_attack list.
10. Knowledge sources (sources list) must come from the supplied RAG context only.
    If no RAG context was provided, return an empty sources list.

## Output
Respond with a single JSON object matching the AlertAnalysis schema.
Do not include any text outside the JSON object.
"""

# ---------------------------------------------------------------------------
# User-prompt template
# ---------------------------------------------------------------------------

_USER_TEMPLATE = """\
## IDS Alert — Analyse the following alert

### Alert Context
```json
{alert_json}
```

### Retrieved Knowledge Context (Phase 1: empty)
{knowledge_section}

---

Produce a complete AlertAnalysis JSON object.
Grounding reminder: every claim in `evidence` must map directly to a field or
value present in the Alert Context above.  Do not introduce external facts.
"""


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------

class PromptBuilder:
    """
    Constructs (system_prompt, user_prompt) pairs for the LLM.

    Usage::

        builder = PromptBuilder()
        system, user = builder.build(alert_ctx, knowledge_ctx)
    """

    def __init__(self, system_prompt: str = SYSTEM_PROMPT) -> None:
        self._system_prompt = system_prompt

    # ------------------------------------------------------------------
    def build(
        self,
        alert: AlertContext,
        knowledge: KnowledgeContext | None = None,
    ) -> tuple[str, str]:
        """
        Return ``(system_prompt, user_prompt)`` for the given alert.

        Parameters
        ----------
        alert:
            The grounded, immutable AlertContext produced by the IDS.
        knowledge:
            Optional RAG context.  Empty in Phase 1.

        Returns
        -------
        tuple[str, str]
            ``(system_prompt, user_prompt)`` ready to pass to the LLM provider.
        """
        if knowledge is None:
            knowledge = KnowledgeContext()

        alert_json = self._serialise_alert(alert)
        knowledge_section = self._serialise_knowledge(knowledge)

        user_prompt = _USER_TEMPLATE.format(
            alert_json=alert_json,
            knowledge_section=knowledge_section,
        )

        log.debug(
            "PromptBuilder: built prompt for alert_id=%s attack_type=%s",
            alert.alert_id,
            alert.attack_type,
        )
        return self._system_prompt, user_prompt

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialise_alert(alert: AlertContext) -> str:
        """
        Serialise AlertContext to compact, readable JSON.

        ``flow_statistics`` is included only when it is not None so the
        prompt isn't cluttered with ``"flow_statistics": null``.
        """
        data = alert.model_dump(exclude_none=True)
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def _serialise_knowledge(knowledge: KnowledgeContext) -> str:
        """
        Serialise the RAG knowledge context into the prompt.

        Phase 1: always returns a placeholder message.
        Phase 2+: format each retrieved document chunk into numbered
        sections so the model can cite them via ``sources``.
        """
        if not knowledge.documents:
            return (
                "No external knowledge context was retrieved for this alert.\n"
                "Return an empty `sources` list."
            )

        # Phase 2 placeholder – will be implemented when RAG is added
        lines: List[str] = []
        for i, doc in enumerate(knowledge.documents, start=1):
            lines.append(f"[{i}] {json.dumps(doc, default=str)}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Module-level default instance
# ---------------------------------------------------------------------------
_default_builder: PromptBuilder | None = None


def get_prompt_builder() -> PromptBuilder:
    """Return the module-level singleton PromptBuilder."""
    global _default_builder
    if _default_builder is None:
        _default_builder = PromptBuilder()
    return _default_builder
