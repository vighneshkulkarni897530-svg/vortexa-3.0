"""Source Context and Trust Evaluation (Section 4 & Section 6).

Evaluates the trust level and structural role of content based on its origin.
Untrusted documents, webpages, and tool outputs are treated as passive data
carriers, preventing them from gaining executive instruction authority.
"""

from enum import Enum
from typing import Any, Dict, Optional, Set
from pydantic import BaseModel, Field

from backend.detection.schemas import SourceType


class TrustLevel(str, Enum):
    """Server-assigned trust boundary classification."""
    UNTRUSTED_EXTERNAL = "UNTRUSTED_EXTERNAL"  # e.g., retrieved webpages from web
    UNTRUSTED_DATA = "UNTRUSTED_DATA"          # e.g., uploaded docs, tool results
    SEMI_TRUSTED_PROMPT = "SEMI_TRUSTED_PROMPT" # e.g., user prompt (user has conversational intent)
    SYSTEM_INTERNAL = "SYSTEM_INTERNAL"        # reserved for verified server-side prompts


class SourceContext(BaseModel):
    """Contextual security metadata derived for a content item."""
    source_type: SourceType
    trust_level: TrustLevel
    is_executive_context: bool = Field(
        ...,
        description="Whether this source is authorized to issue top-level conversational directives"
    )
    allows_system_instructions: bool = Field(
        False,
        description="Whether instructions in this source may be treated as authoritative system commands"
    )
    max_tolerated_risk: float = Field(
        0.5,
        description="Threshold at which indirect findings cause immediate blocking"
    )
    context_notes: str = ""


class SourceContextEvaluator:
    """Evaluates content origin and enforces strict authority boundaries."""

    @staticmethod
    def evaluate(
        source_type: SourceType,
        trusted_metadata: Optional[Dict[str, Any]] = None,
        application_context: Optional[str] = None,
    ) -> SourceContext:
        """Derive authoritative source context.

        CRITICAL: Never accepts client-asserted privilege elevation or policy overrides.
        Server logic alone determines trust level.
        """
        trusted_metadata = trusted_metadata or {}

        if source_type == SourceType.USER_PROMPT:
            # User prompts can issue conversational requests, but cannot alter system rules or secrets
            return SourceContext(
                source_type=source_type,
                trust_level=TrustLevel.SEMI_TRUSTED_PROMPT,
                is_executive_context=True,
                allows_system_instructions=False,
                max_tolerated_risk=0.70,
                context_notes="User conversational prompt; executive intent allowed, system overrides forbidden."
            )

        elif source_type == SourceType.UPLOADED_DOCUMENT:
            # Uploaded documents are untrusted passive data carriers
            return SourceContext(
                source_type=source_type,
                trust_level=TrustLevel.UNTRUSTED_DATA,
                is_executive_context=False,
                allows_system_instructions=False,
                max_tolerated_risk=0.45,
                context_notes="Uploaded document; passive data only. Any embedded directives are treated as indirect injection."
            )

        elif source_type == SourceType.RETRIEVED_WEBPAGE:
            # Retrieved webpages are untrusted external data with high risk of hidden injections
            return SourceContext(
                source_type=source_type,
                trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
                is_executive_context=False,
                allows_system_instructions=False,
                max_tolerated_risk=0.40,
                context_notes="External webpage; zero executive authority. High vigilance for injection or exfiltration spans."
            )

        elif source_type == SourceType.TOOL_OUTPUT:
            # Tool outputs could reflect third-party poisoned data (e.g. SQL, search results)
            return SourceContext(
                source_type=source_type,
                trust_level=TrustLevel.UNTRUSTED_DATA,
                is_executive_context=False,
                allows_system_instructions=False,
                max_tolerated_risk=0.50,
                context_notes="Tool execution output; passive operational data. Must not issue secondary tool commands."
            )

        # Fallback default to most restrictive untrusted level
        return SourceContext(
            source_type=source_type,
            trust_level=TrustLevel.UNTRUSTED_EXTERNAL,
            is_executive_context=False,
            allows_system_instructions=False,
            max_tolerated_risk=0.40,
            context_notes="Unrecognized source origin; defaulted to strictest untrusted data level."
        )


# Discussion / educational context markers that indicate benign analysis rather than attack
BENIGN_DISCUSSION_MARKERS: Set[str] = {
    "for example, an attack might look like",
    "such as 'ignore previous instructions'",
    "such as \"ignore previous instructions\"",
    "an example of prompt injection is",
    "common jailbreak techniques include",
    "researchers demonstrated that",
    "in this paper we analyze",
    "mitigate prompt injection by",
    "defending against jailbreaks",
    "the paper titled",
    "educational demonstration of",
    "vulnerability analysis:",
    "testing security filters with",
    "simulating an adversarial attack",
}
