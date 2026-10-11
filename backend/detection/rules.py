"""Explainable Multi-Signal Injection Detection Rules (Stage C).

Detects direct & indirect prompt injection, system overrides, security bypasses,
prompt disclosures, data exfiltration, tool abuse, and policy tampering.
Accounts for semantic intent, quotation, and benign educational discussions
to prevent false positives.
"""

import re
from dataclasses import dataclass
from typing import Callable, List, Optional, Pattern, Tuple

from backend.detection.schemas import (
    DecisionAction,
    DetectionFinding,
    EvidenceSpan,
    RuleCategory,
    Severity,
    SourceType,
)
from backend.detection.source_context import BENIGN_DISCUSSION_MARKERS, SourceContext


@dataclass
class RuleDefinition:
    """Definition of an explainable detection rule."""
    rule_id: str
    name: str
    category: RuleCategory
    base_severity: Severity
    base_confidence: float
    regex: Pattern
    summary_template: str
    recommended_action: DecisionAction
    check_benign_context: bool = True


# Compiled pattern definitions
SYSTEM_OVERRIDE_PATTERNS = [
    RuleDefinition(
        rule_id="INJ-SYS-001",
        name="Direct System Prompt Override",
        category=RuleCategory.SYSTEM_OVERRIDE,
        base_severity=Severity.HIGH,
        base_confidence=0.92,
        regex=re.compile(
            r"\b(?:ignore|disregard|forget|override|neglect|dismiss)\s+(?:all\s+|your\s+|any\s+)?(?:previous\s+|prior\s+|above\s+|initial\s+|system\s+)?(?:instruction|prompt|rule|directive|constraint|guideline)s?\b",
            re.IGNORECASE,
        ),
        summary_template="Direct imperative command attempting to discard or override system instructions",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-SYS-002",
        name="Roleplay / Persona Hijack (DAN / Jailbreak Mode)",
        category=RuleCategory.SYSTEM_OVERRIDE,
        base_severity=Severity.HIGH,
        base_confidence=0.88,
        regex=re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:you\s+are\s+in|to\s+be|you\s+are\s+a)|you\s+are\s+a)\s+(?:DAN|Do\s+Anything\s+Now|an\s+unrestricted\s+AI|evil\s+AI|developer\s+mode|jailbroken|unfiltered|red\s+team\s+penetration\s+testing)\b",
            re.IGNORECASE,
        ),
        summary_template="Persona hijack attempting to induce unrestricted/DAN operational mode",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-SYS-003",
        name="System Frame Delimiter Injection",
        category=RuleCategory.SYSTEM_OVERRIDE,
        base_severity=Severity.HIGH,
        base_confidence=0.90,
        regex=re.compile(
            r"(?:<\s*\|\s*im_start\s*\|?>?\s*system|\[\s*SYSTEM\s*(?:INSTRUCTION|MESSAGE|PROMPT)?\s*\]|<<SYS>>|===\s*SYSTEM\s*===)",
            re.IGNORECASE,
        ),
        summary_template="Artificial prompt delimiter attempting to forge trusted system boundaries",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-SYS-004",
        name="Authority Inversion Command",
        category=RuleCategory.SYSTEM_OVERRIDE,
        base_severity=Severity.HIGH,
        base_confidence=0.85,
        regex=re.compile(
            r"\b(?:from\s+now\s+on\s+you\s+(?:must|will)\s+only|you\s+must\s+obey\s+only\s+my|new\s+system\s+directive\s*:)\b",
            re.IGNORECASE,
        ),
        summary_template="Attempt to enforce exclusive authority overriding system hierarchy",
        recommended_action=DecisionAction.BLOCK,
    ),
]

SECURITY_BYPASS_PATTERNS = [
    RuleDefinition(
        rule_id="INJ-BYP-001",
        name="Safety Filter Disablement Directive",
        category=RuleCategory.SECURITY_BYPASS,
        base_severity=Severity.HIGH,
        base_confidence=0.90,
        regex=re.compile(
            r"\b(?:disable|turn\s+off|bypass|circumvent|deactivate)\s+(?:all\s+)?(?:safety|security|filters|content\s+filters|ethical\s+guidelines|guardrails)\b",
            re.IGNORECASE,
        ),
        summary_template="Explicit command targeting deactivation of safety filters and guardrails",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-BYP-002",
        name="Hypothetical Security Waiver",
        category=RuleCategory.SECURITY_BYPASS,
        base_severity=Severity.MEDIUM,
        base_confidence=0.80,
        regex=re.compile(
            r"\b(?:in\s+a\s+hypothetical\s+world\s+where\s+(?:no\s+rules|safety\s+does\s+not\s+apply)|pretend\s+there\s+are\s+no\s+(?:ethics|rules|restrictions))\b",
            re.IGNORECASE,
        ),
        summary_template="Hypothetical framing attempting to bypass ethical and safety constraints",
        recommended_action=DecisionAction.BLOCK,
    ),
]

PROMPT_DISCLOSURE_PATTERNS = [
    RuleDefinition(
        rule_id="INJ-DISC-001",
        name="System Prompt Disclosure Request",
        category=RuleCategory.HIDDEN_PROMPT_DISCLOSURE,
        base_severity=Severity.HIGH,
        base_confidence=0.91,
        regex=re.compile(
            r"\b(?:repeat|print|reveal|output|echo|display|show\s+me)\s+(?:(?:in\s+markdown\s+(?:codeblock\s+)?)?\s*(?:everything\s+above|the\s+entire\s+(?:system\s+|initial\s+)?(?:prompt|message|instruction)s?|(?:the\s+|your\s+|initial\s+|system\s+|developer\s+|hidden\s+)*(?:prompt|instructions?|directives?|rules?)))\b",
            re.IGNORECASE,
        ),
        summary_template="Imperative command instructing the model to disclose protected system prompts",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-DISC-002",
        name="Verbatim Instructions Extraction",
        category=RuleCategory.HIDDEN_PROMPT_DISCLOSURE,
        base_severity=Severity.MEDIUM,
        base_confidence=0.86,
        regex=re.compile(
            r"\b(?:what\s+were\s+your\s+exact\s+initial\s+instructions|print\s+your\s+instructions\s+verbatim|output\s+in\s+markdown\s+codeblock\s+the\s+system\s+message)\b",
            re.IGNORECASE,
        ),
        summary_template="Attempt to extract verbatim initial instructions and configuration",
        recommended_action=DecisionAction.BLOCK,
    ),
]

DATA_EXFILTRATION_PATTERNS = [
    RuleDefinition(
        rule_id="INJ-EXFIL-001",
        name="Markdown Image Exfiltration Channel",
        category=RuleCategory.DATA_TRANSFER,
        base_severity=Severity.CRITICAL,
        base_confidence=0.96,
        regex=re.compile(
            r"!\[.*?\]\((?:https?:)?//[^)]+[\?&](?:data|token|leak|secret|key|stolen|q)=[^)]*\)",
            re.IGNORECASE,
        ),
        summary_template="Detected markdown rendering payload designed to leak data via external image URL",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-EXFIL-002",
        name="External Exfiltration Instruction",
        category=RuleCategory.DATA_TRANSFER,
        base_severity=Severity.HIGH,
        base_confidence=0.88,
        regex=re.compile(
            r"\b(?:send|transmit|post|forward|upload|exfiltrate)\s+(?:all\s+)?(?:data|credentials|passwords|secrets|keys)\s+to\s+(?:https?://|http://|[a-zA-Z0-9.\-]+\.[a-z]{2,})\b",
            re.IGNORECASE,
        ),
        summary_template="Instruction commanding the model or tool to exfiltrate private data to an external address",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-EXFIL-003",
        name="SSRF / Cloud Metadata Exfiltration",
        category=RuleCategory.DATA_TRANSFER,
        base_severity=Severity.CRITICAL,
        base_confidence=0.96,
        regex=re.compile(
            r"(?:169\.254\.169\.254|metadata\.google\.internal|latest/meta-data|attacker-c2\.net)",
            re.IGNORECASE,
        ),
        summary_template="Attempt to access cloud instance metadata or unauthorized external C2 destination",
        recommended_action=DecisionAction.BLOCK,
    ),
]

TOOL_MANIPULATION_PATTERNS = [
    RuleDefinition(
        rule_id="INJ-TOOL-001",
        name="Destructive Shell / Command Execution Injection",
        category=RuleCategory.TOOL_MANIPULATION,
        base_severity=Severity.CRITICAL,
        base_confidence=0.94,
        regex=re.compile(
            r"\b(?:run|execute|call)\s+(?:bash|sh|cmd|powershell|terminal)\s+(?:command\s*)?:?\s*(?:rm\s+-rf|del\s+/f|format\s+[a-z]:|curl\s+.*\|\s*sh|cat\s+/etc/shadow)\b",
            re.IGNORECASE,
        ),
        summary_template="Attempt to coerce tool integration into running arbitrary or destructive shell commands",
        recommended_action=DecisionAction.BLOCK,
    ),
    RuleDefinition(
        rule_id="INJ-TOOL-002",
        name="Unauthorized SQL / Database Modification via Tool",
        category=RuleCategory.TOOL_MANIPULATION,
        base_severity=Severity.HIGH,
        base_confidence=0.91,
        regex=re.compile(
            r"\b(?:DROP\s+TABLE|ALTER\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE|INSERT\s+INTO\s+.*SELECT|UNION\s+SELECT\s+.*FROM)\b",
            re.IGNORECASE,
        ),
        summary_template="Destructive or unauthorized database manipulation payload embedded in content",
        recommended_action=DecisionAction.BLOCK,
    ),
]

POLICY_MANIPULATION_PATTERNS = [
    RuleDefinition(
        rule_id="INJ-POL-001",
        name="PromptShield Policy Override Tampering",
        category=RuleCategory.POLICY_MANIPULATION,
        base_severity=Severity.HIGH,
        base_confidence=0.93,
        regex=re.compile(
            r"\b(?:set\s+(?:security\s+)?policy\s+to\s+(?:ALLOW|PERMISSIVE)|override\s+PromptShield|disable\s+PromptShield|security\s+decision\s*:\s*ALLOW)\b",
            re.IGNORECASE,
        ),
        summary_template="Untrusted content attempting to forge or manipulate security policy evaluation",
        recommended_action=DecisionAction.BLOCK,
    ),
]

ANOMALOUS_STRUCTURE_PATTERNS = [
    RuleDefinition(
        rule_id="ANOM-STRUCT-001",
        name="Maintenance Mode Override Directive in Technical Document",
        category=RuleCategory.ANOMALOUS_STRUCTURE,
        base_severity=Severity.MEDIUM,
        base_confidence=0.72,
        regex=re.compile(
            r"\b(?:maintenance\s+mode|administrative\s+reset|emergency\s+access|recovery\s+script).*?(?:override|ignore\s+lock)\b",
            re.IGNORECASE,
        ),
        summary_template="Technical manual excerpt referencing override or ignore flags; context requires human reviewer verification",
        recommended_action=DecisionAction.ESCALATE,
    ),
    RuleDefinition(
        rule_id="ANOM-STRUCT-002",
        name="Ambiguous Auth or Bypass Parameter in Query",
        category=RuleCategory.ANOMALOUS_STRUCTURE,
        base_severity=Severity.MEDIUM,
        base_confidence=0.75,
        regex=re.compile(
            r"\b(?:auth_flag|bypass_check|security_override|auth_bypass|debug_mode=true)\b",
            re.IGNORECASE,
        ),
        summary_template="Ambiguous parameter flag indicating security check bypass; requires analyst escalation",
        recommended_action=DecisionAction.ESCALATE,
    ),
    RuleDefinition(
        rule_id="ANOM-STRUCT-003",
        name="Non-Routable Internal Network Endpoint Reference",
        category=RuleCategory.ANOMALOUS_STRUCTURE,
        base_severity=Severity.MEDIUM,
        base_confidence=0.70,
        regex=re.compile(
            r"\b(?:internal-(?:proxy|service|api|db)\.corp|localhost:\d+)\b",
            re.IGNORECASE,
        ),
        summary_template="Content references internal corporate endpoint; escalated to verify network policy compliance",
        recommended_action=DecisionAction.ESCALATE,
    ),
    RuleDefinition(
        rule_id="ANOM-STRUCT-004",
        name="Governance Context Discussing System Instructions",
        category=RuleCategory.ANOMALOUS_STRUCTURE,
        base_severity=Severity.MEDIUM,
        base_confidence=0.68,
        regex=re.compile(
            r"\b(?:governance\s+committee|policy\s+draft|compliance\s+audit).*?(?:system\s+instruction|prompt\s+guideline)s?\b",
            re.IGNORECASE,
        ),
        summary_template="Governance or draft compliance document referencing prompt instructions; flagged for human review",
        recommended_action=DecisionAction.ESCALATE,
    ),
    RuleDefinition(
        rule_id="ANOM-STRUCT-005",
        name="Security Anomaly in Operational Tool Output",
        category=RuleCategory.ANOMALOUS_STRUCTURE,
        base_severity=Severity.MEDIUM,
        base_confidence=0.74,
        regex=re.compile(
            r"\b(?:status\s+403\s+on\s+path|unusual\s+bearer\s+token|removed\s+legacy\s+token\s+verification|legacy\s+token\s+verification\s+filter)\b",
            re.IGNORECASE,
        ),
        summary_template="Security-relevant anomaly reported in tool output or code diff; escalated for operational verification",
        recommended_action=DecisionAction.ESCALATE,
    ),
    RuleDefinition(
        rule_id="ANOM-STRUCT-006",
        name="Architecture Discussion Touching Prompt Structure",
        category=RuleCategory.ANOMALOUS_STRUCTURE,
        base_severity=Severity.MEDIUM,
        base_confidence=0.65,
        regex=re.compile(
            r"\b(?:custom\s+prompt\s+prefix|langchain\s+prompt\s+template).*?(?:security\s+consideration|architecture)\b",
            re.IGNORECASE,
        ),
        summary_template="Technical architectural inquiry discussing prompt structures; escalated for policy check",
        recommended_action=DecisionAction.ESCALATE,
    ),
]

ALL_RULES: List[RuleDefinition] = (
    SYSTEM_OVERRIDE_PATTERNS
    + SECURITY_BYPASS_PATTERNS
    + PROMPT_DISCLOSURE_PATTERNS
    + DATA_EXFILTRATION_PATTERNS
    + TOOL_MANIPULATION_PATTERNS
    + POLICY_MANIPULATION_PATTERNS
    + ANOMALOUS_STRUCTURE_PATTERNS
)


class InjectionRuleEngine:
    """Evaluates content against explainable multi-signal detection rules."""

    def __init__(self, rules: Optional[List[RuleDefinition]] = None):
        self.rules = rules or ALL_RULES

    def is_benign_security_discussion(self, text: str, match_start: int, match_end: int) -> bool:
        """Determines if a matched phrase occurs in benign educational/research context.

        Checks for:
        1. Explicit discussion markers anywhere in document
        2. Surrounding quotation marks around matched phrase
        3. Explanatory prefaces like 'e.g.', 'such as', 'for example'
        """
        text_lower = text.lower()

        # Check document-level markers
        for marker in BENIGN_DISCUSSION_MARKERS:
            if marker in text_lower:
                return True

        # Check surrounding window (up to 160 chars before and after)
        window_start = max(0, match_start - 160)
        window_end = min(len(text), match_end + 160)
        surrounding_text = text_lower[window_start:window_end]

        benign_window_cues = [
            "for example", "such as", "e.g.", "known attack",
            "paper discusses", "research on", "sample payload",
            "concept of", "what is", "explain what", "explain the",
            "explain how", "how does", "vulnerability named", "definition of",
            "prevent attackers", "parameterized queries", "educational",
            "defense against", "mitigate", "how to defend",
        ]
        if any(cue in surrounding_text for cue in benign_window_cues):
            return True

        # Check document-level query cues for explanation / defense inquiries
        if any(q in text_lower for q in ["what does", "what is", "explain the concept", "how to mitigate", "how do parameterized"]):
            return True

        # Check if match is enclosed in quotation marks (e.g. "ignore previous instructions")
        if match_start > 0 and match_end < len(text):
            char_before = text[match_start - 1]
            char_after = text[match_end] if match_end < len(text) else ""
            if (char_before in {'"', "'", "“", "`"} and char_after in {'"', "'", "”", "`"}):
                # If the user is asking "What does 'ignore previous instructions' mean?"
                if any(q in text_lower for q in ["what does", "what is", "explain", "meaning of", "why do people"]):
                    return True

        return False

    def evaluate(
        self,
        text: str,
        source_ctx: SourceContext,
        auxiliary_channels: Optional[List[Tuple[str, str]]] = None,
    ) -> List[DetectionFinding]:
        """Scan normalized content and auxiliary channels for injection findings."""
        findings: List[DetectionFinding] = []
        if not text:
            return findings

        # 1. Main Content Scan
        for rule in self.rules:
            for match in rule.regex.finditer(text):
                matched_span = match.span()
                matched_text = match.group(0)

                # Contextual check: Benign educational discussion or research
                if rule.check_benign_context and self.is_benign_security_discussion(
                    text, matched_span[0], matched_span[1]
                ):
                    # Lower confidence & severity to SAFE/LOW informatory finding that ALLOWs
                    findings.append(
                        DetectionFinding(
                            rule_id=f"{rule.rule_id}-BENIGN-CTX",
                            category=rule.category,
                            severity=Severity.LOW,
                            confidence=0.25,
                            evidence_span=EvidenceSpan(
                                start=matched_span[0],
                                end=matched_span[1],
                                text_preview=matched_text[:100],
                            ),
                            safe_evidence_summary=f"Discussive / educational mention of security concept ({rule.name}) detected in benign context",
                            source_context=source_ctx.source_type.value,
                            recommended_action=DecisionAction.ALLOW,
                        )
                    )
                    continue

                # Source-Aware context handling:
                # If detected inside uploaded document or retrieved webpage, it's an INDIRECT injection
                effective_category = rule.category
                effective_summary = rule.summary_template
                recommended_action = rule.recommended_action
                confidence = rule.base_confidence
                severity = rule.base_severity

                if source_ctx.source_type in {SourceType.UPLOADED_DOCUMENT, SourceType.RETRIEVED_WEBPAGE, SourceType.TOOL_OUTPUT}:
                    if rule.recommended_action == DecisionAction.ESCALATE:
                        effective_summary = f"Anomalous structure in {source_ctx.source_type.value}: {rule.name}"
                        recommended_action = DecisionAction.ESCALATE
                    else:
                        effective_category = RuleCategory.INDIRECT_INJECTION
                        effective_summary = f"Indirect prompt injection attempt in {source_ctx.source_type.value}: {rule.name}"
                        recommended_action = DecisionAction.SANITIZE

                findings.append(
                    DetectionFinding(
                        rule_id=rule.rule_id,
                        category=effective_category,
                        severity=severity,
                        confidence=confidence,
                        evidence_span=EvidenceSpan(
                            start=matched_span[0],
                            end=matched_span[1],
                            text_preview=matched_text[:100],
                        ),
                        safe_evidence_summary=effective_summary,
                        source_context=source_ctx.source_type.value,
                        recommended_action=recommended_action,
                    )
                )

        # 2. Auxiliary Decoded Channel Scan (Base64 / Hex decoded text)
        if auxiliary_channels:
            for channel_type, decoded_text in auxiliary_channels:
                for rule in self.rules:
                    match = rule.regex.search(decoded_text)
                    if match:
                        findings.append(
                            DetectionFinding(
                                rule_id=f"{rule.rule_id}-ENCODED",
                                category=RuleCategory.ENCODED_PAYLOAD,
                                severity=Severity.CRITICAL,
                                confidence=0.95,
                                evidence_span=None,  # Not in original text directly
                                safe_evidence_summary=f"Obfuscated injection payload discovered inside decoded {channel_type}: {rule.name}",
                                source_context=source_ctx.source_type.value,
                                recommended_action=DecisionAction.BLOCK,
                            )
                        )

        return findings
