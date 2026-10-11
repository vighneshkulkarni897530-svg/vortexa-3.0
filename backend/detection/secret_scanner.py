"""Secret and Sensitive Data Scanner (Stage D).

Detects test canary tokens, explicitly configured sensitive values, and
secret patterns (API keys, tokens, private keys) without leaking matched
values in findings, previews, logs, or error responses.
"""

import codecs
import math
import re
from typing import Dict, List, Optional, Set, Tuple

from backend.config import settings
from backend.detection.schemas import (
    DecisionAction,
    DetectionFinding,
    EvidenceSpan,
    RuleCategory,
    Severity,
)
from backend.detection.source_context import SourceContext


# Synthetic secret patterns
SECRET_PATTERNS = [
    (
        "SEC-PAT-001",
        "Synthetic AWS Access Key ID",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-PAT-002",
        "Synthetic Generic API Secret Key (sk-...)",
        re.compile(r"\bsk-[a-zA-Z0-9_\-]{20,}\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-PAT-003",
        "Synthetic GitHub Personal Access Token",
        re.compile(r"\bghp_[a-zA-Z0-9]{36}\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-PAT-004",
        "Private Key Header",
        re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    (
        "SEC-PAT-005",
        "Synthetic Slack Token",
        re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-PAT-006",
        "Synthetic JWT Format Token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        Severity.HIGH,
    ),
]

LEET_MAP: Dict[str, str] = {
    "a": "[aA4@]",
    "e": "[eE3]",
    "i": "[iI1!|]",
    "o": "[oO0]",
    "s": "[sS5$]",
    "t": "[tT7]",
}


def mask_secret(value: str) -> str:
    """Safely redact secret value so it is never leaked in logs or API responses."""
    if not value:
        return "[REDACTED]"
    length = len(value)
    if length <= 6:
        return "[REDACTED_SECRET]"
    # Show first 3 chars, middle masked, last 3 chars
    prefix = value[:3]
    suffix = value[-3:]
    return f"{prefix}***{suffix} (REDACTED_{length}_CHARS)"


def calculate_entropy(s: str) -> float:
    """Calculate Shannon entropy to identify high-randomness tokens."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def build_flexible_token_regex(token: str) -> re.Pattern:
    """Build a regex matching a token despite spacing, case, delimiters, or simple leetspeak."""
    parts = []
    for c in token:
        c_low = c.lower()
        if c in {"_", "-", "."}:
            parts.append(r"[\s_\-.]*")
        elif c_low in LEET_MAP:
            parts.append(LEET_MAP[c_low] + r"\s*")
        elif c.isalnum():
            parts.append(re.escape(c) + r"\s*")
        else:
            parts.append(re.escape(c) + r"\s*")
    pat = "".join(parts).rstrip(r"\s*")
    return re.compile(pat, re.IGNORECASE)


class SecretScanner:
    """Scans content for canary secrets and sensitive credential patterns."""

    def __init__(
        self,
        canary_tokens: Optional[List[str]] = None,
        configured_secrets: Optional[List[str]] = None,
    ):
        self.canary_tokens: Set[str] = set(canary_tokens or settings.CANARY_TOKENS)
        self.configured_secrets: Set[str] = set(configured_secrets or settings.CONFIGURED_SENSITIVE_KEYS)
        self._regex_cache: Dict[str, re.Pattern] = {}

    def _get_token_regex(self, token: str) -> re.Pattern:
        if token not in self._regex_cache:
            self._regex_cache[token] = build_flexible_token_regex(token)
        return self._regex_cache[token]

    def scan(
        self,
        text: str,
        source_ctx: SourceContext,
        auxiliary_channels: Optional[List[Tuple[str, str]]] = None,
        extra_tokens: Optional[List[str]] = None,
    ) -> List[DetectionFinding]:
        """Scan text and auxiliary channels, returning findings with safe redacted evidence."""
        findings: List[DetectionFinding] = []
        if not text:
            return findings

        # Track matched spans to avoid duplicate reporting on overlapping rules
        reported_spans: Set[Tuple[int, int]] = set()

        all_canaries = set(self.canary_tokens)
        if extra_tokens:
            all_canaries.update(t.strip() for t in extra_tokens if t and t.strip())

        # 1. Canary Token Flexible Scan (Catches spacing, capitalization, leetspeak, delimiters)
        for canary in all_canaries:
            if not canary:
                continue
            token_rgx = self._get_token_regex(canary)
            for match in token_rgx.finditer(text):
                found_at, end_pos = match.span()
                span_key = (found_at, end_pos)
                if span_key in reported_spans:
                    continue
                reported_spans.add(span_key)

                findings.append(
                    DetectionFinding(
                        rule_id="SEC-CANARY-001",
                        category=RuleCategory.SECRET_EXFILTRATION,
                        severity=Severity.CRITICAL,
                        confidence=0.99,
                        evidence_span=EvidenceSpan(
                            start=found_at,
                            end=end_pos,
                            text_preview=mask_secret(canary),
                        ),
                        safe_evidence_summary=f"Detected configured canary token ({mask_secret(canary)}) in content",
                        source_context=source_ctx.source_type.value,
                        recommended_action=DecisionAction.BLOCK,
                    )
                )

            # ROT13 encoded canary scan
            rot13_canary = codecs.encode(canary, "rot_13")
            rot13_rgx = self._get_token_regex(rot13_canary)
            for match in rot13_rgx.finditer(text):
                found_at, end_pos = match.span()
                span_key = (found_at, end_pos)
                if span_key in reported_spans:
                    continue
                reported_spans.add(span_key)

                findings.append(
                    DetectionFinding(
                        rule_id="SEC-CANARY-001-ROT13",
                        category=RuleCategory.SECRET_EXFILTRATION,
                        severity=Severity.CRITICAL,
                        confidence=0.99,
                        evidence_span=EvidenceSpan(
                            start=found_at,
                            end=end_pos,
                            text_preview=mask_secret(canary),
                        ),
                        safe_evidence_summary=f"Detected ROT13-encoded canary token ({mask_secret(canary)}) in content",
                        source_context=source_ctx.source_type.value,
                        recommended_action=DecisionAction.BLOCK,
                    )
                )

        # 2. Configured Sensitive Secrets Flexible Scan
        for secret in self.configured_secrets:
            if not secret:
                continue
            token_rgx = self._get_token_regex(secret)
            for match in token_rgx.finditer(text):
                found_at, end_pos = match.span()
                span_key = (found_at, end_pos)
                if span_key in reported_spans:
                    continue
                reported_spans.add(span_key)

                findings.append(
                    DetectionFinding(
                        rule_id="SEC-CONFIG-001",
                        category=RuleCategory.SECRET_EXFILTRATION,
                        severity=Severity.CRITICAL,
                        confidence=0.98,
                        evidence_span=EvidenceSpan(
                            start=found_at,
                            end=end_pos,
                            text_preview=mask_secret(secret),
                        ),
                        safe_evidence_summary=f"Detected configured sensitive credential ({mask_secret(secret)}) in content",
                        source_context=source_ctx.source_type.value,
                        recommended_action=DecisionAction.BLOCK,
                    )
                )

        # 3. Known Secret-Like Patterns Scan
        for rule_id, pattern_name, regex, severity in SECRET_PATTERNS:
            for match in regex.finditer(text):
                matched_val = match.group(0)
                span_key = (match.start(), match.end())
                if span_key in reported_spans:
                    continue
                reported_spans.add(span_key)

                findings.append(
                    DetectionFinding(
                        rule_id=rule_id,
                        category=RuleCategory.SECRET_EXFILTRATION,
                        severity=severity,
                        confidence=0.95,
                        evidence_span=EvidenceSpan(
                            start=match.start(),
                            end=match.end(),
                            text_preview=mask_secret(matched_val),
                        ),
                        safe_evidence_summary=f"Detected credential signature matching {pattern_name} ({mask_secret(matched_val)})",
                        source_context=source_ctx.source_type.value,
                        recommended_action=DecisionAction.SANITIZE if source_ctx.source_type.value in {"uploaded_document", "retrieved_webpage"} else DecisionAction.BLOCK,
                    )
                )

        # 4. Auxiliary Channel Scan (Base64, Hex, and Decoded Payloads)
        if auxiliary_channels:
            for channel_type, decoded_text in auxiliary_channels:
                for canary in self.canary_tokens:
                    if not canary:
                        continue
                    token_rgx = self._get_token_regex(canary)
                    if token_rgx.search(decoded_text):
                        findings.append(
                            DetectionFinding(
                                rule_id="SEC-CANARY-001-ENCODED",
                                category=RuleCategory.SECRET_EXFILTRATION,
                                severity=Severity.CRITICAL,
                                confidence=0.99,
                                evidence_span=None,
                                safe_evidence_summary=f"Detected obfuscated canary token ({mask_secret(canary)}) inside decoded {channel_type}",
                                source_context=source_ctx.source_type.value,
                                recommended_action=DecisionAction.BLOCK,
                            )
                        )

                for secret in self.configured_secrets:
                    if not secret:
                        continue
                    token_rgx = self._get_token_regex(secret)
                    if token_rgx.search(decoded_text):
                        findings.append(
                            DetectionFinding(
                                rule_id="SEC-CONFIG-001-ENCODED",
                                category=RuleCategory.SECRET_EXFILTRATION,
                                severity=Severity.CRITICAL,
                                confidence=0.98,
                                evidence_span=None,
                                safe_evidence_summary=f"Detected obfuscated sensitive credential ({mask_secret(secret)}) inside decoded {channel_type}",
                                source_context=source_ctx.source_type.value,
                                recommended_action=DecisionAction.BLOCK,
                            )
                        )

                for rule_id, pattern_name, regex, severity in SECRET_PATTERNS:
                    match = regex.search(decoded_text)
                    if match:
                        matched_val = match.group(0)
                        findings.append(
                            DetectionFinding(
                                rule_id=f"{rule_id}-ENCODED",
                                category=RuleCategory.SECRET_EXFILTRATION,
                                severity=severity,
                                confidence=0.95,
                                evidence_span=None,
                                safe_evidence_summary=f"Detected credential signature matching {pattern_name} ({mask_secret(matched_val)}) inside decoded {channel_type}",
                                source_context=source_ctx.source_type.value,
                                recommended_action=DecisionAction.BLOCK,
                            )
                        )

        return findings
