"""Secret and Sensitive Data Scanner (Stage D).

Detects test canary tokens, explicitly configured sensitive values, and
secret patterns (API keys, tokens, private keys) without leaking matched
values in findings, previews, logs, or error responses.
"""

import math
import re
from typing import List, Optional, Set, Tuple

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


class SecretScanner:
    """Scans content for canary secrets and sensitive credential patterns."""

    def __init__(
        self,
        canary_tokens: Optional[List[str]] = None,
        configured_secrets: Optional[List[str]] = None,
    ):
        self.canary_tokens: Set[str] = set(canary_tokens or settings.CANARY_TOKENS)
        self.configured_secrets: Set[str] = set(configured_secrets or settings.CONFIGURED_SENSITIVE_KEYS)

    def scan(self, text: str, source_ctx: SourceContext) -> List[DetectionFinding]:
        """Scan text and return findings with safe redacted evidence."""
        findings: List[DetectionFinding] = []
        if not text:
            return findings

        # 1. Canary Token Exact & Substring Scan
        for canary in self.canary_tokens:
            if not canary:
                continue
            idx = 0
            while True:
                found_at = text.find(canary, idx)
                if found_at == -1:
                    break
                end_pos = found_at + len(canary)
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
                idx = end_pos

        # 2. Configured Sensitive Secrets Scan
        for secret in self.configured_secrets:
            if not secret:
                continue
            idx = 0
            while True:
                found_at = text.find(secret, idx)
                if found_at == -1:
                    break
                end_pos = found_at + len(secret)
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
                idx = end_pos

        # 3. Known Secret-Like Patterns Scan
        for rule_id, pattern_name, regex, severity in SECRET_PATTERNS:
            for match in regex.finditer(text):
                matched_val = match.group(0)
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

        return findings
