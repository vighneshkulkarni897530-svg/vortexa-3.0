"""Safe Content Sanitizer (Stage F).

Provides surgical, explainable span removal for isolated injection or
sensitive spans. Ensures unrelated text is preserved, never silently rewrites
the entire message, and aborts to BLOCK or ESCALATE when sanitization cannot
be guaranteed safe.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

from backend.detection.schemas import DecisionAction, DetectionFinding


@dataclass
class SanitizationResult:
    """Outcome of content sanitization."""
    is_safe: bool
    sanitized_content: Optional[str]
    removed_spans_count: int
    bytes_removed: int
    fallback_action: DecisionAction = DecisionAction.BLOCK
    audit_notes: str = ""


class ContentSanitizer:
    """Surgically strips malicious or sensitive spans from content."""

    @staticmethod
    def sanitize(
        content: str,
        findings: List[DetectionFinding],
    ) -> SanitizationResult:
        """Sanitize content by removing offending spans identified in findings.

        Returns SanitizationResult with safe preview if successful, or fallback action.
        """
        if not content:
            return SanitizationResult(
                is_safe=True,
                sanitized_content="",
                removed_spans_count=0,
                bytes_removed=0,
                audit_notes="Empty content, nothing to sanitize.",
            )

        # Only sanitize actionable findings with defined evidence spans
        actionable_findings = [
            f for f in findings if f.recommended_action in {DecisionAction.SANITIZE, DecisionAction.BLOCK}
        ]

        if not actionable_findings:
            return SanitizationResult(
                is_safe=True,
                sanitized_content=content,
                removed_spans_count=0,
                bytes_removed=0,
                audit_notes="No actionable findings; original content preserved.",
            )

        # Verify that all actionable findings have isolated, valid evidence spans
        spans_to_remove: List[Tuple[int, int, str]] = []
        for f in actionable_findings:
            if f.evidence_span is None:
                # Diffuse, obfuscated, or unspanned finding cannot be surgically sanitized
                return SanitizationResult(
                    is_safe=False,
                    sanitized_content=None,
                    removed_spans_count=0,
                    bytes_removed=0,
                    fallback_action=DecisionAction.BLOCK,
                    audit_notes=f"Cannot guarantee safe sanitization: finding {f.rule_id} has no isolated span.",
                )
            spans_to_remove.append(
                (f.evidence_span.start, f.evidence_span.end, f.rule_id)
            )

        # Sort spans by start offset
        spans_to_remove.sort(key=lambda s: s[0])

        # Merge overlapping spans
        merged_spans: List[Tuple[int, int, List[str]]] = []
        for start, end, rule_id in spans_to_remove:
            # Bound check
            start = max(0, min(start, len(content)))
            end = max(start, min(end, len(content)))
            if not merged_spans:
                merged_spans.append((start, end, [rule_id]))
            else:
                last_start, last_end, rule_ids = merged_spans[-1]
                if start <= last_end:
                    merged_spans[-1] = (last_start, max(last_end, end), rule_ids + [rule_id])
                else:
                    merged_spans.append((start, end, [rule_id]))

        # Calculate total characters being removed
        total_removed_chars = sum(end - start for start, end, _ in merged_spans)
        original_length = len(content)

        # If > 70% of the text is malicious or if legitimate text is effectively empty,
        # sanitization would alter the request entirely -> fallback to BLOCK
        if original_length > 0 and (total_removed_chars / original_length > 0.70):
            return SanitizationResult(
                is_safe=False,
                sanitized_content=None,
                removed_spans_count=len(merged_spans),
                bytes_removed=total_removed_chars,
                fallback_action=DecisionAction.BLOCK,
                audit_notes="Offending spans comprise >70% of payload; safe partial sanitization impossible.",
            )

        # Perform surgical removal / replacement
        sanitized_parts = []
        last_idx = 0
        for start, end, rule_ids in merged_spans:
            sanitized_parts.append(content[last_idx:start])
            marker = f" [REMOVED_SECURITY_SPAN: {','.join(set(rule_ids))}] "
            sanitized_parts.append(marker)
            last_idx = end

        sanitized_parts.append(content[last_idx:])
        sanitized_text = "".join(sanitized_parts)

        # Ensure we didn't leave only blank whitespace or markers
        clean_text_check = sanitized_text
        for _, _, rule_ids in merged_spans:
            clean_text_check = clean_text_check.replace(
                f"[REMOVED_SECURITY_SPAN: {','.join(set(rule_ids))}]", ""
            )

        if not clean_text_check.strip():
            return SanitizationResult(
                is_safe=False,
                sanitized_content=None,
                removed_spans_count=len(merged_spans),
                bytes_removed=total_removed_chars,
                fallback_action=DecisionAction.BLOCK,
                audit_notes="Sanitization resulted in empty legitimate text.",
            )

        return SanitizationResult(
            is_safe=True,
            sanitized_content=sanitized_text,
            removed_spans_count=len(merged_spans),
            bytes_removed=total_removed_chars,
            audit_notes=f"Successfully excised {len(merged_spans)} isolated malicious span(s).",
        )
