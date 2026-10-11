from typing import List, Tuple, Optional
from promptshield.schemas.scan import MatchedSpan
from promptshield.security.sanitization import sanitize_text


def excise_offending_spans(
    content: str,
    spans: List[MatchedSpan],
    default_replacement: str = "[REDACTED_SPAN]"
) -> Tuple[str, bool]:
    """
    Surgically remove identified offending spans while preserving legitimate surrounding text.
    Sorts spans in reverse order to preserve indexing offsets.
    Returns (sanitized_text, is_safe).
    """
    if not content:
        return "", True
    
    if not spans:
        # No specific spans to excise; apply heuristic secret mask
        sanitized = sanitize_text(content)
        return sanitized, True

    # Filter and validate valid span bounds
    valid_spans = []
    content_len = len(content)
    for span in spans:
        if 0 <= span.start <= span.end <= content_len:
            valid_spans.append(span)

    if not valid_spans:
        # Invalid span coordinates
        return content, False

    # Sort descending by start to avoid shifting indices
    sorted_spans = sorted(valid_spans, key=lambda s: (s.start, s.end), reverse=True)

    result = content
    for span in sorted_spans:
        replacement = span.replacement if span.replacement is not None else default_replacement
        result = result[:span.start] + replacement + result[span.end:]

    # Secondary sanitization pass to ensure no raw secrets leaked in unspanned regions
    cleaned = sanitize_text(result)

    # Post-sanitization verification: Ensure non-trivial safe content remains
    is_safe = True
    if len(cleaned.strip()) == 0:
        # Everything was excised; cannot forward empty content
        is_safe = False

    return cleaned, is_safe
