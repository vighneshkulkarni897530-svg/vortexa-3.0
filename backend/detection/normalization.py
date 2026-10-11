"""Content normalization engine for PromptShield (Stage B).

Provides bounded, safe normalization:
- Unicode NFKC normalization
- Homoglyph and confusable folding (Cyrillic, Greek, fullwidth lookalikes)
- Zero-width character and directional override stripping
- Repeated whitespace collapse
- Bounded URL unquoting (up to 2 passes)
- Safe HTML entity decoding
- Bounded Base64 and Hex inspection (without code execution)
"""

import base64
import html
import re
import unicodedata
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from backend.detection.schemas import NormalizedContentMetadata


# Common homoglyph mappings (Cyrillic, Greek, math alphabet -> Latin ASCII equivalents)
HOMOGLYPH_MAP: Dict[str, str] = {
    # Cyrillic lowercase
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    # Cyrillic uppercase
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I", "Ј": "J", "К": "K", "М": "M", "О": "O",
    "Р": "P", "Т": "T", "Х": "X",
    # Greek lowercase & uppercase
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ο": "o", "ρ": "p", "υ": "u", "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X", "Ζ": "Z",
    # Mathematical / fullwidth characters
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e", "ｆ": "f", "ｇ": "g", "ｈ": "h",
    "ｉ": "i", "ｊ": "j", "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o", "ｐ": "p",
    "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t", "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x",
    "ｙ": "y", "ｚ": "z",
}

# Zero-width and control characters often used to evade keyword filters
ZERO_WIDTH_CHARS: Set[str] = {
    "\u200B",  # Zero-width space
    "\u200C",  # Zero-width non-joiner
    "\u200D",  # Zero-width joiner
    "\uFEFF",  # Byte order mark / zero-width no-break space
    "\u2060",  # Word joiner
    "\u200E",  # Left-to-right mark
    "\u200F",  # Right-to-left mark
    "\u202A",  # Left-to-right embedding
    "\u202B",  # Right-to-left embedding
    "\u202C",  # Pop directional formatting
    "\u202D",  # Left-to-right override
    "\u202E",  # Right-to-left override
    "\x00",    # Null byte
}

BASE64_PATTERN = re.compile(r"(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
HEX_PATTERN = re.compile(r"(?:(?:\\x|0x)[0-9a-fA-F]{2}){4,}")


@dataclass
class NormalizationResult:
    """Carries original, normalized text and detected metadata."""
    original_text: str
    normalized_text: str
    auxiliary_channels: List[Tuple[str, str]]  # (channel_type, decoded_text)
    metadata: NormalizedContentMetadata


class ContentNormalizer:
    """Normalizes text for robust security inspection while preserving original content."""

    def __init__(self, max_length: int = 200000):
        self.max_length = max_length

    def normalize(self, text: str) -> NormalizationResult:
        """Run safe, multi-pass bounded normalization."""
        if not text:
            return NormalizationResult(
                original_text="",
                normalized_text="",
                auxiliary_channels=[],
                metadata=NormalizedContentMetadata(
                    original_length=0,
                    normalized_length=0,
                    transformations_applied=[],
                    encodings_detected=[],
                ),
            )

        original_length = len(text)
        transformations: List[str] = []
        encodings: List[str] = []
        has_unicode_norm = False
        has_homoglyphs = False
        has_collapsed_ws = False

        working_text = text[: self.max_length]

        # 0. Directional override (BiDi) un-reversal
        if "\u202e" in working_text:
            def reverse_bidi(m):
                return m.group(1)[::-1]
            working_text = re.sub(r"\u202e([^\u202c]*?)(?:\u202c|$)", reverse_bidi, working_text)
            transformations.append("bidi_override_reversed")
            encodings.append("bidi_override")

        # 1. Zero-width character detection & stripping
        cleaned_chars = []
        stripped_zero_width = False
        for char in working_text:
            if char in ZERO_WIDTH_CHARS:
                stripped_zero_width = True
            else:
                cleaned_chars.append(char)

        if stripped_zero_width:
            working_text = "".join(cleaned_chars)
            transformations.append("zero_width_stripped")

        # 2. Unicode NFKC Normalization
        nfkc_text = unicodedata.normalize("NFKC", working_text)
        if nfkc_text != working_text:
            has_unicode_norm = True
            transformations.append("unicode_nfkc")
            working_text = nfkc_text

        # 3. Homoglyph / Confusable Folding
        folded_chars = []
        for char in working_text:
            if char in HOMOGLYPH_MAP:
                folded_chars.append(HOMOGLYPH_MAP[char])
                has_homoglyphs = True
            else:
                folded_chars.append(char)

        if has_homoglyphs:
            working_text = "".join(folded_chars)
            transformations.append("homoglyphs_folded")

        # 4. HTML entity decoding (safe bounded pass)
        if "&" in working_text and (";" in working_text or "#" in working_text):
            html_decoded = html.unescape(working_text)
            if html_decoded != working_text:
                working_text = html_decoded
                encodings.append("html_entities")
                transformations.append("html_entities_decoded")

        # 5. URL unquoting (bounded up to 2 passes to handle double encoding)
        if "%" in working_text:
            pass1 = urllib.parse.unquote(working_text)
            if pass1 != working_text:
                encodings.append("url_encoding")
                transformations.append("url_decoded_pass1")
                working_text = pass1
                if "%" in working_text:
                    pass2 = urllib.parse.unquote(working_text)
                    if pass2 != working_text:
                        transformations.append("url_decoded_pass2")
                        working_text = pass2

        # 6. Whitespace collapse for rule evaluation
        collapsed = re.sub(r"[ \t\f\v]+", " ", working_text)
        collapsed = re.sub(r"[\r\n]{3,}", "\n\n", collapsed)
        if collapsed != working_text:
            has_collapsed_ws = True
            transformations.append("whitespace_collapsed")
            working_text = collapsed

        # 7. Auxiliary channel inspection: Base64 and Hex extraction (NON-EXECUTING)
        auxiliary_channels: List[Tuple[str, str]] = []

        # Bounded Base64 detection
        b64_matches = BASE64_PATTERN.findall(text)
        for match in b64_matches[:5]:  # Bound to first 5 matches
            try:
                decoded_bytes = base64.b64decode(match, validate=True)
                # Ensure it's valid UTF-8/ASCII printable text
                decoded_str = decoded_bytes.decode("utf-8")
                if len(decoded_str) >= 8 and any(c.isalpha() for c in decoded_str):
                    auxiliary_channels.append(("base64_payload", decoded_str))
                    if "base64" not in encodings:
                        encodings.append("base64")
            except Exception:
                continue

        # Hex detection
        hex_matches = HEX_PATTERN.findall(text)
        for match in hex_matches[:5]:
            try:
                clean_hex = match.replace("\\x", "").replace("0x", "")
                decoded_bytes = bytes.fromhex(clean_hex)
                decoded_str = decoded_bytes.decode("utf-8")
                if len(decoded_str) >= 6:
                    auxiliary_channels.append(("hex_payload", decoded_str))
                    if "hex" not in encodings:
                        encodings.append("hex")
            except Exception:
                continue

        metadata = NormalizedContentMetadata(
            original_length=original_length,
            normalized_length=len(working_text),
            transformations_applied=transformations,
            encodings_detected=encodings,
            has_unicode_normalization=has_unicode_norm,
            has_homoglyphs=has_homoglyphs,
            has_collapsed_whitespace=has_collapsed_ws,
        )

        return NormalizationResult(
            original_text=text,
            normalized_text=working_text,
            auxiliary_channels=auxiliary_channels,
            metadata=metadata,
        )
