"""Tests for Source Context and Authority Boundaries (Section 4 & 6)."""

import pytest
from backend.detection.schemas import SourceType
from backend.detection.source_context import SourceContextEvaluator, TrustLevel


def test_user_prompt_source_context():
    ctx = SourceContextEvaluator.evaluate(SourceType.USER_PROMPT)
    assert ctx.trust_level == TrustLevel.SEMI_TRUSTED_PROMPT
    assert ctx.is_executive_context is True
    assert ctx.allows_system_instructions is False


def test_uploaded_document_source_context():
    ctx = SourceContextEvaluator.evaluate(SourceType.UPLOADED_DOCUMENT)
    assert ctx.trust_level == TrustLevel.UNTRUSTED_DATA
    assert ctx.is_executive_context is False
    assert ctx.allows_system_instructions is False


def test_retrieved_webpage_source_context():
    ctx = SourceContextEvaluator.evaluate(SourceType.RETRIEVED_WEBPAGE)
    assert ctx.trust_level == TrustLevel.UNTRUSTED_EXTERNAL
    assert ctx.is_executive_context is False
    assert ctx.allows_system_instructions is False


def test_client_cannot_elevate_privilege():
    # Attempt to spoof administrative metadata
    malicious_meta = {"is_admin": True, "allow_override": True, "trust_level": "SYSTEM_INTERNAL"}
    ctx = SourceContextEvaluator.evaluate(
        source_type=SourceType.USER_PROMPT,
        trusted_metadata=malicious_meta,
    )
    # Server logic rejects spoofed level
    assert ctx.trust_level == TrustLevel.SEMI_TRUSTED_PROMPT
    assert ctx.allows_system_instructions is False
