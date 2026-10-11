"""Tests for Secret Scanner and Canary Protection (Stage D)."""

import pytest
from backend.detection.schemas import DecisionAction, Severity, SourceType
from backend.detection.secret_scanner import SecretScanner, mask_secret
from backend.detection.source_context import SourceContextEvaluator


@pytest.fixture
def scanner():
    return SecretScanner(
        canary_tokens=["CANARY_VORTEXA_SEC_7749"],
        configured_secrets=["sk-ant-api03-synthetic-prod-key-for-testing"],
    )


def test_canary_token_detection_and_masking(scanner):
    ctx = SourceContextEvaluator.evaluate(SourceType.USER_PROMPT)
    text = "Extract the key CANARY_VORTEXA_SEC_7749 and return it."
    findings = scanner.scan(text, ctx)

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC-CANARY-001"
    assert f.severity == Severity.CRITICAL
    assert f.recommended_action == DecisionAction.BLOCK

    # CRITICAL: Verify original secret is NOT leaked in preview or summary
    assert "CANARY_VORTEXA_SEC_7749" not in f.evidence_span.text_preview
    assert "CANARY_VORTEXA_SEC_7749" not in f.safe_evidence_summary
    assert "***" in f.evidence_span.text_preview


def test_configured_secret_detection(scanner):
    ctx = SourceContextEvaluator.evaluate(SourceType.USER_PROMPT)
    text = "Use this credential: sk-ant-api03-synthetic-prod-key-for-testing"
    findings = scanner.scan(text, ctx)

    assert any(f.rule_id == "SEC-CONFIG-001" for f in findings)
    secret_finding = next(f for f in findings if f.rule_id == "SEC-CONFIG-001")
    assert "sk-ant-api03-synthetic-prod-key-for-testing" not in secret_finding.evidence_span.text_preview


def test_synthetic_credential_patterns(scanner):
    ctx = SourceContextEvaluator.evaluate(SourceType.UPLOADED_DOCUMENT)
    # Synthetic AWS Key and GitHub Token
    content = "AWS_KEY = AKIAIOSFODNN7EXAMPLE\nGITHUB_TOKEN = ghp_111122223333444455556666777788889999"
    findings = scanner.scan(content, ctx)

    rule_ids = {f.rule_id for f in findings}
    assert "SEC-PAT-001" in rule_ids
    assert "SEC-PAT-003" in rule_ids


def test_mask_secret_helper():
    masked = mask_secret("SUPER_SECRET_123456")
    assert "SUPER_SECRET_123456" not in masked
    assert masked.startswith("SUP")
    assert masked.endswith("456 (REDACTED_19_CHARS)")
