"""Tests for LLM Adapter, Output Guard, and Tool Security (Section 7)."""

import pytest
from backend.detection.schemas import (
    DecisionAction,
    NormalizedContentMetadata,
    RiskClassification,
    ScanResponse,
    SourceType,
)
from backend.llm.adapter import LLMAdapter, LLMRequest, SecurityBypassException
from backend.llm.mock_provider import LLMGenerationConfig, MockLLMProvider
from backend.llm.output_guard import OutputGuard, SecurityLeakageException
from backend.tools.security import ToolExecutionRequest, ToolSecurityManager


def make_dummy_scan_response(decision: DecisionAction, sanitized_content=None) -> ScanResponse:
    return ScanResponse(
        scan_id="test-scan-uuid",
        source_type=SourceType.USER_PROMPT,
        normalized_content_metadata=NormalizedContentMetadata(
            original_length=20,
            normalized_length=20,
        ),
        findings=[],
        risk_classification=RiskClassification.SAFE if decision == DecisionAction.ALLOW else RiskClassification.HIGH,
        risk_score=0.0 if decision == DecisionAction.ALLOW else 0.8,
        recommended_action=decision,
        final_decision=decision,
        decision_reason="Testing decision",
        policy_version="v1.2.0-test",
        sanitized_content=sanitized_content,
        processing_duration_ms=1.5,
    )


def test_bypass_attempt_without_screening_rejected():
    adapter = LLMAdapter()
    req = LLMRequest(prompt="What is 2+2?", screening_result=None)
    with pytest.raises(SecurityBypassException, match="must be screened by PromptShield"):
        adapter.generate_guarded(req)


def test_blocked_request_cannot_invoke_llm():
    adapter = LLMAdapter()
    scan_resp = make_dummy_scan_response(DecisionAction.BLOCK)
    req = LLMRequest(prompt="Malicious prompt", screening_result=scan_resp)
    with pytest.raises(SecurityBypassException, match="Security policy decision is 'BLOCK'"):
        adapter.generate_guarded(req)


def test_output_guard_detects_canary_leak():
    provider = MockLLMProvider()
    guard = OutputGuard()
    adapter = LLMAdapter(provider=provider, output_guard=guard)

    scan_resp = make_dummy_scan_response(DecisionAction.ALLOW)
    req = LLMRequest(
        prompt="Tell me secret",
        screening_result=scan_resp,
        generation_config=LLMGenerationConfig(simulate_canary_leak=True),
    )

    with pytest.raises(SecurityLeakageException, match="prohibited sensitive secrets"):
        adapter.generate_guarded(req)


def test_tool_security_manager_allowlist():
    mgr = ToolSecurityManager()

    # Allowed tool
    req_ok = ToolExecutionRequest(tool_name="calculator", arguments={"expression": "5*10"})
    res_ok = mgr.validate_tool_request(req_ok)
    assert res_ok.is_authorized is True

    # Denied tool (bash)
    req_bad = ToolExecutionRequest(tool_name="bash", arguments={"command": "ls"})
    res_bad = mgr.validate_tool_request(req_bad)
    assert res_bad.is_authorized is False
    assert "explicitly forbidden" in res_bad.rejection_reason

    # Unknown tool
    req_unknown = ToolExecutionRequest(tool_name="arbitrary_plugin", arguments={})
    res_unknown = mgr.validate_tool_request(req_unknown)
    assert res_unknown.is_authorized is False
    assert "not in server-side authorized allowlist" in res_unknown.rejection_reason


def test_tool_security_manager_ssrf_protection():
    mgr = ToolSecurityManager()

    # Block localhost
    req_ssrf1 = ToolExecutionRequest(
        tool_name="search_products",
        arguments={},
        destination_url="http://127.0.0.1:8080/admin",
    )
    assert mgr.validate_tool_request(req_ssrf1).is_authorized is False

    # Block cloud metadata
    req_ssrf2 = ToolExecutionRequest(
        tool_name="search_products",
        arguments={},
        destination_url="http://169.254.169.254/latest/meta-data/",
    )
    assert mgr.validate_tool_request(req_ssrf2).is_authorized is False
