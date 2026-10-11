"""PromptShield Detection Engine Service Orchestrator.

Coordinates Stages A through G:
- Stage A: Request validation and sizing limits
- Stage B: Bounded normalization and decoding
- Stage C: Multi-signal injection detection
- Stage D: Canary and secret credential detection
- Stage E: Context and calibrated risk scoring
- Stage F: Surgical sanitization (when safe)
- Stage G: Trusted policy authority handoff
"""

import time
import uuid
from typing import Optional

from backend.config import settings
from backend.detection.normalization import ContentNormalizer
from backend.detection.risk_assessment import RiskAssessmentEngine
from backend.detection.rules import InjectionRuleEngine
from backend.detection.sanitizer import ContentSanitizer
from backend.detection.schemas import (
    DecisionAction,
    DetectionFinding,
    RuleCategory,
    ScanRequest,
    ScanResponse,
    Severity,
    SourceType,
)
from backend.detection.secret_scanner import SecretScanner
from backend.detection.source_context import SourceContextEvaluator
from backend.retrieval.web_retriever import SafeWebRetriever
from backend.policy.client import PolicyClient


class DetectionEngineService:
    """Master orchestrator for content inspection and policy enforcement."""

    def __init__(
        self,
        normalizer: Optional[ContentNormalizer] = None,
        rule_engine: Optional[InjectionRuleEngine] = None,
        secret_scanner: Optional[SecretScanner] = None,
        policy_client: Optional[PolicyClient] = None,
    ):
        self.normalizer = normalizer or ContentNormalizer(max_length=settings.MAX_NORMALIZATION_LENGTH)
        self.rule_engine = rule_engine or InjectionRuleEngine()
        self.secret_scanner = secret_scanner or SecretScanner()
        self.policy_client = policy_client or PolicyClient()

    def scan(self, request: ScanRequest) -> ScanResponse:
        """Execute full end-to-end detection pipeline."""
        start_time = time.perf_counter()
        scan_id = request.scan_id or str(uuid.uuid4())

        # Resolve content to inspect & initialize trusted metadata
        content_to_scan = request.content
        trusted_metadata = dict(request.trusted_metadata or {})

        # Stage A0: Server-side URL retrieval for retrieved_webpage
        if request.source_type == SourceType.RETRIEVED_WEBPAGE:
            has_pre_retrieved_content = bool(
                content_to_scan
                and content_to_scan.strip()
                and content_to_scan.strip() != (request.url or "").strip()
            )
            if not has_pre_retrieved_content:
                target_url = request.url
                if not target_url and content_to_scan and content_to_scan.strip().startswith(("http://", "https://")) and "\n" not in content_to_scan.strip():
                    target_url = content_to_scan.strip()

                if target_url:
                    web_result = SafeWebRetriever.fetch_and_extract(target_url)
                    content_to_scan = web_result.extracted_text
                    trusted_metadata.update({
                        "retrieved_url": web_result.url,
                        "page_title": web_result.title,
                        "content_type": web_result.content_type,
                        "status_code": web_result.status_code,
                        "raw_size_bytes": web_result.raw_size_bytes,
                        "extracted_chars": web_result.extracted_chars,
                    })
            else:
                if request.url:
                    trusted_metadata["target_url"] = request.url
                trusted_metadata["input_mode"] = "pre_retrieved_web_content"
        elif request.source_type == SourceType.TOOL_OUTPUT:
            if request.tool_name:
                trusted_metadata["tool_name"] = request.tool_name
            if content_to_scan and (content_to_scan.strip().startswith("{") or content_to_scan.strip().startswith("[")):
                try:
                    import json
                    json.loads(content_to_scan)
                    trusted_metadata["is_structured_json"] = True
                except Exception:
                    trusted_metadata["is_structured_json"] = False

        if not content_to_scan or not content_to_scan.strip():
            raise ValueError("Content to scan cannot be empty or whitespace only")

        # Stage A: Request validation & content size limit enforcement
        if len(content_to_scan) > settings.MAX_CONTENT_LENGTH:
            raise ValueError(
                f"Content length ({len(content_to_scan)} chars) exceeds maximum allowed limit ({settings.MAX_CONTENT_LENGTH})"
            )

        # Stage B: Normalization & auxiliary channel extraction
        norm_result = self.normalizer.normalize(content_to_scan)

        # Evaluate source context and authority boundary
        source_ctx = SourceContextEvaluator.evaluate(
            source_type=request.source_type,
            trusted_metadata=trusted_metadata,
            application_context=request.application_context,
        )

        # Stage C: Injection detection on normalized text & auxiliary channels
        injection_findings = self.rule_engine.evaluate(
            text=norm_result.normalized_text,
            source_ctx=source_ctx,
            auxiliary_channels=norm_result.auxiliary_channels,
        )

        if request.trusted_context:
            trusted_metadata["trusted_context"] = request.trusted_context

        # Stage D: Secret and canary scanning
        secret_findings = self.secret_scanner.scan(
            text=norm_result.normalized_text,
            source_ctx=source_ctx,
            auxiliary_channels=norm_result.auxiliary_channels,
            extra_tokens=request.protected_values,
        )

        # Check simulated external destination transfer
        destination_findings = []
        if request.destination:
            dest = request.destination.strip().lower()
            trusted_metadata["destination"] = request.destination
            unauthorized_dest_patterns = [
                "attacker", "evil", "exfil", "webhook.site", "pipedream", "requestbin", "ngrok", "burp",
                "169.254.169.254", "metadata.google", "leak", "sink"
            ]
            if any(p in dest for p in unauthorized_dest_patterns) or (
                dest.startswith(("http://", "https://")) and not any(wh in dest for wh in ["localhost", "127.0.0.1", "promptshield.internal"])
            ):
                if any(kw in norm_result.normalized_text.lower() for kw in ["send", "forward", "transmit", "exfiltrate", "post", "leak", "upload", "curl", "fetch"]):
                    destination_findings.append(
                        DetectionFinding(
                            rule_id="EXF-DEST-001",
                            category=RuleCategory.DATA_TRANSFER,
                            severity=Severity.HIGH,
                            confidence=0.92,
                            evidence_span=None,
                            safe_evidence_summary=f"Attempted data transfer to unauthorized external destination ({request.destination[:40]})",
                            source_context=source_ctx.source_type.value,
                            recommended_action=DecisionAction.BLOCK,
                        )
                    )

        # Combine all explainable findings
        all_findings = injection_findings + secret_findings + destination_findings

        # Stage E: Risk assessment and calibrated scoring
        risk_score, risk_classification, recommended_action = RiskAssessmentEngine.assess(
            findings=all_findings,
            source_ctx=source_ctx,
        )

        # Stage F: Sanitization (attempted only when recommended action is SANITIZE)
        sanitized_content = None
        if recommended_action == DecisionAction.SANITIZE:
            sanit_result = ContentSanitizer.sanitize(
                content=content_to_scan,
                findings=all_findings,
            )
            if sanit_result.is_safe and sanit_result.sanitized_content is not None:
                # Invariant: Sanitized content is revalidated before forwarding
                reval_norm = self.normalizer.normalize(sanit_result.sanitized_content)
                reval_injection = self.rule_engine.evaluate(
                    text=reval_norm.normalized_text,
                    source_ctx=source_ctx,
                    auxiliary_channels=reval_norm.auxiliary_channels,
                )
                reval_secrets = self.secret_scanner.scan(reval_norm.normalized_text, source_ctx)
                reval_threats = [
                    f for f in (reval_injection + reval_secrets)
                    if f.severity in (Severity.HIGH, Severity.CRITICAL)
                ]
                if reval_threats:
                    sanitized_content = None
                    recommended_action = DecisionAction.BLOCK
                else:
                    sanitized_content = sanit_result.sanitized_content
            else:
                # Sanitization could not be safely guaranteed -> upgrade to fallback action
                recommended_action = sanit_result.fallback_action

        # Stage G: Policy handoff to trusted authority (Laptop 3)
        policy_result = self.policy_client.evaluate_decision(
            source_type=request.source_type,
            findings=all_findings,
            risk_classification=risk_classification,
            risk_score=risk_score,
            recommended_action=recommended_action,
            tenant_context=request.tenant_context,
        )

        # Finalize sanitized content availability
        if policy_result.final_decision == DecisionAction.ALLOW and sanitized_content is None:
            # Safe original content allowed through
            sanitized_content = content_to_scan
        elif policy_result.final_decision != DecisionAction.SANITIZE and policy_result.final_decision != DecisionAction.ALLOW:
            # Blocked or escalated content must not be forwarded
            sanitized_content = None

        duration_ms = round((time.perf_counter() - start_time) * 1000.0, 3)

        return ScanResponse(
            scan_id=scan_id,
            source_type=request.source_type,
            normalized_content_metadata=norm_result.metadata,
            findings=all_findings,
            risk_classification=risk_classification,
            risk_score=risk_score,
            recommended_action=recommended_action,
            final_decision=policy_result.final_decision,
            decision_reason=policy_result.decision_reason,
            policy_version=policy_result.policy_version,
            sanitized_content=sanitized_content,
            processing_duration_ms=duration_ms,
            action=policy_result.final_decision,
            risk_level=risk_classification.value,
            reason=policy_result.decision_reason,
        )
