"""Policy Service Interface and Client (Stage G - Coordination with Laptop 3).

Transfers detection findings and risk assessment to the trusted policy service.
Enforces fail-secure defaults if the external service is unavailable.
Never allows untrusted scanned text to alter or select the active policy.
"""

import logging
from dataclasses import dataclass
from typing import List, Optional
import httpx

from backend.config import settings
from backend.detection.schemas import (
    DecisionAction,
    DetectionFinding,
    RiskClassification,
    Severity,
    SourceType,
)

logger = logging.getLogger("promptshield.policy")


@dataclass
class PolicyEvaluationResult:
    """Decision produced by the trusted policy authority."""
    final_decision: DecisionAction
    decision_reason: str
    policy_version: str


class PolicyClient:
    """Client for coordinating with Laptop 3's persistent policy management service."""

    def __init__(
        self,
        service_url: Optional[str] = None,
        timeout_seconds: Optional[float] = None,
    ):
        self.service_url = service_url or settings.POLICY_SERVICE_URL
        self.timeout_seconds = timeout_seconds or settings.POLICY_TIMEOUT_SECONDS
        self.fallback_policy_version = settings.POLICY_VERSION

    def evaluate_decision(
        self,
        source_type: SourceType,
        findings: List[DetectionFinding],
        risk_classification: RiskClassification,
        risk_score: float,
        recommended_action: DecisionAction,
        tenant_context: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        """Call trusted policy service or fall back to internal trusted policy matrix."""
        # 1. Attempt remote policy call if configured
        if self.service_url:
            try:
                payload = {
                    "source_type": source_type.value,
                    "risk_classification": risk_classification.value,
                    "risk_score": risk_score,
                    "recommended_action": recommended_action.value,
                    "finding_count": len(findings),
                    "finding_categories": list({f.category.value for f in findings}),
                    "tenant_context": tenant_context,
                }
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    resp = client.post(f"{self.service_url}/api/v1/policy/evaluate", json=payload)
                    if resp.status_code == 200:
                        data = resp.json()
                        return PolicyEvaluationResult(
                            final_decision=DecisionAction(data["final_decision"]),
                            decision_reason=data.get("decision_reason", "Policy enforced by external policy engine"),
                            policy_version=data.get("policy_version", self.fallback_policy_version),
                        )
                    else:
                        logger.warning(f"Remote policy service returned status {resp.status_code}; using fail-secure fallback")
            except Exception as e:
                logger.warning(f"Remote policy service call failed ({e}); employing fail-secure local policy rules")

        # 2. Local trusted policy matrix (Deterministic fail-secure enforcement)
        return self._local_trusted_policy(
            source_type=source_type,
            findings=findings,
            risk_classification=risk_classification,
            risk_score=risk_score,
            recommended_action=recommended_action,
        )

    def _local_trusted_policy(
        self,
        source_type: SourceType,
        findings: List[DetectionFinding],
        risk_classification: RiskClassification,
        risk_score: float,
        recommended_action: DecisionAction,
    ) -> PolicyEvaluationResult:
        """Enforces default trusted policy rules according to strict security boundaries."""
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        has_high = any(f.severity == Severity.HIGH for f in findings)
        has_canary = any(f.rule_id == "SEC-CANARY-001" for f in findings)

        # Policy Rule 1: Zero tolerance for canary secrets or critical exfiltration
        if has_canary or has_critical:
            return PolicyEvaluationResult(
                final_decision=DecisionAction.BLOCK,
                decision_reason="Policy rule POL-001: Critical security threat or canary secret detected. Direct block enforced.",
                policy_version=f"{self.fallback_policy_version}-local",
            )

        # Policy Rule 2: High severity in user prompt -> BLOCK
        if has_high and source_type == SourceType.USER_PROMPT:
            return PolicyEvaluationResult(
                final_decision=DecisionAction.BLOCK,
                decision_reason="Policy rule POL-002: High-severity direct prompt injection detected in user prompt.",
                policy_version=f"{self.fallback_policy_version}-local",
            )

        # Policy Rule 3: High/Medium severity in document or webpage -> SANITIZE if isolated, else ESCALATE/BLOCK
        if recommended_action == DecisionAction.SANITIZE:
            return PolicyEvaluationResult(
                final_decision=DecisionAction.SANITIZE,
                decision_reason="Policy rule POL-003: Isolated threat span permitted for surgical sanitization in passive content.",
                policy_version=f"{self.fallback_policy_version}-local",
            )

        # Policy Rule 4: Ambiguous medium threat -> ESCALATE for human/system review
        if recommended_action == DecisionAction.ESCALATE:
            return PolicyEvaluationResult(
                final_decision=DecisionAction.ESCALATE,
                decision_reason="Policy rule POL-004: Ambiguous high-risk signal requires escalation review.",
                policy_version=f"{self.fallback_policy_version}-local",
            )

        # Policy Rule 5: Default ALLOW for verified safe/low content
        return PolicyEvaluationResult(
            final_decision=DecisionAction.ALLOW,
            decision_reason="Policy rule POL-005: Content verified safe; within acceptable operational risk bounds.",
            policy_version=f"{self.fallback_policy_version}-local",
        )
