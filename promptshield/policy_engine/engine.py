from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field

from promptshield.config import settings
from promptshield.db.models import SecurityPolicy
from promptshield.schemas.scan import DetectionFinding, MatchedSpan
from promptshield.policy_engine.precedence import (
    resolve_action_precedence,
    resolve_highest_severity,
    get_action_rank,
)
from promptshield.policy_engine.sanitizer import excise_offending_spans


@dataclass
class PolicyEvaluationResult:
    action: str
    risk_classification: str
    reason_codes: List[str] = field(default_factory=list)
    sanitized_content: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: int = 1
    rule_triggers: List[Dict[str, Any]] = field(default_factory=list)


class PolicyEngine:
    """
    Authoritative, deterministic policy evaluation engine.
    Guarantees:
    - Precedence: BLOCK > ESCALATE > SANITIZE > ALLOW
    - Fail-secure: missing or invalid configuration defaults to BLOCK
    - Untrusted source rigor: Tool outputs and retrieved documents receive stricter screening
    - Conflicting rule resolution: An allow rule cannot override high-severity exfiltration or prompt injection.
    """

    @classmethod
    def evaluate(
        cls,
        policy: Optional[SecurityPolicy],
        source_type: str,
        findings: List[DetectionFinding],
        content_to_sanitize: Optional[str] = None,
    ) -> PolicyEvaluationResult:
        # 1. Fail-Secure Guard: If policy is absent or inactive
        if not policy or not policy.is_enabled:
            if settings.FAIL_SECURE_MODE:
                return PolicyEvaluationResult(
                    action=settings.DEFAULT_FAIL_SECURE_ACTION,
                    risk_classification="HIGH",
                    reason_codes=["POLICY_MISSING_OR_DISABLED_FAIL_SECURE_TRIGGERED"],
                    policy_id=policy.id if policy else None,
                    policy_version=policy.current_version if policy else 0,
                )
            else:
                return PolicyEvaluationResult(
                    action="ALLOW",
                    risk_classification="BENIGN",
                    reason_codes=["POLICY_ABSENT_FAIL_INSECURE_WARNING"],
                    policy_id=None,
                    policy_version=0,
                )

        # 2. Source Applicability Guard
        applicability = policy.source_applicability or []
        if applicability and source_type.upper() not in [s.upper() for s in applicability]:
            # Policy does not explicitly authorize this source type
            return PolicyEvaluationResult(
                action="BLOCK",
                risk_classification="HIGH",
                reason_codes=[f"SOURCE_TYPE_{source_type.upper()}_NOT_PERMITTED_BY_POLICY"],
                policy_id=policy.id,
                policy_version=policy.current_version,
            )

        # 3. Base initialization
        current_action = policy.default_action.upper()
        reason_codes: List[str] = []
        rule_triggers: List[Dict[str, Any]] = []
        severities: List[str] = []
        spans_to_excise: List[MatchedSpan] = []

        # If findings are empty, return baseline default
        if not findings:
            return PolicyEvaluationResult(
                action=current_action,
                risk_classification="BENIGN",
                reason_codes=[f"BASELINE_DEFAULT_{current_action}_APPLIED", "NO_THREAT_FINDINGS_REPORTED"],
                policy_id=policy.id,
                policy_version=policy.current_version,
            )

        # 4. Evaluate each detection finding against policy rules
        severity_map = policy.severity_thresholds or {
            "CRITICAL": "BLOCK",
            "HIGH": "BLOCK",
            "MEDIUM": "ESCALATE",
            "LOW": "ALLOW"
        }
        
        rule_config = policy.rule_config or {}
        custom_rules = rule_config.get("rules", [])

        # Stricter multiplier for untrusted indirect sources (RETRIEVED_DOC, TOOL_OUTPUT)
        is_untrusted_indirect_source = source_type.upper() in ["RETRIEVED_DOC", "TOOL_OUTPUT"]

        for finding in findings:
            severities.append(finding.severity.upper())
            finding_action = severity_map.get(finding.severity.upper(), "ESCALATE")
            matched_rule_name = None

            # Check explicit category rules in policy rule_config
            for rule in custom_rules:
                cat_match = rule.get("category", "").upper() == finding.threat_category.upper()
                detector_match = rule.get("detector_name", "").lower() == finding.detector_name.lower()
                
                if cat_match or detector_match:
                    rule_action = rule.get("action", "").upper()
                    if rule_action in ["BLOCK", "ESCALATE", "SANITIZE", "ALLOW"]:
                        finding_action = rule_action
                        matched_rule_name = rule.get("name", finding.threat_category)
                        break

            # Stricter enforcement for indirect untrusted sources
            if is_untrusted_indirect_source:
                if finding.threat_category.upper() in ["INDIRECT_INJECTION", "DATA_EXFILTRATION", "SYSTEM_PROMPT_OVERRIDE"]:
                    if finding_action == "ALLOW":
                        finding_action = "ESCALATE"
                        reason_codes.append(f"UNTRUSTED_SOURCE_{source_type.upper()}_ELEVATED_TO_ESCALATE")

            # Collect spans if sanitization is flagged
            if finding_action == "SANITIZE" and finding.matched_spans:
                spans_to_excise.extend(finding.matched_spans)

            # Record rule trigger
            rule_triggers.append({
                "detector": finding.detector_name,
                "category": finding.threat_category,
                "severity": finding.severity,
                "action": finding_action,
                "rule": matched_rule_name,
            })

            # Record reason code
            reason_codes.append(
                f"FINDING_{finding.threat_category.upper()}_{finding.severity.upper()}_{finding_action}"
            )

            # Deterministic precedence resolution
            current_action = resolve_action_precedence(current_action, finding_action)

        # 5. Determine overall risk classification
        risk_class = resolve_highest_severity(severities)

        # 6. Process SANITIZE action if active
        sanitized_text: Optional[str] = None
        if current_action == "SANITIZE":
            if content_to_sanitize is not None:
                sanitized_text, is_safe = excise_offending_spans(content_to_sanitize, spans_to_excise)
                if not is_safe:
                    # Sanitization did not leave viable safe text; fail-secure to BLOCK
                    current_action = "BLOCK"
                    reason_codes.append("SANITIZATION_FAILED_ESCALATED_TO_BLOCK")
                    sanitized_text = None
                else:
                    reason_codes.append("CONTENT_SURGICALLY_SANITIZED")
            else:
                # Sanitization requested but no candidate payload provided to excise
                current_action = "BLOCK"
                reason_codes.append("NO_PAYLOAD_PROVIDED_FOR_SANITIZATION_ESCALATED_TO_BLOCK")

        return PolicyEvaluationResult(
            action=current_action,
            risk_classification=risk_class,
            reason_codes=reason_codes,
            sanitized_content=sanitized_text,
            policy_id=policy.id,
            policy_version=policy.current_version,
            rule_triggers=rule_triggers,
        )
