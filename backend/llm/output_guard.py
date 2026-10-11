"""Output Guard for LLM Response Inspection (Section 7).

Inspects generated model output before transmission to the user or downstream consumers.
Prevents canary token leakage, credential disclosure, and unauthorized output artifacts.
"""

from typing import List, Optional
from pydantic import BaseModel

from backend.config import settings
from backend.detection.secret_scanner import SecretScanner, mask_secret
from backend.detection.source_context import SourceContext, SourceType, TrustLevel


class OutputGuardResult(BaseModel):
    is_safe: bool
    safe_output: str
    leaked_canary_detected: bool = False
    leaked_secrets_detected: bool = False
    rejection_reason: Optional[str] = None


class SecurityLeakageException(Exception):
    """Raised when an LLM generation attempts to leak sensitive data or canary secrets."""
    pass


class OutputGuard:
    """Post-generation security filter protecting against data leakage."""

    def __init__(self, secret_scanner: Optional[SecretScanner] = None):
        self.secret_scanner = secret_scanner or SecretScanner()

    def inspect_output(self, generated_text: str) -> OutputGuardResult:
        """Inspect generated text and return safety determination."""
        if not generated_text:
            return OutputGuardResult(is_safe=True, safe_output="")

        # Create dummy context for secret scanner
        dummy_ctx = SourceContext(
            source_type=SourceType.USER_PROMPT,
            trust_level=TrustLevel.SYSTEM_INTERNAL,
            is_executive_context=False,
            allows_system_instructions=False,
        )

        findings = self.secret_scanner.scan(generated_text, dummy_ctx)

        canary_found = any(f.rule_id == "SEC-CANARY-001" for f in findings)
        secrets_found = any(f.rule_id in {"SEC-CONFIG-001", "SEC-PAT-001", "SEC-PAT-002", "SEC-PAT-003"} for f in findings)

        if canary_found or secrets_found:
            masked_reasons = [f.safe_evidence_summary for f in findings]
            return OutputGuardResult(
                is_safe=False,
                safe_output="[RESPONSE_BLOCKED_BY_PROMPTSHIELD_OUTPUT_GUARD: SENSITIVE_DATA_LEAK_PREVENTED]",
                leaked_canary_detected=canary_found,
                leaked_secrets_detected=secrets_found,
                rejection_reason=f"Model output contained prohibited sensitive secrets: {'; '.join(masked_reasons)}",
            )

        return OutputGuardResult(
            is_safe=True,
            safe_output=generated_text,
            leaked_canary_detected=False,
            leaked_secrets_detected=False,
        )
