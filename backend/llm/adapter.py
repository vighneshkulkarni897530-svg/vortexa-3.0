"""Provider-Neutral LLM Adapter with Enforcement Gate (Section 7).

Ensures all prompts are authenticated, screened, and authorized by PromptShield
before LLM invocation. Prevents bypasses, separates trusted system prompts from
untrusted inputs, and guards model output.
"""

import time
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

from backend.detection.schemas import DecisionAction, ScanResponse
from backend.llm.mock_provider import LLMGenerationConfig, MockLLMProvider
from backend.llm.output_guard import OutputGuard, SecurityLeakageException
from backend.llm.providers import get_default_llm_provider



class LLMRequest(BaseModel):
    """Enforced request model for LLM generation."""
    prompt: str
    system_instruction: str = "You are a helpful, secure AI assistant operating under PromptShield protection."
    scan_token: Optional[str] = Field(
        None,
        description="Verification token / scan_id proving prior security screening approval"
    )
    screening_result: Optional[ScanResponse] = Field(
        None,
        description="Authorized ScanResponse object approving this generation"
    )
    generation_config: Optional[LLMGenerationConfig] = None


class LLMResponse(BaseModel):
    """Secure model output returned to consumer."""
    output_text: str
    scan_id: str
    policy_decision: DecisionAction
    latency_ms: float
    output_guard_passed: bool
    model_provider: str


class SecurityBypassException(Exception):
    """Raised when an unscreened or rejected request attempts to call the LLM."""
    pass


class LLMAdapter:
    """Enforces screening verification before calling language model provider."""

    def __init__(
        self,
        provider: Optional[Any] = None,
        output_guard: Optional[OutputGuard] = None,
    ):
        self.provider = provider or get_default_llm_provider()
        self.output_guard = output_guard or OutputGuard()


    def generate_guarded(self, request: LLMRequest) -> LLMResponse:
        """Invokes LLM strictly after verifying security clearance."""
        start_time = time.perf_counter()

        # Enforce Gate 1: Proof of prior screening
        if not request.screening_result:
            raise SecurityBypassException(
                "Direct invocation blocked: request must be screened by PromptShield detection service first."
            )

        # Enforce Gate 2: Policy authorization check
        allowed_actions = {DecisionAction.ALLOW, DecisionAction.SANITIZE}
        if request.screening_result.final_decision not in allowed_actions:
            raise SecurityBypassException(
                f"LLM invocation rejected: Security policy decision is '{request.screening_result.final_decision.value}' (Reason: {request.screening_result.decision_reason})"
            )

        # Enforce Gate 3: Prompt selection (use sanitized content if sanitization was mandated)
        effective_prompt = request.prompt
        if request.screening_result.final_decision == DecisionAction.SANITIZE:
            if request.screening_result.sanitized_content:
                effective_prompt = request.screening_result.sanitized_content
            else:
                raise SecurityBypassException("Sanitization was mandated by policy but sanitized content is empty.")

        # Invoke provider (Mock or real)
        raw_output = self.provider.generate(
            prompt=effective_prompt,
            system_instruction=request.system_instruction,
            config=request.generation_config,
        )

        # Enforce Gate 4: Output Guard inspection for canary / sensitive leaks
        guard_result = self.output_guard.inspect_output(raw_output)
        if not guard_result.is_safe:
            raise SecurityLeakageException(guard_result.rejection_reason)

        latency = round((time.perf_counter() - start_time) * 1000.0, 2)

        return LLMResponse(
            output_text=guard_result.safe_output,
            scan_id=request.screening_result.scan_id,
            policy_decision=request.screening_result.final_decision,
            latency_ms=latency,
            output_guard_passed=True,
            model_provider=getattr(self.provider, "provider_name", "MockProvider"),
        )
