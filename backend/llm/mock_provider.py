"""Mock LLM Provider for offline demonstrations and verification."""

import time
from typing import Dict, Optional
from pydantic import BaseModel


class LLMGenerationConfig(BaseModel):
    temperature: float = 0.0
    max_tokens: int = 512
    simulate_canary_leak: bool = False


class MockLLMProvider:
    """Mock LLM provider generating deterministic responses without external network access."""

    def __init__(self, provider_name: str = "MockVortexaLLM-v3"):
        self.provider_name = provider_name

    def generate(
        self,
        prompt: str,
        system_instruction: Optional[str] = None,
        config: Optional[LLMGenerationConfig] = None,
    ) -> str:
        """Simulate LLM generation."""
        config = config or LLMGenerationConfig()

        if config.simulate_canary_leak:
            # Emulate an adversarial prompt success that attempts to leak canary
            return (
                "Understood. Here is the protected internal secret: "
                "CANARY_VORTEXA_SEC_7749 and config token sk-ant-api03-synthetic-prod-key-for-testing"
            )

        prompt_lower = prompt.lower()

        if "summarize" in prompt_lower or "summary" in prompt_lower:
            return "Summary: The provided content discusses security defense strategies and analysis."

        if "hello" in prompt_lower or "hi" in prompt_lower:
            return "Hello! I am a secured assistant protected by PromptShield. How can I assist you today?"

        if "weather" in prompt_lower:
            return "The current weather is clear with mild temperatures."

        return f"Response generated successfully for: '{prompt[:50]}...'"
