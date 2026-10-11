import os
from typing import List, Set
from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load environment variables from .env file
load_dotenv()


class Settings(BaseModel):

    """Runtime configuration settings."""

    # Service metadata
    SERVICE_NAME: str = "PromptShield Detection Engine"
    SERVICE_VERSION: str = "1.0.0"
    POLICY_VERSION: str = "v1.2.0"
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

    # External LLM Provider settings
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    ACTIVE_LLM_PROVIDER: str = os.getenv("ACTIVE_LLM_PROVIDER", "auto")


    # Content limits (Stage A validation)
    MAX_CONTENT_LENGTH: int = int(os.getenv("MAX_CONTENT_LENGTH", "1048576"))  # 1MB default
    MAX_SCAN_PAYLOAD_BYTES: int = int(os.getenv("MAX_SCAN_PAYLOAD_BYTES", "2097152"))  # 2MB
    MAX_NESTED_DECODING_DEPTH: int = 3
    MAX_NORMALIZATION_LENGTH: int = 200000

    # Policy integration (Laptop 3)
    POLICY_SERVICE_URL: str = os.getenv("POLICY_SERVICE_URL", "")
    POLICY_TIMEOUT_SECONDS: float = float(os.getenv("POLICY_TIMEOUT_SECONDS", "2.0"))

    # Secret scanner configuration (Stage D)
    CANARY_TOKENS: List[str] = Field(
        default_factory=lambda: [
            "CANARY_VORTEXA_SEC_7749",
            "VRTX-TEST-SECRET-XYZ-99",
            "SYNTHETIC-CANARY-TOKEN-42",
        ]
    )
    CONFIGURED_SENSITIVE_KEYS: List[str] = Field(
        default_factory=lambda: [
            "sk-ant-api03-synthetic-prod-key-for-testing",
            "ghp_syntheticGitHubTokenForTestingOnly12345",
        ]
    )

    # Tool security allowlist
    ALLOWED_TOOLS: Set[str] = Field(
        default_factory=lambda: {
            "calculator",
            "search_products",
            "lookup_weather",
            "format_markdown",
        }
    )
    DENIED_TOOLS: Set[str] = Field(
        default_factory=lambda: {
            "bash",
            "sh",
            "eval",
            "exec",
            "os_exec",
            "run_command",
            "filesystem_write",
            "raw_sql",
        }
    )


# Global singleton settings
settings = Settings()
