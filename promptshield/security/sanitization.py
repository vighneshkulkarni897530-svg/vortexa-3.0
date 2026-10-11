import re
from typing import Any, Dict, List, Union

# Common high-risk secret patterns to protect against exfiltration leakage
SECRET_PATTERNS = [
    # AWS Access Key ID
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "[REDACTED_AWS_KEY]"),
    # Generic API Keys / Bearer tokens
    (re.compile(r"Bearer\s+[A-Za-z0-9\-_\.=]{20,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"(?:api_key|apikey|secret|token|password|auth)[\s:=]+['\"]?([a-zA-Z0-9_\-]{16,})['\"]?", re.IGNORECASE), "[REDACTED_SECRET]"),
    # RSA / Private Keys
    (re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----[^-]+-----END (?:RSA )?PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
    # Database connection strings with passwords
    (re.compile(r"://([^:]+):([^@]+)@", re.IGNORECASE), r"://\1:[REDACTED_PASSWORD]@"),
]

SENSITIVE_KEY_NAMES = {
    "password", "secret", "token", "api_key", "apikey", "access_token",
    "private_key", "auth", "authorization", "raw_prompt", "raw_content"
}


def sanitize_text(text: str) -> str:
    """Scan text for credentials and secrets and replace them with safe redaction markers."""
    if not text:
        return text
    sanitized = text
    for pattern, replacement in SECRET_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def sanitize_metadata(data: Any) -> Any:
    """
    Recursively sanitize dictionaries and lists to prevent sensitive values
    or credentials from ever persisting into audit logs or scan records.
    """
    if isinstance(data, dict):
        clean_dict = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(sens in k_lower for sens in SENSITIVE_KEY_NAMES):
                clean_dict[k] = "[REDACTED_SENSITIVE_FIELD]"
            else:
                clean_dict[k] = sanitize_metadata(v)
        return clean_dict
    elif isinstance(data, list):
        return [sanitize_metadata(item) for item in data]
    elif isinstance(data, str):
        return sanitize_text(data)
    else:
        return data
