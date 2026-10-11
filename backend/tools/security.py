"""Tool Security and Destination Governance (Section 7).

Enforces server-side tool allowlists, parameter validation, destination restrictions,
and prevents SSRF and unauthorized command executions requested by LLM tools.
"""

import ipaddress
import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set
from pydantic import BaseModel

from backend.config import settings


class ToolExecutionRequest(BaseModel):
    """Invocation request for an LLM tool."""
    tool_name: str
    arguments: Dict[str, Any]
    destination_url: Optional[str] = None


class ToolValidationResult(BaseModel):
    """Result of tool authorization and validation."""
    is_authorized: bool
    rejection_reason: Optional[str] = None


class ToolSecurityManager:
    """Enforces strict server-side restrictions on tool availability and network destinations."""

    def __init__(
        self,
        allowed_tools: Optional[Set[str]] = None,
        denied_tools: Optional[Set[str]] = None,
    ):
        self.allowed_tools = allowed_tools or settings.ALLOWED_TOOLS
        self.denied_tools = denied_tools or settings.DENIED_TOOLS

    def validate_tool_request(self, request: ToolExecutionRequest) -> ToolValidationResult:
        """Validate whether a requested tool invocation is authorized."""
        # 1. Deny check
        if request.tool_name.lower() in self.denied_tools:
            return ToolValidationResult(
                is_authorized=False,
                rejection_reason=f"Tool '{request.tool_name}' is explicitly forbidden by security policy.",
            )

        # 2. Allowlist check
        if request.tool_name.lower() not in self.allowed_tools:
            return ToolValidationResult(
                is_authorized=False,
                rejection_reason=f"Tool '{request.tool_name}' is not in server-side authorized allowlist.",
            )

        # 3. Argument safety check
        arg_str = str(request.arguments).lower()
        dangerous_tokens = ["rm -rf", "drop table", "format c:", "; cat /etc", "| bash", "chmod 777"]
        for token in dangerous_tokens:
            if token in arg_str:
                return ToolValidationResult(
                    is_authorized=False,
                    rejection_reason=f"Tool arguments contain prohibited shell/database pattern: '{token}'",
                )

        # 4. Destination restriction & SSRF Protection
        if request.destination_url:
            dest_valid = self._validate_destination_url(request.destination_url)
            if not dest_valid.is_authorized:
                return dest_valid

        return ToolValidationResult(is_authorized=True)

    def _validate_destination_url(self, url: str) -> ToolValidationResult:
        """Prevent SSRF, cloud metadata access, and loopback targeting."""
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in {"http", "https"}:
                return ToolValidationResult(
                    is_authorized=False,
                    rejection_reason=f"Unsupported URL scheme '{parsed.scheme}'; only HTTPS/HTTP permitted.",
                )

            hostname = parsed.hostname
            if not hostname:
                return ToolValidationResult(is_authorized=False, rejection_reason="Malformed destination URL host.")

            # Check loopback and cloud metadata
            if hostname.lower() in {"localhost", "127.0.0.1", "169.254.169.254", "metadata.google.internal"}:
                return ToolValidationResult(
                    is_authorized=False,
                    rejection_reason="Access to localhost or cloud metadata services is strictly forbidden.",
                )

            # Check private IP ranges
            try:
                ip = ipaddress.ip_address(hostname)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    return ToolValidationResult(
                        is_authorized=False,
                        rejection_reason="Access to private or local IP ranges is blocked.",
                    )
            except ValueError:
                # Hostname is a domain name, not raw IP
                pass

        except Exception as e:
            return ToolValidationResult(
                is_authorized=False,
                rejection_reason=f"Invalid URL structure: {str(e)}",
            )

        return ToolValidationResult(is_authorized=True)
