"""Secure Server-Side Webpage Retrieval & Text Extraction Module.

Enforces strict anti-SSRF protections:
- Scheme whitelist (HTTP / HTTPS only)
- DNS resolution checks: blocks private IPs (RFC 1918), loopbacks (127.0.0.0/8, ::1),
  link-local / AWS / GCP metadata addresses (169.254.169.254, metadata.google.internal)
- Safe redirect validation: every redirect hop is independently validated against SSRF rules
- Strict response-size and execution bounds (max 2MB raw, timeout 5.0s, no JS execution)
- HTML text extraction: strips executable elements (<script>, <style>, <iframe>, <object>, etc.)
"""

import ipaddress
import logging
import re
import socket
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Tuple

from bs4 import BeautifulSoup
import httpx

from backend.config import settings

logger = logging.getLogger("promptshield.retrieval")

# Blocked well-known metadata and internal hostnames
BLOCKED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "169.254.169.254",
    "metadata.google.internal",
    "instance-data",
    "metadata",
}

# Permitted MIME types for webpage retrieval
ALLOWED_CONTENT_TYPES = (
    "text/html",
    "text/plain",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
    "application/json",
)


@dataclass
class WebExtractionResult:
    """Structured result of safe webpage retrieval and extraction."""
    url: str
    extracted_text: str
    title: Optional[str]
    content_type: str
    status_code: int
    extracted_chars: int
    raw_size_bytes: int


class SafeWebRetriever:
    """Anti-SSRF compliant webpage fetcher and text extractor."""

    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL syntax, scheme, and destination safety against SSRF attacks."""
        if not url or not isinstance(url, str):
            return False, "URL must be a non-empty string"

        url = url.strip()
        try:
            parsed = urllib.parse.urlsplit(url)
        except Exception:
            return False, "Malformed URL structure"

        # 1. Scheme check (HTTP/HTTPS only)
        if parsed.scheme.lower() not in {"http", "https"}:
            return False, f"Unsupported URL scheme '{parsed.scheme}'. Only HTTP and HTTPS are permitted."

        hostname = parsed.hostname
        if not hostname:
            return False, "URL must include a valid hostname"

        # 2. Hostname blacklists
        hostname_lower = hostname.lower()
        if hostname_lower in BLOCKED_HOSTNAMES or hostname_lower.endswith((".internal", ".local", ".corp", ".lan")):
            return False, f"Access to internal or cloud metadata destination '{hostname}' is strictly blocked."

        # 3. Port check (standard web ports only)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port not in {80, 443, 8080, 8443}:
            return False, f"Access to port {port} is restricted. Only standard web ports (80, 443, 8080, 8443) are allowed."

        # 4. Resolve IP addresses to prevent DNS rebinding and loopback/private targetting
        try:
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
            resolved_ips = {item[4][0] for item in addr_info}
        except socket.gaierror as e:
            return False, f"DNS resolution failed for hostname '{hostname}': {str(e)}"
        except Exception as e:
            return False, f"Failed to resolve hostname '{hostname}': {str(e)}"

        if not resolved_ips:
            return False, f"Could not resolve any IP address for '{hostname}'"

        for ip_str in resolved_ips:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                return False, f"Invalid resolved IP address: {ip_str}"

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return False, f"Resolved IP destination {ip_str} belongs to a private, loopback, or reserved address block."

        return True, None

    @classmethod
    def fetch_and_extract(
        cls,
        url: str,
        timeout_seconds: Optional[float] = None,
        max_bytes: Optional[int] = None,
        client: Optional[httpx.Client] = None,
    ) -> WebExtractionResult:
        """Fetch external webpage and extract clean visible text within security limits."""
        timeout = timeout_seconds or settings.WEB_RETRIEVAL_TIMEOUT_SECONDS
        max_response_bytes = max_bytes or settings.MAX_WEB_RETRIEVAL_BYTES

        # In test environments without external network access
        if not settings.ALLOW_EXTERNAL_RETRIEVAL and client is None:
            raise ValueError("External webpage retrieval is disabled in this environment by security configuration.")

        # Initial URL validation
        is_valid, error_msg = cls.validate_url(url)
        if not is_valid:
            raise ValueError(f"SSRF Protection Rejected URL: {error_msg}")

        current_url = url
        redirect_count = 0
        max_redirects = settings.MAX_REDIRECTS

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 PromptShield/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        # Follow redirects manually to validate every intermediate destination
        while redirect_count <= max_redirects:
            try:
                if client is not None:
                    response = client.get(
                        current_url,
                        headers=headers,
                        timeout=timeout,
                        follow_redirects=False,
                    )
                else:
                    with httpx.Client(timeout=timeout, follow_redirects=False, verify=True) as local_client:
                        response = local_client.get(current_url, headers=headers)
            except httpx.TimeoutException:
                raise ValueError(f"Webpage retrieval timed out after {timeout} seconds.")
            except httpx.RequestError as e:
                raise ValueError(f"Failed to connect to webpage: {str(e)}")

            # Check redirect status codes (301, 302, 303, 307, 308)
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("Location")
                if not location:
                    raise ValueError(f"Received redirect status {response.status_code} with missing Location header.")

                # Resolve relative redirect URLs
                redirect_target = urllib.parse.urljoin(current_url, location)
                redirect_count += 1
                if redirect_count > max_redirects:
                    raise ValueError(f"Exceeded maximum allowed redirects ({max_redirects}).")

                # Validate redirect target against SSRF rules!
                is_valid_redir, redir_error = cls.validate_url(redirect_target)
                if not is_valid_redir:
                    raise ValueError(f"Prohibited redirect target rejected by SSRF guard: {redir_error}")

                current_url = redirect_target
                continue

            # Non-redirect response reached
            break

        if response.status_code >= 400:
            parsed_current = urllib.parse.urlsplit(current_url)
            hostname = parsed_current.hostname or "target server"
            server_header = response.headers.get("server", "").lower()
            is_cf = (
                "cloudflare" in server_header
                or "cf-mitigated" in response.headers
                or "cf-ray" in response.headers
                or "challenge" in response.text.lower()
            )
            if response.status_code == 403 and is_cf:
                raise ValueError(
                    f"Target website '{hostname}' blocked automated retrieval with Cloudflare WAF / Anti-Bot challenge (HTTP 403 Forbidden). "
                    "Automated scrapers are restricted by the destination site. "
                    "Please paste the webpage text or HTML into the 'Or Paste Pre-Retrieved Web Content' box below to screen it directly."
                )
            elif response.status_code == 403:
                raise ValueError(
                    f"Target website '{hostname}' returned HTTP 403 Forbidden (access restricted by remote host). "
                    "Please paste the webpage text or HTML into the 'Or Paste Pre-Retrieved Web Content' box below to screen it directly."
                )
            elif response.status_code == 404:
                raise ValueError(
                    f"Target webpage '{hostname}' was not found (HTTP 404 Not Found). Please verify the URL path or paste content directly."
                )
            else:
                raise ValueError(
                    f"Remote server '{hostname}' returned HTTP error status {response.status_code}. "
                    "Please paste the webpage text or HTML into the 'Or Paste Pre-Retrieved Web Content' box below to screen it directly."
                )

        # Content-Type check
        content_type_header = response.headers.get("Content-Type", "").lower()
        if not any(allowed in content_type_header for allowed in ALLOWED_CONTENT_TYPES):
            raise ValueError(
                f"Unsupported content type '{content_type_header}'. Only HTML and text documents can be inspected."
            )

        # Body size enforcement
        content_bytes = response.content
        if len(content_bytes) > max_response_bytes:
            raise ValueError(
                f"Webpage response ({len(content_bytes)} bytes) exceeds maximum permitted limit ({max_response_bytes} bytes)."
            )

        # Decode HTML / text
        encoding = response.encoding or "utf-8"
        try:
            raw_html = content_bytes.decode(encoding, errors="replace")
        except Exception:
            raw_html = content_bytes.decode("utf-8", errors="replace")

        # Extract readable text without script/executable elements
        extracted_text, title = cls._extract_clean_text(raw_html)

        if not extracted_text.strip():
            raise ValueError("Webpage contains no readable text content.")

        # Truncate to maximum content length
        if len(extracted_text) > settings.MAX_CONTENT_LENGTH:
            extracted_text = extracted_text[:settings.MAX_CONTENT_LENGTH]

        return WebExtractionResult(
            url=current_url,
            extracted_text=extracted_text,
            title=title,
            content_type=content_type_header.split(";")[0].strip(),
            status_code=response.status_code,
            extracted_chars=len(extracted_text),
            raw_size_bytes=len(content_bytes),
        )

    @staticmethod
    def _extract_clean_text(html_content: str) -> Tuple[str, Optional[str]]:
        """Parse HTML and extract readable text while neutralizing all script / active elements."""
        soup = BeautifulSoup(html_content, "html.parser")

        title = None
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        # Remove dangerous or non-content tags completely
        for tag in soup(["script", "style", "noscript", "iframe", "svg", "canvas", "object", "embed", "link", "meta"]):
            tag.decompose()

        # Extract textual content with proper spacing
        text = soup.get_text(separator="\n")

        # Clean excess blank lines
        lines = [line.strip() for line in text.splitlines()]
        clean_text = "\n".join(chunk for chunk in lines if chunk)

        return clean_text, title
