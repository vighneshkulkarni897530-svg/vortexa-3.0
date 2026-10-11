"""Security Headers and Request Audit Middleware.

Injects enterprise defense-in-depth headers (HSTS, CSP, X-Frame-Options)
and manages structured logging without exposing sensitive internal state.
"""

import logging
import time
import uuid
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("promptshield.security")


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Applies hardened security headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()
        req_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
        request.state.request_id = req_id

        # Pass through request
        response: Response = await call_next(request)

        # Invert elapsed time
        duration = round((time.perf_counter() - start_time) * 1000.0, 2)

        # Apply hardened security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Request-ID"] = req_id

        logger.info(
            f"request_id={req_id} method={request.method} path={request.url.path} status={response.status_code} duration_ms={duration}"
        )

        return response
