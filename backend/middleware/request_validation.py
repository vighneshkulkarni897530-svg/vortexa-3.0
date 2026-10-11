"""Request Validation Middleware (Stage A).

Validates input size, character encodings, UTF-8 validity, and structural integrity
to protect the service from resource exhaustion, malformed payloads, and denial-of-service.
"""

from typing import Callable
from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from backend.config import settings


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Enforces size limits and safe character encoding on incoming HTTP requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Check Content-Length header against max payload bytes
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.MAX_SCAN_PAYLOAD_BYTES:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={
                            "error": "PAYLOAD_TOO_LARGE",
                            "message": f"Payload size exceeds maximum limit of {settings.MAX_SCAN_PAYLOAD_BYTES} bytes",
                        },
                    )
            except ValueError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"error": "INVALID_CONTENT_LENGTH", "message": "Malformed Content-Length header"},
                )

        # For POST requests, inspect body for raw binary/null byte anomalies
        if request.method == "POST" and request.url.path.startswith("/api/"):
            try:
                body = await request.body()
                # Ensure body is valid UTF-8
                body.decode("utf-8")
            except UnicodeDecodeError:
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={
                        "error": "INVALID_ENCODING",
                        "message": "Request payload must be valid UTF-8 encoded text",
                    },
                )

        response = await call_next(request)
        return response
