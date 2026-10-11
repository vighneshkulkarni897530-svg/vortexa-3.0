"""PromptShield Detection Engine API (VORTEXA 3.0 Problem C-03).

Provides high-assurance content inspection, multi-signal prompt injection detection,
canary secret protection, sanitization, and LLM output guard endpoints.
"""

import logging
from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend.config import settings
from backend.detection.rules import ALL_RULES
from backend.detection.schemas import (
    DecisionAction,
    ScanRequest,
    ScanResponse,
)
from backend.detection.service import DetectionEngineService
from backend.llm.adapter import LLMAdapter, LLMRequest, SecurityBypassException
from backend.llm.output_guard import SecurityLeakageException
from backend.middleware.request_validation import RequestValidationMiddleware
from backend.middleware.security_middleware import SecurityHeadersMiddleware

# Configure structured logging
logging.basicConfig(
    level=settings.LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("promptshield.api")

app = FastAPI(
    title=settings.SERVICE_NAME,
    version=settings.SERVICE_VERSION,
    description="Enterprise Prompt Injection Detection and LLM Protection Engine for VORTEXA 3.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Attach defense middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)

# Initialize core services
detection_service = DetectionEngineService()
llm_adapter = LLMAdapter()


# Custom exception handlers preventing stack trace leakage
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Sanitize validation errors and return structured 422 response."""
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "VALIDATION_ERROR",
            "message": "Request payload failed schema validation",
            "details": [{"loc": err["loc"], "msg": err["msg"], "type": err["type"]} for err in exc.errors()],
        },
    )


@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    """Handle business logic / size constraint value errors."""
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "BAD_REQUEST", "message": str(exc)},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Sanitize unhandled errors to prevent stack trace leaks to clients."""
    logger.error(f"Unhandled internal error during request: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An internal error occurred while processing security inspection. Stack traces redacted.",
        },
    )


@app.get("/health", tags=["System"])
async def health_check():
    """Service health and diagnostic status."""
    return {
        "status": "HEALTHY",
        "service": settings.SERVICE_NAME,
        "version": settings.SERVICE_VERSION,
        "policy_version": settings.POLICY_VERSION,
        "environment": settings.ENVIRONMENT,
    }


@app.post(
    "/api/v1/scan",
    response_model=ScanResponse,
    status_code=status.HTTP_200_OK,
    tags=["Inspection"],
    summary="Inspect untrusted content for prompt injection and secret leaks",
)
async def scan_content(request: ScanRequest) -> ScanResponse:
    """Core screening endpoint agreed across VORTEXA 3.0 teams."""
    try:
        response = detection_service.scan(request)
        return response
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@app.get("/api/v1/rules", tags=["Inspection"])
async def list_rules():
    """List active detection rules and risk scoring documentation."""
    rule_list = [
        {
            "rule_id": r.rule_id,
            "name": r.name,
            "category": r.category.value,
            "base_severity": r.base_severity.value,
            "base_confidence": r.base_confidence,
            "recommended_action": r.recommended_action.value,
        }
        for r in ALL_RULES
    ]
    scoring_guide = {
        "score_interpretation": "Deterministic weighted index based on signal severity and detector confidence. Not a probability.",
        "tiers": {
            "SAFE": "0.00 - 0.19 -> ALLOW",
            "LOW": "0.20 - 0.44 -> ALLOW",
            "MEDIUM": "0.45 - 0.69 -> SANITIZE (if isolated) or ESCALATE",
            "HIGH": "0.70 - 0.89 -> BLOCK (or SANITIZE if passive document)",
            "CRITICAL": "0.90 - 1.00 -> Immediate BLOCK",
        },
    }
    return {"total_rules": len(rule_list), "rules": rule_list, "scoring_documentation": scoring_guide}


class ScreenedLLMRequest(ScanRequest):
    """Extended request for end-to-end screened LLM execution."""
    system_instruction: str = "You are a helpful and secure AI assistant protected by PromptShield."


@app.post(
    "/api/v1/llm/generate",
    tags=["LLM Guard"],
    summary="Execute end-to-end screened and policy-authorized LLM generation",
)
async def screened_llm_generate(request: ScreenedLLMRequest):
    """Screens input through detection pipeline, enforces policy, and calls guarded LLM."""
    # 1. Screen input
    scan_resp = detection_service.scan(request)

    # 2. Check policy decision
    if scan_resp.final_decision in {DecisionAction.BLOCK, DecisionAction.ESCALATE}:
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "EXECUTION_BLOCKED_BY_POLICY",
                "final_decision": scan_resp.final_decision.value,
                "reason": scan_resp.decision_reason,
                "scan_id": scan_resp.scan_id,
                "findings": [f.model_dump() for f in scan_resp.findings],
            },
        )

    # 3. Invoke LLM with screening proof and output guard
    try:
        llm_req = LLMRequest(
            prompt=request.content,
            system_instruction=request.system_instruction,
            screening_result=scan_resp,
        )
        llm_resp = llm_adapter.generate_guarded(llm_req)
        return {
            "llm_response": llm_resp.model_dump(),
            "security_scan": scan_resp.model_dump(),
        }
    except (SecurityBypassException, SecurityLeakageException) as se:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(se))
