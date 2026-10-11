from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class MatchedSpan(BaseModel):
    start: int = Field(..., ge=0)
    end: int = Field(..., ge=0)
    span_type: str = Field(default="offending_content")
    replacement: Optional[str] = None


class DetectionFinding(BaseModel):
    detector_name: str
    threat_category: str = Field(
        ...,
        description="e.g. PROMPT_INJECTION, INDIRECT_INJECTION, DATA_EXFILTRATION, SYSTEM_PROMPT_OVERRIDE, SECRET_LEAK, CANARY_LEAK"
    )
    severity: str = Field(..., pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    confidence: float = Field(..., ge=0.0, le=1.0)
    matched_spans: List[MatchedSpan] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)


class EnforceRequest(BaseModel):
    """
    Authoritative evaluation contract for Laptop 2 (Detection logic) and gateway middleware.
    Accepts validated detector findings and untrusted source metadata.
    """
    correlation_id: Optional[str] = Field(None, description="Request tracking ID")
    source_type: str = Field(
        default="USER_PROMPT",
        pattern="^(USER_PROMPT|SYSTEM_PROMPT|RETRIEVED_DOC|TOOL_OUTPUT)$",
        description="Origin source of the scanned text"
    )
    detection_findings: List[DetectionFinding] = Field(
        default_factory=list,
        description="Findings produced by Laptop 2 detection engines"
    )
    content_to_sanitize: Optional[str] = Field(
        None,
        description="Candidate content payload for surgical span excision if SANITIZE action triggers"
    )
    redacted_content_ref: Optional[str] = Field(
        None,
        description="Authorized redacted snippet reference for audit logging. Never send raw secrets."
    )
    policy_id: Optional[str] = Field(
        None,
        description="Optional explicit policy UUID to enforce; defaults to active policy for source_type"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Non-sensitive operational metadata"
    )


class EnforceResponse(BaseModel):
    """
    Authoritative response contract returned to Laptop 2 and Gateway.
    """
    scan_id: str
    correlation_id: str
    final_action: str = Field(..., pattern="^(ALLOW|BLOCK|SANITIZE|ESCALATE)$")
    risk_classification: str = Field(..., pattern="^(BENIGN|LOW|MEDIUM|HIGH|CRITICAL)$")
    reason_codes: List[str]
    sanitized_content: Optional[str] = None
    review_case_id: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: int
    processing_duration_ms: float
    evaluated_at: datetime


class ScanRecordResponse(BaseModel):
    id: str
    correlation_id: str
    source_type: str
    detection_findings: List[Dict[str, Any]]
    final_action: str
    risk_classification: str
    reason_codes: List[str]
    policy_id: Optional[str] = None
    policy_version: int
    processing_duration_ms: float
    redacted_content_ref: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
