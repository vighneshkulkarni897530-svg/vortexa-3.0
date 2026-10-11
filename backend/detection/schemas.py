"""Pydantic schemas and typed definitions for the PromptShield Detection Engine."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class SourceType(str, Enum):
    """Supported untrusted and trusted content sources."""
    USER_PROMPT = "user_prompt"
    UPLOADED_DOCUMENT = "uploaded_document"
    RETRIEVED_WEBPAGE = "retrieved_webpage"
    TOOL_OUTPUT = "tool_output"


class Severity(str, Enum):
    """Finding severity levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskClassification(str, Enum):
    """Aggregate risk classification."""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DecisionAction(str, Enum):
    """Security actions recommended by detection and enforced by policy."""
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class RuleCategory(str, Enum):
    """Categorization of detected injection and data security signals."""
    SYSTEM_OVERRIDE = "SYSTEM_OVERRIDE"
    SECURITY_BYPASS = "SECURITY_BYPASS"
    HIDDEN_PROMPT_DISCLOSURE = "HIDDEN_PROMPT_DISCLOSURE"
    SECRET_EXFILTRATION = "SECRET_EXFILTRATION"
    DATA_TRANSFER = "DATA_TRANSFER"
    TOOL_MANIPULATION = "TOOL_MANIPULATION"
    POLICY_MANIPULATION = "POLICY_MANIPULATION"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    ENCODED_PAYLOAD = "ENCODED_PAYLOAD"
    ANOMALOUS_STRUCTURE = "ANOMALOUS_STRUCTURE"


class EvidenceSpan(BaseModel):
    """Span in the input content associated with a finding."""
    start: int = Field(..., ge=0, description="Start character offset in normalized content")
    end: int = Field(..., ge=0, description="End character offset in normalized content")
    text_preview: str = Field(..., description="Safe preview snippet without sensitive secrets")


class DetectionFinding(BaseModel):
    """Granular, explainable security finding produced by detection rules."""
    rule_id: str = Field(..., description="Unique rule identifier e.g. INJ-SYS-001")
    category: RuleCategory = Field(..., description="Security category of the signal")
    severity: Severity = Field(..., description="Severity level of the finding")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score between 0.0 and 1.0")
    evidence_span: Optional[EvidenceSpan] = Field(None, description="Character offsets of matching span")
    safe_evidence_summary: str = Field(..., description="Explainable description of detected pattern")
    source_context: str = Field(..., description="Contextual source classification (e.g. untrusted webpage)")
    recommended_action: DecisionAction = Field(..., description="Recommended handling for this finding")


class NormalizedContentMetadata(BaseModel):
    """Metadata detailing normalization steps applied during inspection."""
    original_length: int = Field(..., ge=0)
    normalized_length: int = Field(..., ge=0)
    transformations_applied: List[str] = Field(default_factory=list)
    encodings_detected: List[str] = Field(default_factory=list)
    has_unicode_normalization: bool = False
    has_homoglyphs: bool = False
    has_collapsed_whitespace: bool = False


class ScanRequest(BaseModel):
    """Input payload for content security scanning."""
    scan_id: Optional[str] = Field(None, description="Optional scan identifier provided by caller")
    content: str = Field(..., min_length=1, description="Raw untrusted content to inspect")
    source_type: SourceType = Field(..., description="Origin of the content")
    trusted_metadata: Optional[Dict[str, Any]] = Field(default=None, description="Server-validated metadata")
    application_context: Optional[str] = Field(default=None, description="Target application name or ID")
    tenant_context: Optional[str] = Field(default=None, description="Tenant identifier for multi-tenant isolation")

    @field_validator("content")
    @classmethod
    def validate_content_not_empty(cls, v: str) -> str:
        if v is None or not v.strip():
            raise ValueError("Content cannot be empty or whitespace only")
        return v


class ScanResponse(BaseModel):
    """Shared team response contract for content inspection."""
    scan_id: str = Field(..., description="Unique scan identifier")
    source_type: SourceType = Field(..., description="Original source type")
    normalized_content_metadata: NormalizedContentMetadata = Field(..., description="Normalization audit trail")
    findings: List[DetectionFinding] = Field(default_factory=list, description="List of explainable detection findings")
    risk_classification: RiskClassification = Field(..., description="Aggregate risk classification")
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Calibrated risk score (0.00 to 1.00)")
    recommended_action: DecisionAction = Field(..., description="Detection engine's recommended action")
    final_decision: DecisionAction = Field(..., description="Final policy decision from trusted policy handoff")
    decision_reason: str = Field(..., description="Human-readable justification for the policy decision")
    policy_version: str = Field(..., description="Active policy version identifier")
    sanitized_content: Optional[str] = Field(None, description="Sanitized content when action is SANITIZE or ALLOW")
    processing_duration_ms: float = Field(..., ge=0.0, description="Total inspection duration in milliseconds")
