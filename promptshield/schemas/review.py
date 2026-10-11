from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

from promptshield.schemas.scan import ScanRecordResponse


class ReviewCaseResponse(BaseModel):
    id: str
    scan_id: str
    reason: str
    severity: str
    status: str
    assigned_reviewer_id: Optional[str] = None
    reviewer_decision: Optional[str] = None
    decision_justification: Optional[str] = None
    created_at: datetime
    resolved_at: Optional[datetime] = None
    scan: Optional[ScanRecordResponse] = None

    model_config = ConfigDict(from_attributes=True)


class ReviewDecisionRequest(BaseModel):
    decision: str = Field(..., pattern="^(ALLOW|BLOCK|SANITIZE)$")
    justification: str = Field(..., min_length=5, description="Mandatory security justification for decision")
    sanitized_content: Optional[str] = Field(None, description="Approved sanitized text if decision is SANITIZE")


class ReviewAssignRequest(BaseModel):
    reviewer_id: Optional[str] = Field(None, description="Reviewer user ID to assign; defaults to current actor")
