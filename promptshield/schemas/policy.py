from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class PolicyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: Optional[str] = None
    is_enabled: bool = True
    source_applicability: List[str] = Field(
        default=["USER_PROMPT", "SYSTEM_PROMPT", "RETRIEVED_DOC", "TOOL_OUTPUT"],
        description="Target content sources this policy governs"
    )
    rule_config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Detection rules, categories, and custom constraints"
    )
    severity_thresholds: Dict[str, str] = Field(
        default={
            "CRITICAL": "BLOCK",
            "HIGH": "BLOCK",
            "MEDIUM": "ESCALATE",
            "LOW": "ALLOW"
        },
        description="Action mapping for detection severity ratings"
    )
    default_action: str = Field(
        default="ALLOW",
        pattern="^(ALLOW|BLOCK|SANITIZE|ESCALATE)$",
        description="Fallback baseline action if no rule triggers"
    )
    change_summary: Optional[str] = Field(
        default="Initial policy release",
        description="Audit summary of initial configuration"
    )


class PolicyUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=128)
    description: Optional[str] = None
    is_enabled: Optional[bool] = None
    source_applicability: Optional[List[str]] = None
    rule_config: Optional[Dict[str, Any]] = None
    severity_thresholds: Optional[Dict[str, str]] = None
    default_action: Optional[str] = Field(None, pattern="^(ALLOW|BLOCK|SANITIZE|ESCALATE)$")
    change_summary: str = Field(
        ...,
        min_length=5,
        description="Mandatory description of reasons and scope for the policy update"
    )


class PolicyResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    is_enabled: bool
    source_applicability: List[str]
    rule_config: Dict[str, Any]
    severity_thresholds: Dict[str, str]
    default_action: str
    current_version: int
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PolicyVersionResponse(BaseModel):
    id: str
    policy_id: str
    version_number: int
    configuration_snapshot: Dict[str, Any]
    change_summary: Optional[str] = None
    author_id: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
