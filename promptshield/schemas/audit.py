from datetime import datetime
from typing import Optional, Dict, Any
from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    id: str
    correlation_id: Optional[str] = None
    actor_id: str
    actor_role: str
    event_type: str
    target_resource: str
    action_taken: str
    outcome: str
    policy_version: Optional[int] = None
    safe_metadata: Dict[str, Any]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
