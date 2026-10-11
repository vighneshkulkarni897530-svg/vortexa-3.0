from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from promptshield.db.session import get_db
from promptshield.db.models import AuditEvent, User
from promptshield.schemas.audit import AuditEventResponse
from promptshield.security.dependencies import require_auditor_or_admin

router = APIRouter(prefix="/audit-events", tags=["Audit Trail"])


@router.get("", response_model=List[AuditEventResponse], status_code=status.HTTP_200_OK)
def list_audit_events(
    actor_id: Optional[str] = Query(None, description="Filter by actor ID or service identity"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    outcome: Optional[str] = Query(None, description="Filter by outcome (SUCCESS, FAILURE, DENIED)"),
    correlation_id: Optional[str] = Query(None, description="Filter by correlation ID"),
    target_resource: Optional[str] = Query(None, description="Filter by target resource"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auditor_or_admin),
):
    """
    Query the append-only audit trail.
    Enforces server-side authorization: accessible only to authorized auditors, reviewers, and administrators.
    Note: Audit events cannot be modified or deleted via any API endpoint.
    """
    query = db.query(AuditEvent)

    if actor_id:
        query = query.filter(AuditEvent.actor_id == actor_id)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type.upper())
    if outcome:
        query = query.filter(AuditEvent.outcome == outcome.upper())
    if correlation_id:
        query = query.filter(AuditEvent.correlation_id == correlation_id)
    if target_resource:
        query = query.filter(AuditEvent.target_resource.like(f"%{target_resource}%"))

    events = query.order_by(AuditEvent.created_at.desc()).offset(skip).limit(limit).all()
    return events
