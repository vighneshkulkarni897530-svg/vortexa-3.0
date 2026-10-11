"""Dashboard Statistics and Telemetry API.

Provides real, measured operational statistics from the database
(no hardcoded production numbers).
"""

from typing import Dict, Any
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import func

from promptshield.db.session import get_db
from promptshield.db.models import ScanRecord, ReviewCase, AuditEvent, SecurityPolicy

router = APIRouter(prefix="/stats", tags=["Telemetry & Statistics"])


@router.get("", status_code=status.HTTP_200_OK)
def get_dashboard_stats(db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Retrieve verified operational counts from persistence layer."""
    total_scans = db.query(func.count(ScanRecord.id)).scalar() or 0
    threats_intercepted = (
        db.query(func.count(ScanRecord.id))
        .filter(ScanRecord.final_action.in_(["BLOCK", "SANITIZE"]))
        .scalar()
        or 0
    )
    high_risk_count = (
        db.query(func.count(ScanRecord.id))
        .filter(ScanRecord.risk_classification.in_(["HIGH", "CRITICAL"]))
        .scalar()
        or 0
    )
    pending_reviews = (
        db.query(func.count(ReviewCase.id))
        .filter(ReviewCase.status == "PENDING")
        .scalar()
        or 0
    )
    total_audit_events = db.query(func.count(AuditEvent.id)).scalar() or 0
    active_policies = (
        db.query(func.count(SecurityPolicy.id))
        .filter(SecurityPolicy.is_enabled == True)
        .scalar()
        or 0
    )

    # Count data leaks intercepted in audit events or scan records
    leak_events = (
        db.query(func.count(AuditEvent.id))
        .filter(
            (AuditEvent.event_type.like("%EXFIL%"))
            | (AuditEvent.target_resource.like("%canary%"))
        )
        .scalar()
        or 0
    )

    return {
        "total_scans": total_scans,
        "threats_intercepted": threats_intercepted,
        "data_leaks_prevented": leak_events,
        "high_risk_count": high_risk_count,
        "pending_reviews": pending_reviews,
        "total_audit_events": total_audit_events,
        "active_policies_count": active_policies,
    }
