from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from promptshield.db.session import get_db
from promptshield.db.models import ReviewCase, ScanRecord, AuditEvent, User, utc_now
from promptshield.schemas.review import (
    ReviewCaseResponse,
    ReviewDecisionRequest,
    ReviewAssignRequest,
)
from promptshield.security.dependencies import require_reviewer
from promptshield.security.sanitization import sanitize_metadata

router = APIRouter(prefix="/review-queue", tags=["Human Review Queue"])


@router.get("", response_model=List[ReviewCaseResponse])
def list_review_cases(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (PENDING, IN_REVIEW, RESOLVED, DISMISSED)"),
    severity_filter: Optional[str] = Query(None, alias="severity", description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_reviewer: User = Depends(require_reviewer),
):
    """List review queue cases with optional status and severity filtering."""
    query = db.query(ReviewCase)
    if status_filter:
        query = query.filter(ReviewCase.status == status_filter.upper())
    if severity_filter:
        query = query.filter(ReviewCase.severity == severity_filter.upper())
    
    cases = query.order_by(ReviewCase.created_at.desc()).offset(skip).limit(limit).all()
    return cases


@router.get("/{case_id}", response_model=ReviewCaseResponse)
def get_review_case_details(
    case_id: str,
    db: Session = Depends(get_db),
    current_reviewer: User = Depends(require_reviewer),
):
    """Retrieve full details of an escalated review case, including redacted evidence."""
    case = db.query(ReviewCase).filter(ReviewCase.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review case '{case_id}' not found."
        )
    return case


@router.post("/{case_id}/assign", response_model=ReviewCaseResponse)
def assign_review_case(
    case_id: str,
    assign_req: Optional[ReviewAssignRequest] = None,
    db: Session = Depends(get_db),
    current_reviewer: User = Depends(require_reviewer),
):
    """Assign an escalated review case to an authorized security reviewer."""
    case = db.query(ReviewCase).filter(ReviewCase.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review case '{case_id}' not found."
        )

    assignee_id = (assign_req.reviewer_id if assign_req and assign_req.reviewer_id else current_reviewer.id)
    target_user = db.query(User).filter(User.id == assignee_id).first()
    if not target_user or target_user.role not in ["reviewer", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Assignee must be an active user with reviewer or admin role."
        )

    case.assigned_reviewer_id = target_user.id
    if case.status == "PENDING":
        case.status = "IN_REVIEW"

    # Append-only audit record
    audit = AuditEvent(
        actor_id=current_reviewer.id,
        actor_role=current_reviewer.role,
        event_type="REVIEW_ASSIGNED",
        target_resource=f"review_case:{case.id}",
        action_taken="ASSIGN",
        outcome="SUCCESS",
        safe_metadata={
            "assigned_to": target_user.username,
            "case_id": case.id,
            "status": case.status,
        },
        created_at=utc_now(),
    )
    db.add(audit)
    db.commit()
    db.refresh(case)
    return case


@router.post("/{case_id}/decision", response_model=ReviewCaseResponse)
@router.post("/{case_id}/decide", response_model=ReviewCaseResponse, include_in_schema=False)
def submit_review_decision(
    case_id: str,
    req: ReviewDecisionRequest,
    db: Session = Depends(get_db),
    current_reviewer: User = Depends(require_reviewer),
):
    """
    Record an authoritative human review decision and justification.
    Updates the review case, updates the associated scan record, and writes an immutable audit record transactionally.
    """
    case = db.query(ReviewCase).filter(ReviewCase.id == case_id).first()
    if not case:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review case '{case_id}' not found."
        )

    if case.status in ["RESOLVED", "DISMISSED"]:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Case is already in '{case.status}' status and cannot be modified."
        )

    # Transactional update
    now = utc_now()
    case.reviewer_decision = req.decision
    case.decision_justification = req.justification
    case.status = "RESOLVED"
    case.resolved_at = now
    if not case.assigned_reviewer_id:
        case.assigned_reviewer_id = current_reviewer.id

    # Update associated scan record with human resolution
    scan = db.query(ScanRecord).filter(ScanRecord.id == case.scan_id).first()
    if scan:
        scan.final_action = req.decision
        current_reasons = list(scan.reason_codes or [])
        current_reasons.append(f"HUMAN_REVIEW_RESOLVED_{req.decision}: {req.justification[:60]}")
        scan.reason_codes = current_reasons

    # Append-only audit record
    audit = AuditEvent(
        correlation_id=scan.correlation_id if scan else None,
        actor_id=current_reviewer.id,
        actor_role=current_reviewer.role,
        event_type="REVIEW_DECIDED",
        target_resource=f"review_case:{case.id}",
        action_taken=req.decision,
        outcome="SUCCESS",
        policy_version=scan.policy_version if scan else None,
        safe_metadata=sanitize_metadata({
            "case_id": case.id,
            "scan_id": case.scan_id,
            "decision": req.decision,
            "justification": req.justification,
            "reviewer_username": current_reviewer.username,
        }),
        created_at=now,
    )
    db.add(audit)
    db.commit()
    db.refresh(case)
    return case
