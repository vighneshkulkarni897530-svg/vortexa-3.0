import time
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from promptshield.db.session import get_db
from promptshield.db.models import SecurityPolicy, ScanRecord, ReviewCase, AuditEvent, User
from promptshield.schemas.scan import EnforceRequest, EnforceResponse
from promptshield.policy_engine.engine import PolicyEngine
from promptshield.security.dependencies import get_current_user_optional
from promptshield.security.sanitization import sanitize_text, sanitize_metadata
from promptshield.db.models import utc_now

router = APIRouter(tags=["Enforcement & Detection Integration"])


@router.post("/enforce", response_model=EnforceResponse, status_code=status.HTTP_200_OK)
def enforce_policy(
    request: EnforceRequest,
    db: Session = Depends(get_db),
    current_actor: Optional[User] = Depends(get_current_user_optional),
):
    """
    Authoritative decision enforcement endpoint for Laptop 2 (Detection engine) and API gateway.
    Accepts validated detector findings, evaluates against trusted security policy with deterministic precedence,
    persists scan records, auto-escalates to human review queue when warranted, and logs append-only audit events.
    """
    start_time = time.perf_counter()
    correlation_id = request.correlation_id or str(uuid.uuid4())
    actor_id = current_actor.id if current_actor else "service:laptop-2-detector"
    actor_role = current_actor.role if current_actor else "service"

    # 1. Resolve Policy
    policy: Optional[SecurityPolicy] = None
    if request.policy_id:
        policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == request.policy_id).first()
    else:
        # Locate active policy matching this source_type
        all_active = db.query(SecurityPolicy).filter(SecurityPolicy.is_enabled == True).all()
        for p in all_active:
            if not p.source_applicability or any(s.upper() == request.source_type.upper() for s in p.source_applicability):
                policy = p
                break
        if not policy and all_active:
            policy = all_active[0]

    # 2. Authoritative Policy Evaluation
    eval_result = PolicyEngine.evaluate(
        policy=policy,
        source_type=request.source_type,
        findings=request.detection_findings,
        content_to_sanitize=request.content_to_sanitize,
    )

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 3)

    # 3. Safe Redacted Content Reference (Never store raw prompts or secrets)
    safe_content_ref = sanitize_text(request.redacted_content_ref) if request.redacted_content_ref else None

    # 4. Persist Scan Record
    findings_data = [sanitize_metadata(f.model_dump()) for f in request.detection_findings]
    scan_id = str(uuid.uuid4())
    scan_record = ScanRecord(
        id=scan_id,
        correlation_id=correlation_id,
        source_type=request.source_type,
        detection_findings=findings_data,
        final_action=eval_result.action,
        risk_classification=eval_result.risk_classification,
        reason_codes=eval_result.reason_codes,
        policy_id=eval_result.policy_id,
        policy_version=eval_result.policy_version,
        processing_duration_ms=elapsed_ms,
        redacted_content_ref=safe_content_ref,
        created_at=utc_now(),
    )
    db.add(scan_record)

    # 5. Escalation into Human Review Queue if action is ESCALATE
    review_case_id = None
    if eval_result.action == "ESCALATE":
        review_case_id = str(uuid.uuid4())
        escalation_reason = "; ".join(eval_result.reason_codes) or "Flagged by security policy for manual verification"
        review_case = ReviewCase(
            id=review_case_id,
            scan_id=scan_id,
            reason=escalation_reason,
            severity=eval_result.risk_classification,
            status="PENDING",
            created_at=utc_now(),
        )
        db.add(review_case)

    # 6. Append-Only Audit Event
    audit = AuditEvent(
        correlation_id=correlation_id,
        actor_id=actor_id,
        actor_role=actor_role,
        event_type="SCAN_EVALUATED",
        target_resource=f"scan:{scan_id}",
        action_taken=eval_result.action,
        outcome="SUCCESS",
        policy_version=eval_result.policy_version,
        safe_metadata=sanitize_metadata({
            "source_type": request.source_type,
            "risk_classification": eval_result.risk_classification,
            "reason_codes": eval_result.reason_codes,
            "findings_count": len(request.detection_findings),
            "review_case_id": review_case_id,
            "duration_ms": elapsed_ms,
        }),
        created_at=utc_now(),
    )
    db.add(audit)
    db.commit()

    return EnforceResponse(
        scan_id=scan_id,
        correlation_id=correlation_id,
        final_action=eval_result.action,
        risk_classification=eval_result.risk_classification,
        reason_codes=eval_result.reason_codes,
        sanitized_content=eval_result.sanitized_content,
        review_case_id=review_case_id,
        policy_id=eval_result.policy_id,
        policy_version=eval_result.policy_version,
        processing_duration_ms=elapsed_ms,
        evaluated_at=scan_record.created_at,
    )
