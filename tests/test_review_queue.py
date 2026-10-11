import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from promptshield.db.models import SecurityPolicy, ReviewCase, ScanRecord, AuditEvent, User


def test_review_workflow_end_to_end(
    client: TestClient,
    db_session: Session,
    default_policy: SecurityPolicy,
    reviewer_headers: dict,
    reviewer_user: User,
    user_headers: dict,
):
    # 1. Trigger an escalation via enforcement
    enforce_payload = {
        "correlation_id": "corr-review-workflow-100",
        "source_type": "RETRIEVED_DOC",
        "detection_findings": [
            {
                "detector_name": "indirect_rag_detector",
                "threat_category": "INDIRECT_INJECTION",
                "severity": "MEDIUM",
                "confidence": 0.85,
            }
        ],
        "redacted_content_ref": "Doc excerpt: [SUSPICIOUS_PHRASE]",
    }
    enforce_res = client.post("/api/v1/enforce", json=enforce_payload)
    assert enforce_res.status_code == 200
    case_id = enforce_res.json()["review_case_id"]
    scan_id = enforce_res.json()["scan_id"]
    assert case_id is not None

    # 2. Ordinary user attempts to view review queue -> 403 Forbidden
    unauth_res = client.get("/api/v1/review-queue", headers=user_headers)
    assert unauth_res.status_code == 403

    # 3. Reviewer lists cases
    list_res = client.get("/api/v1/review-queue?status=PENDING", headers=reviewer_headers)
    assert list_res.status_code == 200
    cases = list_res.json()
    assert any(c["id"] == case_id for c in cases)

    # 4. Reviewer assigns case
    assign_res = client.post(f"/api/v1/review-queue/{case_id}/assign", headers=reviewer_headers)
    assert assign_res.status_code == 200
    assert assign_res.json()["status"] == "IN_REVIEW"
    assert assign_res.json()["assigned_reviewer_id"] == reviewer_user.id

    # 5. Reviewer records decision with justification
    decision_payload = {
        "decision": "BLOCK",
        "justification": "Confirmed malicious indirect prompt injection disguised as customer feedback.",
    }
    dec_res = client.post(
        f"/api/v1/review-queue/{case_id}/decision",
        json=decision_payload,
        headers=reviewer_headers
    )
    assert dec_res.status_code == 200
    case_data = dec_res.json()
    assert case_data["status"] == "RESOLVED"
    assert case_data["reviewer_decision"] == "BLOCK"
    assert case_data["decision_justification"] == decision_payload["justification"]
    assert case_data["resolved_at"] is not None

    # 6. Verify transactional update on ScanRecord
    scan = db_session.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
    assert scan.final_action == "BLOCK"
    assert any("HUMAN_REVIEW_RESOLVED_BLOCK" in r for r in scan.reason_codes)

    # 7. Verify AuditEvent created
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.target_resource == f"review_case:{case_id}",
        AuditEvent.event_type == "REVIEW_DECIDED"
    ).first()
    assert audit is not None
    assert audit.action_taken == "BLOCK"
    assert audit.actor_id == reviewer_user.id

    # 8. Re-attempt to decide an already resolved case -> 409 Conflict
    re_attempt = client.post(
        f"/api/v1/review-queue/{case_id}/decision",
        json=decision_payload,
        headers=reviewer_headers
    )
    assert re_attempt.status_code == 409
