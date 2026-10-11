import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from promptshield.db.models import AuditEvent, User, utc_now
from promptshield.security.sanitization import sanitize_metadata


def test_audit_event_permissions(
    client: TestClient,
    admin_headers: dict,
    auditor_headers: dict,
    user_headers: dict,
):
    # 1. Ordinary user -> 403 Forbidden
    res_user = client.get("/api/v1/audit-events", headers=user_headers)
    assert res_user.status_code == 403

    # 2. Auditor -> 200 OK
    res_auditor = client.get("/api/v1/audit-events", headers=auditor_headers)
    assert res_auditor.status_code == 200

    # 3. Admin -> 200 OK
    res_admin = client.get("/api/v1/audit-events", headers=admin_headers)
    assert res_admin.status_code == 200


def test_audit_event_filtering(
    client: TestClient,
    db_session: Session,
    admin_headers: dict,
    admin_user: User,
):
    # Insert explicit audit event
    audit = AuditEvent(
        correlation_id="corr-audit-999",
        actor_id=admin_user.id,
        actor_role=admin_user.role,
        event_type="POLICY_CREATED",
        target_resource="policy:test-uuid",
        action_taken="CREATE",
        outcome="SUCCESS",
        policy_version=1,
        safe_metadata={"policy_name": "Test Policy"},
        created_at=utc_now(),
    )
    db_session.add(audit)
    db_session.commit()

    res = client.get(
        "/api/v1/audit-events?event_type=POLICY_CREATED&outcome=SUCCESS",
        headers=admin_headers
    )
    assert res.status_code == 200
    events = res.json()
    assert len(events) >= 1
    assert any(e["correlation_id"] == "corr-audit-999" for e in events)


def test_audit_metadata_secrets_redacted(
    client: TestClient,
    db_session: Session,
    admin_headers: dict,
):
    raw_sensitive_metadata = {
        "api_key": "secret-super-key-12345",
        "password": "ClearTextPassword!",
        "safe_key": "safe_value",
    }
    sanitized = sanitize_metadata(raw_sensitive_metadata)
    assert sanitized["api_key"] == "[REDACTED_SENSITIVE_FIELD]"
    assert sanitized["password"] == "[REDACTED_SENSITIVE_FIELD]"
    assert sanitized["safe_key"] == "safe_value"
