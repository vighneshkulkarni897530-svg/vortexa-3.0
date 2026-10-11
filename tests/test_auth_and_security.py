import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from promptshield.db.models import User, SecurityPolicy, AuditEvent
from promptshield.security.hashing import hash_password, verify_password


def test_user_registration_and_login_flow(client: TestClient):
    reg_payload = {
        "username": "new_security_analyst",
        "email": "analyst@promptshield.io",
        "password": "VeryStrongPassword2026!",
        "role": "reviewer",
    }
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    user_data = reg_res.json()
    assert user_data["username"] == reg_payload["username"]
    assert user_data["role"] == "reviewer"

    # Login
    login_payload = {
        "username": "new_security_analyst",
        "password": "VeryStrongPassword2026!",
    }
    login_res = client.post("/api/v1/auth/token", json=login_payload)
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert token_data["access_token"] is not None
    assert token_data["role"] == "reviewer"

    # Test me endpoint
    auth_header = {"Authorization": f"Bearer {token_data['access_token']}"}
    me_res = client.get("/api/v1/auth/me", headers=auth_header)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "new_security_analyst"


def test_invalid_login_rejected_and_audited(client: TestClient, db_session: Session):
    login_payload = {
        "username": "non_existent_hacker",
        "password": "BadPassword123!",
    }
    login_res = client.post("/api/v1/auth/token", json=login_payload)
    assert login_res.status_code == 401

    # Verify audit event logged for failed attempt
    audit = db_session.query(AuditEvent).filter(
        AuditEvent.event_type == "AUTH_LOGIN_FAILED",
        AuditEvent.actor_id == "non_existent_hacker"
    ).first()
    assert audit is not None
    assert audit.outcome == "DENIED"


def test_health_check_endpoint(client: TestClient):
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "UP"
    assert data["database"] == "healthy"
    assert data["fail_secure_mode"] is True


def test_sql_injection_resilience_in_policy_enforce(
    client: TestClient,
    default_policy: SecurityPolicy
):
    """
    Ensure adversarial SQL injection attempts inside detection findings or payloads
    are safely parameterized and never alter tables or execute arbitrary SQL.
    """
    adversarial_payload = {
        "correlation_id": "'; DROP TABLE security_policies; --",
        "source_type": "USER_PROMPT",
        "detection_findings": [
            {
                "detector_name": "'; UPDATE security_policies SET default_action='ALLOW'; --",
                "threat_category": "PROMPT_INJECTION",
                "severity": "HIGH",
                "confidence": 0.99,
                "details": {"payload": "OR '1'='1' --"},
            }
        ],
        "redacted_content_ref": "SELECT * FROM users WHERE password LIKE '%'",
    }

    res = client.post("/api/v1/enforce", json=adversarial_payload)
    assert res.status_code == 200
    data = res.json()
    assert data["final_action"] == "BLOCK"

    # Verify policies table was NOT dropped or modified
    get_res = client.get("/api/v1/health")
    assert get_res.status_code == 200
    assert get_res.json()["database"] == "healthy"
