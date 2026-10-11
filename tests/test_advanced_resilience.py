import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from alembic.config import Config
from alembic import command

from promptshield.db.models import SecurityPolicy, User, AuditEvent
from promptshield.db.session import transaction_scope


def test_reviewer_cannot_modify_policy(
    client: TestClient,
    reviewer_headers: dict,
    default_policy: SecurityPolicy
):
    """
    Reviewers can resolve assigned cases but cannot modify security policies.
    """
    payload = {
        "description": "Unauthorized attempt by reviewer",
        "default_action": "ALLOW",
        "change_summary": "Attempted modification",
    }
    res = client.put(f"/api/v1/policies/{default_policy.id}", json=payload, headers=reviewer_headers)
    assert res.status_code == 403
    assert "Required role: one of ['admin']" in res.json()["detail"]


def test_invalid_policy_configuration_rejected(
    client: TestClient,
    admin_headers: dict,
    default_policy: SecurityPolicy
):
    """
    Policy updates must reject invalid default actions and empty change summaries.
    """
    # 1. Invalid default action
    invalid_action_payload = {
        "default_action": "INVALID_ACTION",
        "change_summary": "Valid change summary here",
    }
    res = client.put(f"/api/v1/policies/{default_policy.id}", json=invalid_action_payload, headers=admin_headers)
    assert res.status_code == 422

    # 2. Too short change summary (< 5 chars)
    short_summary_payload = {
        "change_summary": "fix",
    }
    res2 = client.put(f"/api/v1/policies/{default_policy.id}", json=short_summary_payload, headers=admin_headers)
    assert res2.status_code == 422


def test_transaction_rollback_guarantee(db_session: Session, admin_user: User):
    """
    Verify that an exception raised within transaction_scope cleanly rolls back
    and leaves no partial records in the database.
    """
    count_before = db_session.query(AuditEvent).count()

    with pytest.raises(RuntimeError):
        with transaction_scope() as session:
            event = AuditEvent(
                actor_id=admin_user.id,
                actor_role=admin_user.role,
                event_type="TEST_TRANSACTION_ROLLBACK",
                target_resource="test:rollback",
                action_taken="TEST",
                outcome="SUCCESS",
            )
            session.add(event)
            session.flush()
            # Force an unexpected failure to trigger rollback
            raise RuntimeError("Simulated mid-transaction crash")

    # Re-query count in db_session
    count_after = db_session.query(AuditEvent).count()
    assert count_after == count_before


def test_alembic_programmatic_migrations():
    """
    Test running Alembic migrations forward and backward via the Python API on a test database.
    """
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", "sqlite:///./test_migration_runner.db")
    
    # Upgrade to head
    command.upgrade(alembic_cfg, "head")
    
    # Downgrade to base
    command.downgrade(alembic_cfg, "base")
    
    # Clean up test migration db
    import os
    if os.path.exists("./test_migration_runner.db"):
        os.remove("./test_migration_runner.db")
