import pytest
from typing import Generator, Dict, Any
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
import httpx

from promptshield.db.base import Base
from promptshield.db.session import get_db
from promptshield.db.models import User, SecurityPolicy, PolicyVersion
from promptshield.security.hashing import hash_password
from promptshield.security.tokens import create_access_token
from promptshield.main import create_app


# In-memory SQLite for test isolation
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="function")
def db_session() -> Generator[Session, None, None]:
    Base.metadata.create_all(bind=test_engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(scope="function")
def client(db_session: Session) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def admin_user(db_session: Session) -> User:
    user = User(
        username="admin_user",
        email="admin@promptshield.internal",
        hashed_password=hash_password("AdminSecurePassword123!"),
        role="admin",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def reviewer_user(db_session: Session) -> User:
    user = User(
        username="reviewer_user",
        email="reviewer@promptshield.internal",
        hashed_password=hash_password("ReviewerSecurePassword123!"),
        role="reviewer",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def auditor_user(db_session: Session) -> User:
    user = User(
        username="auditor_user",
        email="auditor@promptshield.internal",
        hashed_password=hash_password("AuditorSecurePassword123!"),
        role="auditor",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def standard_user(db_session: Session) -> User:
    user = User(
        username="standard_user",
        email="user@promptshield.internal",
        hashed_password=hash_password("StandardSecurePassword123!"),
        role="user",
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def admin_headers(admin_user: User) -> Dict[str, str]:
    token = create_access_token({"sub": admin_user.username, "role": admin_user.role, "user_id": admin_user.id})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def reviewer_headers(reviewer_user: User) -> Dict[str, str]:
    token = create_access_token({"sub": reviewer_user.username, "role": reviewer_user.role, "user_id": reviewer_user.id})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def auditor_headers(auditor_user: User) -> Dict[str, str]:
    token = create_access_token({"sub": auditor_user.username, "role": auditor_user.role, "user_id": auditor_user.id})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def user_headers(standard_user: User) -> Dict[str, str]:
    token = create_access_token({"sub": standard_user.username, "role": standard_user.role, "user_id": standard_user.id})
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="function")
def default_policy(db_session: Session, admin_user: User) -> SecurityPolicy:
    policy = SecurityPolicy(
        name="Default PromptShield Production Policy",
        description="Comprehensive defensive policy protecting against prompt injection and data exfiltration",
        is_enabled=True,
        source_applicability=["USER_PROMPT", "SYSTEM_PROMPT", "RETRIEVED_DOC", "TOOL_OUTPUT"],
        rule_config={
            "rules": [
                {
                    "name": "Block Exfiltration",
                    "category": "DATA_EXFILTRATION",
                    "min_severity": "HIGH",
                    "action": "BLOCK"
                },
                {
                    "name": "Block Direct Injection",
                    "category": "PROMPT_INJECTION",
                    "min_severity": "HIGH",
                    "action": "BLOCK"
                },
                {
                    "name": "Escalate Indirect Injection",
                    "category": "INDIRECT_INJECTION",
                    "min_severity": "MEDIUM",
                    "action": "ESCALATE"
                },
                {
                    "name": "Sanitize Sensitive PII",
                    "category": "PII_LEAK",
                    "min_severity": "LOW",
                    "action": "SANITIZE"
                }
            ]
        },
        severity_thresholds={
            "CRITICAL": "BLOCK",
            "HIGH": "BLOCK",
            "MEDIUM": "ESCALATE",
            "LOW": "ALLOW"
        },
        default_action="ALLOW",
        current_version=1,
        created_by=admin_user.id,
        updated_by=admin_user.id,
    )
    db_session.add(policy)
    db_session.commit()
    db_session.refresh(policy)

    initial_version = PolicyVersion(
        policy_id=policy.id,
        version_number=1,
        configuration_snapshot={
            "name": policy.name,
            "description": policy.description,
            "is_enabled": policy.is_enabled,
            "source_applicability": policy.source_applicability,
            "rule_config": policy.rule_config,
            "severity_thresholds": policy.severity_thresholds,
            "default_action": policy.default_action,
        },
        change_summary="Initial fixture policy version 1",
        author_id=admin_user.id,
    )
    db_session.add(initial_version)
    db_session.commit()

    return policy
