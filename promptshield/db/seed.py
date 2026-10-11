"""Database Seeder for PromptShield.

Seeds initial trusted administrators, reviewers, auditors, and the default
production security policy idempotently.
"""

import logging
from sqlalchemy.orm import Session
from promptshield.db.models import User, SecurityPolicy, PolicyVersion, AuditEvent
from promptshield.security.hashing import hash_password

logger = logging.getLogger("promptshield.seed")


def seed_default_data(db: Session) -> None:
    """Idempotently seed default users and active security policy."""
    try:
        # 1. Seed Default Administrator if not exists
        admin = db.query(User).filter(User.username == "admin_user").first()
        if not admin:
            admin = User(
                username="admin_user",
                email="admin@promptshield.internal",
                hashed_password=hash_password("AdminSecurePassword123!"),
                role="admin",
                is_active=True,
            )
            db.add(admin)
            db.flush()
            logger.info("Seeded default administrator: admin_user")

        # 2. Seed Default Reviewer if not exists
        reviewer = db.query(User).filter(User.username == "reviewer_user").first()
        if not reviewer:
            reviewer = User(
                username="reviewer_user",
                email="reviewer@promptshield.internal",
                hashed_password=hash_password("ReviewerSecurePassword123!"),
                role="reviewer",
                is_active=True,
            )
            db.add(reviewer)
            db.flush()
            logger.info("Seeded default reviewer: reviewer_user")

        # 3. Seed Default Auditor if not exists
        auditor = db.query(User).filter(User.username == "auditor_user").first()
        if not auditor:
            auditor = User(
                username="auditor_user",
                email="auditor@promptshield.internal",
                hashed_password=hash_password("AuditorSecurePassword123!"),
                role="auditor",
                is_active=True,
            )
            db.add(auditor)
            db.flush()
            logger.info("Seeded default auditor: auditor_user")

        # 4. Seed Default Security Policy if none active
        active_policy = db.query(SecurityPolicy).filter(SecurityPolicy.is_enabled == True).first()
        if not active_policy:
            policy = SecurityPolicy(
                name="Default PromptShield Production Policy",
                description="Comprehensive defensive policy protecting against prompt injection and data exfiltration",
                is_enabled=True,
                source_applicability=["USER_PROMPT", "SYSTEM_PROMPT", "RETRIEVED_DOC", "TOOL_OUTPUT"],
                rule_config={
                    "rules": [
                        {"name": "Block Exfiltration", "category": "DATA_EXFILTRATION", "action": "BLOCK"},
                        {"name": "Intercept Injections", "category": "PROMPT_INJECTION", "action": "BLOCK"},
                        {"name": "Escalate Ambiguous Signals", "category": "ANOMALY", "action": "ESCALATE"},
                    ]
                },
                severity_thresholds={
                    "CRITICAL": "BLOCK",
                    "HIGH": "BLOCK",
                    "MEDIUM": "ESCALATE",
                    "LOW": "ALLOW",
                },
                default_action="ALLOW",
                current_version=1,
                created_by=admin.id,
                updated_by=admin.id,
            )
            db.add(policy)
            db.flush()

            # Snapshot initial version
            snapshot = {
                "name": policy.name,
                "description": policy.description,
                "is_enabled": policy.is_enabled,
                "source_applicability": policy.source_applicability,
                "rule_config": policy.rule_config,
                "severity_thresholds": policy.severity_thresholds,
                "default_action": policy.default_action,
            }
            version_entry = PolicyVersion(
                policy_id=policy.id,
                version_number=1,
                configuration_snapshot=snapshot,
                change_summary="Initial system seed production policy",
                author_id=admin.id,
            )
            db.add(version_entry)

            # Audit record
            audit = AuditEvent(
                actor_id=admin.id,
                actor_role=admin.role,
                event_type="POLICY_CREATED",
                target_resource=f"policy:{policy.id}",
                action_taken="CREATE",
                outcome="SUCCESS",
                policy_version=1,
                safe_metadata={
                    "policy_name": policy.name,
                    "default_action": policy.default_action,
                    "version": 1,
                },
            )
            db.add(audit)
            logger.info("Seeded default active security policy v1")

        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to seed default data: {e}")
