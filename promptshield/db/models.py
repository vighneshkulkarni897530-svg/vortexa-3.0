import uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from sqlalchemy import (
    String,
    Boolean,
    Integer,
    Float,
    DateTime,
    Text,
    ForeignKey,
    JSON,
    Index,
    UniqueConstraint
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from promptshield.db.base import Base


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    email: Mapped[str] = mapped_column(String(120), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="user", index=True, nullable=False)  # admin, reviewer, auditor, user, service
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    created_policies = relationship("SecurityPolicy", foreign_keys="[SecurityPolicy.created_by]", back_populates="creator")
    assigned_reviews = relationship("ReviewCase", foreign_keys="[ReviewCase.assigned_reviewer_id]", back_populates="assigned_reviewer")


class SecurityPolicy(Base):
    __tablename__ = "security_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True, nullable=False)
    
    # Source types to which this policy applies: e.g. ["USER_PROMPT", "SYSTEM_PROMPT", "RETRIEVED_DOC", "TOOL_OUTPUT"]
    source_applicability: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    
    # Detailed detection rules and actions
    rule_config: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    
    # Action thresholds by severity
    severity_thresholds: Mapped[Dict[str, str]] = mapped_column(JSON, default=dict, nullable=False)
    
    # Baseline action: ALLOW, BLOCK, SANITIZE, ESCALATE
    default_action: Mapped[str] = mapped_column(String(32), default="ALLOW", nullable=False)
    
    # Version tracker
    current_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    
    # Audit tracking
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    creator = relationship("User", foreign_keys=[created_by], back_populates="created_policies")
    versions = relationship("PolicyVersion", back_populates="policy", cascade="all, delete-orphan", order_by="PolicyVersion.version_number.desc()")
    scans = relationship("ScanRecord", back_populates="policy")


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    policy_id: Mapped[str] = mapped_column(String(36), ForeignKey("security_policies.id", ondelete="CASCADE"), nullable=False, index=True)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    configuration_snapshot: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False)
    change_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    author_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Constraints & Relationships
    __table_args__ = (
        UniqueConstraint("policy_id", "version_number", name="uq_policy_version_number"),
    )
    policy = relationship("SecurityPolicy", back_populates="versions")
    author = relationship("User", foreign_keys=[author_id])


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    correlation_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # USER_PROMPT, SYSTEM_PROMPT, RETRIEVED_DOC, TOOL_OUTPUT
    detection_findings: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    final_action: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # ALLOW, BLOCK, SANITIZE, ESCALATE
    risk_classification: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # BENIGN, LOW, MEDIUM, HIGH, CRITICAL
    reason_codes: Mapped[List[str]] = mapped_column(JSON, default=list, nullable=False)
    
    policy_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("security_policies.id", ondelete="SET NULL"), nullable=True)
    policy_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    processing_duration_ms: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    
    # Authorized redacted reference only. NEVER store full raw prompts or secrets.
    redacted_content_ref: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

    # Relationships
    policy = relationship("SecurityPolicy", back_populates="scans")
    review_case = relationship("ReviewCase", back_populates="scan", uselist=False, cascade="all, delete-orphan")


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(64), index=True, nullable=True)
    actor_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    actor_role: Mapped[str] = mapped_column(String(32), nullable=False)
    event_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    target_resource: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    action_taken: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), index=True, nullable=False)  # SUCCESS, FAILURE, DENIED
    policy_version: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    safe_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

    __table_args__ = (
        Index("ix_audit_events_created_actor", "created_at", "actor_id"),
    )


class ReviewCase(Base):
    __tablename__ = "review_cases"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scan_records.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="MEDIUM", index=True, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True, nullable=False)  # PENDING, IN_REVIEW, RESOLVED, DISMISSED
    
    assigned_reviewer_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewer_decision: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # ALLOW, BLOCK, SANITIZE
    decision_justification: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    scan = relationship("ScanRecord", back_populates="review_case")
    assigned_reviewer = relationship("User", foreign_keys=[assigned_reviewer_id], back_populates="assigned_reviews")


class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    dataset_name: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    dataset_version: Mapped[str] = mapped_column(String(32), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    sample_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    
    true_positives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_positives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    true_negatives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    false_negatives: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    
    precision: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    recall: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    false_positive_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    false_negative_rate: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    
    execution_status: Mapped[str] = mapped_column(String(32), default="PENDING", index=True, nullable=False)  # PENDING, RUNNING, COMPLETED, FAILED
    report_metadata: Mapped[Dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    
    created_by: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, index=True, nullable=False)

    creator = relationship("User", foreign_keys=[created_by])
