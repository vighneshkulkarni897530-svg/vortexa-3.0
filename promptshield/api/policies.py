from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from promptshield.db.session import get_db
from promptshield.db.models import SecurityPolicy, PolicyVersion, AuditEvent, User
from promptshield.schemas.policy import (
    PolicyCreate,
    PolicyUpdate,
    PolicyResponse,
    PolicyVersionResponse,
)
from promptshield.security.dependencies import (
    get_current_user,
    require_admin,
    require_auditor_or_admin,
)

router = APIRouter(prefix="/policies", tags=["Security Policies"])


@router.get("", response_model=List[PolicyResponse])
def list_policies(
    is_enabled: Optional[bool] = Query(None, description="Filter by active status"),
    source_type: Optional[str] = Query(None, description="Filter by source applicability"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve security policies with optional status and source filters."""
    query = db.query(SecurityPolicy)
    if is_enabled is not None:
        query = query.filter(SecurityPolicy.is_enabled == is_enabled)
    
    policies = query.offset(skip).limit(limit).all()
    
    if source_type:
        filtered = []
        for p in policies:
            if any(s.upper() == source_type.upper() for s in (p.source_applicability or [])):
                filtered.append(p)
        return filtered

    return policies


@router.get("/{policy_id}", response_model=PolicyResponse)
def get_policy_by_id(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a single security policy by unique identifier."""
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy '{policy_id}' not found."
        )
    return policy


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
def create_policy(
    data: PolicyCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Create a new trusted security policy.
    Enforces strict administrator authorization and writes an immutable version snapshot.
    """
    existing = db.query(SecurityPolicy).filter(SecurityPolicy.name == data.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Policy with name '{data.name}' already exists."
        )

    policy = SecurityPolicy(
        name=data.name,
        description=data.description,
        is_enabled=data.is_enabled,
        source_applicability=data.source_applicability,
        rule_config=data.rule_config,
        severity_thresholds=data.severity_thresholds,
        default_action=data.default_action,
        current_version=1,
        created_by=current_user.id,
        updated_by=current_user.id,
    )
    db.add(policy)
    db.flush()

    # Immutable initial version snapshot
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
        change_summary=data.change_summary or "Initial policy creation",
        author_id=current_user.id,
    )
    db.add(version_entry)

    # Append-only audit record
    audit = AuditEvent(
        actor_id=current_user.id,
        actor_role=current_user.role,
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
    db.commit()
    db.refresh(policy)
    return policy


@router.put("/{policy_id}", response_model=PolicyResponse)
def update_policy(
    policy_id: str,
    data: PolicyUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Update a security policy.
    Never silently rewrites configuration: creates an immutable PolicyVersion record.
    Requires administrator authorization.
    """
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy '{policy_id}' not found."
        )

    if data.name and data.name != policy.name:
        conflict = db.query(SecurityPolicy).filter(
            SecurityPolicy.name == data.name, SecurityPolicy.id != policy_id
        ).first()
        if conflict:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Policy name '{data.name}' is already in use by another policy."
            )
        policy.name = data.name

    if data.description is not None:
        policy.description = data.description
    if data.is_enabled is not None:
        policy.is_enabled = data.is_enabled
    if data.source_applicability is not None:
        policy.source_applicability = data.source_applicability
    if data.rule_config is not None:
        policy.rule_config = data.rule_config
    if data.severity_thresholds is not None:
        policy.severity_thresholds = data.severity_thresholds
    if data.default_action is not None:
        policy.default_action = data.default_action

    # Increment version
    policy.current_version += 1
    policy.updated_by = current_user.id

    # Create immutable version record
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
        version_number=policy.current_version,
        configuration_snapshot=snapshot,
        change_summary=data.change_summary,
        author_id=current_user.id,
    )
    db.add(version_entry)

    # Append-only audit record
    audit = AuditEvent(
        actor_id=current_user.id,
        actor_role=current_user.role,
        event_type="POLICY_UPDATED",
        target_resource=f"policy:{policy.id}",
        action_taken="UPDATE",
        outcome="SUCCESS",
        policy_version=policy.current_version,
        safe_metadata={
            "policy_name": policy.name,
            "new_version": policy.current_version,
            "change_summary": data.change_summary,
        },
    )
    db.add(audit)
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/{policy_id}/versions", response_model=List[PolicyVersionResponse])
def get_policy_versions(
    policy_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_auditor_or_admin),
):
    """Retrieve the immutable audit history of configuration versions for a policy."""
    policy = db.query(SecurityPolicy).filter(SecurityPolicy.id == policy_id).first()
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security policy '{policy_id}' not found."
        )

    versions = db.query(PolicyVersion).filter(
        PolicyVersion.policy_id == policy_id
    ).order_by(PolicyVersion.version_number.desc()).all()
    return versions
