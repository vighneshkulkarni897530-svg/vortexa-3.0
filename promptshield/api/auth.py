from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from datetime import timedelta

from promptshield.db.session import get_db
from promptshield.db.models import User, AuditEvent
from promptshield.schemas.auth import UserRegister, UserLogin, TokenResponse, UserResponse
from promptshield.security.hashing import hash_password, verify_password
from promptshield.security.tokens import create_access_token
from promptshield.security.dependencies import get_current_user
from promptshield.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user with an assigned RBAC role."""
    existing_user = db.query(User).filter(
        (User.username == data.username) | (User.email == data.email)
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A user with that username or email already exists."
        )

    user = User(
        username=data.username,
        email=data.email,
        hashed_password=hash_password(data.password),
        role=data.role,
        is_active=True,
    )
    db.add(user)
    db.flush()

    # Append-only audit record
    audit = AuditEvent(
        actor_id=user.id,
        actor_role=user.role,
        event_type="AUTH_USER_REGISTERED",
        target_resource=f"user:{user.id}",
        action_taken="REGISTER",
        outcome="SUCCESS",
        safe_metadata={"username": user.username, "role": user.role},
    )
    db.add(audit)
    db.commit()
    db.refresh(user)
    return user


@router.post("/token", response_model=TokenResponse)
def login_for_access_token(data: UserLogin, db: Session = Depends(get_db)):
    """Authenticate with username and password to obtain a signed JWT token."""
    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        # Audit failed login attempt without exposing timing signals or passwords
        audit = AuditEvent(
            actor_id=data.username,
            actor_role="anonymous",
            event_type="AUTH_LOGIN_FAILED",
            target_resource=f"user:{data.username}",
            action_taken="LOGIN",
            outcome="DENIED",
            safe_metadata={"attempted_username": data.username},
        )
        db.add(audit)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )

    token = create_access_token(
        data={"sub": user.username, "role": user.role, "user_id": user.id},
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Audit successful login
    audit = AuditEvent(
        actor_id=user.id,
        actor_role=user.role,
        event_type="AUTH_LOGIN_SUCCESS",
        target_resource=f"user:{user.id}",
        action_taken="LOGIN",
        outcome="SUCCESS",
        safe_metadata={"username": user.username, "role": user.role},
    )
    db.add(audit)
    db.commit()

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role,
        user_id=user.id,
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


@router.get("/me", response_model=UserResponse)
def read_current_user_profile(current_user: User = Depends(get_current_user)):
    """Retrieve details and RBAC role of the authenticated actor."""
    return current_user
