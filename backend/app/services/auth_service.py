"""
Authentication and User Account Business Logic Service.

Implements AUTH-1 through AUTH-8 and SEC-1.
"""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models import User, UserSettings
from app.schemas.auth import UserRegisterRequest

GENERIC_AUTH_ERROR = {
    "code": "UNAUTHORIZED",
    "message": "Invalid email or password.",
}


def register_user(db: Session, req: UserRegisterRequest) -> User:
    """
    Register a new user account.
    - Enforces unique email check (AUTH-1)
    - Hashes password using bcrypt directly (AUTH-2, SEC-1)
    - Creates corresponding user_settings row in the same transaction (AUTH-7)
    """
    existing_user = db.query(User).filter(User.email == req.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "EMAIL_ALREADY_EXISTS",
                "message": "An account with this email address already exists.",
            },
        )

    # Hash password with bcrypt
    pw_hash = hash_password(req.password)

    # Atomically create User and default UserSettings in one transaction
    new_user = User(
        email=req.email,
        password_hash=pw_hash,
        full_name=req.full_name,
        role="user",
        is_active=True,
    )
    db.add(new_user)
    db.flush()

    default_settings = UserSettings(
        user_id=new_user.id,
        default_scan_depth="standard",
        notify_scan_completed=True,
        notify_scan_failed=True,
        notify_critical_finding=True,
    )
    db.add(default_settings)
    db.commit()
    db.refresh(new_user)

    return new_user


def authenticate_user(db: Session, email: str, password: str) -> User:
    """
    Authenticate user credentials.
    - Rejects invalid emails or passwords with the identical generic message (AUTH-3)
    - Rejects inactive user accounts (AUTH-8)
    """
    clean_email = email.strip().lower()
    user = db.query(User).filter(User.email == clean_email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_AUTH_ERROR,
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "ACCOUNT_INACTIVE",
                "message": "This account is inactive. Please contact support.",
            },
        )

    if not verify_password(password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=GENERIC_AUTH_ERROR,
        )

    return user
