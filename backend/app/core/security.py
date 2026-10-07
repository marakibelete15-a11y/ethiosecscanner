"""
Security and Cryptography Utilities.

Enforces direct bcrypt password hashing and PyJWT token handling (SEC-1, SEC-2).
"""

import datetime
from typing import Any, Dict, Optional
import bcrypt
import jwt
from app.core.settings import settings


def get_jwt_secret() -> str:
    """
    Retrieve JWT signing secret.
    Refuses to start in production if secret is missing or default (AUTH-6, SEC-2).
    """
    secret = settings.JWT_SECRET_KEY
    if settings.ENVIRONMENT == "production":
        if not secret or secret == "replace-with-a-strong-jwt-secret-in-production":
            raise RuntimeError("JWT_SECRET_KEY must be configured in environment in production.")
    return secret


def validate_password_complexity(password: str) -> None:
    """
    Enforce password complexity rules (AUTH-2, SEC-1):
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At most 72 bytes (bcrypt maximum length; rejected, not silently truncated)
    """
    pw_bytes = password.encode("utf-8")
    if len(pw_bytes) > 72:
        raise ValueError("Password cannot exceed 72 bytes.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one digit.")


def hash_password(password: str) -> str:
    """Hash a plaintext password directly using bcrypt."""
    validate_password_complexity(password)
    pw_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash string."""
    pw_bytes = plain_password.encode("utf-8")
    if len(pw_bytes) > 72:
        return False
    try:
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(pw_bytes, hash_bytes)
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[datetime.timedelta] = None) -> str:
    """Generate a signed JWT token with configurable expiration."""
    secret = get_jwt_secret()
    to_encode = data.copy()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + datetime.timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRES_MINUTES
        )
    to_encode.update({"exp": expire, "iat": now_utc})
    return jwt.encode(to_encode, secret, algorithm="HS256")


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT access token."""
    secret = get_jwt_secret()
    return jwt.decode(token, secret, algorithms=["HS256"])
