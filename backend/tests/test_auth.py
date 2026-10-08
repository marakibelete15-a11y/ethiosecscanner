"""
Authentication and User Account Tests (Step 3B).

Tests for:
1. Registration with lowercase email and automatic user_settings creation
2. Password rules (min 8 chars, upper, lower, digit, max 72 bytes)
3. Direct bcrypt hashing (passwords never logged/returned)
4. Duplicate email rejection
5. Identical generic 401 message for wrong email and wrong password
6. Inactive user login rejection
7. GET /api/auth/me with and without Bearer token
8. Production JWT secret validation
"""

import uuid
import pytest
from fastapi.testclient import TestClient
from app.core.security import get_jwt_secret, hash_password
from app.core.settings import settings
from app.main import app
from app.models import User, UserSettings


def test_register_success_creates_user_and_settings(client, db_session):
    """Register creates user with lowercase email and default user_settings row (AUTH-1, AUTH-7)."""
    email_input = f"TEST_ANALYST_{uuid.uuid4().hex[:6]}@EthioSec.LOCAL"
    payload = {
        "email": email_input,
        "password": "StrongPassword123!",
        "full_name": "Test Analyst",
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()

    # User fields
    assert data["email"] == email_input.strip().lower()
    assert data["full_name"] == "Test Analyst"
    assert data["role"] == "user"
    assert data["is_active"] is True
    assert "password" not in data
    assert "password_hash" not in data

    # Verify user_settings row was created in database
    user_id = uuid.UUID(data["id"])
    user_settings = db_session.query(UserSettings).filter(UserSettings.user_id == user_id).first()
    assert user_settings is not None
    assert user_settings.default_scan_depth == "standard"
    assert user_settings.notify_scan_completed is True


def test_register_rejects_weak_passwords(client):
    """Password rules require at least 8 chars, uppercase, lowercase, and digit (AUTH-2)."""
    test_cases = [
        ("Short1!", "at least 8 characters"),
        ("nouppercase123!", "uppercase letter"),
        ("NOLOWERCASE123!", "lowercase letter"),
        ("NoDigitsInPassword!", "digit"),
    ]
    for weak_pw, expected_reason in test_cases:
        payload = {
            "email": f"weak_{uuid.uuid4().hex[:6]}@test.local",
            "password": weak_pw,
        }
        response = client.post("/api/auth/register", json=payload)
        assert response.status_code == 422
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"
        assert expected_reason in data["error"]["message"]


def test_register_rejects_73_byte_password(client):
    """Passwords exceeding 72 bytes are rejected, not truncated (AUTH-2, SEC-1)."""
    # 73 bytes: 60 'A's + 11 'a's + 2 '1's
    long_password = ("A" * 60) + ("a" * 11) + ("1" * 2)
    assert len(long_password.encode("utf-8")) == 73

    payload = {
        "email": f"longpw_{uuid.uuid4().hex[:6]}@test.local",
        "password": long_password,
    }
    response = client.post("/api/auth/register", json=payload)
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "72 bytes" in data["error"]["message"]


def test_register_rejects_duplicate_email(client):
    """Duplicate email registration must return a clear error (AUTH-1)."""
    email = f"duplicate_{uuid.uuid4().hex[:6]}@test.local"
    payload = {
        "email": email,
        "password": "ValidPassword123!",
        "full_name": "Original User",
    }
    first_res = client.post("/api/auth/register", json=payload)
    assert first_res.status_code == 201

    # Attempt registration with same email (different casing)
    duplicate_payload = {
        "email": email.upper(),
        "password": "AnotherPassword123!",
        "full_name": "Duplicate User",
    }
    second_res = client.post("/api/auth/register", json=duplicate_payload)
    assert second_res.status_code == 400
    data = second_res.json()
    assert data["error"]["code"] == "EMAIL_ALREADY_EXISTS"


def test_login_success_returns_jwt(client):
    """Valid login credentials return signed JWT (AUTH-3)."""
    email = f"login_test_{uuid.uuid4().hex[:6]}@test.local"
    password = "ValidPassword123!"

    reg_res = client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_res.status_code == 201

    login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert len(data["access_token"]) > 20


def test_login_wrong_password_and_unknown_email_return_identical_401(client):
    """Wrong email and wrong password return identical generic 401 error (AUTH-3)."""
    email = f"user_{uuid.uuid4().hex[:6]}@test.local"
    password = "ValidPassword123!"

    reg_res = client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_res.status_code == 201

    # Case 1: Wrong password
    wrong_pw_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword123!"},
    )
    assert wrong_pw_res.status_code == 401
    wrong_pw_data = wrong_pw_res.json()

    # Case 2: Unknown email
    unknown_email_res = client.post(
        "/api/auth/login",
        json={"email": f"unknown_{uuid.uuid4().hex[:6]}@test.local", "password": password},
    )
    assert unknown_email_res.status_code == 401
    unknown_email_data = unknown_email_res.json()

    # Verify identical envelope and message
    assert wrong_pw_data == unknown_email_data
    assert wrong_pw_data["error"]["code"] == "UNAUTHORIZED"
    assert wrong_pw_data["error"]["message"] == "Invalid email or password."


def test_login_inactive_user_rejected(client, db_session):
    """Inactive accounts cannot log in (AUTH-8)."""
    email = f"inactive_{uuid.uuid4().hex[:6]}@test.local"
    password = "ValidPassword123!"

    reg_res = client.post(
        "/api/auth/register",
        json={"email": email, "password": password},
    )
    assert reg_res.status_code == 201

    # Deactivate account directly in DB
    user = db_session.query(User).filter(User.email == email).first()
    user.is_active = False
    db_session.commit()

    login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 401
    data = login_res.json()
    assert data["error"]["code"] == "ACCOUNT_INACTIVE"


def test_get_me_with_valid_token(client):
    """GET /api/auth/me returns profile of logged-in user (AUTH-4)."""
    email = f"me_test_{uuid.uuid4().hex[:6]}@test.local"
    password = "ValidPassword123!"

    reg_res = client.post(
        "/api/auth/register",
        json={"email": email, "password": password, "full_name": "Me Tester"},
    )
    assert reg_res.status_code == 201

    login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    token = login_res.json()["access_token"]

    me_res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    data = me_res.json()
    assert data["email"] == email
    assert data["full_name"] == "Me Tester"
    assert "password_hash" not in data


def test_get_me_without_token(client):
    """GET /api/auth/me without token returns 401 UNAUTHORIZED (AUTH-4)."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "UNAUTHORIZED"


def test_get_me_with_invalid_token(client):
    """GET /api/auth/me with corrupt token returns 401 UNAUTHORIZED (AUTH-4)."""
    response = client.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer not-a-valid-jwt-token"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "UNAUTHORIZED"


def test_startup_fails_with_placeholder_secret(monkeypatch):
    """App startup must fail in any environment if JWT_SECRET_KEY is the placeholder (AUTH-6, SEC-2)."""
    monkeypatch.setattr(settings, "JWT_SECRET_KEY", "replace-with-a-strong-jwt-secret-in-production")
    with pytest.raises(RuntimeError) as exc_info:
        with TestClient(app):
            pass
    assert "JWT_SECRET_KEY" in str(exc_info.value)


def test_jwt_secret_enforced_in_any_environment(monkeypatch):
    """Refuses empty, placeholder, or <32 char keys in any environment (AUTH-6, SEC-2)."""
    invalid_keys = [
        "",
        "replace-with-a-strong-jwt-secret-in-production",
        "short-secret-under-32-chars",
    ]
    for env in ["development", "testing", "production"]:
        monkeypatch.setattr(settings, "ENVIRONMENT", env)
        for key in invalid_keys:
            monkeypatch.setattr(settings, "JWT_SECRET_KEY", key)
            with pytest.raises(RuntimeError) as exc_info:
                get_jwt_secret()
            assert "JWT_SECRET_KEY" in str(exc_info.value)
