"""
Foundation and Infrastructure Tests (Step 3A).

Verifies:
1. /health endpoint and DB connectivity
2. Standardized error envelope (SRS Section 7) for 404 and validation errors
3. SCN-10 startup behavior (abandoned running scans marked failed)
"""

import datetime
import pytest
from fastapi import FastAPI, Query
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.core.error_handlers import register_error_handlers
from app.main import app, _configured_cors_origins, _documentation_urls
from app.models import Scan, Target, User


def test_health_check_returns_200(client):
    """GET /health must return 200 and database connected status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"


def test_404_returns_standard_error_envelope(client):
    """Non-existent endpoints must return SRS Section 7 error envelope."""
    response = client.get("/api/does-not-exist")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert isinstance(data["error"]["message"], str)


def test_validation_error_returns_standard_envelope():
    """Request validation errors must return VALIDATION_ERROR envelope."""
    temp_app = FastAPI()
    register_error_handlers(temp_app)

    @temp_app.get("/test-val")
    def dummy_endpoint(num: int = Query(...)):
        return {"num": num}

    temp_client = TestClient(temp_app)
    response = temp_client.get("/test-val?num=invalid_integer")
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "num" in data["error"]["message"]


def test_unhandled_exception_returns_generic_error_envelope(caplog):
    secret = "FAKE_UNHANDLED_TOKEN_123"
    fake_path = "/tmp/internal_unhandled_error.py"
    temp_app = FastAPI()
    register_error_handlers(temp_app)

    @temp_app.get("/test-error")
    def failing_endpoint():
        raise RuntimeError(f"token={secret}; file path={fake_path}")

    caplog.set_level("ERROR", logger="ethiosec.errors")
    with TestClient(temp_app, raise_server_exceptions=False) as temp_client:
        response = temp_client.get("/test-error")

    assert response.status_code == 500
    assert response.json() == {
        "error": {
            "code": "INTERNAL_SERVER_ERROR",
            "message": "An internal server error occurred.",
        }
    }
    assert secret not in response.text
    assert fake_path not in response.text
    assert secret not in caplog.text
    assert fake_path not in caplog.text


def test_production_disables_all_api_schema_routes():
    assert _documentation_urls("production") == {
        "docs_url": None,
        "redoc_url": None,
        "openapi_url": None,
    }
    assert _documentation_urls("development")["openapi_url"] == "/openapi.json"


def test_cors_origins_parse_as_empty_default_or_explicit_allowlist():
    assert _configured_cors_origins("") == []
    assert _configured_cors_origins(" https://ui.example ,https://admin.example,") == [
        "https://ui.example",
        "https://admin.example",
    ]


def test_startup_lifespan_marks_abandoned_scans_as_failed(db_session, monkeypatch):
    """The real application lifespan marks persisted running scans as failed."""
    user = User(
        email="orphan_scan_test@ethiosec.local",
        password_hash="hash",
    )
    db_session.add(user)
    db_session.flush()

    target = Target(
        user_id=user.id,
        url="http://orphan.local",
        normalized_url="http://orphan.local",
        verification_token="token",
    )
    db_session.add(target)
    db_session.flush()

    running_scan = Scan(
        user_id=user.id,
        target_id=target.id,
        target_url=target.url,
        depth="standard",
        status="running",
        progress=45,
    )
    db_session.add(running_scan)
    db_session.commit()

    scan_id = running_scan.id

    class StartupSession:
        def __getattr__(self, name):
            return getattr(db_session, name)

        def close(self):
            pass

    monkeypatch.setattr("app.main.SessionLocal", lambda: StartupSession())
    with TestClient(app):
        recovered_scan = db_session.query(Scan).filter(Scan.id == scan_id).one()
        assert recovered_scan.status == "failed"
        assert "server restart" in recovered_scan.error_message.lower()
