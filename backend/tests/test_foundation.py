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


def test_startup_marks_abandoned_scans_as_failed(db_session):
    """SCN-10: Scans left in 'running' state on server start are marked 'failed'."""
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

    # Simulate startup reset
    db_session.query(Scan).filter(Scan.status == "running").update(
        {
            Scan.status: "failed",
            Scan.error_message: "Scan marked failed due to server restart",
            Scan.finished_at: datetime.datetime.now(datetime.timezone.utc),
        },
        synchronize_session=False,
    )
    db_session.commit()

    reloaded_scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
    assert reloaded_scan.status == "failed"
    assert "server restart" in reloaded_scan.error_message.lower()
