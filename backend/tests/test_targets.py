"""
Targets and Ownership Verification Integration Tests (Step 3C).

Covers:
1. URL normalization (scheme, port, trailing slash, casing)
2. Duplicate target prevention per user
3. Cross-user multi-tenancy (different users can add same site)
4. SSRF protection (loopback blocked when flag off, cloud metadata blocked even when flag on)
5. Meta tag ownership verification (success and clear failure)
6. Well-known challenge file verification (success and clear failure)
7. Strict tenant isolation (404 Not Found, never 403)
8. Delete cascades (deleting target removes scans, findings, reports)
9. Unauthenticated rejection (401 Unauthorized)
"""

import uuid
import pytest
from app.core.settings import settings
from app.models import Finding, Report, Scan, Target, User
from app.scanner.http_client import SafeResponse


def _register_and_login(client, email_prefix="target_tester"):
    """Helper to create a user and return auth bearer headers and user object."""
    email = f"{email_prefix}_{uuid.uuid4().hex[:6]}@test.local"
    password = "StrongPassword123!"
    reg_res = client.post("/api/auth/register", json={"email": email, "password": password})
    assert reg_res.status_code == 201

    login_res = client.post("/api/auth/login", json={"email": email, "password": password})
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}, email


def test_create_target_normalizes_url(client):
    """Adding a target normalizes URL structure and generates verification instructions (TGT-1, TGT-2)."""
    headers, _ = _register_and_login(client)

    payload = {
        "url": "HTTP://EXAMPLE.COM:80/blog/",
        "verification_method": "meta_tag",
    }
    response = client.post("/api/targets", json=payload, headers=headers)
    assert response.status_code == 201
    data = response.json()

    # Normalization checks
    assert data["normalized_url"] == "http://example.com/blog"
    assert data["verification_method"] == "meta_tag"
    assert len(data["verification_token"]) == 32
    assert data["is_verified"] is False
    assert data["verified_at"] is None

    # Instructions check
    instructions = data["instructions"]
    assert instructions["method"] == "meta_tag"
    assert data["verification_token"] in instructions["summary"]
    assert f'<meta name="ethiosec-verification" content="{data["verification_token"]}">' in instructions["meta_tag"]


def test_create_duplicate_target_rejected(client):
    """The same user cannot register the same normalized URL twice (TGT-3)."""
    headers, _ = _register_and_login(client)

    res1 = client.post(
        "/api/targets",
        json={"url": "https://example.com/"},
        headers=headers,
    )
    assert res1.status_code == 201

    # Attempt to register equivalent URL (trailing slash / case variation)
    res2 = client.post(
        "/api/targets",
        json={"url": "https://EXAMPLE.COM:443"},
        headers=headers,
    )
    assert res2.status_code == 400
    data = res2.json()
    assert data["error"]["code"] == "TARGET_ALREADY_EXISTS"
    assert "already registered" in data["error"]["message"].lower()


def test_different_users_can_add_same_target(client):
    """Two different users can register the same target website independently."""
    headers1, _ = _register_and_login(client, "user_one")
    headers2, _ = _register_and_login(client, "user_two")

    url = "https://shared-target.org"
    res1 = client.post("/api/targets", json={"url": url}, headers=headers1)
    assert res1.status_code == 201

    res2 = client.post("/api/targets", json={"url": url}, headers=headers2)
    assert res2.status_code == 201
    assert res1.json()["id"] != res2.json()["id"]


def test_ssrf_rejection_loopback_with_flag_off(client, monkeypatch):
    """Loopback addresses are rejected when ALLOW_LOCAL_TARGETS is False (SEC-4)."""
    monkeypatch.setattr(settings, "ALLOW_LOCAL_TARGETS", False)
    headers, _ = _register_and_login(client)

    response = client.post(
        "/api/targets",
        json={"url": "http://127.0.0.1:5000"},
        headers=headers,
    )
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "SSRF_ERROR"
    assert "loopback" in data["error"]["message"].lower()


def test_ssrf_rejection_metadata_ip_with_flag_on(client, monkeypatch):
    """Cloud metadata address 169.254.169.254 is ALWAYS refused even when ALLOW_LOCAL_TARGETS is True (SEC-4)."""
    monkeypatch.setattr(settings, "ALLOW_LOCAL_TARGETS", True)
    headers, _ = _register_and_login(client)

    response = client.post(
        "/api/targets",
        json={"url": "http://169.254.169.254/latest/meta-data/"},
        headers=headers,
    )
    assert response.status_code == 400
    data = response.json()
    assert data["error"]["code"] == "SSRF_ERROR"
    assert "cloud metadata" in data["error"]["message"].lower()


def test_verify_meta_tag_success(client, monkeypatch):
    """Ownership verification succeeds when homepage includes expected <meta> tag (TGT-6)."""
    headers, _ = _register_and_login(client)
    create_res = client.post(
        "/api/targets",
        json={"url": "https://example.com", "verification_method": "meta_tag"},
        headers=headers,
    )
    assert create_res.status_code == 201
    target_data = create_res.json()
    target_id = target_data["id"]
    token = target_data["verification_token"]

    # Mock safe_get to return HTML with matching meta tag
    html_doc = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <meta name="ethiosec-verification" content="{token}">
        <title>Example Domain</title>
    </head>
    <body><h1>Welcome</h1></body>
    </html>
    """
    mock_resp = SafeResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        content=html_doc.encode("utf-8"),
        url="https://example.com",
        final_url="https://example.com",
        elapsed_seconds=0.1,
    )
    monkeypatch.setattr("app.services.verification_service.safe_get", lambda *args, **kwargs: mock_resp)

    verify_res = client.post(f"/api/targets/{target_id}/verify", headers=headers)
    assert verify_res.status_code == 200
    vdata = verify_res.json()
    assert vdata["is_verified"] is True
    assert vdata["verified_at"] is not None
    assert vdata["last_checked_at"] is not None
    assert "successfully" in vdata["message"].lower()


def test_verify_meta_tag_failure(client, monkeypatch):
    """Verification failure returns clear reason and updates last_checked_at without verifying (TGT-6)."""
    headers, _ = _register_and_login(client)
    create_res = client.post(
        "/api/targets",
        json={"url": "https://example.com", "verification_method": "meta_tag"},
        headers=headers,
    )
    target_id = create_res.json()["id"]

    # Mock safe_get returning HTML without meta tag
    html_doc = "<html><head><title>No Meta Tag Here</title></head><body>Hello</body></html>"
    mock_resp = SafeResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        content=html_doc.encode("utf-8"),
        url="https://example.com",
        final_url="https://example.com",
        elapsed_seconds=0.1,
    )
    monkeypatch.setattr("app.services.verification_service.safe_get", lambda *args, **kwargs: mock_resp)

    verify_res = client.post(f"/api/targets/{target_id}/verify", headers=headers)
    assert verify_res.status_code == 200
    vdata = verify_res.json()
    assert vdata["is_verified"] is False
    assert vdata["verified_at"] is None
    assert vdata["last_checked_at"] is not None
    assert "not found" in vdata["details"].lower()


def test_verify_http_file_success(client, monkeypatch):
    """Ownership verification succeeds when challenge file matches token exactly (TGT-6)."""
    headers, _ = _register_and_login(client)
    create_res = client.post(
        "/api/targets",
        json={"url": "https://example.com", "verification_method": "http_file"},
        headers=headers,
    )
    target_id = create_res.json()["id"]
    token = create_res.json()["verification_token"]

    mock_resp = SafeResponse(
        status_code=200,
        headers={"content-type": "text/plain"},
        content=f"{token}\n".encode("utf-8"),
        url="https://example.com/.well-known/ethiosec-challenge.txt",
        final_url="https://example.com/.well-known/ethiosec-challenge.txt",
        elapsed_seconds=0.1,
    )
    monkeypatch.setattr("app.services.verification_service.safe_get", lambda *args, **kwargs: mock_resp)

    verify_res = client.post(f"/api/targets/{target_id}/verify", headers=headers)
    assert verify_res.status_code == 200
    vdata = verify_res.json()
    assert vdata["is_verified"] is True
    assert vdata["verified_at"] is not None


def test_verify_http_file_failure(client, monkeypatch):
    """Challenge file 404 returns failure message and updates last_checked_at (TGT-6)."""
    headers, _ = _register_and_login(client)
    create_res = client.post(
        "/api/targets",
        json={"url": "https://example.com", "verification_method": "http_file"},
        headers=headers,
    )
    target_id = create_res.json()["id"]

    mock_resp = SafeResponse(
        status_code=404,
        headers={"content-type": "text/plain"},
        content=b"Not Found",
        url="https://example.com/.well-known/ethiosec-challenge.txt",
        final_url="https://example.com/.well-known/ethiosec-challenge.txt",
        elapsed_seconds=0.1,
    )
    monkeypatch.setattr("app.services.verification_service.safe_get", lambda *args, **kwargs: mock_resp)

    verify_res = client.post(f"/api/targets/{target_id}/verify", headers=headers)
    assert verify_res.status_code == 200
    vdata = verify_res.json()
    assert vdata["is_verified"] is False
    assert vdata["last_checked_at"] is not None
    assert "404" in vdata["details"]


def test_tenant_isolation_returns_404(client):
    """Querying, verifying, or deleting another user's target returns 404 Not Found, never 403 (TGT-7)."""
    headers_owner, _ = _register_and_login(client, "owner")
    headers_other, _ = _register_and_login(client, "intruder")

    # Owner creates target
    owner_target = client.post(
        "/api/targets",
        json={"url": "https://owner-only-domain.com"},
        headers=headers_owner,
    ).json()
    target_id = owner_target["id"]

    # 1. Other user attempts GET
    get_res = client.get(f"/api/targets/{target_id}", headers=headers_other)
    assert get_res.status_code == 404
    assert get_res.json()["error"]["code"] == "TARGET_NOT_FOUND"

    # 2. Other user attempts POST /verify
    verify_res = client.post(f"/api/targets/{target_id}/verify", headers=headers_other)
    assert verify_res.status_code == 404
    assert verify_res.json()["error"]["code"] == "TARGET_NOT_FOUND"

    # 3. Other user attempts DELETE
    del_res = client.delete(f"/api/targets/{target_id}", headers=headers_other)
    assert del_res.status_code == 404
    assert del_res.json()["error"]["code"] == "TARGET_NOT_FOUND"


def test_delete_target_cascades_scans_findings_reports(client, db_session):
    """Deleting a target cascades and deletes all related scans, findings, and reports (TGT-8)."""
    headers, email = _register_and_login(client, "cascade_user")
    user = db_session.query(User).filter(User.email == email).first()

    # Create target via API
    create_res = client.post(
        "/api/targets",
        json={"url": "https://cascade-test.org"},
        headers=headers,
    )
    assert create_res.status_code == 201
    target_id = uuid.UUID(create_res.json()["id"])

    # Directly create child records in database (Scan -> Finding, Scan -> Report)
    scan = Scan(
        user_id=user.id,
        target_id=target_id,
        target_url="https://cascade-test.org",
        depth="standard",
        status="completed",
        progress=100,
    )
    db_session.add(scan)
    db_session.commit()
    db_session.refresh(scan)

    finding = Finding(
        scan_id=scan.id,
        target_id=target_id,
        module="headers",
        severity="medium",
        title="Missing CSP Header",
        description="Content-Security-Policy header is absent.",
        remediation="Configure CSP header.",
        affected_url="https://cascade-test.org",
    )
    report = Report(
        scan_id=scan.id,
        user_id=user.id,
        report_format="json",
        summary={"findings_count": 1},
    )
    db_session.add(finding)
    db_session.add(report)
    db_session.commit()

    # Verify records exist before delete
    assert db_session.query(Target).filter(Target.id == target_id).first() is not None
    assert db_session.query(Scan).filter(Scan.target_id == target_id).first() is not None
    assert db_session.query(Finding).filter(Finding.target_id == target_id).first() is not None
    assert db_session.query(Report).filter(Report.scan_id == scan.id).first() is not None

    # Call DELETE /api/targets/{id}
    del_res = client.delete(f"/api/targets/{target_id}", headers=headers)
    assert del_res.status_code == 200

    # Verify cascade deletion in DB
    assert db_session.query(Target).filter(Target.id == target_id).first() is None
    assert db_session.query(Scan).filter(Scan.target_id == target_id).first() is None
    assert db_session.query(Finding).filter(Finding.target_id == target_id).first() is None
    assert db_session.query(Report).filter(Report.scan_id == scan.id).first() is None


def test_targets_endpoints_require_authentication(client):
    """Accessing target endpoints without authentication returns 401 (SRS Section 4.2)."""
    fake_id = uuid.uuid4()
    assert client.get("/api/targets").status_code == 401
    assert client.post("/api/targets", json={"url": "https://example.com"}).status_code == 401
    assert client.get(f"/api/targets/{fake_id}").status_code == 401
    assert client.delete(f"/api/targets/{fake_id}").status_code == 401
    assert client.post(f"/api/targets/{fake_id}/verify").status_code == 401
