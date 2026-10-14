"""Tests for reports and authenticated user profile/password/settings APIs."""

import uuid

from app.models import Finding, Scan, Target, User, UserSettings


PASSWORD = "StrongPassword123!"


def _register_and_login(client, prefix, password=PASSWORD):
	email = f"{prefix}_{uuid.uuid4().hex[:8]}@test.local"
	registered = client.post(
		"/api/auth/register",
		json={"email": email, "password": password, "full_name": "Initial Name"},
	)
	assert registered.status_code == 201
	login = client.post("/api/auth/login", json={"email": email, "password": password})
	assert login.status_code == 200
	return {"Authorization": f"Bearer {login.json()['access_token']}"}, email


def _target_and_scan(db_session, email, *, scan_status="completed", module_progress=None, score=72):
	user = db_session.query(User).filter(User.email == email).one()
	target_url = f"https://{uuid.uuid4().hex}.example.test"
	target = Target(
		user_id=user.id,
		url=target_url,
		normalized_url=target_url,
		verification_method="meta_tag",
		verification_token=uuid.uuid4().hex,
		is_verified=True,
	)
	db_session.add(target)
	db_session.flush()
	scan = Scan(
		user_id=user.id,
		target_id=target.id,
		target_url=target_url,
		depth="standard",
		selected_modules=["headers", "https"],
		module_progress=module_progress or {
			"headers": {"status": "done", "checks_run": 8, "checks_passed": 5, "findings_count": 1},
			"https": {"status": "error", "checks_run": 3, "checks_passed": 2, "findings_count": 0},
		},
		status=scan_status,
		progress=100 if scan_status == "completed" else 0,
		security_score=score,
	)
	db_session.add(scan)
	db_session.flush()
	return user, target, scan


def _add_finding(db_session, scan, target, severity, title):
	finding = Finding(
		scan_id=scan.id,
		target_id=target.id,
		module="headers",
		severity=severity,
		status="open",
		title=title,
		description=f"{title} description",
		evidence="sanitized evidence",
		remediation=f"{title} remediation",
		affected_url=target.normalized_url,
		owasp_category="A05:2021",
		cwe_id="CWE-693",
		confidence="high",
	)
	db_session.add(finding)
	return finding


def test_report_create_regenerate_detail_critical_and_tenant_isolation(client, db_session):
	owner_headers, owner_email = _register_and_login(client, "report_owner")
	other_headers, other_email = _register_and_login(client, "report_other")
	owner, target, scan = _target_and_scan(db_session, owner_email)
	_, other_target, other_scan = _target_and_scan(db_session, other_email)
	_add_finding(db_session, scan, target, "low", "Low issue")
	critical = _add_finding(db_session, scan, target, "critical", "Critical issue")
	db_session.commit()

	payload = {"scan_id": str(scan.id), "report_format": "json"}
	created = client.post("/api/reports", json=payload, headers=owner_headers)
	assert created.status_code == 201
	report_id = created.json()["id"]
	assert created.json()["summary"]["passed_count"] == 7
	assert created.json()["summary"]["module_summary"]["headers"]["checks_passed"] == 5
	assert created.json()["summary"]["scanner_error_count"] == 1
	assert created.json()["summary"]["counts"]["critical"] == 1
	assert created.json()["summary"]["verdict"] == "critical"
	assert created.json()["summary"]["total_findings_count"] == 2

	scan.module_progress = {
		**scan.module_progress,
		"headers": {**scan.module_progress["headers"], "checks_passed": 6},
	}
	db_session.commit()
	regenerated = client.post("/api/reports", json=payload, headers=owner_headers)
	assert regenerated.status_code == 200
	assert regenerated.json()["id"] == report_id
	assert regenerated.json()["summary"]["passed_count"] == 8

	detail = client.get(f"/api/reports/{report_id}", headers=owner_headers)
	assert detail.status_code == 200
	assert detail.json()["findings"][0]["severity"] == "critical"
	assert detail.json()["findings"][0]["title"] == critical.title
	assert detail.json()["findings"][0]["evidence"] == "sanitized evidence"
	assert detail.json()["findings"][0]["remediation"] == "Critical issue remediation"
	assert detail.json()["findings"][0]["affected_url"] == target.normalized_url
	assert detail.json()["findings"][0]["owasp_category"] == "A05:2021"
	assert detail.json()["findings"][0]["cwe_id"] == "CWE-693"

	assert client.post(
		"/api/reports", json={"scan_id": str(other_scan.id), "report_format": "json"}, headers=owner_headers
	).status_code == 404
	assert client.get(f"/api/reports/{report_id}", headers=other_headers).status_code == 404
	assert client.get("/api/reports", headers=other_headers).json()["total"] == 0
	assert client.get("/api/reports?page=1&page_size=1", headers=owner_headers).json()["total"] == 1
	assert client.post(
		"/api/reports", json={"scan_id": str(scan.id), "report_format": "xml"}, headers=owner_headers
	).status_code == 422


def test_report_requires_completed_scan(client, db_session):
	headers, email = _register_and_login(client, "report_queued")
	_, _, queued_scan = _target_and_scan(db_session, email, scan_status="queued")
	db_session.commit()
	response = client.post(
		"/api/reports",
		json={"scan_id": str(queued_scan.id), "report_format": "pdf"},
		headers=headers,
	)
	assert response.status_code == 409
	assert response.json()["error"]["code"] == "SCAN_NOT_COMPLETED"


def test_profile_update_and_rejects_fields_outside_full_name(client):
	headers, _ = _register_and_login(client, "profile_user")
	updated = client.put(
		"/api/user/profile", json={"full_name": "  Updated Name  "}, headers=headers
	)
	assert updated.status_code == 200
	assert updated.json()["full_name"] == "Updated Name"
	assert "password_hash" not in updated.json()
	assert client.get("/api/user/profile", headers=headers).json()["full_name"] == "Updated Name"
	assert client.put(
		"/api/user/profile", json={"full_name": "Changed", "role": "admin"}, headers=headers
	).status_code == 422
	assert client.put(
		"/api/user/profile", json={"full_name": "   "}, headers=headers
	).status_code == 422
	assert client.put(
		"/api/user/profile", json={"full_name": "x" * 151}, headers=headers
	).status_code == 422


def test_password_change_validation_and_login(client):
	headers, email = _register_and_login(client, "password_user")
	base = {"current_password": PASSWORD, "new_password": "NewStrongPassword456!"}
	assert client.put(
		"/api/user/password",
		json={"current_password": "WrongPassword123!", "new_password": base["new_password"]},
		headers=headers,
	).status_code == 400
	wrong = client.put(
		"/api/user/password",
		json={"current_password": "WrongPassword123!", "new_password": base["new_password"]},
		headers=headers,
	)
	assert wrong.json()["error"]["code"] == "INVALID_CURRENT_PASSWORD"
	assert client.put(
		"/api/user/password", json={"current_password": PASSWORD, "new_password": "weak"}, headers=headers
	).status_code == 422
	long_password = "A" * 60 + "a" * 11 + "1" * 2
	assert len(long_password.encode("utf-8")) == 73
	assert client.put(
		"/api/user/password",
		json={"current_password": PASSWORD, "new_password": long_password},
		headers=headers,
	).status_code == 422
	assert client.put(
		"/api/user/password",
		json={"current_password": PASSWORD, "new_password": PASSWORD},
		headers=headers,
	).status_code == 422
	changed = client.put("/api/user/password", json=base, headers=headers)
	assert changed.status_code == 200
	assert changed.json() == {"message": "Password updated successfully."}
	assert PASSWORD not in changed.text
	assert client.post("/api/auth/login", json={"email": email, "password": PASSWORD}).status_code == 401
	assert client.post(
		"/api/auth/login", json={"email": email, "password": base["new_password"]}
	).status_code == 200
	assert client.get("/api/user/profile", headers=headers).status_code == 200


def test_settings_update_and_validation(client, db_session):
	headers, email = _register_and_login(client, "settings_user")
	settings = client.get("/api/user/settings", headers=headers)
	assert settings.status_code == 200
	assert settings.json() == {
		"default_scan_depth": "standard",
		"notify_scan_completed": True,
		"notify_scan_failed": True,
		"notify_critical_finding": True,
	}
	updated = client.put(
		"/api/user/settings",
		json={
			"default_scan_depth": "deep",
			"notify_scan_completed": False,
			"notify_scan_failed": True,
			"notify_critical_finding": False,
		},
		headers=headers,
	)
	assert updated.status_code == 200
	assert updated.json()["default_scan_depth"] == "deep"
	assert updated.json()["notify_scan_completed"] is False
	assert updated.json()["notify_critical_finding"] is False
	assert client.put(
		"/api/user/settings",
		json={
			"default_scan_depth": "extreme",
			"notify_scan_completed": True,
			"notify_scan_failed": True,
			"notify_critical_finding": True,
		},
		headers=headers,
	).status_code == 422
	assert client.put(
		"/api/user/settings",
		json={
			"default_scan_depth": "quick",
			"notify_scan_completed": True,
			"notify_scan_failed": True,
			"notify_critical_finding": True,
			"email_notifications": True,
		},
		headers=headers,
	).status_code == 422
	user = db_session.query(User).filter(User.email == email).one()
	assert db_session.query(UserSettings).filter(UserSettings.user_id == user.id).one().default_scan_depth == "deep"


def test_settings_are_scoped_to_authenticated_user(client):
	owner_headers, _ = _register_and_login(client, "settings_owner")
	other_headers, _ = _register_and_login(client, "settings_other")
	owner_values = {
		"default_scan_depth": "deep",
		"notify_scan_completed": False,
		"notify_scan_failed": True,
		"notify_critical_finding": False,
	}
	assert client.put("/api/user/settings", json=owner_values, headers=owner_headers).status_code == 200

	other_settings = client.get("/api/user/settings", headers=other_headers)
	assert other_settings.status_code == 200
	assert other_settings.json()["default_scan_depth"] == "standard"
	assert other_settings.json()["notify_scan_completed"] is True
	other_values = {
		"default_scan_depth": "quick",
		"notify_scan_completed": False,
		"notify_scan_failed": False,
		"notify_critical_finding": True,
	}
	assert client.put("/api/user/settings", json=other_values, headers=other_headers).status_code == 200
	assert client.get("/api/user/settings", headers=owner_headers).json() == owner_values


def test_all_step_endpoints_require_authentication(client):
	report_id = uuid.uuid4()
	scan_id = uuid.uuid4()
	requests = [
		("get", "/api/reports", None),
		("get", f"/api/reports/{report_id}", None),
		("post", "/api/reports", {"scan_id": str(scan_id), "report_format": "json"}),
		("get", "/api/user/profile", None),
		("put", "/api/user/profile", {"full_name": "New Name"}),
		("put", "/api/user/password", {"current_password": PASSWORD, "new_password": "NewStrongPassword456!"}),
		("get", "/api/user/settings", None),
		("put", "/api/user/settings", {
			"default_scan_depth": "standard",
			"notify_scan_completed": True,
			"notify_scan_failed": True,
			"notify_critical_finding": True,
		}),
	]
	for method, path, payload in requests:
		kwargs = {"json": payload} if payload is not None else {}
		response = getattr(client, method)(path, **kwargs)
		assert response.status_code == 401
		assert set(response.json()["error"]) == {"code", "message"}