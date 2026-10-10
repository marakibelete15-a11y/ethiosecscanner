"""Scan API, worker, and single-module integration tests."""

import uuid

from app.models import Finding, Scan, Target, User
from app.scanner.http_client import SafeResponse


def _register_and_login(client, prefix="scan_user"):
	email = f"{prefix}_{uuid.uuid4().hex[:8]}@test.local"
	password = "StrongPassword123!"
	assert client.post(
		"/api/auth/register", json={"email": email, "password": password}
	).status_code == 201
	login = client.post(
		"/api/auth/login", json={"email": email, "password": password}
	)
	return {"Authorization": f"Bearer {login.json()['access_token']}"}, email


def _add_verified_target(db_session, email, url="http://demo-target.test"):
	user = db_session.query(User).filter(User.email == email).one()
	target = Target(
		user_id=user.id,
		url=url,
		normalized_url=url,
		verification_method="meta_tag",
		verification_token=uuid.uuid4().hex,
		is_verified=True,
	)
	db_session.add(target)
	db_session.commit()
	return target


def _mock_response(url="http://demo-target.test", set_cookie_headers=None):
	return SafeResponse(
		status_code=200,
		headers={"content-type": "text/html"},
		content=b"<html><body>Demo target</body></html>",
		url=url,
		final_url=url,
		elapsed_seconds=0.01,
		set_cookie_headers=set_cookie_headers or [],
	)


def _start_worker_in_request_session(monkeypatch, db_session):
	def run_synchronously(scan_id):
		from app.scanner.engine import run_scan_worker

		run_scan_worker(scan_id, db=db_session)

	monkeypatch.setattr("app.routers.scans.start_scan_in_background", run_synchronously)


def test_scan_demo_target_finds_missing_security_headers(client, db_session, monkeypatch):
	headers, email = _register_and_login(client)
	target = _add_verified_target(db_session, email)
	monkeypatch.setattr("app.routers.scans.validate_target_url", lambda url, **kwargs: url)

	class FakeSafeHttpClient:
		def get(self, url, **kwargs):
			return _mock_response(url)

	monkeypatch.setattr("app.scanner.engine.SafeHttpClient", FakeSafeHttpClient)
	_start_worker_in_request_session(monkeypatch, db_session)

	created = client.post(
		"/api/scans", json={"target_id": str(target.id)}, headers=headers
	)
	assert created.status_code == 201
	scan_id = created.json()["id"]

	status = client.get(f"/api/scans/{scan_id}/status", headers=headers).json()
	assert status["status"] == "completed"
	assert status["progress"] == 100
	assert status["module_progress"]["headers"]["status"] == "done"
	assert status["module_progress"]["headers"]["checks_run"] == 6

	results_response = client.get(f"/api/scans/{scan_id}/results", headers=headers)
	assert results_response.status_code == 200
	results = results_response.json()
	assert results["verdict"] == "medium"
	assert results["counts"]["medium"] >= 1
	assert results["counts"]["low"] >= 1
	assert all(item["scan_id"] == scan_id for item in results["findings"])
	assert all(item["target_id"] == str(target.id) for item in results["findings"])


def test_failing_module_is_isolated_and_reported(client, db_session, monkeypatch):
	headers, email = _register_and_login(client, "module_error")
	target = _add_verified_target(db_session, email)
	monkeypatch.setattr("app.routers.scans.validate_target_url", lambda url, **kwargs: url)
	monkeypatch.setattr(
		"app.scanner.engine.SafeHttpClient",
		lambda: type("Client", (), {"get": lambda self, url, **kwargs: _mock_response(url)})(),
	)

	from app.scanner import engine

	original_modules = dict(engine.IMPLEMENTED_MODULES)
	engine.IMPLEMENTED_MODULES["https"] = lambda *args, **kwargs: (_ for _ in ()).throw(
		RuntimeError("isolated module failure")
	)
	try:
		_start_worker_in_request_session(monkeypatch, db_session)
		response = client.post(
			"/api/scans",
			json={"target_id": str(target.id), "modules": ["https", "cookies"]},
			headers=headers,
		)
		assert response.status_code == 201
		progress = client.get(
			f"/api/scans/{response.json()['id']}/status", headers=headers
		).json()
		assert progress["status"] == "completed"
		assert progress["module_progress"]["https"]["status"] == "error"
		assert "isolated module failure" in progress["module_progress"]["https"]["error"]
		assert progress["module_progress"]["cookies"]["status"] == "done"
	finally:
		engine.IMPLEMENTED_MODULES.clear()
		engine.IMPLEMENTED_MODULES.update(original_modules)


def test_unverified_target_is_refused_with_specific_error(client, db_session):
	headers, email = _register_and_login(client, "unverified")
	target = _add_verified_target(db_session, email)
	target.is_verified = False
	db_session.commit()

	response = client.post(
		"/api/scans", json={"target_id": str(target.id)}, headers=headers
	)
	assert response.status_code == 400
	assert response.json()["error"]["code"] == "TARGET_NOT_VERIFIED"


def test_another_users_scan_is_hidden_with_404(client, db_session, monkeypatch):
	owner_headers, owner_email = _register_and_login(client, "scan_owner")
	other_headers, _ = _register_and_login(client, "scan_other")
	target = _add_verified_target(db_session, owner_email)
	monkeypatch.setattr("app.routers.scans.validate_target_url", lambda url, **kwargs: url)
	monkeypatch.setattr(
		"app.scanner.engine.SafeHttpClient",
		lambda: type("Client", (), {"get": lambda self, url, **kwargs: _mock_response(url)})(),
	)
	_start_worker_in_request_session(monkeypatch, db_session)

	created = client.post(
		"/api/scans", json={"target_id": str(target.id)}, headers=owner_headers
	)
	assert created.status_code == 201
	response = client.get(
		f"/api/scans/{created.json()['id']}/status", headers=other_headers
	)
	assert response.status_code == 404
	assert response.json()["error"]["code"] == "SCAN_NOT_FOUND"


def test_cancel_sets_flag_and_worker_finishes_cancelled(client, db_session, monkeypatch):
	headers, email = _register_and_login(client, "cancel_scan")
	target = _add_verified_target(db_session, email)
	monkeypatch.setattr("app.routers.scans.validate_target_url", lambda url, **kwargs: url)
	monkeypatch.setattr("app.routers.scans.start_scan_in_background", lambda scan_id: None)
	created = client.post(
		"/api/scans", json={"target_id": str(target.id)}, headers=headers
	)
	scan_id = uuid.UUID(created.json()["id"])

	initial_status = client.get(
		f"/api/scans/{scan_id}/status", headers=headers
	).json()
	assert initial_status["status"] == "queued"
	assert initial_status["progress"] == 0
	assert initial_status["module_progress"]["headers"]["status"] == "pending"

	cancelled = client.post(f"/api/scans/{scan_id}/cancel", headers=headers)
	assert cancelled.status_code == 200
	assert cancelled.json()["message"] == "Cancellation requested."

	from app.scanner.engine import run_scan_worker

	run_scan_worker(scan_id, db=db_session)
	assert db_session.query(Scan).filter(Scan.id == scan_id).one().status == "cancelled"


def test_scan_creation_rejects_known_unbuilt_module(client, db_session, monkeypatch):
	headers, email = _register_and_login(client, "unbuilt_module")
	target = _add_verified_target(db_session, email)
	monkeypatch.setattr("app.routers.scans.validate_target_url", lambda url, **kwargs: url)

	response = client.post(
		"/api/scans",
		json={"target_id": str(target.id), "modules": ["xss"]},
		headers=headers,
	)
	assert response.status_code == 400
	assert response.json()["error"]["code"] == "MODULE_NOT_IMPLEMENTED"

	unknown = client.post(
		"/api/scans",
		json={"target_id": str(target.id), "modules": ["not_a_module"]},
		headers=headers,
	)
	assert unknown.status_code == 422
	assert unknown.json()["error"]["code"] == "UNKNOWN_MODULE"


def test_results_sort_critical_first_and_never_call_critical_safe(client, db_session):
	headers, email = _register_and_login(client, "critical_verdict")
	target = _add_verified_target(db_session, email)
	user = db_session.query(User).filter(User.email == email).one()
	scan = Scan(
		user_id=user.id,
		target_id=target.id,
		target_url=target.normalized_url,
		depth="quick",
		selected_modules=["headers"],
		module_progress={
			"headers": {
				"checks_run": 2,
				"checks_passed": 0,
				"findings_count": 2,
				"status": "error",
				"error": "short failure",
			}
		},
		status="completed",
		progress=100,
		security_score=74,
	)
	db_session.add(scan)
	db_session.flush()
	for severity, title in (("low", "Low issue"), ("critical", "Critical issue")):
		db_session.add(
			Finding(
				scan_id=scan.id,
				target_id=target.id,
				module="headers",
				severity=severity,
				status="open",
				title=title,
				description="Test finding",
				evidence="masked before persistence",
				remediation="Fix the issue",
				affected_url=target.normalized_url,
				confidence="high",
				http_method="GET",
			)
		)
	db_session.commit()

	response = client.get(f"/api/scans/{scan.id}/results", headers=headers)
	assert response.status_code == 200
	results = response.json()
	assert results["verdict"] == "critical"
	assert results["scanner_error_count"] == 1
	assert [finding["severity"] for finding in results["findings"]] == ["critical", "low"]


def test_https_module_reports_plain_http_demo(client, db_session, demo_target_url, monkeypatch):
	headers, email = _register_and_login(client, "https_demo")
	target = _add_verified_target(db_session, email, demo_target_url)
	_start_worker_in_request_session(monkeypatch, db_session)

	created = client.post(
		"/api/scans",
		json={"target_id": str(target.id), "modules": ["https"]},
		headers=headers,
	)
	assert created.status_code == 201
	results = client.get(
		f"/api/scans/{created.json()['id']}/results", headers=headers
	).json()
	assert results["verdict"] == "high"
	assert any("HTTPS Is Not Available" == item["title"] for item in results["findings"])


def test_cookies_module_reports_flags_without_storing_cookie_value(
	client, db_session, demo_target_url, monkeypatch
):
	headers, email = _register_and_login(client, "cookie_demo")
	target = _add_verified_target(db_session, email, demo_target_url)
	_start_worker_in_request_session(monkeypatch, db_session)

	created = client.post(
		"/api/scans",
		json={"target_id": str(target.id), "modules": ["cookies"]},
		headers=headers,
	)
	assert created.status_code == 201
	findings = client.get(
		f"/api/scans/{created.json()['id']}/results", headers=headers
	).json()["findings"]
	assert len(findings) == 3
	assert {item["title"] for item in findings} == {
		"Cookie Missing Secure Attribute",
		"Cookie Missing HttpOnly Attribute",
		"Cookie Missing SameSite Attribute",
	}
	assert all("demo-cookie-value" not in (item["evidence"] or "") for item in findings)


def test_default_three_module_scan_counts_and_score(
	client, db_session, demo_target_url, monkeypatch
):
	headers, email = _register_and_login(client, "three_modules")
	target = _add_verified_target(db_session, email, demo_target_url)
	_start_worker_in_request_session(monkeypatch, db_session)

	created = client.post(
		"/api/scans", json={"target_id": str(target.id)}, headers=headers
	)
	assert created.status_code == 201
	assert created.json()["selected_modules"] == ["headers", "https", "cookies"]
	status = client.get(
		f"/api/scans/{created.json()['id']}/status", headers=headers
	).json()
	assert status["status"] == "completed"
	assert status["progress"] == 100
	assert status["module_progress"]["headers"]["checks_run"] == 6
	assert status["module_progress"]["https"]["checks_run"] == 4
	assert status["module_progress"]["cookies"]["checks_run"] == 3
	assert [status["module_progress"][name]["findings_count"] for name in ("headers", "https", "cookies")] == [5, 2, 3]

	results = client.get(
		f"/api/scans/{created.json()['id']}/results", headers=headers
	).json()
	assert results["counts"] == {
		"critical": 0,
		"high": 1,
		"medium": 5,
		"low": 4,
		"info": 0,
	}
	assert results["score"] == 66
