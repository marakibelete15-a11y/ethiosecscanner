"""Tests for scan history, finding triage, and dashboard summary APIs."""

import datetime
import uuid

from app.models import Finding, Report, Scan, Target, User


def _register_and_login(client, prefix):
	email = f"{prefix}_{uuid.uuid4().hex[:8]}@test.local"
	password = "StrongPassword123!"
	assert client.post(
		"/api/auth/register", json={"email": email, "password": password}
	).status_code == 201
	login = client.post("/api/auth/login", json={"email": email, "password": password})
	return {"Authorization": f"Bearer {login.json()['access_token']}"}, email


def _add_target(db_session, email, suffix="one", verified=True):
	user = db_session.query(User).filter(User.email == email).one()
	url = f"https://{suffix}.example.test"
	target = Target(
		user_id=user.id,
		url=url,
		normalized_url=url,
		verification_method="meta_tag",
		verification_token=uuid.uuid4().hex,
		is_verified=verified,
	)
	db_session.add(target)
	db_session.flush()
	return target


def _add_scan(
	db_session,
	user,
	target,
	*,
	status="completed",
	created_at=None,
	finished_at=None,
	score=90,
):
	scan = Scan(
		user_id=user.id,
		target_id=target.id,
		target_url=target.normalized_url,
		depth="standard",
		selected_modules=["headers"],
		module_progress={"headers": {"status": "done", "checks_run": 1}},
		status=status,
		progress=100 if status == "completed" else 0,
		security_score=score,
		created_at=created_at,
		finished_at=finished_at,
	)
	db_session.add(scan)
	db_session.flush()
	return scan


def _add_finding(db_session, scan, target, severity="high", finding_status="open"):
	finding = Finding(
		scan_id=scan.id,
		target_id=target.id,
		module="headers",
		severity=severity,
		status=finding_status,
		title=f"{severity.title()} test issue",
		description="Test finding",
		remediation="Fix the issue",
		affected_url=target.normalized_url,
		confidence="high",
	)
	db_session.add(finding)
	db_session.flush()
	return finding


def test_scan_history_filters_paging_and_tenant_scope(client, db_session):
	owner_headers, owner_email = _register_and_login(client, "history_owner")
	other_headers, other_email = _register_and_login(client, "history_other")
	owner = db_session.query(User).filter(User.email == owner_email).one()
	other = db_session.query(User).filter(User.email == other_email).one()
	target = _add_target(db_session, owner_email, "history")
	other_target = _add_target(db_session, other_email, "other-history")
	base = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
	older = _add_scan(db_session, owner, target, created_at=base, finished_at=base, score=80)
	newer = _add_scan(
		db_session,
		owner,
		target,
		created_at=base + datetime.timedelta(days=1),
		finished_at=base + datetime.timedelta(days=1),
	)
	queued = _add_scan(db_session, owner, target, status="queued", created_at=base + datetime.timedelta(days=2))
	_add_scan(db_session, other, other_target, created_at=base + datetime.timedelta(days=3))
	_add_finding(db_session, older, target, "critical")
	db_session.commit()

	first_page = client.get("/api/scans?page=1&page_size=1", headers=owner_headers)
	assert first_page.status_code == 200
	assert first_page.json()["total"] == 3
	assert first_page.json()["scans"][0]["id"] == str(queued.id)
	assert len(first_page.json()["scans"]) == 1
	second_page = client.get("/api/scans?page=2&page_size=1", headers=owner_headers).json()
	assert second_page["scans"][0]["id"] != first_page.json()["scans"][0]["id"]

	filtered = client.get(
		f"/api/scans?status=completed&target_id={target.id}&page_size=10",
		headers=owner_headers,
	).json()
	assert filtered["total"] == 2
	assert {item["id"] for item in filtered["scans"]} == {str(older.id), str(newer.id)}
	assert filtered["scans"][1]["finding_counts"]["critical"] == 1
	assert client.get("/api/scans", headers=other_headers).json()["total"] == 1
	assert client.get("/api/scans?status=invalid", headers=owner_headers).status_code == 422
	assert client.get("/api/scans?page_size=101", headers=owner_headers).status_code == 422


def test_scan_detail_delete_conflict_tenant_isolation_and_cascades(client, db_session):
	owner_headers, owner_email = _register_and_login(client, "delete_owner")
	other_headers, _ = _register_and_login(client, "delete_other")
	owner = db_session.query(User).filter(User.email == owner_email).one()
	target = _add_target(db_session, owner_email, "delete")
	now = datetime.datetime.now(datetime.timezone.utc)
	queued = _add_scan(db_session, owner, target, status="queued")
	running = _add_scan(db_session, owner, target, status="running")
	finished = _add_scan(
		db_session,
		owner,
		target,
		created_at=now,
		finished_at=now,
	)
	finding = _add_finding(db_session, finished, target)
	report = Report(
		scan_id=finished.id,
		user_id=owner.id,
		report_format="json",
		summary={"status": "completed"},
	)
	db_session.add(report)
	db_session.commit()

	detail = client.get(f"/api/scans/{finished.id}", headers=owner_headers)
	assert detail.status_code == 200
	assert detail.json()["selected_modules"] == ["headers"]
	assert "module_progress" in detail.json()
	assert client.get(f"/api/scans/{finished.id}", headers=other_headers).status_code == 404
	assert client.delete(f"/api/scans/{finished.id}", headers=other_headers).status_code == 404
	for active_scan in (queued, running):
		response = client.delete(f"/api/scans/{active_scan.id}", headers=owner_headers)
		assert response.status_code == 409
		assert response.json()["error"]["message"] == "Cancel the scan before deleting it."
		assert db_session.query(Scan).filter(Scan.id == active_scan.id).one_or_none() is not None

	deleted = client.delete(f"/api/scans/{finished.id}", headers=owner_headers)
	assert deleted.status_code == 200
	assert db_session.query(Scan).filter(Scan.id == finished.id).one_or_none() is None
	assert db_session.query(Finding).filter(Finding.id == finding.id).one_or_none() is None
	assert db_session.query(Report).filter(Report.id == report.id).one_or_none() is None


def test_finding_status_validation_ownership_and_critical_verdict(client, db_session):
	owner_headers, owner_email = _register_and_login(client, "finding_owner")
	other_headers, _ = _register_and_login(client, "finding_other")
	owner = db_session.query(User).filter(User.email == owner_email).one()
	target = _add_target(db_session, owner_email, "finding")
	scan = _add_scan(db_session, owner, target, score=37)
	finding = _add_finding(db_session, scan, target, severity="critical")
	db_session.commit()

	path = f"/api/findings/{finding.id}"
	assert client.patch(path, json={"status": "unknown"}, headers=owner_headers).status_code == 422
	assert client.patch(path, json={"status": "open", "severity": "low"}, headers=owner_headers).status_code == 422
	assert client.patch(path, json={"status": "confirmed"}, headers=other_headers).status_code == 404
	updated = client.patch(path, json={"status": "false_positive"}, headers=owner_headers)
	assert updated.status_code == 200
	assert updated.json()["status"] == "false_positive"
	results = client.get(f"/api/scans/{scan.id}/results", headers=owner_headers).json()
	assert results["counts"]["critical"] == 1
	assert results["score"] == 37
	assert results["verdict"] == "critical"


def test_dashboard_summary_for_users_with_and_without_scans(client, db_session):
	headers, email = _register_and_login(client, "dashboard_user")
	empty_headers, empty_email = _register_and_login(client, "dashboard_empty")
	user = db_session.query(User).filter(User.email == email).one()
	target_one = _add_target(db_session, email, "dashboard-one", verified=True)
	target_two = _add_target(db_session, email, "dashboard-two", verified=False)
	base = datetime.datetime(2025, 3, 1, tzinfo=datetime.timezone.utc)
	old_scan = _add_scan(
		db_session,
		user,
		target_one,
		created_at=base,
		finished_at=base,
		score=20,
	)
	latest_one = _add_scan(
		db_session,
		user,
		target_one,
		created_at=base + datetime.timedelta(days=2),
		finished_at=base + datetime.timedelta(days=2),
		score=88,
	)
	latest_two = _add_scan(
		db_session,
		user,
		target_two,
		created_at=base + datetime.timedelta(days=1),
		finished_at=base + datetime.timedelta(days=1),
		score=65,
	)
	_add_scan(db_session, user, target_two, status="queued", created_at=base + datetime.timedelta(days=3))
	_add_finding(db_session, old_scan, target_one, "critical")
	_add_finding(db_session, latest_one, target_one, "high")
	_add_finding(db_session, latest_one, target_one, "critical", finding_status="resolved")
	_add_finding(db_session, latest_two, target_two, "medium")
	_add_finding(db_session, latest_two, target_two, "low", finding_status="false_positive")
	db_session.commit()

	response = client.get("/api/dashboard/summary", headers=headers)
	assert response.status_code == 200
	data = response.json()
	assert data["total_targets"] == 2
	assert data["verified_targets"] == 1
	assert data["total_scans"] == 4
	assert data["completed_scans"] == 3
	assert data["latest_security_score"] == 88
	assert data["severity_distribution"] == {
		"critical": 0,
		"high": 1,
		"medium": 1,
		"low": 0,
		"info": 0,
	}
	assert len(data["recent_scans"]) == 4

	empty_response = client.get("/api/dashboard/summary", headers=empty_headers)
	assert empty_response.status_code == 200
	assert empty_response.json()["total_targets"] == 0
	assert empty_response.json()["total_scans"] == 0
	assert empty_response.json()["completed_scans"] == 0
	assert empty_response.json()["recent_scans"] == []
	assert empty_response.json()["latest_security_score"] is None
	assert empty_response.json()["severity_distribution"] == {
		"critical": 0,
		"high": 0,
		"medium": 0,
		"low": 0,
		"info": 0,
	}


def test_step_endpoints_require_authentication(client):
	unauthorized_calls = (
		("get", "/api/scans"),
		("get", f"/api/scans/{uuid.uuid4()}"),
		("delete", f"/api/scans/{uuid.uuid4()}"),
		("patch", f"/api/findings/{uuid.uuid4()}"),
		("get", "/api/dashboard/summary"),
	)
	for method, path in unauthorized_calls:
		kwargs = {"json": {"status": "open"}} if method == "patch" else {}
		response = getattr(client, method)(path, **kwargs)
		assert response.status_code == 401
		assert set(response.json()["error"]) == {"code", "message"}