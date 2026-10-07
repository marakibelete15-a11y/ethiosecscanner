"""
Database Integrity and Constraint Verification Tests.

Verifies:
1. Connection to test database
2. Existence of all 6 tables
3. CHECK constraint enforcement (invalid severity, progress > 100)
4. UNIQUE constraint enforcement (duplicate target for same user)
5. Foreign key ON DELETE CASCADE behavior
6. Single-transaction creation of User + UserSettings
"""

import datetime
import uuid
import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import IntegrityError

from app.models import Finding, Report, Scan, Target, User, UserSettings


def test_connection_works(test_engine):
    """Verify that test engine connects cleanly to ethiosec_test_db."""
    with test_engine.connect() as conn:
        db_name = conn.execute(text("SELECT current_database();")).scalar()
        assert db_name == "ethiosec_test_db"


def test_all_six_tables_exist(test_engine):
    """Verify that all six core domain tables exist in the schema."""
    inspector = inspect(test_engine)
    existing_tables = set(inspector.get_table_names())
    required_tables = {"users", "user_settings", "targets", "scans", "findings", "reports"}
    assert required_tables.issubset(existing_tables), f"Missing tables: {required_tables - existing_tables}"


def test_user_and_settings_single_transaction(db_session):
    """Verify that User and UserSettings can be created atomically in one transaction."""
    user = User(
        email=f"tester_{uuid.uuid4().hex[:6]}@ethiosec.local",
        password_hash="$2b$12$e8wF1234567890abcdef...",
        full_name="Transaction Test User",
        role="user",
    )
    db_session.add(user)
    db_session.flush()

    settings = UserSettings(
        user_id=user.id,
        default_scan_depth="deep",
        notify_scan_completed=True,
        notify_scan_failed=False,
        notify_critical_finding=True,
    )
    db_session.add(settings)
    db_session.commit()

    reloaded_user = db_session.query(User).filter(User.id == user.id).first()
    assert reloaded_user is not None
    assert reloaded_user.settings is not None
    assert reloaded_user.settings.default_scan_depth == "deep"


def test_constraints_reject_invalid_severity(db_session):
    """Verify that CHECK constraint chk_findings_severity rejects invalid severity strings."""
    user = User(
        email=f"tester_{uuid.uuid4().hex[:6]}@ethiosec.local",
        password_hash="hashed_pw",
    )
    db_session.add(user)
    db_session.flush()

    target = Target(
        user_id=user.id,
        url="http://test.local",
        normalized_url="http://test.local",
        verification_token="token123",
        is_verified=True,
    )
    db_session.add(target)
    db_session.flush()

    scan = Scan(
        user_id=user.id,
        target_id=target.id,
        target_url=target.url,
        depth="standard",
    )
    db_session.add(scan)
    db_session.flush()

    bad_finding = Finding(
        scan_id=scan.id,
        target_id=target.id,
        module="sqli",
        severity="catastrophic",  # Invalid severity value
        status="open",
        title="Invalid Finding",
        description="Test",
        remediation="Fix it",
        affected_url="http://test.local/vuln",
    )
    db_session.add(bad_finding)

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_constraints_reject_invalid_progress(db_session):
    """Verify that CHECK constraint chk_scans_progress rejects progress values over 100."""
    user = User(
        email=f"tester_{uuid.uuid4().hex[:6]}@ethiosec.local",
        password_hash="hashed_pw",
    )
    db_session.add(user)
    db_session.flush()

    target = Target(
        user_id=user.id,
        url="http://test.local",
        normalized_url="http://test.local",
        verification_token="token123",
        is_verified=True,
    )
    db_session.add(target)
    db_session.flush()

    bad_scan = Scan(
        user_id=user.id,
        target_id=target.id,
        target_url=target.url,
        depth="standard",
        progress=101,  # Invalid progress > 100
    )
    db_session.add(bad_scan)

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_constraints_reject_duplicate_target_same_user(db_session):
    """Verify that UNIQUE constraint uq_targets_user_normalized_url prevents duplicate targets for same user."""
    user = User(
        email=f"tester_{uuid.uuid4().hex[:6]}@ethiosec.local",
        password_hash="hashed_pw",
    )
    db_session.add(user)
    db_session.flush()

    target1 = Target(
        user_id=user.id,
        url="https://example.com/path",
        normalized_url="https://example.com",
        verification_token="token1",
    )
    db_session.add(target1)
    db_session.commit()

    target2 = Target(
        user_id=user.id,
        url="https://example.com/other",
        normalized_url="https://example.com",  # Duplicate normalized URL for same user
        verification_token="token2",
    )
    db_session.add(target2)

    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_cascade_delete(db_session):
    """Verify that deleting a target cascades down to scans, findings, and reports."""
    user = User(
        email=f"tester_{uuid.uuid4().hex[:6]}@ethiosec.local",
        password_hash="hashed_pw",
    )
    db_session.add(user)
    db_session.flush()

    target = Target(
        user_id=user.id,
        url="https://target-cascade.local",
        normalized_url="https://target-cascade.local",
        verification_token="token_cascade",
        is_verified=True,
    )
    db_session.add(target)
    db_session.flush()

    scan = Scan(
        user_id=user.id,
        target_id=target.id,
        target_url=target.url,
        depth="standard",
    )
    db_session.add(scan)
    db_session.flush()

    finding = Finding(
        scan_id=scan.id,
        target_id=target.id,
        module="sqli",
        severity="critical",
        status="open",
        title="Cascade Finding",
        description="Test",
        remediation="Fix",
        affected_url="https://target-cascade.local/1",
    )
    db_session.add(finding)

    report = Report(
        scan_id=scan.id,
        user_id=user.id,
        report_format="pdf",
        summary={"test": True},
    )
    db_session.add(report)
    db_session.commit()

    scan_id = scan.id
    finding_id = finding.id
    report_id = report.id

    # Delete the target
    db_session.delete(target)
    db_session.commit()

    # Verify that associated scan, finding, and report were cascade-deleted
    assert db_session.query(Scan).filter(Scan.id == scan_id).first() is None
    assert db_session.query(Finding).filter(Finding.id == finding_id).first() is None
    assert db_session.query(Report).filter(Report.id == report_id).first() is None
