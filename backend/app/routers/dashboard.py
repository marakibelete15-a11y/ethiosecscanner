"""Authenticated user dashboard summary."""

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import Finding, Scan, Target, User
from app.routers.scans import _finding_counts_by_scan, _scan_summary
from app.schemas.dashboard import DashboardSummary
from app.utils.vocabulary import SEVERITY_VALUES

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	total_targets = db.query(func.count(Target.id)).filter(Target.user_id == current_user.id).scalar() or 0
	verified_targets = (
		db.query(func.count(Target.id))
		.filter(Target.user_id == current_user.id, Target.is_verified.is_(True))
		.scalar()
		or 0
	)
	total_scans = db.query(func.count(Scan.id)).filter(Scan.user_id == current_user.id).scalar() or 0
	completed_scans = (
		db.query(func.count(Scan.id))
		.filter(Scan.user_id == current_user.id, Scan.status == "completed")
		.scalar()
		or 0
	)
	recent = (
		db.query(Scan)
		.filter(Scan.user_id == current_user.id)
		.order_by(Scan.created_at.desc(), Scan.id.desc())
		.limit(5)
		.all()
	)
	recent_counts = _finding_counts_by_scan([scan.id for scan in recent], db)
	completed = (
		db.query(Scan)
		.filter(Scan.user_id == current_user.id, Scan.status == "completed")
		.order_by(Scan.finished_at.desc().nullslast(), Scan.created_at.desc(), Scan.id.desc())
		.all()
	)
	latest_by_target = {}
	for scan in completed:
		latest_by_target.setdefault(scan.target_id, scan)
	latest_target_scan_ids = [scan.id for scan in latest_by_target.values()]
	severity_distribution = {severity: 0 for severity in SEVERITY_VALUES}
	if latest_target_scan_ids:
		rows = (
			db.query(Finding.severity, func.count(Finding.id))
			.filter(
				Finding.scan_id.in_(latest_target_scan_ids),
				Finding.status.in_(("open", "confirmed")),
			)
			.group_by(Finding.severity)
			.all()
		)
		for severity, count in rows:
			if severity in severity_distribution:
				severity_distribution[severity] = count
	latest_score = completed[0].security_score if completed else None
	return DashboardSummary(
		total_targets=total_targets,
		verified_targets=verified_targets,
		total_scans=total_scans,
		completed_scans=completed_scans,
		recent_scans=[_scan_summary(scan, recent_counts[scan.id]) for scan in recent],
		latest_security_score=latest_score,
		severity_distribution=severity_distribution,
	)
