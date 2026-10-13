"""Authenticated report generation and retrieval routes."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import Finding, Report, Scan, User
from app.schemas.report import (
	ReportCreateRequest,
	ReportDetailResponse,
	ReportListResponse,
	ReportSummary,
)
from app.services.report_service import build_report_summary
from app.utils.vocabulary import SEVERITY_VALUES

router = APIRouter(prefix="/api/reports", tags=["Reports"])


def _get_user_report(report_id: uuid.UUID, user_id: uuid.UUID, db: Session) -> Report:
	report = (
		db.query(Report)
		.filter(Report.id == report_id, Report.user_id == user_id)
		.first()
	)
	if report is None:
		raise HTTPException(
			status_code=status.HTTP_404_NOT_FOUND,
			detail={"code": "REPORT_NOT_FOUND", "message": "Report not found."},
		)
	return report


@router.post("", response_model=ReportSummary, status_code=status.HTTP_201_CREATED)
def create_report(
	payload: ReportCreateRequest,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	scan = (
		db.query(Scan)
		.filter(Scan.id == payload.scan_id, Scan.user_id == current_user.id)
		.first()
	)
	if scan is None:
		raise HTTPException(
			status_code=status.HTTP_404_NOT_FOUND,
			detail={"code": "SCAN_NOT_FOUND", "message": "Scan not found."},
		)
	if scan.status != "completed":
		raise HTTPException(
			status_code=status.HTTP_409_CONFLICT,
			detail={
				"code": "SCAN_NOT_COMPLETED",
				"message": "A report can only be generated for a completed scan.",
			},
		)
	report = (
		db.query(Report)
		.filter(
			Report.scan_id == scan.id,
			Report.user_id == current_user.id,
			Report.report_format == payload.report_format,
		)
		.first()
	)
	created = report is None
	if created:
		report = Report(
			scan_id=scan.id,
			user_id=current_user.id,
			report_format=payload.report_format,
			summary=build_report_summary(scan, db),
		)
		db.add(report)
	else:
		report.summary = build_report_summary(scan, db)
	db.commit()
	db.refresh(report)
	if not created:
		from fastapi.responses import JSONResponse
		return JSONResponse(status_code=status.HTTP_200_OK, content=ReportSummary.model_validate(report).model_dump(mode="json"))
	return report


@router.get("", response_model=ReportListResponse)
def list_reports(
	page: int = Query(default=1, ge=1),
	page_size: int = Query(default=20, ge=1, le=100),
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	query = db.query(Report).filter(Report.user_id == current_user.id)
	total = query.count()
	reports = (
		query.order_by(Report.created_at.desc(), Report.id.desc())
		.offset((page - 1) * page_size)
		.limit(page_size)
		.all()
	)
	return ReportListResponse(total=total, page=page, page_size=page_size, reports=reports)


@router.get("/{report_id}", response_model=ReportDetailResponse)
def get_report(
	report_id: uuid.UUID,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	report = _get_user_report(report_id, current_user.id, db)
	findings = (
		db.query(Finding)
		.filter(Finding.scan_id == report.scan_id)
		.all()
	)
	severity_order = {severity: index for index, severity in enumerate(SEVERITY_VALUES)}
	findings.sort(key=lambda finding: (severity_order.get(finding.severity, len(severity_order)), finding.created_at, finding.title))
	return ReportDetailResponse(
		id=report.id,
		scan_id=report.scan_id,
		report_format=report.report_format,
		created_at=report.created_at,
		summary=report.summary,
		findings=findings,
	)
