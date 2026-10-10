"""Authenticated scan creation, progress, cancellation, and results routes."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.settings import settings
from app.models import Finding, Scan, Target, User
from app.scanner.engine import (
	IMPLEMENTED_MODULES,
	request_scan_cancellation,
	start_scan_in_background,
)
from app.scanner.safety import InvalidURLError, SSRFError, validate_target_url
from app.schemas.scan import (
	ScanCancelResponse,
	ScanCreateRequest,
	ScanCreateResponse,
	ScanResultsResponse,
	ScanStatusResponse,
)
from app.utils.vocabulary import SCANNER_MODULE_KEYS

router = APIRouter(prefix="/api/scans", tags=["Scans"])


def _get_user_scan(scan_id: uuid.UUID, user_id: uuid.UUID, db: Session) -> Scan:
	scan = (
		db.query(Scan)
		.filter(Scan.id == scan_id, Scan.user_id == user_id)
		.first()
	)
	if scan is None:
		raise HTTPException(
			status_code=status.HTTP_404_NOT_FOUND,
			detail={"code": "SCAN_NOT_FOUND", "message": "Scan not found."},
		)
	return scan


@router.post("", response_model=ScanCreateResponse, status_code=status.HTTP_201_CREATED)
def create_scan(
	payload: ScanCreateRequest,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	target = (
		db.query(Target)
		.filter(Target.id == payload.target_id, Target.user_id == current_user.id)
		.first()
	)
	if target is None:
		raise HTTPException(
			status_code=status.HTTP_404_NOT_FOUND,
			detail={"code": "TARGET_NOT_FOUND", "message": "Target not found."},
		)
	if not target.is_verified:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail={
				"code": "TARGET_NOT_VERIFIED",
				"message": "Verify ownership of this target before starting a scan.",
			},
		)

	try:
		safe_target_url = validate_target_url(
			target.normalized_url,
			allow_local=settings.ALLOW_LOCAL_TARGETS,
			fail_on_unresolvable=True,
		)
	except SSRFError as exc:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail={"code": "SSRF_ERROR", "message": str(exc)},
		) from exc
	except InvalidURLError as exc:
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail={"code": "INVALID_URL", "message": str(exc)},
		) from exc

	if payload.modules is None:
		selected_modules = list(IMPLEMENTED_MODULES)
	else:
		unknown_modules = sorted(set(payload.modules) - set(SCANNER_MODULE_KEYS))
		if unknown_modules:
			raise HTTPException(
				status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
				detail={
					"code": "UNKNOWN_MODULE",
					"message": f"Unknown scanner module(s): {', '.join(unknown_modules)}.",
				},
			)
		unbuilt_modules = sorted(set(payload.modules) - set(IMPLEMENTED_MODULES))
		if unbuilt_modules:
			raise HTTPException(
				status_code=status.HTTP_400_BAD_REQUEST,
				detail={
					"code": "MODULE_NOT_IMPLEMENTED",
					"message": f"Scanner module(s) not implemented yet: {', '.join(unbuilt_modules)}.",
				},
			)
		if not payload.modules:
			raise HTTPException(
				status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
				detail={"code": "MODULES_REQUIRED", "message": "Select at least one scanner module."},
			)
		selected_modules = list(dict.fromkeys(payload.modules))

	default_depth = (
		current_user.settings.default_scan_depth
		if current_user.settings is not None
		else "standard"
	)
	depth = payload.depth or default_depth
	module_progress = {
		module_name: {
			"checks_run": 0,
			"checks_passed": 0,
			"findings_count": 0,
			"status": "pending",
			"error": None,
		}
		for module_name in selected_modules
	}
	scan = Scan(
		user_id=current_user.id,
		target_id=target.id,
		target_url=safe_target_url,
		depth=depth,
		selected_modules=selected_modules,
		module_progress=module_progress,
		status="queued",
		progress=0,
	)
	db.add(scan)
	db.commit()
	db.refresh(scan)
	response = ScanCreateResponse(
		id=scan.id,
		status=scan.status,
		progress=scan.progress,
		depth=scan.depth,
		selected_modules=list(scan.selected_modules),
	)
	start_scan_in_background(scan.id)
	return response


@router.get("/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(
	scan_id: uuid.UUID,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	return _get_user_scan(scan_id, current_user.id, db)


@router.get("/{scan_id}/results", response_model=ScanResultsResponse)
def get_scan_results(
	scan_id: uuid.UUID,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	scan = _get_user_scan(scan_id, current_user.id, db)
	findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
	severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	findings.sort(key=lambda item: (severity_order.get(item.severity, 5), item.created_at, item.title))

	counts = {severity: 0 for severity in severity_order}
	for finding in findings:
		if finding.severity in counts:
			counts[finding.severity] += 1
	progress = scan.module_progress or {}
	passed_count = sum(int(item.get("checks_passed", 0)) for item in progress.values())
	scanner_error_count = sum(item.get("status") == "error" for item in progress.values())

	from app.scanner.scoring import calculate_verdict

	return {
		"id": scan.id,
		"status": scan.status,
		"score": scan.security_score,
		"verdict": calculate_verdict(counts, scanner_error_count),
		"counts": counts,
		"passed_count": passed_count,
		"scanner_error_count": scanner_error_count,
		"findings": findings,
	}


@router.post("/{scan_id}/cancel", response_model=ScanCancelResponse)
def cancel_scan(
	scan_id: uuid.UUID,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	scan = _get_user_scan(scan_id, current_user.id, db)
	if scan.status not in ("queued", "running"):
		raise HTTPException(
			status_code=status.HTTP_409_CONFLICT,
			detail={"code": "SCAN_NOT_ACTIVE", "message": "Only queued or running scans can be cancelled."},
		)

	request_scan_cancellation(scan.id)
	return ScanCancelResponse(
		id=scan.id,
		status=scan.status,
		message="Cancellation requested.",
	)
