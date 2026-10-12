"""Authenticated finding triage routes."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.models import Finding, Scan, User
from app.schemas.scan import FindingResult
from app.schemas.finding import FindingStatusUpdate

router = APIRouter(prefix="/api/findings", tags=["Findings"])


@router.patch("/{finding_id}", response_model=FindingResult)
def update_finding_status(
	finding_id: uuid.UUID,
	payload: FindingStatusUpdate,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	finding = (
		db.query(Finding)
		.join(Scan, Finding.scan_id == Scan.id)
		.filter(Finding.id == finding_id, Scan.user_id == current_user.id)
		.first()
	)
	if finding is None:
		raise HTTPException(
			status_code=status.HTTP_404_NOT_FOUND,
			detail={"code": "FINDING_NOT_FOUND", "message": "Finding not found."},
		)
	finding.status = payload.status
	db.commit()
	db.refresh(finding)
	return finding
