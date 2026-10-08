"""
Targets Router (SRS Section 4.2, TGT-1 to TGT-8, SEC-4, SEC-6).

Provides:
- GET /api/targets: List current user's registered targets
- POST /api/targets: Register a new target URL (with SSRF check and duplicate prevention)
- GET /api/targets/{id}: Retrieve target details and verification instructions (tenant-isolated)
- DELETE /api/targets/{id}: Delete target with cascade (tenant-isolated)
- POST /api/targets/{id}/verify: Trigger real ownership check (tenant-isolated)
"""

import datetime
import secrets
from typing import List
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.settings import settings
from app.models.target import Target
from app.models.user import User
from app.scanner.safety import InvalidURLError, SSRFError, normalize_url, validate_target_url
from app.schemas.target import (
    TargetCreateRequest,
    TargetDeleteResponse,
    TargetResponse,
    TargetVerifyResponse,
    VerificationInstructions,
)
from app.services.verification_service import (
    get_verification_instructions,
    verify_target_ownership,
)

router = APIRouter(prefix="/api/targets", tags=["Targets"])


def _build_target_response(target: Target) -> TargetResponse:
    """Helper to assemble a TargetResponse including publication instructions."""
    instr_data = get_verification_instructions(
        url=target.normalized_url,
        token=target.verification_token,
        method=target.verification_method,
    )
    instructions = VerificationInstructions(**instr_data)

    return TargetResponse(
        id=target.id,
        url=target.url,
        normalized_url=target.normalized_url,
        verification_method=target.verification_method,
        verification_token=target.verification_token,
        is_verified=target.is_verified,
        verified_at=target.verified_at,
        last_checked_at=target.last_checked_at,
        created_at=target.created_at,
        updated_at=target.updated_at,
        instructions=instructions,
    )


@router.get("", response_model=List[TargetResponse])
def list_targets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all registered targets for the current signed-in user (TGT-7)."""
    targets = (
        db.query(Target)
        .filter(Target.user_id == current_user.id)
        .order_by(Target.created_at.desc())
        .all()
    )
    return [_build_target_response(t) for t in targets]


@router.post("", response_model=TargetResponse, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Register a new target URL for scanning.
    Normalizes URL, checks SSRF boundaries, and prevents duplicates for the same user (TGT-1 to TGT-4).
    """
    # 1. Normalize URL and check scheme
    try:
        normalized_url = normalize_url(payload.url)
    except InvalidURLError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_URL", "message": str(err)},
        )

    # 2. Validate URL safety against SSRF blocklist
    try:
        validate_target_url(
            normalized_url,
            allow_local=settings.ALLOW_LOCAL_TARGETS,
            fail_on_unresolvable=False,
        )
    except SSRFError as ssrf_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "SSRF_ERROR", "message": str(ssrf_err)},
        )
    except InvalidURLError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_URL", "message": str(err)},
        )

    # 3. Check duplicate for this specific user (TGT-3)
    existing = (
        db.query(Target)
        .filter(
            Target.user_id == current_user.id,
            Target.normalized_url == normalized_url,
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "TARGET_ALREADY_EXISTS",
                "message": "You have already registered this target URL.",
            },
        )

    # 4. Generate random verification token (32 hex characters / 16 bytes)
    verification_token = secrets.token_hex(16)
    verification_method = payload.verification_method or "meta_tag"

    target = Target(
        user_id=current_user.id,
        url=payload.url.strip(),
        normalized_url=normalized_url,
        verification_method=verification_method,
        verification_token=verification_token,
        is_verified=False,
    )
    db.add(target)
    db.commit()
    db.refresh(target)

    return _build_target_response(target)


@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve target details and verification instructions.
    Returns 404 if the target does not belong to the user (tenant isolation, TGT-7).
    """
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "TARGET_NOT_FOUND", "message": "Target not found."},
        )
    return _build_target_response(target)


@router.delete("/{target_id}", response_model=TargetDeleteResponse)
def delete_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a target URL and cascade-delete its scans, findings, and reports (TGT-8).
    Returns 404 if the target does not belong to the user (tenant isolation, TGT-7).
    """
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "TARGET_NOT_FOUND", "message": "Target not found."},
        )

    db.delete(target)
    db.commit()

    return TargetDeleteResponse(
        message="Target and all associated data deleted successfully.",
        target_id=target_id,
    )


@router.post("/{target_id}/verify", response_model=TargetVerifyResponse)
def verify_target(
    target_id: uuid.UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Execute real ownership verification check against the target.
    Updates is_verified, verified_at, and last_checked_at (TGT-6).
    Returns 404 if the target does not belong to the user (tenant isolation, TGT-7).
    """
    target = (
        db.query(Target)
        .filter(Target.id == target_id, Target.user_id == current_user.id)
        .first()
    )
    if not target:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "TARGET_NOT_FOUND", "message": "Target not found."},
        )

    # Perform real ownership verification
    is_verified, reason = verify_target_ownership(
        target,
        allow_local=settings.ALLOW_LOCAL_TARGETS,
    )

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    target.last_checked_at = now_utc

    if is_verified:
        target.is_verified = True
        target.verified_at = now_utc
        message = "Ownership verified successfully."
    else:
        message = "Ownership verification failed."

    db.commit()
    db.refresh(target)

    return TargetVerifyResponse(
        id=target.id,
        url=target.url,
        normalized_url=target.normalized_url,
        verification_method=target.verification_method,
        verification_token=target.verification_token,
        is_verified=target.is_verified,
        verified_at=target.verified_at,
        last_checked_at=target.last_checked_at,
        message=message,
        details=reason,
    )

