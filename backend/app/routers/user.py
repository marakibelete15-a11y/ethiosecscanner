"""Authenticated user profile, password, and settings routes."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.dependencies import get_current_user
from app.core.security import hash_password, verify_password
from app.models import User, UserSettings
from app.schemas.user import (
	PasswordUpdate,
	UserProfileResponse,
	UserProfileUpdate,
	UserSettingsResponse,
	UserSettingsUpdate,
)

router = APIRouter(prefix="/api/user", tags=["User"])


def _get_settings(db: Session, user: User) -> UserSettings:
	settings = db.query(UserSettings).filter(UserSettings.user_id == user.id).first()
	if settings is None:
		settings = UserSettings(user_id=user.id)
		db.add(settings)
		db.flush()
	return settings


@router.get("/profile", response_model=UserProfileResponse)
def get_profile(current_user: User = Depends(get_current_user)):
	return current_user


@router.put("/profile", response_model=UserProfileResponse)
def update_profile(
	payload: UserProfileUpdate,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	current_user.full_name = payload.full_name
	db.commit()
	db.refresh(current_user)
	return current_user


@router.put("/password", status_code=status.HTTP_200_OK)
def update_password(
	payload: PasswordUpdate,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	if not verify_password(payload.current_password, current_user.password_hash):
		raise HTTPException(
			status_code=status.HTTP_400_BAD_REQUEST,
			detail={
				"code": "INVALID_CURRENT_PASSWORD",
				"message": "The current password is incorrect.",
			},
		)
	current_user.password_hash = hash_password(payload.new_password)
	db.commit()
	return {"message": "Password updated successfully."}


@router.get("/settings", response_model=UserSettingsResponse)
def get_user_settings(
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	return _get_settings(db, current_user)


@router.put("/settings", response_model=UserSettingsResponse)
def update_user_settings(
	payload: UserSettingsUpdate,
	db: Session = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	user_settings = _get_settings(db, current_user)
	for field, value in payload.model_dump().items():
		setattr(user_settings, field, value)
	db.commit()
	db.refresh(user_settings)
	return user_settings
