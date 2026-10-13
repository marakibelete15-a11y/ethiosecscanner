"""Profile, password, and notification settings schemas."""

import uuid

from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from app.core.security import validate_password_complexity
from app.utils.vocabulary import SCAN_DEPTH_VALUES


class UserProfileResponse(BaseModel):
	id: uuid.UUID
	email: str
	full_name: str | None
	role: str
	is_active: bool

	model_config = ConfigDict(from_attributes=True)


class UserProfileUpdate(BaseModel):
	full_name: str

	model_config = ConfigDict(extra="forbid")

	@field_validator("full_name")
	@classmethod
	def validate_full_name(cls, value: str) -> str:
		value = value.strip()
		if not value:
			raise ValueError("full_name cannot be empty.")
		if len(value) > 150:
			raise ValueError("full_name cannot exceed 150 characters.")
		return value


class PasswordUpdate(BaseModel):
	current_password: str
	new_password: str

	model_config = ConfigDict(extra="forbid")

	@field_validator("new_password")
	@classmethod
	def validate_new_password(cls, value: str) -> str:
		validate_password_complexity(value)
		return value

	@model_validator(mode="after")
	def validate_password_changed(self):
		if self.current_password == self.new_password:
			raise ValueError("new_password must differ from current_password.")
		return self


class UserSettingsResponse(BaseModel):
	default_scan_depth: str
	notify_scan_completed: bool
	notify_scan_failed: bool
	notify_critical_finding: bool

	model_config = ConfigDict(from_attributes=True)


class UserSettingsUpdate(BaseModel):
	default_scan_depth: str
	notify_scan_completed: bool
	notify_scan_failed: bool
	notify_critical_finding: bool

	model_config = ConfigDict(extra="forbid")

	@field_validator("default_scan_depth")
	@classmethod
	def validate_default_scan_depth(cls, value: str) -> str:
		if value not in SCAN_DEPTH_VALUES:
			raise ValueError(f"default_scan_depth must be one of: {', '.join(SCAN_DEPTH_VALUES)}")
		return value
