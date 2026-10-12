"""Finding update schemas."""

from pydantic import BaseModel, ConfigDict, field_validator

from app.utils.vocabulary import FINDING_STATUS_VALUES


class FindingStatusUpdate(BaseModel):
	status: str

	model_config = ConfigDict(extra="forbid")

	@field_validator("status")
	@classmethod
	def validate_status(cls, value: str) -> str:
		if value not in FINDING_STATUS_VALUES:
			raise ValueError(f"status must be one of: {', '.join(FINDING_STATUS_VALUES)}")
		return value
