"""Structured report API schemas."""

import datetime
import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator

from app.utils.vocabulary import REPORT_FORMAT_VALUES


class ReportCreateRequest(BaseModel):
	scan_id: uuid.UUID
	report_format: str

	model_config = ConfigDict(extra="forbid")

	@field_validator("report_format")
	@classmethod
	def validate_report_format(cls, value: str) -> str:
		if value not in REPORT_FORMAT_VALUES:
			raise ValueError(f"report_format must be one of: {', '.join(REPORT_FORMAT_VALUES)}")
		return value


class ReportSummary(BaseModel):
	id: uuid.UUID
	scan_id: uuid.UUID
	report_format: str
	created_at: datetime.datetime
	summary: dict[str, Any]

	model_config = ConfigDict(from_attributes=True)


class ReportListResponse(BaseModel):
	total: int
	page: int
	page_size: int
	reports: list[ReportSummary]


class ReportFinding(BaseModel):
	severity: str
	title: str
	description: str
	evidence: str | None
	remediation: str
	affected_url: str
	owasp_category: str | None
	cwe_id: str | None

	model_config = ConfigDict(from_attributes=True)


class ReportDetailResponse(ReportSummary):
	findings: list[ReportFinding]
