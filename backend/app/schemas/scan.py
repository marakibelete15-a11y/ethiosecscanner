"""Scan creation, telemetry, and result schemas."""

import datetime
import uuid
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, field_validator

from app.utils.vocabulary import SCAN_DEPTH_VALUES


class ScanCreateRequest(BaseModel):
	target_id: uuid.UUID
	depth: Optional[str] = None
	modules: Optional[List[str]] = None

	@field_validator("depth")
	@classmethod
	def validate_depth(cls, value: Optional[str]) -> Optional[str]:
		if value is not None and value not in SCAN_DEPTH_VALUES:
			raise ValueError(f"depth must be one of: {', '.join(SCAN_DEPTH_VALUES)}")
		return value


class ScanCreateResponse(BaseModel):
	id: uuid.UUID
	status: str
	progress: int
	depth: str
	selected_modules: List[str]


class ScanStatusResponse(BaseModel):
	id: uuid.UUID
	status: str
	progress: int
	current_module: Optional[str]
	module_progress: Dict[str, Dict[str, Any]]
	error_message: Optional[str]
	created_at: datetime.datetime
	started_at: Optional[datetime.datetime]
	finished_at: Optional[datetime.datetime]

	model_config = ConfigDict(from_attributes=True)


class FindingResult(BaseModel):
	id: uuid.UUID
	scan_id: uuid.UUID
	target_id: uuid.UUID
	module: str
	severity: str
	status: str
	title: str
	description: str
	evidence: Optional[str]
	remediation: str
	affected_url: str
	parameter: Optional[str]
	owasp_category: Optional[str]
	cwe_id: Optional[str]
	confidence: str
	http_method: Optional[str]
	created_at: datetime.datetime

	model_config = ConfigDict(from_attributes=True)


class ScanResultsResponse(BaseModel):
	id: uuid.UUID
	status: str
	score: Optional[int]
	verdict: str
	counts: Dict[str, int]
	passed_count: int
	scanner_error_count: int
	findings: List[FindingResult]


class ScanCancelResponse(BaseModel):
	id: uuid.UUID
	status: str
	message: str
