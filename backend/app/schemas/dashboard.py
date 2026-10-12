"""Dashboard summary schemas."""

from typing import Dict, List, Optional

from pydantic import BaseModel

from app.schemas.scan import ScanSummary


class DashboardSummary(BaseModel):
	total_targets: int
	verified_targets: int
	total_scans: int
	completed_scans: int
	recent_scans: List[ScanSummary]
	latest_security_score: Optional[int]
	severity_distribution: Dict[str, int]
