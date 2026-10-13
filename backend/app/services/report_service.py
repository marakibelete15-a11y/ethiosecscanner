"""Build structured on-demand report summaries from completed scans."""

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.models import Finding, Scan
from app.scanner.scoring import calculate_verdict
from app.utils.vocabulary import SEVERITY_VALUES


def build_report_summary(scan: Scan, db: Session) -> dict:
	findings = db.query(Finding).filter(Finding.scan_id == scan.id).all()
	counts = {severity: 0 for severity in SEVERITY_VALUES}
	for finding in findings:
		if finding.severity in counts:
			counts[finding.severity] += 1
	progress = scan.module_progress or {}
	passed_count = sum(int(module.get("checks_passed", 0)) for module in progress.values())
	scanner_error_count = sum(module.get("status") == "error" for module in progress.values())
	module_summary = {
		name: {
			"status": module.get("status"),
			"checks_run": int(module.get("checks_run", 0)),
			"checks_passed": int(module.get("checks_passed", 0)),
			"findings_count": int(module.get("findings_count", 0)),
		}
		for name, module in progress.items()
	}
	return {
		"target_url": scan.target_url,
		"scan_dates": {
			"started_at": scan.started_at.isoformat() if scan.started_at else None,
			"finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
		},
		"depth": scan.depth,
		"security_score": scan.security_score,
		"verdict": calculate_verdict(counts, scanner_error_count),
		"counts": counts,
		"passed_count": passed_count,
		"scanner_error_count": scanner_error_count,
		"module_summary": module_summary,
		"total_findings_count": len(findings),
		"generated_at": datetime.now(timezone.utc).isoformat(),
	}
