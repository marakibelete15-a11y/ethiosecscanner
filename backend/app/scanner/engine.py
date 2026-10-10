"""Single-worker scan orchestration and persisted progress tracking."""

import datetime
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from typing import Callable

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.settings import settings
from app.models import Finding, Scan
from app.scanner.crawler import PAGE_LIMITS, crawl_target
from app.scanner.http_client import SafeHttpClient
from app.scanner.masking import sanitize_evidence
from app.scanner.modules import cookies, headers, https
from app.scanner.scoring import calculate_security_score

logger = logging.getLogger("ethiosec.scanner")
POLITE_DELAY_SECONDS = 0.25
MODULE_TIMEOUT_SECONDS = float(settings.SCANNER_REQUEST_TIMEOUT_SECONDS)
IMPLEMENTED_MODULES = {
	"headers": headers.run,
	"https": https.run,
	"cookies": cookies.run,
}

_cancel_lock = threading.Lock()
_cancel_flags: dict[uuid.UUID, threading.Event] = {}


class ModuleExecutionTimeout(TimeoutError):
	"""Raised when a scanner module exceeds its execution limit."""


class _PoliteClient:
	def __init__(self, client: SafeHttpClient) -> None:
		self._client = client
		self._last_request = 0.0
		self._lock = threading.Lock()

	def get(self, url: str, **kwargs):
		with self._lock:
			wait_for = POLITE_DELAY_SECONDS - (time.monotonic() - self._last_request)
			if wait_for > 0:
				time.sleep(wait_for)
			self._last_request = time.monotonic()
		return self._client.get(url, **kwargs)


def _cancel_event(scan_id: uuid.UUID) -> threading.Event:
	with _cancel_lock:
		return _cancel_flags.setdefault(scan_id, threading.Event())


def request_scan_cancellation(scan_id: uuid.UUID) -> None:
	"""Set the in-memory cancellation flag for a queued or running scan."""
	_cancel_event(scan_id).set()


def start_scan_in_background(scan_id: uuid.UUID) -> threading.Thread:
	"""Start a single scan worker thread and return it for observability/tests."""
	_cancel_event(scan_id)
	worker = threading.Thread(
		target=run_scan_worker,
		args=(scan_id,),
		name=f"ethiosec-scan-{scan_id}",
		daemon=True,
	)
	worker.start()
	return worker


def _run_module_with_timeout(module, target_url, client, should_cancel):
	executor = ThreadPoolExecutor(max_workers=1)
	future = executor.submit(
		module,
		target_url,
		client,
		pages=[target_url],
		should_cancel=should_cancel,
	)
	try:
		return future.result(timeout=MODULE_TIMEOUT_SECONDS)
	except FutureTimeoutError as exc:
		future.cancel()
		raise ModuleExecutionTimeout("Module timed out.") from exc
	finally:
		executor.shutdown(wait=False, cancel_futures=True)


def _set_module_progress(scan: Scan, module_name: str, value: dict) -> None:
	updated = dict(scan.module_progress or {})
	updated[module_name] = value
	scan.module_progress = updated


def _finalize_scan(db: Session, scan: Scan, event: threading.Event) -> None:
	if event.is_set():
		scan.status = "cancelled"
	elif scan.status != "failed":
		scan.status = "completed"

	severity_counts = {severity: 0 for severity in ("critical", "high", "medium", "low", "info")}
	for finding in db.query(Finding).filter(Finding.scan_id == scan.id).all():
		if finding.severity in severity_counts:
			severity_counts[finding.severity] += 1
	scan.security_score = calculate_security_score(severity_counts)
	scan.finished_at = datetime.datetime.now(datetime.timezone.utc)
	db.commit()


def run_scan_worker(scan_id: uuid.UUID, db: Session | None = None) -> None:
	"""Run selected modules sequentially; a module failure does not stop later modules."""
	owns_session = db is None
	if db is None:
		db = SessionLocal()

	event = _cancel_event(scan_id)
	try:
		scan = db.query(Scan).filter(Scan.id == scan_id).first()
		if scan is None or scan.status not in ("queued", "running"):
			return

		scan.status = "running"
		scan.started_at = datetime.datetime.now(datetime.timezone.utc)
		db.commit()

		client = _PoliteClient(SafeHttpClient())
		if not event.is_set():
			pages = crawl_target(
				scan.target_url,
				PAGE_LIMITS[scan.depth],
				client,
				should_cancel=event.is_set,
			)
		else:
			pages = []

		selected = list(scan.selected_modules or [])
		total_modules = len(selected)
		for module_index, module_name in enumerate(selected):
			if event.is_set():
				break

			scan.current_module = module_name
			_set_module_progress(
				scan,
				module_name,
				{
					"checks_run": 0,
					"checks_passed": 0,
					"findings_count": 0,
					"status": "running",
					"error": None,
				},
			)
			db.commit()

			checks_run = 0
			checks_passed = 0
			module_findings = []
			error = None
			try:
				runner = IMPLEMENTED_MODULES[module_name]
				for page_url in pages:
					if event.is_set():
						break
					result = _run_module_with_timeout(
						runner, page_url, client, event.is_set
					)
					checks_run += int(result.get("checks_run", 0))
					checks_passed += int(result.get("checks_passed", 0))
					module_findings.extend(result.get("findings", []))
			except Exception as exc:
				error = str(exc).strip()[:160] or "Module failed."
				logger.warning("Scan %s module %s failed: %s", scan.id, module_name, error)

			for finding_data in module_findings:
				values = dict(finding_data)
				values.pop("id", None)
				values["scan_id"] = scan.id
				values["target_id"] = scan.target_id
				values["module"] = module_name
				values["evidence"] = sanitize_evidence(values.get("evidence"))
				db.add(Finding(**values))

			_set_module_progress(
				scan,
				module_name,
				{
					"checks_run": checks_run,
					"checks_passed": checks_passed,
					"findings_count": len(module_findings),
					"status": "error" if error else "done",
					"error": error,
				},
			)
			scan.progress = int(((module_index + 1) / total_modules) * 100)
			db.commit()

		_finalize_scan(db, scan, event)
	except Exception as exc:
		db.rollback()
		scan = db.query(Scan).filter(Scan.id == scan_id).first()
		if scan is not None:
			scan.status = "failed"
			scan.error_message = str(exc).strip()[:200] or "Scan failed."
			scan.finished_at = datetime.datetime.now(datetime.timezone.utc)
			db.commit()
		logger.exception("Scan %s failed outside a module", scan_id)
	finally:
		if owns_session:
			db.close()
		with _cancel_lock:
			_cancel_flags.pop(scan_id, None)
