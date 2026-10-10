"""Check common version headers and verbose error responses."""

from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

from app.scanner.http_client import SafeHttpClient

VERSION_HEADERS = ("server", "x-powered-by", "x-aspnet-version")
ERROR_MARKERS = (
	"traceback (most recent call last)",
	"stack trace:",
	"exception details:",
	"werkzeug debugger",
	"django debug",
	"internal server error: ",
)


def _make_finding(target_url: str, title: str, description: str, evidence: str, cwe_id: str):
	return {
		"module": "info_disclosure",
		"severity": "low",
		"title": title,
		"description": description,
		"evidence": evidence,
		"remediation": "Remove version banners and return generic error pages without stack traces or implementation details.",
		"affected_url": target_url,
		"parameter": None,
		"owasp_category": "A05:2021-Security Misconfiguration",
		"cwe_id": cwe_id,
		"confidence": "high",
		"http_method": "GET",
	}


def _verbose_error(text: str) -> bool:
	lowered = text.lower()
	return any(marker in lowered for marker in ERROR_MARKERS)


def run(
	target_url: str,
	client: SafeHttpClient,
	pages: Optional[List[str]] = None,
	should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
	"""Inspect version headers, a missing page, and a malformed encoded path."""
	findings: List[Dict[str, Any]] = []
	checks_run = 0
	checks_passed = 0

	response = client.get(target_url)
	for header_name in VERSION_HEADERS:
		if should_cancel and should_cancel():
			break
		checks_run += 1
		value = response.headers.get(header_name)
		if value:
			pretty_name = "-".join(part.capitalize() for part in header_name.split("-"))
			findings.append(
				_make_finding(
					target_url,
					f"{pretty_name} Version Disclosure",
					f"The response exposes implementation or version information in {pretty_name}.",
					f"{pretty_name}: {value}",
					"CWE-200",
				)
			)
		else:
			checks_passed += 1

	probe_urls = (
		("Nonexistent Page", urljoin(target_url.rstrip("/") + "/", "__ethiosec_missing_probe__")),
		("Malformed URL", urljoin(target_url.rstrip("/") + "/", "%ZZ")),
		("Error Route", urljoin(target_url.rstrip("/") + "/", "error")),
	)
	for label, probe_url in probe_urls:
		if should_cancel and should_cancel():
			break
		checks_run += 1
		probe_response = client.get(probe_url)
		body = probe_response.text[:4000]
		if _verbose_error(body):
			findings.append(
				_make_finding(
					target_url,
					f"Verbose Error Disclosure: {label}",
					"An error response appears to expose stack-trace or framework debugging details.",
					f"{label} response returned HTTP {probe_response.status_code}: {body[:1200]}",
					"CWE-209",
				)
			)
		else:
			checks_passed += 1

	return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}
