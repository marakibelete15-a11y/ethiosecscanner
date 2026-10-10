"""Safely inspect advertised and accepted HTTP methods without mutating data."""

from typing import Any, Callable, Dict, List, Optional

from app.scanner.http_client import SafeHttpClient


def run(
	target_url: str,
	client: SafeHttpClient,
	pages: Optional[List[str]] = None,
	should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
	"""Issue OPTIONS and TRACE only; never send PUT or DELETE probes."""
	findings: List[Dict[str, Any]] = []
	checks_run = 0
	checks_passed = 0

	if should_cancel and should_cancel():
		return {"checks_run": 0, "checks_passed": 0, "findings": findings}

	options_response = client.request("OPTIONS", target_url)
	checks_run += 1
	allow = options_response.headers.get("allow", "")
	risky_methods = [
		method
		for method in (item.strip().upper() for item in allow.split(","))
		if method in {"PUT", "DELETE", "TRACE"}
	]
	if risky_methods:
		findings.append(
			{
				"module": "http_methods",
				"severity": "medium",
				"title": "Risky HTTP Methods Advertised",
				"description": (
					"The Allow header advertises methods that can enable unintended state changes "
					"or expose request contents. The scanner did not invoke PUT or DELETE."
				),
				"evidence": f"Allow: {allow}",
				"remediation": "Disable unneeded methods and restrict state-changing methods to authorized application workflows.",
				"affected_url": target_url,
				"parameter": None,
				"owasp_category": "A05:2021-Security Misconfiguration",
				"cwe_id": "CWE-749",
				"confidence": "high",
				"http_method": "OPTIONS",
			}
		)
	else:
		checks_passed += 1

	if should_cancel and should_cancel():
		return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}

	trace_response = client.request("TRACE", target_url)
	checks_run += 1
	if 200 <= trace_response.status_code < 300:
		findings.append(
			{
				"module": "http_methods",
				"severity": "medium",
				"title": "HTTP TRACE Method Is Accepted",
				"description": (
					"The server accepts TRACE requests, which may echo request data and can increase "
					"exposure in legacy client configurations."
				),
				"evidence": f"TRACE request returned HTTP {trace_response.status_code}.",
				"remediation": "Disable TRACE at the web server or reverse proxy unless a documented need exists.",
				"affected_url": target_url,
				"parameter": None,
				"owasp_category": "A05:2021-Security Misconfiguration",
				"cwe_id": "CWE-693",
				"confidence": "certain",
				"http_method": "TRACE",
			}
		)
	else:
		checks_passed += 1

	return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}
