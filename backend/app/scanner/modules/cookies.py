"""Inspect Set-Cookie security attributes without retaining cookie values."""

from typing import Any, Callable, Dict, List, Optional

from app.scanner.http_client import SafeHttpClient


COOKIE_CHECKS = (
	(
		"Secure",
		"medium",
		"A05:2021-Security Misconfiguration",
		"CWE-614",
		"Set the Secure attribute so browsers send this cookie only over HTTPS.",
	),
	(
		"HttpOnly",
		"medium",
		"A07:2021-Identification and Authentication Failures",
		"CWE-1004",
		"Set the HttpOnly attribute to prevent scripts from reading this cookie.",
	),
	(
		"SameSite",
		"low",
		"A07:2021-Identification and Authentication Failures",
		"CWE-1275",
		"Set an appropriate SameSite attribute, such as Lax or Strict, to limit cross-site cookie sending.",
	),
)


def run(
	target_url: str,
	client: SafeHttpClient,
	pages: Optional[List[str]] = None,
	should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
	"""Check Secure, HttpOnly, and SameSite for every Set-Cookie header."""
	findings: List[Dict[str, Any]] = []
	checks_run = 0
	checks_passed = 0

	for page_url in pages or [target_url]:
		if should_cancel and should_cancel():
			break

		response = client.get(page_url)
		set_cookie_headers = response.set_cookie_headers or []
		if not set_cookie_headers:
			combined = response.headers.get("set-cookie")
			if combined:
				set_cookie_headers = [combined]

		for cookie_header in set_cookie_headers:
			if should_cancel and should_cancel():
				break

			attributes = {
				part.partition("=")[0].strip().lower()
				for part in cookie_header.split(";")[1:]
				if part.strip()
			}
			for flag_name, severity, category, cwe_id, remediation in COOKIE_CHECKS:
				if should_cancel and should_cancel():
					break
				checks_run += 1
				if flag_name.lower() in attributes:
					checks_passed += 1
					continue
				findings.append(
					{
						"module": "cookies",
						"severity": severity,
						"title": f"Cookie Missing {flag_name} Attribute",
						"description": (
							f"A cookie set by the target does not include the {flag_name} attribute, "
							"which weakens browser-side protections for cookie handling."
						),
						"evidence": f"Set-Cookie response from {page_url}; {flag_name} attribute missing.",
						"remediation": remediation,
						"affected_url": page_url,
						"parameter": None,
						"owasp_category": category,
						"cwe_id": cwe_id,
						"confidence": "certain",
						"http_method": "GET",
					}
				)

	return {
		"checks_run": checks_run,
		"checks_passed": checks_passed,
		"findings": findings,
	}
