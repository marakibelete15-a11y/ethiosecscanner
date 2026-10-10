"""Detect permissive cross-origin response policies with a harmless Origin."""

from typing import Any, Callable, Dict, List, Optional

from app.scanner.http_client import SafeHttpClient

TEST_ORIGIN = "https://ethiosec-invalid-origin.example"


def run(
	target_url: str,
	client: SafeHttpClient,
	pages: Optional[List[str]] = None,
	should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
	"""Check wildcard origins and reflected origins allowed with credentials."""
	findings: List[Dict[str, Any]] = []
	checks_run = 1
	checks_passed = 0
	if should_cancel and should_cancel():
		return {"checks_run": 0, "checks_passed": 0, "findings": findings}

	response = client.get(target_url, headers={"Origin": TEST_ORIGIN})
	allow_origin = response.headers.get("access-control-allow-origin", "").strip()
	allow_credentials = response.headers.get(
		"access-control-allow-credentials", ""
	).strip().lower()

	if allow_origin == "*":
		findings.append(
			{
				"module": "cors",
				"severity": "medium",
				"title": "Wildcard CORS Origin Allowed",
				"description": (
					"The response permits every origin to read cross-origin responses. "
					"Sensitive unauthenticated data may be exposed to arbitrary sites."
				),
				"evidence": "Access-Control-Allow-Origin: *",
				"remediation": "Allow only explicitly trusted origins required by the application.",
				"affected_url": target_url,
				"parameter": None,
				"owasp_category": "A05:2021-Security Misconfiguration",
				"cwe_id": "CWE-942",
				"confidence": "certain",
				"http_method": "GET",
			}
		)
	elif allow_origin == TEST_ORIGIN and allow_credentials == "true":
		findings.append(
			{
				"module": "cors",
				"severity": "high",
				"title": "Arbitrary Origin Reflected with Credentials",
				"description": (
					"The server reflects an arbitrary Origin and allows credentials, which can permit "
					"an attacker-controlled site to read authenticated cross-origin responses."
				),
				"evidence": (
					f"Access-Control-Allow-Origin: {TEST_ORIGIN}\n"
					"Access-Control-Allow-Credentials: true"
				),
				"remediation": "Validate Origin against a strict allowlist and permit credentials only for trusted origins.",
				"affected_url": target_url,
				"parameter": None,
				"owasp_category": "A05:2021-Security Misconfiguration",
				"cwe_id": "CWE-942",
				"confidence": "certain",
				"http_method": "GET",
			}
		)
	else:
		checks_passed = 1

	return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}
