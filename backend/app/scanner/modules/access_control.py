"""Find unauthenticated access to common protected application paths."""

from typing import Any, Callable, Optional
from urllib.parse import urljoin

from app.scanner.http_client import SafeHttpClient

PROTECTED_PATHS = (
	"/admin",
	"/dashboard",
	"/account",
	"/profile",
	"/settings",
	"/api/users",
	"/api/admin",
	"/manage",
	"/console",
	"/safe-admin",
	"/billing",
	"/users",
	"/private",
	"/reports",
	"/staff",
)


def _normalized_body(body: str) -> str:
	return " ".join(body.lower().split())


def _is_login_page(body: str) -> bool:
	lowered = body.lower()
	return "type=\"password\"" in lowered or "type='password'" in lowered or (
		"password" in lowered and any(word in lowered for word in ("login", "sign in", "log in"))
	)


def _is_soft_404(body: str, soft_404_body: str) -> bool:
	if _normalized_body(body) == _normalized_body(soft_404_body):
		return True
	lowered = body.lower()
	return any(marker in lowered for marker in ("page not found", "404 not found", "no such page"))


def run(
	target_url: str,
	client: SafeHttpClient,
	pages: Optional[list[str]] = None,
	should_cancel: Optional[Callable[[], bool]] = None,
	**_kwargs,
) -> dict[str, Any]:
	"""Check 15 common paths without credentials or state-changing requests."""
	findings: list[dict[str, Any]] = []
	checks_run = 0
	checks_passed = 0
	soft_404_url = urljoin(target_url.rstrip("/") + "/", "__ethiosec_access_control_missing__")
	soft_404_response = client.get(soft_404_url, follow_redirects=False)
	soft_404_body = soft_404_response.text[:4000]

	for path in PROTECTED_PATHS:
		if should_cancel and should_cancel():
			break
		checks_run += 1
		url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
		response = client.get(url, follow_redirects=False)
		if (
			response.status_code != 200
			or _is_login_page(response.text)
			or _is_soft_404(response.text[:4000], soft_404_body)
		):
			checks_passed += 1
			continue

		findings.append(
			{
				"module": "access_control",
				"severity": "high",
				"title": f"Unauthenticated Access to Protected Path: {path}",
				"description": "A common protected path returned HTTP 200 content to an unauthenticated request.",
				"evidence": f"Unauthenticated GET {url} returned HTTP 200: {response.text[:300]}",
				"remediation": "Require authentication and authorization before returning protected content.",
				"affected_url": url,
				"parameter": None,
				"owasp_category": "A01:2021-Broken Access Control",
				"cwe_id": "CWE-284",
				"confidence": "high",
				"http_method": "GET",
			}
		)

	return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}
