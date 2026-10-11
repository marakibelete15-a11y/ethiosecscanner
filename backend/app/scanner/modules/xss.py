"""Check GET parameters for a harmless unencoded reflected marker."""

import secrets
from typing import Any, Callable, Dict, List, Optional

from app.scanner.crawler import CrawlResult
from app.scanner.http_client import SafeHttpClient
from app.scanner.modules.probe_inputs import get_parameter_targets, replace_parameter


def run(
	target_url: str,
	client: SafeHttpClient,
	pages: Optional[List[str]] = None,
	should_cancel: Optional[Callable[[], bool]] = None,
	crawl_result: Optional[CrawlResult] = None,
	depth: str = "standard",
	**_kwargs,
) -> Dict[str, Any]:
	if depth == "quick":
		return {"checks_run": 0, "checks_passed": 0, "findings": [], "notes": []}
	crawl_result = crawl_result or CrawlResult(pages=pages or [target_url])
	parameters, post_notes = get_parameter_targets(crawl_result)
	findings: List[Dict[str, Any]] = []
	checks_run = 0
	checks_passed = 0
	for url, parameter in parameters:
		if should_cancel and should_cancel():
			break
		marker = f"ETHIOSEC{secrets.token_hex(6)}'\"<>"
		response = client.get(
			replace_parameter(url, parameter, marker),
			follow_redirects=False,
		)
		checks_run += 1
		if "html" in response.headers.get("content-type", "").lower() and marker in response.text:
			findings.append(
				{
					"module": "xss",
					"severity": "high",
					"title": "Unencoded Reflected Input in HTML",
					"description": "A harmless marker containing HTML-significant characters was reflected unencoded in an HTML response.",
					"evidence": f"GET parameter {parameter}; unique marker was returned unencoded in HTML.",
					"remediation": "Contextually encode untrusted data before inserting it into HTML and use a restrictive Content Security Policy as defense in depth.",
					"affected_url": url,
					"parameter": parameter,
					"owasp_category": "A03:2021-Injection",
					"cwe_id": "CWE-79",
					"confidence": "high",
					"http_method": "GET",
				}
			)
		else:
			checks_passed += 1
	return {
		"checks_run": checks_run,
		"checks_passed": checks_passed,
		"findings": findings,
		"notes": post_notes,
	}
