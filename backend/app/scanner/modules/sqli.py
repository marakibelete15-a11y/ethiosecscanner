"""Low-impact GET-only SQL injection indicators; no extraction or time probes."""

import re
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import parse_qsl, urlsplit

from app.scanner.crawler import CrawlResult
from app.scanner.http_client import SafeHttpClient
from app.scanner.modules.probe_inputs import get_parameter_targets, replace_parameter

DATABASE_ERRORS = re.compile(
	r"sql syntax|mysql_fetch|mysql server version|postgresql.*error|pg_query\(|"
	r"sqlite(?:3)?\.OperationalError|sqlite error|unclosed quotation mark|"
	r"microsoft ole db provider for sql server|ora-\d{4,5}|odbc sql server",
	re.IGNORECASE,
)
PROBE_LIMITS = {"standard": 2, "deep": 5}


def _finding(url: str, parameter: str, evidence: str) -> Dict[str, Any]:
	return {
		"module": "sqli",
		"severity": "high",
		"title": "Potential SQL Injection Error Disclosure",
		"description": "A harmless GET parameter variation caused a recognizable database error response.",
		"evidence": evidence,
		"remediation": "Use parameterized queries and return generic errors that do not expose database details.",
		"affected_url": url,
		"parameter": parameter,
		"owasp_category": "A03:2021-Injection",
		"cwe_id": "CWE-89",
		"confidence": "high",
		"http_method": "GET",
	}


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
	max_rounds = PROBE_LIMITS.get(depth, PROBE_LIMITS["standard"])
	findings: List[Dict[str, Any]] = []
	checks_run = 0
	checks_passed = 0
	for url, parameter in parameters:
		if should_cancel and should_cancel():
			break
		baseline = client.get(url, follow_redirects=False)
		baseline_body = baseline.text[:12000]
		original_values = parse_qsl(urlsplit(url).query, keep_blank_values=True)
		current_value = next((value for name, value in original_values if name == parameter), "")
		probe_values = [current_value + "'", current_value + "' OR '1'='1", current_value + "' OR '1'='2"]
		probe_rounds = [(probe_values[0],), (probe_values[1], probe_values[2])]
		for round_index, values in enumerate(probe_rounds[:max_rounds]):
			if should_cancel and should_cancel():
				break
			checks_run += 1
			responses = [
				client.get(
					replace_parameter(url, parameter, value),
					follow_redirects=False,
				)
				for value in values
			]
			bodies = [response.text[:12000] for response in responses]
			matched = None
			if not DATABASE_ERRORS.search(baseline_body):
				matched = next(
					(DATABASE_ERRORS.search(body) for body in bodies if DATABASE_ERRORS.search(body)),
					None,
				)
			if matched:
				findings.append(
					_finding(
						url,
						parameter,
						f"GET parameter {parameter}; database error signature detected in response: {matched.group(0)[:120]}",
					)
				)
				break
			if round_index == 1 and len(bodies) == 2 and bodies[0] != bodies[1]:
				if len(bodies[0]) > len(baseline_body) * 3 or len(bodies[1]) > len(baseline_body) * 3:
					checks_passed += 1
					continue
			checks_passed += 1
	return {
		"checks_run": checks_run,
		"checks_passed": checks_passed,
		"findings": findings,
		"notes": post_notes,
	}
