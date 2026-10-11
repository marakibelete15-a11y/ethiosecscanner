"""Check a bounded list of common sensitive paths for real exposed content."""

from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin

from app.scanner.http_client import SafeHttpClient
from app.scanner.masking import sanitize_evidence

SENSITIVE_PATHS = (
	".env",
	".git/HEAD",
	".git/config",
	".svn/entries",
	".DS_Store",
	"backup.zip",
	"backup.sql",
	"db.sql",
	"database.sql",
	"config.php.bak",
	"phpinfo.php",
	"admin/",
	"wp-config.php.bak",
	"server-status",
	"debug/",
	"dump.sql",
	"site.tar.gz",
	"backup.tar",
	"config.yml.bak",
	"web.config.bak",
	"id_rsa",
	".htpasswd",
	"logs/",
	"error.log",
	"credentials.txt",
	".well-known/security.txt",
)


def _looks_real(path: str, body: str) -> bool:
	text = body.lstrip()
	lower_path = path.lower()
	if lower_path.startswith(".well-known/"):
		return False
	if lower_path.endswith(".env"):
		return any("=" in line and line.split("=", 1)[0].strip().replace("_", "").isalnum() for line in text.splitlines())
	if lower_path.endswith(".git/head"):
		return text.startswith("ref: ")
	if lower_path.endswith(".git/config"):
		return "[core]" in text or "[remote \"" in text
	if lower_path.endswith(".svn/entries"):
		return text.startswith("10\n") or "dir" in text[:300].lower()
	if lower_path.endswith(".ds_store"):
		return len(body) >= 8 and "page not found" not in body.lower()
	if lower_path.endswith((".zip", ".gz", ".tar", ".sql", ".rsa", ".log")):
		return len(body) >= 24 and "page not found" not in body.lower()
	if "phpinfo" in lower_path:
		return "php version" in body.lower() or "phpinfo()" in body.lower()
	if "server-status" in lower_path:
		return "server uptime" in body.lower() or "server version" in body.lower()
	if lower_path.endswith(".htpasswd") or "credentials" in lower_path or "id_rsa" in lower_path:
		return len(text) >= 16 and "page not found" not in body.lower()
	if lower_path.endswith("/") or "debug" in lower_path:
		return any(marker in body.lower() for marker in ("directory listing", "index of /", "debug toolbar"))
	return len(body) >= 32 and "page not found" not in body.lower()


def run(
	target_url: str,
	client: SafeHttpClient,
	pages: Optional[List[str]] = None,
	should_cancel: Optional[Callable[[], bool]] = None,
	depth: str = "standard",
	**_kwargs,
) -> Dict[str, Any]:
	findings: List[Dict[str, Any]] = []
	checks_run = 0
	checks_passed = 0
	for path in SENSITIVE_PATHS:
		if should_cancel and should_cancel():
			break
		if depth == "quick" and path not in {".well-known/", ".well-known/security.txt"}:
			continue
		url = urljoin(target_url.rstrip("/") + "/", path)
		checks_run += 1
		response = client.get(url, follow_redirects=False)
		body = response.text
		if response.status_code != 200 or not _looks_real(path, body):
			checks_passed += 1
			continue
		if path in {".env", ".git/HEAD", ".git/config", ".svn/entries"}:
			severity = "critical" if path in {".env", ".git/HEAD"} else "high"
		elif path in {"backup.zip", "backup.sql", "db.sql", "database.sql", "dump.sql", "id_rsa", "credentials.txt"}:
			severity = "high"
		else:
			severity = "medium"
		sample = sanitize_evidence(body, max_length=60) or ""
		findings.append(
			{
				"module": "exposed_files",
				"severity": severity,
				"title": f"Sensitive File or Endpoint Exposed: /{path}",
				"description": "A sensitive file or operational endpoint is publicly accessible and returned content matching the expected file type.",
				"evidence": sanitize_evidence(f"Path: /{path}\nHTTP status: {response.status_code}\nMasked sample: {sample}", max_length=500),
				"remediation": "Remove sensitive files from the web root or restrict access to operational endpoints.",
				"affected_url": url,
				"parameter": None,
				"owasp_category": "A05:2021-Security Misconfiguration",
				"cwe_id": "CWE-538",
				"confidence": "high",
				"http_method": "GET",
			}
		)
	return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}
