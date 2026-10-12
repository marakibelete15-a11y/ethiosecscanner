"""Bounded unauthenticated checks for password-bearing login forms."""

import secrets
from typing import Any, Callable, Optional

from app.scanner.http_client import SafeHttpClient

MAX_LOGIN_ATTEMPTS_PER_FORM = 6  # Hard cap includes enumeration and rate-limit probes.
MAX_PASSWORD_FORMS_PER_SCAN = 2  # Bound login-form submissions for each scan.
RATE_LIMIT_DELAY_SECONDS = 1.0
SYNTHETIC_KNOWN_EMAIL = "ethiosec-demo-account@example.invalid"
SYNTHETIC_PASSWORD_PREFIX = "EthioSec-NotARealPassword-"

UNKNOWN_ACCOUNT_MARKERS = (
	"no such user",
	"unknown email",
	"email not found",
	"account not found",
	"user does not exist",
)
WRONG_PASSWORD_MARKERS = ("wrong password", "incorrect password", "invalid password")


def _field_names(form) -> tuple[str, str]:
	names = form.input_names
	password_name = next(
		(name for name in names if form.input_types.get(name) == "password"),
		next((name for name in names if "pass" in name.lower()), "password"),
	)
	email_name = next(
		(name for name in names if "email" in name.lower() or "mail" in name.lower()),
		next(
			(name for name in names if any(token in name.lower() for token in ("user", "login"))),
			next((name for name in names if name != password_name), "username"),
		),
	)
	return email_name, password_name


def _is_login_form(form) -> bool:
	if form.method not in {"GET", "POST"}:
		return False
	route = f"{form.page_url} {form.action_url}".lower()
	if any(marker in route for marker in ("signup", "sign-up", "register", "registration")):
		return False
	return any(
		any(token in name.lower() for token in ("email", "mail", "user", "login"))
		for name in form.input_names
	) or any(marker in route for marker in ("login", "signin", "sign-in", "auth"))


def _response_kind(response) -> tuple[str, str]:
	body = " ".join(response.text.lower().split())
	if response.status_code in (301, 302, 303, 307, 308):
		return "redirect", response.headers.get("location", "").lower()
	if any(marker in body for marker in UNKNOWN_ACCOUNT_MARKERS):
		return "unknown_account", body
	if any(marker in body for marker in WRONG_PASSWORD_MARKERS):
		return "wrong_password", body
	return "generic", body


def _submit(client, form, fields: dict[str, str]):
	if form.method == "GET":
		return client.request("GET", form.action_url, params=fields, follow_redirects=False)
	return client.request(
		form.method,
		form.action_url,
		data=fields,
		follow_redirects=False,
	)


def _finding(title, description, evidence, remediation, url, severity, confidence, cwe_id):
	return {
		"module": "auth_checks",
		"severity": severity,
		"title": title,
		"description": description,
		"evidence": evidence,
		"remediation": remediation,
		"affected_url": url,
		"parameter": None,
		"owasp_category": "A07:2021-Identification and Authentication Failures",
		"cwe_id": cwe_id,
		"confidence": confidence,
		"http_method": "POST",
	}


def run(
	target_url: str,
	client: SafeHttpClient,
	crawl_result=None,
	should_cancel: Optional[Callable[[], bool]] = None,
	**_kwargs,
) -> dict[str, Any]:
	"""Inspect at most two password forms using only synthetic credentials."""
	findings = []
	checks_run = 0
	checks_passed = 0
	forms = [
		form
		for form in getattr(crawl_result, "forms", [])
		if any(value == "password" for value in form.input_types.values())
		and _is_login_form(form)
	]
	for form in forms[:MAX_PASSWORD_FORMS_PER_SCAN]:
		if should_cancel and should_cancel():
			break
		checks_run += 1
		if form.page_url.lower().startswith("http://"):
			findings.append(
				_finding(
					"Login Form Served over Plain HTTP",
					"A password form is available over unencrypted HTTP, exposing credentials in transit.",
					f"Password form found at {form.page_url}.",
					"Serve login pages and submissions only over HTTPS and redirect HTTP to HTTPS.",
					form.page_url,
					"medium",
					"certain",
					"CWE-319",
				)
			)
		else:
			checks_passed += 1

		email_name, password_name = _field_names(form)
		password = f"{SYNTHETIC_PASSWORD_PREFIX}{secrets.token_hex(6)}"
		unknown_email = f"ethiosec-no-such-user-{secrets.token_hex(6)}@invalid.example"
		attempts = 0
		blocked_or_delayed = False
		responses = []
		checks_run += 1
		for email in (unknown_email, SYNTHETIC_KNOWN_EMAIL):
			if should_cancel and should_cancel():
				break
			response = _submit(
				client,
				form,
				{email_name: email, password_name: password},
			)
			attempts += 1
			responses.append(response)
			if response.status_code == 429 or response.elapsed_seconds >= RATE_LIMIT_DELAY_SECONDS:
				blocked_or_delayed = True
				break

		if len(responses) == 2:
			first_kind = _response_kind(responses[0])[0]
			second_kind = _response_kind(responses[1])[0]
			if {first_kind, second_kind} == {"unknown_account", "wrong_password"}:
				findings.append(
					_finding(
						"Login Form Reveals Account Existence",
					"Responses distinguish an unknown account from a wrong password.",
					f"Synthetic account responses differed: {first_kind} vs {second_kind}.",
					"Return the same status and generic error message for all authentication failures.",
					form.page_url,
					"medium",
					"high",
					"CWE-204",
				)
				)
			else:
				checks_passed += 1

		checks_run += 1
		while attempts < MAX_LOGIN_ATTEMPTS_PER_FORM and not blocked_or_delayed:
			if should_cancel and should_cancel():
				break
			response = _submit(
				client,
				form,
				{email_name: unknown_email, password_name: password},
			)
			attempts += 1
			if response.status_code == 429 or response.elapsed_seconds >= RATE_LIMIT_DELAY_SECONDS:
				blocked_or_delayed = True

		if attempts == MAX_LOGIN_ATTEMPTS_PER_FORM and not blocked_or_delayed:
			findings.append(
				_finding(
					"Login Form Has No Effective Rate Limit",
					"Six synthetic login attempts were accepted without a block, delay, or HTTP 429 response.",
					f"{attempts} synthetic attempts completed without a rate-limit signal.",
					"Apply per-account and per-source throttling with progressive delays and monitoring.",
					form.page_url,
					"medium",
					"medium",
					"CWE-307",
				)
			)
		else:
			checks_passed += 1

	return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}
