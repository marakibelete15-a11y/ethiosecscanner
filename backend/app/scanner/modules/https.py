"""
HTTPS and Transport Layer Security Scanner Module (SRS Section 5, OWASP A02:2021 Cryptographic Failures).

Evaluates:
1. Transport encryption (HTTPS vs plaintext HTTP)
2. HTTP-to-HTTPS automatic redirection
3. Strict-Transport-Security (HSTS) enforcement on encrypted endpoints
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from app.scanner.http_client import SafeHttpClient, SafeResponse
from app.scanner.masking import sanitize_evidence


def run(
    target_url: str,
    client: SafeHttpClient,
    pages: List[str] = None,
) -> Dict[str, Any]:
    """
    Execute HTTPS and TLS transport checks against the target.
    Returns:
    {
        "checks_run": int,
        "checks_passed": int,
        "findings": List[Dict[str, Any]]
    }
    """
    target = target_url.strip()
    parsed = urlparse(target)
    is_target_https = parsed.scheme.lower() == "https"

    findings: List[Dict[str, Any]] = []
    checks_run = 0
    checks_passed = 0

    # 1. Transport Scheme & HTTPS Redirection
    checks_run += 1
    if not is_target_https:
        # Target was registered as plain HTTP: test if server automatically upgrades to HTTPS
        resp_no_redirect: SafeResponse = client.get(target, follow_redirects=False)
        location = resp_no_redirect.headers.get("Location", "")
        is_redirect_to_https = (
            resp_no_redirect.status_code in (301, 302, 307, 308)
            and location.lower().startswith("https://")
        )

        if not is_redirect_to_https:
            evidence_text = (
                f"Requested: {target}\n"
                f"HTTP Status: {resp_no_redirect.status_code}\n"
                f"Location Header: {location or 'None'}\n"
                f"Connection Protocol: Unencrypted HTTP"
            )
            findings.append({
                "module": "https",
                "severity": "high",
                "title": "Cleartext HTTP Protocol in Use Without HTTPS Redirection",
                "description": (
                    "The target application is accessible over unencrypted HTTP and does not automatically "
                    "redirect requests to HTTPS. All communication, including user credentials and session tokens, "
                    "is transmitted in cleartext and vulnerable to eavesdropping and Man-in-the-Middle (MitM) attacks."
                ),
                "evidence": sanitize_evidence(evidence_text),
                "remediation": "Deploy an SSL/TLS certificate and configure your web server to redirect all HTTP traffic to HTTPS (HTTP 301).",
                "affected_url": target,
                "parameter": None,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cwe_id": "CWE-319",
                "confidence": "certain",
                "http_method": "GET",
            })
        else:
            checks_passed += 1
    else:
        # Target is using HTTPS
        checks_passed += 1

    # 2. Strict-Transport-Security (HSTS) on HTTPS
    checks_run += 1
    if is_target_https:
        response: SafeResponse = client.get(target)
        hsts_header = response.headers.get("Strict-Transport-Security") or response.headers.get("strict-transport-security")
        if not hsts_header:
            evidence_text = f"Target: {target}\nHeaders received:\n" + "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            findings.append({
                "module": "https",
                "severity": "medium",
                "title": "Missing Strict-Transport-Security (HSTS) on HTTPS Endpoint",
                "description": (
                    "Although the target provides HTTPS, it does not instruct browsers to remember this requirement via HSTS. "
                    "First-time visitors and users following plaintext links remain vulnerable to SSL-stripping attacks."
                ),
                "evidence": sanitize_evidence(evidence_text),
                "remediation": "Add the Strict-Transport-Security header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                "affected_url": target,
                "parameter": None,
                "owasp_category": "A02:2021-Cryptographic Failures",
                "cwe_id": "CWE-319",
                "confidence": "certain",
                "http_method": "GET",
            })
        else:
            checks_passed += 1
    else:
        # Plain HTTP cannot send valid HSTS
        checks_passed += 1

    return {
        "checks_run": checks_run,
        "checks_passed": checks_passed,
        "findings": findings,
    }
