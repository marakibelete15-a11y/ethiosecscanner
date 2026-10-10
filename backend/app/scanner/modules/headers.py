"""
Security Headers Scanner Module (SRS Section 5, OWASP A05:2021 Security Misconfiguration).

Evaluates presence and configuration of 6 essential defensive HTTP response headers:
1. Content-Security-Policy (CSP)
2. Strict-Transport-Security (HSTS)
3. X-Frame-Options
4. X-Content-Type-Options
5. Referrer-Policy
6. Permissions-Policy
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
    Execute security headers evaluation against target website.
    Returns:
    {
        "checks_run": int,
        "checks_passed": int,
        "findings": List[Dict[str, Any]]
    }
    """
    target = target_url.strip()
    response: SafeResponse = client.get(target)

    headers_lower = {k.lower(): v for k, v in response.headers.items()}
    parsed = urlparse(target)
    is_https = parsed.scheme.lower() == "https"

    findings: List[Dict[str, Any]] = []
    checks_run = 0
    checks_passed = 0

    headers_dump = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    evidence_text = f"HTTP {response.status_code}\nHeaders received:\n{headers_dump}"

    # 1. Content-Security-Policy
    checks_run += 1
    csp = headers_lower.get("content-security-policy")
    if not csp:
        findings.append({
            "module": "headers",
            "severity": "medium",
            "title": "Missing Content-Security-Policy Header",
            "description": (
                "The Content-Security-Policy (CSP) HTTP response header was not returned by the server. "
                "CSP restricts resources (scripts, images, stylesheets) that the browser is allowed to load, "
                "providing critical defense-in-depth against Cross-Site Scripting (XSS) and data injection attacks."
            ),
            "evidence": sanitize_evidence(evidence_text),
            "remediation": "Configure a robust Content-Security-Policy header, such as: default-src 'self'; script-src 'self'; object-src 'none';",
            "affected_url": target,
            "parameter": None,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "cwe_id": "CWE-693",
            "confidence": "certain",
            "http_method": "GET",
        })
    else:
        checks_passed += 1

    # 2. Strict-Transport-Security (HSTS)
    checks_run += 1
    hsts = headers_lower.get("strict-transport-security")
    if is_https and not hsts:
        findings.append({
            "module": "headers",
            "severity": "medium",
            "title": "Missing Strict-Transport-Security (HSTS) Header",
            "description": (
                "The Strict-Transport-Security (HSTS) header informs user agents that the site should only "
                "be accessed using HTTPS. Its absence allows potential Man-in-the-Middle (MitM) attackers to "
                "downgrade secure connections to plaintext HTTP."
            ),
            "evidence": sanitize_evidence(evidence_text),
            "remediation": "Add the Strict-Transport-Security header: max-age=31536000; includeSubDomains; preload",
            "affected_url": target,
            "parameter": None,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "cwe_id": "CWE-319",
            "confidence": "certain",
            "http_method": "GET",
        })
    elif not is_https:
        # On plaintext HTTP, HSTS is inapplicable
        checks_passed += 1
    else:
        checks_passed += 1

    # 3. X-Frame-Options
    checks_run += 1
    xfo = headers_lower.get("x-frame-options")
    csp_has_ancestors = csp and "frame-ancestors" in csp.lower()
    if not xfo and not csp_has_ancestors:
        findings.append({
            "module": "headers",
            "severity": "medium",
            "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
            "description": (
                "Neither X-Frame-Options nor CSP 'frame-ancestors' directive is present. "
                "An attacker can render this website inside a transparent <iframe> on a malicious domain, "
                "tricking authenticated users into performing unintended actions (Clickjacking)."
            ),
            "evidence": sanitize_evidence(evidence_text),
            "remediation": "Set X-Frame-Options to 'DENY' or 'SAMEORIGIN', or configure CSP frame-ancestors 'self'.",
            "affected_url": target,
            "parameter": None,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "cwe_id": "CWE-1021",
            "confidence": "certain",
            "http_method": "GET",
        })
    else:
        checks_passed += 1

    # 4. X-Content-Type-Options
    checks_run += 1
    xcto = headers_lower.get("x-content-type-options")
    if not xcto or "nosniff" not in xcto.lower():
        findings.append({
            "module": "headers",
            "severity": "low",
            "title": "Missing X-Content-Type-Options Header",
            "description": (
                "The X-Content-Type-Options response header prevents browsers from MIME-sniffing a response away "
                "from the declared content type. Without 'nosniff', untrusted user uploads could be interpreted as executable HTML or script."
            ),
            "evidence": sanitize_evidence(evidence_text),
            "remediation": "Add 'X-Content-Type-Options: nosniff' to all HTTP responses.",
            "affected_url": target,
            "parameter": None,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "cwe_id": "CWE-16",
            "confidence": "certain",
            "http_method": "GET",
        })
    else:
        checks_passed += 1

    # 5. Referrer-Policy
    checks_run += 1
    rp = headers_lower.get("referrer-policy")
    if not rp:
        findings.append({
            "module": "headers",
            "severity": "low",
            "title": "Missing Referrer-Policy Header",
            "description": (
                "The Referrer-Policy header governs what referrer information should be sent when users click links "
                "or load external subresources. Without it, full URL query strings (potentially containing tokens or sensitive parameters) may leak."
            ),
            "evidence": sanitize_evidence(evidence_text),
            "remediation": "Configure 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'.",
            "affected_url": target,
            "parameter": None,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "cwe_id": "CWE-200",
            "confidence": "certain",
            "http_method": "GET",
        })
    else:
        checks_passed += 1

    # 6. Permissions-Policy
    checks_run += 1
    pp = headers_lower.get("permissions-policy")
    if not pp:
        findings.append({
            "module": "headers",
            "severity": "low",
            "title": "Missing Permissions-Policy Header",
            "description": (
                "The Permissions-Policy header allows web developers to explicitly enable or disable browser features "
                "and APIs (such as camera, microphone, geolocation, payment) for their origin and embedded iframes."
            ),
            "evidence": sanitize_evidence(evidence_text),
            "remediation": "Configure Permissions-Policy header, e.g., 'geolocation=(), camera=(), microphone=()'.",
            "affected_url": target,
            "parameter": None,
            "owasp_category": "A05:2021-Security Misconfiguration",
            "cwe_id": "CWE-16",
            "confidence": "certain",
            "http_method": "GET",
        })
    else:
        checks_passed += 1

    return {
        "checks_run": checks_run,
        "checks_passed": checks_passed,
        "findings": findings,
    }
