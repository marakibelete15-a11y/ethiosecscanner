"""HTTPS availability, redirect, certificate, and HSTS checks."""

from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse, urlunparse

from app.scanner.http_client import SafeHttpClient


def _finding(
    *,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    remediation: str,
    target: str,
    cwe_id: str,
) -> Dict[str, Any]:
    return {
        "module": "https",
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "remediation": remediation,
        "affected_url": target,
        "parameter": None,
        "owasp_category": "A02:2021-Cryptographic Failures",
        "cwe_id": cwe_id,
        "confidence": "certain",
        "http_method": "GET",
    }


def _https_url(target: str) -> str:
    parsed = urlparse(target)
    return urlunparse(("https", parsed.netloc, parsed.path, "", parsed.query, ""))


def _http_url(target: str) -> str:
    parsed = urlparse(target)
    return urlunparse(("http", parsed.netloc, parsed.path, "", parsed.query, ""))


def _is_certificate_error(error: Exception) -> bool:
    message = str(error).lower()
    return "certificate" in message or "cert_verify" in message


def run(
    target_url: str,
    client: SafeHttpClient,
    pages: Optional[List[str]] = None,
    should_cancel: Optional[Callable[[], bool]] = None,
) -> Dict[str, Any]:
    """Run four transport checks and return standard module telemetry."""
    target = target_url.strip()
    parsed = urlparse(target)
    findings: List[Dict[str, Any]] = []
    checks_run = 0
    checks_passed = 0

    if should_cancel and should_cancel():
        return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}

    checks_run += 1
    https_response = None
    https_error = None
    https_url = _https_url(target)
    try:
        https_response = client.get(https_url, verify_tls=False)
    except Exception as exc:
        https_error = exc
        findings.append(
            _finding(
                severity="high",
                title="HTTPS Is Not Available",
                description=(
                    "The target could not establish an HTTPS connection. Traffic sent to the HTTP endpoint "
                    "is not protected by TLS and may be intercepted or modified in transit."
                ),
                evidence=f"HTTPS request failed for {https_url}: {type(exc).__name__}",
                remediation="Install a valid TLS certificate and make the application available over HTTPS.",
                target=target,
                cwe_id="CWE-319",
            )
        )
    else:
        checks_passed += 1

    if should_cancel and should_cancel():
        return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}

    checks_run += 1
    http_url = target if parsed.scheme.lower() == "http" else _http_url(target)
    try:
        http_response = client.get(http_url, follow_redirects=False)
        location = http_response.headers.get("location", "")
        redirect_target = urljoin(http_url, location) if location else ""
        redirects_to_https = (
            http_response.status_code in (301, 302, 303, 307, 308)
            and urlparse(redirect_target).scheme.lower() == "https"
        )
    except Exception as exc:
        location = ""
        redirects_to_https = False
        redirect_error = type(exc).__name__
    else:
        redirect_error = None

    if redirects_to_https:
        checks_passed += 1
    else:
        evidence = (
            f"HTTP endpoint: {http_url}\n"
            f"Location header: {location or 'missing'}"
            + (f"\nRequest error: {redirect_error}" if redirect_error else "")
        )
        findings.append(
            _finding(
                severity="medium",
                title="HTTP Does Not Redirect to HTTPS",
                description=(
                    "The HTTP endpoint does not redirect clients to HTTPS, so users may continue "
                    "communicating over an unencrypted connection."
                ),
                evidence=evidence,
                remediation="Configure HTTP to redirect all requests to the corresponding HTTPS URL.",
                target=target,
                cwe_id="CWE-319",
            )
        )

    if should_cancel and should_cancel():
        return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}

    checks_run += 1
    if https_response is None:
        checks_passed += 1
    else:
        try:
            client.get(https_url, verify_tls=True)
        except Exception as exc:
            if _is_certificate_error(exc):
                certificate_detail = "The TLS certificate is expired or otherwise invalid."
                if "expired" in str(exc).lower():
                    certificate_detail = "The TLS certificate has expired."
                findings.append(
                    _finding(
                        severity="high",
                        title="HTTPS Certificate Is Invalid or Expired",
                        description=(
                            f"{certificate_detail} Browsers may reject the connection or display a security warning."
                        ),
                        evidence=f"TLS certificate verification failed for {https_url}.",
                        remediation="Install a current TLS certificate valid for this hostname and renew it before expiry.",
                        target=target,
                        cwe_id="CWE-295",
                    )
                )
            else:
                findings.append(
                    _finding(
                        severity="high",
                        title="HTTPS Certificate Could Not Be Validated",
                        description="The target's TLS certificate could not be validated by the scanner.",
                        evidence=f"TLS validation failed for {https_url}: {type(exc).__name__}.",
                        remediation="Ensure the certificate chain is trusted, current, and valid for the target hostname.",
                        target=target,
                        cwe_id="CWE-295",
                    )
                )
        else:
            checks_passed += 1

    if should_cancel and should_cancel():
        return {"checks_run": checks_run, "checks_passed": checks_passed, "findings": findings}

    checks_run += 1
    if https_response is None:
        checks_passed += 1
    elif not https_response.headers.get("strict-transport-security"):
        findings.append(
            _finding(
                severity="medium",
                title="Missing Strict-Transport-Security Header",
                description=(
                    "The HTTPS response does not include HSTS, so browsers are not instructed to "
                    "prefer HTTPS for future visits."
                ),
                evidence=f"Strict-Transport-Security header missing from {https_url}.",
                remediation="Add Strict-Transport-Security with an appropriate max-age; consider includeSubDomains only when safe.",
                target=target,
                cwe_id="CWE-319",
            )
        )
    else:
        checks_passed += 1

    return {
        "checks_run": checks_run,
        "checks_passed": checks_passed,
        "findings": findings,
    }