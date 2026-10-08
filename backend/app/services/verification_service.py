"""
Target Ownership Verification Service (SRS Section 4.2, SEC-6, TGT-5, TGT-6).

Supports three verification mechanisms:
1. 'meta_tag' (default): HTML <meta name="ethiosec-verification" content="..."> on homepage.
2. 'http_file': Plain text challenge at /.well-known/ethiosec-challenge.txt.
3. 'dns_txt': DNS TXT record at _ethiosec-challenge.<domain> or <domain>.
"""

import logging
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import dns.resolver

from app.core.settings import settings
from app.models.target import Target
from app.scanner.http_client import SafeHttpClient, safe_get
from app.scanner.safety import SSRFError

logger = logging.getLogger("ethiosec.verification")


def get_verification_instructions(url: str, token: str, method: str) -> Dict[str, Any]:
    """
    Generate plain human-readable and structured instructions for publishing verification proof.
    """
    parsed = urlparse(url)
    domain = parsed.hostname or url

    if method == "http_file":
        file_url = f"{url.rstrip('/')}/.well-known/ethiosec-challenge.txt"
        return {
            "method": "http_file",
            "token": token,
            "summary": (
                f"Upload a plain text file containing only your verification token to: {file_url}"
            ),
            "file_url": file_url,
            "file_content": token,
        }
    elif method == "dns_txt":
        record_name = f"_ethiosec-challenge.{domain}"
        record_value = f"ethiosec-verification={token}"
        return {
            "method": "dns_txt",
            "token": token,
            "summary": (
                f"Create a DNS TXT record for '{record_name}' (or '{domain}') with the value: '{record_value}'"
            ),
            "dns_record_name": record_name,
            "dns_record_value": record_value,
        }
    else:  # Default to meta_tag
        meta_tag_snippet = f'<meta name="ethiosec-verification" content="{token}">'
        return {
            "method": "meta_tag",
            "token": token,
            "summary": (
                f"Add the following HTML tag inside the <head> section of your homepage ({url}): {meta_tag_snippet}"
            ),
            "meta_tag": meta_tag_snippet,
        }


def _verify_meta_tag(target: Target, allow_local: bool) -> Tuple[bool, Optional[str]]:
    """Verify ownership via HTML meta tag on target homepage."""
    url = target.normalized_url
    expected_token = target.verification_token.strip()

    try:
        response = safe_get(url, allow_local=allow_local)
    except Exception as exc:
        return False, f"Could not connect to target URL: {exc}"

    if response.status_code >= 400:
        return False, f"Target homepage returned HTTP {response.status_code}."

    soup = BeautifulSoup(response.text, "html.parser")
    # Search for meta tag with name 'ethiosec-verification' (case-insensitive)
    for meta in soup.find_all("meta"):
        meta_name = meta.get("name", "")
        if meta_name and meta_name.lower() == "ethiosec-verification":
            content = meta.get("content", "").strip()
            if content == expected_token:
                return True, None
            else:
                return False, f"Meta tag 'ethiosec-verification' found, but content did not match token."

    return False, "Meta tag '<meta name=\"ethiosec-verification\" content=\"...\">' not found on target homepage."


def _verify_http_file(target: Target, allow_local: bool) -> Tuple[bool, Optional[str]]:
    """Verify ownership via /.well-known/ethiosec-challenge.txt file."""
    challenge_url = f"{target.normalized_url.rstrip('/')}/.well-known/ethiosec-challenge.txt"
    expected_token = target.verification_token.strip()

    try:
        response = safe_get(challenge_url, allow_local=allow_local)
    except Exception as exc:
        return False, f"Could not connect to challenge URL: {exc}"

    if response.status_code != 200:
        return False, f"Challenge file at {challenge_url} returned HTTP status {response.status_code}."

    actual_content = response.text.strip()
    if actual_content == expected_token:
        return True, None

    return False, "Challenge file content did not match the expected verification token."


def _verify_dns_txt(target: Target) -> Tuple[bool, Optional[str]]:
    """Verify ownership via DNS TXT record."""
    parsed = urlparse(target.normalized_url)
    domain = parsed.hostname
    if not domain:
        return False, "Could not determine hostname from target URL."

    expected_token = target.verification_token.strip()
    expected_prefix = f"ethiosec-verification={expected_token}"

    query_domains = [f"_ethiosec-challenge.{domain}", domain]
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5.0
    resolver.lifetime = 5.0

    found_txt_records = []
    for query_domain in query_domains:
        try:
            answers = resolver.resolve(query_domain, "TXT")
            for rdata in answers:
                for txt_bytes in rdata.strings:
                    txt_val = txt_bytes.decode("utf-8", errors="ignore").strip()
                    found_txt_records.append(txt_val)
                    if txt_val == expected_token or txt_val == expected_prefix:
                        return True, None
        except Exception:
            continue

    if found_txt_records:
        return (
            False,
            f"DNS TXT records found for {domain}, but none matched token '{expected_token}'.",
        )
    return False, f"No DNS TXT records found for '_ethiosec-challenge.{domain}' or '{domain}'."


def verify_target_ownership(
    target: Target,
    allow_local: Optional[bool] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Perform ownership verification check against the target website or domain.
    Returns (is_verified, failure_reason).
    """
    effective_allow_local = (
        allow_local if allow_local is not None else settings.ALLOW_LOCAL_TARGETS
    )
    method = target.verification_method or "meta_tag"

    try:
        if method == "meta_tag":
            return _verify_meta_tag(target, allow_local=effective_allow_local)
        elif method == "http_file":
            return _verify_http_file(target, allow_local=effective_allow_local)
        elif method == "dns_txt":
            return _verify_dns_txt(target)
        else:
            return False, f"Unsupported verification method: '{method}'."
    except SSRFError as ssrf_exc:
        return False, f"Verification blocked by security policy: {ssrf_exc}"
    except Exception as exc:
        logger.exception("Unexpected error during target verification: %s", exc)
        return False, f"Verification failed due to an unexpected error: {exc}"

