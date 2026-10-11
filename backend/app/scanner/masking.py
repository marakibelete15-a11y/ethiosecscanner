"""
Evidence Masking and Sanitization Module (SRS FND-6, SEC-11).

Enforces:
1. Redaction of sensitive values: session cookies, Set-Cookie headers, Authorization tokens,
   passwords, API keys, and secret parameters.
2. Shortening of oversized evidence payloads to prevent database bloat and UI degradation.
"""

import re
from typing import Optional

MAX_EVIDENCE_LENGTH = 1000
REDACTED = "********"

# Regex patterns for sensitive header/payload content
PATTERNS = [
    # Mask the complete value regardless of the Authorization scheme.
    (re.compile(r"(Authorization\s*:\s*)[^\r\n]+", re.IGNORECASE), rf"\g<1>{REDACTED}"),

    # Set-Cookie and Cookie header values.
    (re.compile(r"(Set-Cookie\s*:\s*[^=;\s]+)=([^;\r\n]+)", re.IGNORECASE), rf"\g<1>={REDACTED}"),
    (re.compile(r"((?:Cookie\s*:\s*|;\s*)[^=;\s]+)=([^;\r\n]*)", re.IGNORECASE), rf"\g<1>{REDACTED}"),

    # Sensitive query/body values, including quoted values.
    (
        re.compile(
            r"([\"']?(?:password|passwd|pwd|token|access_token|secret|api_key|apikey|auth_token)[\"']?\s*[:=]\s*)(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s&,;}\r\n]+)",
            re.IGNORECASE,
        ),
        rf"\g<1>{REDACTED}",
    ),
    # Environment/configuration assignments commonly appear in exposed-file evidence.
    (re.compile(r"(^[A-Z][A-Z0-9_]*=)[^\r\n]+", re.MULTILINE), rf"\g<1>{REDACTED}"),
]


def mask_evidence(evidence: Optional[str]) -> Optional[str]:
    """
    Sanitize sensitive credentials, tokens, and cookies from evidence text.
    """
    if not evidence:
        return evidence

    text = str(evidence)
    for pattern, replacement in PATTERNS:
        text = pattern.sub(replacement, text)

    return text


def shorten_evidence(evidence: Optional[str], max_length: int = MAX_EVIDENCE_LENGTH) -> Optional[str]:
    """
    Truncate oversized evidence text with a descriptive marker.
    """
    if not evidence or len(evidence) <= max_length:
        return evidence

    return evidence[:max_length] + "\n... [evidence truncated]"


def sanitize_evidence(evidence: Optional[str], max_length: int = MAX_EVIDENCE_LENGTH) -> Optional[str]:
    """
    Combined utility: masks sensitive credentials first, then bounds length.
    Applied before saving any finding to the database.
    """
    if not evidence:
        return evidence

    masked = mask_evidence(evidence)
    return shorten_evidence(masked, max_length=max_length)
