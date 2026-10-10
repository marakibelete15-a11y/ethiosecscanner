from app.scanner.masking import REDACTED, sanitize_evidence
from app.scanner.scoring import calculate_security_score, calculate_verdict


def test_security_score_applies_severity_penalties_and_floor():
    """Score starts at 100, applies defined penalties, and never drops below zero."""
    assert calculate_security_score(
        {"critical": 1, "high": 1, "medium": 1, "low": 1}
    ) == 60
    assert calculate_security_score(["critical"] * 5) == 0
    assert calculate_security_score({"info": 12}) == 100
    assert calculate_security_score({"critical": -1}) == 100


def test_verdict_uses_critical_first_priority():
    assert calculate_verdict({"critical": 1, "high": 1}, error_count=2) == "critical"
    assert calculate_verdict({"high": 1, "medium": 1}) == "high"
    assert calculate_verdict({"info": 1}, error_count=1) == "info"
    assert calculate_verdict({}, error_count=1) == "scanner_error"
    assert calculate_verdict({}) == "safe"


def test_sanitize_evidence_masks_credentials_and_cookie_values():
    evidence = "\n".join(
        [
            "Cookie: session=cookie-secret; theme=dark",
            "Set-Cookie: sid=set-cookie-secret; HttpOnly; Secure",
            "Authorization: Custom auth-secret",
            "token=token-secret",
            'password="password secret"',
            '{"password": "json-password-secret"}',
        ]
    )

    sanitized = sanitize_evidence(evidence)

    for secret in (
        "cookie-secret",
        "dark",
        "set-cookie-secret",
        "auth-secret",
        "token-secret",
        "password secret",
        "json-password-secret",
    ):
        assert secret not in sanitized
    assert sanitized.count(REDACTED) >= 6


def test_sanitize_evidence_shortens_long_evidence():
    sanitized = sanitize_evidence("x" * 1500, max_length=20)

    assert sanitized.startswith("x" * 20)
    assert "evidence truncated" in sanitized