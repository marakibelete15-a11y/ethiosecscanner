from types import SimpleNamespace

from app.scanner.masking import REDACTED, sanitize_evidence
from app.scanner.modules.cors import run as run_cors_module
from app.scanner.modules.https import run as run_https_module
from app.scanner.modules.http_methods import run as run_http_methods_module
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


def test_https_module_reports_expired_certificate():
    class Response:
        status_code = 200
        headers = {"location": "https://example.test", "strict-transport-security": "max-age=31536000"}

    class Client:
        def get(self, url, **kwargs):
            if kwargs.get("verify_tls") is True:
                raise RuntimeError("certificate has expired")
            if url.startswith("http://"):
                return Response()
            return Response()

    result = run_https_module("http://example.test", Client())

    assert result["checks_run"] == 4
    assert any("expired" in finding["title"].lower() for finding in result["findings"])


def test_https_module_checks_http_redirect_and_hsts():
    class Client:
        def get(self, url, **kwargs):
            if url.startswith("http://"):
                return type(
                    "RedirectResponse",
                    (),
                    {"status_code": 301, "headers": {"location": "https://example.test/"}},
                )()
            return type("HttpsResponse", (), {"status_code": 200, "headers": {}})()

    result = run_https_module("https://example.test/", Client())

    titles = {finding["title"] for finding in result["findings"]}
    assert result["checks_run"] == 4
    assert result["checks_passed"] == 3
    assert titles == {"Missing Strict-Transport-Security Header"}


def test_cors_module_reports_wildcard_origin():
    class Client:
        def get(self, url, **kwargs):
            assert kwargs["headers"]["Origin"] == "https://ethiosec-invalid-origin.example"
            return SimpleNamespace(
                headers={"access-control-allow-origin": "*", "access-control-allow-credentials": "true"}
            )

    result = run_cors_module("http://example.test", Client())

    assert result["checks_run"] == 1
    assert result["findings"][0]["severity"] == "medium"
    assert result["findings"][0]["evidence"] == "Access-Control-Allow-Origin: *"


def test_http_methods_module_only_sends_options_and_trace():
    class Client:
        methods = []

        def request(self, method, url, **kwargs):
            self.methods.append(method)
            if method == "OPTIONS":
                return SimpleNamespace(status_code=200, headers={"allow": "GET, PUT, DELETE, TRACE"})
            return SimpleNamespace(status_code=200, headers={})

    client = Client()
    result = run_http_methods_module("http://example.test", client)

    assert client.methods == ["OPTIONS", "TRACE"]
    assert len(result["findings"]) == 2