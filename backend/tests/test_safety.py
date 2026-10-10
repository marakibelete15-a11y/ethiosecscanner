"""
Comprehensive Network Safety, SSRF Defense, and Safe HTTP Client Tests.

Covers:
1. Redirect to cloud metadata (169.254.169.254) blocked
2. Redirect to private IP blocked when ALLOW_LOCAL_TARGETS=false
3. Hostname resolving to private IP blocked (mocked DNS lookup)
4. DNS rebinding prevention (socket pinned to initial validated IP)
5. IPv6 loopback (::1) and IPv4-mapped IPv6 blocked
6. RFC 1918 ranges (10.x, 172.16.x, 192.168.x) blocked when flag is off
7. Redirect hop limit (> 5 hops) refused
8. Response larger than 1 MB refused/truncated
9. dns_txt verification success and failure (mocked DNS resolver)
"""

import ipaddress
import socket
import uuid
import pytest
from unittest.mock import MagicMock, patch

from app.scanner.safety import (
    SSRFError,
    is_ip_blocked,
    normalize_url,
    resolve_and_validate_host,
    validate_target_url,
)
from app.scanner.http_client import (
    ResponseSizeExceededError,
    SafeHttpClient,
    SafeSyncBackend,
)
from app.services.verification_service import verify_target_ownership
from app.models.target import Target


# ==============================================================================
# 1. IP Range & SSRF Validation Tests
# ==============================================================================

def test_ipv6_loopback_and_ipv4_mapped_ipv6_blocked():
    """IPv6 loopback ::1 and IPv4-mapped IPv6 are strictly blocked."""
    # ::1 blocked when allow_local=False
    blocked, reason = is_ip_blocked(ipaddress.ip_address("::1"), allow_local=False)
    assert blocked is True
    assert "loopback" in reason.lower()

    # ::ffff:127.0.0.1 (IPv4-mapped loopback) blocked when allow_local=False
    blocked, _ = is_ip_blocked(ipaddress.ip_address("::ffff:127.0.0.1"), allow_local=False)
    assert blocked is True

    # ::ffff:169.254.169.254 (IPv4-mapped cloud metadata) ALWAYS blocked even with allow_local=True
    blocked, reason = is_ip_blocked(ipaddress.ip_address("::ffff:169.254.169.254"), allow_local=True)
    assert blocked is True
    assert "cloud metadata" in reason.lower()


def test_rfc1918_private_ranges_blocked_when_flag_off():
    """10.x, 172.16.x, and 192.168.x are blocked when allow_local=False, permitted when True."""
    private_ips = ["10.0.0.1", "10.254.1.1", "172.16.0.1", "172.31.255.254", "192.168.1.1", "192.168.100.254"]
    for ip_str in private_ips:
        ip = ipaddress.ip_address(ip_str)
        # Blocked when allow_local=False
        blocked_off, reason_off = is_ip_blocked(ip, allow_local=False)
        assert blocked_off is True, f"Expected {ip_str} to be blocked with allow_local=False"
        assert "private" in reason_off.lower()

        # Permitted when allow_local=True
        blocked_on, _ = is_ip_blocked(ip, allow_local=True)
        assert blocked_on is False, f"Expected {ip_str} to be permitted with allow_local=True"


def test_hostname_resolving_to_private_ip_blocked():
    """A hostname that resolves to a private IP is blocked under SSRF policies."""
    mock_addrinfo = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.55", 80)),
    ]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(SSRFError) as exc_info:
            resolve_and_validate_host("internal-service.corporate.local", allow_local=False)
        assert "192.168.1.55" in str(exc_info.value)
        assert "private" in str(exc_info.value).lower()


# ==============================================================================
# 2. DNS Rebinding Prevention Tests
# ==============================================================================

def test_dns_rebinding_pins_socket_to_initial_ip():
    """
    DNS Rebinding test:
    First DNS lookup resolves to public IP 93.184.216.34.
    Subsequent DNS lookup changes to internal IP 127.0.0.1.
    The TCP connection must remain pinned strictly to the first validated IP.
    """
    backend = SafeSyncBackend(allow_local=False)

    dns_responses = [
        # First call: initial resolution -> public IP
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))],
        # Second call: potential rebind attempt -> loopback
        [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))],
    ]

    with patch("socket.getaddrinfo", side_effect=dns_responses):
        with patch("httpcore.SyncBackend.connect_tcp") as mock_super_connect:
            mock_super_connect.return_value = MagicMock()
            backend.connect_tcp("rebind-attack.com", 80)

            # Assert connection was pinned to the validated public IP
            mock_super_connect.assert_called_once()
            called_host = mock_super_connect.call_args[1].get("host") or mock_super_connect.call_args[0][0]
            assert called_host == "93.184.216.34"
            assert called_host != "127.0.0.1"


# ==============================================================================
# 3. HTTP Client Redirect and Size Limit Tests
# ==============================================================================

def test_redirect_to_metadata_ip_blocked():
    """A redirect from an allowed URL to 169.254.169.254 is blocked even with allow_local=True."""
    client = SafeHttpClient(allow_local=True)

    # Mock response: initial request returns 302 redirect to metadata IP
    mock_redirect_resp = MagicMock()
    mock_redirect_resp.is_redirect = True
    mock_redirect_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    with patch("httpx.Client.request", return_value=mock_redirect_resp):
        with pytest.raises(SSRFError) as exc_info:
            client.get("http://127.0.0.1:5000/redirect-to-metadata")
        assert "cloud metadata" in str(exc_info.value).lower()


def test_redirect_to_private_ip_blocked_when_flag_off():
    """A redirect to a private IP is blocked when ALLOW_LOCAL_TARGETS=False."""
    client = SafeHttpClient(allow_local=False)

    mock_redirect_resp = MagicMock()
    mock_redirect_resp.is_redirect = True
    mock_redirect_resp.headers = {"Location": "http://10.0.0.1/admin"}

    with patch("httpx.Client.request", return_value=mock_redirect_resp):
        with pytest.raises(SSRFError) as exc_info:
            client.get("https://example.com/redirect-to-private")
        assert "private" in str(exc_info.value).lower()


def test_redirect_limit_exceeded_refused():
    """Redirecting more than 5 hops raises SSRFError."""
    client = SafeHttpClient(allow_local=True, max_redirects=5)

    # Mock endless redirect
    mock_redirect_resp = MagicMock()
    mock_redirect_resp.is_redirect = True
    mock_redirect_resp.headers = {"Location": "http://127.0.0.1:5000/loop"}

    with patch("httpx.Client.request", return_value=mock_redirect_resp):
        with pytest.raises(SSRFError) as exc_info:
            client.get("http://127.0.0.1:5000/start")
        assert "too many redirects" in str(exc_info.value).lower()


def test_response_larger_than_1mb_refused():
    """Responses larger than 1 MB are refused via ResponseSizeExceededError."""
    client = SafeHttpClient(allow_local=True, max_response_size=1024 * 1024)

    # Case 1: Content-Length header specifies oversized payload
    mock_resp_header = MagicMock()
    mock_resp_header.is_redirect = False
    mock_resp_header.headers = {"Content-Length": "2000000"}

    with patch("httpx.Client.request", return_value=mock_resp_header):
        with pytest.raises(ResponseSizeExceededError) as exc_info:
            client.get("http://127.0.0.1:5000/huge-file")
        assert "exceeds limit" in str(exc_info.value).lower()

    # Case 2: Body bytes exceed 1 MB
    mock_resp_body = MagicMock()
    mock_resp_body.is_redirect = False
    mock_resp_body.headers = {}
    mock_resp_body.read.return_value = b"A" * (1024 * 1024 + 100)

    with patch("httpx.Client.request", return_value=mock_resp_body):
        with pytest.raises(ResponseSizeExceededError) as exc_info:
            client.get("http://127.0.0.1:5000/stream-bomb")
        assert "exceeds limit" in str(exc_info.value).lower()


# ==============================================================================
# 4. DNS TXT Verification Tests
# ==============================================================================

def test_dns_txt_verification_success_and_failure():
    """dns_txt ownership verification handles matching record and missing record properly."""
    token = "a1b2c3d4e5f67890abcdef1234567890"
    target = Target(
        id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        url="https://verify-me.example.com",
        normalized_url="https://verify-me.example.com",
        verification_method="dns_txt",
        verification_token=token,
        is_verified=False,
    )

    # 1. Success case: TXT record contains ethiosec-verification=<token>
    mock_rdata = MagicMock()
    mock_rdata.strings = [f"ethiosec-verification={token}".encode("utf-8")]

    with patch("dns.resolver.Resolver.resolve", return_value=[mock_rdata]):
        verified, reason = verify_target_ownership(target)
        assert verified is True
        assert reason is None

    # 2. Failure case: TXT records exist but token does not match
    mock_wrong_rdata = MagicMock()
    mock_wrong_rdata.strings = [b"v=spf1 include:_spf.google.com ~all"]

    with patch("dns.resolver.Resolver.resolve", return_value=[mock_wrong_rdata]):
        verified, reason = verify_target_ownership(target)
        assert verified is False
        assert "none matched" in reason.lower()

    # 3. Failure case: Resolver raises DNS exception (record does not exist)
    with patch("dns.resolver.Resolver.resolve", side_effect=Exception("No answer")):
        verified, reason = verify_target_ownership(target)
        assert verified is False
        assert "no dns txt records found" in reason.lower()
