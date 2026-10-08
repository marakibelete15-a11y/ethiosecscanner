"""
Safe HTTP Client with SSRF Blocking and DNS Rebinding Prevention (SRS Section 4.2, SEC-4).

Guarantees:
1. DNS resolution once per host and IP address pinning on the outbound socket (connect_tcp).
2. Strict re-validation of every redirect destination before connecting.
3. Configurable timeout and maximum response body size limits.
4. Universal use across target ownership verification and scanner execution.
"""

import time
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import httpcore
import httpx

from app.core.settings import settings
from app.scanner.safety import SSRFError, resolve_and_validate_host, validate_target_url


class ResponseSizeExceededError(ValueError):
    """Raised when an HTTP response payload exceeds configured maximum size."""
    pass


class SafeSyncBackend(httpcore.SyncBackend):
    """
    Custom network backend that enforces IP pinning and SSRF validation
    at the raw TCP socket connection level (preventing DNS rebinding).
    """

    def __init__(self, allow_local: bool = False):
        super().__init__()
        self.allow_local = allow_local

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: Optional[float] = None,
        local_address: Optional[str] = None,
        socket_options: Any = None,
    ) -> httpcore.NetworkStream:
        # Resolve hostname and validate against SSRF blocklist
        valid_ips = resolve_and_validate_host(host, allow_local=self.allow_local)
        if not valid_ips:
            raise SSRFError(f"No valid IP addresses available for host '{host}'.")

        # Pin socket connection strictly to the first validated IP address
        pinned_ip = valid_ips[0]
        return super().connect_tcp(
            host=pinned_ip,
            port=port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )


class SafeTransport(httpx.HTTPTransport):
    """HTTPX Transport backed by SafeSyncBackend for IP pinning and SSRF defense."""

    def __init__(self, allow_local: bool = False, **kwargs):
        super().__init__(**kwargs)
        self._pool = httpcore.ConnectionPool(
            ssl_context=self._pool._ssl_context,
            network_backend=SafeSyncBackend(allow_local=allow_local),
            http1=True,
            http2=False,
            retries=0,
        )


class SafeResponse:
    """Standardized response object returned by SafeHttpClient."""

    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        content: bytes,
        url: str,
        final_url: str,
        elapsed_seconds: float,
    ):
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.url = url
        self.final_url = final_url
        self.elapsed_seconds = elapsed_seconds

    @property
    def text(self) -> str:
        """Decode content to string using UTF-8 with fallback replacement."""
        return self.content.decode("utf-8", errors="replace")

    def __repr__(self) -> str:
        return f"<SafeResponse [{self.status_code}] final_url='{self.final_url}'>"


class SafeHttpClient:
    """
    SSRF-protected HTTP Client.
    Enforces DNS rebinding defenses, redirect safety, timeouts, and response size bounds.
    """

    DEFAULT_MAX_REDIRECTS = 5
    DEFAULT_MAX_RESPONSE_SIZE = 1024 * 1024  # 1 MB

    def __init__(
        self,
        allow_local: Optional[bool] = None,
        timeout_seconds: Optional[float] = None,
        max_response_size: int = DEFAULT_MAX_RESPONSE_SIZE,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
    ):
        self.allow_local = (
            allow_local if allow_local is not None else settings.ALLOW_LOCAL_TARGETS
        )
        self.timeout_seconds = (
            timeout_seconds
            if timeout_seconds is not None
            else float(settings.SCANNER_REQUEST_TIMEOUT_SECONDS)
        )
        self.max_response_size = max_response_size
        self.max_redirects = max_redirects

    def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        follow_redirects: bool = True,
        **kwargs,
    ) -> SafeResponse:
        """
        Execute safe HTTP request with IP pinning and step-by-step redirect validation.
        """
        start_time = time.monotonic()
        req_headers = {
            "User-Agent": "EthioSecScanner/1.0 (+https://ethiosec.local/bot)",
            **(headers or {}),
        }

        transport = SafeTransport(allow_local=self.allow_local)
        client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(self.timeout_seconds),
            follow_redirects=False,
            verify=False,  # Allow self-signed certificates in scanner & local testing
        )

        current_url = url
        redirect_count = 0

        try:
            while True:
                # 1. Pre-request URL and DNS safety validation
                validate_target_url(current_url, allow_local=self.allow_local)

                # 2. Issue request
                response = client.request(
                    method=method,
                    url=current_url,
                    headers=req_headers,
                    **kwargs,
                )

                # 3. Handle Redirects safely
                if response.is_redirect and follow_redirects:
                    redirect_count += 1
                    if redirect_count > self.max_redirects:
                        raise SSRFError(f"Too many redirects (exceeded limit of {self.max_redirects}).")

                    location = response.headers.get("Location")
                    if not location:
                        break  # No location header; stop redirecting

                    # Resolve relative redirect URLs against current URL
                    next_url = urljoin(current_url, location)

                    # Re-validate new URL and destination host before next iteration
                    validate_target_url(next_url, allow_local=self.allow_local)
                    current_url = next_url
                    continue

                # 4. Check response body size
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > self.max_response_size:
                    raise ResponseSizeExceededError(
                        f"Response Content-Length ({content_length} bytes) exceeds limit of {self.max_response_size} bytes."
                    )

                body = response.read()
                if len(body) > self.max_response_size:
                    raise ResponseSizeExceededError(
                        f"Response body ({len(body)} bytes) exceeds limit of {self.max_response_size} bytes."
                    )

                elapsed = time.monotonic() - start_time
                return SafeResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    content=body,
                    url=url,
                    final_url=str(response.url),
                    elapsed_seconds=elapsed,
                )
        finally:
            client.close()

    def get(self, url: str, **kwargs) -> SafeResponse:
        """Send a safe GET request."""
        return self.request("GET", url, **kwargs)


def safe_get(
    url: str,
    allow_local: Optional[bool] = None,
    timeout_seconds: Optional[float] = None,
    max_response_size: int = SafeHttpClient.DEFAULT_MAX_RESPONSE_SIZE,
    follow_redirects: bool = True,
    headers: Optional[Dict[str, str]] = None,
) -> SafeResponse:
    """Convenience helper function for safe GET requests."""
    client = SafeHttpClient(
        allow_local=allow_local,
        timeout_seconds=timeout_seconds,
        max_response_size=max_response_size,
    )
    return client.get(url, follow_redirects=follow_redirects, headers=headers)

