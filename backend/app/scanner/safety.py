"""
Network Safety and SSRF Protection Module (SRS Section 4.2, SEC-4).

Enforces:
1. URL normalization (canonical scheme, lowercase host, strip default ports & trailing slashes).
2. SSRF prevention (blocks loopback, RFC 1918 private, link-local, multicast, and cloud metadata).
3. Environment override (ALLOW_LOCAL_TARGETS=true permits loopback/private for dev, but cloud metadata 169.254.169.254 is ALWAYS blocked).
4. DNS resolution safety validation before any outbound socket connection.
"""

import ipaddress
import socket
from typing import List, Tuple
from urllib.parse import urlparse, urlunparse


class SSRFError(ValueError):
    """Raised when a target host or IP violates SSRF protection boundaries."""
    pass


class InvalidURLError(ValueError):
    """Raised when a target URL fails schema or syntax validation."""
    pass


# Cloud metadata IP networks (AWS, GCP, Azure, OpenStack, etc.)
# These are strictly forbidden in ALL environments, even when ALLOW_LOCAL_TARGETS is True.
METADATA_NETWORKS = [
    ipaddress.ip_network("169.254.169.0/24"),
    ipaddress.ip_network("fd00:ec2::/64"),
]


def normalize_url(url: str) -> str:
    """
    Validate and normalize a target URL into canonical format (SRS TGT-2).
    - Only 'http' and 'https' schemes allowed.
    - Userinfo (username/password) rejected.
    - Lowercase scheme and netloc (hostname + port).
    - Strip default ports (:80 for http, :443 for https).
    - Strip trailing slashes on path.
    - Strip query parameters and fragments.
    """
    if not url or not isinstance(url, str):
        raise InvalidURLError("A valid target URL must be provided.")

    url_str = url.strip()
    url_lower = url_str.lower()
    if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
        raise InvalidURLError("Target URL scheme must be http:// or https://")

    try:
        parsed = urlparse(url_str)
    except Exception as exc:
        raise InvalidURLError(f"Invalid URL structure: {exc}")

    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        raise InvalidURLError("Target URL scheme must be http:// or https://")

    if not parsed.hostname:
        raise InvalidURLError("Target URL must contain a valid hostname or IP address.")

    if parsed.username or parsed.password:
        raise InvalidURLError("Target URL must not contain embedded user credentials.")

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()

    # Determine port
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = hostname
    elif port is not None:
        netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    # Path normalization: strip trailing slashes, empty path becomes empty string
    path = parsed.path.rstrip("/") if parsed.path else ""

    # Reconstruct normalized URL without query params or fragments
    normalized = urlunparse((scheme, netloc, path, "", "", ""))
    return normalized


def is_ip_blocked(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address, allow_local: bool = False) -> Tuple[bool, str]:
    """
    Evaluate whether an IP address is blocked under SSRF policies (SRS SEC-4).
    Returns (is_blocked, reason).
    """
    # Unwrap IPv4-mapped IPv6 address (e.g., ::ffff:127.0.0.1 -> 127.0.0.1)
    if hasattr(ip_obj, "ipv4_mapped") and ip_obj.ipv4_mapped:
        ip_obj = ip_obj.ipv4_mapped

    # 1. Cloud metadata addresses - ALWAYS BLOCKED in any environment
    for net in METADATA_NETWORKS:
        if ip_obj in net:
            return True, f"Access to cloud metadata IP {ip_obj} is strictly forbidden."

    # Specific check for 169.254.169.254
    if str(ip_obj) == "169.254.169.254":
        return True, f"Access to cloud metadata IP {ip_obj} is strictly forbidden."

    # 2. Link-local addresses - ALWAYS BLOCKED
    if ip_obj.is_link_local:
        return True, f"Link-local IP address {ip_obj} is forbidden."

    # 3. Multicast & Unspecified - ALWAYS BLOCKED
    if ip_obj.is_multicast or ip_obj.is_unspecified:
        return True, f"Special-purpose IP address {ip_obj} is forbidden."

    # 4. Loopback addresses (127.0.0.0/8, ::1)
    if ip_obj.is_loopback:
        if not allow_local:
            return True, f"Loopback address {ip_obj} is forbidden in this environment."
        return False, f"Loopback address {ip_obj} permitted for development."

    # 5. Private network addresses (RFC 1918 & IPv6 Unique Local)
    if ip_obj.is_private:
        if not allow_local:
            return True, f"Private network address {ip_obj} is forbidden in this environment."
        return False, f"Private IP {ip_obj} permitted for development."

    # 6. Other reserved addresses
    if ip_obj.is_reserved:
        return True, f"Reserved IP address {ip_obj} is forbidden."

    return False, "Public IP permitted."


def resolve_and_validate_host(
    hostname: str,
    allow_local: bool = False,
    fail_on_unresolvable: bool = True,
) -> List[str]:
    """
    Resolve a hostname via DNS and validate all resolved IP addresses against SSRF policies.
    Returns the list of valid IP address strings.
    Raises SSRFError if any resolved IP is blocked.
    """
    # 1. Check if hostname is an IP literal
    is_ip = False
    try:
        ip_obj = ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        pass

    if is_ip:
        blocked, reason = is_ip_blocked(ip_obj, allow_local=allow_local)
        if blocked:
            raise SSRFError(reason)
        return [str(ip_obj)]

    # 2. Domain name resolution
    try:
        addrinfo = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    except Exception as exc:
        if fail_on_unresolvable:
            raise SSRFError(f"Could not resolve host '{hostname}': {exc}")
        return []

    if not addrinfo:
        if fail_on_unresolvable:
            raise SSRFError(f"No DNS records found for host '{hostname}'.")
        return []

    resolved_ips: List[str] = []
    for item in addrinfo:
        ip_str = item[4][0]
        if ip_str not in resolved_ips:
            is_valid_format = False
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                is_valid_format = True
            except ValueError:
                pass

            if not is_valid_format:
                raise SSRFError(f"Invalid IP address format resolved for host '{hostname}': {ip_str}")

            blocked, reason = is_ip_blocked(ip_obj, allow_local=allow_local)
            if blocked:
                raise SSRFError(f"Host '{hostname}' resolves to blocked IP {ip_str}: {reason}")
            resolved_ips.append(ip_str)

    return resolved_ips


def validate_target_url(
    url: str,
    allow_local: bool = False,
    fail_on_unresolvable: bool = True,
) -> str:
    """
    Validate target URL syntax, normalize it, and check hostname against SSRF policies.
    Returns normalized URL.
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    hostname = parsed.hostname
    if not hostname:
        raise InvalidURLError("Normalized URL missing hostname.")

    resolve_and_validate_host(
        hostname,
        allow_local=allow_local,
        fail_on_unresolvable=fail_on_unresolvable,
    )
    return normalized
