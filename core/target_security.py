"""URL and network-boundary checks shared by crawling and probing."""
import ipaddress
import socket
from urllib.parse import urlparse


class TargetBoundaryError(ValueError):
    pass


def normalize_domain(domain: str) -> str:
    """Return a lowercase, trailing-dot-free ASCII DNS name."""
    value = (domain or "").strip().rstrip(".").lower()
    if not value:
        raise TargetBoundaryError("Target URL must include a hostname")
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetBoundaryError("Target hostname is not valid IDNA") from exc


def _blocked_ip(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
        or address == "169.254.169.254"
    )


def _resolved_addresses(hostname: str) -> set[str]:
    try:
        return {item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    except socket.gaierror as exc:
        raise TargetBoundaryError(f"Unable to resolve target hostname '{hostname}'") from exc


def validate_target_url(url: str, expected_domain: str | None = None) -> str:
    """Validate scheme, host, DNS resolution, and optional origin ownership."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise TargetBoundaryError("Only http and https targets are supported")
    if parsed.username or parsed.password or not parsed.hostname:
        raise TargetBoundaryError("Target URL must contain a hostname without credentials")

    hostname = normalize_domain(parsed.hostname)
    if expected_domain is not None and hostname != normalize_domain(expected_domain):
        raise TargetBoundaryError(
            f"URL host '{hostname}' does not match authorized host '{normalize_domain(expected_domain)}'"
        )
    if hostname in {"localhost", "localhost.localdomain"}:
        raise TargetBoundaryError("Localhost targets are not allowed")

    try:
        literal_ip = ipaddress.ip_address(hostname)
    except ValueError:
        literal_ip = None
    addresses = {str(literal_ip)} if literal_ip else _resolved_addresses(hostname)
    if any(_blocked_ip(address) for address in addresses):
        raise TargetBoundaryError(f"Target '{hostname}' resolves to a blocked network address")
    return hostname


def same_origin(url: str, expected_domain: str, expected_scheme: str) -> bool:
    parsed = urlparse(url)
    return (
        parsed.scheme.lower() == expected_scheme.lower()
        and normalize_domain(parsed.hostname or "") == normalize_domain(expected_domain)
        and parsed.port in (None, 80 if expected_scheme == "http" else 443)
    )