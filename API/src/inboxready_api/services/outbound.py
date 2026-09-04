"""Network policy shared by outbound HTTP features."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class UnsafeOutboundTarget(ValueError):
    """Raised when a target violates the outbound network policy."""


class OutboundResolutionError(UnsafeOutboundTarget):
    """Raised when a hostname cannot currently be resolved for validation."""


@dataclass(frozen=True)
class ResolvedHttpTarget:
    """An outbound URL plus the addresses approved for the connection."""

    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]

    def pinned_url(self, address: str | None = None) -> str:
        """Replace the URL authority with one vetted address."""
        selected = address or self.addresses[0]
        parsed = urlsplit(self.url)
        literal = f"[{selected}]" if ":" in selected else selected
        return urlunsplit((parsed.scheme, f"{literal}:{self.port}", parsed.path, parsed.query, ""))

    @property
    def host_header(self) -> str:
        parsed = urlsplit(self.url)
        literal = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        default_port = 443 if parsed.scheme == "https" else 80
        return literal if self.port == default_port else f"{literal}:{self.port}"


def resolve_public_http_target(
    url: str,
    *,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> ResolvedHttpTarget:
    """Resolve once, reject non-global answers, and return pinnable addresses."""
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeOutboundTarget("Target URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise UnsafeOutboundTarget("Target URL must not contain credentials.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeOutboundTarget("Target URL contains an invalid port.") from exc

    try:
        addresses = {
            ipaddress.ip_address(item[4][0])
            for item in resolver(parsed.hostname, port, type=socket.SOCK_STREAM)
        }
    except (OSError, ValueError) as exc:
        raise OutboundResolutionError("Target hostname could not be resolved safely.") from exc
    if not addresses:
        raise OutboundResolutionError("Target hostname did not resolve to an address.")
    if any(not address.is_global for address in addresses):
        raise UnsafeOutboundTarget("Target resolves to a private or non-global address.")

    ordered = tuple(str(address) for address in sorted(addresses, key=lambda item: (item.version, int(item))))
    return ResolvedHttpTarget(
        url=url,
        hostname=parsed.hostname,
        port=port,
        addresses=ordered,
    )


def validate_public_http_target(
    url: str,
    *,
    allow_private_hosts: bool,
    resolver: Callable[..., list[tuple]] = socket.getaddrinfo,
) -> str:
    """Require HTTP(S) and reject credentials and non-global destinations."""
    if not allow_private_hosts:
        return resolve_public_http_target(url, resolver=resolver).url

    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeOutboundTarget("Target URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password:
        raise UnsafeOutboundTarget("Target URL must not contain credentials.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise UnsafeOutboundTarget("Target URL contains an invalid port.") from exc
    return url
