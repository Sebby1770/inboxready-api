"""SSRF-resistant HTTP client for fetching attacker-influenced URLs.

Audits accept customer-supplied domains, and some checks (MTA-STS policy files)
fetch ``https://mta-sts.<domain>/.well-known/mta-sts.txt``. Because ``<domain>``
is user controlled, a naive ``httpx.get`` is a server-side request forgery (SSRF)
primitive: a customer can point ``mta-sts.attacker.example`` at ``169.254.169.254``
(cloud metadata), ``127.0.0.1``, or any RFC1918 host and make the server fetch it.

This module fetches URLs while refusing to connect to any non-public IP address,
re-validating on every redirect hop, so the resolved socket can never reach an
internal target.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

import httpx

# Only these schemes are ever fetched; MTA-STS policies are HTTPS by spec.
_ALLOWED_SCHEMES = frozenset({"https"})
_MAX_REDIRECTS = 3
_MAX_BYTES = 256 * 1024  # policy files are tiny; cap the read to avoid abuse.


class UnsafeRequestError(Exception):
    """Raised when a URL resolves to a disallowed (non-public) address."""


@dataclass(frozen=True)
class SafeResponse:
    status_code: int
    text: str


def _is_public_address(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True only for globally routable, non-internal addresses.

    ``is_global`` already rejects private, loopback, and reserved ranges, but we
    additionally reject link-local (169.254/16, fe80::/10 — cloud metadata lives
    at 169.254.169.254) and unspecified/multicast to be explicit and defensive.
    """

    return (
        ip.is_global
        and not ip.is_private
        and not ip.is_loopback
        and not ip.is_link_local
        and not ip.is_multicast
        and not ip.is_reserved
        and not ip.is_unspecified
    )


def _resolve_public_addresses(host: str) -> list[str]:
    """Resolve ``host`` to IPs, requiring every one of them to be public.

    We require *all* resolved addresses to be public (not just one), so an
    attacker cannot smuggle an internal address into a DNS response that also
    contains a public one and race the connection to the internal target.
    """

    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:  # pragma: no cover - network dependent
        raise UnsafeRequestError(f"Could not resolve host: {host}") from exc

    addresses: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:  # pragma: no cover - defensive
            raise UnsafeRequestError(f"Unparseable address for host: {host}")
        if not _is_public_address(ip):
            raise UnsafeRequestError(
                f"Refusing to fetch {host}: resolves to non-public address {raw}."
            )
        addresses.append(raw)

    if not addresses:  # pragma: no cover - defensive
        raise UnsafeRequestError(f"No addresses resolved for host: {host}")
    return addresses


def _validate_url(url: str) -> None:
    parsed = httpx.URL(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeRequestError(f"Disallowed URL scheme: {parsed.scheme or '(none)'}")
    host = parsed.host
    if not host:
        raise UnsafeRequestError("URL has no host.")
    # If the host is already a literal IP, validate it directly; otherwise
    # resolve and validate every A/AAAA record before we ever open a socket.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        _resolve_public_addresses(host)
    else:
        if not _is_public_address(ip):
            raise UnsafeRequestError(
                f"Refusing to fetch literal address {host}: not publicly routable."
            )


def safe_get(
    url: str,
    *,
    timeout: float,
    user_agent: str,
    allow_private_networks: bool = False,
) -> SafeResponse:
    """GET ``url`` while refusing to reach any non-public host.

    Redirects are followed manually so each hop is re-validated against the
    public-address policy. ``allow_private_networks`` is an explicit escape
    hatch for trusted local development only and must never be enabled in
    production.
    """

    headers = {"User-Agent": user_agent}
    current = url
    with httpx.Client(
        timeout=timeout,
        headers=headers,
        follow_redirects=False,
    ) as client:
        for _ in range(_MAX_REDIRECTS + 1):
            if not allow_private_networks:
                _validate_url(current)

            with client.stream("GET", current) as response:
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise UnsafeRequestError("Redirect without a Location header.")
                    current = str(httpx.URL(current).join(location))
                    continue

                body = bytearray()
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > _MAX_BYTES:
                        break
                text = body[:_MAX_BYTES].decode("utf-8", errors="replace")
                return SafeResponse(status_code=response.status_code, text=text)

    raise UnsafeRequestError("Too many redirects.")
