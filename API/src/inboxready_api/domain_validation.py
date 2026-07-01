from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit


DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def normalize_domain(value: str) -> str:
    raw_value = value.strip()
    if not raw_value:
        raise ValueError("Domain is required.")

    candidate = raw_value if "://" in raw_value else f"//{raw_value}"
    try:
        parsed = urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Domain contains an invalid port or host.") from exc

    if parsed.username or parsed.password:
        raise ValueError("Domain must not include credentials.")
    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP or HTTPS URLs are accepted.")
    if port is not None:
        raise ValueError("Domain must not include a port.")

    hostname = (parsed.hostname or "").rstrip(".").lower()
    try:
        domain = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain contains invalid international characters.") from exc

    if len(domain) > 253:
        raise ValueError("Domain must be 253 characters or fewer.")

    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("Enter a domain name, not an IP address.")

    labels = domain.split(".")
    if len(labels) < 2:
        raise ValueError("Enter a fully qualified domain such as example.com.")
    if any(not DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Domain contains an invalid label.")
    if labels[-1].isdigit():
        raise ValueError("Domain must end with a valid top-level domain.")

    return domain
