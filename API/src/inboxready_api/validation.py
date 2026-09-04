"""Validation and canonicalisation for attacker-controlled API inputs."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from urllib.parse import urlsplit

DOMAIN_MAX = 253
DOMAIN_INPUT_MAX = 2_048
SELECTOR_MAX = 253
SELECTORS_MAX = 20
EXPECTED_PROVIDERS_MAX = 20
EXPECTED_PROVIDER_MAX = 120

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SELECTOR_LABEL = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")


def normalize_domain(value: str) -> str:
    """Return one canonical DNS hostname or raise ``ValueError``.

    HTTP(S) URLs remain accepted for backwards compatibility, but credentials,
    ports, IP literals, malformed labels, and non-HTTP schemes are rejected
    before they can reach the DNS resolver or an outbound MTA-STS request.
    """
    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Domain must not be empty.")
    if len(raw) > DOMAIN_INPUT_MAX:
        raise ValueError("Domain input is too long.")

    if "://" in raw:
        parsed = urlsplit(raw)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP(S) URLs or bare domains are accepted.")
        if parsed.username or parsed.password:
            raise ValueError("Domain URLs must not contain credentials.")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("Domain URL contains an invalid port.") from exc
        if port is not None:
            raise ValueError("Domain URLs must not contain a port.")
        candidate = parsed.hostname or ""
    else:
        candidate = raw.split("/", maxsplit=1)[0]
        if any(character in candidate for character in "@:#?[]"):
            raise ValueError("Expected a bare domain without credentials, a port, or a query.")

    candidate = candidate.rstrip(".").lower()
    try:
        domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Domain contains invalid international characters.") from exc

    if not domain or len(domain) > DOMAIN_MAX:
        raise ValueError(f"Domain must be at most {DOMAIN_MAX} characters.")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError("IP addresses are not valid email domains.")

    labels = domain.split(".")
    if any(not _DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValueError("Domain contains an invalid DNS label.")
    return domain


def normalize_domains(values: Iterable[str]) -> list[str]:
    return [normalize_domain(value) for value in values]


def normalize_selectors(values: Iterable[str]) -> list[str]:
    selectors = _clean_unique(values, max_items=SELECTORS_MAX, item_max=SELECTOR_MAX, name="selector")
    for selector in selectors:
        labels = selector.lower().split(".")
        if any(not _SELECTOR_LABEL.fullmatch(label) for label in labels):
            raise ValueError(f"Invalid DKIM selector: {selector}")
    return [selector.lower() for selector in selectors]


def normalize_expected_providers(values: Iterable[str]) -> list[str]:
    return _clean_unique(
        values,
        max_items=EXPECTED_PROVIDERS_MAX,
        item_max=EXPECTED_PROVIDER_MAX,
        name="expected provider",
        casefold_output=False,
    )


def _clean_unique(
    values: Iterable[str],
    *,
    max_items: int,
    item_max: int,
    name: str,
    casefold_output: bool = True,
) -> list[str]:
    items = list(values)
    if len(items) > max_items:
        raise ValueError(f"At most {max_items} {name}s are allowed.")

    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in items:
        item = str(raw).strip()
        if not item:
            continue
        if len(item) > item_max or any(ord(character) < 32 for character in item):
            raise ValueError(f"Invalid {name}: value is too long or contains control characters.")
        identity = item.casefold()
        if identity in seen:
            continue
        seen.add(identity)
        cleaned.append(identity if casefold_output else item)
    return cleaned
