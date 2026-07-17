from __future__ import annotations

# Free mailbox / disposable providers — not suitable as custom sending domains.
FREE_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "yahoo.com",
        "yahoo.co.uk",
        "ymail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "aol.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "mail.com",
        "protonmail.com",
        "proton.me",
        "zoho.com",
        "gmx.com",
        "gmx.net",
        "yandex.com",
        "yandex.ru",
        "mail.ru",
        "qq.com",
        "163.com",
        "126.com",
        "mailinator.com",
        "guerrillamail.com",
        "guerrillamail.net",
        "sharklasers.com",
        "tempmail.com",
        "temp-mail.org",
        "10minutemail.com",
        "throwaway.email",
        "trashmail.com",
        "getnada.com",
        "yopmail.com",
        "dispostable.com",
        "maildrop.cc",
        "fakeinbox.com",
    }
)

# Substring patterns for known disposable / free providers (matched against full domain).
FREE_EMAIL_PATTERNS: tuple[str, ...] = (
    "mailinator",
    "guerrillamail",
    "tempmail",
    "temp-mail",
    "10minutemail",
    "throwaway",
    "trashmail",
    "yopmail",
    "dispostable",
    "maildrop",
    "fakeinbox",
    "sharklasers",
)


def is_free_email_domain(domain: str) -> bool:
    normalized = domain.strip().lower().rstrip(".")
    if not normalized:
        return False
    if normalized in FREE_EMAIL_DOMAINS:
        return True
    return any(pattern in normalized for pattern in FREE_EMAIL_PATTERNS)


def free_email_warning_message(domain: str) -> str:
    return (
        f"'{domain}' looks like a free or disposable mailbox provider, "
        "not a custom sending domain you control."
    )
