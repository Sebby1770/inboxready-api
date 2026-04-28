from __future__ import annotations

from dataclasses import dataclass

from inboxready_api.models import ProviderMatch


@dataclass(frozen=True)
class ProviderFingerprint:
    name: str
    patterns: tuple[str, ...]
    suggested_selectors: tuple[str, ...] = ()
    confidence: float = 0.75


PROVIDER_FINGERPRINTS: tuple[ProviderFingerprint, ...] = (
    ProviderFingerprint(
        name="Google Workspace",
        patterns=("_spf.google.com", "googlemail.com"),
        suggested_selectors=("google", "selector1", "selector2"),
        confidence=0.88,
    ),
    ProviderFingerprint(
        name="Microsoft 365",
        patterns=("spf.protection.outlook.com", "mail.protection.outlook.com"),
        suggested_selectors=("selector1", "selector2"),
        confidence=0.88,
    ),
    ProviderFingerprint(
        name="Amazon SES",
        patterns=("amazonses.com",),
        suggested_selectors=("selector1", "selector2"),
        confidence=0.74,
    ),
    ProviderFingerprint(
        name="Mailgun",
        patterns=("mailgun.org", "mailgun.us"),
        suggested_selectors=("krs", "smtp", "mx"),
        confidence=0.82,
    ),
    ProviderFingerprint(
        name="SendGrid",
        patterns=("sendgrid.net",),
        suggested_selectors=("s1", "s2"),
        confidence=0.82,
    ),
    ProviderFingerprint(
        name="Postmark",
        patterns=("pm.mtasv.net", "postmarkapp.com"),
        suggested_selectors=("pm", "postmark"),
        confidence=0.8,
    ),
    ProviderFingerprint(
        name="Mailchimp Transactional",
        patterns=("servers.mcsv.net", "mandrillapp.com"),
        suggested_selectors=("mandrill", "k1", "k2"),
        confidence=0.8,
    ),
    ProviderFingerprint(
        name="HubSpot",
        patterns=("hubspotemail.net", "hsdomains.com"),
        suggested_selectors=("hs1", "hs2"),
        confidence=0.76,
    ),
    ProviderFingerprint(
        name="Zendesk",
        patterns=("zendesk.com", "zendeskmail.com"),
        suggested_selectors=("zendesk1", "zendesk2"),
        confidence=0.72,
    ),
    ProviderFingerprint(
        name="Klaviyo",
        patterns=("klaviyomail.com",),
        suggested_selectors=("kl", "fm1"),
        confidence=0.74,
    ),
)


def detect_providers(evidence_strings: list[str]) -> list[ProviderMatch]:
    haystack = "\n".join(evidence_strings).lower()
    matches: list[ProviderMatch] = []

    for fingerprint in PROVIDER_FINGERPRINTS:
        evidence = [
            pattern
            for pattern in fingerprint.patterns
            if pattern.lower() in haystack
        ]
        if evidence:
            matches.append(
                ProviderMatch(
                    name=fingerprint.name,
                    confidence=fingerprint.confidence,
                    evidence=evidence,
                    suggested_selectors=list(fingerprint.suggested_selectors),
                )
            )

    matches.sort(key=lambda item: item.confidence, reverse=True)
    return matches


def get_provider_catalog() -> list[ProviderMatch]:
    return [
        ProviderMatch(
            name=fingerprint.name,
            confidence=fingerprint.confidence,
            evidence=list(fingerprint.patterns),
            suggested_selectors=list(fingerprint.suggested_selectors),
        )
        for fingerprint in PROVIDER_FINGERPRINTS
    ]
