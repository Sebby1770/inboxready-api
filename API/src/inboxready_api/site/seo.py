"""Canonical URLs, social-card metadata, and JSON-LD structured data.

Structured data is generated from the same content the page renders, so the
markup can never drift from what a human reads — the most common cause of a
"structured data does not match visible content" penalty.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote, urlsplit

from inboxready_api.settings import Settings
from inboxready_api.site import content
from inboxready_api.site.pages import Page, breadcrumbs

#: Relative path of the social sharing card (checklist item 13).
SOCIAL_CARD_PATH = "img/social-card.svg"
SOCIAL_CARD_TYPE = "image/svg+xml"
SOCIAL_CARD_WIDTH = 1200
SOCIAL_CARD_HEIGHT = 630
SOCIAL_CARD_ALT = (
    "InboxReady social sharing card: the wordmark above the line "
    "'Email domain readiness in one API call' and the seven protocol checks."
)


def site_origin(settings: Settings, request_base_url: str = "") -> str:
    """Absolute origin used for canonical links, sitemap entries, and og:url."""
    configured = settings.site_base_url.strip()
    if configured:
        return configured.rstrip("/")
    parts = urlsplit(request_base_url or "http://127.0.0.1:8000")
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return "http://127.0.0.1:8000"


def absolute_url(origin: str, path: str) -> str:
    if path.startswith(("http://", "https://")):
        return path
    return f"{origin.rstrip('/')}/{path.lstrip('/')}" if path != "/" else f"{origin.rstrip('/')}/"


def directions_url() -> str:
    """A maps link that opens directions to the office (checklist item 14)."""
    return "https://www.google.com/maps/dir/?api=1&destination=" + quote(
        content.ORG.address.map_query
    )


def map_view_url() -> str:
    geo = content.ORG.geo
    return f"https://www.openstreetmap.org/?mlat={geo.latitude}&mlon={geo.longitude}#map=13/{geo.latitude}/{geo.longitude}"


def apple_maps_url() -> str:
    return "https://maps.apple.com/?daddr=" + quote(content.ORG.address.map_query)


# ---------------------------------------------------------------------------
# JSON-LD builders
# ---------------------------------------------------------------------------


def organisation_schema(origin: str) -> dict[str, Any]:
    org = content.ORG
    return {
        "@type": "Organization",
        "@id": f"{origin}/#organization",
        "name": org.name,
        "legalName": org.legal_name,
        "url": f"{origin}/",
        "email": f"mailto:{org.email}",
        "description": org.description,
        "foundingDate": org.founded,
        "logo": {
            "@type": "ImageObject",
            "url": absolute_url(origin, f"static/{org.logo_path}"),
        },
        "sameAs": list(org.social_profiles),
        "address": postal_address_schema(),
        "contactPoint": [
            {
                "@type": "ContactPoint",
                "contactType": "customer support",
                "email": org.email,
                "availableLanguage": ["English"],
                "areaServed": "Worldwide",
            }
        ],
    }


def postal_address_schema() -> dict[str, Any]:
    address = content.ORG.address
    schema: dict[str, Any] = {
        "@type": "PostalAddress",
        "addressLocality": address.locality,
        "addressRegion": address.region,
        "addressCountry": address.country_code,
    }
    if address.street:
        schema["streetAddress"] = address.street
    if address.postal_code:
        schema["postalCode"] = address.postal_code
    return schema


def local_business_schema(origin: str) -> dict[str, Any]:
    """``ProfessionalService`` — the LocalBusiness subtype that actually fits.

    Checklist item 17. Geo coordinates and opening hours are what let a search
    engine place the business on a map and answer "are they open now".
    """
    org = content.ORG
    schema: dict[str, Any] = {
        "@type": "ProfessionalService",
        "@id": f"{origin}/#localbusiness",
        "name": org.name,
        "image": absolute_url(origin, f"static/{SOCIAL_CARD_PATH}"),
        "url": f"{origin}/",
        "email": f"mailto:{org.email}",
        "description": org.description,
        "parentOrganization": {"@id": f"{origin}/#organization"},
        "address": postal_address_schema(),
        "geo": {
            "@type": "GeoCoordinates",
            "latitude": org.geo.latitude,
            "longitude": org.geo.longitude,
        },
        "areaServed": {"@type": "Place", "name": org.service_area},
        "openingHours": list(org.opening_hours),
        "priceRange": "$$",
        "hasMap": map_view_url(),
    }
    rating = content.average_rating()
    if rating is not None:
        # Emitted only when real reviews exist — see site.content.
        schema["aggregateRating"] = {
            "@type": "AggregateRating",
            "ratingValue": rating,
            "reviewCount": len(content.REVIEWS),
            "bestRating": 5,
            "worstRating": 1,
        }
        schema["review"] = [
            {
                "@type": "Review",
                "author": {"@type": "Person", "name": review.author},
                "datePublished": review.published,
                "reviewBody": review.body,
                "reviewRating": {
                    "@type": "Rating",
                    "ratingValue": review.rating,
                    "bestRating": 5,
                    "worstRating": 1,
                },
            }
            for review in content.REVIEWS
        ]
    return schema


def website_schema(origin: str) -> dict[str, Any]:
    return {
        "@type": "WebSite",
        "@id": f"{origin}/#website",
        "url": f"{origin}/",
        "name": content.ORG.name,
        "description": content.ORG.tagline,
        "publisher": {"@id": f"{origin}/#organization"},
        "inLanguage": "en",
        "potentialAction": {
            "@type": "SearchAction",
            "target": {
                "@type": "EntryPoint",
                "urlTemplate": f"{origin}/app?domain={{search_term_string}}",
            },
            "query-input": "required name=search_term_string",
        },
    }


def software_schema(origin: str, version: str) -> dict[str, Any]:
    return {
        "@type": "SoftwareApplication",
        "@id": f"{origin}/#software",
        "name": "InboxReady API",
        "applicationCategory": "DeveloperApplication",
        "operatingSystem": "Any (HTTP API)",
        "softwareVersion": version,
        "url": f"{origin}/",
        "publisher": {"@id": f"{origin}/#organization"},
        "offers": [
            {
                "@type": "Offer",
                "name": tier["name"],
                "price": str(tier["price"]).lstrip("$"),
                "priceCurrency": "USD",
                "url": f"{origin}/pricing",
                "availability": "https://schema.org/InStock",
            }
            for tier in _pricing_tiers()
        ],
    }


def _pricing_tiers() -> list[dict[str, Any]]:
    from inboxready_api.site_content import PRICING_TIERS

    return list(PRICING_TIERS)


def breadcrumb_schema(origin: str, page: Page) -> dict[str, Any] | None:
    """``BreadcrumbList`` for the visible breadcrumb trail (checklist item 05)."""
    trail = breadcrumbs(page)
    if len(trail) < 2:
        return None
    return {
        "@type": "BreadcrumbList",
        "itemListElement": [
            {
                "@type": "ListItem",
                "position": index,
                "name": crumb.breadcrumb_label,
                "item": absolute_url(origin, crumb.path),
            }
            for index, crumb in enumerate(trail, start=1)
        ],
    }


def faq_schema(origin: str) -> dict[str, Any]:
    """``FAQPage`` for the questions rendered on the page (checklist item 07)."""
    return {
        "@type": "FAQPage",
        "@id": f"{origin}/faq#faq",
        "mainEntity": [
            {
                "@type": "Question",
                "name": faq.question,
                "acceptedAnswer": {"@type": "Answer", "text": faq.answer},
            }
            for faq in content.faqs_for_schema()
        ],
    }


def case_study_schema(origin: str, study: content.CaseStudy) -> dict[str, Any]:
    return {
        "@type": "Article",
        "@id": absolute_url(origin, study.path) + "#article",
        "headline": study.title,
        "description": study.summary,
        "about": study.segment,
        "isAccessibleForFree": True,
        "publisher": {"@id": f"{origin}/#organization"},
        "mainEntityOfPage": absolute_url(origin, study.path),
        "disambiguatingDescription": (
            "Illustrative scenario describing a typical integration; not an account "
            "of a named customer."
        ),
    }


def person_schema(origin: str) -> list[dict[str, Any]]:
    """``Person`` entries for real team members only (checklist item 20)."""
    return [
        {
            "@type": "Person",
            "name": member.name,
            "jobTitle": member.role,
            "image": absolute_url(origin, f"static/{member.photo}"),
            "worksFor": {"@id": f"{origin}/#organization"},
            **({"url": member.profile_url} if member.profile_url else {}),
        }
        for member in content.TEAM
        if not member.placeholder
    ]


def build_json_ld(origin: str, page: Page, version: str) -> str:
    """Return the ``@graph`` payload for ``page`` as a JSON string."""
    graph: list[dict[str, Any]] = [
        organisation_schema(origin),
        local_business_schema(origin),
        website_schema(origin),
    ]

    crumbs = breadcrumb_schema(origin, page)
    if crumbs:
        graph.append(crumbs)

    if page.path == "/":
        graph.append(software_schema(origin, version))
    if page.path in {"/", "/faq"}:
        graph.append(faq_schema(origin))
    if page.path == "/pricing":
        graph.append(software_schema(origin, version))
    if page.path == "/about":
        graph.extend(person_schema(origin))
    if page.context_key:
        study = content.case_study_by_slug(page.context_key)
        if study is not None:
            graph.append(case_study_schema(origin, study))

    payload = {"@context": "https://schema.org", "@graph": graph}
    return json.dumps(payload, indent=2, ensure_ascii=False)


def social_meta(origin: str, page: Page) -> dict[str, str]:
    """Open Graph + Twitter card tags (checklist item 13)."""
    url = absolute_url(origin, page.path)
    image = absolute_url(origin, f"static/{SOCIAL_CARD_PATH}")
    return {
        "og:site_name": content.ORG.name,
        "og:type": page.og_type,
        "og:title": f"{page.title} · {content.ORG.name}",
        "og:description": page.description,
        "og:url": url,
        "og:image": image,
        "og:image:type": SOCIAL_CARD_TYPE,
        "og:image:width": str(SOCIAL_CARD_WIDTH),
        "og:image:height": str(SOCIAL_CARD_HEIGHT),
        "og:image:alt": SOCIAL_CARD_ALT,
        "og:locale": "en_AU",
        "twitter:card": "summary_large_image",
        "twitter:title": f"{page.title} · {content.ORG.name}",
        "twitter:description": page.description,
        "twitter:image": image,
        "twitter:image:alt": SOCIAL_CARD_ALT,
    }


def robots_txt(origin: str, *, indexable: bool) -> str:
    """``robots.txt`` body (checklist item 10).

    Non-production environments return a blanket disallow: a staging copy that
    gets indexed competes with the real site for its own keywords.
    """
    lines: list[str] = []
    if not indexable:
        lines += [
            "# Non-production environment — indexing is disabled on purpose.",
            "User-agent: *",
            "Disallow: /",
            "",
        ]
    else:
        lines += [
            "User-agent: *",
            "Allow: /",
            "",
            "# Machine surfaces: useful to humans, noise in a search index.",
            "Disallow: /docs",
            "Disallow: /redoc",
            "Disallow: /openapi.json",
            "Disallow: /thank-you",
            "Disallow: /healthz",
            "Disallow: /readyz",
            "Disallow: /v1/",
            "",
            "# Well-behaved crawlers only need one pass per page.",
            "Crawl-delay: 1",
            "",
        ]
    lines.append(f"Sitemap: {origin}/sitemap.xml")
    lines.append("")
    return "\n".join(lines)


def sitemap_xml(origin: str, lastmod: str) -> str:
    """``sitemap.xml`` for every indexable registered page."""
    from inboxready_api.site.pages import indexable_pages

    entries = "\n".join(
        "  <url>\n"
        f"    <loc>{absolute_url(origin, page.path)}</loc>\n"
        f"    <lastmod>{lastmod}</lastmod>\n"
        f"    <changefreq>{page.changefreq}</changefreq>\n"
        f"    <priority>{page.priority:.1f}</priority>\n"
        "  </url>"
        for page in indexable_pages()
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{entries}\n"
        "</urlset>\n"
    )
