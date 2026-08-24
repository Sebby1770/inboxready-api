"""One test per item on the conversion / SEO checklist.

The product audits other people's domains for the things they forgot to
configure. It would be embarrassing for its own front door to fail the
equivalent review, so each of the twenty items is asserted here rather than
being left to a manual pass before a launch.

Test names carry the item number so a failure names the thing that regressed.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from _html import Html
from inboxready_api.settings import get_settings
from inboxready_api.site import content, seo
from inboxready_api.site.pages import (
    ALL_PAGES,
    DESCRIPTION_MAX,
    DESCRIPTION_MIN,
    TITLE_MAX,
    indexable_pages,
)

STATIC_DIR = Path(__file__).resolve().parents[1] / "src" / "inboxready_api" / "static"

#: Every page a crawler or a human can reach, used by the sweep-style tests.
PAGE_PATHS = [page.path for page in ALL_PAGES]


@pytest.fixture(scope="module")
def rendered(request) -> dict[str, Html]:
    """Render every registered page once and reuse it across the sweeps."""
    client = request.getfixturevalue("client")
    pages: dict[str, Html] = {}
    for path in PAGE_PATHS:
        response = client.get(path)
        assert response.status_code == 200, f"{path} returned {response.status_code}"
        pages[path] = Html(response.text)
    return pages


# ---------------------------------------------------------------------------
# 01 — custom 404 page
# ---------------------------------------------------------------------------


def test_01_custom_404_page_is_branded_and_helpful(client) -> None:
    response = client.get("/this-page-does-not-exist")

    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"]

    page = Html(response.text)
    assert "InboxReady" in response.text
    assert "404" in response.text

    # A 404 that only apologises wastes the visit; this one has to route people on.
    destinations = set(page.internal_links())
    for wanted in {"/", "/app", "/contact", "/pricing", "/product"}:
        assert wanted in destinations, f"404 page does not offer {wanted}"

    # It must never be indexed, however helpful it is.
    assert page.meta(name="robots") == "noindex, nofollow"


def test_01_api_clients_still_get_json_404s(client) -> None:
    response = client.get("/v1/does-not-exist")

    assert response.status_code == 404
    assert response.headers["content-type"].startswith("application/json")
    assert "detail" in response.json()


def test_01_unknown_case_study_slug_renders_the_404_page(client) -> None:
    response = client.get("/case-studies/not-a-real-slug")

    assert response.status_code == 404
    assert "text/html" in response.headers["content-type"]


# ---------------------------------------------------------------------------
# 02 — CTA above the fold
# ---------------------------------------------------------------------------


def test_02_primary_cta_appears_above_the_fold(rendered) -> None:
    home = rendered["/"]
    body = home.raw[home.raw.index("<main"):]

    cta_at = body.index('data-cta="hero-primary"')
    # The first section heading marks the start of "keep scrolling" content.
    first_h2_at = body.index("<h2")

    assert cta_at < first_h2_at, "the primary CTA sits below the first section heading"
    assert cta_at < len(body) * 0.25, "the primary CTA is too far down the document"

    # And it has to be a real action, not a nav link.
    assert "Run a free domain audit" in body[:first_h2_at]


@pytest.mark.parametrize(
    "path",
    ["/", "/product", "/case-studies", "/pricing", "/faq", "/about", "/contact"],
)
def test_02_every_marketing_page_opens_with_a_call_to_action(rendered, path) -> None:
    page = rendered[path]
    body = page.raw[page.raw.index("<main"):]
    hero = body[: body.index("</section>")]

    assert 'class="button' in hero, f"{path} has no call to action in its hero"
    assert "above-the-fold" in hero


# ---------------------------------------------------------------------------
# 03 — internal links
# ---------------------------------------------------------------------------


def test_03_every_page_links_to_several_others(rendered) -> None:
    for path, page in rendered.items():
        others = {link for link in page.internal_links() if link and link != path}
        assert len(others) >= 5, f"{path} links to only {len(others)} other internal pages"


def test_03_no_page_is_orphaned_from_the_home_page(rendered) -> None:
    """Every indexable page must be reachable from `/` within two hops."""
    reachable = {"/"}
    frontier = ["/"]
    for _ in range(2):
        next_frontier: list[str] = []
        for path in frontier:
            for link in rendered[path].internal_links():
                if link in rendered and link not in reachable:
                    reachable.add(link)
                    next_frontier.append(link)
        frontier = next_frontier

    orphans = {page.path for page in indexable_pages()} - reachable
    assert not orphans, f"unreachable from the home page in two hops: {sorted(orphans)}"


def test_03_internal_links_all_resolve(client, rendered) -> None:
    """No internal link may 404 — the cheapest possible broken-link check."""
    targets = {
        link
        for page in rendered.values()
        for link in page.internal_links()
        if link and not link.startswith("/static/")
    }
    for target in sorted(targets):
        assert client.get(target).status_code == 200, f"broken internal link: {target}"


# ---------------------------------------------------------------------------
# 04 — thank you page
# ---------------------------------------------------------------------------


def test_04_contact_submission_redirects_to_the_thank_you_page(client) -> None:
    response = client.post(
        "/contact",
        data={
            "name": "Dana Okafor",
            "email": "dana@example.com",
            "company": "Example Co",
            "topic": "Integration help",
            "message": "We want to gate activation on the audit score. How do you suggest we do it?",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/thank-you?ref=contact"


def test_04_thank_you_page_confirms_and_keeps_the_visitor_moving(client) -> None:
    response = client.get("/thank-you")
    page = Html(response.text)

    assert response.status_code == 200
    assert "Thanks" in page.title()
    # It is a conversion destination, so it must be excluded from the index.
    assert page.meta(name="robots") == "noindex, nofollow"
    assert response.headers["cache-control"] == "no-store"
    # And it must fire a measurable conversion event.
    assert 'data-conversion="contact"' in response.text
    assert {"/app", "/faq", "/case-studies"} <= set(page.internal_links())


# ---------------------------------------------------------------------------
# 05 — breadcrumbs
# ---------------------------------------------------------------------------


def test_05_child_pages_render_a_breadcrumb_trail(rendered) -> None:
    page = rendered["/case-studies/support-triage"]

    assert '<nav class="breadcrumbs" aria-label="Breadcrumb">' in page.raw
    crumbs = page.graph("BreadcrumbList")
    assert crumbs, "no BreadcrumbList structured data"
    items = crumbs[0]["itemListElement"]
    assert [item["position"] for item in items] == [1, 2, 3]
    assert items[0]["name"] == "Home"
    assert items[-1]["item"].endswith("/case-studies/support-triage")


def test_05_home_page_has_no_breadcrumb(rendered) -> None:
    home = rendered["/"]
    assert 'aria-label="Breadcrumb"' not in home.raw
    assert not home.graph("BreadcrumbList")


def test_05_visible_breadcrumbs_match_the_structured_data(rendered) -> None:
    for path in ("/pricing", "/about", "/case-studies/portfolio-monitoring"):
        page = rendered[path]
        crumbs = page.graph("BreadcrumbList")[0]["itemListElement"]
        for crumb in crumbs:
            assert crumb["name"] in page.text, f"{path}: {crumb['name']} is not visible on the page"


# ---------------------------------------------------------------------------
# 06 — case studies
# ---------------------------------------------------------------------------


def test_06_case_study_index_lists_every_study(rendered) -> None:
    index = rendered["/case-studies"]
    for study in content.CASE_STUDIES:
        assert study.path in index.raw
        assert study.title in index.text


def test_06_each_case_study_has_its_own_page_and_article_schema(rendered) -> None:
    assert len(content.CASE_STUDIES) >= 3
    for study in content.CASE_STUDIES:
        page = rendered[study.path]
        assert study.challenge in page.text
        assert study.outcome in page.text
        article = page.graph("Article")
        assert article, f"{study.path} has no Article structured data"
        assert article[0]["headline"] == study.title


def test_06_illustrative_studies_are_labelled_as_such(rendered) -> None:
    """We do not have named customers yet, and must not imply that we do."""
    for study in content.CASE_STUDIES:
        if not study.illustrative:
            continue
        page = rendered[study.path]
        assert "Illustrative scenario" in page.raw
        assert "not an account of a named customer" in page.raw


# ---------------------------------------------------------------------------
# 07 — five FAQs
# ---------------------------------------------------------------------------


def test_07_at_least_five_faqs_exist_and_render(rendered) -> None:
    assert len(content.FAQS) >= 5

    faq_page = rendered["/faq"]
    for faq in content.FAQS:
        assert faq.question in faq_page.text
        assert faq.answer in faq_page.text


def test_07_home_page_surfaces_five_faqs(rendered) -> None:
    home = rendered["/"]
    rendered_questions = [faq.question for faq in content.FAQS if faq.question in home.text]
    assert len(rendered_questions) >= 5


def test_07_faq_schema_matches_the_rendered_questions(rendered) -> None:
    faq_page = rendered["/faq"]
    schema = faq_page.graph("FAQPage")[0]
    questions = [entry["name"] for entry in schema["mainEntity"]]

    assert len(questions) >= 5
    for question in questions:
        assert question in faq_page.text, "FAQ schema advertises a question the page does not show"


# ---------------------------------------------------------------------------
# 08 — response time promise
# ---------------------------------------------------------------------------


def test_08_response_promise_appears_on_every_page(rendered) -> None:
    promise = content.response_promise(get_settings().support_response_hours)
    for path, page in rendered.items():
        assert promise.headline in page.raw, f"{path} does not state the response promise"


def test_08_contact_page_states_the_promise_before_the_form(rendered) -> None:
    page = rendered["/contact"]
    promise = content.response_promise(get_settings().support_response_hours)

    assert page.raw.index(promise.headline) < page.raw.index("<form")
    assert "Monday to Friday" in page.raw


def test_08_promise_tracks_the_configured_response_window() -> None:
    assert content.response_promise(24).headline == "We reply within 1 business day"
    assert content.response_promise(48).headline == "We reply within 2 business days"
    assert content.response_promise(1).headline == "We reply within the hour"
    assert content.response_promise(4).headline == "We reply within 4 hours"


# ---------------------------------------------------------------------------
# 09 — sticky mobile CTA
# ---------------------------------------------------------------------------


def test_09_sticky_mobile_cta_is_present_and_dismissible(rendered) -> None:
    home = rendered["/"]

    assert "data-sticky-cta" in home.raw
    assert 'data-cta="sticky-mobile"' in home.raw
    assert "data-sticky-dismiss" in home.raw
    # Hidden server-side; the script decides when it earns the space.
    bar = home.find_all("div", **{"class": "sticky-cta"})
    assert bar and "hidden" in bar[0].attrs


def test_09_sticky_cta_is_mobile_only_and_respects_the_safe_area() -> None:
    css = (STATIC_DIR / "css" / "site.css").read_text(encoding="utf-8")
    assert "@media (min-width: 761px) {\n  .sticky-cta {\n    display: none;" in css
    assert "env(safe-area-inset-bottom)" in css


def test_09_sticky_cta_never_shadows_the_page_it_points_at() -> None:
    script = (STATIC_DIR / "js" / "site.js").read_text(encoding="utf-8")
    assert 'document.body.dataset.page === "/app"' in script


# ---------------------------------------------------------------------------
# 10 — robots.txt
# ---------------------------------------------------------------------------


def test_10_robots_txt_is_served_with_a_sitemap_reference(client, configured) -> None:
    configured(environment="production", site_base_url="https://inboxready.dev")
    response = client.get("/robots.txt")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    assert "User-agent: *" in body
    assert "Allow: /" in body
    assert "Sitemap: https://inboxready.dev/sitemap.xml" in body
    # Machine surfaces should not compete with the marketing pages in the index.
    assert "Disallow: /v1/" in body
    assert "Disallow: /thank-you" in body


def test_10_non_production_environments_are_not_indexable(client, configured) -> None:
    configured(environment="staging")
    body = client.get("/robots.txt").text

    assert "Disallow: /" in body
    assert "Allow: /" not in body


def test_10_pages_are_noindex_outside_production(client, configured) -> None:
    configured(environment="staging")
    assert Html(client.get("/").text).meta(name="robots") == "noindex, nofollow"

    configured(environment="production")
    assert Html(client.get("/").text).meta(name="robots") == "index, follow"


# ---------------------------------------------------------------------------
# 11 — unique page titles
# ---------------------------------------------------------------------------


def test_11_every_page_declares_a_title(rendered) -> None:
    for path, page in rendered.items():
        assert page.title(), f"{path} has an empty <title>"


def test_11_titles_are_unique_across_the_site(rendered) -> None:
    titles = [page.title() for page in rendered.values()]
    duplicates = {title for title in titles if titles.count(title) > 1}
    assert not duplicates, f"duplicate <title> values: {duplicates}"


def test_11_titles_survive_serp_truncation() -> None:
    for page in ALL_PAGES:
        assert len(page.title) <= TITLE_MAX, f"{page.path}: title is {len(page.title)} chars"
        assert page.title == page.title.strip()


# ---------------------------------------------------------------------------
# 12 — meta descriptions
# ---------------------------------------------------------------------------


def test_12_every_page_has_a_meta_description(rendered) -> None:
    for path, page in rendered.items():
        description = page.meta(name="description")
        assert description, f"{path} has no meta description"


def test_12_meta_descriptions_are_unique(rendered) -> None:
    descriptions = [page.meta(name="description") for page in rendered.values()]
    duplicates = {item for item in descriptions if descriptions.count(item) > 1}
    assert not duplicates, f"duplicate meta descriptions: {duplicates}"


def test_12_meta_descriptions_are_sensibly_sized() -> None:
    for page in ALL_PAGES:
        length = len(page.description)
        assert DESCRIPTION_MIN <= length <= DESCRIPTION_MAX, (
            f"{page.path}: description is {length} chars "
            f"(want {DESCRIPTION_MIN}–{DESCRIPTION_MAX})"
        )


# ---------------------------------------------------------------------------
# 13 — social share image
# ---------------------------------------------------------------------------


def test_13_open_graph_and_twitter_cards_are_complete(rendered) -> None:
    for path, page in rendered.items():
        assert page.meta(property="og:title"), f"{path} has no og:title"
        assert page.meta(property="og:description"), f"{path} has no og:description"
        assert page.meta(property="og:image"), f"{path} has no og:image"
        assert page.meta(property="og:image:alt"), f"{path} has no og:image:alt"
        assert page.meta(property="og:url", ) == page.find_all("link", rel="canonical")[0].attrs["href"]
        assert page.meta(name="twitter:card") == "summary_large_image"


def test_13_the_social_card_asset_exists_and_is_served(client) -> None:
    asset = STATIC_DIR / seo.SOCIAL_CARD_PATH
    assert asset.exists(), "the social card referenced by og:image is missing"

    response = client.get(f"/static/{seo.SOCIAL_CARD_PATH}")
    assert response.status_code == 200
    assert "svg" in response.headers["content-type"]
    # The card has to carry the pitch on its own, away from the page.
    assert "InboxReady" in response.text or "INBOXREADY" in response.text


def test_13_social_image_urls_are_absolute(client, configured) -> None:
    configured(site_base_url="https://inboxready.dev")
    page = Html(client.get("/pricing").text)
    assert page.meta(property="og:image").startswith("https://inboxready.dev/static/")


# ---------------------------------------------------------------------------
# 14 — maps and directions
# ---------------------------------------------------------------------------


def test_14_contact_page_shows_a_map_and_offers_directions(rendered) -> None:
    page = rendered["/contact"]

    maps = page.find_all("img", **{"class": "static-map"})
    assert maps, "no map on the contact page"
    assert len(maps[0].attrs.get("alt", "")) > 30, "the map needs a descriptive alt text"

    assert seo.directions_url() in page.text
    assert seo.apple_maps_url() in page.text
    assert "Directions in Google Maps" in page.raw


def test_14_directions_links_point_at_the_published_address() -> None:
    assert "Melbourne" in seo.directions_url()
    assert seo.directions_url().startswith("https://www.google.com/maps/dir/")
    assert seo.apple_maps_url().startswith("https://maps.apple.com/?daddr=")


def test_14_every_page_footer_offers_directions(rendered) -> None:
    for path, page in rendered.items():
        assert "Get directions" in page.raw, f"{path} footer has no directions link"


# ---------------------------------------------------------------------------
# 15 — real reviews
# ---------------------------------------------------------------------------


def test_15_no_invented_reviews_ship_by_default() -> None:
    """Guard rail: fabricated testimonials must never creep into the repo."""
    assert content.REVIEWS == (), (
        "REVIEWS must stay empty until real, attributable reviews exist"
    )
    assert content.average_rating() is None


def test_15_aggregate_rating_is_withheld_when_there_are_no_reviews(rendered) -> None:
    business = rendered["/"].graph("ProfessionalService")[0]
    assert "aggregateRating" not in business, (
        "AggregateRating markup with no reviews behind it is a structured-data violation"
    )
    assert "review" not in business


def test_15_checkable_proof_is_shown_in_place_of_testimonials(rendered) -> None:
    home = rendered["/"]
    assert "No testimonials yet" in home.raw
    for signal in content.TRUST_SIGNALS:
        assert signal.label in home.text
        assert signal.href in home.text


def test_15_real_reviews_render_and_produce_schema(client, monkeypatch) -> None:
    review = content.Review(
        author="Sam Rivera",
        author_title="Platform lead, Example Co",
        rating=5,
        body="The audit replaced a three-day support loop with a single screen.",
        published="2026-08-01",
        source="G2",
        source_url="https://www.g2.com/",
    )
    monkeypatch.setattr(content, "REVIEWS", (review,))

    page = Html(client.get("/").text)
    assert review.body in page.text
    assert review.author in page.text

    business = page.graph("ProfessionalService")[0]
    assert business["aggregateRating"]["ratingValue"] == 5
    assert business["aggregateRating"]["reviewCount"] == 1
    assert business["review"][0]["author"]["name"] == "Sam Rivera"


# ---------------------------------------------------------------------------
# 16 — alt text on images
# ---------------------------------------------------------------------------


def test_16_every_image_has_alt_text_or_is_explicitly_decorative(rendered) -> None:
    for path, page in rendered.items():
        for image in page.find_all("img"):
            assert "alt" in image.attrs, f"{path}: <img src={image.attrs.get('src')}> has no alt attribute"
            if image.attrs["alt"] == "":
                assert image.attrs.get("aria-hidden") == "true", (
                    f"{path}: empty alt on a non-decorative image ({image.attrs.get('src')})"
                )


def test_16_meaningful_images_have_descriptive_alt_text(rendered) -> None:
    """An alt of 'image' or 'photo' is worse than none — it defeats the fallback."""
    useless = {"image", "photo", "picture", "logo", "icon", "graphic"}
    for path, page in rendered.items():
        for image in page.find_all("img"):
            alt = image.attrs.get("alt", "").strip().lower()
            if not alt:
                continue
            assert alt not in useless, f"{path}: unhelpful alt text {alt!r}"
            assert len(alt) >= 10, f"{path}: alt text {alt!r} is too terse to be useful"


def test_16_inline_svgs_are_labelled(client) -> None:
    for asset in ("img/favicon.svg", "img/social-card.svg", "img/map-melbourne.svg"):
        markup = client.get(f"/static/{asset}").text
        assert "<title>" in markup or 'role="img"' in markup, f"{asset} is unlabelled"


# ---------------------------------------------------------------------------
# 17 — local schema
# ---------------------------------------------------------------------------


def test_17_every_page_carries_valid_json_ld(rendered) -> None:
    for path, page in rendered.items():
        payload = page.json_ld()
        assert payload["@context"] == "https://schema.org", path
        assert isinstance(payload["@graph"], list) and payload["@graph"], path


def test_17_local_business_schema_is_complete(rendered) -> None:
    business = rendered["/"].graph("ProfessionalService")[0]

    assert business["name"] == content.ORG.name
    assert business["address"]["addressLocality"] == "Melbourne"
    assert business["address"]["addressCountry"] == "AU"
    assert business["geo"]["latitude"] == content.ORG.geo.latitude
    assert business["geo"]["longitude"] == content.ORG.geo.longitude
    assert business["openingHours"] == list(content.ORG.opening_hours)
    assert business["hasMap"].startswith("https://www.openstreetmap.org/")


def test_17_organisation_and_website_schema_are_linked(rendered) -> None:
    home = rendered["/"]
    organisation = home.graph("Organization")[0]
    website = home.graph("WebSite")[0]

    assert website["publisher"]["@id"] == organisation["@id"]
    assert organisation["email"].startswith("mailto:")
    assert "potentialAction" in website


def test_17_structured_data_matches_the_visible_address(rendered) -> None:
    contact = rendered["/contact"]
    address = contact.graph("ProfessionalService")[0]["address"]
    assert address["addressLocality"] in contact.text
    assert address["addressRegion"] in contact.text


# ---------------------------------------------------------------------------
# 18 — privacy policy page
# ---------------------------------------------------------------------------


def test_18_privacy_policy_exists_and_covers_the_essentials(rendered) -> None:
    page = rendered["/privacy"]
    raw = page.raw.lower()

    for topic in ("what we collect", "lawful basis", "retention", "your rights", "controller"):
        assert topic in raw, f"the privacy policy does not cover {topic!r}"
    assert content.ORG.email in page.raw


def test_18_privacy_policy_is_linked_from_every_page(rendered) -> None:
    for path, page in rendered.items():
        assert "/privacy" in page.internal_links(), f"{path} does not link to the privacy policy"


def test_18_supporting_legal_pages_exist(rendered) -> None:
    assert "Terms of service" in rendered["/terms"].raw
    assert "responsible disclosure" in rendered["/security"].raw.lower()


# ---------------------------------------------------------------------------
# 19 — Google Analytics
# ---------------------------------------------------------------------------


def test_19_no_analytics_ships_until_a_measurement_id_is_configured(client, configured) -> None:
    configured(analytics_ga4_id="")
    body = client.get("/").text

    assert "googletagmanager" not in body
    assert "analytics.js" not in body
    assert "data-consent-banner" not in body


def test_19_analytics_loads_behind_a_consent_gate_when_configured(client, configured) -> None:
    configured(analytics_ga4_id="G-TEST12345", analytics_require_consent="true")
    body = client.get("/").text

    assert 'data-ga4-id="G-TEST12345"' in body
    assert 'data-require-consent="true"' in body
    assert "data-consent-banner" in body
    assert "/privacy" in body


def test_19_analytics_script_defaults_consent_to_denied() -> None:
    script = (STATIC_DIR / "js" / "analytics.js").read_text(encoding="utf-8")

    assert 'analytics_storage: granted ? "granted" : "denied"' in script
    assert "ad_storage: \"denied\"" in script
    assert "doNotTrack" in script
    # Nothing may be requested from Google before the visitor opts in.
    assert "if (REQUIRE_CONSENT && !granted)" in script


def test_19_csp_only_opens_up_for_analytics_when_it_is_enabled(client, configured) -> None:
    configured(analytics_ga4_id="")
    tight = client.get("/").headers["content-security-policy"]
    assert "googletagmanager" not in tight
    assert "script-src 'self'" in tight

    configured(analytics_ga4_id="G-TEST12345")
    relaxed = client.get("/").headers["content-security-policy"]
    assert "https://www.googletagmanager.com" in relaxed


def test_19_conversions_are_instrumented(rendered) -> None:
    script = (STATIC_DIR / "js" / "site.js").read_text(encoding="utf-8")
    assert "generate_lead" in script
    assert "cta_click" in script
    assert 'data-cta="hero-primary"' in rendered["/"].raw


# ---------------------------------------------------------------------------
# 20 — team photo
# ---------------------------------------------------------------------------


def test_20_about_page_shows_a_team_photo_and_portraits(rendered) -> None:
    page = rendered["/about"]

    assert content.TEAM_PHOTO["alt"] in page.text
    assert page.find_all("figure", **{"class": "team-photo panel"})

    portraits = page.find_all("img", **{"class": "team-portrait"})
    assert len(portraits) == len(content.TEAM)
    for portrait in portraits:
        assert len(portrait.attrs.get("alt", "")) > 10
        assert portrait.attrs.get("loading") == "lazy"


def test_20_team_images_are_served(client) -> None:
    for member in content.TEAM:
        assert client.get(f"/static/{member.photo}").status_code == 200
    assert client.get(f"/static/{content.TEAM_PHOTO['src']}").status_code == 200


def test_20_placeholder_profiles_are_labelled_and_excluded_from_schema(rendered) -> None:
    page = rendered["/about"]

    if any(member.placeholder for member in content.TEAM):
        assert "Placeholder" in page.raw
    real_people = [member for member in content.TEAM if not member.placeholder]
    assert len(page.graph("Person")) == len(real_people), (
        "Person structured data must describe real people only"
    )


# ---------------------------------------------------------------------------
# Cross-cutting: the checklist is only useful if the plumbing holds
# ---------------------------------------------------------------------------


def test_sitemap_lists_every_indexable_page(client, configured) -> None:
    configured(site_base_url="https://inboxready.dev")
    response = client.get("/sitemap.xml")

    assert response.status_code == 200
    root = ET.fromstring(response.text)
    namespace = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    locations = {element.text for element in root.iter(f"{namespace}loc")}

    for page in indexable_pages():
        expected = seo.absolute_url("https://inboxready.dev", page.path)
        assert expected in locations, f"{page.path} is missing from the sitemap"

    assert not any("/thank-you" in (loc or "") for loc in locations)


def test_canonical_urls_are_absolute_and_self_referential(client, configured) -> None:
    configured(site_base_url="https://inboxready.dev")
    for page in ALL_PAGES:
        html = Html(client.get(page.path).text)
        canonical = html.find_all("link", rel="canonical")[0].attrs["href"]
        assert canonical == seo.absolute_url("https://inboxready.dev", page.path)


def test_security_headers_are_present_on_html(client) -> None:
    headers = client.get("/").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]


def test_page_registry_is_the_single_source_of_truth() -> None:
    paths = [page.path for page in ALL_PAGES]
    assert len(paths) == len(set(paths)), "duplicate page paths in the registry"
    for page in ALL_PAGES:
        if page.parent:
            assert page.parent in paths, f"{page.path} has a dangling parent {page.parent}"


def test_site_pages_inventory_endpoint_matches_the_registry(client) -> None:
    payload = client.get("/site/pages").json()
    assert payload["count"] == len(ALL_PAGES)
    assert {entry["path"] for entry in payload["pages"]} == {page.path for page in ALL_PAGES}
    assert json.dumps(payload)  # serialisable, so it is usable by a link checker
