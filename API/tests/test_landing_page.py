"""The landing page's own design surface.

The home page carries its own stylesheet and script, and a few pieces of it
make claims — a demo trace, an animated diagram — that have to stay honest and
accessible as the copy changes.
"""

from __future__ import annotations

from pathlib import Path

from _html import Html

STATIC = Path(__file__).resolve().parents[1] / "src" / "inboxready_api" / "static"


def home(client) -> Html:
    response = client.get("/")
    assert response.status_code == 200
    return Html(response.text)


def test_home_loads_its_own_stylesheet_and_script(client) -> None:
    page = home(client)
    assert "css/home.css" in page.raw
    assert "js/home.js" in page.raw
    assert (STATIC / "css" / "home.css").exists()
    assert (STATIC / "js" / "home.js").exists()


def test_landing_assets_are_not_pulled_into_other_pages(client) -> None:
    """The heavy landing treatment is scoped to the one page that needs it."""
    for path in ("/pricing", "/faq", "/about", "/app"):
        body = client.get(path).text
        assert "css/home.css" not in body, f"{path} loads the landing stylesheet"
        assert "js/home.js" not in body, f"{path} loads the landing script"


def test_demo_trace_is_labelled_as_a_demo() -> None:
    """
    The hero console shows a plausible-looking audit before the visitor runs
    one. It must never read as a real result for a real domain.
    """
    script = (STATIC / "js" / "home.js").read_text(encoding="utf-8")
    assert "# demo trace — enter a domain above for live results" in script
    # And it must get out of the way the moment a real audit starts.
    assert 'form.addEventListener("submit", stop' in script


def test_hero_console_hosts_the_real_audit_form(client) -> None:
    page = home(client)
    forms = page.find_all("form", **{"class": "audit-form console-form"})
    assert forms, "the hero console has no audit form"
    assert 'data-results-target="hero-results"' in page.raw
    assert 'id="hero-results"' in page.raw


def test_chain_diagram_is_described_for_screen_readers(client) -> None:
    page = home(client)
    svg = page.find_all("svg", **{"class": "chain-svg"})
    assert svg, "the authentication chain diagram is missing"
    assert svg[0].attrs.get("role") == "img"
    assert svg[0].attrs.get("aria-labelledby") == "chain-title chain-desc"
    assert 'id="chain-title"' in page.raw
    assert 'id="chain-desc"' in page.raw
    # The description has to carry the meaning, not just name the picture.
    assert "spam folder" in page.text


def test_chain_gradient_uses_user_space_units(client) -> None:
    """
    An objectBoundingBox gradient on a perfectly horizontal line has a
    zero-height box and renders as nothing. This caught a real regression.
    """
    page = home(client)
    assert 'gradientUnits="userSpaceOnUse"' in page.raw


def test_marquee_duplicate_is_hidden_from_assistive_tech(client) -> None:
    page = home(client)
    groups = page.find_all("ul", **{"class": "marquee-group"})
    assert len(groups) == 2, "the marquee needs exactly two passes to loop seamlessly"
    assert groups[1].attrs.get("aria-hidden") == "true"
    assert groups[0].attrs.get("aria-hidden") is None


def test_decorative_motion_respects_reduced_motion() -> None:
    css = (STATIC / "css" / "home.css").read_text(encoding="utf-8")
    block = css[css.index("@media (prefers-reduced-motion: reduce)") :]
    for selector in (".marquee-track", ".chain-packet", ".hero-underline path", ".trace li"):
        assert selector in block, f"{selector} keeps animating under reduced motion"


def test_stamp_perforation_does_not_depend_on_mask_compositing() -> None:
    """
    The perforated edge is painted with background gradients. A mask-based
    version silently erased the whole card in browsers that disagree about
    `mask-composite`, so the technique is deliberately boring.
    """
    css = (STATIC / "css" / "home.css").read_text(encoding="utf-8")
    stamp = css[css.index(".stamp-card {") : css.index(".stamp-inner {")]
    assert "mask-composite" not in stamp
    assert "radial-gradient" in stamp


def test_no_inline_scripts_anywhere(client) -> None:
    """
    The CSP is `script-src 'self'`. Any inline <script> other than the
    JSON-LD data block would silently stop executing in production.
    """
    for path in ("/", "/app", "/contact", "/pricing"):
        page = Html(client.get(path).text)
        for tag in page.find_all("script"):
            script_type = tag.attrs.get("type", "")
            if script_type == "application/ld+json":
                continue
            assert tag.attrs.get("src"), f"{path} has an inline <script>"


def test_reveal_animation_cannot_permanently_hide_content(client) -> None:
    """Content must survive a scroll observer that never fires."""
    body = client.get("/").text
    assert "<noscript>" in body
    site_js = (STATIC / "js" / "site.js").read_text(encoding="utf-8")
    assert "initRevealFailsafe" in site_js
    assert "window.setTimeout(reveal" in site_js
