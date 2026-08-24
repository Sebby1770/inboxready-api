# Growth checklist — what shipped, and where it lives

InboxReady audits other people's domains for the things they forgot to set up.
Its own front door is held to the same standard: a twenty-item conversion and
SEO checklist, each item implemented in code and each one guarded by a test in
[`API/tests/test_growth_checklist.py`](../API/tests/test_growth_checklist.py).

Test names carry the item number, so a regression names the thing that broke:

```bash
cd API && pytest tests/test_growth_checklist.py -v
```

| # | Item | Where it lives | Guarded by |
| --- | --- | --- | --- |
| 01 | Custom 404 page | [`templates/error.html`](../API/src/inboxready_api/templates/error.html), `render_not_found()` in [`site/router.py`](../API/src/inboxready_api/site/router.py) | `test_01_*` |
| 02 | CTA above the fold | [`templates/index.html`](../API/src/inboxready_api/templates/index.html) hero; every page hero carries `.above-the-fold` | `test_02_*` |
| 03 | Internal links | [`site/pages.py`](../API/src/inboxready_api/site/pages.py) drives header, footer, and in-body links | `test_03_*` |
| 04 | Thank-you page | `/thank-you` + the `303` from `POST /contact` | `test_04_*` |
| 05 | Breadcrumbs | `base.html` trail + `BreadcrumbList` from [`site/seo.py`](../API/src/inboxready_api/site/seo.py) | `test_05_*` |
| 06 | Case studies | `/case-studies` index and three detail pages, `Article` schema | `test_06_*` |
| 07 | Five FAQs | eight in [`site/content.py`](../API/src/inboxready_api/site/content.py), `FAQPage` schema on `/` and `/faq` | `test_07_*` |
| 08 | Response-time promise | `ResponsePromise`, rendered on every page and above the contact form | `test_08_*` |
| 09 | Sticky mobile CTA | `.sticky-cta` in `base.html`, driven by [`static/js/site.js`](../API/src/inboxready_api/static/js/site.js) | `test_09_*` |
| 10 | robots.txt | `GET /robots.txt`, environment-aware | `test_10_*` |
| 11 | Unique page titles | `Page.title` in the registry, ≤ 60 characters | `test_11_*` |
| 12 | Meta descriptions | `Page.description`, 70–165 characters, unique | `test_12_*` |
| 13 | Social share image | [`static/img/social-card.svg`](../API/src/inboxready_api/static/img/social-card.svg) + OG/Twitter tags | `test_13_*` |
| 14 | Maps + directions | `/contact` static map, Google/Apple/OSM links, `geo` in schema | `test_14_*` |
| 15 | Real reviews | `REVIEWS` in `site/content.py` — **empty by design** | `test_15_*` |
| 16 | Alt text on images | every `<img>`, swept across all pages | `test_16_*` |
| 17 | Local schema | `ProfessionalService` + `Organization` + `WebSite` JSON-LD | `test_17_*` |
| 18 | Privacy policy | `/privacy`, plus `/terms` and `/security` | `test_18_*` |
| 19 | Google Analytics | [`static/js/analytics.js`](../API/src/inboxready_api/static/js/analytics.js), consent-gated | `test_19_*` |
| 20 | Team photo | `/about`, `TEAM` + `TEAM_PHOTO` in `site/content.py` | `test_20_*` |

## Three items need your content, not more code

The mechanism is built for all twenty. Three of them are only *finished* once a
human supplies something that cannot be honestly invented.

### 15 — Reviews

`REVIEWS` ships as an empty tuple, and the home page renders four checkable
trust signals in its place. This is deliberate:

- inventing testimonials and attributing them to people is dishonest, and
- emitting `AggregateRating` markup with no ratings behind it is a
  structured-data violation that gets rich results suppressed.

Add real, attributable entries and the section, the `Review` nodes, and the
`aggregateRating` all appear automatically:

```python
REVIEWS = (
    Review(
        author="Sam Rivera",
        author_title="Platform lead, Example Co",
        rating=5,
        body="The audit replaced a three-day support loop with a single screen.",
        published="2026-08-01",
        source="G2",
        source_url="https://www.g2.com/products/...",
    ),
)
```

`test_15_no_invented_reviews_ship_by_default` is a guard rail against fake
testimonials creeping in, so update it in the same commit that adds real ones.

### 20 — Team

`TEAM` ships three slots marked `placeholder=True`. They render with a visible
*Placeholder* badge and are excluded from `Person` structured data. Replace the
name, role, bio, and photo, drop `placeholder=True`, and the schema follows.
Same for `TEAM_PHOTO` — swap the illustrated group image for a real one and
remove the `placeholder` flag.

### 14 — Address

The published address is city-level (`Melbourne, Victoria, Australia`) because
that is what is true for a remote-first project; inventing a street address
would be worse than omitting one. Add `street=` and `postal_code=` to
`ORG.address` when there is a real one, and both the visible address and the
`PostalAddress` schema pick it up. Update `ORG.geo` to match, or the map pin and
the structured data disagree.

## Before you point a domain at it

```bash
INBOXREADY_ENVIRONMENT=production          # otherwise robots.txt disallows everything
INBOXREADY_SITE_BASE_URL=https://your.domain
INBOXREADY_ANALYTICS_GA4_ID=G-XXXXXXXXXX   # optional; omit and no analytics is served
INBOXREADY_API_KEYS=...                    # locks down /v1
```

`INBOXREADY_ENVIRONMENT` defaults to `development` on purpose: a staging copy
that gets indexed competes with the real site for its own keywords.

## Notes on the social card

`og:image` points at an SVG. Modern crawlers handle it, but a few still do not.
If you need a raster fallback:

```bash
cd API && make og-card   # needs rsvg-convert or cairosvg
```

Then point `SOCIAL_CARD_PATH` in `site/seo.py` at the PNG and update
`SOCIAL_CARD_TYPE`.


## The landing page

`/` carries its own stylesheet and script — [`home.css`](../API/src/inboxready_api/static/css/home.css)
and [`home.js`](../API/src/inboxready_api/static/js/home.js) — loaded nowhere
else, so the rest of the site stays on the lighter base sheet.

| Piece | What it is |
| --- | --- |
| Airmail rule | Chevron strip in `repeating-linear-gradient`, top of the hero and the closing panel |
| Ghost records | Real-shaped DNS records at 7% opacity behind the hero |
| Live console | The actual audit form, styled as a terminal, with a **labelled demo trace** that steps out of the way on first submit |
| Marquee | Two identical passes translated `-50%`; the duplicate is `aria-hidden` |
| Chain diagram | Inline SVG with `<title>`/`<desc>`, packet animated along `offset-path` |
| Stamp cards | Perforations painted with four `radial-gradient` layers in the page colour |
| Index cards | Ruled-paper case study teasers with a manila tab |

Two bugs found while building it are worth knowing about, because both fail
silently:

- An SVG `linearGradient` in the default `objectBoundingBox` units renders
  nothing on a perfectly horizontal line — the box has zero height. Use
  `gradientUnits="userSpaceOnUse"`.
- Four-layer `mask-composite: intersect` erases the element entirely: each mask
  layer only covers its own edge band, so the intersection is empty. The
  perforations are painted instead, and
  `test_stamp_perforation_does_not_depend_on_mask_compositing` keeps it that way.

Everything decorative is switched off under `prefers-reduced-motion`, and
`test_decorative_motion_respects_reduced_motion` asserts it.
