# Publishing the site

The marketing site lives inside the FastAPI app, but every page is a pure
function of the [page registry](../API/src/inboxready_api/site/pages.py) —
nothing on them needs a request at view time. So the whole public surface can
be rendered once and served as files.

**Live:** <https://sebby1770.github.io/inboxready-api/>

## Build it locally

```bash
cd API && make site
python3 -m http.server -d ../_site 8080
```

Note the base path: a GitHub Pages *project* site is served from
`/<repo>/`, so links are rewritten onto that prefix at build time. To preview
it exactly as published, serve a parent directory:

```bash
mkdir -p /tmp/preview && cp -R _site /tmp/preview/inboxready-api
python3 -m http.server -d /tmp/preview 8080   # then open /inboxready-api/
```

## What the build produces

| Output | Notes |
| --- | --- |
| `index.html` + one directory per page | 15 pages, from the registry |
| `404.html` | GitHub Pages serves it for unknown paths, so the custom 404 carries over |
| `robots.txt`, `sitemap.xml` | Absolute URLs against the published origin |
| `docs/index.html` + `openapi.json` | Redoc reference, generated from the live schema |
| `site/pages.json` | Page inventory, useful to a link checker |
| `static/` | Copied verbatim |
| `.nojekyll` | Otherwise Jekyll drops underscore-prefixed paths |

## What a static host cannot do

Two surfaces need a backend, and the build swaps them rather than leaving
buttons that 404. `INBOXREADY_STATIC_BUILD=true` drives all of it:

- **The audit form** explains that no API is attached and shows the two commands
  that make it live locally. Pass `--api-base https://your-api.example.com` and
  the published pages call that instead — the form works again, unchanged.
- **The contact form** becomes a `mailto:` button. The map, directions, hours,
  and response promise beside it are static and survive intact.
- **The health-probe trust signal** is dropped. It is a real signal on a running
  instance and a dead link on a mirror, so the static build does not make the
  claim.

## How it publishes

[`.github/workflows/pages.yml`](../.github/workflows/pages.yml) builds the site,
runs the link checker over the output, and force-pushes the result to the
`gh-pages` branch. Pages serves that branch.

That branch is the **single publisher**. Do not also enable an
`actions/deploy-pages` artifact deploy — two publishers on one Pages site race
each other and you get whichever finished last.

Trigger a rebuild by pushing to `main`, or from the Actions tab via
**Run workflow** (which also accepts an API origin, if you want the published
audit form pointed at a deployment).

## Known limitation: robots.txt

A GitHub Pages project site cannot serve the origin's `robots.txt` — crawlers
read `https://sebby1770.github.io/robots.txt`, which belongs to the user page,
not to this repository. The generated file has correctly prefixed rules and is
there for completeness (and for a future custom domain), but until then submit
`sitemap.xml` directly in Search Console rather than relying on discovery.
