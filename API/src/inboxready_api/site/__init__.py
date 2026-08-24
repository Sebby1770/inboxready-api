"""Public marketing / growth surface for InboxReady.

The modules here own everything a visitor (or a crawler) sees that is *not* the
JSON API:

* :mod:`inboxready_api.site.content` — editable business content (org profile,
  team, case studies, reviews, FAQs).
* :mod:`inboxready_api.site.pages`   — the page registry that drives routing,
  navigation, breadcrumbs, sitemap, and the SEO test suite.
* :mod:`inboxready_api.site.seo`     — canonical URLs, social cards, JSON-LD.
* :mod:`inboxready_api.site.leads`   — contact form capture.
* :mod:`inboxready_api.site.router`  — the FastAPI router wiring it together.
"""

from __future__ import annotations

__all__ = ["content", "pages", "seo", "leads", "router"]
