/**
 * Site chrome: mobile navigation, the sticky mobile CTA, the analytics consent
 * gate, and lightweight conversion events.
 *
 * Deliberately dependency-free and CSP-friendly — nothing here is inlined into
 * a template, so the page can ship `script-src 'self'`.
 */

const CONSENT_KEY = "inboxready.consent";
const STICKY_DISMISS_KEY = "inboxready.sticky-cta-dismissed";
const STICKY_BREAKPOINT = 760;
const STICKY_SCROLL_TRIGGER = 320;

function readStorage(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function writeStorage(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    /* Private browsing, or storage disabled. Non-fatal. */
  }
}

/* ---------------------------------------------------------------- nav ---- */

function initMobileNav() {
  const toggle = document.querySelector("[data-nav-toggle]");
  const nav = document.getElementById("primary-navigation");
  if (!toggle || !nav) return;

  const setOpen = (open) => {
    toggle.setAttribute("aria-expanded", String(open));
    document.body.classList.toggle("nav-open", open);
  };

  toggle.addEventListener("click", () => {
    setOpen(toggle.getAttribute("aria-expanded") !== "true");
  });

  nav.addEventListener("click", (event) => {
    if (event.target instanceof HTMLAnchorElement) setOpen(false);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") setOpen(false);
  });

  const media = window.matchMedia(`(min-width: ${STICKY_BREAKPOINT + 1}px)`);
  media.addEventListener("change", (event) => {
    if (event.matches) setOpen(false);
  });
}

/* --------------------------------------------------------- sticky CTA ---- */

function initStickyCta() {
  const bar = document.querySelector("[data-sticky-cta]");
  if (!bar) return;

  // Never shadow the page the CTA points at.
  if (document.body.dataset.page === "/app") return;
  if (readStorage(STICKY_DISMISS_KEY) === "1") return;

  const dismiss = bar.querySelector("[data-sticky-dismiss]");
  dismiss?.addEventListener("click", () => {
    bar.hidden = true;
    writeStorage(STICKY_DISMISS_KEY, "1");
  });

  const update = () => {
    const narrow = window.innerWidth <= STICKY_BREAKPOINT;
    const scrolled = window.scrollY > STICKY_SCROLL_TRIGGER;
    const atFooter =
      window.innerHeight + window.scrollY >= document.body.offsetHeight - 220;
    bar.hidden = !(narrow && scrolled && !atFooter);
  };

  update();
  window.addEventListener("scroll", update, { passive: true });
  window.addEventListener("resize", update, { passive: true });
}

/* ------------------------------------------------------------ consent ---- */

function currentConsent() {
  const stored = readStorage(CONSENT_KEY);
  return stored === "granted" || stored === "denied" ? stored : null;
}

function initConsentBanner() {
  const banner = document.querySelector("[data-consent-banner]");
  if (!banner) return;

  if (currentConsent() !== null) {
    banner.hidden = true;
    return;
  }

  banner.hidden = false;
  for (const button of banner.querySelectorAll("[data-consent]")) {
    button.addEventListener("click", () => {
      const choice = button.dataset.consent === "granted" ? "granted" : "denied";
      writeStorage(CONSENT_KEY, choice);
      banner.hidden = true;
      window.dispatchEvent(new CustomEvent("inboxready:consent", { detail: choice }));
    });
  }
}

/* ---------------------------------------------------------- analytics ---- */

/**
 * Fire a named conversion. Safe to call whether or not analytics is loaded:
 * `gtag` only exists once a measurement ID is configured *and* consent allows it.
 */
function trackEvent(name, params = {}) {
  if (typeof window.gtag === "function") {
    window.gtag("event", name, params);
  }
}

function initConversionTracking() {
  for (const element of document.querySelectorAll("[data-cta]")) {
    element.addEventListener("click", () => {
      trackEvent("cta_click", {
        cta_id: element.dataset.cta,
        page_path: document.body.dataset.page || window.location.pathname,
      });
    });
  }

  // 04 — the thank-you page is the conversion, so it reports itself.
  const conversion = document.querySelector("[data-conversion]");
  if (conversion) {
    trackEvent("generate_lead", { form: conversion.dataset.conversion });
  }
}

/* ------------------------------------------------------------- reveal ---- */

/**
 * Failsafe for the scroll-reveal animation.
 *
 * Reveal starts elements at `opacity: 0`. If the IntersectionObserver never
 * fires — a background tab, an unusual viewport, a script error earlier in the
 * queue — the page stays blank. Content is not allowed to depend on animation
 * succeeding, so anything still hidden after a beat is shown unconditionally.
 */
function initRevealFailsafe() {
  const reveal = () => {
    for (const element of document.querySelectorAll("[data-reveal], .panel")) {
      element.classList.add("is-visible");
    }
  };

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    reveal();
    return;
  }

  window.setTimeout(reveal, 1500);
}

/* --------------------------------------------------------------- init ---- */

document.addEventListener("DOMContentLoaded", () => {
  initMobileNav();
  initRevealFailsafe();
  initStickyCta();
  initConsentBanner();
  initConversionTracking();
});

window.inboxreadySite = { trackEvent, currentConsent };
