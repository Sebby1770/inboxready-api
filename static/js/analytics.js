/**
 * Google Analytics 4 loader (checklist item 19).
 *
 * Two things make this different from the snippet Google hands you:
 *
 *  1. It lives in a file, so the site can keep `script-src 'self'` instead of
 *     opening the CSP up to inline script.
 *  2. Consent Mode defaults to *denied*. Nothing is stored and no hit is sent
 *     until the visitor accepts the banner, and Do Not Track is honoured
 *     outright. The measurement ID comes from the script tag's data attribute,
 *     which the server only renders when one is configured.
 */

const script = document.currentScript;
const MEASUREMENT_ID = script?.dataset.ga4Id || "";
const REQUIRE_CONSENT = script?.dataset.requireConsent !== "false";
const CONSENT_KEY = "inboxready.consent";

function storedConsent() {
  try {
    return window.localStorage.getItem(CONSENT_KEY);
  } catch {
    return null;
  }
}

function doNotTrack() {
  return (
    window.doNotTrack === "1" ||
    navigator.doNotTrack === "1" ||
    navigator.doNotTrack === "yes" ||
    navigator.msDoNotTrack === "1"
  );
}

window.dataLayer = window.dataLayer || [];
function gtag() {
  // eslint-disable-next-line prefer-rest-params
  window.dataLayer.push(arguments);
}
window.gtag = gtag;

function bootstrap() {
  if (!MEASUREMENT_ID || doNotTrack()) return;

  const granted = !REQUIRE_CONSENT || storedConsent() === "granted";

  gtag("consent", "default", {
    ad_storage: "denied",
    ad_user_data: "denied",
    ad_personalization: "denied",
    analytics_storage: granted ? "granted" : "denied",
    wait_for_update: 500,
  });

  if (REQUIRE_CONSENT && !granted) {
    // Load nothing at all until the visitor opts in. Consent Mode alone would
    // still contact Google; this does not.
    window.addEventListener("inboxready:consent", (event) => {
      if (event.detail === "granted") load();
    });
    return;
  }

  load();
}

function load() {
  if (document.getElementById("ga4-tag")) return;

  gtag("consent", "update", { analytics_storage: "granted" });

  const tag = document.createElement("script");
  tag.id = "ga4-tag";
  tag.async = true;
  tag.src = `https://www.googletagmanager.com/gtag/js?id=${encodeURIComponent(MEASUREMENT_ID)}`;
  document.head.appendChild(tag);

  gtag("js", new Date());
  gtag("config", MEASUREMENT_ID, {
    anonymize_ip: true,
    send_page_view: true,
    page_path: window.location.pathname,
  });
}

bootstrap();
