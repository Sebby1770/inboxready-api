/**
 * Landing-page motion: the demo trace in the hero console, and the count-up on
 * the metric band.
 *
 * The trace is explicitly labelled as a demo. It plays until the visitor runs a
 * real audit, at which point it gets out of the way — `app.js` owns the result
 * shell from the first submit onward.
 */

const TRACE_STEPS = [
  {
    query: "dig +short MX example.com",
    record: "10 aspmx.l.google.com.",
    verdict: "ok",
    label: "MX",
  },
  {
    query: "dig +short TXT example.com",
    record: '"v=spf1 include:_spf.google.com ~all"',
    verdict: "warn",
    label: "SPF · soft fail",
  },
  {
    query: "dig +short TXT google._domainkey.example.com",
    record: '"v=DKIM1; k=rsa; p=MIIBIjANBg…"',
    verdict: "ok",
    label: "DKIM",
  },
  {
    query: "dig +short TXT _dmarc.example.com",
    record: '"v=DMARC1; p=none; rua=mailto:…"',
    verdict: "warn",
    label: "DMARC · monitoring only",
  },
  {
    query: "GET https://mta-sts.example.com/.well-known/mta-sts.txt",
    record: "mode: enforce",
    verdict: "ok",
    label: "MTA-STS",
  },
  {
    query: "dig +short TXT _smtp._tls.example.com",
    record: '"v=TLSRPTv1; rua=mailto:…"',
    verdict: "ok",
    label: "TLS-RPT",
  },
  {
    query: "dig +short TXT default._bimi.example.com",
    record: "not found",
    verdict: "info",
    label: "BIMI · optional",
  },
];

const DEMO_SCORE = 78;
const STEP_MS = 320;

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function buildTrace() {
  const list = document.createElement("ul");
  list.className = "trace";

  const intro = document.createElement("li");
  intro.style.animationDelay = "0ms";
  intro.innerHTML =
    '<span class="q"># demo trace — enter a domain above for live results</span>';
  list.appendChild(intro);

  TRACE_STEPS.forEach((step, index) => {
    const item = document.createElement("li");
    item.style.animationDelay = `${(index + 1) * STEP_MS}ms`;

    const query = document.createElement("span");
    query.className = "q";
    query.textContent = `$ ${step.query}`;

    const record = document.createElement("span");
    record.className = "rr";
    record.textContent = step.record;

    const verdict = document.createElement("span");
    verdict.className = step.verdict === "info" ? "q" : step.verdict === "ok" ? "ok" : "warn";
    verdict.textContent = `${step.verdict === "ok" ? "✓" : step.verdict === "warn" ? "!" : "·"} ${step.label}`;

    item.append(query, record, verdict);
    list.appendChild(item);
  });

  return list;
}

function buildScore() {
  const wrapper = document.createElement("div");
  wrapper.className = "trace-score";
  wrapper.style.animationDelay = `${(TRACE_STEPS.length + 1) * STEP_MS}ms`;

  const dial = document.createElement("div");
  dial.className = "dial";
  const value = document.createElement("strong");
  value.textContent = "0";
  dial.appendChild(value);

  const copy = document.createElement("p");
  copy.innerHTML =
    "<strong>Needs work</strong>Two fixes stand between this domain and a clean send: " +
    "tighten SPF, and move DMARC off <code>p=none</code>.";

  wrapper.append(dial, copy);
  return { wrapper, dial, value };
}

function countUp(element, target, duration = 900) {
  if (prefersReducedMotion()) {
    element.textContent = String(target);
    return;
  }

  const start = performance.now();
  const tick = (now) => {
    const progress = Math.min(1, (now - start) / duration);
    // Ease-out so the number decelerates into place rather than stopping dead.
    const eased = 1 - (1 - progress) ** 3;
    element.textContent = String(Math.round(target * eased));
    if (progress < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

function initDemoTrace() {
  const shell = document.querySelector("[data-demo-trace]");
  const form = document.querySelector(".console-form");
  if (!shell || !form) return;

  let cancelled = false;
  const timers = [];

  const stop = () => {
    cancelled = true;
    timers.forEach(clearTimeout);
  };

  // The moment a real audit starts, app.js owns this shell.
  form.addEventListener("submit", stop, { capture: true, once: true });

  shell.replaceChildren(buildTrace());

  const { wrapper, dial, value } = buildScore();
  shell.appendChild(wrapper);

  const revealDelay = prefersReducedMotion() ? 0 : (TRACE_STEPS.length + 1) * STEP_MS;
  timers.push(
    window.setTimeout(() => {
      if (cancelled) return;
      dial.style.setProperty("--dial", `${DEMO_SCORE}%`);
      countUp(value, DEMO_SCORE);
    }, revealDelay)
  );
}

function initCounters() {
  const cards = document.querySelectorAll("[data-count-to]");
  if (!cards.length) return;

  const animate = (element) => {
    const raw = element.dataset.countTo || element.textContent.trim();
    // Only whole numbers count up; "<5m" and "1 call" stay as written.
    if (!/^\d+$/.test(raw)) return;
    countUp(element, Number(raw), 1100);
  };

  if (!("IntersectionObserver" in window) || prefersReducedMotion()) {
    cards.forEach(animate);
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        animate(entry.target);
        observer.unobserve(entry.target);
      }
    },
    { threshold: 0.5 }
  );

  cards.forEach((card) => observer.observe(card));
}

document.addEventListener("DOMContentLoaded", () => {
  initDemoTrace();
  initCounters();
});
