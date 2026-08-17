const RECENT_DOMAINS_KEY = "inboxready.recent-domains";

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function parseCsv(value) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function getStatusLabel(status) {
  return {
    pass: "Ready",
    warn: "Needs work",
    fail: "Broken",
    info: "Optional",
  }[status] || "Unknown";
}

function getScoreColor(score) {
  if (score >= 85) return "#1f7a56";
  if (score >= 65) return "#aa6b10";
  return "#b23b33";
}

function recentDomains() {
  try {
    return JSON.parse(localStorage.getItem(RECENT_DOMAINS_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveRecentDomain(domain) {
  const deduped = recentDomains().filter((item) => item !== domain);
  deduped.unshift(domain);
  localStorage.setItem(RECENT_DOMAINS_KEY, JSON.stringify(deduped.slice(0, 6)));
}

function renderRecentDomains(container, onSelect) {
  if (!container) return;

  const items = recentDomains();
  if (!items.length) {
    container.innerHTML = '<p class="result-empty">Recent test domains will appear here.</p>';
    return;
  }

  container.innerHTML = "";
  for (const domain of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "recent-domain-button";
    button.textContent = domain;
    button.addEventListener("click", () => onSelect(domain));
    container.appendChild(button);
  }
}

function renderEmptyState(target) {
  target.innerHTML = `
    <div class="result-empty">
      <h3>Ready for a live audit</h3>
      <p>Submit a domain to see provider detection, protocol checks, a weighted score, and remediation guidance.</p>
    </div>
  `;
}

function renderLoadingState(target, domain) {
  target.innerHTML = `
    <div class="result-loading">
      <strong>Auditing ${escapeHtml(domain)}...</strong>
      <div class="loading-bar" aria-hidden="true"></div>
    </div>
  `;
}

function renderErrorState(target, message) {
  target.innerHTML = `
    <div class="result-error">
      <h3>Audit failed</h3>
      <p>${escapeHtml(message)}</p>
    </div>
  `;
}

function formatScoreDelta(delta) {
  if (delta === null || delta === undefined) return "";
  const numeric = Number(delta);
  if (!Number.isFinite(numeric)) return "";
  const sign = numeric > 0 ? "+" : "";
  const cls = numeric > 0 ? "delta-up" : numeric < 0 ? "delta-down" : "delta-flat";
  return `<span class="score-delta ${cls}">${sign}${escapeHtml(numeric)}</span>`;
}

function renderSparkline(scores) {
  if (!Array.isArray(scores) || !scores.length) return "";
  const values = scores.map((value) => Number(value)).filter((value) => Number.isFinite(value));
  if (!values.length) return "";

  const width = 168;
  const height = 36;
  const pad = 3;
  const min = Math.min(...values, 0);
  const max = Math.max(...values, 100);
  const span = max - min || 1;
  const denom = Math.max(values.length - 1, 1);
  const points = values
    .map((score, index) => {
      const x = pad + (index * (width - pad * 2)) / denom;
      const y = height - pad - ((score - min) / span) * (height - pad * 2);
      return `${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");

  return `
    <div class="score-history">
      <svg class="score-sparkline" viewBox="0 0 ${width} ${height}" width="${width}" height="${height}" role="img" aria-label="Score history">
        <polyline points="${points}"></polyline>
      </svg>
    </div>
  `;
}

async function loadHistoryScores(domain) {
  const response = await fetch(`/v1/history?domain=${encodeURIComponent(domain)}&limit=20`);
  if (!response.ok) return [];
  const payload = await response.json();
  const entries = Array.isArray(payload.entries) ? payload.entries : [];
  return entries.map((entry) => entry.score).reverse();
}

function renderAudit(target, audit, historyScores = []) {
  const providers = audit.providers.length
    ? audit.providers
        .map(
          (provider) =>
            `<span class="provider-chip">${escapeHtml(provider.name)} · ${Math.round(provider.confidence * 100)}%</span>`
        )
        .join("")
    : '<p class="result-empty">No provider fingerprint matched the DNS evidence.</p>';

  const checks = Object.entries(audit.checks)
    .map(([name, check]) => {
      const detailBits = [];
      if (check.details?.record) {
        detailBits.push(`<div><strong>Record:</strong> ${escapeHtml(check.details.record)}</div>`);
      }
      if (check.details?.policy) {
        detailBits.push(`<div><strong>Policy:</strong> ${escapeHtml(check.details.policy)}</div>`);
      }
      if (check.details?.records?.length) {
        detailBits.push(`<div><strong>Found:</strong> ${escapeHtml(check.details.records.join(", "))}</div>`);
      }
      return `
        <article class="check-card">
          <span class="status-pill status-${escapeHtml(check.status)}">${getStatusLabel(check.status)}</span>
          <h4>${escapeHtml(name.replaceAll("_", " "))}</h4>
          <p>${escapeHtml(check.summary)}</p>
          ${detailBits.length ? `<div class="check-meta">${detailBits.join("")}</div>` : ""}
        </article>
      `;
    })
    .join("");

  const recommendations = audit.recommendations.length
    ? audit.recommendations
        .map(
          (item) =>
            `<li><strong>${escapeHtml(item.severity)}</strong> · ${escapeHtml(item.message)}${
              item.details ? ` <span>${escapeHtml(item.details)}</span>` : ""
            }</li>`
        )
        .join("")
    : "<li>No urgent remediation items. This domain is in a good place.</li>";

  const references = audit.references.length
    ? `<ul>${audit.references
        .map((reference) => `<li><a href="${escapeHtml(reference)}" target="_blank" rel="noreferrer">${escapeHtml(reference)}</a></li>`)
        .join("")}</ul>`
    : "<p>No references returned.</p>";

  target.innerHTML = `
    <div class="audit-report">
      <div class="report-top">
        <div class="score-ring" style="--score-value:${escapeHtml(audit.score)}; --score-color:${getScoreColor(audit.score)};">
          <strong>${escapeHtml(audit.score)}</strong>
        </div>

        <div class="report-title">
          <h3>${escapeHtml(audit.domain)} ${formatScoreDelta(audit.score_delta)}</h3>
          <p>Checked ${new Date(audit.checked_at).toLocaleString()}</p>
          <span class="status-pill status-${escapeHtml(audit.overall_status)}">
            ${getStatusLabel(audit.overall_status)}
          </span>
          ${renderSparkline(historyScores)}
        </div>
      </div>

      <div class="report-grid">
        <div class="report-column">
          <div class="check-grid">${checks}</div>
        </div>

        <div class="report-column side-stack">
          <div class="provider-list">
            <h4>Detected providers</h4>
            <div class="recent-domains">${providers}</div>
          </div>

          <div class="recommendations">
            <h4>Recommended next actions</h4>
            <ul>${recommendations}</ul>
          </div>

          <details class="json-panel">
            <summary>Raw JSON response</summary>
            <pre>${escapeHtml(JSON.stringify(audit, null, 2))}</pre>
          </details>

          <div class="provider-list">
            <h4>References</h4>
            ${references}
          </div>
        </div>
      </div>
    </div>
  `;
}

async function runAudit(payload) {
  const response = await fetch("/v1/audits/email-domain", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    let message = `The API returned ${response.status}.`;
    try {
      const error = await response.json();
      if (error?.detail) {
        message = typeof error.detail === "string" ? error.detail : JSON.stringify(error.detail);
      }
    } catch {
      // No extra payload to parse.
    }
    throw new Error(message);
  }

  return response.json();
}

function initAuditForm(form) {
  const resultsTarget = document.getElementById(form.dataset.resultsTarget);
  const recentTarget = document.getElementById(form.dataset.recentTarget);
  const domainInput = form.querySelector('input[name="domain"]');
  const selectorsInput = form.querySelector('input[name="selectors"]');
  const expectedProvidersInput = form.querySelector('input[name="expected_providers"]');
  const submitButton = form.querySelector('button[type="submit"]');

  if (!resultsTarget || !domainInput || !submitButton) return;

  renderEmptyState(resultsTarget);
  renderRecentDomains(recentTarget, (domain) => {
    domainInput.value = domain;
    form.requestSubmit();
  });

  form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const domain = domainInput.value.trim();
    if (!domain) {
      renderErrorState(resultsTarget, "Please enter a root domain.");
      return;
    }

    const payload = {
      domain,
      selectors: parseCsv(selectorsInput?.value || ""),
      expected_providers: parseCsv(expectedProvidersInput?.value || ""),
    };

    submitButton.disabled = true;
    submitButton.textContent = "Running…";
    renderLoadingState(resultsTarget, domain);

    try {
      const audit = await runAudit(payload);
      saveRecentDomain(audit.domain);
      let historyScores = [];
      try {
        historyScores = await loadHistoryScores(audit.domain);
      } catch {
        historyScores = [];
      }
      renderAudit(resultsTarget, audit, historyScores);
      renderRecentDomains(recentTarget, (recentDomain) => {
        domainInput.value = recentDomain;
        form.requestSubmit();
      });
    } catch (error) {
      renderErrorState(resultsTarget, error instanceof Error ? error.message : "Unknown error");
    } finally {
      submitButton.disabled = false;
      submitButton.textContent = submitButton.classList.contains("full-width")
        ? "Run Domain Audit"
        : "Run Audit";
    }
  });

  const params = new URLSearchParams(window.location.search);
  const queryDomain = params.get("domain");
  if (queryDomain && !form.dataset.autoloaded) {
    form.dataset.autoloaded = "true";
    domainInput.value = queryDomain;
    form.requestSubmit();
  }
}

function initRevealAnimations() {
  const items = document.querySelectorAll("[data-reveal], .hero-copy, .hero-panel");
  if (!("IntersectionObserver" in window)) {
    items.forEach((item) => item.classList.add("is-visible"));
    return;
  }

  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("is-visible");
          observer.unobserve(entry.target);
        }
      }
    },
    {
      threshold: 0.12,
    }
  );

  items.forEach((item) => observer.observe(item));
}

async function initHealthIndicator() {
  const indicator = document.querySelector("[data-health-indicator]");
  if (!indicator) return;

  try {
    const response = await fetch("/healthz");
    if (!response.ok) throw new Error("not ok");
    const payload = await response.json();
    indicator.innerHTML = '<span class="status-dot ready"></span> API ' + escapeHtml(payload.status);
  } catch {
    indicator.innerHTML = '<span class="status-dot"></span> API unavailable';
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-audit-form]").forEach(initAuditForm);
  initRevealAnimations();
  initHealthIndicator();
});
