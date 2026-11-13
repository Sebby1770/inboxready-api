document.addEventListener("DOMContentLoaded", () => {
  const menu = document.querySelector(".menu-toggle");
  const nav = document.getElementById("primary-nav");
  const closeMenu = () => {
    nav?.classList.remove("is-open");
    menu?.setAttribute("aria-expanded", "false");
  };
  menu?.addEventListener("click", () => {
    const open = nav.classList.toggle("is-open");
    menu.setAttribute("aria-expanded", String(open));
  });
  nav?.addEventListener("click", (event) => {
    if (event.target.closest("a")) closeMenu();
  });
  document.addEventListener("keydown", (event) => {
    if (
      event.key === "Escape" &&
      menu?.getAttribute("aria-expanded") === "true"
    ) {
      closeMenu();
      menu.focus();
    }
  });

  document.querySelectorAll("[data-protocol]").forEach((button) =>
    button.addEventListener("click", () => {
      document
        .querySelectorAll("[data-protocol]")
        .forEach((item) =>
          item.setAttribute("aria-pressed", String(item === button)),
        );
      document.querySelectorAll("[data-protocol-panel]").forEach((panel) => {
        panel.hidden = panel.dataset.protocolPanel !== button.dataset.protocol;
      });
    }),
  );
  document.querySelectorAll("[data-code-tab]").forEach((button) =>
    button.addEventListener("click", () => {
      document
        .querySelectorAll("[data-code-tab]")
        .forEach((item) =>
          item.setAttribute("aria-pressed", String(item === button)),
        );
      document.querySelectorAll("[data-code-panel]").forEach((panel) => {
        panel.hidden = panel.dataset.codePanel !== button.dataset.codeTab;
      });
    }),
  );
  document
    .querySelector("[data-copy-code]")
    ?.addEventListener("click", async () => {
      const feedback = document.querySelector("[data-copy-feedback]");
      try {
        await navigator.clipboard.writeText(
          document.querySelector("[data-code-panel]:not([hidden])").textContent,
        );
        feedback.textContent = "Copied";
      } catch {
        feedback.textContent = "Select the code to copy it.";
      }
    });
  const volume = document.getElementById("monthly-audits");
  const catalog = document.getElementById("plan-catalog");
  if (volume && catalog) {
    const plans = Object.entries(JSON.parse(catalog.textContent)).sort(
      (a, b) => a[1].limit - b[1].limit,
    );
    volume.addEventListener("input", () => {
      const units = Number(volume.value);
      const output = document.querySelector("[data-plan-recommendation]");
      if (!Number.isSafeInteger(units) || units < 1) {
        output.textContent = "Enter a positive whole number.";
        return;
      }
      const plan = plans.find(([, details]) => details.limit >= units);
      output.textContent = plan
        ? `${plan[0][0].toUpperCase() + plan[0].slice(1)} fits · ${plan[1].price}/month`
        : "Over 75,000? Contact support.";
    });
  }
  document.querySelectorAll("[data-toggle-password]").forEach((button) =>
    button.addEventListener("click", () => {
      const input = document.getElementById(
        button.getAttribute("aria-controls"),
      );
      const reveal = input.type === "password";
      input.type = reveal ? "text" : "password";
      button.textContent = reveal ? "Hide" : "Show";
      button.setAttribute("aria-pressed", String(reveal));
    }),
  );
  document
    .querySelector("[data-copy-key]")
    ?.addEventListener("click", async (event) => {
      const button = event.currentTarget;
      try {
        await navigator.clipboard.writeText(
          document.getElementById("new-api-key").value,
        );
        button.textContent = "Copied";
      } catch {
        button.textContent = "Select the key to copy";
      }
    });
});
