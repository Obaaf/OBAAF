"use strict";
const revisions = {
  risk: {label: "A MOVABLE VERSION LABEL", code: "uses: actions/checkout@v6.0.0", description: "A version tag can move to different code. OBAAF flags this action because it is not pinned to an exact revision.", audit: "FAIL", merge: "BLOCKED", rule: "Finding: OBAAF-GHA-008 · Medium severity", link: "https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005157685", linkText: "Inspect the failed audit ↗"},
  fix: {label: "AN EXACT CODE REVISION", code: "uses: actions/checkout@1af3b93b6815bc44a9784bd300feb67ff0d1eeb3 # v6.0.0", description: "Restoring the reviewed commit SHA made the audit pass. The proposed workflow now selects the exact action revision.", audit: "PASS", merge: "ALLOWED", rule: "No active findings at the configured threshold", link: "https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005287677", linkText: "Inspect the passing audit ↗"}
};
document.querySelectorAll("[data-revision]").forEach(button => button.addEventListener("click", () => {
  const state = revisions[button.dataset.revision];
  document.querySelectorAll("[data-revision]").forEach(other => {other.classList.toggle("selected", other === button); other.setAttribute("aria-pressed", String(other === button));});
  for (const [id, value] of [["demo-label", state.label], ["demo-code", state.code], ["demo-description", state.description], ["audit-status", state.audit], ["merge-status", state.merge], ["demo-rule", state.rule]]) document.getElementById(id).textContent = value;
  document.getElementById("audit-status").className = state.audit === "PASS" ? "pass" : "fail";
  document.getElementById("demo-run").href = state.link;
  document.getElementById("demo-run").textContent = state.linkText;
}));
document.querySelectorAll("[data-audience]").forEach(button => button.addEventListener("click", () => {
  const audience = button.dataset.audience;
  document.querySelectorAll("[data-audience]").forEach(other => {other.classList.toggle("selected", other === button); other.setAttribute("aria-pressed", String(other === button));});
  document.getElementById("lead-panel").hidden = audience !== "lead";
  document.getElementById("engineer-panel").hidden = audience !== "engineer";
}));
