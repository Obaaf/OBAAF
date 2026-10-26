"use strict";
const revisions = {
  "risk": {
    "label": "A MOVABLE VERSION LABEL",
    "code": "uses: actions/checkout@v6.0.0",
    "description": "A version tag can move to different code. OBAAF flags this action because it is not pinned to an exact revision.",
    "audit": "FAIL",
    "merge": "BLOCKED",
    "rule": "Finding: OBAAF-GHA-008 · Medium severity",
    "link": "https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005157685",
    "linkText": "Inspect the failed audit ↗",
    "executionLabel": "Application type check + build",
    "execution": "PASS",
    "gateLabel": "Merge gate",
    "caption": "Pinning selects exact code; it does not prove that code is safe. Both build-demo reports include one documented exception for the trusted auditor's private-access key, expiring January 9, 2027. This was not a full framework or studio validation."
  },
  "fix": {
    "label": "AN EXACT CODE REVISION",
    "code": "uses: actions/checkout@1af3b93b6815bc44a9784bd300feb67ff0d1eeb3 # v6.0.0",
    "description": "Restoring the reviewed commit SHA made the audit pass. The proposed workflow now selects the exact action revision.",
    "audit": "PASS",
    "merge": "ALLOWED",
    "rule": "No active findings at the configured threshold",
    "link": "https://github.com/Ofonna-N/netflix-clone-2/actions/runs/38005287677",
    "linkText": "Inspect the passing audit ↗",
    "executionLabel": "Application type check + build",
    "execution": "PASS",
    "gateLabel": "Merge gate",
    "caption": "Pinning selects exact code; it does not prove that code is safe. Both build-demo reports include one documented exception for the trusted auditor's private-access key, expiring January 9, 2027. This was not a full framework or studio validation."
  },
  "agentRisk": {
    "label": "OVER-SCOPED AGENT AUTHORITY",
    "code": "permissions:\n  contents: write\n  issues: write\n  pull-requests: write\n  id-token: write\n# Agent step also references a model secret.",
    "description": "The configuration gives an issue-triggered agent write access, permission to request cloud credentials, and access to a model secret. The static audit fails without executing the agent.",
    "audit": "FAIL",
    "merge": "FAIL",
    "rule": "4 high findings: GHA-001, GHA-003, GHA-004, GHA-005. Also low GHA-020.",
    "link": "https://github.com/Obaaf/agent-audit-demo/actions/runs/40240418961",
    "linkText": "Inspect the failed agent audit ↗",
    "executionLabel": "Agent execution",
    "execution": "NOT RUN",
    "gateLabel": "Medium-severity threshold",
    "caption": "Synthetic configuration audit using OBAAF 0.1.0 from PyPI. The agent workflow is disabled and its job is skipped; no model call, application build, or protected merge gate is demonstrated. The audit checks only agent-triage.yml. The bounded example still has low-severity GHA-020 for unrestricted egress. Anonymous pilot contribution hosted by the Obaaf organization."
  },
  "agentFix": {
    "label": "BOUNDED AGENT AUTHORITY",
    "code": "permissions:\n  contents: read\n  issues: read\n# Same agent action, with no model secret.\n# No write permissions or OIDC token access.",
    "description": "Removing write permissions, OIDC token access, and the model-secret reference clears the high-severity authority findings. The audit passes the medium threshold; egress remains a low-severity finding.",
    "audit": "PASS",
    "merge": "PASS",
    "rule": "0 high, 0 medium, 1 low: GHA-020. Passes --fail-on medium.",
    "link": "https://github.com/Obaaf/agent-audit-demo/actions/runs/40240448552",
    "linkText": "Inspect the passing agent audit ↗",
    "executionLabel": "Agent execution",
    "execution": "NOT RUN",
    "gateLabel": "Medium-severity threshold",
    "caption": "Synthetic configuration audit using OBAAF 0.1.0 from PyPI. The agent workflow is disabled and its job is skipped; no model call, application build, or protected merge gate is demonstrated. The audit checks only agent-triage.yml. The bounded example still has low-severity GHA-020 for unrestricted egress. Anonymous pilot contribution hosted by the Obaaf organization."
  }
};
document.querySelectorAll("[data-revision]").forEach(button => button.addEventListener("click", () => {
  const state = revisions[button.dataset.revision];
  document.querySelectorAll("[data-revision]").forEach(other => {other.classList.toggle("selected", other === button); other.setAttribute("aria-pressed", String(other === button));});
  for (const [id, value] of [["demo-label", state.label], ["demo-code", state.code], ["demo-description", state.description], ["audit-status", state.audit], ["merge-status", state.merge], ["demo-rule", state.rule], ["demo-execution-label", state.executionLabel], ["demo-execution-status", state.execution], ["demo-gate-label", state.gateLabel]]) document.getElementById(id).textContent = value;
  document.getElementById("demo-execution-status").className = state.execution === "PASS" ? "pass" : "";
  document.getElementById("demo-caption").replaceChildren(document.createTextNode(state.caption + " "));
  const agent = button.dataset.revision.startsWith("agent");
  const record = document.createElement("a");
  record.href = "https://github.com/Obaaf/OBAAF/blob/main/docs/" + (agent ? "agent-checker-demonstration.md" : "checker-demonstration.md");
  record.textContent = agent ? "Read the agent audit record" : "Read the build audit record";
  document.getElementById("demo-caption").append(record, ".");
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
