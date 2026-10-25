# Agent configuration audit demonstration

This synthetic example is hosted at [Obaaf/agent-audit-demo](https://github.com/Obaaf/agent-audit-demo).
It audits one agent workflow with the published `obaaf==0.1.0` package and
`--fail-on medium`. The audit runs in GitHub Actions; the agent does not execute.

| Revision | Public audit | Result |
| --- | --- | --- |
| [Over-scoped](https://github.com/Obaaf/agent-audit-demo/blob/f8d6fd402ca921576fee5e20a436c07f7b4b916c/.github/workflows/agent-triage.yml) | [Failing run](https://github.com/Obaaf/agent-audit-demo/actions/runs/40240418961) | Exit 1: high GHA-001, GHA-003, GHA-004, GHA-005; low GHA-020 |
| [Bounded](https://github.com/Obaaf/agent-audit-demo/blob/2a697e7fadeccd25d9f2ca37b327a922ff0f7b49/.github/workflows/agent-triage.yml) | [Passing run](https://github.com/Obaaf/agent-audit-demo/actions/runs/40240448552) | Exit 0: low GHA-020 only |

## What changed

The first configuration grants an issue-triggered agent write access to contents,
issues and pull requests, `id-token: write`, and a model-secret reference.
The corrected version grants read-only contents and issues access, removes OIDC
token authority, and removes the secret reference. Both select the same pinned
agent action. The audit scans only `.github/workflows/agent-triage.yml`.

## Limits

- This demonstrates configuration detection, not a real agent run, application
  build, protected merge gate, or complete R1-R8 compliance.
- The agent workflow is disabled, its job has `if: ${{ false }}`, and repository
  issues are disabled. No model credentials are configured. The auditor still
  inspects the fixture's declared permissions and secret reference.
- The bounded example retains low-severity GHA-020 because it has no enforced
  egress restriction. A passing medium threshold does not mean zero findings.
- The workflow installs OBAAF 0.1.0 from PyPI. Newer checker changes on GitHub
  `main` are not included in this result.
- The example is an anonymous pilot contribution. The site does not attribute
  the contributor's personal account. GitHub's own run metadata may identify
  the organization member who pushes or reruns the audit.

The existing build-workflow demonstration is documented separately in
[checker-demonstration.md](checker-demonstration.md).
