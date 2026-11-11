# Flagship: plan and progress

*Status: in progress. Item 0 (set up and plan) is done; items 1 to 4 are open. Last updated 2026-11-11 (run 1).*

This is the working plan for taking OBAAF from a young linter to a framework that holds up in real use. Sean Keluo-Udeke asked for it on 2026-11-11. A scheduled Claude agent does the work over many runs. Each run starts from nothing but this file and the tracking issue ([#51](https://github.com/Obaaf/OBAAF/issues/51)), so everything learned or decided is written here.

It is a planning document, not part of the specification. Decisions that change what the tools do also get a *Proposed* entry in [DECISIONS.md](../DECISIONS.md) in the slice that implements them, for the maintainers to accept or reject when they merge.

## How the work is organised

- `flagship` is the integration branch. One standing pull request, `flagship` into `main`, stays open for a maintainer to merge. The agent never merges into `main`, never pushes to `main`, never tags and never releases.
- Each slice is a branch `flagship/<short-name>` and a pull request into `flagship`. A slice merges only when CI is green and a reviewer that did not write it (a separate agent) has reviewed it and its blocking findings are fixed.
- Comments by Sean or another maintainer on the tracking issue or the standing pull request outrank this plan.
- Every claim that something works links a run or says "not run".

## Where OBAAF stood on 2026-11-11

Checked in run 1, on `main` at `d014b63`, in a clean virtual environment (Python 3.13.18, PyYAML 6.0.3, jsonschema 4.26.0, cryptography 50.0.1, setuptools 84.0.0; these came from the machine, not from the pinned `constraints.txt`, because the session could not reach PyPI).

| What | Result |
| --- | --- |
| `python -m unittest discover -s tests` | 437 tests, all pass, 14 seconds |
| `obaaf catalog`, `obaaf docs build --check` | both pass |
| `obaaf check .` on OBAAF | 4 workflow files and 3 Jenkinsfiles; 0 findings; exit 0 |
| `obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes` on Expectrail at `0509d73` | 27 workflow files; 38 findings, all in the baseline; 1 ignored by configuration; "0 new"; exit 0 |
| Rule catalogue | 24 GitHub Actions rules, 15 Jenkins rules (advisory), 2 repository rules, 1 instruction-file rule |

What the Expectrail numbers say. Expectrail declares 19 jobs as agent jobs in `.github/obaaf.yml`. Every one of them carries the same two findings: OBAAF-GHA-005 (a secret is available to an agent job) and OBAAF-GHA-020 (no egress restriction). All 38 are in the baseline. The baseline file was created on 2026-11-09 and changed in three more commits on 2026-11-10 (the clone is shallow, so earlier history was not checked). Neither finding has a fix an adopter can apply today: the fix text for GHA-005 says to move the model key into an inference proxy that OBAAF has not built, and GHA-020 asks for an egress control OBAAF does not ship. A finding that can only be accepted is noise, and the gate's answer to every new one has been "accept".

What was not checked in run 1: the six settings incidents described in the brief (they are in repository settings, which nothing in OBAAF reads yet); anything on a live GitHub repository; other tools on the same repositories (item 1).

Two false negatives were found in the first hour of reading the checker and confirmed with a local run. Under [SECURITY.md](../SECURITY.md) a false negative is a vulnerability, so the details are published only with the fix, in slice 2d.1. This matches the brief's warning: the checker is young, and more of the same should be assumed.

### The three open Dependabot pull requests

None was merged or changed. All three target `main`, which only a maintainer merges. Their checks last ran on 2026-10-29 and their branches are 13 to 16 commits behind `main`.

| Pull request | Checks on 2026-10-29 | Note for the maintainers |
| --- | --- | --- |
| #40 cryptography `>=50.0.2` | `test (3.10)` and `test (3.13)` failed; 7 passed | pip cannot resolve it: `actions/setup-obaaf/constraints.txt` pins cryptography 50.0.1. Needs the constraint and the hash lock updated in the same change. |
| #42 setuptools `>=84.2.1` | 9 of 9 passed | Raises the build requirement above the pinned setuptools 80.10.2 in `constraints.txt`. Passing checks do not show the two agree. |
| #43 PyYAML `>=6.0.3` | 9 of 9 passed | The branch has a bad merge: `dependencies` lists PyYAML and jsonschema twice (`PyYAML>=6.0.3`, `jsonschema>=4.18`, `PyYAML>=6.0`, `jsonschema>=4.26.0`). Do not merge as it is; ask Dependabot to recreate it. |

## Where the papers and practice disagree

Both papers were read before planning (Paper 1: abstract, sections 5 to 8 and 11; Paper 2: abstract, sections 5 and 10; the incident tables and related work were skimmed). Where they disagree with what adopters hit, practice wins.

1. **"No secrets in an agent job" is not where adopters are.** Paper 1 (R2, R3) gives an agent job no secrets and keeps the model key in an inference proxy. No such proxy exists in OBAAF, and all 19 of Expectrail's agent jobs hold a model key. The rule built from the paper can therefore only be accepted. The plan keeps the paper's goal but adds a second way to clear the finding: controls OBAAF can verify (the key lives in a branch-restricted environment, the job runs no code a pull request controls, egress is enforced to an allowlist). Anything OBAAF cannot verify is reported as "cannot tell", never as a pass.
2. **The papers assume the settings are right.** Paper 1 says the lanes are "implemented by structure" and that "labels must reflect repository settings". In Expectrail every real incident in two days was a setting, and OBAAF read none of them. The settings audit (2b) is where the paper's assumptions get checked.
3. **Egress is a requirement the paper leaves to others.** Paper 1 (R7) names "no native egress allow-list" as a gap and points to self-hosted runners or a runtime monitor. An adopter on hosted runners has nothing to turn on. Slice 2c ships one control, or says exactly what cannot be enforced.
4. **"The remaining gaps are not technical" did not survive the first adopter.** [The October strategy memo](roadmap-to-gold-standard.md) concluded that OBAAF's gaps were distribution, adoption and governance, and advised against building enforcement. Expectrail showed gaps that are technical: findings that cannot be resolved, no view of settings, nothing enforced, and bypasses in new rules. This plan puts correctness first. The memo's point about becoming a format others emit still stands and is not part of this work.

## The plan

Items are done in order. Each slice lists what "done" means. A slice is not done until it is merged into `flagship`.

Legend: ☐ open, ◐ in progress, ☑ merged into `flagship`.

### 0. Set up and plan

- ☑ **0.1** Read the repository and both papers, run the suite and the checker on OBAAF and Expectrail, create `flagship`, open the tracking issue and the standing pull request, write this plan. *Done in run 1.*

### 1. Know the field, then position OBAAF

Output: `docs/landscape.md`. Every entry is dated and links its sources. Nothing is written from memory. No disparagement: facts, links and the date checked.

- ☐ **1.1 Workflow scanners.** zizmor, actionlint, poutine, Octoscan, OpenSSF Scorecard, Legitify, Gato-X, Checkov and KICS workflow rules, Semgrep rules for Actions. *Done when* each has an entry (what it does, licence, whether it enforces or reports, what it sees of settings, what it knows about agents) and, for each, either a recorded run on OBAAF and Expectrail (version, command, counts, what it found that OBAAF missed and the reverse) or "not run" with the reason.
- ☐ **1.2 Enforcement and the platform.** StepSecurity Harden-Runner and its enterprise tier; GitHub's own features (CodeQL for Actions, Actions policies and workflow execution protections, rulesets, artifact attestations, agentic workflows and their firewall, the `pull_request_target` default change on 2026-12-02); SLSA, Sigstore, in-toto. *Done when* each has an entry as above and the entry says what OBAAF should consume instead of rebuilding.
- ☐ **1.3 Enterprise products and agent-specific tools.** Legit Security, Cycode, Apiiro, Wiz, Snyk, Endor Labs, Chainguard, and anything aimed at AI agents in CI found during the search. *Done when* each has an entry from public documentation only, and the entry says what is not knowable without an account.
- ☐ **1.4 Positioning.** *Done when* `docs/landscape.md` has a section that says plainly where OBAAF should not compete (and which tool it consumes or recommends there), where it must be at least as good, and what it alone does; a rule-by-rule table shows which OBAAF rules overlap a tool with more users; and this plan's later items are checked against it and changed where they conflict.

### 2. Make the core airtight

**2a. Findings that mean something**

- ☐ **2a.1 Lifecycle.** Each finding is one of: new, fixed by a control OBAAF verified, accepted (with owner, reason and expiry), or cannot tell. An acceptance with no reason, no owner or a past expiry fails the check. *Done when* the model is implemented behind the existing commands, existing `.github/obaaf.yml` files and `obaaf-baseline/v0.1` baselines still load, a migration command turns a v0.1 baseline into the new form, and Expectrail's current config and baseline run unchanged with a result that is no weaker than today's. Tests cover every state and every way an acceptance can be invalid.
- ☐ **2a.2 Controls that clear GHA-005 and GHA-020.** *Done when* an agent job that holds a model key can clear GHA-005 by controls the checker verifies from what it can read (the secret is declared protected and the job names its environment; no trigger or checkout brings pull-request-controlled code or text; egress is enforced by a recognised control), each control reports verified, not met, or cannot tell, and no path reports a pass on something the checker did not read. The environment's branch restriction is a setting: until 2b can read it, that control reports "cannot tell".
- ☐ **2a.3 Reports that lead with accepted risk.** *Done when* the text, JSON and SARIF outputs lead with how much risk is accepted, by whom and until when, rather than "0 new", and JSON keeps the fields existing consumers read.

**2b. Settings audit**

No earlier design was found in the repository's issues, pull requests or documents (searched in run 1), so this is designed fresh and its decisions are recorded here.

- ☐ **2b.1 Read, snapshot, report what was not read.** A command (working name `obaaf audit`) reads repository and organisation settings through the GitHub API with whatever read access the token has, writes a snapshot, and can run later against that snapshot offline. *Done when* it runs with no token on public data where the API allows, every setting it could not read is listed by name as unread with the reason (never skipped), it never asks for more than read access, and tests run from recorded API responses.
- ☐ **2b.2 Rules for the six incidents.** *Done when* each has a rule (ids `OBAAF-SET-nnn`) and a test built from a recorded API response: (1) a protected environment with no branch restriction, or with secrets reachable from pull requests; (2) a ruleset bypass actor, and whether an identity that authors changes can bypass; (3) required approvals that cannot be met; (4) required checks compared with the checks workflows report on pull requests (missing, never reporting, path-filtered); (5) an Actions policy that blocks a trigger a workflow uses or allows one it should not; (6) a reusable workflow that expects its caller's environment secrets. Also: default token permissions, fork pull request approval, SHA pinning requirements, and readiness for the `pull_request_target` change on 2026-12-02.
- ☐ **2b.3 Drift.** *Done when* a committed snapshot of the settings that matter can be compared with live settings, a difference is a finding, and a workflow template runs the comparison on a schedule.
- ☐ **2b.4 Expectrail, read-only.** *Done when* the audit has been run against Expectrail without changing any setting and its findings are recorded for the case study, with what could not be read.

**2c. One control that enforces**

- ☐ **2c.1 Design.** Study how Harden-Runner and GitHub's agentic-workflow firewall restrict egress. *Done when* a design note says which mechanism OBAAF uses on GitHub-hosted Linux runners, how the confined command is kept from undoing it (hosted runners have passwordless sudo), and where the other tools are the better choice.
- ☐ **2c.2 The action and its escape tests.** *Done when* an action in this repository runs a command with network access limited to a declared allowlist, blocks and logs everything else, and OBAAF's own CI has a job that tries to get out (a blocked hostname, a direct IP, another DNS resolver, IPv6, sudo, a child process) and fails on every attempt, plus a test that the allowed host still works. If full enforcement is not achievable on hosted runners, the documentation says exactly what is and is not blocked, and nothing is shipped that looks like enforcement and is not.
- ☐ **2c.3 The checker recognises it.** *Done when* GHA-020 clears only when the agent step really runs under the control (structurally: the step, not a declaration), and a test shows that a look-alike does not clear it.

**2d. Hardening**

- ◐ **2d.1 Secret references fail closed.** The two false negatives found in run 1. *Done when* any reference to the `secrets` context that is not a plain literal name counts as every secret, every place a job can use a secret is read, and both cases are tests.
- ☐ **2d.2 Bypass attempts, rule by rule.** For every security-relevant rule, a reviewer that did not write it tries to get past it: YAML anchors and aliases, flow mappings, escapes, expressions and `fromJSON`, reusable workflows and `secrets: inherit`, composite actions, matrix and `if` tricks, case and whitespace, computed secret names, comments and block scalars. *Done when* every rule has a recorded attempt, every successful bypass is a test, and each fix removes the class (parse properly or fail closed), not the case.
- ☐ **2d.3 Property and fuzz tests.** *Done when* the expression and workflow readers have property tests (for example: rewriting an expression in an equivalent spelling never removes a finding) that run in CI.
- ☐ **2d.4 Local reusable workflows and composite actions.** *Done when* a job that reaches an agent or a secret through `uses: ./...` is read through, or reported as not read.

**2e. No breadth for its own sake.** Standing rule, not a slice: depth on GitHub Actions first. Jenkins stays as it is (advisory); no other CI system is added.

### 3. The easiest adoption path

- ☐ **3.1 Measure what exists.** Time the current path in a clean directory and a fresh repository layout: install to first useful result, and to a gate in CI. *Done when* the times and every stumble are recorded here.
- ☐ **3.2 Zero-config first run.** *Done when* `obaaf check` with no configuration prints a summary a stranger can act on: each finding, why it matters, the exact fix.
- ☐ **3.3 `obaaf init`.** *Done when* it inspects a repository, proposes `.github/obaaf.yml` (including detected agent jobs and secrets) and adds a workflow, with no file written by hand.
- ☐ **3.4 CI integration.** An official pinned GitHub Action, SARIF for code scanning, a pre-commit hook, stable exit codes and JSON output. *Done when* each is documented and tested; what exists today (`actions/setup-obaaf`, `--format sarif`, `--format json`) is checked before anything is built.
- ☐ **3.5 Versioning and moving from report-only to gate.** *Done when* there is an upgrade note and a documented path from reporting to gating.
- ☐ **3.6 Timed again.** *Done when* a stranger's path is under five minutes to a useful result and under fifteen to a gate in CI, measured, with the times and stumbles recorded.
- ☐ **3.7 Expectrail case study.** From public facts only, with numbers recomputed here, stating plainly that Expectrail is the author's own project and that outside results are still to come.
- ☐ **3.8 "Run this and send us the result".** One page for Sean's contacts, a result file with no secrets and no source code, and a short template for reporting a finding that changed what they shipped.

### 4. The website

The site lives in [`site/`](../site/README.md), is built by `site/build.py`, and deploys to GitHub Pages from `main` after CI. That stays unless a slice records a strong reason to change it. Because it deploys only from `main`, slices provide screenshots and build instructions.

- ☐ **4.1 Content and truth table.** *Done when* every claim planned for the site is listed beside the code, test or document that backs it, and anything unbacked is cut.
- ☐ **4.2 Home page.** Leads with what OBAAF does and the fastest way to try it: a real terminal session and a real finding with its fix. Original inline SVG for the three ideas and for how check, audit and enforcement fit together; animation only where it explains, honouring `prefers-reduced-motion`.
- ☐ **4.3 Pages.** Quickstart, rule catalogue, landscape comparison with its date and sources, case study, papers.
- ☐ **4.4 Checked in a browser.** *Done when* it has been checked at desktop and phone widths, in light and dark, with JavaScript off, with no third-party fonts, scripts or trackers, and the screenshots are in the pull request.

## Decisions

| # | Date | Decision | Reason |
| --- | --- | --- | --- |
| F-01 | 2026-11-11 | Agent comments end with the "Generated by Claude Code" footer. Later runs treat any comment with that footer as an agent report, not as direction. | The agent has no GitHub account of its own, so its comments appear under Sean's. Without a marker a later run could mistake its own earlier report for an instruction from Sean. |
| F-02 | 2026-11-11 | A false negative in a rule is published only together with its fix. | SECURITY.md counts false negatives as vulnerabilities and asks that details stay out of public issues. Pull requests #48 and #50 already fixed such gaps in the open, fix and description together. |
| F-03 | 2026-11-11 | Flagship decisions are logged here. A decision that changes tool behaviour or a file format also gets a *Proposed* entry in DECISIONS.md in the slice that implements it. | GOVERNANCE.md makes the maintainers the ones who accept decisions. |
| F-04 | 2026-11-11 | Settings rules get new ids, `OBAAF-SET-nnn`. No existing id changes meaning. | CONTRIBUTING.md: rule ids are stable (NFR7). |
| F-05 | 2026-11-11 | Agent commits are authored as the session's identity (Claude) with a co-author trailer and carry no `Signed-off-by`. | CONTRIBUTING.md asks for a DCO sign-off, which is a person's statement. Earlier agent-assisted commits were signed off in Sean's name with him present. Sean is not watching these runs, so the agent does not sign for him. See "Waiting on Sean". |
| F-06 | 2026-11-11 | Slice 2d.1 was taken before item 1. | The brief says not to defer a small worthwhile fix, and a false negative is a vulnerability under SECURITY.md. Everything else follows the order of the plan. |
| F-07 | 2026-11-11 | The Dependabot pull requests are reported, not touched. | They target `main`, which only a maintainer merges, and two of the three should not merge as they are. |

## Waiting on Sean

1. **DCO sign-off.** Commits on `flagship` have no `Signed-off-by` (decision F-05). Either sign off when merging `flagship`, or comment on the tracking issue that the agent should add your sign-off line.
2. **Do not copy the agent footer** into your own comments on the tracking issue or the standing pull request; a later run would read such a comment as an agent report (decision F-01).
3. **The session could not reach PyPI** (the network policy for scheduled runs refused it). Tests ran against the machine's own packages, not the pinned constraints, and other Python tools could not be installed for comparison. If item 1 should include runs of tools that install from PyPI, allow PyPI for the scheduled task's environment.
4. **Dependabot #40, #42, #43**: see the table above.

## Run log

| Run | Date (UTC) | What happened |
| --- | --- | --- |
| 1 | 2026-11-11 | Item 0 done. Tracking issue #51 and this plan written. See the issue for the report. |
