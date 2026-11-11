# Flagship: plan and progress

*Status: in progress. Done and on `main`: item 0, slice 2d.1, slice 1.1. Open slices and what each needs are in [the table below](#what-may-be-worked-on-and-when). Last updated 2026-11-11, after run 2.*

**First thing every run:** read the tracking issue's comments to see which slices other runs hold, then the state of the current standing pull request (linked from the tracking issue); merge `main` into `flagship` if `main` has moved.

This is the working plan for taking OBAAF from a young linter to a framework that holds up in real use. Sean Keluo-Udeke asked for it on 2026-11-11. A scheduled Claude agent does the work over many runs. Each run starts from nothing but this file and the tracking issue ([#51](https://github.com/Obaaf/OBAAF/issues/51)), so everything learned or decided is written here.

It is a planning document, not part of the specification. Decisions that change what the tools do also get a *Proposed* entry in [DECISIONS.md](../DECISIONS.md) in the slice that implements them, for the maintainers to accept or reject when they merge.

## How the work is organised

- `flagship` is the integration branch. One standing pull request, `flagship` into `main`, stays open for a maintainer to merge. The agent never merges into `main`, never pushes to `main`, never tags and never releases.
- Each slice is a branch `flagship-slice/<short-name>` and a pull request into `flagship` (decision F-08). The pull request is opened as a draft and marked ready only when CI is green and a reviewer that did not write it (a separate agent) has reviewed it and its blocking findings are fixed (decision F-11). The agent then merges it.
- Updates to this file, and merges of `main` into `flagship`, are committed straight to `flagship` (decision F-09). Everything else goes through a slice.
- Every commit the agent makes ends with Sean's sign-off line, `Signed-off-by: Sean Keluo-Udeke <55066947+seanudeke@users.noreply.github.com>`, after the co-author and session lines (decision F-13).
- A new standing pull request is opened when `flagship` differs from `main` in content, not merely by a merge commit (decision F-14).
- Comments by Sean or another maintainer on the tracking issue or the standing pull request outrank this plan.
- Every claim that something works links a run or says "not run".

## Working in parallel

From 2026-11-11 several runs may work at once (decision F-16). No run waits for another to finish.

- **A claim** is a comment on the tracking issue: `Run started, <UTC time>, run <tag>, slice <id>`. The tag is any short word the run picks. It is released by `Run finished, <UTC time>, run <tag>` with the report. A claim with no matching "Run finished" lapses after 5 hours.
- **A run takes the first slice in the table below that** is not done, is not claimed, has every slice in its "needs" column merged into `flagship`, and, if it is marked *core*, only when no other active run holds a *core* slice. *Core* slices change the checker's shared code (`src/obaaf/checker/`, `cli.py`, the rule data), where two slices at once would collide.
- **After posting a claim, read the comments once more.** If another run claimed the same slice first, withdraw (`Run finished, <UTC time>, run <tag>: withdrew`) and choose again.
- **Unblocking** (a red check on `flagship` or the standing pull request, `main` ahead of `flagship`, a comment from Sean) is claimed the same way, as slice `unblock`, by the first run that finds it.
- **Shared files.** A run changes only its own slice's entry in this file, the decisions it adds and its own run-log line, and only its own row in the tracking issue. Before pushing an update to this file it fetches and merges `flagship`; on a conflict it keeps both sides. Never force-push.
- **If nothing qualifies,** the run posts a one-line "Run finished" and stops. It does not invent work and does not start a slice whose needs are unmet.

### What may be worked on, and when

| Slice | Needs | Core |
| --- | --- | --- |
| 1.2 Enforcement and the platform | nothing | |
| 1.3 Enterprise products and agent tools | nothing | |
| 1.4 Positioning | 1.2, 1.3 | |
| 2a.1 Lifecycle | nothing | core |
| 2a.2 Controls that clear GHA-005 and GHA-020 | 2a.1 | core |
| 2a.3 Reports that lead with accepted risk | 2a.1 | core |
| 2b.1 Read, snapshot, report what was not read | nothing | |
| 2b.2 Rules for the six incidents | 2b.1 | |
| 2b.3 Drift | 2b.1 | |
| 2b.4 Expectrail, read-only | 2b.2 | |
| 2c.1 Egress control: design | 1.2 | |
| 2c.2 The action and its escape tests | 2c.1 | |
| 2c.3 The checker recognises it | 2c.2, 2a.2 | core |
| 2d.2 Bypass attempts, rule by rule | nothing | core |
| 2d.3 Property and fuzz tests | nothing | core |
| 2d.4 Local reusable workflows and composite actions | nothing | core |
| 2d.5 Agent tools installed by a script | 1.4 | core |
| 3.1 Measure the adoption path that exists | nothing | |
| 3.2 Zero-config first run | 2a.3 | core |
| 3.3 `obaaf init` | 2a.1 | core |
| 3.4 CI integration | 2a.3 | |
| 3.5 Versioning, and from report-only to gate | 2a.1 | |
| 3.6 Timed again | 3.2, 3.3, 3.4 | |
| 3.7 Expectrail case study | 2b.4 | |
| 3.8 "Run this and send us the result" | 3.2 | |
| 4.1 Website: content and truth table | 1.4 | |
| 4.2 Website: home page | 4.1 | |
| 4.3 Website: pages | 4.1, 3.7 | |
| 4.4 Website: checked in a browser | 4.2, 4.3 | |

The settings audit (2b) is new code in its own module, so it is not marked core; if a 2b slice has to change the checker's shared code it waits for the core slot like any other. Where a later slice's design should follow the positioning section and 1.4 is not yet done, the slice says in its pull request what it assumed.

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

Legend: ☐ open, ◐ in progress, ☑ merged into `flagship`. The order below is the order of preference; what may actually start is decided by [the table above](#what-may-be-worked-on-and-when).

### 0. Set up and plan

- ☑ **0.1** Read the repository and both papers, run the suite and the checker on OBAAF and Expectrail, create `flagship`, open the tracking issue and the standing pull request, write this plan. *Done in run 1.*

### 1. Know the field, then position OBAAF

Output: `docs/landscape.md`. Every entry is dated and links its sources. Nothing is written from memory. No disparagement: facts, links and the date checked.

Notes for the rest of item 1, learned in slice 1.1:

- **What can be run.** The session cannot reach PyPI, the Go module proxy or crates.io. GitHub release downloads work when the exact URL is known (`https://github.com/<owner>/<repo>/releases/download/<tag>/<file>`); the `releases/latest` page does not. The binaries used in 1.1 and their file names are in [landscape.md](landscape.md). Checkov, Semgrep and Gato-X (PyPI), KICS (Docker) and Legitify (needs a token) were not run.
- **Run other tools on a copy of Expectrail, not on the clone.** The clone's working tree was unchanged after the 1.1 runs, but one of the tools touched files inside `.git`.
- **Reading pages.** GitHub release pages print dates without a year and may be stored copies; directory and tag pages on github.com refuse automated fetches. A binary's own version output and build date are better evidence than the page.
- **A fact-check by an independent agent is worth its time.** In 1.1 it found six statements that were wrong or went past the evidence, all in the prose drawn from correct numbers, and a seventh in the corrections.
- One page found by search and not yet read: Trail of Bits, ["We hardened zizmor's GitHub Actions static analyzer"](https://blog.trailofbits.com/2026/05/22/we-hardened-zizmors-github-actions-static-analyzer/) (2026-05-22).

Read on 2026-11-11, from GitHub's changelog (the three pages only; the documentation they link to was not read):

- ["pull_request_target blocked by default December 2"](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2), published 2026-11-02. From 2026-12-02 GitHub Actions blocks `pull_request_target` events by default in all public repositories unless "an applicable Actions event policy explicitly allows them". Private and internal repositories are not affected, and GitHub Enterprise Server is not included. There are two brownouts, on 2026-11-09 and 2026-11-16, 16:00 to 18:00 UTC, during which blocked attempts "create failed runs with an error annotation; the workflows won't execute". The way to keep such a workflow running is to allow the event in an Actions event policy, which can be scoped to named workflow files. The page names no API endpoint.
- ["Workflow execution protections in GitHub Actions generally available"](https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available), published 2026-09-17. An allowlist of who can trigger a workflow (actor rules) and which events can start it (event rules), set at enterprise, organisation or repository level, with an evaluate mode and targeting of specific workflow files. The page says a REST API can create, read, update and delete the rules at all three levels and links to `docs.github.com/rest/actions/policies`; it gives no endpoint path, and does not say what a blocked run looks like. This is the setting behind Expectrail's incident 5, and the place slice 2b.2 has to read.
- ["Safer pull_request_target defaults for GitHub Actions checkout"](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout), published 2026-06-18. `actions/checkout` v7 refuses to fetch a fork pull request's code in `pull_request_target` workflows, and in `workflow_run` workflows that follow a pull request event, unless the step sets `allow-unsafe-pr-checkout` (which OBAAF-GHA-019 already reports). Fetching the same code with `git` or `gh` in a `run` step is not blocked, other events such as `issue_comment` are not covered, and same-repository pull requests are not affected. Pins to a commit do not pick the change up.

- ☑ **1.1 Workflow scanners.** Merged as [#56](https://github.com/Obaaf/OBAAF/pull/56): the first part of [landscape.md](landscape.md). Ten tools read (zizmor, actionlint, poutine, Octoscan, OpenSSF Scorecard, Legitify, Gato-X, Checkov, KICS, Semgrep rules); five run offline on OBAAF, Expectrail and OBAAF's 15 risky workflows (zizmor 1.32.0, actionlint 1.7.12, poutine 1.1.6, Octoscan v0.1.7, Scorecard 5.6.0); the other five not run, with the reason given. An independent agent fact-checked it in two passes. What it showed, which the later items have to answer:
  - Script injection, pull-request checkouts in privileged workflows, pinning, runners, token permissions, persisted credentials and cache poisoning are covered by other tools (OBAAF's GHA-002, 006, 008 to 011, 013, 019, in whole or in part). zizmor has 42 audits and fixes some findings itself.
  - No other tool has the agent or effect framing, and none of the four run reported what GHA-007, 012, 016, 017, 018, 020, 021 and 022 are about. zizmor reports some of the facts behind GHA-003, 004, 005, 014, 015 and 024 without that framing.
  - **OBAAF recognised 2 of Expectrail's 19 agent jobs unaided.** The other 17 are found only because Expectrail lists them by hand. Without that file OBAAF reports 5 findings there, not 39. This bears on slice 3.3 (`obaaf init` must detect agent jobs) and on any claim about what OBAAF finds by itself.
  - **A miss on OBAAF's own subject:** poutine found an agent's command-line tool installed with `curl … | bash` in ten of Expectrail's agent jobs. OBAAF has no rule that reads a tool installed by a `run` script (see slice 2d.5).
  - OBAAF does not read composite action files; zizmor reported a high `github-env` finding in OBAAF's own `actions/setup-obaaf/action.yml` (see slice 2d.4).
  - From their documentation, none of the tools checks four of Expectrail's six settings incidents; Legitify lists a ruleset-bypass policy, and required checks are covered only as "are checks required". A settings audit that compares settings with what the workflows assume (2b) would mostly not repeat them.
- ☑ **1.2 Enforcement and the platform.** Merged as [#58](https://github.com/Obaaf/OBAAF/pull/58): part 2 of [landscape.md](landscape.md). Read from their own pages: GitHub's native egress firewall, the Agent Workflow Firewall (AWF), GitHub Agentic Workflows (gh-aw), Copilot's firewall, Harden-Runner, Bullfrog, workflow execution protections, workflow lockfiles, rulesets, artifact attestations, SLSA 1.2, Sigstore, in-toto. Run: CodeQL 2.27.4 with `codeql/actions-queries` 0.6.39, offline, on OBAAF, Expectrail at `0509d73` and the 15 risky workflows (default suite 0 / 0 / 7 results, extended suite 0 / 1 / 9). **Not run:** any egress control, `gh attestation verify`, cosign, slsa-verifier, any REST endpoint. An independent agent fact-checked it in two passes: three blocking findings and fourteen smaller ones in the first, none blocking in the second. CI passed on the head commit ([run 43114738246](https://github.com/Obaaf/OBAAF/actions/runs/43114738246)). What it showed, which the later items have to answer:
  - **For 2c.1 (design): do not start from a blank page.** Four controls that OBAAF did not write can already restrict a hosted runner's network. GitHub's native firewall runs outside the runner's virtual machine, so root inside cannot touch it, but it is a technical preview (`runs-on: ubuntu-24.04-firewall`, policy in `.github/egress-firewall.yaml`); whether this repository can use that label is unknown and cheap to try. AWF is MIT-licensed, published as an action (`github/gh-aw-firewall@v1`) and as a command (`awf --allow-domains … -- <command>`), and by its documentation runs the command as an ordinary user after dropping `CAP_NET_ADMIN`, with the Docker socket hidden. The design should start from pinning and wrapping AWF and build a new mechanism only if AWF fails OBAAF's escape tests or cannot be pinned. Read first, because 1.2 did not: AWF's `docs/architecture.md` and `docs/security.md`, and the repository of Harden-Runner's agent. AWF's pages disagree about its default mode (host `iptables` with `sudo`, or a Docker network with no `sudo`), so establish it by running the pinned version. Gaps AWF states itself: IPv6 "not supported", the home directory mounted read-write, a shared kernel; what it does about DNS exfiltration through the allowed resolvers is not stated.
  - **For 2c.2 (escape tests): the published bypasses are the test list.** Harden-Runner: DNS over HTTPS and DNS over TCP (both fixed in v2.16.0), traffic sent with `sendto`/`sendmsg` escaping the log, `disable-sudo` undone through Docker. Bullfrog: a second DNS query in the same TCP segment, a `Host` header aimed at an allowed site's shared IP address, `sudo` restored through the `docker` group. Add these to the brief's list (blocked hostname, direct IP, another resolver, IPv6, sudo, child process).
  - **For 2c.3 (checker): today's test is too generous.** OBAAF-GHA-020 clears for any step using `step-security/harden-runner` with `egress-policy: block` and no `if:`, whatever its version, its place in the job, or whether `sudo` and containers are removed; a step placed after the agent would clear it. Harden-Runner's free tier "does not support private repositories", so on a private repository the step may enforce nothing; what it does there was not established. The sentence that GitHub-hosted runners have no native egress allow-list is in five places (`rules.yaml` under OBAAF-GHA-020, `agent_controls.yaml` under R7, the agent template and its README, `docs/inference-proxy.md`). It is left as it is, because it is still true of what is generally available; change it in the slice that teaches the checker about the native firewall. Also undecided: whether the checker should read a gh-aw `.lock.yml` file and credit the controls in it.
  - **For 2a.2 (clearing GHA-005): a key proxy exists.** AWF's README says its API proxy "holds LLM API keys so they never reach the agent process" and is always on; its usage page lists the flag as off by default. If it works as the README says, it is the inference proxy that R3 asks for and OBAAF never built. Test it before claiming it.
  - **For 2b.1 and 2b.2 (settings audit): what GitHub's REST reference says can be read** (API version 2026-03-10; no endpoint was called). Without a token, on a public repository: `GET /repos/{owner}/{repo}/rulesets` (a list without rules; `includes_parents` defaults to true), `GET /repos/{owner}/{repo}/rulesets/{ruleset_id}` (rules with their parameters, such as `required_approving_review_count` and `required_status_checks[].context`), `GET /repos/{owner}/{repo}/rules/branches/{branch}` (active rules only; evaluate and disabled ones are left out), `GET /repos/{owner}/{repo}/environments` and `…/environments/{environment_name}/deployment-branch-policies` (`protection_rules` of type `required_reviewers`, `wait_timer`, `branch_policy`; `deployment_branch_policy` with `protected_branches` and `custom_branch_policies`, or null when every branch may deploy). Needing more: a ruleset's `bypass_actors` is "only returned if the user making the API request has write access to the ruleset"; the Actions settings under `GET /repos/{owner}/{repo}/actions/permissions` (`allowed_actions`, `sha_pinning_required`; `…/workflow` for `default_workflow_permissions` and `can_approve_pull_request_reviews`; `…/fork-pr-contributor-approval` for `approval_policy`) need the "Administration" permission (read); and Actions policies, `GET /repos/{owner}/{repo}/actions/policies` and `GET /orgs/{org}/actions/policies`, need "Administration" (write) per the reference. So of the six incidents, a no-token audit can check the environment without a branch restriction and the required approvals and checks, and must report the ruleset bypass and the Actions policy as unread, naming the access that would show them. Responses carry an `X-Accepted-GitHub-Permissions` header that names what an endpoint needs. `can_admins_bypass` was not seen on the pages read, and the endpoints for classic branch protection were not read.
  - **For 2b.2: the `pull_request_target` change.** The default rule blocks the event in public repositories with no applicable event policy. It is in evaluate mode, with two enforcement windows (2026-11-09 and 2026-11-16, 16:00 to 18:00 UTC), and is enforced from 2026-12-02. GitHub's two changelog entries word its reach differently (all public repositories; or those "using the default pull_request_target policy before general availability"). A blocked run "will fail with an error" of the form "Event '…' is not allowed to trigger Actions workflows."
  - **For 2d.4 and 2d.5.** CodeQL reads local action files (5 in Expectrail, 1 in OBAAF) and OBAAF does not. Workflow lockfiles (`.github/workflows/actions.lock`, generally available since 2026-10-28) pin actions and their dependencies; nothing read says they cover tools a `run` script downloads.
  - **For item 3 (adoption).** The adoption guide should say to turn on GitHub's default code scanning setup, which includes CodeQL's workflow analysis, and should point a team starting a new agent workflow at gh-aw. gh-aw is generally available (2026-10-28), MIT-licensed, and does what OBAAF's agent lane templates aim at, with a firewall and a key proxy; OBAAF's example agent calls no model.
  - **Still coming from GitHub, state not established:** scoped secrets ("Secrets are no longer implicitly inherited"), a separate permission for managing secrets, and the Actions Data Stream. Each bears on OBAAF-GHA-005 and 024.
  - **How to read pages from a run.** The page-fetch tool refuses a URL that has not appeared in a search result in the same session. Search for the page first, then fetch it. GitHub rate-limits fetches when several agents read github.com at once.
- ☑ **1.3 Enterprise products and agent-specific tools.** Merged as [#59](https://github.com/Obaaf/OBAAF/pull/59): part 3 of [landscape.md](landscape.md). Seven enterprise products from their public pages only (Wiz, Endor Labs, Cycode, Legit Security, Apiiro, Snyk, Chainguard), each with what cannot be known without an account; and the tools aimed at AI agents in CI: ci-agent-audit (read as source and compared with OBAAF rule by rule), Aikido's PromptPwnd, Wiz's study of AI actions, the guardrails `openai/codex-action` and `anthropics/claude-code-action` document, and four scanners for agent configuration. **Nothing was run.** An attempt to run ci-agent-audit with no network was refused by the session's own safety rules (code from a source the session had not used before), and nothing was done to get around it; Aikido's Opengrep rules were not run either. An independent agent fact-checked it in two passes: four blocking findings in the first, one in the second (introduced by the first round of fixes), all corrected. CI passed on the head commit ([run 43117429658](https://github.com/Obaaf/OBAAF/actions/runs/43117429658)). What it showed, which the later items have to answer:
  - **OBAAF is not alone on its own subject.** [ci-agent-audit](https://github.com/layer8labs8/ci-agent-audit) (MIT, alpha, first released 2026-10-30) reads workflows and asks what an AI agent in them can reach; Wiz says its product detects misconfigured AI agents in CI; Aikido says its product and its open Opengrep rules detect the pattern. No claim that OBAAF is the only one may appear anywhere, the website included (item 4).
  - **For 2d.5 and 3.3: OBAAF is behind on named agent tools.** ci-agent-audit has 20 signature files, each with the tool's action names, program, prompt inputs and dangerous settings; OBAAF's `detection.yaml` has 11 action names and 10 command patterns and reads none of those settings. `safety-strategy: unsafe` and `allow-users: "*"` on `openai/codex-action`, `allowed_non_write_users: "*"` and `allowed_bots: "*"` on `anthropics/claude-code-action`, and flags such as `--dangerously-skip-permissions` are exact, cheap things to report, and OBAAF reports none. Four of ci-agent-audit's eleven rules (safety checks off, anyone can trigger, unpinned MCP servers, the agent told to fetch issue text) have no counterpart in OBAAF.
  - **For 3.3 (`obaaf init`): no list finds a home-grown agent.** Of Expectrail's 19 declared agent jobs, two install and call a named program; the other 17 start their model from the project's own code (twelve through `python -m agents.…`, five through other modules), and ten install an agent's command-line program with `curl … | bash`. Declaring a job an agent job outright is something only OBAAF offers. A heuristic to test: propose as an agent job any job that holds a model provider's key.
  - **For 2a.2 and 2c: candidates, not answers.** `codex-action`'s default `safety-strategy: drop-sudo` removes `sudo`, the Docker socket, new privileges and capabilities before the agent starts, and the action keeps the model key behind a proxy it starts. With AWF's (slice 1.2) that makes two key proxies and one privilege drop that exist today. Both proxies run on the runner inside the job; the fix text of OBAAF-GHA-005 asks for one "outside the job", and R3 for one "outside the agent's reach". Neither was tested. `drop-sudo` restricts privilege, not the network.
  - **For 2c.1: a sixth egress control.** Cycode's Cimon (eBPF, on the runner; "free and open source", licence not read) has a prevent mode that drops network calls. Read its repository with the others.
  - **For 2b: what the enterprise products say about settings.** Wiz ("over 40" rules for settings, a 2024 figure), Endor Labs (five named policies for Actions settings; "over 50" in all) and Legitify check settings against fixed good practice, as far as their pages say. None says it compares a setting with what the workflows assume. That is a statement about public pages, not about products nobody here has used.
  - **For item 4 (website) and 1.4:** the seven vendors' AI claims are mostly about the developer's side (the coding assistant, MCP servers, skills), not an agent inside a CI job.
  - **Not done, and worth a later look:** run ci-agent-audit and Aikido's rules on OBAAF's risky workflows and on Expectrail (Sean, or a session allowed to run them); read ARKEXA, the "agentic-actions-auditor" plugin listed under Trail of Bits' skills, Wiz's October 2026 follow-up to its study, and GitHub's two previews of 2026-10-28 ("Code scanning for AI applications", "AI Scan for repositories").
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

- ☑ **2d.1 Expressions are read from their tokens and fail closed.** Merged as [#53](https://github.com/Obaaf/OBAAF/pull/53) and [#54](https://github.com/Obaaf/OBAAF/pull/54). Before it, secrets and outsider-written fields were found by matching patterns against an expression's text, and these spellings got past every rule: `secrets.*` and any use of the `secrets` context other than one literal name; a secret in `outputs` or any job key outside a fixed list; anything after a `}}` inside a string; and for OBAAF-GHA-010 a wildcard, a computed index, a group or function result, env values (through any number of hops), and the matrix. `obaaf.checker.expr` now tokenizes expressions; anything it cannot pin down counts as the worst case; files it cannot read are errors. An independent reviewer made three passes: the first found a crash and a slow-input regression in the first commit and two more bypass classes, the second found a memory blow-up and one more bypass in the fixes, the third found nothing blocking. Its fuzzing on the final code (200,000 generated expressions, 600,000 random token texts) found no missed secret read and no missed expansion; the reviewer notes that its oracle was aligned with three deliberate changes. 499 tests pass on the merged `flagship` (437 before), run locally on Python 3.13; the 116 checker tests also pass on Python 3.11. CI passed on #53's commit; **CI never ran on #54's commits**: its run was still queued, with no job started, when #54 was merged ten minutes after it was opened. The next standing pull request into `main` is where CI first runs on this code, on Python 3.10 among others. Output for existing fixtures, templates and Expectrail is unchanged. **Not run on GitHub**: what the runner does with these spellings rests on its documentation and on recollection of its source.
- ☐ **2d.2 Bypass attempts, rule by rule.** For every security-relevant rule, a reviewer that did not write it tries to get past it: YAML anchors and aliases, flow mappings, escapes, expressions and `fromJSON`, reusable workflows and `secrets: inherit`, composite actions, matrix and `if` tricks, case and whitespace, computed secret names, comments and block scalars. *Done when* every rule has a recorded attempt, every successful bypass is a test, and each fix removes the class (parse properly or fail closed), not the case. Known starting points from 2d.1, all stated in the OBAAF-GHA-010 description as not followed: values set at run time (`GITHUB_ENV`); values passed between jobs through outputs; scripts other than `run` and `actions/github-script`; an `env:` written as one expression that reads other env or matrix values, and a `with:` written as one expression. Also from 2d.1's review: OBAAF-GHA-002 and 012, the narrowing of triggers by `if:`, and runner labels still match expression text rather than tokens; SARIF output carries no errors, so a file the checker refused shows only in the exit code and the text and JSON output; and whether GitHub's own YAML reader accepts the tagged values the checker now refuses has not been verified.
- ☐ **2d.3 Property and fuzz tests.** *Done when* the expression and workflow readers have property tests (for example: rewriting an expression in an equivalent spelling never removes a finding) that run in CI.
- ☐ **2d.4 Local reusable workflows and composite actions.** *Done when* a job that reaches an agent or a secret through `uses: ./...` is read through, or reported as not read, and the repository's own action files (`action.yml`) are read. Start by triaging what zizmor and Octoscan reported on OBAAF's own repository in slice 1.1 (seven and four findings; listed in [landscape.md](landscape.md), not yet judged).
- ☐ **2d.5 Agent tools installed by a script.** Found in slice 1.1: an agent's command-line tool installed by piping a download into a shell, or by a package manager without a fixed version, inside a `run` step. Agent control R6 asks for agent tools to be pinned; GHA-008 reads only actions and images. *Done when* an agent job that installs its tool this way is reported, with a test built from the pattern poutine found, and the decision whether to detect it in OBAAF or to take it from poutine's output is recorded against the positioning in 1.4.

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
| F-08 | 2026-11-11 | Slice branches are named `flagship-slice/<short-name>`, not `flagship/<short-name>`. | Git cannot hold a branch `flagship` and a branch `flagship/x` at once: the first is a file where the second needs a directory. |
| F-09 | 2026-11-11 | Updates to this file and merges of `main` into `flagship` are committed straight to `flagship`. | They are bookkeeping the brief asks for at the end of every run; a pull request and review for each would add nothing. Code, tests, rule data and every other document go through a slice. |
| F-10 | 2026-11-11 | The session subscribes to pull request events only while a run is working, and unsubscribes before "Run finished". | Between runs the schedule is the only thing that should act, so two runs never work at once. The next run picks up comments, failing checks and merges in its first steps. |
| F-11 | 2026-11-11 | Slice pull requests are opened as drafts and marked ready only when the review is done and CI is green. The standing pull request into `main` is a draft whenever CI has not yet passed on its head. If a slice is merged before its review has finished anyway, the review still runs to the end and its fixes land as a follow-up slice. | In run 1 Sean merged all three pull requests within fifteen minutes of their being opened: #53 before its review had finished, #54 before any CI job had started. A maintainer may merge whenever they choose; a draft makes "not ready" visible and cannot be merged by one tap. |
| F-12 | 2026-11-11 | A fix that changes code after the reviewer's last pass is either reviewed again or limited to wording. | The second round of fixes in 2d.1 introduced a new problem (memory), which only the next review pass caught. |
| F-13 | 2026-11-11 | Agent commits carry Sean's sign-off line from this point on. Earlier commits are left as they are. This replaces the second half of F-05; the author of the commits is still the session's identity. | Sean said so in the session after run 2 ("Proceed with the sign-off"). The line is his statement under the DCO, and the form is the one his earlier commits use. History is never rewritten, so commits before this have none. If a DCO check is ever added it will want the author and the sign-off to match; that would need a further word from Sean. |
| F-14 | 2026-11-11 | A new standing pull request opens when `flagship` and `main` differ in content. A difference of merge commits alone does not count. | GitHub merges the standing pull request with a merge commit, which `flagship` then has to merge back. If that alone counted as "ahead", every merge would call for another empty pull request. |
| F-15 | 2026-11-11 | The comparison in slice 1.1 stands without the tools that need PyPI, Docker or a token. No slice waits for access the session lacks: it does what can be done, names what was not run, and moves on. | Sean said so in the session after run 2. The five tools run are the closest to OBAAF; the other five are described from their own pages. The one gap that could change a conclusion is Semgrep's rule list, which could not be read at all; the page says so. |
| F-16 | 2026-11-11 | Runs may work in parallel, with claims on the tracking issue and the dependency table above. This replaces "one run at a time". | Sean asked for continuous work that never waits on another agent, on tasks nobody else holds and that depend on nothing in progress. One *core* slice at a time keeps two runs out of the same checker files. |

| F-17 | 2026-11-11 | A run may claim its next slice while its current one is being reviewed, and holds both until each is merged or released. Its claim comment says so. | In run 3 the fact-check of 1.2 left the run with nothing to do but wait, and the reading for 1.3 depends on nothing in 1.2. Naming both slices in the claim keeps another run off them. |
| F-18 | 2026-11-11 | What one slice learns for another is written under the slice that learned it, as "For 2b.1: …". The later slice starts from those notes and verifies them; it does not redo the reading. | 1.2 had to read GitHub's REST reference to say what each tool can see of settings. The same facts decide the design of 2b.1 and 2c.1. |

## Waiting on Sean

1. **The current standing pull request** (linked from the tracking issue), whenever it is ready. #55 was merged on 2026-11-11, so slices 2d.1 and 1.1 are on `main`. 2d.1 is not released; an adopter whose workflows use one of the newly caught spellings will see new findings when it is.
2. **Leave draft slice pull requests for the agent to finish.** A slice is a draft until it is reviewed and green (decision F-11). Sean merged #52 to #55 himself; #56 was left as a draft and the agent merged it.
3. **Do not copy the agent footer** into your own comments on the tracking issue or the standing pull request; a later run would read such a comment as an agent report (decision F-01).
4. **PyPI is optional now.** Sean chose on 2026-11-11 to proceed without it (decision F-15). If it is ever wanted: the setting is on the scheduled task's cloud environment. Edit the task, open the environment's settings and set **Network access** to Trusted, or to Custom with "Also include default list of common package managers" ticked; it applies from the next run.
5. **Dependabot #40, #42, #43**: see the table above.
6. **Findings other tools reported on OBAAF's own repository** (zizmor 7, Octoscan 4; listed in [landscape.md](landscape.md)) are not triaged. They are queued under slice 2d.4.

## Run log

| Run | Date (UTC) | What happened |
| --- | --- | --- |
| 1 | 2026-11-11, 18:35 to about 21:00 | Item 0 done: tracking issue #51, this plan, standing pull request #52. Slice 2d.1 done in two pull requests, #53 and #54, after three passes by an independent reviewer. Sean merged all three pull requests himself, and confirmed it after the run: #52 and #53 at 19:08, before #53's review had finished, and #54 at 20:33, after its review but before its CI had started. The full suite was then run locally on the merged `flagship`: 499 pass. `main` was merged back into `flagship`. Item 1 not started, apart from three GitHub changelog pages read for 2b. What took the time: the first review pass ran 67 minutes, so a slice with review needs about two hours. |
| 2 | 2026-11-11, 20:59 to about 21:55 | Asked for by Sean in the session. CI on #55 passed (all nine checks, at 20:58) and it was marked ready. Slice 1.1 done: `docs/landscape.md`, first part, merged by the agent as #56 after two fact-check passes and green CI. Sean left the draft alone. Not started: 1.2 to 1.4. |
| after 2 | 2026-11-11, about 21:50 | Sean merged #55 and said to add his sign-off line to the agent's commits (F-13). `main` merged back into `flagship`; this file updated; the next standing pull request opened. No slice. |
| after 2 | 2026-11-11, about 22:00 | Sean asked for continuous, parallel-safe work and chose not to wait for PyPI (F-15, F-16). This file gained the claim rules and the dependency table; the scheduled task's instructions and timing were changed to match. No slice. |
