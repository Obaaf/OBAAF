# The landscape: what else checks GitHub Actions, and where OBAAF fits

*Checked 2026-11-11. Part 1 covers ten workflow scanners. [Part 2](#part-2-tools-that-enforce-and-what-github-itself-provides) covers tools that enforce while a job runs, GitHub's own features, and the standards for build provenance. [Part 3](#part-3-enterprise-products-and-tools-aimed-at-ai-agents-in-ci) covers seven enterprise products and the tools aimed at AI agents in CI. [Positioning](#positioning-where-obaaf-stands-and-what-it-plans-to-do-about-it) says what OBAAF plans to do about all of it.*

The aim is a fair comparison a team can rely on. Every fact below comes from a page read or a command run on the date above, and says which. Where a source did not say, this page says "not stated" rather than guess.

## How this was put together

**Reading.** Each project's own documentation and repository pages were read on 2026-11-11. Links are in [Sources](#sources). Three limits apply. GitHub's release pages print a day and month without a year, so release years below are inferred unless marked otherwise. Some GitHub pages appeared to be stored copies up to three months old. And some pages could not be fetched at all; those gaps are named.

**Running.** Five tools publish Linux binaries on their GitHub releases and were run, without a token and without network access, on three targets:

- OBAAF itself, at `461090e`;
- Expectrail, the first adopter, at `0509d73` (27 workflow files). Expectrail is a project of OBAAF's author, so the Expectrail results are not an independent adopter's;
- OBAAF's own 15 risky workflows (`tests/fixtures/workflows/risky/`), copied into a repository layout, to see which of OBAAF's rules overlap rules elsewhere.

| Tool | Version run | Command | Download checked against a published checksum |
| --- | --- | --- | --- |
| zizmor | 1.32.0 | `zizmor --offline --no-exit-codes --format json .` (and again with `--persona auditor`) | no checksum file fetched |
| actionlint | 1.7.12 | `actionlint -format '{{json .}}'` | yes |
| poutine | 1.1.6 | `poutine analyze_local . --format json --quiet --disable-version-check` | no checksum file found |
| Octoscan | release tag v0.1.7 (the binary prints "0.1") | `octoscan scan . --disable-rules repo-jacking --format json` | no checksum file found |
| OpenSSF Scorecard | 5.6.0 | `scorecard --local <dir> --format json` | yes |
| OBAAF | 0.2.0 plus `flagship` | `obaaf check .` | built from source |

**The tools did not run on equal terms on Expectrail.** OBAAF ran with Expectrail's own configuration file, which lists its 19 agent jobs by hand, because OBAAF recognises only 2 of them unaided. The other tools ran with their defaults and no configuration. Without that file OBAAF reports 5 findings on the same workflows, not 39.

Running offline matters. zizmor's online audits (impostor commits, known-vulnerable actions, ref confusion, stale refs) did not run. Octoscan's `repo-jacking` rule was switched off because it needs the network; with it on, the sandbox's blocked requests were reported as possible findings. Scorecard in local mode ran 11 checks and none of those that need the GitHub API (branch protection among them); its Fuzzing check failed for lack of network.

**Not run**, and why: Checkov, Semgrep and Gato-X install from PyPI, which the session could not reach. KICS publishes no binaries (Docker only). Legitify and Gato-X need a personal access token with broad scopes, and this work creates no tokens.

## The ten tools at a glance

| Tool | Latest release seen | Licence | Reads | Sees repository or organisation settings? | Fixes or enforces? | Rules about AI agents in CI? |
| --- | --- | --- | --- | --- | --- | --- |
| [zizmor](https://docs.zizmor.sh/) | 1.32.0 (the binary in the release is dated 2026-11-02) | MIT | Workflows, composite and Docker actions, Dependabot config; pre-commit config and workflow lockfiles (experimental) | No. Its docs say it "cannot actually see where secrets are stored on GitHub's side" | `--fix` applies fixes in place; exit codes 11 to 14 by highest severity; SARIF; inline and file ignores | None among the 42 audits |
| [actionlint](https://github.com/rhysd/actionlint) | 1.7.12, 2026-03-30 | MIT | Workflow files and local action metadata | No. Variables and runner labels are listed by hand in its config | Reports; exit code 1 on problems; ignore by message pattern | None. Knows the inputs of three agent actions as data |
| [poutine](https://github.com/boostsecurityio/poutine) | 1.1.6 (built 2026-05-22) | Apache-2.0 | GitHub Actions, GitLab, Azure DevOps and Tekton pipelines; a whole organisation with a read token | Not stated | Reports; `--fail-on-violation` exits 10; SARIF; skips in a config file | None among its 13 rules |
| [Octoscan](https://github.com/synacktiv/octoscan) | v0.1.7 (30 March, year inferred) | GPL-3.0, per the repository page | Workflow files; can download them for an organisation with a token | No | Reports; JSON and SARIF | None found |
| [OpenSSF Scorecard](https://github.com/ossf/scorecard) | 5.6.0 (the binary's build date is 2026-10-11) | Apache-2.0 | Repository files, and the GitHub API for pull requests, releases and settings | Partly: branch protection and rulesets, and webhooks. Its docs say it cannot detect the read-only default token setting | Reports a score from 0 to 10 per check; no fix | None. AI review bots "do not count as code review" |
| [Legitify](https://github.com/Legit-Labs/legitify) | 1.0.11 (9 July, year not stated) | Apache-2.0 | Settings through the API only; can also run Scorecard | Yes: about 55 GitHub policies for enterprise, organisation, repository, member, Actions and runner groups. Full results need an organisation owner; a repository administrator sees the repository policies only (about half of them). Scopes for full analysis: `admin:org, read:enterprise, admin:org_hook, read:org, repo, read:repo_hook`. Fine-grained tokens are not supported | Reports; remediation steps are manual | None found |
| [Gato-X](https://github.com/AdnaneKhan/gato-x) | 1.4.0 (25 April, year inferred) | Apache-2.0 | Workflow files across repositories, and run logs for self-hosted runners | No. Its docs say it "does not check for best practices like GitHub Actions version pinning, branch protection, secure defaults" | Reports, and can exploit what it finds (it is an offensive tool) | None found |
| [Checkov](https://github.com/bridgecrewio/checkov) | 3.4.0 (28 October, year inferred) | Apache-2.0 | Workflow files (8 checks) and, as a separate framework, organisation and repository settings (26 checks) | Yes: two-factor, SSO, branch protection, webhooks, repository creation. No check title covers rulesets, environments, Actions policies, default token permissions or fork pull request approval | Reports; exit code 1; SARIF; skip lists | None found |
| [KICS](https://github.com/Checkmarx/kics) | 2.1.21 (30 July, year inferred) | Apache-2.0 | Workflow files (4 queries) | No | Reports; exit codes by severity; ignore comments | None found |
| [Semgrep rules](https://github.com/semgrep/semgrep-rules) | No releases; a rules repository | Semgrep Rules License v1.0 (its text was not read) | Files, through the Semgrep CLI | Not stated | Rules can carry autofixes | Not established: the rule list could not be read, and neither could the repository's top-level `ai` directory |

Notes on single tools:

- **zizmor** has the most security rules of the scanners read here (42 audits) and can fix some findings itself. Its documentation recommends against installing from the GitHub release binaries; that was the only route available in this session.
- **actionlint** describes itself as focused on "catching mistakes in workflow files". It has two checks it calls security checks (script injection, hard-coded credentials). OBAAF's own CI already runs it.
- **poutine** also reads GitLab, Azure DevOps and Tekton pipelines. Its full rule documentation could not be fetched; the 13 rule ids come from the binary's own output.
- **Octoscan** v0.1.7 does not read YAML anchors and aliases, which Expectrail's workflows use. On Expectrail it reported 16 `syntax-check` findings about alias nodes (14 of the form "alias node but mapping node is expected"), so it did not read those parts of the workflows. zizmor warned on the same run that the input contains YAML anchors; its usage page calls its anchor support beta.
- **Legitify**'s release page gives no year for its latest release, so how recent it is was not established.
- **KICS** stopped publishing binaries at version 1.5.2 and distributes Docker images.

## What the runs showed

### On Expectrail

| Tool | Findings | What they were |
| --- | --- | --- |
| OBAAF, with Expectrail's configuration | 39 | 19 × a secret is available to an agent job (GHA-005, high), 19 × an agent job has no egress restriction (GHA-020, low), 1 × a secret reachable from a pull request workflow (GHA-001, low, ignored with a reason and an expiry) |
| OBAAF, without it | 5 | 2 × GHA-005, 2 × GHA-020 (the two jobs whose agent it recognises unaided), 1 × GHA-001 |
| zizmor | 85 | 82 × `self-repository` (low), 2 × `dangerous-triggers`, 1 × `artipacked`. With `--persona auditor`: 184, mostly `anonymous-definition` and `self-repository`, and 1 × `template-injection` |
| poutine | 12 | 10 × `unverified_script_exec`, 1 × `untrusted_checkout_exec`, 1 × `github_action_from_unverified_creator_used` (the OBAAF setup action itself) |
| Octoscan | 134 | 78 × `local-action`, 26 × `dangerous-write` (writes to `GITHUB_OUTPUT` or `GITHUB_ENV`), 16 × `syntax-check` (YAML aliases it cannot read), 12 × `dangerous-checkout` (a custom `ref`), 2 × `expression-injection` |
| actionlint | 1 | An empty string where a value is required (`byo-smoke.yml`, line 34) |
| Scorecard (local) | score 6.2 | Dangerous-Workflow 10, Token-Permissions 10, Pinned-Dependencies 3, Dependency-Update-Tool 0, SAST 0, Security-Policy 0 |

**What the others found that OBAAF did not.**

- **An agent's command-line tool installed by piping a download into a shell.** poutine reported `curl -fsSL … | bash` in ten jobs; all ten are jobs Expectrail declares as agent jobs. OBAAF's agent control R6 asks for agent tools to be pinned by digest. Its rule for that (GHA-008) reads actions and container images; nothing reads a tool installed by a `run` script. This is the most relevant miss: it is squarely OBAAF's subject.
- **A step output passed to an action.** Octoscan flagged `steps.*.outputs.*` at two places in `unity.yml`, where a step's output is used as a cache key. Neither is inside a script. OBAAF's injection rule reads scripts only, and does not follow values that are set while a job runs; its rule description says so.
- **Writes to `GITHUB_ENV` and `GITHUB_OUTPUT`**, 26 places (Octoscan). OBAAF has no rule for these.
- **The triggers themselves.** zizmor's `dangerous-triggers` reported two workflows for using `workflow_run`. OBAAF does not report a trigger alone; it reports a job reached through one when that job holds a secret, checks out a pull request's code, keeps the job token on disk, or the like.
- **In areas where OBAAF has rules, and reported nothing:** poutine's `untrusted_checkout_exec` on `expectrail-comment.yml` (a local action used in a `workflow_run` workflow; compare GHA-002), zizmor's `artipacked` on `mutation-record.yml` (compare GHA-011), and Octoscan's 12 `dangerous-checkout` findings for a checkout with a custom `ref`.
- **The one actionlint finding.** Expectrail does not run actionlint.

None of these was judged here as a true or false positive for Expectrail; that belongs to its maintainers.

**What OBAAF found that the others did not.** The 38 agent findings, 34 of which exist only because Expectrail listed its agent jobs by hand. No other tool run here has a notion of an agent job, so none asks what a model's key can reach or whether the job's network is restricted. This matches the documentation read: no rule about AI agents was found in the nine tools whose rules could be read (Semgrep's could not).

Those 38 findings are also the ones Expectrail accepts wholesale in its baseline, because OBAAF offers no way to resolve them yet ([flagship plan](flagship.md), item 2a). Being the only tool to report something is not the same as the report being useful.

### On OBAAF itself

OBAAF reports no finding on its own repository (it read 4 workflow files and 3 Jenkinsfiles; it does not read `actions/setup-obaaf/action.yml`, where zizmor's `github-env` finding is). Others do:

| Tool | Findings | What they were |
| --- | --- | --- |
| zizmor | 7 | `github-env` (high) in `actions/setup-obaaf/action.yml`; `dangerous-triggers` (high) for `workflow_run` in `pages.yml`; 2 × `dependabot-cooldown`; 3 × `self-repository` |
| Octoscan | 4 | `dangerous-checkout` for a custom `ref` in `release-pypi.yml`; 3 × `local-action` |
| poutine, actionlint | 0 | |
| Scorecard (local) | score 7.2 | Dangerous-Workflow 10, Token-Permissions 10, Pinned-Dependencies 6, Security-Policy 4, Binary-Artifacts 0, SAST 0 |

These have not been triaged. They are listed in the flagship plan for a maintainer or a later slice to look at.

### On OBAAF's own risky workflows

Each row is one of OBAAF's published test workflows, the OBAAF rules its test requires it to trigger (with the configuration the test supplies; OBAAF reports other rules on some of these files too), and the rule ids the other tools reported on the same file. A match on the same file is not always the same finding, but an empty cell means the tool said nothing at all about a file OBAAF calls risky. zizmor is shown in its default persona. actionlint's `syntax-check` entries are all `unexpected key "cache-mode"`, a key actionlint 1.7.12 rejects; OBAAF's own CI runs actionlint with that message ignored.

| Test workflow | OBAAF rules | zizmor | poutine | Octoscan | actionlint |
| --- | --- | --- | --- | --- | --- |
| `nx-title-injection` | GHA-010, 001 | `template-injection`, `dangerous-triggers` | `injection` | `expression-injection` | `expression` |
| `expression-spellings` | GHA-010, 001, 005, 024 | `template-injection` | | `expression-injection` | `expression` |
| `pwn-request` | GHA-001, 002, 008, 009, 011 | `dangerous-triggers`, `excessive-permissions`, `unpinned-uses`, `artipacked` | `untrusted_checkout_exec`, `default_permissions_on_risky_events` | `dangerous-checkout` | |
| `unsafe-checkout-opt-in` | GHA-019, 002 | `dangerous-triggers` | `untrusted_checkout_exec` | `dangerous-checkout` | |
| `pytorch-self-hosted` | GHA-013, 008, 009 | `excessive-permissions`, `unpinned-uses`, `artipacked` | `pr_runs_on_self_hosted` | `runner-label` | `runner-label` |
| `tj-actions-unpinned` | GHA-008, 016, 017 | `unpinned-uses` | `github_action_from_unverified_creator_used` | | `syntax-check` |
| `clinejection-triage` | GHA-007, 003, 008 | `excessive-permissions`, `unpinned-uses` | | | `syntax-check` |
| `clinejection-release` | GHA-006, 014, 016, 017, 008 | `cache-poisoning`, `unpinned-uses`, `artipacked`, `use-trusted-publishing` | | | |
| `promptpwnd-issue-agent` | GHA-001, 003, 004, 005, 008, 020 | `dangerous-triggers`, `unpinned-uses`, `artipacked` | `github_action_from_unverified_creator_used` | `expression-injection` | |
| `claude-action-toctou` | GHA-012, 011, 020 | `artipacked` | `github_action_from_unverified_creator_used` | | |
| `effect-without-checks` | GHA-021, 022 | `dangerous-triggers` | | | |
| `release-from-comment` | GHA-015 | `dangerous-triggers` | | | `syntax-check` |
| `protected-secret-repo-scope` | GHA-024 | (none; `secrets-outside-env` with `--persona auditor`) | | | |
| `signing-key-in-build` | GHA-018 | | | | `syntax-check` |
| `template-placeholder` | GHA-023 | | `github_action_from_unverified_creator_used` | | |

What the table says:

- **Script injection, pull-request checkouts in privileged workflows, unpinned actions, self-hosted runners, token permissions, persisted credentials and cache poisoning are covered elsewhere**, and zizmor can fix some of what it finds. That is OBAAF's GHA-002, 006, 008 to 011, 013 and 019, in whole or in part.
- **On script injection, released OBAAF is behind.** zizmor, Octoscan and actionlint all reported the `expression-spellings` workflow. OBAAF 0.2.0 and its `main` branch miss the spellings in it; the fix (slice 2d.1 of the flagship work) is on the `flagship` branch as of 2026-11-11 and not yet released.
- **zizmor has a rule next to GHA-024.** Its `secrets-outside-env` audit (auditor persona) reports a secret used by a job with no environment. It reported the GHA-024 test workflow, and nothing on Expectrail, whose jobs declare their environment. OBAAF's rule differs in being told which secret belongs to which environment.
- **No other tool has the agent or effect framing, but zizmor reported some of the same underlying facts without it**, and it does recognise publishing workflows (`cache-poisoning` and `use-trusted-publishing` on `clinejection-release`). In its default persona: the trigger of a release workflow (`dangerous-triggers` on `release-from-comment`, which is what GHA-015 is about), and a job left with default token permissions (`excessive-permissions` on `clinejection-triage`, the condition GHA-003 names for an agent job). Not in its default persona: write permissions and `id-token: write` on the agent workflow (the facts behind GHA-003 and 004), and a secret used outside an environment, both on the agent workflow (GHA-005) and on the publishing job of `clinejection-release` (the fact GHA-014 names).
- **None of the four tools run reported, in any persona, what these rules are about:** a low-trust workflow that can write the default-branch cache (GHA-007); an agent that reads instructions from the change under review (GHA-012) or can reach the whole network (GHA-020); agent output applied without verification or approval (GHA-021, 022); a release without a provenance check or provenance (GHA-016, 017); and a signing key in the build (GHA-018). Checkov, which was not run, lists checks for builds without cosign signing or attestation (CKV_GHA_5, CKV_GHA_6), which sit next to GHA-017.
- **Two rules have no single counterpart.** For GHA-001 (a secret reachable from an untrusted trigger), zizmor reports the trigger and, outside its default persona, the secret, as separate findings on three of the four test workflows; poutine's findings on two of them list the secrets the job references. GHA-023 is about OBAAF's own templates.

## The six settings incidents, against these tools

Expectrail's real incidents in its first two days were all repository settings. From the documentation read, not from runs:

| Incident | A check for it in the tools read |
| --- | --- |
| A protected environment with no branch restriction | None found. No environment policy appears in Legitify's or Checkov's lists; Scorecard's docs do not mention environments |
| A ruleset bypass that lets an administrator's sessions skip every required check | Legitify lists "Users Are Allowed To Bypass Ruleset Rules". Scorecard's Branch-Protection check reads rulesets |
| Required approvals that the only account can never give | None found |
| A required-checks list naming one check of eleven | Partly: Checkov CKV_GITHUB_14, Legitify's "Default Branch Should Require All Checks To Pass Before Merge" and Scorecard look at whether status checks are required, not whether the list matches what workflows report |
| An Actions policy that blocked a trigger a workflow used | None found |
| A reusable workflow that could not see its caller's environment secrets | None found |

So a settings audit that compares settings with what the workflows assume would mostly not repeat these tools. It would overlap Legitify on a few fixed checks (the default token permission, ruleset bypass, workflows approving pull requests). The two that read settings broadly, Legitify and Checkov, check them against fixed good practice. Legitify needs a classic token, and an organisation owner's for its full results.

## What this already suggests

These are inputs to the positioning section (item 1.4), not decisions.

1. OBAAF should not try to match zizmor rule for rule. On generic workflow hygiene zizmor has more rules (42 audits against OBAAF's 24 GitHub Actions rules) and fixes some of what it finds.
2. No tool read here asks a repository to declare its agent jobs and then asks what each can reach. That is OBAAF's own ground. It is also weak in practice: OBAAF recognised 2 of Expectrail's 19 agent jobs unaided, and the findings it produced there can only be accepted.
3. OBAAF missed things on its own subject that other tools caught. The agent tool installed with `curl | bash` is the clearest.
4. A team that runs only OBAAF today loses what zizmor, poutine and actionlint report. For "lose nothing by running OBAAF as the default check" to hold, OBAAF has to run them, read their output, or say plainly to run them alongside.

## Part 2: tools that enforce, and what GitHub itself provides

*Checked 2026-11-11.*

Part 1 was about tools that read workflow files and report. This part is about three other things: tools that restrict what a running job can do, the features GitHub has built into the platform, and the standards for recording what went into a build. For each it says what OBAAF should use as it is, what it should recommend, and what is left for OBAAF to build.

### How this part was put together

**Reading.** Each project's own pages were read on 2026-11-11; the links are under [Sources](#sources). Three limits apply:

- GitHub's REST reference pages are long, and their response schemas were not read. Field names below come from the example responses and the parameter tables.
- Harden-Runner's "how it works" page does not describe how its agent filters traffic on a GitHub-hosted runner, and the agent's own repository was not read.
- The Agent Workflow Firewall's pages disagree with each other about its default mode (see [below](#restricting-what-an-agents-job-can-reach-five-ways)).

**Running.** One tool was run: CodeQL's queries for GitHub Actions, offline, on the same three targets as part 1: OBAAF at `07de975` (its workflows, its action and the risky workflows are identical to those at `461090e`, the commit part 1 used), Expectrail at `0509d73`, and OBAAF's 15 risky workflows.

| Tool | Version run | Commands |
| --- | --- | --- |
| CodeQL | CLI 2.27.4, from the bundle tagged `codeql-bundle-v2.27.4`; query pack `codeql/actions-queries` 0.6.39 | `codeql database create --language=actions`, then `codeql database analyze` with the suite `actions-code-scanning.qls` (17 queries) and again with `actions-security-extended.qls` (23 queries) |

**Not run**, and why. The egress controls need a GitHub runner, or Docker with root, and this part changed no workflow; trying them is the job of slices 2c.1 and 2c.2 of the [flagship plan](flagship.md). `gh attestation verify`, cosign and slsa-verifier need the GitHub API or a signed artifact, and this work uses no token.

### At a glance

| What | Kind | Licence or plan | Enforces, or reports? | Knows about AI agents? |
| --- | --- | --- | --- | --- |
| [GitHub's native egress firewall](https://github.com/github-early-access/actions-native-egress-firewall/) | Platform feature. Its README says "Status: Technical Preview" | Plan not stated. The README describes a programme for "design partners" | Enforces or logs, from outside the runner's virtual machine | Not stated |
| [Agent Workflow Firewall](https://github.com/github/gh-aw-firewall) (AWF) | Open source command and action, from GitHub | MIT | Enforces a domain allowlist on one command and its children | Yes. It is built to confine an agent, and has a proxy that "holds LLM API keys so they never reach the agent process" |
| [GitHub Agentic Workflows](https://github.com/github/gh-aw) (gh-aw) | A way to write agent workflows in Markdown, compiled to Actions workflows. Generally available since 2026-10-28 | MIT. "GitHub Free, Team, and Enterprise" | Enforces by how it builds the workflow: read-only agent job, writes in separate jobs, AWF around the agent | Yes. It is the closest thing on GitHub to OBAAF's agent lane |
| [Copilot's firewall](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall) | Built into Copilot's cloud agent | Part of Copilot | Enforces, for "processes started by the agent via its Bash tool" | Yes, for Copilot's own agent only |
| [Harden-Runner](https://github.com/step-security/harden-runner) | An action that installs an agent on the runner (StepSecurity) | Action: Apache-2.0. The community agent for Linux is open source; the enterprise agent is not. Free "for public repositories on GitHub-hosted runners"; the paid tier is listed at $16 per contributing developer per month | `egress-policy: audit` reports; `egress-policy: block` enforces | Nothing specific on the pages read |
| [Bullfrog](https://github.com/bullfrogsec/bullfrog) | An action | MIT | `audit` (the default) reports; `block` enforces | Nothing on the page read |
| [Workflow execution protections](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) | Platform feature (an "Actions policy"). Generally available since 2026-09-17 | "All public repositories, and private repositories on GitHub Team or GitHub Enterprise." Evaluate mode: Enterprise Cloud only | Enforces before a run starts: who may trigger which workflow, and by which event | Actor rules can name Copilot |
| [Workflow lockfiles](https://github.blog/changelog/2026-10-28-github-actions-workflow-lockfiles-are-generally-available/) | Platform feature. Generally available since 2026-10-28 | Enterprise Cloud, Team and Free plans | Enforces: an onboarded workflow runs the commits recorded in the lockfile | No |
| [Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) | Platform feature | Public repositories on Free; private ones on Pro, Team and Enterprise Cloud | Enforces rules on branches, tags and pushes | No |
| [CodeQL for GitHub Actions](https://github.blog/changelog/2025-04-22-github-actions-workflow-security-analysis-with-codeql-is-now-generally-available/) | Static analysis in code scanning. Generally available since 2025-04-22 | Licence of the query pack not read. Plan terms were read only in summary form | Reports | None among its 23 queries |
| [Artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) | Platform feature | Public repositories on every current plan; private ones need Enterprise Cloud | Records. Nothing is enforced until someone verifies: "the attestations must be verified" | No |
| [SLSA](https://slsa.dev/spec/) 1.2 | Specification | Community Specification License 1.0 | Neither. It defines levels and recommends formats | Nothing found on the pages read |
| [Sigstore](https://docs.sigstore.dev/about/overview/) (cosign v3.1.4) | Signing services and tools | cosign: Apache-2.0 | Signs and verifies | No |
| [in-toto attestation framework](https://github.com/in-toto/attestation/blob/main/spec/README.md) 1.2 | Format | Not read | Neither. It is the envelope the others use | No |
| [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator) and [slsa-verifier](https://github.com/slsa-framework/slsa-verifier) | Tools | Apache-2.0 | Both READMEs say the project "is **no longer actively maintained**" and suggest GitHub artifact attestations | No |

### Restricting what an agent's job can reach: five ways

OBAAF's agent control R7 asks that an agent job reach only the hosts its task needs. Until now OBAAF has only reported the lack of such a control (OBAAF-GHA-020). On a GitHub-hosted runner the job has passwordless `sudo`, so the question to ask of any control is: where does it live, relative to the code it confines?

| | Where it runs | What it filters | What keeps the confined code from switching it off |
| --- | --- | --- | --- |
| **GitHub's native egress firewall** | "**outside** the runner VM" | "DNS and HTTP/HTTPS traffic", against an allowlist of hosts in `.github/egress-firewall.yaml`. It ends TLS at the boundary and starts it again to the destination | Nothing inside the machine can reach it. GitHub's roadmap post says it "remains immutable even if an attacker gains root access inside the runner environment" |
| **AWF** | In Docker containers on the runner: a Squid proxy, the agent's container, and a proxy for model keys | HTTP and HTTPS by domain name ("using SNI"). DNS only to the configured resolvers. "Direct IP access (without domain names) is blocked" | The command runs as an ordinary user, after the container has dropped `CAP_NET_ADMIN`, `CAP_SYS_CHROOT` and `CAP_SYS_ADMIN`. `no-new-privileges` and a seccomp profile are set, and the Docker socket is replaced by `/dev/null` to prevent "firewall bypass via `docker run`" |
| **Harden-Runner** | An agent the action installs on the runner's own virtual machine | Its pricing page says: "block unknown outbound calls at the DNS and network layers", against the hosts listed in `allowed-endpoints` | `disable-sudo-and-containers` removes `sudo` and Docker from the job. The pages read do not say what a job that keeps `sudo` can do to the agent |
| **Bullfrog** | On the runner's own virtual machine | `allowed-domains`, `allowed-ips`, and a DNS policy | `enable-sudo: false`. Its README says: "Root access can be used to bypass egress filtering entirely" |
| **Copilot's firewall** | Inside Copilot's own environment | An allowlist of hosts | Not described. Its own page says it "should not be considered a comprehensive security solution" |

Limits each project states, and bypasses that have been published. These are stated as their sources state them; none was reproduced here.

- **GitHub's native egress firewall.** A technical preview, on Linux only, reached by `runs-on: ubuntu-24.04-firewall`. The README expects "roughly a **15–20% increase in workflow runtime**". Because TLS is ended at the boundary, a job that pins certificates has to trust a per-run certificate. Policy for a whole organisation is "not the focus of this technical preview", and "APIs may change". The policy file is read "from the same ref (branch, tag, or SHA) that the workflow runs from". The README does not say what happens to protocols other than HTTP, or whether an allowlist can hold IP ranges. GitHub's roadmap post of 2026-03-26 put the public preview "6-9 months" out and gave no date for general availability.
- **AWF.** Its own threat table lists "Kernel exploits" as "Not protected", because a container shares its host's kernel, and rates host file access as high risk because the home directory is mounted read-write. "IPv6 not supported (only IPv4 configured)"; whether IPv6 is blocked or merely absent is not stated. `--enable-dind` hands the agent the Docker socket and, in the documentation's words, "allows firewall bypass". The pages disagree about the default mode: the older ones describe `sudo awf` with `iptables` rules on the host, while the command-line help in the notes for release v0.28.71 calls that `--legacy-security` and says a mode that "Requires no sudo/NET_ADMIN" is now the default. Published advisories for AWF were not searched for.
- **Harden-Runner.** Five advisories are published on its repository; four concern egress or privilege, and all four are rated moderate. Two are bypasses of the block policy, by DNS over HTTPS ([GHSA-46g3-37rh-v698](https://osv.dev/vulnerability/GHSA-46g3-37rh-v698)) and by DNS over TCP ([GHSA-g699-3x6g-wm3g](https://github.com/advisories/GHSA-g699-3x6g-wm3g)). Both are fixed in v2.16.0, both say the attacker must already be running code in the workflow, and both say the enterprise tier is not affected. The third is outbound connections that escaped logging through `sendto`, `sendmsg` and `sendmmsg` (GHSA-cpmj-h4f6-r6pq, published 2026-02-07, titled for the community tier; the advisory itself was not read). The fourth is `disable-sudo` evaded through Docker (GHSA-mxr3-8whj-j74r, fixed in v2.12.0; `disable-sudo-and-containers` is the vendor's answer to it). Harden-Runner's limitations page says it is not supported for jobs that run in a container on the standard labels, because "it needs sudo access on the Ubuntu VM to run", nor on `ubuntu-slim` runners. It sends telemetry about each run to StepSecurity; the community tier can turn that off in block mode. Its documentation says "The Community Tier does not support private repositories." The latest release seen is v2.22.4 (6 November; the page prints no year).
- **Bullfrog.** Runs only on GitHub-hosted Ubuntu runners, and not for jobs in containers. One CVE was found for it, [CVE-2025-47775](https://osv.dev/vulnerability/CVE-2025-47775) (DNS over TCP, fixed in 0.8.4). An independent researcher published three more reports against v0.8.4 between 2026-02-28 and 2026-03-02: reaching a blocked site that shares an IP address with an allowed one by changing the `Host` header, a second DNS query carried in the same TCP segment as an allowed one, and restoring `sudo` through the `docker` group. Each post records no reply from the maintainers. The README now pins v0.11.1; whether those three are fixed in it was not established.
- **Copilot's firewall.** Its page says it "only applies to processes started by the agent via its Bash tool", not to MCP servers or setup steps, and only inside Copilot's own environment.

What this means for OBAAF (inputs to slices 2a.2, 2c.1 and 2c.3):

1. **Where the control lives decides what it is worth.** Of the four that can wrap any job, only GitHub's native firewall sits where the job cannot reach it. AWF confines by taking privileges away inside a container. Harden-Runner and Bullfrog run beside the job, on the same kernel and, unless `sudo` and Docker are removed, under the same root. The published bypasses are close to a ready-made list of the escape tests OBAAF's own control must pass: another resolver, DNS over TCP, DNS over HTTPS, a `Host` header aimed at a shared address, `sudo`, and the Docker socket.
2. **OBAAF should not write another firewall if an existing one can be used.** AWF is MIT-licensed, is published as an action, wraps any command, and by its documentation drops the privileges the confined command would need to undo it. The design in slice 2c.1 should start from pinning and wrapping AWF; slice 2c.2 then has to prove it with OBAAF's own escape tests in CI, and slice 2c.3 to teach the checker to recognise the step. Building a new mechanism is justified only if AWF fails those tests or cannot be pinned and verified. GitHub's native firewall is the better choice wherever it is available, and the checker should come to recognise it too.
3. **OBAAF's present test for an egress control is too generous.** OBAAF-GHA-020 clears today for any step that uses `step-security/harden-runner` with `egress-policy: block` and has no `if:`. It does not look at the version (releases before v2.16.0 have two published bypasses of the block policy), at whether `sudo` and containers are removed, at where in the job the step sits, or at whether the repository is one the free tier covers. Slice 2c.3 has to tighten this.
4. **AWF's key proxy is the "inference proxy" OBAAF specified and never built.** OBAAF's agent control R3 keeps the model key out of the agent's reach, and [the inference proxy page](inference-proxy.md) says OBAAF ships none. AWF's README says its API proxy is "always enabled", and the notes for release v0.28.71 give the default as "strict security (network-isolation + api-proxy)"; its usage page lists the flag as off by default. If the README is right, an agent job run under AWF may be able to clear OBAAF-GHA-005 by a control that exists today. That has to be tested before it is claimed.
5. **A statement OBAAF repeats is going out of date.** The agent template and its README, the inference proxy page, the text of OBAAF-GHA-020 and agent control R7 all say GitHub-hosted runners have no native egress allow-list. That is still true of what is generally available, and no longer true of what is in preview.

### GitHub Agentic Workflows: the nearest neighbour

GitHub Agentic Workflows became generally available on 2026-10-28. A workflow is written in Markdown with a YAML header and compiled into an ordinary Actions workflow (a `.lock.yml` file). Its documentation and the announcement describe these layers:

- The agent job "runs with minimal read-only permissions, while write operations are deferred to separate jobs".
- What the agent wants to write (an issue, a comment, a pull request) is buffered as an artifact, the "safe outputs", and applied by separate jobs that each hold one narrow permission.
- "a separate detection job" has an agent with a security prompt read those outputs before they are applied.
- The agent runs "inside a sandboxed container behind the Agent Workflow Firewall" (the announcement's words).
- The compiler pins actions and allows only listed expressions. The architecture page also names actionlint, zizmor and poutine as "Security Scanners" the compiler can run; whether they run by default was not established.

It supports Copilot, Claude Code, Codex, Gemini and Pi as engines.

Its documentation is plain about its limits. The README says agentic workflows need "careful human supervision, and even then things can still go wrong". The architecture page says setup steps, custom jobs and the jobs that apply safe outputs are "trusted executable code", "not automatically confined to the agent sandbox"; that the detection job's default is a warn mode which "can publish annotated reviewable outputs even when detection finds a threat or cannot complete"; and that "A read-only `GITHUB_TOKEN` does not remove other credentials or privileged host access."

How this compares with OBAAF, said plainly:

- **OBAAF's agent lane templates aim at the same design** (an agent job with read-only access, and a separate job that applies its proposal after a check), and they are behind. gh-aw is a generally available GitHub product with a firewall and a key proxy. OBAAF's agent template ships with an example agent "which calls no model". A team starting a new agent workflow today should look at gh-aw first.
- **gh-aw governs workflows written in its format.** Nothing on the pages read says it inspects agent jobs written by hand as ordinary workflow files, which is what all 19 of Expectrail's agent jobs are. That, and repository settings, is the ground left to OBAAF: check the agent jobs a repository already has, whatever they were written in, and say what each can reach.
- **gh-aw's compiler calls other scanners rather than rewriting them.** It can run actionlint, zizmor and poutine, which is the route part 1 suggested for OBAAF.
- **OBAAF does not recognise a gh-aw workflow as an agent job with controls.** Whether it should read a compiled `.lock.yml` file and credit the controls in it is a question for slices 2a.2 and 2c.3.

### GitHub's policy features, and what a settings audit can read

**Workflow execution protections** are an allowlist of who may trigger a workflow (actor rules) and which events may start it (event rules). They are set for an enterprise, an organisation or a repository, can target named workflow files, and are evaluated "before a run". When a rule blocks a run, "disallowed workflow runs will fail with an error"; the documentation's example reads "Event 'workflow_dispatch' is not allowed to trigger Actions workflows." Expectrail's workflows record that on 2026-11-11 a run started by `workflow_run` "ended in startup_failure every time", while the same workflow started by `workflow_dispatch` ran. The workflow file does not name the cause. Part 1 lists the incident as an Actions policy that blocked a trigger; the policy cannot be read without administrator access, so that was not confirmed here.

The same feature carries the change of 2026-12-02. GitHub's documentation says it "has added a default policy that will block the `pull_request_target` event in public repositories", and that the policy "will be enforced on December 2, 2026". The default rule applies to public repositories that have no applicable event policy, and started in evaluate mode. The entry of 2026-11-02 also schedules two two-hour windows of temporary enforcement, on 2026-11-09 and 2026-11-16 (16:00 to 18:00 UTC), after each of which the rule returns to evaluate mode. The two changelog entries word its reach differently: the entry of 2026-11-02 speaks of all public repositories unless a policy allows the event, and the general-availability entry of enforcement "for affected repositories that were using the default pull_request_target policy before general availability" (an editor's note there says the date was revised on 2026-10-21). To keep such a workflow running, a repository has to allow the event in a policy, which can name the workflow files it applies to.

**Workflow lockfiles** record the commit of every action a workflow uses, directly or through another action, in `.github/workflows/actions.lock`, written by the `gh actions-lock` extension. An onboarded workflow then "runs its recorded commit", and a "Require lockfile" policy can force adoption. The pages read say nothing about container images or about tools a `run` script downloads, so lockfiles do not cover the `curl … | bash` installs that part 1 found in Expectrail's agent jobs. An older policy, from 2025-08-15, can require every action to be pinned to a full commit SHA.

**Rulesets** are named lists of rules for branches and tags. "Anyone with read access to a repository can view its active rulesets." A bypass list can name roles, teams and GitHub Apps. Where several rulesets or a branch protection rule apply to one branch, "the most restrictive version of the rule applies".

**What can be read, and by whom.** This is what decides how much a read-only audit can see. From GitHub's REST reference (API version 2026-03-10):

| Setting | Endpoints | Who can read it, per the reference |
| --- | --- | --- |
| Rulesets that apply to a repository, with their rules (required approvals, required checks and the rest) | `GET /repos/{owner}/{repo}/rulesets`, `GET /repos/{owner}/{repo}/rulesets/{ruleset_id}`, `GET /repos/{owner}/{repo}/rules/branches/{branch}` | Anyone, without a token, for a public repository |
| Who may bypass a ruleset | the `bypass_actors` field of a ruleset | "only returned if the user making the API request has write access to the ruleset" |
| Environments: required reviewers, wait timer, which branches may deploy | `GET /repos/{owner}/{repo}/environments`, `GET /repos/{owner}/{repo}/environments/{environment_name}/deployment-branch-policies` | Anyone, without a token, for a public repository |
| Actions settings: allowed actions, the SHA pinning requirement, the default token permission, approval for fork pull requests | `GET /repos/{owner}/{repo}/actions/permissions` and the endpoints under it | A token with the "Administration" repository permission (read) |
| Actions policies (workflow execution protections) | `GET /repos/{owner}/{repo}/actions/policies`, `GET /orgs/{org}/actions/policies` | A token with the "Administration" permission (write), per the reference |

So an audit with no token can check, on a public repository, whether a protected environment restricts its branches, how many approvals a ruleset requires and which checks it names. It cannot see who may bypass a ruleset, or the Actions policy that blocks a trigger, without a token that holds more than read access. A settings audit that never asks for more than read access has to report those two as unread, by name, and say what access would show them. None of these endpoints was called in this part; that is slice 2b.1. Classic branch protection rules have endpoints of their own, which were not read.

### CodeQL for GitHub Actions, run on the same targets

CodeQL has analysed workflow files since 2025-04-22, and GitHub's default code scanning setup turns it on when it finds workflows on the default branch. The query pack run here has 17 queries in the default suite and 6 more in the extended one: code injection, checkout of untrusted code (and a time-of-check variant), artifact and cache poisoning, environment and `PATH` injection, exposure of secrets, improper access control, a missing `permissions` block, known vulnerable actions and unpinned tags. None is about an AI agent, a model key or network egress.

| Target | Files read | Default suite | Extended suite |
| --- | --- | --- | --- |
| OBAAF | 5 (4 workflows and `actions/setup-obaaf/action.yml`) | 0 | 0 |
| Expectrail | 32 (27 workflows and 5 local action files) | 0 | 1: `actions/untrusted-checkout/medium` in the local action `expectrail-verify` |
| OBAAF's 15 risky workflows | 15 | 7 | 9 |

On the risky workflows, in the extended suite:

| Test workflow | OBAAF rules its test requires | CodeQL |
| --- | --- | --- |
| `nx-title-injection` | GHA-010, 001 | `actions/code-injection/critical` (twice) |
| `pwn-request` | GHA-001, 002, 008, 009, 011 | `actions/untrusted-checkout/critical`, `actions/missing-workflow-permissions` |
| `unsafe-checkout-opt-in` | GHA-019, 002 | `actions/untrusted-checkout/critical` |
| `pytorch-self-hosted` | GHA-013, 008, 009 | `actions/missing-workflow-permissions` |
| `clinejection-triage` | GHA-007, 003, 008 | `actions/missing-workflow-permissions` |
| `tj-actions-unpinned` | GHA-008, 016, 017 | `actions/unpinned-tag` (extended suite only) |
| `promptpwnd-issue-agent` | GHA-001, 003, 004, 005, 008, 020 | `actions/unpinned-tag` (extended suite only), for the agent action's `v1` tag |
| the other eight | | nothing |

What the run says:

- **CodeQL covers the same generic ground as the scanners in part 1**, and less of it than zizmor did on these files: it reported 7 of the 15 risky workflows, where zizmor reported 12.
- **It said nothing about the `expression-spellings` workflow**, which zizmor, Octoscan and actionlint all reported in part 1. That file reaches an issue's title and body through an environment variable, a group and a wildcard, and reads `secrets.*`.
- **It has no notion of an agent job.** Five of the test workflows are about an agent job. On two of them CodeQL reported something generic (a missing `permissions` block, an unpinned tag), and on none of them anything about the agent. That matches the list of its queries.
- **It reads local action files**, which OBAAF does not (slice 2d.4). It read `actions/setup-obaaf/action.yml` and reported nothing there, where zizmor reported a high `github-env` finding. Which of the two is right was not judged.
- None of CodeQL's findings was judged as a true or false positive.

What OBAAF should do: not rebuild any of this. GitHub's default code scanning setup includes this analysis (which plans get it was read only in summary), and OBAAF's adoption guide should say to turn it on. OBAAF already writes SARIF, so its findings can sit beside CodeQL's in code scanning.

### Provenance: artifact attestations, SLSA, Sigstore and in-toto

These four fit together, and OBAAF already uses all of them rather than its own cryptography:

- **in-toto** defines the envelope: a statement that binds a predicate to the digests of the files it is about. The current version of the attestation framework is 1.2.
- **SLSA** defines levels for how a build was run, and a provenance predicate (`https://slsa.dev/provenance/v1`) that fits in an in-toto statement. Version 1.2, announced on 2025-11-24, added a Source track beside the Build track. Build Environment and Dependency tracks are working drafts. SLSA is a specification, not a tool, and its own text is careful about its reach: Build L3 "does not require that a build platform prevents a producer from performing a risky or insecure build". Nothing about AI agents was found on the pages read.
- **Sigstore** signs with short-lived certificates tied to an identity (for a workflow, its OIDC identity) and records signatures in a public log, so there is no long-lived signing key to steal. The latest cosign release seen is v3.1.4 (the release's files are dated 2026-10-20).
- **GitHub artifact attestations** put the three together: a job with `id-token: write` and `attestations: write` signs an in-toto statement through Sigstore, and `gh attestation verify` checks it. GitHub's documentation says this alone "provides SLSA v1.0 Build Level 2", and that a build run in a reusable workflow shared across repositories can meet Level 3. Public repositories use Sigstore's public instance; private ones use GitHub's own, which has no public log. Private repositories need Enterprise Cloud.

The two tools that used to be the route to SLSA provenance on GitHub, slsa-github-generator and slsa-verifier, both now say they are no longer actively maintained and suggest GitHub artifact attestations and `gh attestation verify` instead.

What OBAAF should do: keep consuming. Its release and agent templates already sign in-toto statements through GitHub's Sigstore with `actions/attest` and `actions/attest-build-provenance`, and its own records are extra predicates in the same envelope. It should not add signing or verification of its own where `gh attestation verify` will do, and should point adopters to that command's `--signer-workflow` and `--deny-self-hosted-runners` options. An attestation does nothing until something refuses to publish an artifact that fails to verify. OBAAF's part there is small and worth keeping: OBAAF-GHA-017 reports a release workflow that signs no provenance, and OBAAF-GHA-016 one that uploads without checking it first.

### What GitHub says is still coming

GitHub's [Actions security roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) of 2026-03-26 listed six items with a timeline. Two have shipped (execution protections, lockfiles) and one is in technical preview (the egress firewall). The other three bear directly on OBAAF's rules, and their state today was not established:

- **Scoped secrets and reusable workflow inheritance.** "Secrets are no longer implicitly inherited". This is the area of OBAAF-GHA-005 and 024, and of the Expectrail incident in which a reusable workflow could not see its caller's environment secrets.
- **A separate permission for managing secrets**, so that "write access to a repository will no longer grant secret management permissions".
- **Actions Data Stream**: "Near real-time execution telemetry". The egress firewall's README names it as where the firewall's events will go at general availability.

Each of these can turn an OBAAF rule from a warning about a gap in the platform into a check that a platform control is switched on. The rules should be revisited as each one ships.

### What part 2 suggests

Inputs to the positioning section (item 1.4), not decisions.

1. **Enforcement: consume, and prove.** Four controls that OBAAF did not write can restrict a job's network on a hosted runner, within the limits listed above (Copilot's covers only Copilot). OBAAF's contribution should be to say which of them really confines an agent job, to test that claim in the open, and to make its checker tell the real thing from a look-alike.
2. **The agent lane: defer to gh-aw for new workflows.** OBAAF's templates should not compete with a generally available GitHub product on its own platform. OBAAF's ground is the agent jobs gh-aw did not compile.
3. **Settings: still open ground, with a hard limit.** No tool in either part compares settings with what the workflows assume. GitHub's API lets anyone read a public repository's rulesets and environments, but not who may bypass a ruleset, nor the Actions policies, without more than read access.
4. **Provenance: nothing to build.** Use GitHub artifact attestations and `gh attestation verify`.
5. **Generic workflow analysis: nothing to build.** Between zizmor, CodeQL, poutine and actionlint the generic rules are covered several times over. Part 1 reached the same conclusion.
6. **A date.** From 2026-12-02 GitHub blocks `pull_request_target` in public repositories unless a policy allows the event. OBAAF has three weeks to be able to tell an adopter whether that applies to them.

## Part 3: enterprise products, and tools aimed at AI agents in CI

*Checked 2026-11-11.*

This part has two halves. The first is seven products sold to security teams. Everything said about them comes from their public pages: marketing pages, press releases and, where they exist, public documentation. Each statement is the vendor's own claim, quoted or closely paraphrased, and none was tested. No account was created, so nothing behind a login was seen; each entry says what that leaves unknown. The second half is the tools and guidance aimed at AI agents running in CI, which is OBAAF's own subject.

### How this part was put together

**Reading.** The pages listed under [Sources](#sources) were read on 2026-11-11. Several vendor pages print no date. One open-source tool, ci-agent-audit, was also read as source code, from a copy of its repository at commit `4a88ee6` (2026-11-07).

**Running.** Nothing in this part was run. An attempt to run ci-agent-audit on the three targets of parts 1 and 2, with no network, was refused by the working session's own safety rules, because the tool came from a source the session had not used before; nothing was done to get around that. Aikido's Opengrep rules were not run either: they need the Opengrep engine, which was not set up. The statements below about what these two would find are therefore from their documentation and, for ci-agent-audit, its source.

### Seven enterprise products

| Product | What its public pages say about CI | Repository settings | Enforces, or reports? | AI agents |
| --- | --- | --- | --- | --- |
| **Wiz** (Wiz Code) | "Wiz now parses your GitHub Actions workflow YAML files and models workflows, jobs, runners, and their relationships" (2026-04-20). Flags "Dangerous triggers like pull_request_target", risky permissions, and keeps an inventory of every action in use | "over 40 Cloud Configuration Rules targeting VCS settings" (a 2024 page) | Findings. Blocking is not stated | "Wiz now detects risks and misconfigurations related to the use of AI agents in CI". Also published research on AI actions (below) |
| **Endor Labs** | "Scan the GitHub Actions used in your workflow files for vulnerabilities, malware, and risky configuration." Named policies: impostor commits, script injection, untrusted checkout, use of the `secrets` object, cloud authentication without OIDC | Yes. Five policies for Actions settings are named, among them "Default workflow token permission should be read only" and "Workflows should not be allowed to create and approve pull requests"; a product page says "over 50 out-of-the-box policies" | "Policies can break builds, block PRs, send notifications, or open tickets" | Its own security agents, which run "inside the coding assistant your developers already have". One is named "CI/CD Posture". Confining an agent inside a CI job is not stated |
| **Cycode** | Cimon, a run-time agent for CI runners built on eBPF. In prevent mode: "unauthorized network call dropped, unexpected process killed, prohibited file access denied". Scanning workflow files is not stated on the pages read | Not stated on the pages read | Cimon blocks at run time, or only observes in detect mode | "AI Teammates" are Cycode's own agents. Nothing on the pages read about an agent inside a CI job |
| **Legit Security** | "CI/CD risk detection, PR checks, pre-receive hooks, gated build steps". Research from 2024: "Legit analyzed 2,500,000 GitHub Actions workflow files" | Through Legitify, its open-source scanner (part 1). How the platform itself reads settings is not stated | Claims gating (the quotation to the left) | "Real-time guardrails against prompt injection, malicious MCP servers, secret leakage, and dangerous operations" for coding assistants such as Cursor, Copilot and Claude Code. An agent inside a CI job is not stated |
| **Apiiro** | "detect CI/CD pipeline and source code management (SCM) misconfigurations, vulnerabilities, exposures"; an inventory of pipelines. GitHub Actions is not named | "SCM misconfigurations"; which settings is not stated | "scan and AutoFix vulnerable or non-compliant code before it reaches the source control manager". A block on a merge or a build is not stated | "Prevent coding agents from generating vulnerable and non-compliant code"; finds "MCP servers, skills, plugins" on developers' machines. An agent inside a CI job is not stated |
| **Snyk** | Its GitHub Actions run Snyk's scanners in CI ("for checking your projects for vulnerabilities"). Nothing read says any Snyk product analyses workflow files | Not stated | The actions "fail the workflow when issues are found" | An "Agent Security solution" (2026-03-23): Agent Scan for "every MCP server and agent skill", Agent Guard for "stopping destructive commands" in the development loop. Agents inside CI jobs are not mentioned |
| **Chainguard** | Chainguard Actions: "a securely rebuilt catalog of GitHub Actions and similar CI/CD workflows", in open beta since 2026-06-24, with "the last 5 versions of 500+ Actions". It does not scan a customer's workflows for weaknesses; a migration tool lists the actions they use | Not stated | A repository uses it by allowing `chainguard-actions/*` in its Actions settings | Agent Skills: "a continuously maintained catalog of hardened AI agent skills". "network access scoping" is listed only among rules planned for later |

Open source, price, and what cannot be known without an account:

- **Wiz.** Nothing open source is named on the pages read, and no price. Its public guide to hardening GitHub Actions (2026-04-15) recommends zizmor for linting workflows and names allstar, pinact and Gato-X. Not knowable from them: the rules themselves (the links go to the product and its documentation behind a login), which permissions its GitHub integration asks for, whether anything blocks, and whether the 2024 figure for settings rules is current.
- **Endor Labs.** Its documentation is public and names its policies, which is more than the others publish. Its agents are "free and open source for Endor Labs customers"; the licence is not named. Prices are not stated. Not knowable: the permissions its GitHub App needs, and how the "Block compromised action versions and tag hijacks in real time" on a product page works, which the documentation read does not describe.
- **Cycode.** "Cimon is free and open source. It runs on GitHub Actions and Azure Pipelines." (a page updated 2026-07-01). The licence is not named there, and Cimon's repository was not read. The same page says Cimon "can run as a standalone tool or connect to the Cycode platform", and that connecting "means generating an API key in Cycode"; its 2023 instructions required the Cimon GitHub App and an API key. Not knowable: what the platform reads of workflows and settings, and prices.
- **Legit Security.** Legitify is open source (part 1). No price. Not knowable: the platform's rules, whether it parses workflow files, and how it connects to GitHub.
- **Apiiro.** Nothing open source is named, and no price. Not knowable: the rules, which CI systems are supported, which settings are read.
- **Snyk.** Agent Scan's command-line tool is Apache-2.0. It needs a Snyk token, and its page says it validates what it finds "with local checks and the Agent Scan API", sending agent application details, MCP server configurations, tool names and descriptions and skill content to Snyk, with secrets redacted. In March 2026 Agent Scan was in open preview and Agent Guard in private preview; their state today was not established. No price on the pages read.
- **Chainguard.** A "30-day free trial"; no price after it. Not knowable from the pages read: whether the rebuilt actions are signed or carry provenance, and what Checks, Workspaces and Harness (in its navigation) and a Chainguard MCP (a post) do; the posts for Checks, Workspaces and MCP are dated 2026-10-14.

What the seven have in common, and what that means for OBAAF:

- **Their AI claims are mostly about a different place.** Legit, Apiiro, Snyk, Endor and Chainguard describe the developer's side: the coding assistant, its MCP servers and skills, and the code it writes. On the pages read, only Wiz says, in so many words, that it detects misconfigured AI agents in CI. OBAAF's subject, an agent running in a CI job with the job's secrets and token, is not crowded among these seven, and is no longer empty either.
- **Where they read settings, the pages describe checks against fixed good practice** ("Default workflow token permission should be read only"). None says it compares a setting with what the repository's workflows assume, which is what all six of Expectrail's incidents were. That agrees with part 1. It is also a statement about marketing pages, not about products nobody here has used.
- **Cimon is a sixth way to restrict a job's network**, beside the five in part 2, and like Harden-Runner and Bullfrog it runs on the runner beside the job. It belongs in slice 2c.1's reading list.
- **OBAAF cannot compete with these as products and should not try.** They come with support, dashboards, and coverage of many systems. What a small open-source project can offer beside them is narrow, checkable and free: a specific question answered with evidence.

### Tools and guidance aimed at AI agents in CI

#### ci-agent-audit: the nearest open-source neighbour

[ci-agent-audit](https://github.com/layer8labs8/ci-agent-audit) "reads your GitHub Actions and GitLab CI files and warns you when an AI agent such as Claude Code, Gemini CLI, or Codex is set up in a way that an outsider could abuse." It is MIT-licensed, written in Python (about 3,400 lines), marked alpha, at version 0.1.4. It "only reads YAML files", writes text, JSON, SARIF and GitHub annotations, can fix three kinds of finding itself, and runs as a command, an action or a pre-commit hook. How many people use it was not established.

It finds agents by name: 20 signature files, one per tool, listing, where they apply, the action names, the command-line program and package, the inputs and flags that carry a prompt, the settings that are dangerous, and, for one, a minimum safe version. Its eleven rules, in its own words:

| Rule | Its question | Nearest OBAAF rule |
| --- | --- | --- |
| AIA001 | "Can outsiders write part of the agent's prompt?" | None for the prompt as such. GHA-010 covers event text in a script; GHA-012 covers instruction files from the change under review |
| AIA002 | "Are the agent's safety checks turned off?" (flags such as `--dangerously-skip-permissions`) | None |
| AIA003 | "Can anyone trigger the agent?" (a `[bot]` name check that can be spoofed, or `"*"`) | None. GHA-001 looks at the trigger and a secret, not at the action's own allowlist |
| AIA004 | "Is the agent action outdated or on a moving version?" | GHA-008 for the moving version. Nothing for a version known to be unsafe |
| AIA005 | "Does the agent hold too much access?" | GHA-003, 004, 005 |
| AIA006 | "Can the agent send data anywhere?" | GHA-020 |
| AIA007 | "Does CI download MCP servers with no fixed version?" | None |
| AIA008 | "Does a privileged job run the agent on untrusted PR code?" | GHA-002, 012 |
| AIA009 | "Is the agent told or allowed to fetch issue text with `gh`?" | None |
| AIA010 | "Does the model's answer reach a shell or git command?" | GHA-021 and 022, for a separate effect job |
| AIA011 | "Is agent work pushed straight to `main`?" | GHA-022 |

The right-hand column comes from reading both rule lists, not from running both tools on the same files.

Its README is candid about limits. It reports "93.9% recall and 100% precision" on its own cases and adds: "We wrote them ourselves, so treat this as a regression check and not a promise about your repository." It "can't detect agents that read issues through their own built-in tools when the workflow doesn't mention them", does not follow data through artifacts, caches or scripts in other languages, and "takes `sandbox: read-only` as written and doesn't verify what the sandbox enforces".

What this means for OBAAF, said plainly:

- **It asks OBAAF's question, and on named tools it asks it in more detail.** OBAAF's own list is 11 action names and 10 command patterns, and it reads none of the agent actions' dangerous settings. Rules AIA002, 003, 007 and 009 have no counterpart in OBAAF at all.
- **Neither tool finds an agent it has no name for.** Of Expectrail's 19 declared agent jobs, two install and call a named agent program. The other 17 start their model from the project's own code (twelve through `python -m agents.…`, five through other project modules), and ten of them install an agent's command-line program with `curl … | bash`; Expectrail's configuration says "The checker does not recognise our model entry points". Neither tool's list names any of these. Both tools let an adopter extend the list (ci-agent-audit with `--signatures-dir`, by action or program name; OBAAF with `agents.commands` and `agents.actions`). Only OBAAF also lets a job be declared an agent job outright, which is what Expectrail did; no equivalent was found in ci-agent-audit's README. A heuristic worth testing for `obaaf init` is a job that holds a model provider's key.
- **What OBAAF has that it does not:** a declared agent job that no name matches; a secret tied to the environment it belongs in (GHA-024); the release and provenance rules; rules for a separate job that applies an agent's output; and, planned, settings and controls that are verified, not taken as written.
- **Both tools share the weakness slice 2c.3 is meant to remove from OBAAF:** they accept a control because the workflow file says it is there.

Its README names one more project in the area, ARKEXA, which was not read.

#### Research: PromptPwnd and the AI actions

[Aikido's PromptPwnd](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents) (2025-12-04, updated 2026-03-17) named the pattern: "Untrusted user input → injected into prompts → AI agent executes privileged tools → secrets leaked or workflows manipulated." It reports that "At least 5 Fortune 500 companies are impacted" and that Google patched its own Gemini CLI repository "within four days". Aikido says it is "open-sourcing Opengrep rules for all security vendors"; those rules were not read or run here. Its remedies: restrict the agent's tools, keep untrusted input out of prompts, treat the agent's output as untrusted code, and limit what a leaked token can do.

[Wiz's study of AI-powered actions](https://www.wiz.io/blog/github-actions-security-ai-powered-actions-vulnerabilities) (2026-04-30) looked at `anthropics/claude-code-action`, `google-github-actions/run-gemini-cli`, `openai/codex-action` and `actions/ai-inference`. It found that "Only two actions - claude-code-action and codex-action - implement their own permission checks", that checks on a bot's name do not tell an app installed in the repository from an outside one, and that verbose output modes expose secrets. Its first recommendation to workflow authors includes: "Do not rely on core models to prevent prompt injection." It released no tool; it points Wiz's customers to rules in the product.

Both describe exactly the agent job OBAAF's rules are about, and both recommend controls OBAAF does not yet check: the action's own allowlist of who may trigger it, and the tools the agent is given.

#### The agent actions' own guardrails

Two widely used agent actions document their own controls, and those controls are things a checker can read.

- **`openai/codex-action`** (Apache-2.0) has an input `safety-strategy`. Its default, `drop-sudo`, "revokes the default user's `sudo` access before invoking Codex", removes access to service sockets "including the Docker daemon", and starts Codex "with `no_new_privs`, no supplementary groups, and empty" capability sets. The other values are `unprivileged-user`, `read-only` and `unsafe` ("No privilege reduction"). The action gives the model key to a proxy it starts, not to Codex; the README warns Codex "could read it if it can reach process memory", and the security notes say passwordless `sudo` can expose it. By default only people with write access can trigger it. Its recommended profile "does not grant network access"; a list of allowed hosts is not described.
- **`anthropics/claude-code-action`** "can only be triggered by users with write access to the repository" unless `allowed_non_write_users` or `allowed_bots` is set; its security page calls the first "a significant security risk". When `allowed_non_write_users` is used, it recommends "restricting allowed tools" to the minimum. It strips hidden text from what the agent reads, "but new bypass techniques may emerge". Its security page says nothing about restricting the network.

What this means for OBAAF:

- **`safety-strategy: unsafe`, `allowed_non_write_users: "*"`, `allow-users: "*"` and `--dangerously-skip-permissions` are cheap, exact things to report**, and OBAAF reports none of them. ci-agent-audit's signature files list all four; whether Aikido's rules cover them was not established.
- **`drop-sudo` is prior art for slice 2c.** It is the same list OBAAF's own control needs: no `sudo`, no Docker socket, no new privileges, no capabilities. It restricts privilege, not the network, so it complements a firewall and does not replace one.
- **A second key proxy exists.** With AWF's (part 2), that is two shipped partial answers to the "inference proxy" OBAAF's agent control R3 calls for. Both run on the runner, inside the job. R3 asks for a proxy "outside the agent's reach", and the fix text of OBAAF-GHA-005 for one "outside the job"; whether either is enough has to be tested before OBAAF-GHA-005 points at them.

#### Scanners for agent configuration, which are not about CI

[Snyk's agent-scan](https://github.com/snyk/agent-scan), [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules) (MIT), [agent-audit](https://github.com/HeadyZhang/agent-audit) (MIT; its README says 66 rules mapped to the OWASP Agentic Top 10) and [promptwarden](https://github.com/paulochastinet/promptwarden) (MIT) scan agent code, MCP configurations, and skill and instruction files. None of their pages says it reads a workflow file. OBAAF has two rules that read these files (a code owner for instruction files, and hidden characters in them); OBAAF-GHA-012 reads the workflow. It should not grow them into a scanner of agent configuration; these tools exist.

Not read: two GitHub previews announced on 2026-10-28, "Code scanning for AI applications" and "AI Scan for repositories", known here only by their titles.

### What part 3 suggests

Inputs to the positioning section (item 1.4), not decisions.

1. **OBAAF is not alone on its own subject.** Part 1 found no tool, among the ten it read, with the agent framing. At least three outside that list have it: ci-agent-audit, in the open; Wiz, by its own account; and Aikido, which says its product and its open Opengrep rules detect the pattern (not read or run here). Others were not read (ARKEXA) or not looked for. OBAAF cannot claim to be the only one.
2. **What is left that only OBAAF does** is narrower and still real: agent jobs that are declared because nothing can detect them; a secret bound to an environment; the job that applies an agent's output; settings checked against what the workflows assume; and controls verified from what can be read, with "cannot tell" where they cannot.
3. **On named agent tools OBAAF is behind ci-agent-audit, which was first released on 2026-10-30 and is marked alpha (OBAAF is marked alpha too).** It should either adopt signature files of the same kind and the checks for dangerous settings, or read ci-agent-audit's output, or recommend it alongside. Which one is a decision for 1.4.
4. **Enterprise products: do not compete; be the narrow, checkable thing beside them.**
5. **Two shipped key proxies and one shipped privilege drop** (AWF, `codex-action`) are candidates for the control behind OBAAF-GHA-005; AWF's firewall, not either proxy, is the candidate for 020. Both proxies run on the runner inside the job, which is weaker than the proxy "outside the job" that the fix text of OBAAF-GHA-005 asks for; R3 itself says "outside the agent's reach". Whether either clears a rule has to be tested first.


## Positioning: where OBAAF stands, and what it plans to do about it

*Written 2026-11-11, from parts 1 to 3. These are the positions the [flagship plan](flagship.md) works to. They are proposals until OBAAF's maintainers accept them.*

OBAAF is a small open-source project with one adopter, and that adopter is its author's own. A third of its rules report what larger tools report too, and on its own subject it is no longer alone. So the position is narrow on purpose:

> For the jobs in a repository that run an AI agent or publish a release, OBAAF says what each job can reach, checks that the controls claimed for it are real (in the workflow file, in the repository's settings, and while the job runs), and shows its evidence. For everything else it points to the tool that already does it well.

This is the position OBAAF is building towards. Today it reads workflow files only: no settings, nothing enforced, and a control is accepted because the file names it.

The aim is that a team can run OBAAF as its default check and lose nothing. A team that runs only `obaaf check` today does lose something: what zizmor, CodeQL, actionlint and poutine report. The aim is met by setting those tools up beside OBAAF, not by rewriting them inside it, and it is not met until `obaaf init` does that.

### Where OBAAF does not compete

"Not run here" means the recommendation rests on the tool's documentation, as read in parts 2 and 3.

| Area | Use this | What OBAAF does there |
| --- | --- | --- |
| General weaknesses in workflow files: script injection, checkout of a pull request's code, unpinned actions, token permissions, caches, runners | zizmor first: it has the most rules and fixes some findings itself. CodeQL where code scanning is on. actionlint for plain mistakes. poutine for scripts piped into a shell | Adds no new general rule. Keeps the eight it has, because the one adopter gates on them, and holds them to the standard in the next section. Planned (slices 3.2 to 3.4), not built: the first run names these tools; `obaaf init` offers to set them up beside OBAAF, reporting only; the adoption guide tells readers to turn on GitHub's default code scanning setup |
| Restricting what a job can reach on the network | GitHub's native egress firewall where a repository has it. Otherwise the Agent Workflow Firewall. Harden-Runner or Cimon where a team already runs one. None was run here | Planned (slice 2c), not built: a small action that pins and wraps AWF, escape tests that try to get out of it on every change, and a checker that recognises a real control and refuses a look-alike. OBAAF writes a mechanism of its own only if AWF fails those tests |
| Controlling who and what can start a workflow | GitHub's workflow execution protections | Planned (slice 2b), not built: where the policy can be read, compare it with the triggers the workflows use, starting with the `pull_request_target` change of 2026-12-02 |
| Pinning and vetting the actions a workflow uses | GitHub's workflow lockfiles and its policy for pinning to a commit. Chainguard Actions is a commercial option (not run here) | Keeps its report of unpinned actions (GHA-008). Does not yet know about lockfiles |
| Writing a new agent workflow | GitHub Agentic Workflows (not run here) | OBAAF's agent lane templates stay as a worked example of its controls. They are not the recommended place to start |
| Signing and verifying what was built | GitHub artifact attestations and `gh attestation verify` | Keeps its own records (an agent's run, an approval, a build) as in-toto statements signed the same way, and its two rules about releases without provenance |
| Scanning what steers an agent: skills, MCP servers, instruction files | Snyk's agent-scan, Agent Threat Rules, agent-audit, promptwarden (none run here) | Keeps its two small rules about instruction files. Adds none |
| Checking a whole organisation's settings against a standard | Legitify, OpenSSF Scorecard, or one of the enterprise products | Planned (slice 2b), not built: a settings audit that reads only the settings the repository's own workflows depend on |
| Other CI systems | poutine reads GitLab, Azure DevOps and Tekton | GitHub Actions only. Jenkins support stays advisory, as it is |

### Where OBAAF must be at least as good

Each of these is something a test can check.

1. **On the rules it shares with other tools**, OBAAF must report what the best of them reports on the same file, or the rule's description must say what it does not follow. Released OBAAF 0.2.0 fails this: three linters reported the `expression-spellings` workflow and OBAAF 0.2.0 misses the spellings in it. The fix (slice 2d.1) is merged and not yet released. A test in OBAAF's own CI should run zizmor on OBAAF's risky workflows, and on at least one set of workflows OBAAF's authors did not write, and fail when zizmor reports a weakness that maps to an OBAAF rule and OBAAF is silent, unless the mapping records why.
2. **On agent tools that have a name**, OBAAF must recognise at least the tools ci-agent-audit recognised on 2026-11-07 (its commit `4a88ee6`), and must report the settings those tools' own documentation warns about. Today it does neither.
3. **In reading workflow files**: YAML anchors, expressions, local actions and reusable workflows are read, or reported as not read. Octoscan could not read the parts of Expectrail's workflows that use anchors; CodeQL reads local action files and OBAAF does not yet.
4. **As a tool to live with**: SARIF, JSON, stable exit codes, a way to set a finding aside, and a first result in minutes. zizmor already offers the first four, and also fixes some findings itself, which OBAAF does not: it prints a fix and applies none. OBAAF's own way of setting a finding aside asks for a reason and an expiry date, and should keep doing so.
5. **In saying what it cannot do.** Every rule is to state what it does not follow; many of OBAAF's rule descriptions do not yet. ci-agent-audit's README, with its section "What it can't do", is the standard to meet.

### What OBAAF alone does

Checked against OBAAF's code on 2026-11-11, and against the tools in parts 1 to 3 as far as their pages and the runs show.

Today:

- **A job can be declared an agent job, whatever starts the agent.** A job the checker would otherwise class as trusted or untrusted can be declared an agent, effect or release job; a declaration cannot move a job to a lane with fewer rules. A job has one lane, so one already classed as release or effect cannot also be declared an agent job. This is how Expectrail's 17 home-grown agent jobs are checked at all.
- **A secret can be tied to the environment it belongs in**, and a job that uses it without naming that environment is reported (OBAAF-GHA-024). OBAAF knows this only from its configuration file; like zizmor, it cannot see where the secret is stored. zizmor has a neighbouring audit that is not told which secret belongs where.
- **Rules for the job that applies an agent's output** (OBAAF-GHA-021, 022) and for releases (016 to 018). No tool that was run reported these. By their rule lists, ci-agent-audit's AIA010 and AIA011 and Checkov's CKV_GHA_5 and 6 come close; neither was run.
- **Signed records of an agent's run and of a person's approval**, and commands that refuse a release or an agent's proposal without them. Expectrail uses only `obaaf proposal check`; no adopter uses the signed records or `obaaf verify`.

Planned in the flagship work, and not built yet:

- **Findings that a control can clear.** Each finding ends as fixed by a control OBAAF verified, accepted by a named person until a date, or new; and where OBAAF cannot tell, it says "cannot tell".
- **Settings compared with what the workflows assume**: an environment a job relies on that any branch can use, a required check that no workflow reports, a trigger that a policy blocks (where the policy can be read; that needs more than read access). No tool in parts 1 to 3 says it does this.
- **Evidence that a control holds**: escape tests that run in the open on every change, and a checker that tells the control from something that only looks like it. Whether the other projects publish tests of this kind was not checked, so this is not claimed as OBAAF's alone.

Not alone, and not to be claimed as such: asking what an agent job in CI can reach. ci-agent-audit does. Wiz and Aikido say their products detect misconfigured agents in CI; neither was tested here.

### Rule by rule

R means another tool reported the same or a neighbouring weakness on that rule's test workflow, in the runs of parts 1 and 2. "R: none" does not mean the tools were silent on the file. D means the overlap is read from a tool's list of rules, and that tool was not run.

Positions: *Shared* means at least one other tool reports the same weakness. *Partly shared* means another tool reports part of it. *OBAAF's subject* means agents in CI, where OBAAF is not alone. *OBAAF's* means no tool that was run reported it.

| OBAAF rule | What it reports | Who else reports it | Position |
| --- | --- | --- | --- |
| GHA-010 | Untrusted event text expanded in a script | R: zizmor `template-injection`, CodeQL `actions/code-injection`, poutine `injection`, Octoscan `expression-injection`, actionlint | Shared |
| GHA-002, GHA-019 | A pull request's code checked out in a privileged workflow | R: CodeQL `actions/untrusted-checkout`, poutine `untrusted_checkout_exec`, Octoscan `dangerous-checkout`; zizmor `dangerous-triggers` reports the trigger | Shared |
| GHA-008 | An action or image not pinned to a digest | R: zizmor `unpinned-uses`, CodeQL `actions/unpinned-tag`. GitHub can also enforce pinning by policy and by lockfile | Shared |
| GHA-009 | Token permissions not declared | R: zizmor `excessive-permissions`, CodeQL `actions/missing-workflow-permissions`, poutine `default_permissions_on_risky_events` | Shared |
| GHA-011 | Checkout leaves the job token on disk | R: zizmor `artipacked`, which is wider: OBAAF's rule covers agent jobs and untrusted triggers only | Shared |
| GHA-013 | Self-hosted runner used for untrusted work | R: poutine `pr_runs_on_self_hosted`; Octoscan and actionlint `runner-label` | Shared |
| GHA-006 | A release job can read a shared cache | R: zizmor `cache-poisoning` | Shared |
| GHA-015 | A release workflow started by untrusted input | R: zizmor `dangerous-triggers`, which reports the trigger and not that the workflow releases | Partly shared |
| GHA-001 | A secret reachable from an untrusted trigger | R: zizmor reports the trigger and, outside its default persona, the secret, as separate findings | Partly shared. The combination is OBAAF's |
| GHA-014 | A release job not behind a protected environment | R: zizmor `secrets-outside-env`, outside its default persona, reports the secret used with no environment | Partly shared. Means little until the settings audit can read the environment |
| GHA-003, 004, 005 | An agent job can write, can request cloud credentials, holds a secret | R: zizmor reports some of the same permissions, without knowing the job runs an agent. D: ci-agent-audit AIA005 | OBAAF's subject |
| GHA-012 | An agent reads instructions from the change under review | R: none. D: ci-agent-audit AIA008 is close | OBAAF's subject |
| GHA-020 | An agent job with no egress restriction | R: none. D: ci-agent-audit AIA006 | OBAAF's subject. Slice 2c is to make it checkable |
| GHA-021, 022 | An agent's output applied without verifying its record, or without approval | R: none. D: ci-agent-audit AIA010 and AIA011 are close | OBAAF's subject |
| GHA-007 | A low-trust workflow can write the default branch's cache | R: none. CodeQL's three cache poisoning queries are about this weakness; run on this rule's test workflow, they reported nothing | OBAAF's, and close to CodeQL's by its rule list |
| GHA-016, 017 | A release uploaded without a provenance check, or built without provenance | R: none. D: Checkov CKV_GHA_5 and 6 sit next to GHA-017 | OBAAF's |
| GHA-018 | A signing key available to build steps | R: none | OBAAF's |
| GHA-024 | A protected secret used outside its environment | R: zizmor `secrets-outside-env`, outside its default persona, is close | OBAAF's |
| GHA-023 | A placeholder left in an OBAAF template | Not applicable | Housekeeping |
| REPO-001, REPO-002, INS-001 | No code owner for CI files or instruction files; hidden characters in an instruction file | D: the scanners for agent configuration in part 3 cover instruction files | Kept small |

Eight of the 24 GitHub Actions rules are shared outright and three partly. OBAAF has one adopter. GitHub wrote in April 2025 that during the preview of CodeQL's workflow analysis it had "helped secure over 158,000 repositories"; use of the other tools was not measured. On those eight rules OBAAF adds little that a team running zizmor does not already have; they stay because rule ids are stable and the one adopter gates on them. The 15 Jenkins rules are advisory and are not in the table.

### What changes in OBAAF's plan because of this

1. **No new general rules** (decision F-19). Depth goes to the rules that are OBAAF's subject, to the settings audit and to enforcement.
2. **Egress (slice 2c) starts from AWF** (F-20), not from a new mechanism. The checker is to recognise GitHub's native firewall, AWF and OBAAF's wrapper, each under stated conditions, and Harden-Runner only when its version, the removal of `sudo` and containers, the step's place in the job and the kind of repository can all be established without trusting text the workflow's author controls. Otherwise it says "cannot tell".
3. **New agent workflows are pointed at GitHub Agentic Workflows** (F-21). Because of that, slice 2a.2 has to settle whether OBAAF reads the workflows gh-aw compiles and credits their controls, or says plainly that it does not.
4. **Clearing "a secret is available to an agent job" (slice 2a.2)** tests the two key proxies that exist before designing anything.
5. **Agent detection (slices 2d.5 and 3.3)** becomes data in the style of signature files, covers the named tools, reports the settings their documentation warns about as new rules, and for `obaaf init` also proposes any job that holds a model provider's key (F-22). A tool that an agent job installs by a script is OBAAF's to report; the same in any other job is poutine's (F-24).
6. **Parity is tested (slice 2d.3)**: OBAAF against zizmor, audit by audit where one maps to an OBAAF rule, in OBAAF's own CI.
7. **The settings audit (slice 2b) stays narrow** (F-23): each rule compares a setting with something a workflow in the repository uses or assumes.
8. **The first run and `obaaf init` (slices 3.2 to 3.4)** name the companion tools and offer to set them up beside OBAAF, reporting only.
9. **The website (item 4)** leads with the narrow position, says what is built and what is planned, and never says "only" about asking what an agent can reach.

## Sources

Read on 2026-11-11.

### Part 1

- zizmor: [documentation](https://docs.zizmor.sh/), [audits](https://docs.zizmor.sh/audits/), [usage](https://docs.zizmor.sh/usage/), [installation](https://docs.zizmor.sh/installation/), [release notes](https://docs.zizmor.sh/release-notes/), [repository](https://github.com/zizmorcore/zizmor)
- actionlint: [repository](https://github.com/rhysd/actionlint), [checks](https://github.com/rhysd/actionlint/blob/main/docs/checks.md), [usage](https://github.com/rhysd/actionlint/blob/main/docs/usage.md), [configuration](https://github.com/rhysd/actionlint/blob/main/docs/config.md), [releases](https://github.com/rhysd/actionlint/releases)
- poutine: [repository](https://github.com/boostsecurityio/poutine), [releases](https://github.com/boostsecurityio/poutine/releases), [sample configuration](https://github.com/boostsecurityio/poutine/blob/main/.poutine.sample.yml)
- Octoscan: [repository](https://github.com/synacktiv/octoscan), [releases](https://github.com/synacktiv/octoscan/releases)
- OpenSSF Scorecard: [repository](https://github.com/ossf/scorecard), [checks](https://github.com/ossf/scorecard/blob/main/docs/checks.md), [releases](https://github.com/ossf/scorecard/releases), [scorecard.dev](https://scorecard.dev/)
- Legitify: [repository](https://github.com/Legit-Labs/legitify), [releases](https://github.com/Legit-Labs/legitify/releases), [policies](https://policies.legitify.dev/), [product page](https://www.legitsecurity.com/legitify)
- Gato-X: [repository](https://github.com/AdnaneKhan/gato-x), [documentation](https://adnanekhan.github.io/gato-x/), [releases](https://github.com/AdnaneKhan/gato-x/releases)
- Checkov: [repository](https://github.com/bridgecrewio/checkov), [GitHub Actions policy index](https://www.checkov.io/5.Policy%20Index/github_actions.html), [GitHub configuration policy index](https://www.checkov.io/5.Policy%20Index/github_configuration.html), [GitHub scan example](https://www.checkov.io/7.Scan%20Examples/Github.html)
- KICS: [repository](https://github.com/Checkmarx/kics), [CI/CD queries](https://docs.kics.io/latest/queries/cicd-queries/), [documentation](https://docs.kics.io/latest/documentation/)
- Semgrep rules: [repository](https://github.com/semgrep/semgrep-rules), [licence file](https://github.com/semgrep/semgrep-rules/blob/develop/LICENSE)

Not read, and so not relied on: poutine's rule documentation, Octoscan's licence file, the Semgrep rule list for GitHub Actions, and the text of the Semgrep rules licence.

### Part 2

- GitHub's native egress firewall: [early access repository](https://github.com/github-early-access/actions-native-egress-firewall/), [Actions security roadmap](https://github.blog/news-insights/product-news/whats-coming-to-our-github-actions-2026-security-roadmap/) (2026-03-26, updated 2026-03-30)
- Agent Workflow Firewall: [repository](https://github.com/github/gh-aw-firewall), [documentation](https://github.github.com/gh-aw-firewall/), [usage](https://github.com/github/gh-aw-firewall/blob/main/docs/usage.md), [chroot mode](https://github.com/github/gh-aw-firewall/blob/main/docs/chroot-mode.md), [quickstart](https://github.com/github/gh-aw-firewall/blob/main/docs/quickstart.md), [domain filtering](https://github.github.com/gh-aw-firewall/guides/domain-filtering/), [notes for release v0.28.71](https://newreleases.io/project/github/github/gh-aw-firewall/release/v0.28.71) (a third-party copy of the release notes)
- GitHub Agentic Workflows: [repository](https://github.com/github/gh-aw), [licence](https://github.com/github/gh-aw/blob/main/LICENSE), [architecture](https://github.github.com/gh-aw/introduction/architecture/), [network permissions](https://github.github.com/gh-aw/reference/network/), [network configuration](https://github.github.com/gh-aw/guides/network-configuration/), [general availability](https://github.blog/changelog/2026-10-28-github-agentic-workflows-generally-available/) (2026-10-28)
- Copilot's firewall: [customising or disabling the firewall](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/coding-agent/customize-the-agent-firewall)
- Harden-Runner: [repository](https://github.com/step-security/harden-runner), [documentation](https://docs.stepsecurity.io/harden-runner), [how it works](https://github.com/step-security/harden-runner/blob/main/docs/how-it-works.md), [limitations](https://github.com/step-security/harden-runner/blob/main/docs/limitations.md), [releases](https://github.com/step-security/harden-runner/releases), [release v2.16.0](https://github.com/step-security/harden-runner/releases/tag/v2.16.0), [security advisories](https://github.com/step-security/harden-runner/security), [GHSA-g699-3x6g-wm3g](https://github.com/advisories/GHSA-g699-3x6g-wm3g), [GHSA-46g3-37rh-v698](https://osv.dev/vulnerability/GHSA-46g3-37rh-v698), [the `disable-sudo` change](https://www.stepsecurity.io/blog/evolving-harden-runners-disable-sudo-policy-for-improved-runner-security) (2025-04-21), [pricing](https://www.stepsecurity.io/pricing), and the reporter's account of the two DNS bypasses, ["More egress filtering bypasses in harden-runner"](https://devansh.bearblog.dev/harden-runner-bypass/) (2026-03-15)
- Bullfrog: [repository](https://github.com/bullfrogsec/bullfrog), [CVE-2025-47775](https://osv.dev/vulnerability/CVE-2025-47775), and three posts by the same researcher: [shared IP address](https://devansh.bearblog.dev/virtual-hosting-bypass/) (2026-03-02), [DNS pipelining](https://devansh.bearblog.dev/bullfrog-dns-pipelining/) (2026-02-28), [`sudo` through Docker](https://devansh.bearblog.dev/sudo-bypass/) (2026-02-28)
- Workflow execution protections: [governing execution of workflows](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution), [about Actions policies](https://docs.github.com/en/actions/concepts/about-actions-policies), [REST endpoints for Actions policies](https://docs.github.com/en/rest/actions/policies), [public preview](https://github.blog/changelog/2026-06-18-control-who-and-what-triggers-github-actions-workflows/) (2026-06-18), [general availability](https://github.blog/changelog/2026-09-17-workflow-execution-protections-in-github-actions-generally-available/) (2026-09-17), [`pull_request_target` blocked by default](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (2026-11-02), [blocking and SHA pinning in the allowed actions policy](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/) (2025-08-15)
- Workflow lockfiles: [general availability](https://github.blog/changelog/2026-10-28-github-actions-workflow-lockfiles-are-generally-available/) (2026-10-28), [public preview](https://github.blog/changelog/2026-10-14-github-actions-workflow-lockfiles-in-public-preview/) (2026-10-14), [locking action dependencies](https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/secure-your-work/lock-workflow-dependencies)
- Rulesets and other settings: [about rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets), REST reference for [rules](https://docs.github.com/en/rest/repos/rules), [environments](https://docs.github.com/en/rest/deployments/environments), [deployment branch policies](https://docs.github.com/en/rest/deployments/branch-policies), [protection rules](https://docs.github.com/en/rest/deployments/protection-rules), [Actions permissions](https://docs.github.com/en/rest/actions/permissions), and [permissions required for fine-grained tokens](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
- CodeQL for GitHub Actions: [general availability](https://github.blog/changelog/2025-04-22-github-actions-workflow-security-analysis-with-codeql-is-now-generally-available/) (2025-04-22), [the queries](https://docs.github.com/en/code-security/reference/code-scanning/codeql/codeql-queries/actions-built-in-queries); the lists of queries and the results come from the run, not from the page
- Artifact attestations: [concept](https://docs.github.com/en/actions/concepts/security/artifact-attestations), [how to use them](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations), [`gh attestation verify`](https://cli.github.com/manual/gh_attestation_verify)
- SLSA: [specification](https://slsa.dev/spec/), [announcement of version 1.2](https://slsa.dev/blog/2025/11/announce-slsa-v1.2) (2025-11-24), [Build track](https://slsa.dev/spec/v1.2/build-track-basics), [Build requirements](https://slsa.dev/spec/v1.2/build-requirements), drafts of the [Build Environment](https://slsa.dev/spec/draft/attested-build-env-levels) and [Dependency](https://slsa.dev/spec/draft/dependency-track) tracks, [slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator), [slsa-verifier](https://github.com/slsa-framework/slsa-verifier)
- Sigstore: [overview](https://docs.sigstore.dev/about/overview/), [cosign](https://github.com/sigstore/cosign), [cosign releases](https://github.com/sigstore/cosign/releases), [Rekor v2](https://blog.sigstore.dev/rekor-v2-ga/) (2025-10-10)
- in-toto: [attestation framework](https://github.com/in-toto/attestation/blob/main/spec/README.md), [version 1](https://github.com/in-toto/attestation/blob/main/spec/v1/README.md)
- Other GitHub changelog entries: [more control over hosted runners](https://github.blog/changelog/2026-06-25-more-control-over-your-github-hosted-runners/) (2026-06-25), [package firewall](https://github.blog/changelog/2026-10-20-github-package-firewall-in-public-preview/) (2026-10-20; a proxy for package registries, not a control on a runner's network)

Read, but not relied on: StepSecurity's own [comparison of Harden-Runner with GitHub's firewall](https://www.stepsecurity.io/blog/github-actions-native-egress-firewall-vs-harden-runner-five-differences-that-matter) (2026-10-28).

Not read, and so not relied on: the repository of Harden-Runner's agent and its page of advisory GHSA-cpmj-h4f6-r6pq; AWF's architecture and security pages; gh-aw's pages on safe outputs and threat detection (the architecture page was used instead); the REST reference's response schemas; the licence of CodeQL's query pack; the in-toto project's own site; GitHub's documentation on `pull_request_target` and on enforcing lockfiles; and GitHub's changelog listing for Actions, so entries between 2026-06-25 and 2026-10-01 may have been missed.

### Part 3

- Wiz: [Wiz Code and the build environment](https://www.wiz.io/blog/from-code-to-pipeline-wiz-code-now-secures-your-build-environment) (2026-04-20), [hardening guide for GitHub Actions](https://www.wiz.io/blog/github-actions-security-guide) (2026-04-15), [AI-powered actions](https://www.wiz.io/blog/github-actions-security-ai-powered-actions-vulnerabilities) (2026-04-30), [GitHub, GitLab and Azure Repos](https://www.wiz.io/blog/wiz-code-unify-security-across-github-gitlab-and-azure-repos) (2024-07-18)
- Endor Labs: documentation on [scanning GitHub Actions](https://docs.endorlabs.com/scan/github-actions) and [GitHub Action policies](https://docs.endorlabs.com/platform-administration/policies/finding-policies/github-action-policies), product pages on [CI/CD security](https://www.endorlabs.com/use-case/ci-cd-security), [pipeline discovery](https://endorlabs.com/product/endor-labs-ci-cd) and [agentic workflows](https://www.endorlabs.com/platform/agentic-workflows) (none dated)
- Cycode: [CI/CD build hardening](https://cycode.com/blog/cicd-build-hardening/) (updated 2026-07-01), [introducing Cimon](https://cycode.com/blog/introducing-cimon-build-hardening/) (updated 2025-08-12), [press release on run-time protection and AI Teammates](https://www.businesswire.com/news/home/20250422028471/en) (the address is dated 2025-04-22)
- Legit Security: [what is CI/CD security](https://www.legitsecurity.com/blog/what-is-cicd-security) (2024-11-25), [platform overview](https://info.legitsecurity.com/hubfs/Legit%20Agentic%20AppSec%20Platform%20Overview%20(3).pdf) (a PDF, undated), [the state of GitHub Actions security](https://www.legitsecurity.com/press-releases/the-state-of-github-actions-security) (2024-07-15), [introducing Legitify](https://www.legitsecurity.com/blog/introducing-legitify) (2022-08-18)
- Apiiro: [home page](https://apiiro.com/), [ASPM](https://apiiro.com/product/aspm) (neither dated)
- Snyk: [Agent Security announcement](https://snyk.io/news/snyk-launches-agent-security-solution/) (2026-03-23), [agent-scan](https://github.com/snyk/agent-scan), [Snyk's GitHub Actions](https://github.com/snyk/actions)
- Chainguard: [introducing Chainguard Actions](https://www.chainguard.dev/unchained/introducing-chainguard-actions) (2026-03-17), [open beta](https://www.chainguard.dev/de-DE/unchained/secure-your-pipelines-with-chainguard-actions-now-available-in-open-beta) (2026-06-24, read in its German edition), [announcements of June 2026](https://www.chainguard.dev/unchained/everything-we-announced-during-ai-readiness-innovation-week) (2026-06-25), [Agent Skills](https://www.chainguard.dev/de-DE/unchained/introducing-chainguard-agent-skills) (2026-03-17, German edition)
- ci-agent-audit: [repository](https://github.com/layer8labs8/ci-agent-audit), README and source at commit `4a88ee6`; two forks of it were read first ([one](https://github.com/AhmadAnzar/ci-agent-audit), [two](https://github.com/codekongdev/ci-agent-audit))
- Aikido: [PromptPwnd](https://www.aikido.dev/blog/promptpwnd-github-actions-ai-agents) (2025-12-04, updated 2026-03-17)
- `openai/codex-action`: [repository](https://github.com/openai/codex-action), [security notes](https://github.com/openai/codex-action/blob/main/docs/security.md), [documentation](https://developers.openai.com/codex/github-action) (it redirects to learn.chatgpt.com)
- `anthropics/claude-code-action`: [security notes](https://github.com/anthropics/claude-code-action/blob/main/docs/security.md); Claude Code's own [security page](https://docs.claude.com/en/docs/claude-code/security)
- Scanners for agent configuration: [Agent Threat Rules](https://github.com/Agent-Threat-Rule/agent-threat-rules), [agent-audit](https://github.com/HeadyZhang/agent-audit), [promptwarden](https://github.com/paulochastinet/promptwarden)

Not read, and so not relied on: anything behind a login at any of the seven vendors, and their pricing pages; Cimon's repository; Aikido's Opengrep rules; ARKEXA; an "agentic-actions-auditor" plugin listed under Trail of Bits' skills, seen only as a search result; the October 2026 follow-up that Wiz's study of AI actions now links to; Apiiro's command-line tool; Chainguard's Checks, Workspaces, Harness and MCP; and the two GitHub previews for AI applications named above.
