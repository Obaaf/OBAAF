# The landscape: what else checks GitHub Actions, and where OBAAF fits

*Checked 2026-11-11. This first part covers ten workflow scanners. Runtime enforcement and GitHub's own features, enterprise products, and the positioning section are still to come ([flagship plan](flagship.md), items 1.2 to 1.4).*

The aim is a fair comparison a team can rely on. Every fact below comes from a page read or a command run on the date above, and says which. Where a source did not say, this page says "not stated" rather than guess.

## How this was put together

**Reading.** Each project's own documentation and repository pages were read on 2026-11-11. Links are in [Sources](#sources). Three limits apply. GitHub's release pages print a day and month without a year, so release years below are inferred unless marked otherwise. Some GitHub pages appeared to be stored copies up to three months old. And some pages could not be fetched at all; those gaps are named.

**Running.** Five tools publish Linux binaries on their GitHub releases and were run, without a token and without network access, on three targets:

- OBAAF itself, at `461090e`;
- Expectrail, the first adopter, at `0509d73` (27 workflow files). Expectrail is a project of OBAAF's author, so nothing here is an independent result;
- OBAAF's own 15 risky workflows (`tests/fixtures/workflows/risky/`), copied into a repository layout, to see which of OBAAF's rules overlap rules elsewhere.

| Tool | Version run | Command | Download checked against a published checksum |
| --- | --- | --- | --- |
| zizmor | 1.32.0 | `zizmor --offline --no-exit-codes --format json .` (and again with `--persona auditor`) | no checksum file fetched |
| actionlint | 1.7.12 | `actionlint -format '{{json .}}'` | yes |
| poutine | 1.1.6 | `poutine analyze_local . --format json --quiet --disable-version-check` | no checksum file found |
| Octoscan | release tag v0.1.7 (the binary prints "0.1") | `octoscan scan . --disable-rules repo-jacking --format json` | no checksum file found |
| OpenSSF Scorecard | 5.6.0 | `scorecard --local <dir> --format json` | yes |
| OBAAF | 0.2.0 plus `flagship` | `obaaf check .` | built from source |

**The tools did not run on equal terms on Expectrail.** OBAAF ran with Expectrail's own configuration file, which lists 19 jobs as agent jobs by hand because OBAAF does not recognise how they start a model. The other tools ran with their defaults and no configuration. Without that file OBAAF reports 5 findings on the same workflows, not 39.

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
| [Legitify](https://github.com/Legit-Labs/legitify) | 1.0.11 (9 July, year not stated) | Apache-2.0 | Settings through the API only; can also run Scorecard | Yes: about 55 GitHub policies for enterprise, organisation, repository, member, Actions and runner groups. Full results need an organisation owner; a repository administrator sees the repository policies only (27 of the 55). Scopes for full analysis: `admin:org, read:enterprise, admin:org_hook, read:org, repo, read:repo_hook`. Fine-grained tokens are not supported | Reports; remediation steps are manual | None found |
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

Each row is one of OBAAF's published test workflows, the OBAAF rules its test requires it to trigger (with the configuration the test supplies; OBAAF reports other rules on some of these files too), and the rule ids the other tools reported on the same file. A match on the same file is not always the same finding, but an empty cell means the tool said nothing at all about a file OBAAF calls risky. zizmor is shown in its default persona. actionlint's `syntax-check` entries are all `unexpected key "cache-mode"`, a workflow key this actionlint version does not know; OBAAF's own CI runs actionlint with that message ignored.

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
- **No other tool has the agent, effect or release framing, but zizmor reported some of the same underlying facts without it.** In its default persona: the trigger of a release workflow (`dangerous-triggers` on `release-from-comment`, which is what GHA-015 is about), and a job left with default token permissions (`excessive-permissions` on `clinejection-triage`, the condition GHA-003 names for an agent job). In its auditor persona only: write permissions, `id-token: write` and a secret outside an environment on the agent workflow (the facts behind GHA-003, 004 and 005).
- **Nothing reported, in either persona, what these rules are about:** a low-trust workflow that can write the default-branch cache (GHA-007); an agent that reads instructions from the change under review (GHA-012) or can reach the whole network (GHA-020); agent output applied without verification or approval (GHA-021, 022); a release without an approval, a provenance check or provenance (GHA-014, 016, 017); and a signing key in the build (GHA-018).
- **Two rules have no single counterpart.** GHA-001 (a secret reachable from an untrusted trigger) is two separate findings in zizmor, the trigger and, in the auditor persona, the secret. GHA-023 is about OBAAF's own templates.

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
2. No tool read here asks a repository to declare its agent jobs and then asks what each can reach. That is OBAAF's own ground. It is also where OBAAF is weakest in practice: it recognised 2 of Expectrail's 19 agent jobs unaided, and the findings it produced there can only be accepted.
3. OBAAF missed things on its own subject that other tools caught. The agent tool installed with `curl | bash` is the clearest.
4. A team that runs only OBAAF today loses what zizmor, poutine and actionlint report. For "lose nothing by running OBAAF as the default check" to hold, OBAAF has to run them, read their output, or say plainly to run them alongside.

## Sources

Read on 2026-11-11.

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
