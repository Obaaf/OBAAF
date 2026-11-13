# The first adopter: Expectrail

*Plan slice 3.7, written on 2026-11-13. **Expectrail is the project of OBAAF's author**, Sean Keluo-Udeke, who maintains it with Timothy Itodo. This page is therefore no evidence that a team with no tie to OBAAF finds it useful. Results from outside teams are still to come; none has been reported. Everything here comes from public facts: Expectrail's repository and its history, OBAAF's repository, and GitHub's answers to a caller with no token. Every number was computed again for this page, with the commands at the end. Nothing was changed in Expectrail.*

[Expectrail](https://github.com/Expectrail/Expectrail) is an open-source project (Apache-2.0). Its README calls it "an independent verification layer for changes made by AI agents". Several of its GitHub Actions jobs give a language model untrusted input and act on what the model says, and those jobs hold model API keys. That makes it the kind of repository OBAAF was written for.

## In short

- **What worked.** Expectrail had to name its agent jobs, and OBAAF then asked what each could reach. That idea held up. Model keys were moved into one environment limited to `main`, and the checker holds them there. The gate also stopped one unreviewed agent job: it turned `main` red the day after it was switched on.
- **What did not.**
  - Every finding the gate raised could only be accepted. The baseline grew from 32 to 38 entries in 21 hours. Each entry is one of two findings that no setting or change Expectrail could make would clear.
  - Every incident of those days was in GitHub's settings, which OBAAF did not read.
  - Nothing OBAAF ran restricted anything. It reported.
- **What has changed since.** These changes are on OBAAF's `flagship` branch and in no release:
  - an acceptance now needs an owner, a reason and an expiry date;
  - the report begins with the accepted risk;
  - a settings audit, `obaaf audit`, now exists;
  - an egress control now exists, though the checker does not yet credit it.
- **Expectrail still runs the OBAAF of 2026-11-11** (commit `d014b63`). None of the above applies to it until it moves that pin.

## How Expectrail uses OBAAF

The dates below are commit dates in UTC, from Expectrail's history.

- **2026-10-30, 08:56.** "OBAAF Phase A" (`4e02acc0`): the checker runs in reporting mode, and `.github/obaaf.yml` declares 8 agent jobs. The commit message says why: OBAAF "does not recognise python -m agents.*".
- **2026-11-10, 04:07.** OBAAF moves to `d014b63` (`a7d0d4e6`), with `protected_secrets` and a baseline of 32 findings. From then on the CI step
  ```
  obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes
  ```
  fails on any finding not in the baseline. It runs through OBAAF's own `setup-obaaf` action, pinned to that commit (`.github/workflows/ci.yml`, line 57).
- **Today**, at Expectrail's head `da06323` (2026-11-13 19:08), `.github/obaaf.yml` holds:
  - **19 jobs declared `agent`**, and one declared `probe`, a label of Expectrail's own (see below);
  - **`protected_secrets`**: `HELDOUT_TOKEN` and every `*_API_KEY` may be used only by jobs in the environment `main-only`;
  - **one `ignore` entry**, for `OBAAF-GHA-001` on `unity.yml#build`, until 2027-02-09.

Without that file OBAAF recognises **2 of the 19** as agent jobs. Those two install an agent's command-line tool, `byo-live` and `byo-gateway-probe`. The other 17 start a model from the project's own code, which no tool compared in [the landscape](landscape.md) recognises either.

## What worked

- **Declaring agent jobs, then asking what each can reach.** No other tool compared in [the landscape](landscape.md) lets a repository say outright which jobs are agents. In Expectrail that declaration covers 17 jobs that nothing would otherwise find.
- **Keys in one environment.** Expectrail moved every model key into `main-only` (`afc4e7c3`, 2026-11-10 03:21). Rule `OBAAF-GHA-024` keeps them there: a job that reads such a key without naming that environment is a finding. GitHub's answer of 2026-11-13 09:10 UTC shows `main-only` deploying from `main` only ([the settings record](expectrail-settings-audit.md)).
- **The gate stopped an unreviewed agent job once.** At 20:47 on 2026-11-10 (`baee2dc5`), Expectrail recorded that "CI on main failed OBAAF's 'no new findings' step after #231: jit.yml#propose is an agent job with a model key". This happened the day after the gate was switched on. Before it, in reporting mode, the high findings rose from 8 to 17 with nothing failing; OBAAF's [#48](https://github.com/Obaaf/OBAAF/pull/48), which added baselines, gives those numbers.

## What did not work

### Findings that could only be accepted

Every entry in Expectrail's baseline is one of two findings on one of its 19 agent jobs:

- **`OBAAF-GHA-005`**: a secret is available to an agent job;
- **`OBAAF-GHA-020`**: an agent job has no egress restriction.

Neither had a fix Expectrail could apply with OBAAF as it was. The fix text for the first pointed to an inference proxy OBAAF had not built, and the second asked for an egress control OBAAF did not ship. So each new agent job added two findings, and the answer was always to accept them:

| Commit (UTC) | Entries | What happened |
| --- | --- | --- |
| `a7d0d4e6`, 2026-11-10 04:07 | 32 | Baseline created: 16 of each finding |
| `baee2dc5`, 2026-11-10 20:47 | 34 | `jit.yml#propose` added, after main went red |
| `2f32938e`, 2026-11-10 22:48 | 36 | `jit.yml#revise` added |
| `92f668ad`, 2026-11-11 01:18 | 38 | `jit-blind.yml#entry` added |

That is three changes in four and a half hours, each adding the same two findings for one new job. None of the 38 entries names an owner or a reason, and none expires. With Expectrail's pinned OBAAF at its head today, the gate passes: 38 findings accepted, "0 new", exit 0. That line is the problem: a gate whose only answer is "accept" says nothing.

### The incidents were in the settings

The work on OBAAF began from six incidents in Expectrail's first days with the gate. All six were in GitHub's settings, and OBAAF read none of them. What the public record shows of each, and what [the settings audit](expectrail-settings-audit.md) saw on 2026-11-13 at 09:10 UTC:

| Incident, as reported when the work began | What the public record shows | The audit now |
| --- | --- | --- |
| A protected environment created with no branch restriction | Expectrail's `docs/obaaf.md` warns that "GitHub creates a missing environment on first use, with no protection" | `main-only` and `github-pages` are limited to `main`. `unity` is open to every branch: a medium finding |
| A bypass on the branch ruleset that lets the authors' accounts skip every required check | `docs/obaaf.md`: "organization admins may bypass, for pull requests only" | Cannot tell: GitHub shows the bypass list only to a caller with write access to the ruleset |
| Required approvals that the one shared account could never give | `docs/obaaf.md` still says "a pull request with one approval of its latest push" | The ruleset requires 0 approvals |
| A required-checks list that named one check of the eleven that ran | `docs/obaaf.md` still says "a passing `test` check" | 12 checks are required, each reported by a job; three pull-request jobs are not required (medium findings) |
| An Actions policy that blocked a trigger a workflow used | `4332e112` (2026-11-11 17:39): "every run GitHub started that way ended in startup_failure with no job, while the same file started by workflow_dispatch ran" | Cannot tell: reading Actions policies needs write access, which OBAAF never asks for. The commit does not name a policy; that cause comes from the account given when the work began |
| A reusable workflow that could not see its caller's environment secrets | `ad3e0775` (2026-11-10 23:49): "a called workflow does not see the main-only environment's secrets" | Does not apply: no job passes a secret to a reusable workflow now |

For two of these, Expectrail's own page and GitHub's answer now disagree. The page says one approval, and GitHub shows 0. The page says one required check, and GitHub shows 12. Either the settings or the page changed, and nothing compared the two. Comparing the settings with a committed snapshot over time is what the audit's drift check (`obaaf audit --expected`) does. Expectrail does not run it.

### It reported and did not enforce

Expectrail's `docs/obaaf.md` says it plainly: "No agent job has an enforced network policy. `OBAAF_EGRESS` would only record intent, so it is not set." OBAAF offered nothing to enforce.

### The checker was young

An independent review of OBAAF's new rule `OBAAF-GHA-024` found two ways around it the day it was written. One read a secret by a computed name; the other spelled `secrets` in another case. Both were fixed in [#50](https://github.com/Obaaf/OBAAF/pull/50) before Expectrail pinned `d014b63`. The plan assumes more of the same exists.

### A label OBAAF does not have

Expectrail declares `byo-smoke.yml#byo-smoke` with the lane `probe`. This is not one of OBAAF's lanes. The comment in `.github/obaaf.yml` explains: the job "calls each configured provider once and acts only on whether text came back", and Expectrail's own audit script reads `probe`. It is the first recorded case of an adopter using OBAAF's configuration for something OBAAF does not model. The OBAAF it pins ignores the entry. The code on `flagship` reports it as `OBAAF-CFG-001`, a declaration that does nothing.

## What has changed in OBAAF since

All of this is on the `flagship` branch at `7fb8cac`, after release 0.3.0, and in no release. [The plan](flagship.md) has each slice; [the upgrade note](upgrading.md#the-first-adopter) has what Expectrail must do.

- **An acceptance needs an owner, a reason and an expiry date.** One without them accepts nothing (slice 2a.1). Expectrail's baseline is in the old format.
- **The report begins with the accepted risk** (2a.3). Before, it ended in "0 new".
- **`OBAAF-GHA-005` and `OBAAF-GHA-020` list the controls that would clear them** (2a.2), and say for each whether it is verified, not met, or cannot be told. Neither can be cleared yet.
- **`obaaf audit` reads the settings, with 15 rules, and compares them over time** (2b.1 to 2b.6). One rule was written for each of the six incidents above.
- **`actions/egress` confines one command's network to listed hosts** (2c.2). On GitHub-hosted runners, all 20 IPv4 attempts to get out were blocked in CI. It refuses model keys for now, and the checker does not yet credit it (2c.3 and 2c.4).

**What Expectrail would see if it moved its pin today.** This is computed on a copy of its files at `da06323`, with OBAAF at `7fb8cac`.

- **As the files are:** the gate fails (exit 1) with 40 new findings, 20 high and 20 low.
  - The old baseline accepts nothing.
  - The `ignore` entry names no owner, so it accepts nothing either.
  - The `probe` entry is a new high finding.
- **After two changes:** running `obaaf baseline migrate` with an owner, a reason and a date, and adding an owner to the `ignore` entry.
  - 39 findings are accepted, each under that owner until a date: 38 by the baseline and 1 by the `ignore` entry.
  - One is new: the `probe` entry.

  Both changes touch the baseline or the configuration, so under Expectrail's `AGENTS.md` they are Sean's to make.

## What this page does not show

- **That OBAAF helps anyone else.** The only adopter is the author's own project.
- **Anything an administrator's token would show.** The settings were read with no token. So were the bypass list, the Actions policies and the names of secrets, which GitHub then withholds.
- **The settings now.** They were read at 09:10 UTC. This session could not read GitHub's API for Expectrail: its proxy refused the request. The audit was run again offline on that reading, with Expectrail's files at `da06323`. It gave the same 4 medium findings and 7 "cannot tell" as with the files at `36a7a8a`.
- **That the incidents happened as reported.** The table gives what the public record shows. The causes come from the account given when the work began, and this page does not check them where the record is silent.

## How the numbers were made

On 2026-11-13, in the agent's session, with Expectrail cloned read-only (full history) and checked out at `da063233` (`git archive` into a scratch directory, so the clone was not touched):

```bash
# The pinned gate, with OBAAF at d014b63: 38 accepted, 0 new, exit 0
obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes
# The same with OBAAF at 7fb8cac: 40 new (20 high, 20 low), exit 1
# On a copy, after `obaaf baseline migrate ... --owner ... --reason ... --expires 2027-02-01` and an
# `owner:` on the ignore entry: 39 accepted, 1 new (OBAAF-CFG-001), exit 1
# Without .github/obaaf.yml: `obaaf check . --lanes` names 2 agent jobs
# The baseline's history: entries at each commit that touched it
git log --format=%h -- .github/obaaf-baseline.json   # 4 commits: 32, 34, 36, 38 entries
# The settings: the snapshot of 09:10 UTC, with the files at da06323
obaaf audit <files> --fail-on never --from-snapshot tests/fixtures/settings/live-expectrail-2026-11-13/snapshot.json
```

The commit dates are author dates converted to UTC (`TZ=UTC git show -s --date=format-local:...`). The quotations are from the commit messages and from `docs/obaaf.md` at `da06323`.
