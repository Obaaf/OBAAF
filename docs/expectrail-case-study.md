# The first adopter: Expectrail

*Plan slice 3.7, written on 2026-11-13.*

***Expectrail is the project of one of OBAAF's two authors.*** *Sean Keluo-Udeke maintains it with Timothy Itodo. So this page is no evidence that a team with no tie to OBAAF finds it useful. Results from outside teams are still to come, and none has been reported.*

*What the page draws on:*

- *Public facts: Expectrail's repository and its history, OBAAF's repository and pull requests, and GitHub's answers about Expectrail to a caller with no token.*
- *One exception: the list of six incidents came from the brief that started this work. It is published in [the settings audit's guide](settings-audit.md#the-six-incidents), and the page says where the public record supports each one.*
- *Every number about Expectrail's files, its baseline and its settings was computed again for this page. The commands are at the end.*
- *Figures quoted from OBAAF's own pages and pull requests are cited, not recomputed.*

*Nothing was changed in Expectrail.*

[Expectrail](https://github.com/Expectrail/Expectrail) is an open-source project (Apache-2.0). Its README calls it "an independent verification layer for changes made by AI agents". Several of its GitHub Actions jobs give a language model untrusted input and act on what the model says, and those jobs hold model API keys. That is the kind of repository OBAAF was written for.

## In short

- **What worked.**
  - **Agent jobs were declared.** Expectrail named its agent jobs, and OBAAF then asked what each could reach. It is the part of OBAAF that no other tool read for the landscape was found to offer.
  - **Keys stay in one environment.** Every job that uses a model key names one environment limited to `main`, and the checker reports a job that does not.
  - **The gate caught a new agent job.** It reached `main` without baseline entries, and `main` went red about three hours after the gate itself reached `main`.
- **What did not.**
  - **Accepting was always the answer.** Each finding the gate raised was answered by accepting it. The baseline went from 32 to 38 entries in 21 hours, and every entry is one of two findings for which OBAAF itself offered no fix.
  - **The settings were out of view.** The six incidents the work began from were all, as reported, in GitHub's settings, which OBAAF did not read.
  - **Nothing was enforced.** Nothing OBAAF ran restricted a job at run time. It reported.
- **What has changed since.** All of this is on OBAAF's `flagship` branch and in no release:
  - an acceptance needs an owner, a reason and an expiry date;
  - the report begins with the accepted risk;
  - a settings audit, `obaaf audit`, exists;
  - an egress control exists, which the checker does not credit yet.
- **Expectrail still runs the OBAAF of 2026-11-10** (commit `d014b63`). None of the above applies to it until it moves that pin.

## How Expectrail uses OBAAF

The dates are commit dates in UTC, from Expectrail's history.

- **2026-10-30, 08:56: OBAAF Phase A** (`4e02acc0`). The checker runs in reporting mode, and `.github/obaaf.yml` declares 8 agent jobs. The commit says why: OBAAF "does not recognise python -m agents.*".
- **2026-11-10, 17:36: the gate reaches `main`** with Expectrail's #223 (`be5711bc`). Its branch had moved OBAAF to `d014b63` at 04:07 (`a7d0d4e6`), with `protected_secrets` and a baseline of 32 findings. The CI step runs through OBAAF's own `setup-obaaf` action, pinned to that commit (`.github/workflows/ci.yml`, line 57):

  ```
  obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes
  ```

  It fails on any finding that is not in the baseline.
- **At Expectrail's head `da06323` (2026-11-13 19:08),** `.github/obaaf.yml` holds:
  - **19 jobs declared `agent`**, plus one declared `probe`, a label of Expectrail's own (see below);
  - **`protected_secrets`:** `HELDOUT_TOKEN` and every `*_API_KEY` may be used only by jobs in the environment `main-only`;
  - **one `ignore` entry,** for `OBAAF-GHA-001` on `unity.yml#build`, until 2027-02-09.

**Without that file, OBAAF recognises 2 of the 19 as agent jobs.** Those two install Claude Code, which OBAAF has a name for. Ten of the other 17 install an agent tool with `curl … | bash`, which it does not recognise. All 17 start their model from the project's own code, which none of the tools run for [the landscape](landscape.md) recognised either.

## What worked

- **Declaring agent jobs, then asking what each can reach.** Among the tools read for [the landscape](landscape.md), no other was found that lets a repository declare a job an agent job outright. In Expectrail that covers 17 agent jobs OBAAF would otherwise miss.
- **Keys in one environment.** Expectrail's commits moved its model keys into `main-only`. That began with `afc4e7c3` (2026-11-10 03:21). The last keys kept elsewhere, in a `provider-keys` environment, moved with `f287932f` (04:18).
  - Every job that uses such a key now names `main-only`.
  - `OBAAF-GHA-024` reports a job that reads one without naming it. It reads only the workflow files.
  - Whether copies of the keys are stored elsewhere cannot be read without a token.
  - GitHub's answer of 2026-11-13 09:10 UTC shows `main-only` deploying from `main` only ([the settings record](expectrail-settings-audit.md)).
- **The gate caught an agent job that reached `main` without baseline entries.** Expectrail's #231 merged at 20:32 on 2026-11-10. Expectrail's account (`baee2dc5`, 20:47): "CI on main failed OBAAF's 'no new findings' step after #231: jit.yml#propose is an agent job with a model key". That was about three hours after the gate reached `main`.
  - Nothing was undone. #231 had itself declared the job an agent job, and #237 accepted its two findings at 20:56.
  - Before the gate, in reporting mode, the high findings had grown with nothing failing. OBAAF's [#48](https://github.com/Obaaf/OBAAF/pull/48), which added baselines, says in its description that they "went from 8 to 17".

## What did not work

### Findings that were always accepted

Every entry in Expectrail's baseline is one of two findings on one of its 19 agent jobs:

- **`OBAAF-GHA-005`:** a secret is available to an agent job;
- **`OBAAF-GHA-020`:** an agent job has no egress restriction.

**OBAAF itself provided a fix for neither.**

- **`OBAAF-GHA-005`.** At `d014b63` its fix text says "Keep the model credential in an inference proxy outside the job". OBAAF had not built such a proxy. Expectrail's own page says clearing it "needs the gateway hosted outside the job".
- **`OBAAF-GHA-020`.** Its fix asks to "Limit the agent job's egress to the inference proxy, with ephemeral self-hosted runners behind a network policy or a blocking runtime egress monitor that always runs", so it too leans on the proxy OBAAF had not built.
  - The pinned checker clears it for a blocking Harden-Runner step, a third-party tool. Expectrail has not adopted one.
  - Since slice 2a.2, OBAAF no longer credits that step alone ([the upgrade note](upgrading.md)).

So each new agent job added two findings, and the answer was to accept them:

| Commit (UTC) | Entries | What happened |
| --- | --- | --- |
| `a7d0d4e6`, 2026-11-10 04:07 | 32 | Baseline created: 16 of each finding |
| `baee2dc5`, 2026-11-10 20:47 | 34 | `jit.yml#propose` added, after main went red |
| `2f32938e`, 2026-11-10 22:48 | 36 | `jit.yml#revise` added |
| `92f668ad`, 2026-11-11 01:18 | 38 | `jit-blind.yml#entry` added |

The last three changes came within four and a half hours, each adding the same two findings for one new job. None of the 38 entries names an owner or a reason, and none expires.

With Expectrail's pinned OBAAF, the gate passes at its head today: 38 findings accepted, "0 new", exit 0. The report counts the accepted findings, but no acceptance names an owner or an expiry date.

### The incidents, as reported, were in the settings

The work on OBAAF began from six incidents in Expectrail's first days with the gate. As reported, all six were in GitHub's settings, and OBAAF read none of them. Other things went wrong in those days too: the red `main` above, and errors from Expectrail's own main-health job, which `baee2dc5` records.

The table shows, for each incident, what the public record shows and what [the settings audit](expectrail-settings-audit.md) saw on 2026-11-13 at 09:10 UTC:

| Incident, as reported when the work began | What the public record shows | The audit now |
| --- | --- | --- |
| A protected environment created with no branch restriction | Expectrail's `docs/obaaf.md` warns that "GitHub creates a missing environment on first use, with no protection" | `main-only` and `github-pages` are limited to `main`. `unity` is open to every branch: a medium finding |
| A bypass on the branch ruleset that lets the account that authors changes skip every required check | `docs/obaaf.md`: "organization admins may bypass, for pull requests only" | Cannot tell: GitHub shows the bypass list only to a caller with write access to the ruleset |
| Required approvals that the one shared account could never give | `docs/obaaf.md` still says "a pull request with one approval of its latest push" | The ruleset requires 0 approvals |
| A required-checks list that named one check of the eleven that ran | `docs/obaaf.md` still says "a passing `test` check" | 12 checks are required, each reported by a job. Three pull-request jobs are not required: medium findings |
| An Actions policy that blocked a trigger a workflow used | `4332e112` (2026-11-11 17:39): "every run GitHub started that way ended in startup_failure with no job, while the same file started by workflow_dispatch ran" | Cannot tell: reading Actions policies needs write access, which OBAAF never asks for. The commit does not name a policy; that cause comes from the account given when the work began |
| A reusable workflow that could not see its caller's environment secrets | `ad3e0775` (2026-11-10 23:49): "a called workflow does not see the main-only environment's secrets" | Does not apply: no job passes a secret to a reusable workflow now. The audit record notes that this one changed in the workflow files, not in the settings |

On two rows, Expectrail's own page and GitHub's answer now disagree: one approval against 0, and one required check against 12. The page may never have matched the settings, or the settings may have changed since. Nothing compares the two.

OBAAF's drift check (`obaaf audit --expected`) would at least have caught the settings changing. It compares them with a snapshot committed earlier. Expectrail does not run it.

### It reported and did not enforce

Expectrail's `docs/obaaf.md` says it plainly: "No agent job has an enforced network policy. `OBAAF_EGRESS` would only record intent, so it is not set." OBAAF shipped no control of its own to enforce one.

### The checker was young

Two independent reviews found ways past checks OBAAF had just written:

- **GHA-024.** A review of the new rule `OBAAF-GHA-024` found two ways around it: reading a secret by a computed name, and spelling `secrets` in another case. It found more gaps besides. All were fixed in [#50](https://github.com/Obaaf/OBAAF/pull/50).
- **Baselines.** A review of the new baselines found that a forged entry could accept a new high finding. This was fixed in #48 before it merged (`1df61fb`).

Both fixes came before Expectrail pinned `d014b63`. The plan assumes more of the same exists.

### A label OBAAF does not have

Expectrail declares `byo-smoke.yml#byo-smoke` with the lane `probe`, which is not one of OBAAF's lanes. The comment in `.github/obaaf.yml` explains: the job "calls each configured provider once and acts only on whether text came back", and Expectrail's own audit script reads `probe`. So Expectrail used OBAAF's configuration for something OBAAF does not model.

- The OBAAF it pins ignores the entry.
- The code on `flagship` reports it as `OBAAF-CFG-001`, a declaration that does nothing.

## What has changed in OBAAF since

All of this is on the `flagship` branch at `7fb8cac`, after release 0.3.0, and in no release. [The plan](flagship.md) has each slice, and [the upgrade note](upgrading.md#the-first-adopter) has what Expectrail must do.

- **An acceptance needs an owner, a reason and an expiry date** (slice 2a.1). One without them accepts nothing. Expectrail's baseline is in the old format.
- **The report begins with the accepted risk** (2a.3). Before, the report ended in "0 new".
- **`OBAAF-GHA-005` and `OBAAF-GHA-020` list the controls that would clear them** (2a.2). For each control the report says whether it is verified, not met, or cannot be told. Neither finding can be cleared yet.
- **`obaaf audit` reads the settings and compares them over time** (2b.1 to 2b.6). It applies 15 rules, and each of the six incidents above has at least one.
- **`actions/egress` runs one command with its network limited to listed hosts** (2c.2). In OBAAF's CI on GitHub-hosted runners, all 20 IPv4 attempts to get out were blocked. Its limits:
  - IPv6 was not testable;
  - a host name the command asks the proxy for still leaves the runner in a DNS query, although the proxy refuses it;
  - model keys are refused for now;
  - (both of these changed later on `flagship`, in slice 2c.4: the proxy's resolver answers only listed names, and model keys go to AWF's API proxy, never to the command; see [the egress page](egress-control.md));
  - the checker does not credit it yet (2c.3).

**What Expectrail would see if it moved its pin today.** This was computed on a copy of its files at `da06323`, with OBAAF at `7fb8cac`.

- **As its files stand:** the gate fails (exit 1) with 40 new findings, 20 high and 20 low.
  - The old baseline accepts nothing.
  - The `ignore` entry names no owner, so it accepts nothing either.
  - The `probe` entry is a new high finding.
- **After two changes:** `obaaf baseline migrate`, run with an owner, a reason and a date, and an owner added to the `ignore` entry.
  - 39 findings are accepted, each under that owner until a date: 38 by the baseline and 1 by the `ignore` entry.
  - One finding is new: the `probe` entry.
  - Expectrail's `.github/CODEOWNERS` names Sean as the owner of everything under `.github/`.

## What this page does not show

- **That OBAAF helps anyone else.** The only adopter on record is a project of one of OBAAF's authors.
- **Anything a token would show.** The settings were read with no token.
  - GitHub withheld the one thing the audit asked for and could not get: the bypass list.
  - The Actions policies and the names of secrets were not asked for, because GitHub does not show them without a token.
- **The settings now.** They were read at 09:10 UTC.
  - This session could not read GitHub's API for Expectrail: its proxy refused the request.
  - So the audit was run again offline on that reading, with Expectrail's files at `da06323`. It gave the same 4 medium findings and 7 "cannot tell" as with the files at `36a7a8a`.
- **That the incidents happened as reported.** The table gives what the public record shows. Where the record is silent, the causes come from the account given when the work began, and this page does not check them.

## How the numbers were made

On 2026-11-13, in the agent's session, Expectrail was cloned read-only with its full history. Its files at `da063233` were copied into a scratch directory with `git archive`, so the clone itself was not touched.

```bash
# The pinned gate, with OBAAF at d014b63: 38 accepted, 0 new, exit 0
obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes
# The same with OBAAF at 7fb8cac: 40 new (20 high, 20 low), exit 1
# On a copy, after `obaaf baseline migrate ... --owner ... --reason ... --expires 2027-02-01` and an
# `owner:` on the ignore entry: 39 accepted, 1 new (OBAAF-CFG-001), exit 1
# Without .github/obaaf.yml: `obaaf check . --lanes` names 2 agent jobs
# The baseline's history: entries at each commit that touched it, and the job each change added
git log --format=%h -- .github/obaaf-baseline.json   # 4 commits: 32, 34, 36, 38 entries
# The settings: the snapshot of 09:10 UTC, with the files at da06323
obaaf audit <files> --fail-on never --from-snapshot tests/fixtures/settings/live-expectrail-2026-11-13/snapshot.json
```

Commit times are author dates converted to UTC (`TZ=UTC git show -s --date=format-local:...`); merge times are the merge commits' dates. The quotations are from the commit messages, from `docs/obaaf.md` at `da06323`, and from OBAAF's `rules.yaml` at `d014b63`.
