# The settings audit on the first adopter, 2026-11-13

*Plan slice 2b.4. One run of `obaaf audit` against [Expectrail/Expectrail](https://github.com/Expectrail/Expectrail), read-only and with no token. **Expectrail is the author's own project**, so this is not evidence from an outside adopter; outside results are still to come. No setting of Expectrail was changed, and nothing was written there. This page is the record the case study (slice 3.7) draws on.*

**In one paragraph.** On 2026-11-13 at 09:10 UTC the audit read what GitHub shows anyone about Expectrail's settings and compared it with Expectrail's 29 workflow files at commit [`36a7a8a`](https://github.com/Expectrail/Expectrail/tree/36a7a8aeb9b041ae70d481310bafe1d7a89d9fb5). It reported **4 findings, all medium**: one environment that any branch may use, guarded only by a reviewer who may approve their own run, and three pull-request jobs whose failure does not block a merge (one of them is the job called "Merge guard"). For **7 of the 15 rules it could not tell**, and **10 of the 15 settings were not read**: nine because GitHub shows them only to a token, and the list of who may bypass the branch ruleset because GitHub shows it only to someone who could change it. Of the first adopter's six incidents of 2026-11-11 and 2026-11-12, two no longer show in the settings, two show again in another form, and two cannot be seen without an administrator.

## How it was run

- **Where.** In this repository's own workflow, [`settings-audit-live.yml`](../.github/workflows/settings-audit-live.yml), on the pull request of this slice: [run 43399109471](https://github.com/Obaaf/OBAAF/actions/runs/43399109471), job "Read this repository's settings", step "A public repository that has rulesets, with no token". A session of the agent does not call GitHub's API itself (plan decision F-34); a workflow run is evidence anyone can open while GitHub keeps its log.
- **What it read.** Expectrail's settings, with no token: the workflow's own token is for this repository and is never sent for another. Eight GET requests.
- **What it compared them with.** Expectrail's workflow files and `.github/obaaf.yml`, from a clone made in the same step with no credentials, at commit `36a7a8aeb9b041ae70d481310bafe1d7a89d9fb5` (the step prints it). All 29 files were read; the step fails otherwise.
- **The command**, as the step ran it (`$clone` is the clone's directory):

  ```bash
  obaaf audit --repo Expectrail/Expectrail --no-token --fail-on never \
    --snapshot-out audit-live/rulesets.json --record audit-live/rulesets "$clone"
  ```

- **Kept here.** GitHub's eight answers and the snapshot made from them, as the step printed them, are in [`tests/fixtures/settings/live-expectrail-2026-11-13/`](../tests/fixtures/settings/live-expectrail-2026-11-13/). `tests/test_settings_adopter.py` checks that the snapshot is what those answers give, and that what this page says the settings were is what the snapshot says.
- **To make the report again, with no network:**

  ```bash
  git clone https://github.com/Expectrail/Expectrail expectrail
  git -C expectrail checkout 36a7a8aeb9b041ae70d481310bafe1d7a89d9fb5
  obaaf audit expectrail --from-snapshot tests/fixtures/settings/live-expectrail-2026-11-13/snapshot.json
  ```

  This was done in the agent's session with the code of this slice and a clone at that commit: the findings, the "cannot tell" results, the rules' lines and what was read came out identical to the step's report. Only the line that says where the settings came from and the last line differ, as they should.

## The findings

Each finding is quoted from the report, then judged by reading Expectrail's files. "True" means the report describes the settings and files correctly; whether the risk is worth a change is Expectrail's decision.

### `OBAAF-SET-001`, medium: the environment `unity`

> Any branch or tag may use the environment "unity", a pull request's branch included, and 1 job names it (.github/workflows/unity.yml#build). A job on any such branch can name it and read whatever secrets it holds. Its only protection is its required reviewers, and a reviewer may approve their own run.

**True.** GitHub's answer for `unity` has no branch limit, one required reviewer (`seanudeke`), self-review allowed, and administrators allowed to bypass. The job that names it builds the Unity game on pull requests that touch its files, and on request, and refers to three secrets (`UNITY_LICENSE`, `UNITY_EMAIL`, `UNITY_PASSWORD`); whether they are stored in the environment is one of the settings no token was given to read.

What makes it matter here: Expectrail's agents and its author work through one GitHub account. The three pull requests from its agents' branches merged on the morning of 2026-11-13 (#375, #381 and #382) were merged under the account `seanudeke`, and the runs of `main-health.yml` started after #381 and #382 show it as the actor. So a reviewer requirement that its own account may satisfy does not separate a session of an agent from the author, which is what Expectrail's `AGENTS.md` asks for ("Approve a protected environment's run (`unity`, `main-only`)" is on its list of what only a person may do). That rule holds today because the agents follow it, not because GitHub enforces it.

The fix the report offers (limit the environment to the default branch) does not suit a job whose purpose is to build pull requests. The other way out, a reviewer who is not the account that starts the run, needs a second account. The finding cannot be cleared by a setting alone while one account does everything, and that is worth knowing.

### `OBAAF-SET-008`, medium: three pull-request jobs whose failure does not block a merge

> .github/workflows/merge-guard.yml#merge-guard runs on every pull request into "main" and reports the check "merge-guard", which is not required (12 checks are required there). A pull request can merge while the job is failing.

The same sentence is reported for `ci.yml#agents-daily-offline` and `private-scan-request.yml#private-scan-request`.

- **`merge-guard`: true, and the one that matters most.** The job "checks the diff against the rules no agent may break" (its step's name) on every pull request. Expectrail's merge guard, an agent, merges only when every check on the head is green, so a failing `merge-guard` stops that agent. Nothing in GitHub stops a merge made any other way: by a person, or by any other session using the same account. The job that guards the rules does not guard the merge button.
- **`agents-daily-offline`: true.** It runs the daily offline end-to-end test on every pull request and is not required. Either it should be, or it is advisory and `continue-on-error: true` at job level would say so in the file.
- **`private-scan-request`: true as stated, and of little consequence.** This job asks the default branch's scanner to scan the pull request's commit; the scanner reports `private-export-scan`, which is required. If the request fails, that check never arrives and the merge stays blocked anyway. Its failure is not silent, only indirect.

The rule's own statement of what it does not see applies: it compares names in the files with the required checks; it does not read which checks actually ran.

## What the audit could not tell

Seven rules answered "cannot tell". None of these is a pass.

| Rule | What is not known | What would settle it |
| --- | --- | --- |
| `OBAAF-SET-003` | Whether a secret that `protected_secrets` keeps in `main-only` (`*_API_KEY`, `HELDOUT_TOKEN`) is also stored where every job can read it | The names of the repository's, the organisation's and each environment's secrets ("Secrets" and "Environments" read) |
| `OBAAF-SET-004` | Who may bypass the ruleset "Protect main" | The bypass list, which GitHub shows only to someone with write access to the ruleset |
| `OBAAF-SET-007` | Whether `private-export-scan`, a required check, reports for every pull request: the workflow that reports it runs only when dispatched, and `private-scan-request.yml` is what dispatches it | Nothing the audit reads; it is a question about what another workflow does |
| `OBAAF-SET-009` | Whether an Actions policy blocks one of the five events the 29 workflows use (`pull_request`, `push`, `schedule`, `workflow_dispatch`, `workflow_run`) | The Actions policies, which GitHub's reference shows only with the "Administration" permission at write level; OBAAF asks nobody for that |
| `OBAAF-SET-013` | Whether workflows may approve pull requests | The default workflow permissions ("Administration" read). Today the ruleset requires 0 approvals, so an approval by a workflow would add nothing; the rule asks because that can change |
| `OBAAF-SET-014` | Whose fork pull requests need approval before workflows run | The fork pull request setting ("Administration" read) |
| `OBAAF-SET-015` | Whether the repository requires actions to be pinned to a commit. Every action the jobs use is pinned | The Actions permissions ("Administration" read) |

The rules that did answer without a finding: `OBAAF-SET-006` compared the 12 required checks with the names the jobs report and found each reported. `OBAAF-SET-002`, `005`, `010`, `011` and `012` did not apply: no job that outsiders' events can start names an environment, the branch requires no approval, no workflow uses `pull_request_target`, no job passes a secret to a reusable workflow, and every job declares its permissions.

## What was read, and what was not

From the report, word for word:

```text
READ: 5 of 15
  The repository
      public repository, default branch main, owned by the organisation Expectrail
  Rulesets and their rules
      "Protect main" (active, branch, from Repository Expectrail/Expectrail): deletion, non_fast_forward, pull_request (0 approvals), required_status_checks (test, obaaf-audit, capture-smoke, web-capture, seeded-bugs, agents-gate1, agents-harness-verify, feedback-offline, agents-sandbox, agents-bench-compare, private-export-scan, package)
  Rules in force on each audited branch
      "main": deletion, non_fast_forward, pull_request (0 approvals), required_status_checks (test, obaaf-audit, capture-smoke, web-capture, seeded-bugs, agents-gate1, agents-harness-verify, feedback-offline, agents-sandbox, agents-bench-compare, private-export-scan, package)
  Each audited branch, as anyone may see it
      "main": GitHub calls it protected; no required checks shown in this view
  Environments: reviewers and which branches may deploy
      "github-pages": may deploy: branch main; no required reviewers
      "main-only": may deploy: branch main; no required reviewers
      "unity": any branch or tag may deploy; reviewers: seanudeke (self-review allowed); administrators may bypass these rules: yes
```

Not read (10 of 15): classic branch protection; the names of the secrets in each environment, of the repository's secrets and of the organisation secrets the repository receives; which actions may run and whether they must be pinned; what the workflow token may do by default; approval before workflows run on fork pull requests; Actions policies; how many accounts hold each role; and who may bypass each ruleset. The first nine were not asked for, because no token was given and GitHub's reference says each needs one. The bypass list was asked for and left out of GitHub's answer (`withheld`), as GitHub does for a caller without write access to the ruleset.

**What an administrator's token would add.** It would read all ten, which turns six of the seven "cannot tell" into answers (`003`, `004`, `009`, `013`, `014`, `015`); `007` stays, for the reason in the table. It would also give `OBAAF-SET-001` the names of the secrets in `unity`. This run had no such token: the agents create no token and ask for none. One run by a maintainer, with a token that can read the administrative settings and with its report sent here, would close most of this page's gaps; it is on the list for Sean in [the plan](flagship.md#waiting-on-sean).

## The six incidents, then and now

The first adopter's incidents of 2026-11-11 and 2026-11-12, as the plan records them, against what this run saw. "Now" is 2026-11-13 09:10 UTC.

| Incident | Rule | Now |
| --- | --- | --- |
| A protected environment created with no branch restriction | `OBAAF-SET-001` | `main-only`, which holds the model keys and the held-out token, may deploy from `main` only, and so may `github-pages`: no finding for either. `unity` is open to every branch: the finding above |
| A bypass on the branch ruleset that let any session using the administrator's account skip every required check | `OBAAF-SET-004` | Cannot tell: the bypass list is withheld from a caller with no token |
| Required approvals that the one shared account could never give | `OBAAF-SET-005` | Does not apply: "Protect main" now requires 0 approvals. The incident is gone because no approval is required at all; GitHub requires no review before a merge, and Expectrail relies on its merge guard instead. The audit has no rule against that choice: it compares settings with what the workflows use (plan decision F-23), and nothing here contradicts the other |
| A required-checks list that named one check of the eleven that ran | `OBAAF-SET-006` to `008` | 12 checks are required, and each is one a job reports. Three pull-request jobs are not required: the `OBAAF-SET-008` findings above |
| An Actions policy that allowed two events for one workflow, so its new `workflow_run` trigger failed before any job started | `OBAAF-SET-009` | Cannot tell: the policies need an administrator. Expectrail moved that scan to a dispatch (the comment at the top of `private-scan-request.yml` says why). Two workflows still use `workflow_run` (`main-health.yml`, `expectrail-comment.yml`); their runs listed for 2026-11-13 started and finished, so no policy blocked them that day. That is the run history, not the audit |
| A reusable workflow that could not see its caller's environment secrets | `OBAAF-SET-011` | Does not apply: no job passes a secret to a reusable workflow |

## What changed since the first reading

The live workflow's run of 2026-11-12 at 01:33 UTC kept GitHub's answers about Expectrail as a recording (`tests/fixtures/settings/live-expectrail-no-token/`). Compared with this run by the audit's own drift check (`--expected`), one thing changed: the check `package` was added to the required checks of "Protect main", in the ruleset and therefore in the rules in force on `main`. Run offline on that earlier reading, with the files at the same commit `36a7a8a`, the audit reports `ci.yml#package` as a pull-request job whose failure does not block a merge, a fifth finding (checked in the agent's session). Who changed the setting, and why, is not in anything the audit reads. Nothing else that both readings could see had changed.

## What this run does not show

- **One moment and one commit.** The settings as GitHub showed them at 09:10 UTC on 2026-11-13, and the files at `36a7a8a`. Both move: Expectrail's agents merge several pull requests a day.
- **No token, so no administrative setting.** Every statement about secrets, Actions policies, the default token, fork pull requests, pinning and the bypass list is "not read".
- **No check runs.** The rules compare the names in the files with the required checks. Whether those checks really ran on recent pull requests was not read.
- **GitHub's own pages on environments were not re-read for this page.** The request for them on 2026-11-13 was not answered. What the report says of `unity` comes from GitHub's answer fields as the reader records them (`prevent_self_review`, `can_admins_bypass`, the reviewers and the branch policy) and from the reasoning in `OBAAF-SET-001`, whose limits are in [the settings audit's guide](settings-audit.md#what-the-rules-take-on-trust-and-what-they-do-not-do).
- **Three findings, three judgements.** Whether `merge-guard` and `agents-daily-offline` should be required, and whether `unity` should keep its open branch policy, are Expectrail's decisions. This page says what the settings and files are and what follows; it changes nothing there.
