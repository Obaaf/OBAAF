# The settings audit on the first adopter, 2026-11-13

*Plan slice 2b.4. One run of `obaaf audit` against [Expectrail/Expectrail](https://github.com/Expectrail/Expectrail), read-only and with no token. **Expectrail is the author's own project**, so this is not evidence from an outside adopter; outside results are still to come. No setting of Expectrail was changed, and nothing was written there. This page is the record the case study (slice 3.7) draws on.*

**In one paragraph.** On 2026-11-13 at 09:10 UTC the audit read what GitHub shows anyone about Expectrail's settings and compared it with Expectrail's 29 workflow files at commit [`36a7a8a`](https://github.com/Expectrail/Expectrail/tree/36a7a8aeb9b041ae70d481310bafe1d7a89d9fb5), which GitHub's answer gave as the head of `main` at that moment. It reported **4 findings, all medium**: one environment that any branch may use, guarded only by a reviewer who may approve their own run, and three pull-request jobs whose failure does not block a merge (one of them is `merge-guard`, the job of the workflow "Merge guard"). For **7 of the 15 rules it could not tell**, and **10 of the 15 settings were not read**: nine because GitHub shows them only to a token, and the list of who may bypass the branch ruleset because GitHub shows it only to someone who could change it. Of the six incidents of Expectrail's first two days, as the plan recorded them on 2026-11-11, two no longer show (one because a setting changed, one because the workflow files did), two show again in another form, and two cannot be seen without an administrator.

## How it was run

- **Where.** In this repository's own workflow, [`settings-audit-live.yml`](../.github/workflows/settings-audit-live.yml), on the pull request of this slice: [run 43399109471](https://github.com/Obaaf/OBAAF/actions/runs/43399109471), job "Read this repository's settings", step "A public repository that has rulesets, with no token". A session of the agent does not call GitHub's API to run the audit (plan decision F-34); a workflow run is evidence anyone can open while GitHub keeps its log.
- **What it read.** Expectrail's settings, with no token: the workflow's own token is for this repository and is never sent for another. Eight GET requests.
- **What it compared them with.** Expectrail's workflow files and `.github/obaaf.yml`, from a clone made in the same step with no credentials, at commit `36a7a8aeb9b041ae70d481310bafe1d7a89d9fb5` (the step prints it). All 29 files were read; the step fails otherwise.
- **The command.** That run was on the slice's first commit, `4f08b21`, where the step put the clone's directory first: `obaaf audit "$clone" --repo Expectrail/Expectrail --no-token --fail-on never --snapshot-out audit-live/rulesets.json --record audit-live/rulesets`. The workflow as merged puts the directory after the options, which the command line reads the same way, and checks out only `.github` of the clone. RUN-ON-FINAL-HEAD
- **Kept here.** GitHub's eight answers and the snapshot made from them, as the step printed them, are in [`tests/fixtures/settings/live-expectrail-2026-11-13/`](../tests/fixtures/settings/live-expectrail-2026-11-13/). `tests/test_settings_adopter.py` checks that the snapshot is what those answers give, and that what this page says the settings were is what the snapshot says.
- **To make the report again**, with no request to GitHub's API (the clone is the only thing fetched):

  ```bash
  git clone https://github.com/Expectrail/Expectrail expectrail
  git -C expectrail checkout 36a7a8aeb9b041ae70d481310bafe1d7a89d9fb5
  obaaf audit expectrail --fail-on never --from-snapshot tests/fixtures/settings/live-expectrail-2026-11-13/snapshot.json
  ```

  Without `--fail-on never` it ends with status 1, because the four findings are medium. This was done in the agent's session with the code of this slice: the findings, the "cannot tell" results, the rules' lines and what was read came out identical to the step's report. Three lines differ, as they should: the second (where the settings came from), the third (the directory compared; the session's clone has the origin remote `seanudeke/expectrail`, a name under which GitHub serves the same repository, so the report adds that it compared the files because the directory was named) and the last (requests sent, against requests the snapshot lists).

## The findings

Each finding is quoted from the report, then judged by reading Expectrail's files. "True" means the report describes the settings and files correctly; whether the risk is worth a change is Expectrail's decision.

### `OBAAF-SET-001`, medium: the environment `unity`

> Any branch or tag may use the environment "unity", a pull request's branch included, and 1 job names it (.github/workflows/unity.yml#build). A job on any such branch can name it and read whatever secrets it holds. Its only protection is its required reviewers, and a reviewer may approve their own run.

**True.** GitHub's answer for `unity` has no branch limit, one required reviewer (`seanudeke`), self-review allowed, and administrators allowed to bypass. The job that names it builds the Unity game on pull requests that touch its files, and on request, and refers to three secrets (`UNITY_LICENSE`, `UNITY_EMAIL`, `UNITY_PASSWORD`); whether they are stored in the environment is one of the settings no token was given to read.

Why it matters here: as far as public data shows, Expectrail's agents and its author reach `main` through one GitHub account. Fifteen pull requests were merged into `main` between 00:00 and 09:10 UTC on 2026-11-13, from branches named `agent/`, `agent2/`, `arch/` and `chatgpt/`, and every one of their merge commits is authored by the address of the account `seanudeke` (`55066947+seanudeke@users.noreply.github.com`) and committed by GitHub, and GitHub's list of runs names `seanudeke` as the actor of the runs those merges started (for example [43396601449](https://github.com/Expectrail/Expectrail/actions/runs/43396601449), after #382). If that account is also the reviewer and may approve its own runs, the reviewer requirement does not separate a session of an agent from the author. Expectrail's `AGENTS.md` asks for exactly that separation ("Approve a protected environment's run (`unity`, `main-only`)" is on its list of what only a person may do), and its `.github/obaaf.yml` accepts `OBAAF-GHA-001` for this job until 2027-02-09 on the reason that the environment "requires Sean's approval for every run, so a pull request's build gets it only after a maintainer approves that run". The settings show an approval that the same account can give to itself. The rule holds today because the agents follow it, not because GitHub enforces it.

The fix the report offers (limit the environment to the default branch) does not suit a job whose purpose is to build pull requests. The other way out, a reviewer who is not the account that starts the run, needs a second account. While one account does everything, no setting alone clears this finding, and that is worth knowing.

### `OBAAF-SET-008`, medium: three pull-request jobs whose failure does not block a merge

> .github/workflows/merge-guard.yml#merge-guard runs on every pull request into "main" and reports the check "merge-guard", which is not required (12 checks are required there). A pull request can merge while the job is failing.

The same sentence is reported for `ci.yml#agents-daily-offline` and `private-scan-request.yml#private-scan-request`.

- **`merge-guard`: true, and the one that matters most.** The job "checks the diff against the rules no agent may break" (its step's name) on every pull request. Expectrail's merge guard, an agent, merges only when every check on the head is green (its `AGENTS.md`), so a failing `merge-guard` stops that agent. Nothing in GitHub stops a merge made any other way: by a person, or by any other session using the same account. The job that guards the rules does not guard the merge button.
- **`agents-daily-offline`: true.** It runs the daily offline end-to-end test on every pull request and is not required. Either it should be, or it is advisory and `continue-on-error: true` at job level would say so in the file.
- **`private-scan-request`: true as stated, and of little consequence.** This job asks the default branch's scanner to scan the pull request's commit; the scanner reports `private-export-scan`, which is required. If the request fails, that check never arrives and the merge stays blocked anyway. Its failure is not silent, only indirect.

The rule's own statement of what it does not see applies: it compares names in the files with the required checks; it does not read which checks actually ran.

## What the audit could not tell

Seven rules answered "cannot tell". None of these is a pass.

| Rule | What is not known | What would settle it |
| --- | --- | --- |
| `OBAAF-SET-003` | Whether a secret that `protected_secrets` keeps in `main-only` (`*_API_KEY`, `HELDOUT_TOKEN`) is also stored where every job can read it | The names of the repository's, the organisation's and each environment's secrets ("Secrets" and "Environments" read) |
| `OBAAF-SET-004` | Who may bypass the ruleset "Protect main" | The bypass list, which GitHub returns only to a caller with write access to the ruleset; OBAAF asks nobody for that, so an administrator would read it in the repository's settings |
| `OBAAF-SET-007` | Whether `private-export-scan`, a required check, reports for every pull request: the workflow that reports it runs only when dispatched, and `private-scan-request.yml` is what dispatches it | Nothing the audit reads; it is a question about what another workflow does |
| `OBAAF-SET-009` | Whether an Actions policy blocks one of the five events the 29 workflows use (`pull_request`, `push`, `schedule`, `workflow_dispatch`, `workflow_run`) | The Actions policies, which GitHub's reference shows only with the "Administration" permission at write level; OBAAF asks nobody for that, so an administrator would read them in the repository's settings |
| `OBAAF-SET-013` | Whether workflows may approve pull requests | The default workflow permissions ("Administration" read). The rule asks whatever the number of approvals the branch requires, which can change; see also the note on approvals [below](#what-this-run-does-not-show) |
| `OBAAF-SET-014` | Whose fork pull requests need approval before workflows run | The fork pull request setting ("Administration" read) |
| `OBAAF-SET-015` | Whether the repository requires actions to be pinned to a commit. Every action the jobs use is pinned | The Actions permissions ("Administration" read) |

The rules that did answer without a finding: `OBAAF-SET-006` compared the 12 required checks with the names the jobs report and found each reported. `OBAAF-SET-002`, `005`, `010`, `011` and `012` did not apply: no job that outsiders' events can start names an environment, the branch requires no approval by count, no workflow uses `pull_request_target`, no job passes a secret to a reusable workflow, and every job declares its permissions.

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

Not read, 10 of 15, in the report's words:

- Classic branch protection
- Names of the secrets in each environment
- Names of the repository's secrets
- Names of the organisation secrets this repository receives
- Which actions may run, and whether they must be pinned
- What the workflow token may do by default
- Approval before workflows run on fork pull requests
- Actions policies: who and which events may start a workflow
- How many accounts hold each role
- Who may bypass each ruleset

The first nine were not asked for, because no token was given and GitHub's reference says each needs one. The bypass list was asked for and left out of GitHub's answer (`withheld`), as GitHub does for a caller without write access to the ruleset. What each needs is in [the settings audit's guide](settings-audit.md#what-it-reads), from GitHub's reference as read on 2026-11-12 ([sources](settings-audit.md#sources)).

**What an administrator's token would add.** A token that can read the administrative settings, and nothing more, would read eight of the ten: all but the bypass list and the Actions policies, which GitHub shows only with write access. That turns four of the seven "cannot tell" into answers (`003`, `013`, `014`, `015`) and gives `OBAAF-SET-001` the names of the secrets in `unity`. `004` and `009` would still need an administrator to look in the repository's settings, and `007` stays, for the reason in the table. This run had no such token: the agents create no token and ask for none. One run by a maintainer, with such a token and its report sent here, would close most of this page's gaps; it is on the list for Sean in [the plan](flagship.md#waiting-on-sean).

## The six incidents, then and now

The incidents of Expectrail's first two days, as the plan recorded them on 2026-11-11, against what this run saw. "Now" is 2026-11-13 09:10 UTC.

| Incident | Rule | Now |
| --- | --- | --- |
| A protected environment created with no branch restriction | `OBAAF-SET-001` | `main-only`, which Expectrail's files say holds the model keys and the held-out token, may deploy from `main` only, and so may `github-pages`: no finding for either. `unity` is open to every branch: the finding above. `main-only` has no required reviewers, although Expectrail's `AGENTS.md` names it among the environments whose runs only a person may approve: GitHub asks nobody before a job on `main` uses it |
| A bypass on the branch ruleset that let any session using the administrator's account skip every required check | `OBAAF-SET-004` | Cannot tell: the bypass list is withheld from a caller with no token |
| Required approvals that the one shared account could never give | `OBAAF-SET-005` | Does not apply: "Protect main" now requires 0 approvals by count. The incident went away because the count was set to zero. The same rule carries a parameter OBAAF does not read, `require_extra_approval_for_unattributed_changes: true` (see [below](#what-this-run-does-not-show)) |
| A required-checks list that named one check of the eleven that ran | `OBAAF-SET-006` to `008` | 12 checks are required, and each is one a job reports. Three pull-request jobs are not required: the `OBAAF-SET-008` findings above |
| An Actions policy that allowed two events for one workflow, so its new `workflow_run` trigger failed before any job started | `OBAAF-SET-009` | Cannot tell: the policies need an administrator. The comment at the top of Expectrail's `private-scan-request.yml` says that runs started by `workflow_run` ended in `startup_failure` every time on 2026-11-11 (its #247) and that the scan is now started by a dispatch; it does not name a policy, which is the plan's account of the cause. Two workflows still use `workflow_run`, `main-health.yml` and `expectrail-comment.yml`. The two latest runs of each, read at about 09:15 UTC from GitHub's list of runs through the agent's GitHub tools (not by the audit), all started: `main-health.yml` [43396601449](https://github.com/Expectrail/Expectrail/actions/runs/43396601449) and [43389951771](https://github.com/Expectrail/Expectrail/actions/runs/43389951771), success; `expectrail-comment.yml` [43397483198](https://github.com/Expectrail/Expectrail/actions/runs/43397483198), success, and [43397257642](https://github.com/Expectrail/Expectrail/actions/runs/43397257642), skipped |
| A reusable workflow that could not see its caller's environment secrets | `OBAAF-SET-011` | Does not apply: no job passes a secret to a reusable workflow. This one changed in the workflow files, not in the settings |

## What changed since the first reading

The live workflow's run of 2026-11-12 at 01:33 UTC kept GitHub's answers about Expectrail as a recording (`tests/fixtures/settings/live-expectrail-no-token/`). Compared with this run by the audit's own drift check (`--expected`), one thing changed: the check `package` was added to the required checks of "Protect main", in the ruleset and therefore in the rules in force on `main`. GitHub's answer gives the ruleset's last change as 2026-11-12 08:08 UTC, after that first reading; who made it, and why, is not in anything the audit reads. Run offline on that earlier reading, with the files at the same commit `36a7a8a`, the audit reports `ci.yml#package` as a pull-request job whose failure does not block a merge, a fifth finding (checked in the agent's session). Nothing else that both readings could see had changed.

## What this run does not show

- **One moment and one commit.** The settings as GitHub showed them at 09:10 UTC on 2026-11-13, and the files at `36a7a8a`. Both move: fifteen pull requests were merged that morning alone.
- **No token, so no administrative setting.** Every statement about secrets, Actions policies, the default token, fork pull requests, pinning and the bypass list is "not read".
- **No check runs.** The rules compare the names in the files with the required checks. Whether those checks really ran on recent pull requests was not read.
- **An approval parameter OBAAF does not read.** The ruleset's pull-request rule has `require_extra_approval_for_unattributed_changes: true`, in this reading and in the first. OBAAF's reader keeps it in the snapshot, and no rule reads it: `OBAAF-SET-005` counts `required_approving_review_count` only, and says nothing about the parameter. Its name suggests that some changes may need an approval even when the count is zero; what GitHub does with it was not established (GitHub's pages could not be read for this page), so this page does not say that GitHub requires no review before a merge. Of the commits on `main` since 2026-11-12, 34 are authored as `Claude <noreply@anthropic.com>`, an address that is not a GitHub account's noreply address, which may matter to such a rule. That the rules pass over an approval setting they do not know without saying so is a gap in OBAAF, recorded as [issue #118](https://github.com/Obaaf/OBAAF/issues/118) (plan slice 2b.5).
- **GitHub's own pages on environments were not re-read for this page.** The request for them on 2026-11-13 was not answered. What the report says of `unity` comes from GitHub's answer fields as the reader records them (`prevent_self_review`, `can_admins_bypass`, the reviewers and the branch policy) and from the reasoning in `OBAAF-SET-001`, whose limits are in [the settings audit's guide](settings-audit.md#what-the-rules-take-on-trust-and-what-they-do-not-do).
- **Four findings, three decisions for Expectrail.** Whether `merge-guard` and `agents-daily-offline` should be required, and whether `unity` should keep its open branch policy, are Expectrail's decisions; the fourth finding, `private-scan-request`, has no consequence worth a change. This page says what the settings and files are and what follows; it changes nothing there.
