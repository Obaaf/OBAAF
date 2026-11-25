# From a report to a gate

How a team moves `obaaf check` from something it reads to something that fails a build, without a day on which every existing finding blocks every pull request. Each step is a command and the exit status it ends with. `tests/test_adoption_path.py` runs the commands of steps 1, 2, 4 and 5 in this order on a small repository and checks the status of each; it does not check every sentence here.

**If you have release 0.3.0**, start with `obaaf check . --fail-on never` for a report and `obaaf check . --lanes` to review job classification. Keep your existing gate’s configuration, baseline and threshold. Before using the development steps below, review the upgrade guidance. Release 0.3.0 lacks `obaaf init`, `obaaf fix` and the baseline owner, reason and expiry options. [Upgrading](upgrading.md)

**Development status.** The development branch includes the to-do list and accepted-risk summary. The complete walkthrough was rehearsed locally at `93be00a` on a disposable repository. Two reviewed workflow edits reduced seven findings to five. After those five were explicitly accepted, the medium gate passed. A later workflow change introduced three new findings and the gate failed. All 21 commands returned their expected status. The action catalogue now lists a reviewed egress commit. The final checker pin, hosted launch rehearsal and timed first-user trial remain open. [Rehearsal results](https://github.com/Obaaf/OBAAF/issues/295#issuecomment-7025513204)

## Install and preview report-only CI

Start in your repository on a branch you trust. Install from a separate OBAAF checkout at the reviewed development commit you intend to evaluate, using an activated Python 3.10+ virtual environment. In this example the checkout is the sibling directory `../obaaf-src`. After installation, record its commit and the output of `obaaf --version` because development builds share the version string.

```bash
python -m pip install ../obaaf-src
obaaf init
```

Review the proposed configuration, agent lanes and secret names against your jobs. The preview also shows the proposed report-only workflow and its pinned checker. After reviewing both files, run `obaaf init --apply` and commit the setup. A conflicting existing setup needs manual reconciliation. If you maintain a custom CI workflow, use the check in step 1 there. [Init conflicts and optional companion checks](upgrading.md#set-up-a-first-github-actions-check)

## The exit status

Of `obaaf check` when it reports, that is, without `--lanes` or `--write-baseline`:

| Status | Meaning |
| --- | --- |
| 0 | Nothing at or above `--fail-on` counts (a finding counts when it is new or when the checker cannot tell), no baseline entry at or above it is left without its finding, and every file was read |
| 1 | A finding at or above `--fail-on` is not accepted; or a baseline entry at or above it no longer matches a finding; or a file could not be read |
| 2 | The command could not run: an option, the configuration or a baseline is wrong, or there is nothing to check |

A file the checker could not read ends the check with 1 whatever `--fail-on` says, `never` included. A check that did not read a workflow has not passed it. The dates in this page's commands are examples: an expiry date must not have passed and can be at most 366 days ahead, so use your own.

## 1. Read the report, and fail nothing

```bash
obaaf check . --fail-on never
```

Status 0. The report begins with the accepted risk (none yet) and one line that counts the findings. Each finding has its file and line, what is wrong, why it matters in one sentence, the requirement it threatens where it has one, and the fix.

The local development report ends with “What to do next”. It groups outstanding findings by cause, with counts and the next command or manual task. Use `obaaf check . --fail-on never --summary` locally for a shorter view. It opens with accepted risk, including approaching expiries within the warning period, then shows outstanding work and applicable warnings. Reuse your gate’s threshold when you want its exit status. The current init workflow installs the interim checker at `8caddd6`. The final reviewed checker pin and its CI rehearsal are tracked in [#296](https://github.com/Obaaf/OBAAF/issues/296). On upgrade, a previous baseline match can be shown as a hint. Review its new finding before deciding whether to accept it. The prior acceptance does not carry over automatically.

## 2. Say which jobs run an agent, and check that the checker agrees

```bash
obaaf check . --lanes
```

Status 0 when every file was read: `--lanes` lists and judges nothing, which is to say it prints each job's lane and reports no finding, whatever `--fail-on` says. A workflow or Jenkinsfile that step 1 would report as an error is an error here too, on standard error (the jobs of a file it could not read are missing from the list), and the status is 1; a path with no workflow or Jenkinsfile is status 2, as for step 1. One line for each job with the lane the checker put it in. If a job runs an AI agent and is not listed as `agent`, declare it: `OBAAF_LANE: agent` in the job's `env`, or an entry under `lanes:` in `.github/obaaf.yml` ([configuration guide](checker-configuration.md#telling-the-checker-about-your-agents)). An agent job gets the agent rules; a job the checker takes for an ordinary one does not, and its report is shorter than it should be.

Do this before step 4. A declaration that does nothing (`OBAAF_LANE: agnet`) is itself a finding, `OBAAF-CFG-001`, and `--lanes` prints it as a note on standard error. If it is still there when you write the baseline, the baseline accepts it, and the findings it hides are never seen.

## 3. Fix what is cheap

Run `obaaf fix .` with the same check inputs you used for the report. Read the proposed diff, the findings listed under “You are accepting risk” and the changes left for manual review. The preview checks its edits on a private copy. It can correct an unambiguous lane spelling and remove obsolete entries. Adding your name to an existing ignore accepts risk and needs `--owner`. Migrating an old baseline also needs its path, your reason and an expiry. [Paperwork and upgrade examples](upgrading.md#preview-the-changes-to-your-obaaf-files)

When the report used `--settings FILE`, pass the same option to the paperwork preview. The suggested checkout and package-pin commands already carry that path. Keep the snapshot inside the repository so the checker can read the same evidence on the private copy. A single-workflow scan cannot verify snapshot ownership.

For a proven `obaaf fix` edit, start at the Git worktree root. On Linux, repeat the reviewed command with `--apply`. On macOS or Windows, repeat it with `--patch FILE`, choosing a new patch file. Read it, run `git apply -v --check FILE` and check that Git reports every intended path. Then run `git apply -v FILE` from the same root. Rerun the checker with the same inputs, inspect the diff and commit before editing the same file again. The upgrade guide covers patch refusals, whitespace and line endings. [Save a proven edit as a patch](upgrading.md#save-a-proven-edit-as-a-patch)

Two development fixes can affect how a job runs. Request each separately. The values below illustrate syntax. Choose an exact package version your team has approved.

- `obaaf fix . --tighten checkout-credentials` previews setting `persist-credentials: false` on eligible checkout steps. Check whether a later step needs authenticated Git access.
- `obaaf fix . --pin @openai/codex=1.2.3` previews eligible installs of that package at the supplied version. The report gives separate counts for eligible pins and installs that need a hand edit. Choose a version your team has verified. OBAAF performs no version lookup.

For either kind, inspect the diff and use the Linux apply or portable patch procedure above with the invocation you reviewed. If an edit would disturb an existing acceptance, the preview names the affected finding. The printed `--candidate` command checks that step on its own. If the same acceptance still prevents the edit, the named request exits 1 and leaves the workflow and acceptance untouched, including with `--apply`. Review the baseline or ignore entry with its owner. If the team approves a change to that entry, review and commit it separately, then rerun the named preview. You can also keep the existing acceptance and leave that step as it is.

Pin other actions to reviewed commits, check job permissions and decide which team should own any uncovered paths in CODEOWNERS. Handle ambiguous edits, unsupported install forms and Jenkinsfile changes by hand. Rerun the report after edits.

## 4. Accept what is left, in somebody's name and until a date

```bash
obaaf check . --write-baseline .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
```

Status 0 when nothing at or above `--fail-on` had to be left out (see below), and a line on standard error that says how many findings were newly accepted, by whom and until when. Without `--owner`, `--reason` and `--expires` the status is 2 and nothing is written: an acceptance needs an owner (`@user`, `@org/team` or an e-mail address), a reason, and an expiry date at most 366 days ahead. `--fail-on` is medium here as everywhere; give step 4 the `--fail-on` step 5 will use.

Two kinds of finding are not written to the baseline. One that no valid baseline entry accepts yet and that an `ignore` entry names without counting (it has expired, names no owner, gives a reason of fewer than four letters or digits, or is dated more than 366 days ahead): the decision about it was made in that entry, so it is renewed, completed or removed there. And one that no entry can accept, such as `OBAAF-REPO-001` when the repository has no CODEOWNERS file or no rule in it owns the baseline: it is fixed, not accepted. Step 5 counts both. So step 4 ends as step 5 would: status 1 when one of them is at or above `--fail-on`, with an `error:` line and a `not written:` line for each on standard error, and status 0 with a `warning:` when all are below it. The baseline is written either way, without them. A finding ignored by a valid entry is left out as well, without a word, and stays accepted by that entry.

Before committing, review every newly accepted entry, including those below your gate threshold. The write command accepts all eligible outstanding findings. The threshold determines the exit status. Put the reviewed file under CODEOWNERS. It is a list of accepted risks: review a change to it like a change to a workflow.

## 5. Fail on anything new

```bash
obaaf check . --baseline .github/obaaf-baseline.json --fail-on medium
```

When this local check returns 0, preview activation for the workflow created by init. Review the workflow diff and number of findings that would count before applying it.

```bash
obaaf fix . --gate medium --baseline .github/obaaf-baseline.json
```

Use the step 3 procedure on this exact gate preview (`--apply` on Linux or `--patch FILE` on macOS and Windows). Gate activation preserves the installed checker pin. The `obaaf fix --gate` preview takes no `--settings` option. For a local gate check with a snapshot, add `--settings .github/obaaf-settings.json` to the `obaaf check` command above.

Commit the reviewed gate change. On a pull request, it reads configuration and baseline from the exact target commit. A baseline introduced only by the pull request gives that run zero baseline acceptances. Land the reviewed baseline on the target branch before enabling the gate if the existing findings would otherwise block that transition. A custom workflow gets instructions for editing its own CI step. [Gate activation](upgrading.md#enable-the-generated-workflows-gate)

For a generated workflow from before #367, rerun init with the same companion options. Review and commit the proposed report-only workflow on the adoption branch. If a gate is active, restore its previous threshold and baseline in that same pull request before merging. Merge the code-owned `.github/obaaf-settings.json` on the target before setting the repository variable `OBAAF_USE_SETTINGS` to `true`. Both report and gate then read the target commit’s snapshot on a pull request and the pushed commit’s snapshot on a push. A missing or invalid selected snapshot fails the run. A hosted simulation verified target-snapshot selection with the interim checker. Fork pull-request variable availability and the hosted launch rehearsal remain unverified. [Generated workflow and settings](ci-integration.md)

From now on:

- **A new finding at medium or high fails the check** (status 1). Review and fix the finding. If the team chooses bulk acceptance, step 4 gives the supplied owner, reason and expiry to every newly accepted finding, including unrelated and below-threshold ones. Existing valid matches keep their original decisions. Read the entire baseline diff before committing.
- **A finding you fixed fails it too**, once, at or above `--fail-on`: its entry no longer matches anything, and the report lists it under "no longer found". For an obsolete entry, run `obaaf fix . --baseline .github/obaaf-baseline.json --fail-on medium` over the full repository. Inspect every listed removal and the complete diff. If you approve it, use the step 3 procedure with `--apply` on Linux or `--patch FILE` on macOS and Windows, then rerun the gate. This cleanup adds no acceptance. If the fixed finding comes back later, it counts as new.
- **Changing a step can make an accepted finding on it new.** A step with no `name` or `id` is known by the action it uses, version included. Pin `actions/checkout@v4` to a commit SHA and every accepted finding still on that step counts as new, and each of the step's old entries as no longer found (the pin itself fixes the unpinned-action finding); review the replacement finding and its old entry separately. Repeating step 4 records a new decision on every eligible outstanding finding. Give the step a `name` before you accept a finding on it ([configuration guide](checker-configuration.md#baseline), "A step by its name"), and read the diff of the baseline.
- **An entry whose date has passed accepts nothing.** Its finding counts as new on the day after. The report lists acceptances that run out within 30 days as "expiring soon" (`--expiry-warning DAYS` changes the window), which changes no exit status: it is there to be read before the day the gate goes red.

`--fail-on authority:medium` gates on the findings about who can change, build, release or sign, and leaves pinning and hardening for later.

## 6. Tighten

- `--fail-on low`, when the medium findings are under control.
- Shorter dates. Writing the baseline again never renews an entry that is still valid and still matches its finding: it keeps its owner, reason and date. To extend one, change its date in the file, where a reviewer sees the change; once it has run out, step 4 writes it again with the owner, reason and date you give.
- Fewer entries. The first lines of every report say how many findings are accepted, at what severity, by which owner, and when the first one runs out. That number is the thing to bring down.

## Code scanning is not the gate

```bash
obaaf check . --format sarif --output obaaf.sarif --fail-on never
```

Status 0. Upload the file to GitHub code scanning if you want the findings beside the code. Keep the step from step 5 as well. [CI integration](ci-integration.md) has a workflow that does both, and a hook that runs the gate before each commit. Going by GitHub's own page on its SARIF support (read on 2026-11-12; nobody here has uploaded a report to check it), code scanning shows an accepted finding as an open alert, and shows none of the accepted-risk total, the expiry warning or a file that could not be read.

## Next sitting: confine an agent job

From a trusted branch, run `obaaf fix egress . --job NAME` to preview a draft for a job whose ID is unique in the repository. If several workflows use the same job ID, select the workflow file as well. For example, `obaaf fix egress .github/workflows/case-spend.yml --job run` selects that file’s `run` job. Add `--brief` to either command for a Markdown work order. Automatic selection requires one recognised, supported direct agent `run` step. In the test-catalogue rehearsal, five workflows used the ID `run`. Selecting the file resolved the ambiguity, but its agent-lane job did not meet the direct-step requirement. [Walkthrough evidence](https://github.com/Obaaf/OBAAF/issues/295#issuecomment-7026138338)

When automatic selection cannot identify the invocation, inspect the job and its local scripts on a trusted branch. An owner who can identify a supported run step can select it explicitly. In the read-only Expectrail trial, `obaaf fix egress .github/workflows/byo-smoke.yml --job byo-smoke --step "One live call per configured provider"` and its `--brief` form both returned 0 and left the source bytes unchanged. If the owner cannot identify a supported step, use the manual setup guide and keep unresolved controls open. Rerun `obaaf check .` with the same checker version and gate options and review the verdicts. [Explicit-step trial](https://github.com/Obaaf/OBAAF/actions/runs/45551337803/job/138992972538) · [Manual setup](egress-control.md#using-it)

The development catalogue lists `Obaaf/OBAAF/actions/egress@80db1e68769165c9ecf24e553254fa35d6e168d5` for drafts and work orders. Older installations with an empty catalogue return 0, explain the release hold and stop before printing either. [Reviewed action listing](https://github.com/Obaaf/OBAAF/pull/248)

With a listed commit, review the proposed job, its private-copy checker verdicts and the conditions that still need work. The draft is never applied automatically. Choose literal allowed hosts carefully because each includes its subdomains. If you adopt the change, inspect the action’s `denied` output after a run. The confined command writes to its scratch copy. Only `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` can be held by the proxy. Other provider keys passed to the command remain readable. Use a suitable proxy or decide explicitly how to handle the residual risk. A job that later commits, comments or opens a pull request needs to be split. Review the runner, other steps, credentials and permissions before relying on confinement. [Egress control](egress-control.md)

### What a settings snapshot establishes

To collect evidence, `obaaf audit --repo OWNER/REPO --snapshot-out .github/obaaf-settings.json` reads GitHub settings with read-only access. The development evidence reader uses `obaaf check . --settings .github/obaaf-settings.json --fail-on never` to inspect the explicitly selected file offline. Review its repository identity, UTC timestamp and observations. Protect the file with CODEOWNERS. A pull request must use evidence from its target commit so it cannot supply its own proof. [Settings audit](settings-audit.md)

For the environment control, the snapshot needs complete observations showing the secret exists only in the configured environment, covering repository and organisation secret inventories and the environment’s branch rules. An unread setting leaves uncertainty. A snapshot more than 30 days old cannot verify the control. An observed duplicate or an unprotected branch can show the control is unmet. For a job with named secrets, a qualifying snapshot and all five verified controls can clear OBAAF-GHA-005 with the listed pin. A job that only declares an environment cannot clear it. When a finding accepted by the baseline clears, review its stale entry in step 5. OBAAF-GHA-020 can clear with verified native firewall enforcement or the listed action. A possible artifact upload in the agent job leaves otherwise verified egress at “cannot tell” under either route, and credential isolation at “cannot tell” for the listed action. Review downstream artifact use separately while [#366](https://github.com/Obaaf/OBAAF/pull/366) is pending. [Controls that clear a finding](checker-configuration.md#controls-that-clear-a-finding)
