# From a report to a gate

How a team moves `obaaf check` from something it reads to something that fails a build, without a day on which every existing finding blocks every pull request. Each step is a command and the exit status it ends with. `tests/test_adoption_path.py` runs the steps in this order on a small repository, so the page cannot drift from the tool.

OBAAF is 0.x. The commands here are those of the code on `main` after release 0.3.0; that release has no `--owner`, `--reason` or `--expires`. Before you move to a newer version, read [Upgrading](upgrading.md).

## The exit status

| Status | Meaning |
| --- | --- |
| 0 | Nothing at or above `--fail-on` is new, and every file was read |
| 1 | A finding at or above `--fail-on` is not accepted; or a baseline entry at or above it no longer matches a finding; or a file could not be read |
| 2 | The command could not run: an option, the configuration or a baseline is wrong, or there is nothing to check |

A file the checker could not read ends the check with 1 whatever `--fail-on` says, `never` included. A check that did not read a workflow has not passed it.

## 1. Read the report, and fail nothing

```bash
obaaf check . --fail-on never
```

Status 0. The report begins with the accepted risk (none yet) and one line that counts the findings. Each finding has its file and line, what is wrong, the requirement it threatens and the fix.

Put this in CI first if you like. A step that runs it never fails a build for a finding, and still fails when a workflow cannot be read.

## 2. Say which jobs run an agent, and check that the checker agrees

```bash
obaaf check . --lanes
```

Status 0. One line for each job with the lane the checker put it in. If a job runs an AI agent and is not listed as `agent`, declare it: `OBAAF_LANE: agent` in the job's `env`, or an entry under `lanes:` in `.github/obaaf.yml` ([configuration guide](checker-configuration.md#telling-the-checker-about-your-agents)). An agent job gets the agent rules; a job the checker takes for an ordinary one does not, and its report is shorter than it should be.

Do this before step 4. A declaration that does nothing (`OBAAF_LANE: agnet`) is itself a finding, `OBAAF-CFG-001`, and `--lanes` prints it as a note on standard error. If it is still there when you write the baseline, the baseline accepts it, and the findings it hides are never seen.

## 3. Fix what is cheap

Pin actions to a commit SHA, add `persist-credentials: false` to checkout steps, declare `permissions`. Run step 1 again after each change. What is left is what you will accept for now.

## 4. Accept what is left, in somebody's name and until a date

```bash
obaaf check . --write-baseline .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
```

Status 0, and a line on standard error that says how many findings were newly accepted, by whom and until when. Without `--owner`, `--reason` and `--expires` the status is 2 and nothing is written: an acceptance needs an owner (`@user`, `@org/team` or an e-mail address), a reason, and an expiry date at most 366 days ahead.

Commit the file and put it under CODEOWNERS. It is a list of accepted risks: review a change to it like a change to a workflow.

## 5. Fail on anything new

```bash
obaaf check . --baseline .github/obaaf-baseline.json --fail-on medium
```

Status 0 today. This is the gate. From now on:

- **A new finding at medium or high fails the check** (status 1). Fix it, or accept it by running step 4 again: entries that are still valid keep their own owner, reason and date, and only the new finding takes the ones you give.
- **A finding you fixed fails it too**, once, at or above `--fail-on`: its entry no longer matches anything, and the report lists it under "no longer found". Run step 4 again to drop the entry. The fix is then locked in: the same finding coming back is new.
- **An entry whose date has passed accepts nothing.** Its finding counts as new on the day after. The report lists acceptances that run out within 30 days as "expiring soon" (`--expiry-warning DAYS` changes the window), which changes no exit status: it is there to be read before the day the gate goes red.

`--fail-on authority:medium` gates on the findings about who can change, build, release or sign, and leaves pinning and hardening for later.

## 6. Tighten

- `--fail-on low`, when the medium findings are under control.
- Shorter dates. Writing the baseline again never renews an entry that is still valid: it keeps its owner, reason and date. To extend one, change its date in the file, where a reviewer sees the change; once it has run out, step 4 writes it again with the owner, reason and date you give.
- Fewer entries. The first lines of every report say how many findings are accepted, at what severity, by which owner, and when the first one runs out. That number is the thing to bring down.

## Code scanning is not the gate

```bash
obaaf check . --format sarif --output obaaf.sarif --fail-on never
```

Status 0. Upload the file to GitHub code scanning if you want the findings beside the code. Keep the step from step 5 as well. Going by GitHub's own page on its SARIF support (read on 2026-11-12; nobody here has uploaded a report to check it), code scanning shows an accepted finding as an open alert, and shows none of the accepted-risk total, the expiry warning or a file that could not be read.

## What this path does not do yet

- There is no `obaaf init`: the configuration and the workflow that runs the check are written by hand, or installed with `obaaf templates install` ([templates](../templates/github-actions/README.md)).
- Two findings on an agent job, a secret in the job (`OBAAF-GHA-005`) and no egress restriction (`OBAAF-GHA-020`), cannot be cleared by anything the checker verifies today. They list the controls that would clear them and which of those are not met. Until the settings rules and the egress control exist, they are accepted or they fail.
- The times this path takes have not been measured.
