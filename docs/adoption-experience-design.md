# Adopting OBAAF: a to-do list, checked fixes, a draft for confining an agent, and a finding that can clear

**Status:** approved by Sean on 19 November 2026 as a P0 delivery: all of it is finished before the build goes to its first users. The date moves if it must; the scope does not. Nothing is built yet.

**Who builds it:** the project's lead architect builds and implements all of it, under the project's usual rules. Sean said so on 19 November 2026. The author of this document builds none of it.

## Why

OBAAF finds the right things and then leaves the user alone with them. Measured on 19 November 2026 on a read-only copy of Expectrail (`d702ee2`) with the development checker (`b1a9d3d`) and Expectrail's own CI command:

- The report is 608 lines, about 16,700 words, for 69 findings.
- The 69 findings have five causes.
- One existing command (`obaaf baseline migrate`) brings 69 down to 50. Two hand edits to `.github/obaaf.yml` (an owner on 18 `ignore` entries, one dead lane line) bring 50 down to 31. Nothing OBAAF has addresses the last 31: 19 agent jobs holding secrets and 12 agent tool installs.
- Every finding prints a paragraph on how to fix it. Nothing produces the change.
- The most common high finding for a team that runs agents, OBAAF-GHA-005 (a secret available to an agent job), can be accepted and can never be cleared. One of its five controls is a repository setting `obaaf check` does not read.

A stranger who meets this stops, or accepts everything. Neither is adoption.

Sean's direction, 19 November: adopting OBAAF should be seamless and still secure, and the date can move a few days for it. He chose three things:

1. **The finish line of a first sitting.** The team has a short to-do list, the mechanical fixes applied from a preview they approved, and a gate that blocks only new risk. Confining an agent is the guided next step, one job at a time.
2. **How fixes are made.** OBAAF proposes each mechanical fix as a patch it has already proven. For confining an agent it drafts the change and writes a work order a person or their coding agent can follow.
3. **The finding can clear.** `obaaf check` may use the settings file `obaaf audit` already writes, so that a team that does everything right sees OBAAF-GHA-005 clear.

## Goals

1. Every `obaaf check` text report ends with a to-do list: one line per cause, how many findings it covers, and the next command.
2. `obaaf fix` previews, and on request applies, the fixes that cannot break a build.
3. One-line workflow fixes are previewed and applied by kind.
4. For an agent job, OBAAF prints the job's agent step rewritten to run through the egress action, says what the checker makes of the result, and writes a work order.
5. OBAAF-GHA-005 clears when all five of its controls are verified, the second from a settings snapshot.
6. The same list serves someone who has just upgraded.
7. On a real agent repository, a stranger gets from install to a gate that blocks only new risk in under fifteen minutes. The only things they type or edit by hand are decisions: who owns an accepted risk, why and until when, and anything the list marks "by hand". Measured, as the plan's timed run already requires.

## Not goals

- No bot, no hosted service, no write access to anyone's repository.
- No network in `obaaf check` or `obaaf fix`. OBAAF does not look up a version or a commit. Pinning actions to commits stays with GitHub's workflow lockfiles and the tools that already do it; the list points to them.
- No change to which findings exist, their severity or their identity, other than OBAAF-GHA-005 becoming able to clear.
- No fixes for Jenkinsfiles in the first version. Their findings appear in the list as "by hand".
- `obaaf init` is not part of this. It is the plan's existing work (decision D-089). This design adds one thing to it: its last output is the to-do list and a pointer to `obaaf fix`.

## What would make it a failure, even if it works

- **A fix that accepts risk for the user.** Accepting stays a person's act: they name the owner, the reason and the expiry on the command line, and the preview lists every finding they are accepting, under its own heading.
- **A fix OBAAF has not proven.**
- **A fix that changes more than it showed.**
- **A report that hides findings.** The detail stays, and JSON and SARIF keep everything.
- **Repository text reaching a coding agent as instructions** through the work order.
- **A settings file that a pull request can forge** being believed.

## What the user sees

At the end of the report (Expectrail's real numbers):

```
What to do next: 69 findings, 5 things to do

1. 19 risks accepted in an old-format baseline no longer count    19 findings
     obaaf fix --baseline FILE --owner @you --reason "..." --expires DATE
2. 18 accepted risks name no owner                                18 findings
     obaaf fix --owner @you            you are accepting these; they are listed first
3. 19 agent jobs hold secrets their agent can read                19 high
     obaaf fix egress --job NAME       drafts the change for one job
4. 12 agent tools are installed at a version that can change      12 high
     obaaf fix --pin PACKAGE=VERSION   2 can be pinned; 10 are by hand
5. 1 lane name is not a lane                                       1 high
     by hand: 'probe' is not close to any lane name

obaaf fix shows every change before it makes one.
To block only new risk after that: accept what remains, then turn the gate on (below).
```

`obaaf check --summary` prints only this list. Every command in it carries the options the check was run with, as the report's other lines already do.

The preview:

```
$ obaaf fix --baseline .github/obaaf-baseline.json --owner @sean --reason "accepted at adoption" --expires 2027-02-18

You are accepting risk (37 findings). Nothing else below accepts anything.
  .github/obaaf.yml            owner added to 18 entries (their reasons and dates are yours, unchanged)
  .github/obaaf-baseline.json  converted; 19 findings carried over, none added
  [the 37 findings, one line each]

Corrections: none.

Could not be made automatically:
  lanes: '...byo-smoke' is 'probe', which is not close to a lane name

Checked on a copy: 37 accepted, 32 other findings, no finding new, no entry left without a finding.
Run again with --apply to write this. [unified diff follows]
```

After an upgrade, acceptances that stopped matching are paired with the findings that replaced them (same rule, file and job) and shown as one cause: "19 accepted risks need accepting again: OBAAF now records more about them", with the command. This is display only. Nothing is carried over.

## The path to a gate

1. `obaaf init` writes the configuration and a workflow that reports and does not fail (D-089).
2. `obaaf check .` ends with the list.
3. `obaaf fix` previews; `--apply` writes.
4. **Accept what remains.** This is the existing command, `obaaf check . --write-baseline FILE --owner ... --reason ... --expires ...`. It stays the one way to accept in bulk. The list shows it last, with the count by severity.
5. **Turn the gate on.** `obaaf fix --gate LEVEL` previews the one-line change to the workflow `obaaf init` wrote (the baseline and `--fail-on`). It works only on that workflow, whose shape OBAAF knows. A team that wrote its own CI step is shown the line to change.

## The kinds of fix

| Kind | What it touches | Can it break a build? | How it is applied | First version |
| --- | --- | --- | --- | --- |
| Paperwork | OBAAF's own files: the configuration and the baseline | No | Together, from one preview | Convert an old-format baseline. Add the owner the user names to `ignore` entries that have none. Correct a lane value one edit away from a real lane name. Remove an entry whose finding a fix in the same preview cleared. Turn the gate on in the workflow `init` wrote. |
| Tightening | One line of a workflow | Yes, where a job relied on the looseness | By kind, each on request | `persist-credentials: false` on a checkout (OBAAF-GHA-011). An exact version on an agent tool install, when the user gives the version (OBAAF-GHA-025). |
| Confinement | How the agent runs | Yes | Never applied. Printed as a draft. | `obaaf fix egress --job NAME` |

- The baseline conversion and the owner make an acceptance count that did not count before. They need `--owner`, and the baseline also `--reason` and `--expires`. They are the "You are accepting risk" block, and without those options they are not offered.
- **Entries.** `obaaf fix` may remove a baseline or `ignore` entry whose finding is gone. It never adds one and never changes what one covers.
- **A fix that disturbs other acceptances.** An edit to a workflow can change how another, accepted finding in the same file is described, so its acceptance stops matching. Such a fix is held back and listed with the number of findings that would need accepting again. The user can ask for it by name.
- **Code owners.** A missing CODEOWNERS rule is not fixed automatically. It changes who must approve changes, and OBAAF cannot check offline that the owner exists. The list prints the lines to add.

Which tightening fixes come next is decided by evidence: the result files first users send back count findings by rule.

## How a fix is proven

1. Work out the edit as a text change at the lines the checker already reports.
2. Apply it to a private copy outside the repository.
3. Run the same check on the copy. `obaaf fix` takes `obaaf check`'s own options (the path, `--config`, `--baseline`, `--platform`, `--fail-on`), and it proves against exactly those.
4. Offer the edit only if all of these hold: the findings it targets are gone, or accepted as the preview states; no finding counts that did not count before; no entry is left without a finding; each edited YAML file parses to the same structure as before except at the edited key; no other file differs.
5. Otherwise list it under "Could not be made automatically", with the reason.

`--apply` works the edits out again, proves them again, and writes exactly the diff it prints. It stops before writing anything if a file it would edit has uncommitted changes, so the fix is its own reviewable commit.

## The egress draft, and what it cannot promise

`obaaf fix egress --job NAME` prints the job with its agent step rewritten to use OBAAF's egress action at the commit OBAAF lists as released: the step's command as `run`, the model keys the action can hold as `model-keys`, the other names the step passes as `env`, and an `allow` list to complete. It applies the draft to a private copy, runs the check, and prints what the checker makes of it: the verdict of each control and, where one is not verified, the checker's own reason. A draft is not held back when it does not clear; it is printed with that verdict.

The draft says these things before anything else:

- **No listed commit, no draft.** Until a commit of the action is listed (pull request #248, Sean's decision), the command says so and stops.
- **The checker asks more of the job than one step.** For the egress control to be verified, no step but `actions/upload-artifact` may run after or beside the action, no other step and no `env` of the job or the workflow may be given a secret or the job's token, the job must not be able to request OIDC tokens, the allow-list must be written out, and the runner must be GitHub-hosted `ubuntu-24.04` (the full list is in `docs/egress-control.md`). A job that commits, comments or opens a pull request after its agent has to be split in two. The draft does not do that. It names each condition the job does not meet.
- **The action holds only two keys.** `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` can be kept out of the agent's reach. A job whose agent uses another provider's key is still network-limited by the draft, but the key stays within reach, so OBAAF-GHA-005 stands and is accepted. Seventeen of Expectrail's 19 agent jobs are in this case; two use only `ANTHROPIC_API_KEY`.
- What the command can no longer do (write outside its scratch copy, reach other hosts, read the job's other secrets), and how to find the hosts it needs (the action's `denied` output after one run).

The work order (`--brief`) is the same content as a Markdown task: what to change, where, what must not change (no `ignore` or baseline entry may be added or widened; one whose finding is gone is removed), and the command that proves it. Names taken from the repository are quoted and length-limited as the settings report quotes them, and labelled as data. It tells the reader to generate it from a branch they trust.

## OBAAF-GHA-005 can clear

The second of its five controls is that the secret is stored only in the environment named in `protected_secrets`, and that only protected branches may use that environment. `obaaf audit` reads those settings and can save them (`--snapshot-out`).

- `obaaf check --settings FILE` takes such a snapshot. The second control is verified only when the snapshot shows, as read and not as assumed, every setting the control needs: the environment's secret names, the repository's and the organisation's secret names, and the environment's branch rule. Where the snapshot says a setting was not read, the control stays "cannot tell", with the snapshot's own reason.
- The finding states the snapshot's date. A snapshot older than a limit is not believed; the limit is a proposed decision for Sean (this document suggests 30 days).
- **Forgery.** A snapshot is evidence a pull request could alter. It is read only from the path the user passes. That file counts among the files that need a code owner, as a baseline does. The CI template reads it from the target branch, as it reads the configuration.
- With all five controls verified the finding is cleared, as OBAAF-GHA-020 is by its one control. This is the only change to a finding's lifecycle in this design, and it is recorded as a proposed decision.
- `obaaf check` still sends no request. Taking the snapshot is `obaaf audit`'s job, with read access only.

## The to-do list as data

There are two kinds of cause.

- **An acceptance that does not count.** The finding is named by an `ignore` or baseline entry, and the entry lacks something: an owner, the new format, a date that has not passed. One cause per reason.
- **A rule and kind.** Each cause is an entry in the catalogue: an id, its sentence, the rule and kind pairs it covers, the kind of fix and the next command. `obaaf catalog` fails if a pair belongs to no cause or to two.

A finding counts under exactly one cause: an acceptance that does not count first, otherwise its rule and kind. Accepted and cleared findings are in no cause. Causes that OBAAF can fix now come first, then the rest by severity and count.

JSON gains a `todo` array: for each cause its id, its kind, the sentence, the count by severity, the kind of fix and the command. Nothing else in JSON changes, and SARIF does not change.

## Constraints

- Offline. The standard library and PyYAML only. No new dependency.
- Today's text report is unchanged except for the list added before its last line.
- The report, the command line and the rules are shared code, so the project's rule of one such change at a time applies.
- Each change records the result before and after on this repository and on a read-only copy of Expectrail.
- New behaviour is recorded as proposed decisions for Sean, as usual.

## Order of building

Each step is useful without the next.

1. The to-do list, with the pairing after an upgrade. Report only.
2. `obaaf fix`: the proof, the preview and the paperwork fixes.
3. The egress draft, once a commit of the action is listed.
4. OBAAF-GHA-005 clears with a settings snapshot.
5. The two tightening fixes.
6. The work order.
7. `obaaf init`'s last output, the gate switch, the documents, and the timed run again. This waits for `obaaf init` itself.

All seven steps are P0. None is left for after the first users.

## Approaches considered

1. **Checked patches inside OBAAF, plus a work order for confinement.** Chosen by Sean. Deterministic, offline, proven before offered. The most to build, and it fixes only what it can prove.
2. **A work order for the team's coding agent, for everything.** Fast to ship and handles judgement. The result depends on their agent, teams without one get nothing, and an agent's easiest fix is to write an acceptance.
3. **A bot that opens a pull request in the user's repository.** The smoothest to use. It needs write access to other people's repositories, which makes OBAAF a target and ends its read-only promise. Rejected.

## Left to the builder

- Option names beyond those shown, and whether `obaaf fix` with no fix option previews everything it can.
- How the private copy is made and removed.
- The wording of each cause's sentence.
- How "one edit away from a lane name" is measured.
- How the snapshot's settings map onto the second control, within the rule above.

## Calls made in writing this, which Sean approved with the design

- The list goes at the end of the report, where a terminal leaves the reader, and the detail above it stays as it is today.
- Causes OBAAF can fix now are listed first, ahead of severity, so the first command a newcomer runs makes visible progress.
- Completing an acceptance is offered only with `--owner` on the command line, and is shown as accepting risk, apart from every other fix.
- Accepting everything that remains stays the existing `--write-baseline` command. `obaaf fix` gets no second way to do it.
- `obaaf fix` may remove an entry whose finding is gone, and holds back a fix that would unsettle another acceptance.
- Missing code-owner rules are printed, not written.
- The first version has two tightening fixes. Everything else is "by hand" until first users' results say what to automate next.
- A settings snapshot is believed for 30 days.
- Jenkins is out of the first version.
