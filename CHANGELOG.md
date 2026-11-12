# Changelog

All notable changes to OBAAF. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow semantic versioning: drafts are numbered 0.x, and version 1.0 follows the first pilot.

## [Unreleased]

**Upgrading from 0.3.0: a gate that uses a baseline or an ignore entry will fail until its acceptances are completed.** Each needs an owner, and one whose reason has fewer than four letters or digits, or whose date is more than 366 days ahead, no longer counts. Nothing about the workflows has to change, and one command converts a baseline. See "The lifecycle of a finding" below. Two more changes can turn a passing gate red without a baseline being involved: an agent job whose egress control is a blocking Harden-Runner step is now reported under OBAAF-GHA-020 as "cannot tell", where it used to pass; a job whose `if:` only looked like a test of the event is now checked for every event that can start it; and an input written in another case (`REF:` for `ref:`) is now read. See "Controls", "Which events can start a job" and "Inputs in any case" below. Not released; Expectrail and anyone else pinned to a commit or to 0.3.0 see no change until they move.

### The lifecycle of a finding

The first adopter's gate asked one question of every finding, "is it new?", and the answer was always to accept it: all 38 findings in its baseline were accepted in a file that names nobody, gives no reason and never expires, and the file was regenerated three times in a day to add more. This changes what accepting a finding takes, and what a finding is.

- **A finding is new, accepted, fixed, or one the checker cannot tell about.** JSON output has `state` on every finding and a `summary` of the counts. Text output prints a line under a finding that was accepted by a baseline entry, that is named by an entry that does not count, or that has controls; a finding with no such line is new. "Fixed" means every control that clears the finding was read and verified, and "cannot tell" means one of them could not be read; a finding the checker cannot tell about fails the check like a new one. Two rules report controls, OBAAF-GHA-005 and OBAAF-GHA-020 (see "Controls" below); every other finding is new or accepted.
- **An acceptance needs an owner, a reason and an expiry date, in an `ignore` entry and in a baseline entry alike.** The owner is a user (`@name`), a team (`@org/team`) or an e-mail address; only its form is checked. The reason needs at least four letters or digits. The date must not have passed and must be at most 366 days ahead. An entry that lacks one of the three, has expired, or is dated further ahead accepts nothing: its finding counts as new, and the report says under the finding what the entry lacks.
- **`ignore` entries need `owner:`.** A configuration written for 0.3.0 still loads, and its entries ignore nothing until an owner is added to each. `until: 2999-01-01` no longer works either. An `until` that is not a plain date (`2027-01-31T10:00:00Z`, `20270131`) is now a configuration error on every Python version; a time of day there used to end in a traceback when the entry matched a finding.
- **New baseline format, `obaaf-baseline/v0.2`.** An entry holds what the finding is (rule, file, job, step, which of the rule's cases, and the values it is about, such as the secrets a job receives), the severity it was accepted at, and the owner, reason and expiry date. It has no fingerprint and no message: the fields a reviewer reads are the acceptance. Entries no longer depend on how a rule's message is worded, so a release that rewords one does not break a baseline. Three kinds of finding still carry text: for OBAAF-GHA-003 the reason the job is an agent job is part of the finding, as the text the checker shows, so an acceptance stops covering the job when that text changes (another recognised action, a command in another step, a declaration added), and it does not tell agents apart beyond that; for OBAAF-INS-001 each hidden character is identified with a digest of the line it is on (a line ends at a line feed or a carriage return), so the same character with other text on its line is another finding; and Jenkins findings are still identified by their whole message. An entry does not cover a finding that has become more severe than the entry says.
- **`obaaf-baseline/v0.1` files (written by 0.2.0 and 0.3.0) are still read, and accept nothing.** Each entry still finds its finding, so the report can say what the file used to cover, but with `--fail-on low` the check fails until the file is converted. `obaaf baseline migrate FILE --owner … --reason … --expires …` converts it: it carries over the findings the old file covers that are still found, and accepts nothing else.
- **`--write-baseline` takes `--owner`, `--reason` and `--expires`, and never renews an acceptance by itself.** Entries of the file it replaces that are still valid keep their own owner, reason and date. Only findings that no valid entry accepts get the ones given on the command line, and without them nothing is written (exit 2). It refuses to write over a v0.1 file, and over any existing file that is not a baseline (0.3.0 wrote over whatever was there, `/dev/null` included).
- **JSON output** keeps every field it had. New: `state`, `kind`, `facts`, `acceptance` and `controls` on a finding, `summary`, `baseline.format`, and `fixed` (findings cleared by verified controls, which are no longer in `findings`). SARIF results carry `obaaf-state`.

What an adopter will see on upgrading:

- With a v0.1 baseline: every finding the baseline covered is reported as new, with the line "Not accepted: the baseline entry that names this finding does not count", and the report ends with the `obaaf baseline migrate` command to run. After converting, the same findings are accepted again, each with an owner, a reason and a date.
- With `ignore` entries: each finding an entry used to ignore is reported, with "because it names no owner", until `owner:` is added. An entry whose reason has fewer than four letters or digits (`reason: ok`), or whose `until` is more than 366 days ahead, stays without effect after that, and the report says which.
- With neither: no change in findings or exit codes. Messages are word for word what they were (compared on this repository, its fixtures and templates, and Expectrail at `16edb91`).

### Controls

The first adopter had the same two findings on each of its 19 agent jobs, a secret in the job (OBAAF-GHA-005) and no egress restriction (OBAAF-GHA-020), and the only thing it could do with any of the 38 was accept it. Both findings now name the controls that would clear them and say what the checker established about each. **Neither can be cleared yet**, and the report says which control stands in the way.

- **OBAAF-GHA-005, for a job that references secrets, lists four controls**, and is fixed only when all four are verified: `secrets-protected` (each secret is listed in `protected_secrets` and the job declares the environment named there), `environment-restricted` (the secrets are stored only in that environment and only protected branches may use it), `no-outsider-input` (no pull request, issue or comment can start the job, no checkout step names a pull request's ref, and no expression or `if:` reads a field an outsider writes) and `egress-enforced` (a control the checker recognises limits the job's network access to an allow-list). Each is reported as verified, not met or cannot tell. The guide has [what is read for each and what is not](docs/checker-configuration.md#controls).
- **`environment-restricted` is never verified.** It is a repository setting. `obaaf audit` reads environments and their branch rules, and `obaaf check` does not use what it reads yet, so it is "cannot tell"; for a job that declares no environment it is "not met".
- **`egress-enforced` is never verified.** A job with no blocking egress control, with one behind an `if:`, with one that is not the job's first step on its own (it starts after other steps, in a `parallel` group or in the background), or with only an `OBAAF_EGRESS` declaration is "not met". A `step-security/harden-runner` step with `egress-policy: block` and no `if:`, as the job's first step, is "cannot tell": whether it limits the agent depends on its version and on the job being unable to undo it with sudo or a container, and the checker reads neither yet.
- **OBAAF-GHA-020 is now reported for every agent job**, with that one control. This is the one place where a workflow that passed is now reported: a job with a blocking Harden-Runner step and no `if:` had no OBAAF-GHA-020 finding, whatever the step's version and wherever it stood in the job, even after the agent. It now has one: "cannot tell" when the monitor is the job's first step, "not met" when it is not. Either fails a gate at `--fail-on low` until it is accepted with an owner, a reason and an expiry date. A baseline entry that accepts the "cannot tell" case is for the workflow file as it stood, byte for byte (the finding carries the file's digest), so it stops covering the job when the monitor is repinned, moved or changed in any way, and also on any other change to that file. An ignore entry holds until its date, as before. The three cases reported before keep their messages and their identity, so a baseline entry for one still matches.
- **A proxy that holds the model key is not counted as a control.** Two exist (the Agent Workflow Firewall's, and `openai/codex-action`'s); neither has been run here, so neither is credited.
- **A workflow compiled by GitHub Agentic Workflows (`.lock.yml`) is read like any other workflow file** and gets no credit for how it was made.
- Text output lists the controls under a finding, one to a line, verdict first. JSON output has `id` on each control. For a finding that lists controls the line "Architecture: fixing this means adopting the agent and effect lanes" is no longer printed: the controls are the other way to clear it.

On the first adopter's workflows at `b4e07bc`, with its own configuration: all 19 agent jobs have `secrets-protected` verified; 11 have `no-outsider-input` verified and 8 "cannot tell" (seven check out a second repository, one checks out a ref computed when the job runs); all 19 have `environment-restricted` "cannot tell" and `egress-enforced` "not met". So all 38 findings are still new, and what each job lacks is an egress control.

### Which events can start a job

Many rules ask which events can start a job, and a job's `if:` can rule an event out. That was decided by searching the text of the `if:` for `github.event_name == '...'`, so text that only looked like such a test removed an event, and every rule that depends on the event (OBAAF-GHA-001, 002, 007, 011, 013 and 015, one case of 012, the severity of 008 and 010, and whether a job builds pull requests) was silent or too mild for a job that does run on it. The condition is now read from its tokens. With `on: [pull_request_target, workflow_dispatch]`, each of these was read as "runs on `workflow_dispatch` only" and is now read as running on both:

- **The test inside a string**: `if: ${{ 'github.event_name == "workflow_dispatch"' != '' }}`, which is always true, and the same text as an argument of `format`.
- **A comparison of the comparison**: `if: github.event_name == 'workflow_dispatch' == false`, which is true on every event except the one named.
- **Text outside `${{ }}`**: `if: ${{ github.event_name == 'workflow_dispatch' }} && ${{ true }}`, a `${{ }}` followed by a space, and a `|` block, whose line break is outside it. GitHub reads each as a text, and a text that is not empty is true.
- **A job that needs a gate and can outrun it**: a job that `needs` a job limited to one event was limited to that event too, unless its `if:` said `always()`, `failure()`, `cancelled()`, `!success()` or `success() || ...`. `success() == false`, `!(success())` and `success()` passed to a function also let it run when the gate was skipped, and were not seen. The same reading decides whether a check in an earlier step or a needed job really stops a release or an applied proposal (OBAAF-GHA-016, 021, 022).
- **A called workflow**: with `on: workflow_call`, `if: github.event_name == 'pull_request_target'` was read as "never runs". In a called workflow `github.event_name` is the caller's event, so no test rules `workflow_call` out.

What rules an event out now: a comparison of `github.event_name` with a text, `==` or `!=`, either way round, alone or joined to other conditions by `&&` and `||`. So the reader is also more exact than it was: a condition with a negation elsewhere in it (`github.event_name == 'push' && !contains(...)`), the text first (`'push' == github.event_name`) and `github['event_name']` now narrow, where before they did not, which can remove a finding from a job that never runs on the event. A comparison with a letter outside ASCII is not read, because what GitHub's comparison makes of it has not been established. A status function still counts wherever the text has it, inside a string and outside `${{ }}` included, as before. Nothing here has been run on GitHub: it rests on GitHub's documentation of expressions and of `if:`.

### Inputs in any case

GitHub hands an action its inputs as environment variables named in upper case, so `REF:` and `ref:` under `with:` are the same input. The checker read input names exactly as written, so a rule that looks at an input did not see one spelt in another case: with `on: pull_request_target`, a checkout with `REF: ${{ github.event.pull_request.head.sha }}` was not reported by OBAAF-GHA-002, `Allow-Unsafe-PR-Checkout: true` not by OBAAF-GHA-019, and an agent job's checkout of the pull request not by OBAAF-GHA-012. The same held for the cache inputs OBAAF-GHA-006 reads and for a monitor's `egress-policy`; and `Persist-Credentials: false` was not seen, so OBAAF-GHA-011 was reported where it should not have been. Input names are now read with A to Z in either case. A step that gives the same input twice in two spellings is an error: the checker cannot tell which value GitHub uses. So is an input name with a letter outside ASCII, since what GitHub's upper-casing makes of one is not established. Found by the review of the controls above; not run on GitHub.

### Settings audit

- New command `obaaf audit`: reads the GitHub settings that workflows depend on and records them in a snapshot file (`obaaf-settings-snapshot/v0.1`). It reads rulesets and who may bypass them, the rules in force on the default branch, classic branch protection, environments and which branches may deploy to them, the names of environment, repository and organisation secrets, Actions permissions, the workflow token's default permissions, approval for fork pull requests, Actions policies, and how many accounts hold each role. **It applies no rule yet**: it reports what the settings are, not whether they are right.
- Every setting is recorded as read, partly read, not read or not applicable. A setting that was not read is listed by name with the reason and with what GitHub's reference says a caller needs; it is never left out. An answer that does not have the documented shape is recorded as not read: a field whose absence could pass for "none" must be there. In a value, `null` means not known, a part that does not apply is left out, and a known "none" is written out. Every snapshot is checked against its schema before it is written or reported, and a value the schema refuses makes that setting not read.
- Read-only by construction: the client sends GET requests and has no other verb. A token is taken from the environment (`GH_TOKEN`, `GITHUB_TOKEN` or `--token-env NAME`), never from the command line, and is sent only to the API address the audit was started with. It is in no output, and is cut out of any answer that echoes it. With no token the audit reads what GitHub shows anyone about a public repository and asks for nothing else.
- An empty list of who may bypass a ruleset is never recorded as "nobody": GitHub shows the real list only to a caller with write access to the ruleset, and it is not established what it sends anyone else. The audit can show that someone may bypass; it cannot yet show that nobody may.
- `obaaf audit --from-snapshot FILE` reports from a saved snapshot with no network, after checking the file against a schema that covers every value. `--fail-on-unread` exits 1 when a setting that applies was not read in full. Reading nothing at all (repository not found, rate limited at the first request) exits 1, and so does any failure the command did not foresee.
- Tested from recordings written by hand from the examples in GitHub's REST reference, and from two recordings of what GitHub itself answered a caller with no token, for this repository and for the first adopter's. Run against GitHub by a workflow in this repository, with the workflow's own token and with no token: the settings GitHub shows anyone were read, and the administrative ones were refused and reported as not read. It has not been run with a token that can read the administrative settings. See [docs/settings-audit.md](docs/settings-audit.md).

### Fixed

- `obaaf check --write-baseline` ended in a Python traceback when a job id contained a lone surrogate character (a name YAML can spell and Unicode cannot encode). The baseline is now written, as valid UTF-8, and read back.
- Two more tracebacks, both in 0.3.0: `--write-baseline` to a directory that does not exist, and a v0.1 baseline whose `rule` or `severity` is a list. Each is now an error message and exit code 2. So is `obaaf check --output` to a path that cannot be written.
- An `ignore` entry dated with spaces around a quoted date (`until: " 2027-01-31 "`) is read as that date; 0.3.0 refused it.

## [0.3.0] - 2026-11-12

**Upgrading from 0.2.0: a gate that passed can fail without the workflows having changed.** Several changes make the checker report what it missed before. The largest are "Lanes" and "Expressions" below. Among the smaller ones: a repository that has a Jenkinsfile now has it checked along with its workflows, and an agent command line with options before the prompt flag, such as `claude --model x -p ...`, now makes a job an agent job (both under "Jenkins (advisory)"); an unknown setting in `.github/obaaf.yml` is refused ("Protected secrets"); and a path with nothing to check is an error, not a pass ("Checker"). Baselines are new in this release. One written from `main` before the release can go stale under "Lanes" or "Expressions" and has to be regenerated with `--write-baseline`.

### Lanes

A job now gets the rules of every lane it belongs to. Before, a job had exactly one lane, chosen in a fixed order (agent, effect, release, untrusted), so a job that did two things was checked for one of them. An independent reviewer found the first two cases on 2026-11-11; the rest are the same class, found while fixing it and in a second review of the fix.

- **A job that runs an agent and publishes** was checked as an agent job only: the release rules (OBAAF-GHA-006, 014, 015, 016, 017) did not run on it. It is now in both lanes.
- **A job declared an agent job that also publishes** was checked as a release job only, and the declaration was dropped: no OBAAF-GHA-003, 005 or 020. The same held for any declared lane on a job the checker had already placed in another. A declaration now adds a lane and never replaces one.
- **A declaration could remove a finding.** Declaring a pull request job `release` or `effect` moved it out of the untrusted lane and dropped OBAAF-GHA-011. So did adding an upload step. A job that runs only for pull requests (`pull_request`, `merge_group`) is now in the untrusted lane whatever else it is.
- **A job that uses a release environment and can be started by a pull request or another untrusted event** was not a release job: an environment whose name says release, production, publish, deploy or a store made a job a release job only when no untrusted trigger could start it, which is the case OBAAF-GHA-015 exists for. With `on: pull_request_target` and `environment: production` the job was shown as `trusted (default)`. The environment now decides on its own. Because more jobs are now judged by the name, one kind of name is no longer taken for a release environment: a name in which `non` or `pre` does not follow a letter a to z (case ignored) and stands before `prod` with at most one of `-`, `_`, `.` or a space between: `nonprod`, `aws-non-prod`, `pre-production`. A push job with such an environment got the release rules before and does not now. `canon-prod` and `AppNonProd` are still release environments, because there `non` follows a letter. Every other name is matched as it was, anywhere in the name and in any case.
- **An agent started from a repository script** was detected only in jobs with no other lane. It is now detected in any job.
- **Two declarations for one job.** A lane in `.github/obaaf.yml` hid the job's own `OBAAF_LANE`, a per-job entry hid a per-file entry, and a job's `OBAAF_LANE` hid the workflow's. All of them now count.
- **A declaration that did nothing was ignored without a word.** Case and surrounding space no longer matter (`OBAAF_LANE: Agent` is `agent`, in a workflow, in `lanes:` and for a Jenkins stage). These are now listed in the report's notes: a value that is not a lane (a misspelling, an expression, an empty value) in a workflow, a Jenkinsfile or `lanes:`; `OBAAF_LANE` in a step's `env`, a container's or a service's, where a workflow does not read it; for a file the run reads, a `lanes:` entry that names a job or Jenkins stage the file does not have; and, when a repository is checked, a `lanes:` entry for a file that is not there. An entry for a file outside the run (another file when one file is checked, a Jenkinsfile when only workflows are checked) is not looked at. Notes do not change the exit code.
- **A Jenkins stage's declarations hid each other.** A `lanes:` entry for a stage replaced the stage's own `OBAAF_LANE`, and a stage's `OBAAF_LANE` replaced the pipeline's, so `lanes: {Jenkinsfile#Ship: trusted}` on a stage declared `release` removed OBAAF-JEN-005 and OBAAF-JEN-012. Every `agent` and `release` declaration that reaches a step now counts, as in a workflow; on a Jenkins stage the other lanes change nothing. A `lanes:` entry for an outer stage now also reaches the stages nested in it, and an entry for the file (`Jenkinsfile`), which did nothing, reaches every stage. A declared stage now also covers a step whose code is not in the file (a shared-library step) unless the step is in a `post`, `catch` or `finally` block, and a stage declared `release` covers the `sshPublisher` and `ftpPublisher` steps, which the guide told adopters to declare and the checker then ignored; before, a declaration reached only shell steps.
- **OBAAF-JEN-012 could be reported at medium when a step published with no check at all.** It is reported once for a Jenkinsfile, and it went to the first publishing step that lacked a full check. When that step had a provenance check, the finding was medium and a later step that nothing checked was not mentioned. It now goes to the first step with no check, and to a step with a provenance check only when there is none.
- **One workflow checked with the repository's configuration** (`obaaf check .github/workflows/ci.yml --config .github/obaaf.yml`) lost its `lanes:` entries, because the checker called the file `ci.yml` and the configuration calls it `.github/workflows/ci.yml`. Both names now match.
- **A note could be silenced.** The note about a job whose name suggests agent work was printed only for jobs in no lane, so declaring `untrusted` removed it. It is now printed for any such job that is not in the agent lane, and reads "are not in the agent lane".
- **`lanes:` that is not a mapping.** `lanes: 5` and `lanes: true` stopped the checker with a Python traceback, and a list gave an error that did not name the setting. Each is now a configuration error that says `lanes` must be a mapping. An empty value still declares nothing. A configuration file that is not valid YAML was a traceback as well, and is now a configuration error.
- **A step name that contains a line break** could make one line of `--lanes` or of the text report look like two, the second of them invented. Text taken from the files checked is now printed on one line, with the line break shown as `\n`. The JSON and SARIF output carry the text unchanged.

What an adopter will see on upgrading:

- New findings on jobs that are in more than one lane, and on jobs that use a release environment and can be started by a pull request or another untrusted event. `--lanes` names the extra lanes: `agent (…; also release: …)`.
- For a job whose lanes did not change, the same findings with the same messages, so baseline entries still match. Two things are kept as they were for that reason: a job that is declared into a lane it is also inferred into shows the declaration as the reason, and OBAAF-GHA-017, which is reported once per workflow, stays on the first publishing job that is not also an agent or effect job when there is one.
- The exception: a declaration that used to be ignored is read now. That is one written in another case or with spaces (`OBAAF_LANE: Agent`), one that stood behind another declaration for the same job (only the first was read, even when its value was not a lane), and a `lanes:` entry for a workflow checked on its own. If the job was already in the lane it names, the job's agent findings quote the declaration as the reason (`set by OBAAF_LANE`) where they quoted what the job runs, or gain or lose the words about `trusted`, and a baseline entry for them has to be regenerated.
- In a Jenkinsfile, more advisory findings where more than one declaration reaches a stage or a declared stage calls a shared-library step. OBAAF-JEN-005 and OBAAF-JEN-012 are reported once for a file and can move to another stage when that happens. OBAAF-JEN-012 can also move, and rise from medium to high, in a Jenkinsfile with no declaration at all: when one step publishes after a provenance check and a later one publishes with no check, the finding is now about the later one.
- New notes for declarations that do nothing. Notes appear in the text and JSON output and with `--lanes`; the SARIF output does not carry notes yet.

The Jenkins analyser still decides what a stage does step by step, with its own code. What changed there is how it reads declarations and which step OBAAF-JEN-012 is reported on.

### Expressions

Several spellings that no rule reported are now reported. They were found by reading the checker and by an independent review of the first fix. None has been run on GitHub.

- **Secrets.** Secret references are read from an expression's tokens, not matched as text. `secrets.*`, and any other use of the `secrets` context that is not one literal name (for example `contains(secrets, 'x')`), counts as every secret (OBAAF-GHA-001, 005, 024). A secret referenced anywhere in a job is found, including in `outputs`; before, only `env`, `with`, `secrets`, `container`, `services` and `steps` were read.
- **Where an expression ends.** An expression is no longer cut short at a `}}` inside a string, as in `${{ format('}}{0}', secrets.KEY) }}`, which hid whatever followed from every rule that reads expressions.
- **OBAAF-GHA-010.** The rule keeps its text patterns and adds a second pass over the expression's tokens. It now follows a wildcard or computed index (`github.event.*.title`, `github.event.issue.*`, `github.event[inputs.kind].body`), a property of a group or of a function's result (`(github.event.issue).title`, `toJSON(github.event.issue || 1)`), `${{ env.NAME }}` when NAME is set from an outsider-written field, directly, through other env values or through the matrix, and `${{ matrix.x }}` when the job's matrix is built from such a field. It does not follow values set at run time (`GITHUB_ENV`), values passed between jobs or into reusable workflows and composite actions, scripts other than `run` and `actions/github-script`, an `env:` written as one expression that itself reads env or matrix values, or a `with:` written as one expression.
- **Files the checker cannot read are errors, which fail the check:** an expression nested more than 64 levels deep, a text with too many unfinished expressions, a file too large to read in the memory available, a value only an explicit YAML tag produces (`!!set`, `!!pairs`, `!!omap`, `!!binary`, or text under `!!null`), a job or step that is not a mapping, and a file containing U+0085, U+2028 or U+2029 (YAML readers disagree on whether these end a line).

Other changes in behaviour: any string given for `secrets:` on a reusable-workflow call counts as `inherit`; `secrets["KEY"]` (double quotes, which GitHub rejects) and an index that is not a name count as every secret; an expression with no closing `}}` is read to the end of its text; text inside a string, such as `format('secrets.KEY')`, is no longer mistaken for a secret reference (OBAAF-GHA-010 still reports a field named inside a string, as before). Because `obaaf attest` records the secrets a job can read and `obaaf verify release` checks that record, a job that names a secret only in a place that was not read before is now recorded as holding it. Findings for workflows that use none of these spellings are unchanged (checked on this repository's workflows, fixtures and templates, and on Expectrail).

### Protected secrets

- GHA-024 hardening, after an independent review: a computed secret index (`secrets[format(...)]`, `secrets[matrix.k]`) counts as every secret for all rules; the `secrets` context matches in any case; overlapping `protected_secrets` entries all apply; environment names compare case-insensitively; reusable-workflow callers get advice they can follow, and `secrets: inherit` is no longer reported; globs need three letters or digits; unknown configuration settings are refused. The published test set shows the configuration a fixture is checked with.
- New rule OBAAF-GHA-024. List secrets under `protected_secrets` in `.github/obaaf.yml` (optionally with the environment that must hold each one), and the checker reports every job that uses one without declaring that environment. Anyone with write access can read a repository secret by pushing a workflow on a branch; the GitHub settings guide now says so and describes how to keep such secrets in an environment limited to the default branch. Test fixtures can carry a configuration in an `# obaaf-config:` line.

### Baselines

- `obaaf check --write-baseline FILE` records the current findings; `obaaf check --baseline FILE` reports them but fails only on new findings, or on baseline entries that no longer match (so fixes are locked in). Findings match without line numbers. JSON output marks `baselined` and lists stale entries, and SARIF output sets `baselineState`, only when a baseline is used. See docs/checker-configuration.md#baseline. Each entry's fingerprint is recomputed from its visible fields on load (a mismatch is refused), stale entries follow the `--fail-on` threshold and category, and expired ignores are never written into a baseline.

### Fixed

- A negated status function in a job's `if:` (for example `!cancelled() && github.event_name == 'workflow_dispatch'`) no longer stops the checker from narrowing the job's triggers by its event test. Any other negation still does.

### Project

- Governance is adopted rather than draft, and the project now accepts outside contributions under CONTRIBUTING.md; the code of conduct is the Contributor Covenant 2.1 in CODE_OF_CONDUCT.md (D-038).
- New documents: [docs/landscape.md](docs/landscape.md) compares OBAAF with other tools that check workflows and repository settings, with what the five that could be run found on the same repositories, and says where OBAAF stands; [docs/egress-control.md](docs/egress-control.md) is the design of a control that limits an agent command's network access, not built yet; [docs/flagship.md](docs/flagship.md) is the plan both belong to.

### Platform scope

- The website, README, adoption guide, glossary, traceability and package description now say that `obaaf check` reads GitHub Actions workflows and, as an advisory auditor, Jenkinsfiles. The templates, `setup-obaaf` and keyless signing remain GitHub Actions only. The site's quickstart runs `obaaf check .`, which covers both.

### Added

- Projects that vendor no binaries can declare `vendored_binaries: none` in `obaaf-sources.yaml`. `obaaf manifest create` writes an empty `obaaf-manifest/v0.1` with `vendoredBinaries: "none"` so the build-record digest binds the claim; empty `components` without that declaration still fails closed (D-033). Set `build_record.require_sdks: false` in the release policy so `obaaf verify release` accepts an empty SDK list.
- OBAAF's own repository commits that empty declaration and, on PyPI release, checks the manifest, signs an OBAAF build record beside SLSA provenance, and runs `obaaf verify release` (provenance body, build record, environment approvals, agent history) before upload.

### Changed

- `jsonschema` 4.26.0 or later is required (was 4.18).
- PyPI publish dogfoods FR6: `.github/obaaf-policy.yaml` (`require_sdks: false`, environment `pypi`, `runner_environments: [github-hosted]`); the publish job checks out the default branch, installs the reviewed CLI via `./actions/setup-obaaf`, and replaces the `gh attestation verify` type-only loop with `obaaf verify release`. Residual vs the template lane: no `workflow_run` split and no pre-approval summary job.

### Jenkins (advisory)

- `obaaf check` now reads Jenkinsfiles (`Jenkinsfile`, `Jenkinsfile.<name>`, `Jenkinsfile-<name>`, `<name>.jenkinsfile`, and globs in `jenkins.files`) alongside workflows, or alone with `--platform jenkins`. A syntax-only parser reads the Groovy without running any of it (D-034). Fifteen rules, OBAAF-JEN-001 to OBAAF-JEN-015, cover credentials that change requests or an agent can reach, builds on the controller and shared agents, agent stages that push or publish, pipeline code from unapproved revisions, approvals, host access from containers and pods, agent egress, unpinned images, libraries and agent CLIs, Groovy-interpolated untrusted text and secrets, moving artifact references, publishing after a failed check, missing release verification, signing keys, and webhook tokens in the file. Each maps to profile requirements and agent controls in the catalog.
- Every Jenkinsfile gets a coverage result per rule (pass, fail, ignored, unknown, not applicable) in text and JSON output, with the reason for each unknown. Controller settings and shared-library code are reported as unknown, never as a pass, and the report states that exit 0 is not a conformance decision (D-036). See [docs/jenkins.md](docs/jenkins.md).
- `templates/jenkins/obaaf-audit.Jenkinsfile` runs the audit as a Jenkins job.
- New configuration: `jenkins.files`, `jenkins.exclude` and `agents.steps`; lane overrides and ignore entries take a Jenkins stage as `file#stage` and `job: <stage>`. `--lanes` lists Jenkins stages.
- OBAAF-REPO-001 also covers Jenkinsfiles, and is retitled "CI definition files have no code owner".
- Release lane on Jenkins (D-037): `templates/jenkins/obaaf-release-build.Jenkinsfile` builds a protected tag with no credentials in a project that builds only tags; `obaaf-release-publish.Jenkinsfile`, a separate job read from the default branch with no parameters, finds the tag build that started it, signs SLSA provenance and the build record through a key service, verifies, waits for a named approver and verifies again before uploading. A `signing: keys` policy example is included.
- `obaaf dsse prepare` and `obaaf dsse assemble` sign records with a key that stays in a key service: `prepare` writes the bytes (or digest) to sign, `assemble` accepts the service's signature (raw or base64, DER or r||s), checks it against the public key and writes the DSSE envelope.
- `obaaf verify release` reads Jenkins evidence: `--approvals` takes the publishing build's JSON from the controller, `--release-run` the JSON of the build that produced the artifacts. The publishing build must have been started by that build alone, which must be the tag build of `release.jenkins_project` and have checked out the release commit. Whoever started either build cannot approve; with `release.approvers` set, only listed people count (on GitHub too). Replays, stage restarts, builds started by hand, unclassified causes and incomplete evidence are blocked.
- Records written in a Jenkins build name it in `run` (controller, job, build URL), marked as self-reported, and the build record says its source came from the Jenkins release job.
- Agent CLI patterns accept options before the prompt flag or subcommand (`claude --model x -p ...`, `codex -m o3 exec`). This also applies to workflows, where such jobs were previously left out of the agent lane.

### Checker

- `obaaf check .github/workflows`, the form the website quickstart shows, checked zero files and passed, because discovery expected a repository root. The checker now accepts a repository root, its `.github` directory or its `.github/workflows` directory, and keeps repository-relative paths. When nothing is found, `obaaf check` exits 2 and says nothing was checked, instead of passing.

## [0.2.0] - 2026-10-26

### Attestation formats (breaking)

- Move the predicate type URIs from the reserved `obaaf.example` domain to the project's domain (D-007): `https://www.obaaf.com/attestation/agent-run/v0.1`, `.../agent-approval/v0.1`, `.../build-record/v0.1`, and the generic SLSA build type `https://www.obaaf.com/buildtypes/generic/v0.1`. The JSON Schemas' `$id` values move with them. The site now publishes a page at each type URI and each schema at its `$id`.
- Records signed with the 0.1 URIs do not verify under this version. Sign new records with the updated templates.

### Supply chain of OBAAF itself

- Install OBAAF's dependencies by hash (D-011): `setup-obaaf` and the PyPI release now install from `actions/setup-obaaf/requirements.txt` with `--require-hashes`, wheels only. `scripts/lock_setup_obaaf.py` generates that file from `constraints.txt` with PyPI's SHA-256 for every file; CI checks it against PyPI and runs the action on Linux, macOS and Windows.
- Sign SLSA provenance for OBAAF's own PyPI release in a separate `attest` job, and verify it with `gh attestation verify` before uploading. Check a downloaded file with `gh attestation verify <file> --repo Obaaf/OBAAF`.

### Papers

- Both companion papers have DOIs on Zenodo: Paper 1, *Untrusted Text, Trusted Tokens*, [10.5281/zenodo.23622566](https://doi.org/10.5281/zenodo.23622566); Paper 2, *Securing the Game Build*, [10.5281/zenodo.23622802](https://doi.org/10.5281/zenodo.23622802). The website, README, generated spec headers, threat model and paper READMEs link to them, and a `CITATION.cff` lists them so GitHub offers a citation.

### Project status

- OBAAF is no longer described as a public draft: version 0.1 is on PyPI and in active adoption with pilot teams. The website, README, CONTRIBUTING and docs say so, the README and CONTRIBUTING reflect the Apache-2.0 and CC BY 4.0 licenses already in `LICENSING.md`, and the package classifier moves from Pre-Alpha to Alpha (takes effect on PyPI with the next release).

### Checker: act on the first pilot's feedback (issue #19)

- Warn, with an advisory note that does not change the result, when a repository has agent instruction files but no job is classified into the agent lane, and when a job whose name suggests agent work stays in the trusted lane. This surfaces agents launched indirectly (for example through a wrapper script) that the lane inference misses.
- Document the existing `agents.commands` and `agents.actions` configuration, lane overrides, `OBAAF_LANE` and expiring `ignore` entries in [docs/checker-configuration.md](docs/checker-configuration.md), so an indirectly launched agent can be declared.
- Give every checker rule a category, authority or hygiene, and report the two separately in the text summary and the SARIF output (`obaaf-category`), so hygiene findings such as digest pinning do not bury authority findings.
- Add category gating to `--fail-on`: `--fail-on authority:medium` (also `hygiene:low`, or a bare `authority`) fails only on that category, so CI can gate on authority findings without first clearing every pinning finding. Plain `--fail-on high|medium|low|never` is unchanged.
- Note the dynamic `runs-on` limitation in OBAAF-GHA-013 and how to record a confirmed-safe runner with an expiring ignore entry.
- Detect agents launched through a repository script: a trusted job whose `run` step calls a repo script (for example `bash run-agent.sh`) that itself invokes an agent CLI is reclassified into the agent lane, so the agent controls apply. Best-effort, so scripts the checker cannot read still fall back to the advisory note.
- Flag findings that need an architecture change rather than a one-line fix (the agent and effect lane controls OBAAF-GHA-003, GHA-004, GHA-005, GHA-021 and GHA-022) in the text output and as `obaaf-remediation` in JSON and SARIF, pointing to the lane templates.
- Trace simple same-step copies of repository scripts to temporary locations back to their repository source for agent detection. This never executes shell code or reads outside the repository; complex shell flow and generated scripts remain unsupported.
- Report mixed hosted/self-hosted runtime selectors as informational uncertainty, retaining high findings for known self-hosted matrices and medium findings for other unknown runner labels or inputs.
- Lower GHA-008 to low only for ordinary jobs with explicitly limited permissions, no referenced secrets and no privileged outside trigger. Agent, release and effect jobs remain high; other jobs remain medium. SARIF rule metadata reflects the severities actually reported.
- Update first-adoption guidance with lane inspection and a commit-pinned path for trying unreleased code. Regression tests cover the runner and severity changes; pilot validation is pending. See [docs/roadmap-0.2.md](docs/roadmap-0.2.md).

## [0.1.0] - 2026-10-22

### Licensing

- Prepare the license grant (D-003, Proposed): Apache License 2.0 for the code, templates, tools and tests; Creative Commons Attribution 4.0 International for the specifications, guides and documentation, including the data in `src/obaaf/data/`. Add `LICENSE`, `LICENSE-docs` and `NOTICE`; set the package's SPDX expression to `Apache-2.0 AND CC-BY-4.0` with `license-files` in `pyproject.toml` (needs setuptools 77 or later, satisfied by the pinned build backend). The grant takes effect when the maintainers accept D-003 by committing these files.

### Packaging and distribution

- Publish OBAAF to PyPI (D-011): version 0.1.0 is installable with `pip install obaaf`, built and published by a trusted-publishing (OIDC) release workflow ([docs/releasing.md](docs/releasing.md)). Add `branding` to `actions/setup-obaaf` for a future GitHub Marketplace listing. Defer pre-built single-file binaries.

### Public draft publication

- Authorize public repository access and the resource site on October 10, 2026; supersede the employer-approval prerequisite for that publication (D-002).
- Publish the resource guide and generated self-assessment with GitHub Pages, deploying from main after CI succeeds.
- Keep copyright notices, draft validation limits, and intended licensing status explicit. No research-paper submission is included.

### Repository validation

- Pin rpds-py to 0.30.0, which supports the Python 3.10 and 3.13 CI matrix.
- Document intentional deferred token expansion in the Git credential helper so workflow linting preserves its behavior.

### Added

- Version 0.1 draft of all five components, built from the two companion papers and the product specification:
  - the build-integrity profile: 28 requirements in nine families, each with a rationale, a pass-or-fail test, evidence and SSDF and SLSA mappings (FR1);
  - the agent controls R1–R8 with their traceability, GitHub realization and the agent-run record's fields;
  - the self-assessment: 34 items in four tiers, an offline scorer with ranked fixes, a printable checklist and an offline HTML form that cannot make network requests (FR2);
  - GitHub Actions templates for the untrusted, agent, effect and release lanes, and a pipeline-check workflow (FR3–FR11);
  - `obaaf check`, a pipeline checker with 26 rules mapped to the profile, text, JSON and SARIF output, expiring suppressions, and a test set of 13 risky workflows modeled on documented incidents (FR12);
  - `obaaf verify release`, which blocks an upload unless provenance, the build record, release approvals and every agent record since the policy's baseline verify, and the released commit is on the protected branch (FR6);
  - `obaaf verify agent-run`, which checks an agent run's signed record against the proposal and snapshot before the effect lane acts on them (R8, FR8);
  - record generators: `obaaf snapshot`, `obaaf attest agent-run|approval|build-record|slsa`, `obaaf record write`, `obaaf manifest create|check` and `obaaf proposal check`;
  - JSON Schemas for the agent-run, agent-approval and build-record predicates (FR10).
- Guides for every self-assessment item, GitHub settings, the inference-proxy contract, attestation formats, the architecture, live acceptance tests, and a traceability matrix from FR1–FR12 to tests.
- Project documents: decisions log, contributing guide, security policy and licensing status, and a glossary.

### Draft corrections

The following corrections are recorded in the draft. Remaining issues are listed below.

- `obaaf proposal check` reads the patch with Git as well as its own parser, decodes quoted file names, matches protected paths without regard to case, refuses renames, copies, unusual file modes and paths under names starting with `.`, and with `--repo` tests the patch against a temporary index. Four patch forms that previously reached protected files are now refused. The comment filter is stricter.
- The effect lane is split into an `approve` job, which verifies the agent-run record against every proposal file and the snapshot, and an `apply` job, which holds write access but cannot sign. Approvals by anyone who wrote the agent's inputs no longer count.
- Releases are published by a new `obaaf-publish.yml`, which runs from the default branch, verifies before the approval and again after it, and requires the released commit to be on the protected branch. Agent commits are checked from a baseline in the policy rather than from the previous tag.
- The release verifier fails closed on missing certificate fields, requires `source_refs`, ignores a bad extra attestation when a valid one exists, ties each agent record to the commit that adds it, checks it is used once, requires the exact approved diff by default, and checks the agent run's cache, environment and runner. Its `--gh-json` option is removed.
- The checker no longer lets a negated condition, a declared lane or a match-everything ignore entry hide findings, reports unknown runner labels, finds script injection written with index syntax or `toJSON`, treats GitHub Script artifact downloads as effect jobs, does not count a verification whose failure is ignored, and reports provenance-only checks and declared-but-unenforced egress.
- The setup action pins its build backend and installs `cryptography` for key-based verification. The snapshot's default floor is Public, and membership alone no longer raises a label. The binary manifest records symbolic links.
- The generated specifications keep the papers' qualifiers (for example "Build L3, for Tier A" and "PS.4 (draft 1.2)"). Status statements for FR3, FR4, FR7, FR10, FR11 and NFR3 now say what version 0.1 does not do. Guides for items 1.2, 1.6, 2.3, 2.5, 2.10, 3.3, 4.1 and 4.3 are corrected, and the employer-name test no longer contains the names.
- Second round: the checker now sees steps inside `parallel` groups, does not count a `background` verification as a gate, does not narrow triggers through jobs a `success() || …` condition can bypass, requires both checks for an effect job, and reports step forms it cannot read. The verifier compares an agent commit with the approved patch by applying the patch to the commit's parent, refuses other changes in the records directory, shallow clones, and a `--range` that overrides the policy's baseline, and no longer skips the protected-branch check when it lacks the release commit. More agent configuration files are protected. The documents say that the author has not yet reviewed version 0.1, what Free, Pro and Team plans can and cannot do, and that the agent's pull requests need to be reopened to start their checks.

### Still open after review

- Live acceptance tests: none has been run; they need a sandbox repository.
- Egress for agent jobs is declared but not enforced by default, and the inference proxy is not built (D-020).
- Models are not pinned by digest (FR10), and game binaries are not code-signed (D-031).
- A merge-review mode for the effect lane, and a key-signing release template, for private repositories without GitHub Enterprise Cloud (D-023).
- The proposal check's list of agent configuration files has to follow new agent products.
