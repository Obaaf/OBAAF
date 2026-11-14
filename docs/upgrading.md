# Upgrading OBAAF

What changes when you move to a newer OBAAF, and how to do it so that a gate that turns red tells you something. OBAAF is 0.x: a release may change what passes. Release 0.3.0 showed the need. The code after it turns a passing gate red in several ways without a line of the workflows having changed, each on purpose.

## Versions, and what to pin

- **A release** has three numbers (`0.3.0`). It is on PyPI (`pip install obaaf==0.3.0`) and has a tag (`v0.3.0`).
- **Between releases** the code on `main` calls itself a development number (`0.4.0.dev0` on the way to 0.4.0). It is not a release, and it changes without notice. The JSON and SARIF reports, a baseline file and the generated documents say which version wrote them; the text report does not (`obaaf --version` does).
- **Pin what your gate runs**: a release from PyPI, or the `setup-obaaf` action at a full commit SHA. A gate that follows `main` can fail because OBAAF changed, on a day nobody chose.
- How a release is made is in [releasing.md](releasing.md). What each release changed is in the [changelog](../CHANGELOG.md).

## How to upgrade

Move the pin in a pull request of its own, so that the gate runs once with the new version and nothing else changes with it.

1. Read the section below for the version you are moving to.
2. With the new version, run the report without failing anything: `obaaf check . --fail-on never`, with `--baseline FILE` if your gate uses one. Read its first lines and anything marked "Not accepted".
3. Run your gate's own command and look at the exit status. If it is 1, the report says why: each finding that counts says under it what its acceptance lacks, and an old baseline is named with the command that converts it.
4. Do what the section says: convert the baseline, complete the `ignore` entries, correct the declarations.
5. Run the gate's command again. Commit the pin together with the changed baseline and configuration, and have the baseline reviewed like a workflow.

## From 0.3.0 to the code on `main` (0.4.0, not released)

Nobody is affected until they move: a repository pinned to 0.3.0 or to a commit sees no change. This section becomes the note for 0.4.0 when that is released, and may gain entries until then.

### What can turn a passing gate red

| What you have | What happens | What to do |
| --- | --- | --- |
| A baseline written by 0.2.0 or 0.3.0 (`obaaf-baseline/v0.1`) | It is still read and accepts nothing: every finding it covered counts as new, marked "Not accepted" | `obaaf baseline migrate FILE --owner OWNER --reason REASON --expires YYYY-MM-DD`, once. It carries over the findings the old file covers and accepts nothing new |
| An `ignore` entry with no `owner:` | It ignores nothing, and the finding is reported with "because it names no owner" | Add `owner:` (`@user`, `@org/team` or an e-mail address) |
| An `ignore` entry whose reason has fewer than four letters or digits, or whose `until` is more than 366 days ahead | It ignores nothing, and the report says which | Give a reason; bring the date within a year |
| An `ignore` entry whose `until` is a date in another spelling (`20270131`) | A configuration error, exit status 2. (A time of day, `2027-01-31T10:00:00Z`, ended 0.3.0 in a traceback when the entry matched a finding; it is the same error now) | Write `YYYY-MM-DD` |
| A lane declaration that does nothing: `OBAAF_LANE: agnet`, `OBAAF_LANE` in a step's `env`, a `lanes:` entry for a job that is not there | 0.3.0 listed it in a note. It is the finding `OBAAF-CFG-001`, high in most cases, and fails the default gate | Correct or delete it, then run `obaaf check . --lanes`. Correcting it can bring the findings it was hiding. To keep it, accept it in the baseline; an `ignore` entry cannot accept this rule and is a configuration error if it names it |
| An agent job whose egress control is a blocking `step-security/harden-runner` step | 0.3.0 reported no `OBAAF-GHA-020` for it. It is now reported. It is "not met" when the step is not the job's first, runs behind an `if:`, is at a commit OBAAF lists as a release before v2.16.0, leaves `sudo` or containers to the job, or the job runs in a container on a GitHub-hosted runner; otherwise "cannot tell" (a tag or an unlisted commit included). A baseline entry written for "cannot tell" before slice 2c.3 stops counting where the monitor is now "not met", because that is another case of the rule | Set `disable-sudo-and-containers: true` and pin a release from v2.16.0 on, then accept it again; or move the job to GitHub's native egress firewall or OBAAF's egress action, which can clear it |
| A job whose agent CLI is only in the `run` input of OBAAF's egress action, or in a script that input runs | It is now an agent job, with the agent rules (OBAAF-GHA-003, 005, 020 and the rest) | Fix or accept the findings; OBAAF-GHA-020 can be cleared by the action itself (see "Egress control" in the changelog) |
| An agent job that runs `awf ... --` in a script (where a command starts, outside a comment), with an accepted `OBAAF-GHA-020` | The finding is now the case `awf` ("cannot tell"), not `none`, so an acceptance of `none` no longer names it | Accept it again |
| A job whose `if:` only looked like a test of the event (the test inside a string, compared with `false`, or outside `${{ }}`) | It is now checked for every event that can start it, and can have findings it did not have | Fix the findings, or write the `if:` as a plain comparison of `github.event_name` |
| An input written in another case under `with:` (`REF:` for `ref:`) | It is read as the input it is, so a rule that looks at it now sees it | Fix the finding |
| A release policy (`signing: keys`) or `obaaf dsse assemble --public-key` that names a key outside ECDSA P-256 and P-384, Ed25519 and RSA (P-521, secp256k1, DSA, Ed448, X25519, a binary curve) | The key is refused when it is loaded, with an error naming the file, and `obaaf verify release` and `obaaf dsse assemble` end with status 1. Before, a key on another prime curve was accepted, a binary-curve key ended both commands in a traceback (with the pinned cryptography 50.0.1), and the other kinds failed later | Sign with a P-256, P-384, Ed25519 or RSA key and name its public key in the policy |
| A step that gives one input twice under two spellings (`ref:` and `REF:`) | An error for the file, and exit status 1 whatever `--fail-on` says: the checker cannot tell which value GitHub uses | Keep one of the two |
| A step that runs `obaaf check --lanes` | It ends with 1 where `obaaf check` reports an error for a file (it could not be read or parsed, an input given twice, an expression too deep), and with 2 when the path has no workflow or Jenkinsfile or is not there; it ended with 0 in every case (slice 3.2a) | Fix the file the `error:` line names, or the path |
| A `permissions` value GitHub does not document: a scope name in another case, a level other than `read`, `write` or `none`, a string other than exactly `read-all` or `write-all` | An error for the file, exit status 1 whatever `--fail-on` says; the agent rules read it as the widest grant (slice 2d.2b) | Write it as GitHub documents |
| An event under `on:` written other than in lower-case letters and underscores | An error for the file, exit status 1 | Write the event's name as GitHub does |
| An agent job with no permissions in a workflow that has `workflow_call` | OBAAF-GHA-003 is now the case `inherited`, not `undeclared`, so an acceptance of `undeclared` no longer names it; OBAAF-GHA-004 is new | Declare the job's permissions in the called workflow |
| `protected_secrets` set, and a job that calls a reusable workflow with `secrets: inherit` | A new high OBAAF-GHA-024 for each protected entry | Pass the secrets the called workflow needs by name, none of them protected, and declare the environment in the called workflow's job |
| `protected_secrets` with two entries for one secret name in different case | A configuration error, exit status 2 | Keep one |
| A job that can read every secret (`secrets: inherit`, `toJSON(secrets)`, a computed name) | A new OBAAF-GHA-018, case `any-secret` (medium, high in a release job) | Pass only the secrets the job needs, by name |
| An accepted OBAAF-GHA-001, 005 or 018 about secrets, on a job that declares an environment | The environment is now part of the finding, so the acceptance no longer names it | Accept it again; `obaaf baseline migrate` is not needed for this |
| A `pull_request_target` job behind an environment named by an expression | OBAAF-GHA-001 is high, case `privileged`, where it was medium | Name the environment in plain text, with required reviewers |
| A `CODEOWNERS` file, or an agent instruction file that is not a link, that cannot be read | An error for the file, exit status 1; `obaaf check` ended in a traceback, `--lanes` ended 0, and an unreadable instruction file was skipped (slice 2d.8) | Make the file readable, or remove it |
| A checkout or a script in a `pull_request_target`, `workflow_run`, comment or review workflow that brings in a pull request's code in a spelling OBAAF did not read (index syntax, another case, `format`, `env`, the fork's repository with no `ref`, `git -c ... checkout`, `git pull`, `git reset`, `gh pr diff \| git apply`, curl of the patch, a `docker://` step's `args`) | A new high OBAAF-GHA-002 (and OBAAF-GHA-012 in an agent job) (slice 2d.2c) | Build the pull request's code in a `pull_request` workflow, as the fix says |
| A checkout whose `ref` or `repository` comes from a step's or job's output, an input, a variable or an `env` name the file does not set, or a fetch command with a step's or job's output, in such a workflow | A new medium OBAAF-GHA-002, case `checkout-unresolved` or `fetch-unresolved` ("cannot tell"); in an agent job an outsider's event can start, OBAAF-GHA-012 too | If it is not the pull request's code, accept it with the reason; otherwise move the build to a `pull_request` workflow |
| A job a pull request starts, beside other triggers (`on: [pull_request, workflow_dispatch]`), whose checkout keeps the token | A new medium OBAAF-GHA-011 | Add `persist-credentials: false` |
| `allow-unsafe-pr-checkout` written as an expression (`${{ true }}`), an empty value or text other than `false`, `0` or `no` | A new high OBAAF-GHA-019 | Remove the input |
| An agent job on `pull_request_review` or `pull_request_review_comment` with the default checkout, or on `pull_request` with `ref: ${{ github.sha }}`, `${{ github.ref }}` or `${{ github.ref_name }}` | A new high OBAAF-GHA-012, case `merge-commit` | Check out the base branch for the instruction files, as the fix says |
| A job that runs `claude -p`, `gemini -p`, `codex exec`, `opencode run` or `copilot -p` by a path or quoted (`$HOME/.local/bin/claude -p`) | It is now an agent job, with the agent rules (OBAAF-GHA-003, 005, 011, 012, 020 and the rest) | Fix or accept the findings, or declare the job's lane |
| An accepted OBAAF-GHA-002, 011, 012 or 019 in a v0.2 baseline | The findings have new facts (what was read, the triggers, the `if:`, the credential and what the token can write, the value, and for "cannot tell" everything in the file the value can depend on), so the acceptance no longer names them | Accept them again. A v0.1 baseline from 0.3.0 still names them, and `obaaf baseline migrate` carries them over |
| A step that expands an outsider-written field OBAAF did not list (an edited title's old value, a review comment's `path` or `diff_hunk`, a commit's committer or file names, a gollum page's title, a discussion's answer, a fork's description, `workflow_run.head_repository` or `path`, a merge group's commit, a `check_suite` or `status` commit), or one in a script other than `run` (a `shell`, the egress action's `run` under any spelling of its path, an input of `azure/cli`, `azure/powershell` and the other actions under `script_inputs`), through another job's `outputs`, or through an `env:` written as one expression that reads the matrix or env | A new OBAAF-GHA-010 (slice 2d.2d) | Pass the value through `env` and quote it in the script, as the fix says |
| A step that expands a field in a reusable workflow (`workflow_call`), on `commit_comment`, `check_suite`, `check_run` or `status`, or a commit's text on `push`, `merge_group` or a `workflow_run` narrowed to pushes (also as `toJSON(github)` or a computed path) | OBAAF-GHA-010 is high where it was medium (slice 2d.2d) | The same fix |
| An accepted OBAAF-GHA-010 in a v0.2 baseline | The finding's facts are now every field the step reaches (`fields`, where it was the first one as `field`), the expressions that reach them and the job's triggers, so the acceptance no longer names it | Accept it again. A v0.1 baseline from 0.3.0 still names it, unless its severity changed (a v0.1 entry names the severity it was accepted at) |
| A job on a runner label shaped like a hosted one that GitHub does not name (`ubuntu-gpu`, `windows-builder`, `ubuntu-20.04`), which a pull request, an outside event or an agent can drive | A new medium OBAAF-GHA-013 ("cannot tell"); the label was taken for GitHub-hosted (slice 2d.2d) | Use a label GitHub names, or accept the finding with the runner's lifecycle as the reason |
| `runs-on: '<label>, self-hosted'`, `'Self-Hosted '` or `'self-hosted linux'` | OBAAF-GHA-013 is high, case `self-hosted`, where it was medium | Run the job on an ephemeral runner, as the fix says |
| A runtime selector that names `self-hosted` in any form but `head.repo.full_name == github.repository && <runner> \|\| '<hosted>'`, including `head.repo.fork && 'ubuntu-latest' \|\| 'self-hosted'`; or the recognised form on an event without a pull request, or in an agent job | OBAAF-GHA-013 is medium, case `other-labels`, where it was informational (slice 2d.2d) | Test `head.repo.full_name`, as above |
| An accepted OBAAF-GHA-013 whose labels come from a matrix, or whose case is `runtime-choice` | The sets the matrix gives, and the selector, are now facts, so the acceptance no longer names it | Accept it again |
| A release job (one that publishes, or uses a production environment) that only `pull_request`, `pull_request_review` or `pull_request_review_comment` can start | OBAAF-GHA-015 is medium, case `pull-request`, where it was high; with an environment named in plain text and another outside event, medium, case `environment` (slice 2d.2d) | Start release jobs only from pushes, tags, releases or dispatch, as the fix says |
| A job an outside event can start that publishes in a way the lists did not name (`gh release edit`, `gh api .../releases`, `git push --tags`, `aws <options> s3 cp`, a command continued on the next line or with its name quoted, `docker buildx build --push`, `pnpm -r publish`, `cargo +stable publish`, `uv publish`, `firebase deploy`, `vercel --prod`, `curl -T`, `createRelease(`, `scripts/release`, a `docker://` step, `pypa/gh-action-pypi-publish`, `js-devtools/npm-publish`, `goreleaser/goreleaser-action`, `rubygems/release-gem`), or that uses an environment named `live`, `prd`, `pypi`, `npm`, `crates`, `gh-pages`, `cd` or one a matrix gives | It is a release job: OBAAF-GHA-015, and the other release rules (OBAAF-GHA-006, 014, 016, 017) on any trigger | Fix or accept the findings |
| A job whose environment is named with a word that only holds the letters of a release word: `kitchen`, `switch`, `restore`, `keystore`, `datastore`, `firestore`, `reproducible`, `product` (not `production`) | It is no longer a release job, so the release rules no longer report it | Nothing |
| A job an outside event can start that has `packages: write`, a secret whose name says it publishes (`NPM_TOKEN`, `PYPI_...`, `DOCKERHUB_TOKEN` and the other `publishing_secret_patterns`), a step using `docker/build-push-action` or another `publishing_actions` entry, or an environment named by an input or a function | A new OBAAF-GHA-015, case `capability`, medium (low on pull request events only): the checker cannot tell whether it releases | If it does not release, accept it and say why |
| An accepted OBAAF-GHA-015 in a v0.2 baseline | Why the job is a release job, the steps that make it one and its environment are now facts, so the acceptance no longer names it | Accept it again. A v0.1 baseline still names it where its severity is unchanged; the cases now at medium (`pull-request`, `environment`) need accepting again |
| A step that runs `obaaf check --lanes` with an option `obaaf check` refuses (`--fail-on` with an unknown value, a missing `--baseline`, `--owner` without `--write-baseline`), or with `--write-baseline` or `--output` | Exit status 2 | Correct or drop the option |

`obaaf audit` is in no release, so nothing about it can change for someone on 0.3.0. If you run it from a commit after 0.3.0: it now applies rules and ends with status 1 on a finding at medium or above (`--fail-on never` gives the old status), and `--format json` prints a report with the snapshot under `snapshot`, where it printed the snapshot; with `--expected`, the comparison is under `drift` in that report, where it printed a document of its own, `obaaf-settings-drift/v0.1` ([the settings audit](settings-audit.md)).

The details of each are in the [changelog](../CHANGELOG.md), under "The lifecycle of a finding", "A lane declaration that does nothing is a finding", "Controls", "Egress control", "Which events can start a job", "Inputs in any case", "The first run says what it did not read", "What a job can reach: six rules attacked", "What a run checks out: four rules attacked", "Triggers, scripts and release jobs: three rules attacked" and "Files the checker could not read".

### What a script that reads the output will notice

- **The text report begins differently**: `Accepted risk: ...` and `Other findings: ...` come first. **It also ends differently**: the last line is `Checked by obaaf VERSION.`, and with no configuration file two lines before it say what an unconfigured run leaves out. The line `Baseline: N finding(s) accepted by the baseline, M new.` is unchanged.
- **`obaaf check --lanes` can end with 1 or 2**: 1 when `obaaf check` would report an error for a workflow or Jenkinsfile (it could not be read or parsed, an input is given twice, an expression is too deep to read), each an `error:` line on standard error, with the jobs of a file that could not be read or parsed left out of the list; 2 when the path has no workflow or Jenkinsfile, or is not there. A Jenkinsfile part of whose pipeline was not analyzed is a `note:` and does not change the status, as for `obaaf check`. It ended with 0 in every case before.
- **The `ignored:` lines** read `ignored: RULE path:line - accepted by OWNER until DATE: REASON`.
- **A path is printed in quotes** where it heads its findings, unless it is made of visible ASCII characters with no space.
- **The notes no longer list lane declarations that do nothing**; they are findings. In JSON they are in `findings` and no longer in `notes`.
- **JSON keeps every top-level field and every field of a finding.** New: `acceptedRisk` and `summary` before the findings; `state` on every finding, `kind` and `facts` where the rule gives them, `acceptance` where a baseline or ignore entry names the finding, and `controls` where it has any; `fixed`, when there are any, a list of findings cleared by controls the checker verified, which are no longer in `findings`. The entries under `baseline.stale` are the baseline's own entries, so with a converted baseline they have `owner`, `reason` and `expires`, and `kind` and `facts` where the finding had them, and no longer `fingerprint` or `message`; the `no longer found:` lines of the text report end differently for the same reason.
- **SARIF**: an accepted finding has a suppression, and its message says who accepted it. Errors and notes are notifications of the run.
- **`--write-baseline`** needs `--owner`, `--reason` and `--expires` for anything it newly accepts (exit status 2 without them), and does not write over a file that is not a baseline.

### One upgrade, start to finish

A repository with two workflows, a baseline written by 0.3.0 that accepts its four findings, and one job declared `OBAAF_LANE: agnet`. With 0.3.0 its gate, `obaaf check . --baseline .github/obaaf-baseline.json --fail-on low`, passes: "4 finding(s) accepted by the baseline, 0 new", and a note about the declaration. With the code on `main` the same command ends with status 1:

```text
Baseline: 0 finding(s) accepted by the baseline, 5 new.
  The baseline is in the old format (obaaf-baseline/v0.1). Its entries name no owner, reason or expiry date, so none of them accepts a finding. Convert it once, saying who accepts these findings, why and until when:
    obaaf baseline migrate .github/obaaf-baseline.json --owner OWNER --reason REASON --expires YYYY-MM-DD
```

Convert the baseline:

```bash
obaaf baseline migrate .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Inherited on adoption; tracked in issue 12" --expires 2027-03-31
```

It answers "4 finding(s) carried over" and "1 finding(s) were not in the old baseline and are not accepted by the new one". The gate still ends with status 1, now for one finding:

```text
    12  HIGH   OBAAF-CFG-001  Lane declaration that does nothing  [job triage]
```

Correct `agnet` to `agent`. The job is an agent job now, and the gate ends with status 1 for three findings nobody had seen: `OBAAF-GHA-003` (the agent job can write), `OBAAF-GHA-005` (a secret in an agent job) and `OBAAF-GHA-020` (no egress restriction). In a real upgrade you would fix what can be fixed first. Here nothing is fixed and all three are accepted, to show what the command does:

```bash
obaaf check . --write-baseline .github/obaaf-baseline.json \
  --owner @my-org/build --reason "Agent job found on upgrade; its controls are tracked in issue 31" --expires 2027-01-31
```

"3 finding(s) newly accepted by @my-org/build until 2027-01-31, 4 kept with the owner, reason and expiry date they had." The gate passes, and its first line says what that pass rests on: "Accepted risk: 7 finding(s) are accepted and do not fail the check (3 high, 2 medium, 2 low)".

`tests/test_adoption_path.py` runs this sequence.

### The first adopter

Expectrail, which is the author's own project, runs OBAAF pinned to the commit `d014b63` and sees none of this until it moves its pin. On a copy of its files at `776ddd3`, with its own command, the code on `main` ends with status 1 and 40 findings that count: the 38 its old-format baseline covers, one whose `ignore` entry has no owner, and one lane declaration that does nothing. When it moves its pin it has three things to do, each in a pull request its maintainer makes, because they touch its baseline or its configuration:

1. `obaaf baseline migrate .github/obaaf-baseline.json --owner ... --reason ... --expires ...`.
2. `owner:` on the one entry under `ignore:` in `.github/obaaf.yml`.
3. Its entry `byo-smoke.yml#byo-smoke: probe` under `lanes:`. `probe` is not a lane of OBAAF's. It is a label Expectrail's own audit script reads. Either accept the finding in the baseline with that as the reason, or declare the job `trusted` and keep the list of probes in the script.

After the first step alone, on the same copy: 38 accepted, 2 new. No other adopter's upgrade has been observed.
