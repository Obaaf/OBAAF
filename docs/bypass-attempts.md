# Bypass attempts, rule by rule

This page records every attempt to get past OBAAF's security rules: who tried, what they tried, what got through, and what changed. It is the record plan slice 2d.2 asks for ("every rule has a recorded attempt"). A rule's description in the [rule catalogue](../spec/checker-rules.md) says what the rule does not follow; this page says how that was found.

How an attempt is made. A reviewer that did not write the rule (an Opus 5.5 sub-agent, given the code and the rule's definition, not the author's opinion of it) writes small workflows meant to get a secret, a permission or a signing key past the rule, and runs the checker on each. A way past counts only if GitHub would run the workflow and the job would really get what the rule is about, while OBAAF reports nothing, a weaker case or severity than the plain spelling gets, or facts such that an acceptance of a harmless case also covers the risky one. Each way past becomes a test, and the fix is to the class (read it properly, read it the widest way, or fail the check), not to the one spelling.

Where a way past depends on what GitHub does and the documentation does not say, the record says "not verified". The fix is chosen so that it is right either way.

## Tranches

| Tranche | Rules | Date | Tests |
| --- | --- | --- | --- |
| 2d.1 | Expressions: how secrets and outsider-written fields are found in `${{ }}` | 2026-11-11 | `tests/test_expression_reader.py` |
| 2d.2a | Lane assignment: which jobs are agent, release or effect jobs | 2026-11-11 | `tests/test_lane_assignment.py` |
| 2d.7 | Runner labels written as `matrix.x \|\| 'label'` | 2026-11-14 | `tests/test_matrix_runner_labels.py` |
| 2d.2b | What a job can reach: OBAAF-GHA-001, 003, 004, 005, 018, 024 | 2026-11-14 | `tests/test_reach_bypasses.py` |
| 2d.2c | What a run checks out: OBAAF-GHA-002, 011, 012, 019 | 2026-11-14 | `tests/test_checkout_bypasses.py` |
| **2d.2d** | **Triggers, scripts and release jobs: OBAAF-GHA-010, 013, 015** | **2026-11-14** | `tests/test_trigger_script_release_bypasses.py` |
| **2d.2e** | **Release and effect jobs: OBAAF-GHA-006, 007, 014, 016, 017, 021, 022** | **2026-11-14** | `tests/test_release_effect_bypasses.py` |
| **2d.2f** | **Pins, egress and declarations: OBAAF-GHA-008, 009, 020, 023, OBAAF-CFG-001** | **2026-11-15** | `tests/test_pins_egress_declaration_bypasses.py` |
| **2d.2g** | **The settings rules: OBAAF-SET-001 to OBAAF-SET-015** | **2026-11-15** | `tests/test_settings_bypasses.py` |
| **2d.2h** | **The repository and instruction-file rules: OBAAF-REPO-001, OBAAF-REPO-002, OBAAF-INS-001** | **2026-11-15** | `tests/test_repo_instruction_bypasses.py` |
| **2d.2i** | **Jenkins files and credentials: which Jenkinsfiles are read, OBAAF-JEN-001, 013, 014, 015** | **2026-11-15** | `tests/test_jenkins_files_credentials.py` |
| **2d.2k** | **Pipeline code and pins: OBAAF-JEN-004, 008** | **2026-11-17** | `tests/test_jenkins_code_pins.py` |
| **2d.2j** | **Agent stages and workspaces: OBAAF-JEN-002, 003, 006, 007** ([below](#2d2j-agent-stages-and-workspaces)) | **2026-11-17, 2026-11-20** | `tests/test_jenkins_workspaces.py` |
| **2d.2l** | **Release approvals: OBAAF-JEN-005** ([below](#2d2l-release-approvals)) | **2026-11-21** | `tests/test_jenkins_approvals.py` |
| **2d.2** | **Untrusted text in a command: OBAAF-JEN-009** ([below](#2d2-untrusted-text-in-a-command)) | **2026-11-22** | `tests/test_jenkins_injection.py` |

The rest of this page is tranches 2d.2b, [2d.2c](#2d2c-what-a-run-checks-out), [2d.2d](#2d2d-triggers-scripts-and-release-jobs), [2d.2e](#2d2e-release-and-effect-jobs), [2d.2f](#2d2f-pins-egress-and-declarations), [2d.2g](#2d2g-the-settings-rules), [2d.2h](#2d2h-the-repository-and-instruction-file-rules), [2d.2i](#2d2i-jenkins-files-and-credentials), [2d.2k](#2d2k-pipeline-code-and-pins) and [2d.2j](#2d2j-agent-stages-and-workspaces).

## 2d.2b: what a job can reach

Run `knot`, 2026-11-14. Two reviewers worked in parallel on a copy of `flagship` at `0bd97f4`: one on OBAAF-GHA-005, 018 and 024 (44 test workflows), one on OBAAF-GHA-001, 003 and 004 (about 70). A third reviewer then attacked the fixes. Expectrail at `5433b5e` (read-only copy) and this repository were checked with the old and new code: the only differences are the intended ones.

GitHub's documentation was read for: reusable workflows and the token a called workflow gets ("The `GITHUB_TOKEN` permissions passed from the caller workflow can be only downgraded", [Reusing workflow configurations](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations)); environments created on first use ("will create an environment with the referenced name ... will not have any protection rules or secrets configured", [Managing environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)); `deployment: false` ("The job has full access to environment secrets and variables"; required reviewers and wait timers still apply; branch policies are not mentioned, [Control deployments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/control-deployments)). Not verified: whether GitHub accepts permission scopes, levels and event names in another case, and what it does with an empty or numeric environment name.

### Shared by all six: how secrets and permissions are read

**Held.** The secret reader (`secret_names`, from 2d.1) found every spelling tried: workflow-level `env` read later as `$X`; YAML anchors within and across jobs; a workflow written entirely in flow mappings; `services.*.env` and `container.credentials`; `SECRETS.x`, `secrets [ 'X' ]`, `(secrets).X`, `(a || secrets).X`, `fromJSON(toJSON(secrets)).X`, `secrets[join(...)]`, `secrets.*`, a double-quoted index; `}}` and `${{` inside strings; `\x24{{` and `${{` YAML escapes; an expression used as an `env` key. YAML the reader refuses (a tab before `#`, two documents, duplicate keys) fails the check.

**Got through, fixed.**

- *Permissions spellings.* `permissions: Write-All`, `permissions: write`, an expression, `contents: WRITE`, `contents: " write"`, `Contents: write`, `ID-TOKEN: write`, `permissions: " read-all"`: each was read as no permissions (or as read-all), with no word. GitHub probably rejects most of them (not verified). Now each is an error for the file and is read as the widest grant.
- *`permissions:` with no value* at job level was read as `{}` and hid a workflow-level `write-all`. Now it is taken as not written.
- *Event names.* `on: Pull_Request_Target` and `on: [{pull_request_target: {}}]` were dropped without a word. Now an event not written in lower-case letters and underscores is an error for the file.
- *Numbers of thousands of digits* in `on:`, `permissions:` or `environment:` ended the check in a traceback (status 1, no report). Now they are read as text or are an error for the file.

### OBAAF-GHA-001 Secret available to a workflow started by untrusted input

**Held.** `on:` as a string, list, flow mapping, quoted key, anchor or alias; narrowing by `if:` only for plain comparisons of `github.event_name` (`contains`, `startsWith`, `format`, `fromJSON` and negations narrow nothing); `needs` chains, cycles and missing jobs; `workflow_run` after a push versus after a pull request; secrets through `env`, a reusable call's `secrets:`, `with:`, `secrets: inherit`, `toJSON(secrets)`.

**Got through, fixed.**

- *Any `environment:` lowered the finding from high to medium*, including `tmp-${{ github.run_id }}` (created on first use with no reviewers) and `${{ github.event.pull_request.head.ref }}` (the pull request's author picks it). Now only a name written in plain text lowers it.
- *The environment was not part of the finding*: an acceptance for the job in `sandbox` covered it in `production`. Now it is a fact.

**Not fixed, stated as limits.** Events an app can raise for an outsider's change (`check_run`, `check_suite`, `status`, `deployment`, `deployment_status`) and `merge_group` are not treated as untrusted; whether an outsider can raise them depends on the apps installed, which OBAAF does not read. A workflow with only `workflow_call` is never reported; its caller is, when checked in the same run.

### OBAAF-GHA-003 Agent job can write

**Held.** `write-all` quoted and unquoted; quoted keys and values; anchors, aliases, flow mappings; job-level `read-all` or `{}` over workflow-level `write-all`; no permissions anywhere (reported as undeclared).

**Got through, fixed.**

- *A called workflow that declares nothing* holds its caller's token, but was reported as "undeclared", the same facts as a job whose repository default is read-only. Now it is the case `inherited`.
- The permissions spellings above.

**Not fixed, stated as limits.** The repository's default token permissions are not read. An agent wrapped in a local composite action (`uses: ./.github/actions/x`) did not make the job an agent job. Slice 2d.4a reads the action's steps for an agent, and names in a note or an error what it cannot read through; its own reviewer's ways past its first version are tests in `tests/test_local_composite_actions.py`, and the limits it keeps are in D-081.

### OBAAF-GHA-004 Agent job can request cloud credentials

**Got through, fixed.**

- *A called workflow that declares nothing* got no finding, though its caller can grant `id-token: write`. Now it is reported, case `inherited`.
- *`ID-TOKEN: write`* was a write scope to OBAAF-GHA-003 and nothing to OBAAF-GHA-004. Now a scope in another case counts as that scope (and the file fails the check).

**Not fixed, stated as a limit.** The checker takes the repository default never to include `id-token: write`.

### OBAAF-GHA-005 Secret available to an agent job

**Got through, fixed.**

- *The environment was not part of the finding.* An acceptance written for the agent job in `sandbox` covered it in `production`, where the same reference reads production's secret (an environment's secret takes precedence over a repository secret of the same name). Now the environment is a fact.

**Not fixed, stated as limits.** In a local reusable agent workflow, the finding names the secret parameter (`MODEL_KEY`), not the secret the caller maps onto it (`PROD_DEPLOY_KEY`), and the calling job is not an agent job, so changing the mapping raises nothing: slice 2d.4. Slice 2d.4b1 makes what each caller of the repository passes, followed to the first caller, a fact of OBAAF-GHA-005 and 001 on the called job (D-082); the calling job is still not an agent job. Secrets that reach the agent through artifacts, caches, files or another job's outputs are not followed. `Secrets: inherit` with a capital S is not read (GitHub very probably rejects the key; not verified).

### OBAAF-GHA-018 Signing key available to build steps

**Held.** `cosign_private_key`, `SECRETS['Gpg_Private_Key']`, `${{secrets.ANDROID_KEYSTORE}}`, `\x24{{ }}`, `format('}}{0}', secrets.DEVELOPER_ID_CERT)`; a signing secret in workflow `env` or `container.credentials`; a caller passing `SIGNING_KEY` under another name; one-line `cosign sign --key`, `gpg --import`, `signtool /f`, `jarsigner -keystore`, `apksigner --ks`.

**Got through, fixed.**

- *A job that can read every secret* (`secrets[format('{0}_KEY','SIGNING')]`, `secrets[matrix.key]`, `toJSON(secrets)`, `secrets: inherit`) got no finding: the rule dropped them. Now case `any-secret`.
- *Continued lines*: `cosign sign \` on two lines, and PowerShell's backtick and cmd's caret (found by the third reviewer). Now matched both as written and joined, so joining never hides what one line shows (the second pass found that matching only the joined text hid a file-key `cosign sign` followed on the joined line by a KMS one).
- *Commands, actions and names the data missed*: `/usr/bin/gpg`, `gpg2`, `gpg.exe`, options before `--import` (also a quoted value with spaces, though `--passphrase="a b"` is still missed), `.P12`, `Import-PfxCertificate`, `crazy-max/ghaction-import-gpg`, `apple-actions/import-codesign-certs`; `CSC_LINK`, `MACOS_CERTIFICATE`, `WINDOWS_CERTIFICATE`, `APPLE_CERTIFICATE`, `KEY_STORE`. Added. `gpg --import-ownertrust` and a `gpg --version` line followed by another command's `--import` are no longer taken for a key import.
- *The environment was not part of a secrets finding.* Now it is a fact.

**Not fixed, stated as limits.** Signing material is recognised by name and command patterns, which can always be missed (a key stored as `BLOB`, a signing tool not in the data). A step reported for its command is identified by its name, not its text, so an accepted harmless step (`gpg --import public.asc`) keeps its acceptance if it later imports a private key and signs; putting a step's text in its identity would make every edit a new finding, and is left for a decision on identity.

### OBAAF-GHA-024 Protected secret used outside its environment

**Held.** All 13 expression spellings were reported, with "it can take every secret" where it applies; `RELEASE` and `{name: Release}` match `release`; `" release"` with a space is reported (stricter, not looser); a protected secret passed by name to a reusable workflow is reported. A merge key that supplies `environment:` is read by this YAML reader and, as far as is known, not by GitHub's (not verified).

**Got through, fixed.**

- *`secrets: inherit` was silent* where passing the secret by name was high; both pass the repository or organization copy wherever one exists. Now reported alike.
- *Two entries for one name in different case* (`PYPI_TOKEN: release`, `pypi_token: staging`): the second replaced the first. Now a configuration error.
- *Names equal only under Unicode case folding* (`Kube-prod` with the Kelvin sign, `straße` and `strasse`, `releaſe`) were taken for the protected environment. Now compared by the case of A to Z only; the others are unconfirmed (medium), as the OBAAF-GHA-005 control already did.
- *An environment that is not a name.* `environment: 010` matched a protected `"8"`; a blank name counted as declared. Now a number or true or false is unconfirmed only where it could be the wanted name, a blank or missing name is no environment (high), and a list or mapping is not a name (high). The third reviewer found that the first version of this fix lowered `environment: 1` from high to medium, and its second pass that `environment: 1` was still medium against a protected `"8"`; now the value is unconfirmed only where the wanted name is one of the names it may be (`010` may be `8`, `10` or `010`), read from the text as written. Text this reader keeps as text that a YAML 1.2 reader takes for a number (`0o10`, `1e3`) is treated the same way unless quoted. Where the text as written cannot be found (an environment that comes through a merge key, a job whose id YAML reads as true, false or a number), a number is unconfirmed against any wanted name that looks like a number, and plain `0o10` is read as text: the third pass found both, and GitHub very probably refuses merge keys (not verified).
- *Fact `via`* said only yes or no, so an acceptance of a caller passing `toJSON(secrets)` covered one with `secrets: inherit` (found by the third reviewer). Now it says which.

**Not fixed, stated as limits.** An environment named by an expression is never evaluated, even `${{ 'staging' }}` or a literal matrix, and stays medium. `environment: {name: release, deployment: false}` counts as `release`: GitHub says the job gets the environment's secrets and its reviewers still apply, and does not say whether its branch policy does. The checker never sees where a secret is stored or an environment's branch rule; `obaaf audit` reads those.

## 2d.2c: what a run checks out

Run `skua`, 2026-11-14. One reviewer (an Opus 5.5 sub-agent that did not write the rules) worked on a copy of `flagship` at `01d7005` and wrote 106 workflows against OBAAF-GHA-002, 011, 012 and 019: **57 got through**, in 16 classes; 3 were not counted and 1 was out of the rules' scope. A second reviewer attacked OBAAF-GHA-010, 013 and 015 at the same time; those three rules are a later tranche (see [the plan](flagship.md)), and its results are published with their fixes. The new code was then run on every attempt, on this repository, the templates, the risky fixtures and Expectrail at `9dc79d5` (read-only copy) with its baseline, against the old code: the only differences are the intended ones (below).

The reviewer read actions/checkout's own reading of `persist-credentials` in its v3.5.0 source, `(core.getInput('persist-credentials') || 'false').toUpperCase() === 'TRUE'`, and its `action.yml` ("Otherwise, uses the default branch" for a `repository` with no `ref`), through a mirror; the github.com sources could not be reached from the session, so later versions were not read. actions/checkout v7 (and its backports from July 2026) refuses a fork's head on `pull_request_target` and on `workflow_run` after a pull request, however the ref is spelled ([changelog](https://github.blog/changelog/2026-06-18-safer-pull_request_target-defaults-for-github-actions-checkout)); it does nothing for `issue_comment`, for fetch commands, or for a checkout pinned to a commit from before the change, which OBAAF-GHA-008 asks for. So the rules stay needed. Not verified: that GitHub reads context and property names without regard to case (OBAAF's expression reader has assumed it since 2d.1), how v7 parses `allow-unsafe-pr-checkout`, whether the runner matches input names without regard to case, and that `workflow_run.pull_requests` is empty for a fork's pull request.

### OBAAF-GHA-002 Untrusted code checked out in a privileged workflow

**Held.** The plain head SHA; spaces inside `${{ }}`; `refs/pull/${{ github.event.number }}/head`; `workflow_run.head_sha` and `head_repository.full_name`; `merge_commit_sha`; `Actions/Checkout`; inputs through an anchor, a flow mapping with quoted keys and `Ref:`, a block scalar; `gh pr checkout`; `git fetch refs/pull/...` then `git switch`; `on:` as a flow list with an anchor; `if:` with `contains()`, a negation or `github.event.action` (none narrows the trigger); `pull_request_review`; a `needs` chain with `!cancelled()`.

**Got through, fixed.** `ref` and `repository` were matched as text against a pattern of plain spellings, and scripts against one spelling per command.

- *The ref in another spelling:* `head['sha']`, `GitHub.Event.Pull_Request.Head.SHA`, `format('refs/{0}/{1}/merge', 'pull', github.event.number)`, the same with `issue.number` on `issue_comment`, `join(fromJSON(...))`, `fromJSON(toJSON(github.event.pull_request.head)).sha`, and the SHA given through the job's or the workflow's `env`. Now both inputs are read with the expression reader and `env` is followed to where it is set.
- *The fork's repository with no `ref`* (`repository: ${{ github.event.pull_request.head.repo.full_name }}`), which checks out the fork's default branch. Now the head repository is the pull request's code.
- *A ref computed while the job runs* (`steps.pr.outputs.sha` after `gh pr view --json headRefOid`, or `needs.resolve.outputs.sha`: the usual `issue_comment` pattern). Now any value the checker cannot read to a value is case `checkout-unresolved`, medium, "cannot tell".
- *Fetch commands:* `git fetch origin <head SHA>` then `git checkout FETCH_HEAD`; `git -c x=y checkout`; `git -C . fetch`; `git pull`; `git clone` of the head's clone URL; a line continuation; `gh pr diff | git apply`; `curl` of the patch; `/usr/bin/gh` or `"gh"`; `gh pr --repo X checkout`; `gh api .../tarball/<sha>`; `git reset --hard <sha>`; `exec.exec('git', ['fetch', ...])` in github-script; `subprocess.run(['git', 'fetch', ...])` with `shell: python`; `git fetch` in a `docker://` step's `args`. Now a script is split as a shell splits it, command by command (continued lines joined; a pipeline is one command; a quoted script given to `sh -c` read again): a command that brings code in, and something in the same command that names the pull request's code, is case `fetch`, high. What names it: an expression or `env` value that does, a field read from the event file (`.pull_request.head.sha`), from `gh pr view` (`headRefOid`) or `gh pr diff`, `GITHUB_HEAD_REF`, `refs/pull/` or `pull/N/head`, the pull request's number, a variable set earlier in the step from any of these, or a file an earlier command wrote from them. Such a command with a step's or job's output is case `fetch-unresolved`, medium.
- *Identity:* a checkout guarded by `if: github.event.pull_request.head.repo.full_name == github.repository` and the same checkout unguarded were one finding, so a baseline entry for the first accepted the second (checked with `--write-baseline` and `--baseline`). Now the job's and step's `if:` and what was read are facts.

**Not counted.** `workflow_run.pull_requests[0].head.sha` (said to be empty for a fork's pull request; it is now reported anyway, as a pull request's code); `with:` written as one expression (GitHub very probably refuses it; it is now "cannot tell"); `gh pr --repo X checkout` before the fix was judged unverified (it is now reported).

**Review of the fixes.** A second reviewer (a fresh Opus 5.5 sub-agent) attacked the first version of the fixes and found nine blocking faults, all fixed and each a test (`FirstReviewTest`):

- *Slowness.* The pattern for git's options backtracked: a run of `=` after `git --a` took 97 s on a 100 KB line. Eight env values that each read all eight took 83 s, because each name was read again on every path. An unclosed `${{` repeated took seconds. Now commands are found by splitting the line into words (Python's `shlex`, with a rough split for a line it refuses), each env name is read once, and expressions are found in one pass: each of these inputs takes under a second.
- *Option values in quotes* (`git -C "$GITHUB_WORKSPACE" fetch`, `git -c 'user.name=x' fetch`, `--git-dir="$D/.git"`, `gh pr -R "o/r" checkout`) were missed. The word split reads them.
- *Fetched, then applied on another line*: `gh pr diff "$N" > pr.diff` then `git apply pr.diff`; `curl` of the patch address to a file then `git am`; `| patch -p1`; a github-script `getContent` or `pulls.get` call written over several lines. Now a file written from the pull request's code is followed, `patch` is a command that brings code in, a download of the patch or diff address counts wherever the address comes from, and a github-script script is read whole.
- *False positives the first version added* on ordinary `pull_request_target` workflows: a branch created with the pull request's number in its name (`git switch -c "pr-$N" main`); an env name read as a word anywhere (`BRANCH` in `--branch`, `PR` in `pr-labels`, `N` in `-n`); a comment or a second command on the same line (`git checkout main # PR $N`, `git fetch origin main && gh pr comment "$N"`); `git merge-base` and `git show-ref` taken for `merge` and `show`. Now a variable counts only where the script reads it (`$NAME`, `${NAME}`, `$env:NAME`, `process.env.NAME` and the like), only the same command counts, a word that begins with `#` ends it, subcommands are whole words, and the name of a branch being created is not read.
- *Identity of "cannot tell".* Two checkouts of `${{ steps.pr.outputs.sha }}`, where the step echoes the base commit in one and the head commit in the other, were one finding, so accepting the harmless one (as the finding invites) covered the other. Now what the value can depend on is part of the finding (see the second pass below).
- *A token or SSH key given to checkout* was reported as "the job token", with the same facts as a read-only job. Now the credential is named and is a fact.
- *A traceback* on `allow-unsafe-pr-checkout` set to a number of thousands of digits (older than this slice).
- *Claims the code did not meet*: only one assignment per line was followed (now `read`, `for NAME in`, `typeset`, several on one line); a bash line ending in a backquote was joined to the next as if it were PowerShell (now only for a PowerShell step); a step's `REF: ${{ env.REF }}` was read as itself, not the job's `REF` (now each scope reads the ones outside it); `${{ 0 }}` counted as opting in (now a constant).

A second pass on the revised code found seven more blocking faults in the word-based reader, all fixed and each a test (`SecondReviewTest`): commands written as strings in a script language (`exec.exec(\`git fetch origin ${sha}\`)`, `os.system(f"git checkout {sha}")`, `execFileSync('git', [...])`) and a Python variable read by name were missed, which the first version had caught; a quoted word that began with `#` (`echo "## Testing PR #$N" && gh pr checkout "$N"`) ended the command, because quotes were removed before the test; `patch` counted anywhere in a command, so `gh api --method PATCH .../pulls/N` was reported high, and a github-script script that read the default branch's contents and then set a status on the head commit, or counted the lines of the diff, was reported high; a NUL character in a script and a producing step with keys of mixed types ended the check in a traceback; following written files took 40 s for 1,000 of them; and the "cannot tell" identity covered only the producing step, not a value passed through `GITHUB_ENV`, a second hop, the job's env or a matrix. Now comments are found before quotes are removed; a command's name counts only where a command starts; a script in another language is split roughly with git counted anywhere and its variables by name; a github-script REST call is read from its own arguments, and a diff counts only when the script applies it; NULs are replaced before splitting; facts are written with keys as text; files and variables are looked up by word; and a "cannot tell" finding's identity is everything in the file the value can depend on (the workflow's and job's env, the job's strategy, its earlier steps and the jobs it needs). The second pass also confirmed the first pass's fixes, including every adversarial input under a second.

A third pass found four more, all fixed and each a test (`ThirdReviewTest`): the rule that a command's name counts only where a command starts missed `timeout 300 git fetch`, `/usr/bin/env git`, `sudo -u runner git`, a command in backquotes and `xargs -r git fetch`, which the base caught (now the commands that run the next one are skipped with their options, by base name, and a backquote or `$(` starts a command); in a script language only git was looked for, so `gh pr checkout` in PowerShell or Python, `Invoke-WebRequest` of the diff address and github-script's `exec.exec('gh', ...)` were missed (now gh and downloads count there too; `patch` does not, because it is a word of HTTP); a github-script call was read before the script's variables, so `getContent({ ..., ref })` with `const ref = ...head.sha` was missed (now the calls are read after, and a name given to the call is read where the script defines it); and reading every call scanned to the end of the script for each, 19 s for 4,000 unclosed calls (now each scan stops at the next call). It also noted that a "cannot tell" acceptance now reopens whenever an earlier step of the job changes, which is safe and can be noisy.

A fourth pass found that `flock FILE git`, `retry 3 git`, `time -p git`, a `case` branch (`pr) git fetch ...`) and `|&` still hid a following command; now each is read, and `docker exec CONTAINER git ...` too (`FirstReviewTest`, `SecondReviewTest` and `ThirdReviewTest` hold every case the four passes found). Its last check found one rare false positive left: the `)` that closes an unquoted `$(...)` starts a command, so `echo $(date) git fetch origin "$H"` is reported.

Of its non-blocking points, these were fixed too: OBAAF-GHA-012 has the `if:` as a fact; OBAAF-GHA-019 has the triggers; the old message for the merge-commit case is kept only where 0.3.0 reported it (on `pull_request`), so `obaaf baseline migrate` cannot carry a 0.3.0 entry over to a review-event finding 0.3.0 never made; `github.event.after`, a review's and a review comment's `commit_id` and the head's owner are the head; the base repository's owner, clone address and label, and `workflow_run.repository`, are the base; and an agent CLI name after a path is now matched only for the CLIs with a prompt flag or subcommand (`claude -p`, `codex exec` and the like), because `cd packages/cline` and `rm -rf /tmp/aider` made agent jobs. Left as limits: the job's `environment` is not a fact of OBAAF-GHA-002; what a fetch is used for afterwards is not either; a literal matrix value is "cannot tell"; OBAAF-GHA-012 does not see the merge commit fetched by a script (`git fetch origin "$GITHUB_REF"`) or `github.workflow_sha`; shell functions, arrays, a variable set by a `while read` loop fed from its end, `git` aliases, `hub`, `degit` and `svn` are not followed; text in a comment a bot posts that shows a fetch command, and the pull request's number in a listed command's other arguments (`git clone ... "site-pr-$N"`), are still reported.

**Not fixed, stated as limits.** A local composite action given the head SHA (`uses: ./.github/actions/checkout-pr`), and a reusable workflow called from a `pull_request_target` workflow that checks out `github.event.pull_request.head.sha` or `inputs.ref`: the called workflow is read with its own trigger, `workflow_call`, and the caller has no steps. Both belong to slice 2d.4 (local reusable workflows and composite actions) and are in its entry. Since slice 2d.4b1 a called workflow's jobs get the events of the jobs of the repository that call it, so the head checkout is OBAAF-GHA-002 and `inputs.ref` was "cannot tell" at medium (D-082); since slice 2d.4b3a what each caller of the repository hands the input is read in its place, so `inputs.ref` given the head is OBAAF-GHA-002 high (D-084). Since slice 2d.4b2 the local composite action's steps are read as the job's with the head SHA it is given put in, so its checkout is OBAAF-GHA-002, named `./.github/actions/checkout-pr: actions/checkout@...` (D-083). Values passed between steps through `GITHUB_ENV` or files are not followed. A line that names the pull request's code but runs a command the list does not name is not reported: reporting every use of a pull request's number would report every bot that comments.

### OBAAF-GHA-019 Unsafe pull-request checkout explicitly allowed

**Held.** `true`, `True`, `"TRUE"`, `' true '`, `Allow-Unsafe-PR-Checkout:`, a merge-key anchor, a block scalar.

**Got through, fixed.** `${{ true }}`, `${{ 'true' }}`, `${{ github.event_name == 'pull_request_target' }}`, `${{ env.UNSAFE }}`, `${{ format('{0}', true) }}`, and `${{ true }}` beside `ref: ...head['sha']` on actions/checkout v7.0.1, where OBAAF reported nothing at all. The rule tested the text for `true`; GitHub hands the action what the expression evaluates to. Now anything but a plainly false value counts (`false`, `0`, `no`, or a constant expression of one), and the value is a fact.

### OBAAF-GHA-011 Checkout leaves the job token on disk

**Held.** The default; `on: [pull_request, push]`; `False`, `'false '`, `no`, `0` (not reported, which is right); an expression that evaluates true; `TRUE`; an empty value; `Persist-Credentials: false` (not reported: input names are read without regard to case); a second checkout; a `token:` input; an agent recognised from its install line.

**Got through, fixed.**

- *A job a pull request starts, with another trigger beside it* (`on: [pull_request, workflow_dispatch]`, or with `schedule`): the rule applied to jobs in the untrusted lane, which needs every trigger to be a pull request's. Now any job an outsider's event can start is covered.
- *Identity:* a read-only `pull_request` job and a `pull_request_target` job that can write were the same finding (no facts). Now the triggers, whether the job runs an agent and what the token can write are facts.
- *An agent run by its path* (`$HOME/.local/bin/claude -p`) did not make an agent job, so GHA-011 and GHA-012 did not apply. Now a path, a quote or a backquote may come before an agent CLI's name, and a quote after it (lane assignment, in `data/detection.yaml`).

**False positives fixed.** `persist-credentials: ${{ false }}`, `${{ 'false' }}` and `off` were reported; actions/checkout keeps the token only for `true`. Now a written value other than `true` keeps nothing, and a constant expression is evaluated.

**Found by the review of the fixes.** A personal token (`token: ${{ secrets.ADMIN_PAT }}`) or an SSH key kept by checkout was reported as the job token, with the facts of a read-only job. Now the credential is named and is a fact.

**Out of scope, stated as limits.** Credentials kept by `gh auth setup-git` or a `git config` a script writes: the rule is about actions/checkout. Called workflows (2d.4).

### OBAAF-GHA-012 Agent reads instructions from the change under review

**Held.** `ref: head.sha` on `pull_request`; a sparse checkout of the instruction files from the head; `workflow_run.head_sha`; the default checkout on `pull_request`; `gh pr checkout` on `issue_comment`.

**Got through, fixed.**

- *`ref: ${{ head.sha || base.sha }}`*: any `ref` whose text held the word `base` was skipped. Now a value that names the head is the head, whatever else it names.
- *`ref: ${{ github.sha }}` or `${{ github.ref }}` on `pull_request`*, both the merge commit, and *the default checkout on `pull_request_review` and `pull_request_review_comment`*, whose ref is the merge commit too: the merge-commit case needed `pull_request` and no `ref`. Now it covers those three events, and a `ref` that is only `github.sha`, `github.ref` or `github.ref_name`.
- *`repository:` the head repository*, *the head from a step's output on `issue_comment`*, upper case, index syntax, `format`, `env`, and *`git fetch <sha>` then `git checkout FETCH_HEAD`*: as for OBAAF-GHA-002. A value the checker cannot read is case `unresolved` (medium) where an outsider's event can start the job; on `push` it is not reported.
- *Instruction files fetched one by one*: `git show <head>:CLAUDE.md > CLAUDE.md` and `gh api .../contents/CLAUDE.md?ref=<head>`. Now reported as `fetch`.
- *Identity:* the same checkout on `pull_request` (a fork's run gets no secrets) and on `pull_request_target` were one finding. Now the triggers are a fact.

**Not fixed, stated as limits.** What the agent itself fetches while it runs; values passed between steps; other checkout actions; called workflows and composite actions (2d.4).

### What changed for adopters

Every finding of OBAAF-GHA-002, 011, 012 and 019 has new facts, so a v0.2 baseline entry for one of them, written before this change, no longer accepts it: it becomes new and needs accepting again (the upgrade note says so). A v0.1 baseline (0.3.0) still names these findings: each carries the message 0.3.0 wrote for it, and `obaaf baseline migrate` carries such an entry over with the new facts. On this repository, the newly covered `pull_request` job in the escape tests is accepted by an `ignore` entry in `.github/obaaf.yml` (owner `@seanudeke`, until 2027-05-14), because the kept token is the fixture for the egress action's refusal test. On Expectrail at `9dc79d5`, one finding is new: `expectrail-comment.yml`, job `judge`, checks out `${{ steps.start.outputs.base }}` on `workflow_run` after a pull request, which the checker cannot read (medium, "cannot tell"); Expectrail pins an older OBAAF commit, so its gate does not change until it upgrades.

**False positives seen and not fixed** (ordinary bugs, for later): `pull_request_review` and `pull_request_review_comment` count as privileged for OBAAF-GHA-001 and 002, though GitHub gives a fork's run on them a read-only token and no secrets; and a job that calls a reusable workflow gets OBAAF-GHA-013 "runs on no labels" (fixed in 2d.2d).

## 2d.2d: triggers, scripts and release jobs

Run `ruff`, 2026-11-14, from the classes a reviewer in run `skua` found (115 attempts, 38 ways past, 11 of them under limits the rules stated; the plan records only the classes, under `SECURITY.md`). The run fixed those classes first, on a copy of `flagship` at `3587b2a`, and then two Opus 5.5 reviewers that did not write the code attacked the result in parallel: one OBAAF-GHA-010 (85 attempts), one OBAAF-GHA-013 and 015 (64). Their ways past were then fixed, and every attempt was run again; the last column below is that run. Expectrail at `cb1fc85` (read-only copy, `fresh-*` left out unread) and this repository were checked with the old and new code.

GitHub's documentation could not be read from the session (the fetch was not approved in time), so where a way past depends on what GitHub does, the table says "not verified", and the fix is chosen to be right either way. What the runner reference says about labels was written from what was known on 2026-11-14; a label it lacks is "cannot tell", never a missed self-hosted runner.

### OBAAF-GHA-010 Untrusted event text expanded inside a script

**Got through, now fixed.** Fields a person without write access writes that were not listed (an edited title's old value, a transferred issue or discussion, a review comment's `path` and `diff_hunk`, a commit's committer and file lists, gollum titles, a discussion's answer, a fork's description, `workflow_run.head_repository`, `path` and pull request branches, a merge group's commit, `check_suite`, `check_run` and `status` commits); scripts other than `run` (a `shell`, `defaults.run.shell`, the egress action's `run` under another spelling of its path, `azure/cli`'s `inlineScript`, which the first round of fixes looked up in the wrong case); a reusable workflow, `commit_comment` and the check events at medium; a commit's text on push at medium when written as `toJSON(github)`, `toJSON(github.event.head_commit)` or a computed path, or on a `workflow_run` narrowed to pushes; facts that held only the first field, so an env value, matrix or output holding two showed one; job outputs and an `env:` written as one expression (the stated limits that were cheap to follow); and an acceptance of a harmless boolean expression that also covered a later edit expanding the field (the expression is now a fact).

**Still reported, and accepted as the price of failing closed:** an expression that gives only true or false (`contains(github.event.issue.title, 'bug')`, `title != ''`), and every `matrix` reference in a job whose matrix holds one outsider-written field. **Under stated limits:** `inputs` of a called workflow, the inputs of actions not listed, local composite actions, `with:` given to a reusable workflow, a repository's own Docker action, and the `env` of a `parallel` group (attempt 041, which got through).

### OBAAF-GHA-013 Self-hosted runner used for untrusted work

**Got through, now fixed.** Any `ubuntu-*`, `windows-*` or `macos-*` label taken for GitHub-hosted; `self-hosted` with spaces, in a label with commas, in another case; a runtime selector that always picks `self-hosted` (`false && 'ubuntu-latest' || 'self-hosted'`) reported as informational; the selector and the sets a matrix gives not in the facts (attempt 030: an acceptance for one pool covered another); a job that calls a reusable workflow reported as running on no labels (a false positive, seen on Expectrail); and `head.repo.fork && 'ubuntu-latest' || 'self-hosted'`, which picks the self-hosted runner when `head.repo` is null (attempt 046, not verified), now medium.

**Got through, not fixed here:** a local reusable workflow called from a `pull_request` job runs on `self-hosted` with no finding in either file (attempt 027; slice 2d.4; fixed by slice 2d.4b1, D-082), and an agent CLI the checker does not know (attempt 041, `goose`, `cursor-agent`; slice 2d.5). **False positive kept:** a runner group used for GitHub's larger runners is high, because a group may hold either and the checker fails closed.

### OBAAF-GHA-015 Release workflow started by untrusted input

**Got through, now fixed.** Publishing the lists did not name (attempts 101 to 116, 184, 193): `gh release edit`, `gh api .../releases`, `git push --tags`, `aws` with options before `s3`, a command continued on the next line or with its name quoted, `docker buildx build --push`, `docker image push`, `pnpm -r publish`, `cargo +stable publish`, `createRelease(` in github-script, `scripts/release`, `firebase deploy`, `vercel --prod`, `curl -T`, a `docker://` step, `pypa/gh-action-pypi-publish` (which the first round of fixes counted only as a capability, at medium); environments named `live`, `prd`, `pypi`, `npm`, `crates`, `gh-pages`, `cd`; an environment built by `format` read as complete; and the release reason too general to identify the job (attempt 150: an acceptance for a registry inside the job covered `npm publish`), now with the release steps as facts. The skua classes: environments named by a matrix, the reason and environment not facts, and severity on `pull_request` against OBAAF-GHA-001's.

**Got through, not fixed here:** a local reusable workflow or composite action that publishes (attempts 026, 111; slice 2d.4; since slice 2d.4b1 the called workflow's own job gets OBAAF-GHA-015 with its callers' events, as attempt 026 now does; since slice 2d.4b3b the calling job is a release job too, D-085; since slice 2d.4b2 a composite action that publishes makes the job that uses it a release job, with the release rules on its publishing step, as attempt 111 now does, D-083); deploying with `id-token: write` and a cloud role (attempt 117, not verified; `id-token: write` alone is not counted, because it also signs and attests); `check_suite`, `check_run` and `status` as triggers (attempt 163, not verified; they are not in the list of events outsiders can cause for any rule, issue opened). **By design:** an environment named in plain text lowers the finding to medium (attempt 169), as for OBAAF-GHA-001; GitHub creates an environment that does not exist with no protection, which `obaaf audit` reads. **False positives kept:** a command named in an `echo` (185) and a push to a registry inside the job (146). **Fixed:** `kitchen`, `restore-drill`, `reproducibility`, `product-docs-preview`, `keystore`, `datastore` and `firestore` taken for release environments (`switch-matrix` still is: `switch` is a console a studio releases to) (a first fix read names word by word and lost `euproduction`, `prodeu` and `appstoreconnect`; the review of the slice found it, and names are again matched anywhere, with those words taken out first), and `SUBMODULE_DEPLOY_KEY` and `NODE_AUTH_TOKEN` taken for publishing secrets.

#### Every attempt on OBAAF-GHA-010

| # | Attempt | Verdict on the first round of fixes | Now |
| --- | --- | --- | --- |
| 001 | merge_group head commit message (merge_group.head_commit.message) | way past (not verified) | high |
| 002 | merge_group head commit author name | way past (not verified) | high |
| 003 | issues transferred: changes.new_issue.title | way past (not verified) | high |
| 004 | fork event: forkee.description | way past (not verified) | high |
| 005 | discussion transferred: changes.new_discussion.title | way past (not verified) | high |
| 006 | workflow_run path of the run's workflow file | way past (not verified) | high |
| 007 | workflow_run after push only (if narrows) + workflow_run.head_commit.message | way past (not verified) | high |
| 008 | push: head_commit.message (control, expect high) | held | high |
| 009 | boolean-only expression (FP check) | false positive | high |
| 010 | comparison producing constant strings (FP check) | false positive | high |
| 011 | YAML anchor in env, alias as run | held | high |
| 012 | double-quoted YAML escape \x24{{ | held | high |
| 013 | unicode escape \u0024\u007b\u007b | held | high |
| 014 | letter case + index syntax | held | high |
| 015 | format() of event object | held | high |
| 016 | join() of commits on push | held | high |
| 017 | fromJSON(toJSON(github.event)).issue.title | held | high |
| 018 | job defaults.run.shell holds expression | way past (not verified) | high |
| 019 | step shell: holds expression | way past (not verified) | high |
| 020 | egress action with trailing slash in path | way past (not verified) | high |
| 021 | egress action control (plain spelling) | held | high |
| 022 | egress action path with ./ segment | way past (not verified) | high |
| 023 | repo Docker action with with.entrypoint/args | under a stated limit (not verified) | nothing |
| 024 | docker:// args control | held | high |
| 025 | docker:// with uses having leading whitespace inside quotes | held | high |
| 026 | called workflow uses inputs.* from untrusted caller | under a stated limit | nothing |
| 027 | static job output then needs.<job>.outputs | held | high (indirect) |
| 028 | job output via job env | held | high (indirect) |
| 029 | job output chain a->b->c | held | high (indirect) |
| 030 | whole-expression step env + env.X in run | held | high (through-env) |
| 031 | push: toJSON(github.event) (commit text inside, field reported as github.event) | way past | high |
| 032 | push: toJSON(github.event.head_commit) | way past | high |
| 033 | push: toJSON(github.event.commits) | way past | high |
| 034 | push: computed index github.event[format('head_commit')].message | way past | high |
| 035 | push: wildcard github.event.*.message | held (not verified) | high |
| 036 | push: head commit message through needs output | held | high (indirect) |
| 037 | env holds two fields; facts show only the first | way past | high (through-env) |
| 038 | harmless boolean env (control for 037: same facts?) | false positive | high (through-env) |
| 039 | matrix holds two fields; facts show only the first | way past | high (indirect) |
| 040 | job output holds two fields | way past | high (indirect) |
| 041 | parallel group env holds title, inner step expands env.T | way past (not verified) | nothing |
| 042 | expression split across lines inside block scalar | held | high |
| 043 | folded scalar joins lines | held | high |
| 044 | workflow env -> step env chain -> run | held | high (through-env) |
| 045 | step env overrides tainted job env (FP check, harmless) | held | nothing |
| 046 | job env lower-case key tainted, step env upper-case same name (Linux: distinct) | held | high (through-env) |
| 047 | matrix from fromJSON(needs output holding title) | held | high (through-matrix) |
| 048 | matrix from body JSON | held | high (through-matrix) |
| 049 | github-script script input from comment | held | high |
| 050 | unlisted script action (python script input) | under a stated limit | nothing |
| 051 | local composite action with input | under a stated limit | nothing |
| 052 | reusable workflow call passing title | under a stated limit | nothing |
| 053 | listed script action spelled with trailing slash (azure/cli/) | way past | high |
| 054 | two expressions, two fields in run | held | high |
| 055 | needs.<job> without outputs segment (needs.a) via toJSON | held | high (indirect) |
| 056 | pull_request_target head ref inside if+run, plain (control) | held | high |
| 057 | workflow_dispatch + push only, head_commit.author.email on push | held | high |
| 058 | pull_request: head_ref via github.head_ref | held | high |
| 059 | status event commit message | way past (not verified) | high |
| 060 | check_suite head branch / head commit message | way past (not verified) | high |
| 061 | listed script input azure/cli inlineScript (plain spelling) | way past | high |
| 062 | listed script input azure/powershell inlineScript | way past | high |
| 063 | listed script input nick-fields/retry command (lower-case control) | held | high |
| 064 | commit_comment trigger: comment.body (anyone can comment on a public repo's commits) | way past (not verified) | high |
| 065 | matrix FP: harmless matrix.os flagged because another matrix key holds title | false positive | high (through-matrix) |
| 066 | job env whole expression reading a tainted matrix | held | high (through-env) |
| 067 | step env whole expression reading tainted job env | held | high (through-env) |
| 068 | job env whole expression from a needs output | held | high (through-env) |
| 069 | workflow env whole expression | held | high (through-env) |
| 070 | push: toJSON(github) (commit text inside) | way past | high |
| 071 | repository_dispatch relayed comment (slash-command-dispatch pattern) | held (not verified) | nothing |
| 072 | called workflow: event text directly (control, expect high) | held | high |
| 073 | pull_request_review_comment path + diff_hunk | held | high |
| 074 | issues edited changes.title.from | held | high |
| 075 | workflow_run head_repository.description + committer | held | high |
| 076 | discussion answered: answer.body | held | high |
| 077 | gollum page title via pages.* | held | high |
| 078 | non-ASCII letter in property name (dotless i): github.event.issue.t\u0131tle | held (not verified) | nothing |
| 079 | workflow_run.head_commit via toJSON on TRUSTED narrowing | way past (not verified) | high |
| 080 | pull_request_target: head.repo.owner via toJSON of head.repo (control) | held | high |
| 081 | egress action path with doubled slash | way past (not verified) | high |
| 082 | script_inputs action with camelCase input written lower-case (azure/cli inlinescript) | way past | high |
| 083 | env var on step overriding job env with expression reading the job value (B: ${{ env.B }}) | held | high (through-env) |
| 084 | two steps same name: harmless boolean then risky; one acceptance key | false positive | high |
| B1 | acceptance written for harmless boolean expansions (env T: title == 'x'; contains(comment.body,'/ok')) also accepts the risky edit (T gains ${{ github.event.comment.body }}; step expands comment.body plainly) | way past | high, high (through-env) |

#### Every attempt on OBAAF-GHA-013

| # | Attempt | Verdict on the first round of fixes | Now |
| --- | --- | --- | --- |
| 001 | plain runs-on: self-hosted on pull_request (control) | held | high (self-hosted) |
| 027 | pull_request workflow calls a LOCAL reusable workflow (uses: ./.github/workflows/build.yml) whose job runs on self-hosted; calling job is skipped and the called file's only trigger is workflow_call, which is not in UNTRUSTED_TRIGGERS | way past | nothing |
| 030 | matrix-resolved labels are not in the facts: labels fact is the text '${{ matrix.pool }}'. Baseline written for pool [[self-hosted, ephemeral-firecracker]] was then applied after changing it to [[self-hosted, persistent-build-box]] | way past | high (self-hosted) |
| 046 | fork selector form 1 (head.repo.fork && 'ubuntu-latest' \|\| 'self-hosted') on pull_request_target with types [opened, edited, synchronize]; when the fork has been deleted github.event.pull_request.head.repo is null, .fork is null and the selector picks self-hosted (forms 2 and 3 compare full_name and fall to the hosted side on null) | way past (not verified) | medium (other-labels) |
| 041 | agent job on push + self-hosted using an agent CLI not in agent_commands (goose run --text; same for cursor-agent -p in 042); claude -p in 040 is caught (high) | way past | nothing |
| 010 | runs-on: ${{ 'self-hosted' }} (constant expression) | under a stated limit | medium (other-labels) |
| 011 | list mixing hosted label and 'Self-Hosted' (case) | held | high (self-hosted) |
| 022 | one label 'ubuntu-latest,self-hosted' with a comma | held (not verified) | high (self-hosted) |
| 012 | runs-on mapping with labels only [linux, x64] | held | medium (other-labels) |
| 013 | Runs-On (key in another case) | held (not verified) | medium (other-labels) |
| 014 | duplicate runs-on keys (ubuntu-latest then self-hosted) | held (not verified) | nothing |
| 015 | matrix os [ubuntu-latest] + include {os: self-hosted} | held | high (self-hosted) |
| 016 | matrix value that is a label list [self-hosted, linux] | held | high (self-hosted) |
| 018 | fork selector form 1 on pull_request | held | medium (other-labels) |
| 021 | fork selector on pull_request + issue_comment | held | medium (other-labels) |
| 047 | fork selector in a job that runs an agent | held | medium (other-labels) |
| 045 | needs a push-only job but if: !cancelled() | held | high (self-hosted) |
| 053 | runs-on from needs output | held | medium (other-labels) |
| 043 | trigger written Pull_Request | held (not verified) | nothing |
| 044 | runs-on: {group: ubuntu-larger-runners} for a GitHub-hosted larger-runner group | false positive | high (self-hosted) |

#### Every attempt on OBAAF-GHA-015

| # | Attempt | Verdict on the first round of fixes | Now |
| --- | --- | --- | --- |
| 100 | npm publish on issue_comment (control) | held | high |
| 026 | pull_request_target workflow calls a LOCAL reusable workflow with secrets: inherit; the called job runs npm publish in environment production. Calling job is skipped (release_capability returns on job.reusable) and the called file's trigger workflow_call is not untrusted | way past | nothing |
| 150 | release reason is the generic 'uploads or publishes artifacts' with no step: a baseline written for 'docker push localhost:5000/t' (service-container registry) on pull_request also accepts the job after 'npm publish' with NODE_AUTH_TOKEN is added | way past | medium (pull-request) |
| 101 | create a release through the REST API: gh api -X POST repos/.../releases with contents: write | way past | high |
| 102 | gh release edit v1 --draft=false (publishes a draft release) | way past | high |
| 103 | git tag + git push origin --tags with contents: write | way past | high |
| 104 | curl -T upload to Artifactory with ARTIFACTORY_API_KEY (curl -T is only in jenkins_upload_commands; secret name matches no pattern) | way past | high |
| 105 | aws --region us-east-1 s3 cp (global option between aws and s3 defeats 'aws\s+s3'); AWS keys match no publishing pattern | way past | high |
| 116 | aws \<newline> s3 cp (line continuation) | way past | high |
| 106 | docker/login-action with DOCKER_HUB_ACCESS_TOKEN (matches no pattern) + docker buildx build --push + docker image push | way past | high |
| 107 | pnpm -r publish (option between pnpm and publish); secret NPMJS | way past | high |
| 108 | cargo +stable publish; secret CRATES_KEY | way past | high |
| 109 | actions/github-script calling github.rest.repos.createRelease (contents: write) | way past | high |
| 110 | ./scripts/release.sh (only scripts/publish is listed); secret BOT_TOKEN | way past | high |
| 111 | local composite action ./.github/actions/publish | way past | nothing |
| 112 | firebase deploy with FIREBASE_TOKEN | way past | high |
| 113 | npx vercel --prod with VERCEL_TOKEN | way past | high |
| 184 | uses: docker://node:20 with entrypoint npm, args publish (text() reads run and github-script only) | way past | high |
| 117 | OIDC: id-token: write + aws-actions/configure-aws-credentials role-to-assume + aws lambda update-function-code (id-token: write not counted, no secret) | way past (not verified) | nothing |
| 118 | PyPI trusted publishing with uv publish --trusted-publishing always in environment 'pypi' (name matches no release pattern, plain-text environment is not a capability) | way past | medium (environment) |
| 119 | pull_request_target with no permissions declared; GITHUB_TOKEN login to ghcr.io + docker buildx --push (packages: write only counted when declared) | way past (not verified) | high |
| 114 | '"npm" publish' (quoted command name) | way past | high |
| 193 | pypa/gh-action-pypi-publish (in publishing_actions, not upload_actions) on issue_comment, no environment | way past | high |
| 121 | production environment named 'live' (also prd, gh-pages, npm, crates, cd, main, master, github-pages in 122-126, 133-135), job deploys with KUBECONFIG | way past | medium (environment) |
| 127 | environment: ${{ format('{0}{1}', 'pr', 'oduction') }}: candidates are the literal pieces, read as complete, none matches | way past | medium (capability) |
| 169 | add environment: ci (any plain-text name; GitHub creates a missing environment with no protection) to an npm publish job on issue_comment | way past | medium (environment) |
| 163 | release job on check_suite (also check_run 162, status 164), not in UNTRUSTED_TRIGGERS | way past (not verified) | nothing |
| 120 | environment: production on issue_comment | held | medium (environment) |
| 129 | environment ${{ matrix.target }} over [staging, production] | held | high |
| 130 | matrix include value ${{ 'production' }} | held | medium (capability) |
| 132 | environment ${{ inputs.env }} | held | medium (capability) |
| 160 | release job on workflow_run | held | high |
| 161 | workflow_run with if: github.event.workflow_run.event == 'push' | held | nothing |
| 165 | release job on pull_request_review only | held | medium (pull-request) |
| 166 | pull_request_target + if: event_name == 'push' \|\| pull_request.merged | held | high |
| 167 | needs a push-only gate job | held | nothing |
| 168 | needs a push-only gate but if: !failure() | held | high |
| 172 | issues + if contains(labels, 'release') | held | high |
| 174 | merge_group | held | nothing |
| 190 | permissions: write-all, no publish step | held | medium (capability) |
| 180 | harmless test job with environment 'kitchen' (also restore-drill 181, reproducibility 182, product-docs-preview 183, switch-matrix 143, which is reported again because `switch` is a console): substring itch/store/prod | false positive | nothing |
| 185 | harmless job on issue_comment whose script says echo "skip docker push in CI" (144: echo text with 'npm publish' on pull_request) | false positive | high |
| 146 | docker push to a localhost:5000 service-container registry in a PR test | false positive | medium (pull-request) |
| 145 | checkout with secrets.SUBMODULE_DEPLOY_KEY (read-only SSH deploy key for submodules); 186 NODE_AUTH_TOKEN for npm ci | false positive | nothing |

## 2d.2e: release and effect jobs

Run `tattler`, 2026-11-14, on a copy of `flagship` at `d05095a`. Two Opus 5.5 reviewers that did not write the code attacked seven rules in parallel, and a third reviewed the result (see "Review"): reviewer A OBAAF-GHA-006, 007 and 014 (123 attempts: 56 ways past, 25 of them not verified, 10 false positives, 57 held), reviewer B OBAAF-GHA-016, 017, 021 and 022 (144 attempts, about 40 of them controls: 65 ways past). The classes were then fixed, and every attempt was run again with the old and the new checker; the two tables at the end of this section are that run, generated from the attempt directories. Expectrail at `3ce1c2a` (a read-only copy of `.github` and `AGENTS.md`, `fresh-*` left out unread) gives the same 43 findings, in the same states, with both.

GitHub's documentation could not be read from the session. What `cache-mode` does was read from GitHub's changelogs of [2026-09-10](https://github.blog/changelog/2026-09-10-control-github-actions-cache-access-with-cache-mode) and [2026-06-26](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers/) on 2026-11-14: four values (`read`, `write`, `write-only`, `none`), set on the workflow or the job, the job's value winning, enforced by the cache service, and carried into a called workflow, which "cannot receive more cache access than its caller granted". The changelogs do not say whether a value in another case, an expression or a null is accepted. What bash does was run by reviewer B on bash 5.2.21 and dash (`bash -e`, `bash --noprofile --norc -eo pipefail`, `sh -e`); what PowerShell and GitHub's runner do was not run. Where a way past depends on what was not run, the record says "not verified", and the fix is chosen to be right either way.

### OBAAF-GHA-016 Upload without a provenance check, and OBAAF-GHA-021 Agent output applied without verifying its record

Both rules asked whether a step's text matched a check's pattern and whether the rest of that one line held `||` or `&`. That is the class: the text of a check is not a check.

**Got through, now fixed.** The check's text where it never runs or its failure is ignored: in a comment (105, 205), an `echo` (106), a here-document (107), after `exit 0` (108), in a function never called (117), after `:` (130) or `true ||` (242), in an `&&` list that is not the last command (109, 115, 243), in an `if`, `until` or `!` (110, 111, 112, 209), in a substitution (129, 132, 244), in `sh -c` (131), in a pipe without pipefail (113, 114, 139, 208), with `|| true` on the next line (119), sent to the background with `& wait` (127), after errexit was turned off in any spelling but `set +e` (121 to 126, `set +o errexit`, `set +eu`, `shopt -uo errexit`, a `trap`), through `BASH_ENV` (143, 144), in a shell that does not stop on failure (135, 141, `bash {0}`; 136, 137, 138, PowerShell, cmd, Python; 142, the default shell of a Windows runner, not verified), in `actions/github-script` (180, 181), behind a function that shadows `obaaf` (145), with `--help` (146, 240), and with `--pre-approval`, which skips the approvals and now counts as a provenance check (147). A later upload with `if: always()` or `!cancelled()` after an upload that was checked (162, 163): every upload is now checked, not only the first. A needed job with `continue-on-error` (169, 170, 225, not verified): it is no gate itself, and the jobs it needs still are. For 021: the checks after the step that applies (204), and an apply step with `if: always()` (211). `gh attestation verify` counted as verifying the agent-run record (206): it checks a signature and a predicate type, not the record's run, snapshot or permissions, so it no longer counts.

What a check is now. The first reader tried to follow bash's grammar, and the slice's reviewer got past it 50 more ways; the second used a deny-list over the lines before the check, and the reviewer got past it 20 more ways (see "Review" below). The reader now accepts only what it can vouch for and stops at the first line it cannot. A check counts when its line is that one command (`|| exit N` with N from 1 to 255, `|| exit` and `|| { plain; commands; exit N; }` allowed after it, and a pipe under pipefail), outside any compound command, in a `run` script in bash or sh with errexit on (GitHub's `bash -e` on a runner labelled as Linux or macOS, `shell: bash`, `shell: sh`, a custom shell with only `-e`, `-u`, `-x` and `-o` options, or `set -e` before it), the step runs on success only, and every line before it is one of: simple commands joined by `;`, `&&`, `||` or `|`, each named by a plain word that cannot leave the script, run text as commands, or change what a name runs or how the shell behaves, with no assignment to `PATH`, `BASH_ENV` or `ENV`, no reserved word, no `&`, no here-document, no unquoted `(` but an array assignment, no backslash but one ending the line (joined as bash joins it, after the comment is taken off), and no `${{ }}` expression whose value could hold shell syntax (a text written in the expression is put in as GitHub puts it; `github.sha`, run ids and other values that cannot hold shell syntax are one word); or a plain `if ...; then`, `elif ...; then`, `while ...; do`, `until ...; do`, `for NAME in ...; do`, `else`, `fi` or `done` line. A script with a line break bash does not see or with `$'...'` is not read. A word before the check that names `PATH`, `BASH_CMDS`, `BASH_ALIASES`, `BASH_ENV` or the like (read or written), assigns `PS4`, `PYTHONPATH`, `LD_PRELOAD` or another variable an interpreter reads at start, assigns a variable bash evaluates as arithmetic (`RANDOM`, `OPTIND` and the like), or holds an expansion outside an allow-list (`$NAME`, a special parameter, `$(...)`, which runs in a subshell, and `${NAME}` with nothing but `[@]`, `[*]`, a length, a default or a pattern removed; any other form, such as a subscript, an offset, `${!...}`, `${NAME:=...}`, `$((` or `[[`, can evaluate a value as arithmetic that assigns, even inside quotes), with the check's own words held to the same, an earlier step whose text names `BASH_ENV`, `BASH_FUNC` or `GITHUB_PATH` (a search, not a guarantee), an `env` written as one expression, and a login or interactive shell all mean no check. When a step names a check the reader cannot vouch for, OBAAF-GHA-016 is kind `cannot-tell` (still high) rather than `unchecked`. For 021 the checks count only before the first step that may apply (anything but a checkout, a download of artifacts, a GitHub setup action or a `setup-obaaf` from a repository named `obaaf`), only in a step that runs nothing but the checks and commands that only read or prepare, with no substitution, and none count when a step that may apply runs after a failure. **Stated, not fixed:** what commands and actions earlier in the job, in the same step or before it, do to the runner (replace the `obaaf` binary, rewrite the policy file, write `GITHUB_ENV` or the path file under a name the text search does not see) cannot be ruled out by reading a script.

**False positives fixed.** `obaaf verify release ... || exit 1` (184) and `|| { echo ...; exit 1; }` (188), `||` in a comment after the command (185), `set +e` after the check (186), and `if: ${{success()}}` or `if: true` on the check step (160, 161).

**False positives kept** (failing closed): the check and the upload in one step (166; the rule asks for an earlier step), `"obaaf" verify` with the name quoted (187), a check in a `docker://` step's arguments (182) or a local action (183; since slice 2d.4b2 the action's steps are read, but reading through only adds findings, so a check inside one clears no finding of an upload in the job; it does count for an upload inside the same action, D-083), a check in a subshell `( ... )` (116, newly reported: write it without the parentheses), an `if:` on the check step that is always true for the workflow's triggers (159), and chains through a job with `if: always()` (174, 228, not verified). **Under stated limits:** whether the files verified are the files uploaded (148, 149).

### OBAAF-GHA-017 Release builds without provenance

**Got through, now fixed.** A provenance step that never runs or whose failure is ignored (190 `if: false`, 191 a job no trigger reaches, 192 `continue-on-error`), its text in a comment or an `echo` (193, 194), an attestation of an SBOM only (195 `actions/attest` with `sbom-path`, 196 `cosign attest --type spdxjson`), and "verified elsewhere" accepted from any verify text in the job, after the upload (198) or in an `echo` (200, which also lowered OBAAF-GHA-016 to medium). **Got through, not fixed here:** an attestation job that signs other files than the publishing job uploads and is not tied to it by `needs` (199), and an attestation job that needs a job with `if: false` (201); both are stated limits.

### OBAAF-GHA-022 Agent output applied without an approval gate, and OBAAF-GHA-014 Release job not behind a protected environment

Both took any value that was not empty for an environment. **Got through, now fixed.** A blank name (213, 215, 074, 075), an expression that can be blank (216, 221, 079, 080, 078, 110), a variable that may be unset (217, 083), a matrix with a blank value (222, 084), `${{ null }}` (223), an expression on the needed job (231), and a number or `true` (081, 219): an environment now counts only when its name is written as text, or as an expression whose every value the checker can list with none blank; anything else is "cannot tell" for 014 (kinds `blank`, `open`, `unreadable`) and no gate for 022. **Under a stated limit:** an environment with no protection rules (`environment: ci`, 082; `deployment: false`, 241, not verified): whether it has required reviewers is read by `obaaf audit`, not here.

**OBAAF-GHA-014, publishing the lists did not name.** Now an upload: `docker/build-push-action` and `docker/bake-action` with `push` true or set when the job runs (086), `svenstaro/upload-release-action` and `actions/upload-release-asset` (089), `mvn deploy`, `gradle publish`, `sbt publish` (091), `helm`, `oras`, `podman` and `crane` push (092), `aws s3api put-object` (093), `gh` with options before `release` (094), `semantic-release`, `changeset publish`, `goreleaser release` (095), `bun`, `jsr`, `vsce`, `ovsx`, `maturin`, `pdm publish` and `pod trunk push` (100), github-script `request('POST /repos/.../releases')` (098) and `uploads.github.com` (099). A release job with no upload the lists know is reported when it holds what publishing needs (`packages: write`, a publishing action, a secret whose name says it publishes; kind `capability`), so a deployment through `actions/deploy-pages`, `peaceiris/actions-gh-pages`, `aws-actions/...` or `azure/webapps-deploy` (087, 088, 090) is reported when the job is a release job. **Not counted as publishing, by design:** those deployments in a job that is not otherwise a release job (a documentation site is not a release unless declared one), `rsync`, `scp` and `rclone` (093), `skopeo` (092), dry runs and pushes to `localhost`, a script file (`./release.sh`, `make release`, 095), a command built from a variable (`$D push`, 104), a tag pushed by name (`git push origin v1.2.3`, 099), and a `docker://` step whose image pushes (097). **Got through, now fixed by slice 2d.4b3b** (D-085): a publish inside a local reusable workflow the release job calls (103, 034): the called job that publishes carries OBAAF-GHA-014, and the calling job is a release job.

### OBAAF-GHA-006 Release job can read a shared cache

**Got through, now fixed.** Cache steps the closed list missed, or whose inputs it read as text: an action path with `..` (014, now read as the path it names, whether or not GitHub resolves it), a local composite action (015, taken to restore whatever it holds; since slice 2d.4b2 its steps are read as the job's too, but the rule gives one finding for a job, on its first step that restores, the using step, D-083), `actions-rust-lang/setup-rust-toolchain` (016), cache inputs written as expressions (017, 018, 019, 026) or all inputs as one expression (020), `oven-sh/setup-bun` (021), `pnpm/action-setup` with `cache` (022), `ccache` and `sccache` (023, 024), `docker/bake-action` with `type=gha` (025), `crazy-max/ghaction-github-runtime` and `--cache-from type=gha` in a script (028), github-script with the cache toolkit (029), `jdx/mise-action`, `magic-nix-cache-action` and `mlugg/setup-zig` (105). A release job that downloads artifacts from a job it needs that restores a cache (033), the Clinejection shape: now kind `needed-job-restores`. An acceptance of `actions/cache` with `lookup-only` that also covered `actions/cache/restore` (117) and an accepted low finding that covered steps added later (118): the facts now hold each step's name and the action that restores. **False positives fixed:** `lookup-only: true` (011) and a release job with `cache-mode: write-only` and no cache step (122). **False positives kept:** a cache step whose `if:` never lets it run (032, 111), and a called release job whose caller sets `cache-mode: none` (035, not verified; since slice 2d.4b3b the finding is "cannot tell" when every caller in the repository forbids restoring, because a caller in another repository is not seen, D-085). **Under stated limits:** a `docker://` cache client (031, not verified), a local reusable workflow that restores (034; since slice 2d.4b3b a declared release job that calls it gets `called-restores`, D-085), and a self-hosted runner's local caches (040).

### OBAAF-GHA-007 Low-trust workflow can write the default-branch cache

**Got through, now fixed** (all not verified: GitHub may reject these files). A value in another case or with space (042, 043), an expression (044, 045, 109), a number or `true` (070), a block scalar (048), a key in another spelling (047): each is now reported as a value the checker cannot read (kind `unreadable`). A null at the job (046, 071) hid the workflow's `write`; it no longer does. **Not fixed here:** `check_run`, `check_suite`, `status` and `deployment_status` as triggers (054 to 057, issue #166), the default a job gets when it declares nothing (064), and a top-level `On:` key (108), which hides the triggers from every rule and is outside this tranche. **False positives kept:** the review events, which write the pull request's own cache scope (060, not verified), and an `if:` on `head.repo.full_name` or `author_association` (106, 107).

### Review

One Opus 5.5 reviewer that did not write the code reviewed the slice. Its first pass found the "Now" column right for all 267 attempts, no crash on about 80 odd inputs, and ten blocking findings; each is tested in `tests/test_release_effect_bypasses.py`, and what the second pass found still open is said after the list:

1. An `exit` inside an `if`, a `case`, a `{ }` group, a loop or a function before the check.
2. `${{ }}` read as one word, though GitHub puts its value into the script first (`${{ '|| true' }}` after the check, `${{ 'exit 0' }}` before it).
3. The first reader's grammar: `$'...'`, partly quoted here-document delimiters, quoted or escaped keywords (`"fi"`, `\fi`), a `case` that hides the check, and line breaks Python splits on but bash does not.
4. The `||` exception: `exit 256`, `exit 00`, `exit -0`, `|| false || true`, `exit 1 | cat`, `exit 1 &`, groups with `&`, `||` or a pipe, and a redefined `false`.
5. What the reader did not follow was not "no check": `exec true`, `builtin`, `eval`, `source`, `set` built from a variable, `PATH=`, `hash -p`, and `env --version` or `timeout --help` before the check.
6. Shell options: `bash -e +e {0}`, `bash -el {0}` (a login shell reads files an earlier step can write), an `env` written as one expression, and `BASH_FUNC` or `GITHUB_PATH` written by an earlier step.
7. A self-hosted runner's default shell taken for bash: on Windows it is PowerShell. The default shell now counts only on GitHub-hosted labels or a runner labelled `linux` or `macOS`.
8. OBAAF-GHA-021: a step that applies and then checks counted as checked, and any `*/actions/setup-obaaf` was taken for OBAAF's.
9. OBAAF-GHA-017: `continue-on-error` on the attestation job still counted as signing.
10. The widened publishing list made ordinary CI release jobs (`publishToMavenLocal`, `goreleaser release --snapshot`, `semantic-release --dry-run`, `rclone copy` from a remote, `skopeo copy` to a file, `mvn deploy` to a `file:` repository, `helm push` to `localhost`), with facts that made an acceptance of the dry run cover the real one: dry runs and local targets are not uploads now, and `rclone` and `skopeo` are not listed.

Also corrected from its non-blocking points: the claim that every acceptance of OBAAF-GHA-006 changed (`no-cache-mode` did not), the 021 description's claim about acceptances (it holds for baseline entries, not `ignore` entries), a code span broken by a line wrap in the catalogue, and the upgrade page, which had no rows for this slice. Kept, and stated: `_jobs_feeding` may name a job whose output the release does not use; `${{ inputs.environment }}` with a `choice` input is "cannot tell"; `$((1 << 2))` or `"a<<b"` before a check makes the reader stop (a check that does run is reported missing); actions that cache are still a list; arguments of the check (`--gh PATH`, a policy file an earlier step writes) are not read.

A second pass, on the reader that replaced the first, found every first-pass case reported, no crash on 20,000 fuzzed scripts, and these, all fixed and tested unless said: quoting or a backslash inside `exit` or `eval` (the deny-list ran on text with quoted parts blanked); a line continuation read as a space where bash removes it, and a comment ending in a backslash; an escaped space before `#`; depth fooled by `time if`, a command named `fi`, a `)` inside an expansion or after `#`; a line ending in `||` or `&&` that continues onto the check's line; `PATH` set by `for`, `read` or `printf -v`, or as a prefix on the check's own line, and `mapfile -C`; shell options `-n`, `-t` and `-D` (the options are now an allow-list); a substitution inside a quoted or backquoted word in an OBAAF-GHA-021 check step; the local `./actions/setup-obaaf` taken for OBAAF's (an agent's artifact downloaded to `.` could provide it); and dry-run, `--snapshot`, `localhost` and `file:` exceptions that matched anywhere on the line, so `npm publish # was --dry-run` lost an upload the base checker reported (they now stop at `;`, `&`, `|` and `#`, and the Maven one reads only `-DaltDeploymentRepository`). **Stated, not fixed:** `BASH_ENV` or the path file written under a name the text search does not see (`"BASH""_ENV"`, the runner's `add_path_*` file), `cp /bin/true "$(which obaaf)"` and other changes earlier commands or actions make to the runner, and a `setup-obaaf` from any repository named `obaaf` taken for OBAAF's (the templates may point at a fork). From its non-blocking points, a step whose check cannot be vouched for is now `cannot-tell` instead of "no check". A third pass found every earlier case reported and two more ways past, both fixed and tested: shell state set before the check without naming it at the start of a word (`BASH_CMDS[obaaf]=/bin/true`, `: "${BASH_CMDS[obaaf]:=/bin/true}"`, `: "$((PATH=5))"`, `PS4` with `set -x`), and `npm publish --dry-run false`, which publishes. From its non-blocking points, `PYTHONPATH`, `LD_PRELOAD` and similar interpreter variables are denied before and on the check's line. A fourth pass found arithmetic carried by a variable's value (`x='PATH=5'` then `y[x]=1`, `"${y[x]}"`, `"${s:x}"` or `[[ x -eq 5 ]]`), and a later `--dry-run=false` or `--no-dry-run` after `--dry-run`; both fixed and tested. A fifth pass found the same class in more spellings (`y=([x]=1)`, `"${@:x}"`, `"${0:x}"`, `"${arr[@]:x}"`, `RANDOM=x`, `OPTIND=x`), so the expansions allowed before a check became an allow-list, special variables bash evaluates as arithmetic cannot be assigned, `read` and `test -v` cannot name a subscript, and the check's own words are held to the same. The third pass judged both "stated, not fixed" decisions acceptable as stated; a configuration key naming the trusted OBAAF repository is left for later (issue #169).

### What changed for adopters

- A gate can fail where it passed: a check that does not stop the upload is no check; a later upload, a needed job with `continue-on-error`, an environment that may be blank, publishing the lists now know, a release job that holds publishing credentials, cache steps now known, and cache-mode values the checker cannot read.
- Every v0.2 acceptance of OBAAF-GHA-006 `restores`, 014, 016, 021 and 022 needs accepting again: the steps, the restoring actions, the environment as written and what the job may write are now facts (006 `no-cache-mode` is unchanged). A v0.1 entry from 0.3.0 still names a finding whose message did not change. An `ignore` entry names the rule, file and job, and still covers them.
- Some findings go away: a check written `|| exit 1`, `lookup-only: true`, `write-only` with no cache step.
- This repository: `release-pypi.yml#publish` uses the local action `./actions/setup-obaaf`, which is now taken to restore a cache (it does not), so the job and `pages.yml#deploy` now set `cache-mode: none`, as decision D-019 asks of every release job.

#### Every attempt of reviewer A (OBAAF-GHA-006, 007, 014), before and after the fixes

What the checker reported for these seven rules on each attempt's workflow, with the checker before slice 2d.2e and after it, review fixes included. The attempt numbers are the ones used above.

| # | Before | Now |
| --- | --- | --- |
| 001 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 002 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 003 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 004 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 005 | nothing | nothing |
| 006 | nothing | nothing |
| 007 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 008 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 009 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 010 | nothing | nothing |
| 011 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 low no-cache-mode |
| 012 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 013 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 014 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 015 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 016 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 017 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 018 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 019 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 020 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 021 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 022 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 023 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 024 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 025 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 026 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 027 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 028 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 029 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 030 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 low no-cache-mode |
| 031 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 low no-cache-mode |
| 032 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 033 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-006 high needed-job-restores, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 034 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 low no-cache-mode |
| 035 | OBAAF-GHA-006 high restores, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-006 high restores, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 036 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 037 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 low no-cache-mode |
| 038 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 039 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 040 | nothing | nothing |
| 041 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 042 | nothing | OBAAF-GHA-007 high unreadable |
| 043 | nothing | OBAAF-GHA-007 high unreadable |
| 044 | nothing | OBAAF-GHA-007 high unreadable |
| 045 | nothing | OBAAF-GHA-007 high unreadable |
| 046 | nothing | OBAAF-GHA-007 high |
| 047 | nothing | OBAAF-GHA-007 high unreadable |
| 048 | nothing | OBAAF-GHA-007 high unreadable |
| 049 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 050 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 051 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 052 | nothing | nothing |
| 053 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 054 | nothing | nothing |
| 055 | nothing | nothing |
| 056 | nothing | nothing |
| 057 | nothing | nothing |
| 058 | nothing | nothing |
| 059 | nothing | nothing |
| 060 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 061 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 062 | nothing | nothing |
| 063 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 064 | nothing | nothing |
| 065 | nothing | nothing |
| 066 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 067 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 068 | nothing | nothing |
| 069 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 070 | nothing | OBAAF-GHA-007 high unreadable |
| 071 | nothing | OBAAF-GHA-007 high |
| 072 | nothing | nothing |
| 073 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 074 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium blank, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 075 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium blank, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 076 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 077 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 078 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium open, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 079 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium open, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 080 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium open, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 081 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium unreadable, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 082 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 083 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium open, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 084 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium open, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 085 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium unreadable, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 086 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 087 | nothing | OBAAF-GHA-014 medium capability |
| 088 | nothing | OBAAF-GHA-014 medium capability |
| 089 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 090 | nothing | OBAAF-GHA-014 medium capability |
| 091 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 092 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 093 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 094 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 095 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 096 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 097 | nothing | nothing |
| 098 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 099 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 100 | nothing | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 101 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 102 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 103 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 low no-cache-mode, OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 104 | nothing | nothing |
| 105 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 106 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 107 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 108 | nothing | nothing |
| 109 | nothing | OBAAF-GHA-007 high unreadable |
| 110 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium open, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 111 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 112 | nothing | nothing |
| 113 | nothing | nothing |
| 114 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 115 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 116 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 117 | OBAAF-GHA-006 high restores | OBAAF-GHA-006 high restores |
| 118 | OBAAF-GHA-006 low no-cache-mode | OBAAF-GHA-006 high restores |
| 119 | OBAAF-GHA-007 high | OBAAF-GHA-007 high |
| 120 | OBAAF-GHA-006 low no-cache-mode, OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-006 low no-cache-mode, OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 121 | file refused | file refused |
| 122 | OBAAF-GHA-006 low no-cache-mode | nothing |
| 123 | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-014 medium, OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |

#### Every attempt of reviewer B (OBAAF-GHA-016, 017, 021, 022), before and after the fixes

| # | Before | Now |
| --- | --- | --- |
| 101 | nothing | nothing |
| 102 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 103 | OBAAF-GHA-016 medium provenance-only | OBAAF-GHA-016 medium provenance-only |
| 104 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 105 | nothing | OBAAF-GHA-016 high cannot-tell |
| 106 | nothing | OBAAF-GHA-016 high cannot-tell |
| 107 | nothing | OBAAF-GHA-016 high cannot-tell |
| 108 | nothing | OBAAF-GHA-016 high cannot-tell |
| 109 | nothing | OBAAF-GHA-016 high cannot-tell |
| 110 | nothing | OBAAF-GHA-016 high cannot-tell |
| 111 | nothing | OBAAF-GHA-016 high cannot-tell |
| 112 | nothing | OBAAF-GHA-016 high cannot-tell |
| 113 | nothing | OBAAF-GHA-016 high cannot-tell |
| 114 | nothing | OBAAF-GHA-016 high cannot-tell |
| 115 | nothing | OBAAF-GHA-016 high cannot-tell |
| 116 | nothing | OBAAF-GHA-016 high cannot-tell |
| 117 | nothing | OBAAF-GHA-016 high cannot-tell |
| 118 | nothing | OBAAF-GHA-016 high cannot-tell |
| 119 | nothing | OBAAF-GHA-016 high cannot-tell |
| 120 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 121 | nothing | OBAAF-GHA-016 high cannot-tell |
| 122 | nothing | OBAAF-GHA-016 high cannot-tell |
| 123 | nothing | OBAAF-GHA-016 high cannot-tell |
| 124 | nothing | OBAAF-GHA-016 high cannot-tell |
| 125 | nothing | OBAAF-GHA-016 high cannot-tell |
| 126 | nothing | OBAAF-GHA-016 high cannot-tell |
| 127 | nothing | OBAAF-GHA-016 high cannot-tell |
| 128 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 129 | nothing | OBAAF-GHA-016 high cannot-tell |
| 130 | nothing | OBAAF-GHA-016 high cannot-tell |
| 131 | nothing | OBAAF-GHA-016 high cannot-tell |
| 132 | nothing | OBAAF-GHA-016 high cannot-tell |
| 133 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 134 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 135 | nothing | OBAAF-GHA-016 high cannot-tell |
| 136 | nothing | OBAAF-GHA-016 high cannot-tell |
| 137 | nothing | OBAAF-GHA-016 high cannot-tell |
| 138 | nothing | OBAAF-GHA-016 high cannot-tell |
| 139 | nothing | OBAAF-GHA-016 high cannot-tell |
| 140 | nothing | nothing |
| 141 | nothing | OBAAF-GHA-016 high cannot-tell |
| 142 | nothing | OBAAF-GHA-016 high cannot-tell |
| 143 | nothing | OBAAF-GHA-016 high cannot-tell |
| 144 | nothing | OBAAF-GHA-016 high cannot-tell |
| 145 | nothing | OBAAF-GHA-016 high cannot-tell |
| 146 | nothing | OBAAF-GHA-016 high cannot-tell |
| 147 | nothing | OBAAF-GHA-016 medium provenance-only |
| 148 | nothing | nothing |
| 149 | nothing | nothing |
| 150 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 151 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 152 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 153 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 154 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 155 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 156 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 157 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 158 | nothing | nothing |
| 159 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 160 | OBAAF-GHA-016 high unchecked | nothing |
| 161 | OBAAF-GHA-016 high unchecked | nothing |
| 162 | nothing | OBAAF-GHA-016 high unchecked |
| 163 | nothing | OBAAF-GHA-016 high unchecked |
| 164 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 165 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 166 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 167 | nothing | nothing |
| 168 | nothing | nothing |
| 169 | nothing | OBAAF-GHA-016 high unchecked |
| 170 | nothing | OBAAF-GHA-016 high unchecked |
| 171 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 172 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 173 | nothing | nothing |
| 174 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 175 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 176 | nothing | nothing |
| 177 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 178 | nothing | OBAAF-GHA-016 high cannot-tell |
| 179 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 180 | nothing | OBAAF-GHA-016 high cannot-tell |
| 181 | nothing | OBAAF-GHA-016 high cannot-tell |
| 182 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 183 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 184 | OBAAF-GHA-016 high unchecked | nothing |
| 185 | OBAAF-GHA-016 high unchecked | nothing |
| 186 | OBAAF-GHA-016 high unchecked | nothing |
| 187 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 188 | OBAAF-GHA-016 high unchecked | nothing |
| 189 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 190 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 191 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 192 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 193 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 194 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 195 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 196 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 197 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 198 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked, OBAAF-GHA-017 medium |
| 199 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 200 | OBAAF-GHA-016 medium provenance-only | OBAAF-GHA-016 high cannot-tell, OBAAF-GHA-017 medium |
| 201 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 202 | nothing | nothing |
| 203 | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high |
| 204 | nothing | OBAAF-GHA-021 high unchecked |
| 205 | nothing | OBAAF-GHA-021 high unchecked |
| 206 | nothing | OBAAF-GHA-021 high unchecked |
| 207 | OBAAF-GHA-021 medium no-proposal | OBAAF-GHA-021 medium no-proposal |
| 208 | nothing | OBAAF-GHA-021 high unchecked |
| 209 | nothing | OBAAF-GHA-021 high unchecked |
| 210 | nothing | OBAAF-GHA-021 high unchecked |
| 211 | nothing | OBAAF-GHA-021 high unchecked |
| 212 | OBAAF-GHA-022 high | OBAAF-GHA-022 high |
| 213 | nothing | OBAAF-GHA-022 high |
| 214 | OBAAF-GHA-022 high | OBAAF-GHA-022 high |
| 215 | nothing | OBAAF-GHA-022 high |
| 216 | nothing | OBAAF-GHA-022 high |
| 217 | nothing | OBAAF-GHA-022 high |
| 218 | OBAAF-GHA-022 high | OBAAF-GHA-022 high |
| 219 | nothing | OBAAF-GHA-022 high |
| 220 | OBAAF-GHA-022 high | OBAAF-GHA-022 high |
| 221 | nothing | OBAAF-GHA-022 high |
| 222 | nothing | OBAAF-GHA-022 high |
| 223 | nothing | OBAAF-GHA-022 high |
| 224 | nothing | nothing |
| 225 | nothing | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high |
| 226 | nothing | nothing |
| 227 | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high |
| 228 | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high |
| 229 | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high |
| 230 | nothing | nothing |
| 231 | nothing | OBAAF-GHA-022 high |
| 232 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 233 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 234 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 235 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high unchecked |
| 236 | OBAAF-GHA-016 high unchecked | OBAAF-GHA-016 high cannot-tell |
| 237 | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high |
| 238 | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high | OBAAF-GHA-021 high unchecked, OBAAF-GHA-022 high |
| 239 | OBAAF-GHA-016 high unchecked, OBAAF-GHA-016 medium provenance-only, OBAAF-GHA-017 medium | OBAAF-GHA-016 high unchecked, OBAAF-GHA-016 medium provenance-only, OBAAF-GHA-017 medium |
| 240 | nothing | OBAAF-GHA-021 high unchecked |
| 241 | nothing | nothing |
| 242 | nothing | OBAAF-GHA-016 high cannot-tell |
| 243 | nothing | OBAAF-GHA-016 high cannot-tell |
| 244 | nothing | OBAAF-GHA-016 high cannot-tell |

## 2d.2f: pins, egress and declarations

Run `shoveler`, 2026-11-15, on a copy of `flagship` at `1a8075b`. Two Opus 5.5 reviewers that did not write the code attacked the five workflow rules no earlier tranche took, in parallel: reviewer A OBAAF-GHA-008, 009 and 023 (147 attempts: 38 ways past, 14 of them not verified, 3 weaker cases, 8 false positives, 5 tracebacks, 93 held), reviewer B OBAAF-GHA-020 and OBAAF-CFG-001 (160 attempts: 50 ways past, 14 of them not verified, 1 false positive, 109 held). The classes were then fixed, and every attempt was run again with the old and the new checker; the two tables at the end of this section are that run, generated from the attempt directories. Expectrail at `8321b17` (a read-only copy of `.github` and `AGENTS.md`, `fresh-*` left out unread) gives the same 43 findings, with the same identities, with both.

GitHub's documentation was read for the workflow syntax and contexts (by reviewer A). Two facts were read on 2026-11-15 from primary pages, and both changed the work: the native egress firewall's README ([github-early-access/actions-native-egress-firewall](https://github.com/github-early-access/actions-native-egress-firewall)) describes enforcement in its technical preview ("Deny all by default in `enforce` mode"), exactly three policy keys (`mode`, `allow`, `no-default-urls`), a format that "may change", and default endpoints that include `github.com`; and GitHub's changelog of [2026-07-30](https://github.blog/changelog/2026-07-30-reference-same-repository-actions-with-self-repository-syntax) introduced `uses: $/path`, the workflow's own repository at the running commit. Reviewer B had found only a third-party page that called the firewall audit-only; that page is out of date, and the README was read before anything was credited or withdrawn.

### OBAAF-GHA-008 Action, reusable workflow or image not pinned

**Got through, now fixed.**

- **An image written as an expression was skipped** (025 to 030, 032, 133): `container: ${{ matrix.image }}`, `node:${{ matrix.v }}`, an image with `${{ '' }}` at its end, a service's image from `vars`. Every image is now read. One that is exactly `${{ matrix.x }}` with the matrix written out in the file is read value by value (the reader 2d.7 wrote for runner labels); any other is reported as kind `image-expression`, at the job's severity.
- **Forms of `container` and `services` that were not read** (033, 034, 037, 128, 129, 131, 147): a service written as text, `Image:`, `Container:` or `Services:` in another letter case, a number, services as a list. One function now reads the container and every service; text is an image, and anything else is kind `image-unreadable`. GitHub may refuse some of these files (not verified); none is taken for "no image".
- **A 64-digit ref counted as a commit** (004, 005, 006): github.com has no SHA-256 repositories, so such a ref can only be a tag or a branch. A pin is now 40 hexadecimal digits in lower case, matched in full (the old pattern's `$` also took a ref ending in a line break, 009). An image's digest must be `@sha256:` and 64 hexadecimal digits at its end; before, the text `@sha256:` anywhere counted.
- **A `./` action loaded from another repository** (013, 014, 145): a checkout of `someorg/actions` at `main` (or at its default branch) into `ext`, then `uses: ./ext/deploy`, runs that repository's code at a ref that moves, and was taken for the workflow's own. It is now kind `local-from-checkout`, with the repository and the ref as facts, unless the checkout's `ref` is a full commit SHA (146 is the control); paths are compared after `.` and `..` are resolved, and an absolute path or one with an expression is taken to hold the action. A `./` action after an artifact from another run or repository (`actions/download-artifact` given `run-id`, `repository` or `github-token`, or another repository's download-artifact action), a cache restored at a workspace path that holds it, or a script line that clones or downloads (`git clone`, `git worktree`, `git submodule`, `gh repo clone`, `gh release download`, `gh run download`, `curl`, `wget`, `degit`, `tar x`, `unzip`, `bsdtar`, `7z`) and names a workspace path at or under the action's top directory (not a URL), or clones a repository of that name, is kind `local-after-download`. Not followed: `git fetch` and `git merge`, `git am`, `git apply`, a target on another line or in `working-directory`, downloads before `uses: ./`, an artifact of the same run, and a cache restored at a path written with `~`, an absolute path, a glob or an expression.
- **A called workflow's severity** (050, 053, 135, weaker cases): a job in a workflow that only `workflow_call` starts was low with read-only permissions, though its callers may be started by `pull_request_target`. It is now never low.
- **Tracebacks** (138 to 142): a number of thousands of hexadecimal digits as an image or a `uses` ended the run in Python's integer-to-text limit, and one such file lost every other file's findings. Values are now turned to text with `as_text`, and a `uses` that is not text is an error of the file.

**False positives fixed.** `uses: $/.github/actions/build` and `uses: $/.github/workflows/x.yml` (011, 012), reported as "pinned to nothing"; `Docker://` in another letter case (018), reported as an action.

**False positives kept** (failing closed, not verified): a commit SHA in upper case (008), and a digest by another algorithm (`sha512`, 019).

**Under stated limits** (now in the rule's description): a local composite action's own `uses` (015; fixed by slice 2d.4b2, which reads the action's steps as the job's and reports an unpinned action or image there on that step, D-083), impostor commits (a SHA that exists only in a fork of the repository), a tag named like a 40-digit SHA, and what a pinned action fetches when it runs.

### OBAAF-GHA-009 Token permissions not declared

Every odd `permissions` value already failed the file; keys in another case, look-alike keys and keys in the wrong place were reported. **Got through, now fixed**, all classes shared with every rule:

- **Job ids that collide as text** (044, 045, 092, 103): `null:` and `None:`, `true:` and `"True"`. This YAML reader (1.1) gives `None` and `True`, whose text is the other job's id, so the first job was replaced and vanished from every rule and from `--lanes`. A job id that is not text, and two ids the checker reads as one, are now errors of the file; both jobs are checked (`null` is named as YAML writes it).
- **Workflow files the checker did not find** (074, 075, 104, 120): `.github/workflows/.yml` (Python gives it no suffix) and `wf.YML`. Files are now found with the extension in any letter case. Whether GitHub runs them is not verified.
- **A merge key** (082, 083, 038): `<<: {permissions: {}}` at the top was merged by this reader, and a YAML 1.2 reader would take it for a key named `<<`. A merge key anywhere in a workflow is now an error of the file.

**Kept, on purpose** (127): an acceptance of OBAAF-GHA-009 for a push-only job still covers it after `pull_request_target` is added. The finding is the missing declaration; what a trigger adds is reported by the rules about triggers, with their own identities, and adding the triggers here would make every existing acceptance new for no new risk.

### OBAAF-GHA-023 Template placeholder left in a workflow

**Got through, now fixed.** The rule searched the file's text. A placeholder written with an escape (`OBAAF\x5FOWNER`, `_`, `\U0000005F`, `\x30` in the SHA, `\x40` for `@`, 106 to 112, 123), split by a backslash at the end of a line inside double quotes (108, 110), or in lower case (113) was not found. Values are now read as YAML gives them, `OBAAF_OWNER` in any case and the all-zero SHA as exactly 40 zeros after `@` or as a `uses` ref.

**Acceptance** (124, 125): one finding per file, named only by the placeholder, so a baseline written while the placeholder was in a comment covered a real `uses: OBAAF_OWNER/...` added later. Each placeholder is now its own finding, with the job, the step and the key (`steps[1].uses`) as facts.

**False positives fixed.** A placeholder in a comment (114), which GitHub never reads, and 41 zeros (116). **Kept:** a placeholder in a script's text (115), which may be a value the script uses.

### OBAAF-GHA-020 Agent job without an egress restriction

**Got through, now fixed.**

- **The agent was not found, so there was no finding at all** (279 to 285): the egress action with a trailing or doubled slash, from a fork, or copied into the repository; an agent CLI in another action's `command` input; in a `docker://` step's arguments; spelt `cl''aude -p` or `cl\aude -p`. Only the run script, a github-script script and the `run` of OBAAF's own action were read. The agent is now looked for in each command in any input a step gives an action, a `docker://` step's entrypoint and arguments, the step's `shell` and `env` values and the default shell, where the command's first word (after assignments, wrappers such as `sudo -u user`, `npx`, `nice -n 10` or `timeout 5m`, and a shell's `-c`) is an agent's, and the run script with the step's env values put in (`$AGENT -p`); and the scripts read before are also read with lines joined and quotes and backslashes taken out. A fork or copy of the action is not OBAAF's, so the finding is reported plainly; it never clears.
- **The firewall's policy read narrowly** (211 to 214): `mode: enforce` beside `MODE: log`, `Allow:` beside `allow:`, `allow-ips`, `overrides`. A key other than the README's three, or one of them in another letter case, is now "cannot tell".
- **What may follow the confined command** (236): `actions/upload-artifact/../../../evil/act/v1@v4` was taken for upload-artifact (the path was normalised, then matched by prefix). Only `actions/upload-artifact` or `actions/upload-artifact/merge`, at a path with no `.`, `..` or empty part, may follow now.
- **The scratch directory named by a pattern** (237, 239): `/t[m]p/obaaf-e*` in a cache's path and `$(dirname $(mktemp -u))` in an earlier step. A value names /tmp now also when quotes, backslashes and repeated slashes are taken out, when a top-level part of a path is a pattern or an expansion, and when it asks for a temporary directory by name (`mktemp`, `TMPDIR`, `tempfile`).
- **Processes left running** (241 to 245): `pm2`, `ssh -f`, `sudo -b`, `os.fork()` in Python, `systemctl start`, `dockerd`. The list now has service and process managers, `ssh -f` and `-N`, `ssh-agent`, `socat`, `sudo -b`, the container daemons, `crontab`, and the words a script language forks or spawns with, in any letter case. It is still a list.
- **The agent outside the confined command, with a key by another route** (251, 252, 254, 360): `vars.ANTHROPIC_API_KEY`, a job output, a `docker://` step, github-script. An agent the checker now recognises there is "not met" (252 by the backslash reading, 254 by the arguments); a value given outside the confined command whose name says it may be a credential (`vars.*KEY*`, a job's or step's output named like a token, `toJSON(vars)`, an `env` name of a model key given text) is "cannot tell".

**False positive fixed.** The firewall's label written twice (209) was "cannot tell".

**Not fixed, and stated in the rule's description:** a self-hosted runner given the firewall's label (228; a cleared finding now says the label is taken at its word), an agent run by `npm run` (287), a remote reusable workflow (295) or a local composite action (296, slice 2d.4), code in an earlier action's post step that does not name /tmp, what a later job does with the uploaded artifact (356; OBAAF-GHA-021 and 022), and upload-artifact pinned to an impostor commit (357). **Not a way past:** the firewall's default endpoints (215) are GitHub-managed URLs from its `/meta` endpoint, not a wildcard over Azure storage (README, 2026-11-15); a cleared finding now names them, `github.com` first.

### OBAAF-CFG-001 Lane declaration that does nothing

**Got through, now fixed.**

- **Other spellings** (305 to 311): a zero-width space, a Cyrillic `О`, `OBAAFLANE`, `OBAAF.LANE`, `OBAAF_LANES`, `OBAAF_LANE_`. A name is now another spelling when what it looks like (compatibility forms folded, invisible characters out, look-alike letters and digits mapped, only letters kept, in upper case) is `OBAAFLANE` or one edit from it. `MY_OBAAF_LANE`, `OBAAF_STEP` and `OBAAF_EGRESS` are not.
- **Other spellings where the variable is not read** (313 to 315): a step's, container's or service's env. Reported as `elsewhere`.
- **Places the list did not name** (317 to 320): an `env` written as one expression, a step's `with`, a matrix key, a called workflow's `with`; also a script that writes it to `GITHUB_ENV` (2d.2a's item 4). The whole workflow is walked for the name, and each is the new case `elsewhere` (`workflow-elsewhere` outside the jobs). A definition under the name (a `workflow_call` input written as a mapping) is not a declaration.
- **A configuration file ignored without a word** (335, 337, and 336 weak): `.github/obaaf.yml` beside `obaaf.yml` or `.github/obaaf.yaml`, and `.obaaf.yml`. Two configurations, or a file named like one where the checker does not look, are a configuration error (exit status 2).
- **Jenkins** (347, 348, 350): `environment { obaaf_lane = ... }`, `withEnv(['OBAAF-LANE=...'])` and `script { env.OBAAF_LANE = ... }`. The first two are `jenkins-misnamed`, the third `jenkins-scripted`; D-044 had named them as unreported.

**Changed from 2a.4's tests.** Two tests encoded what was a way past: `OBAAF_LANES` and `OBAAFLANE` were "not a spelling", and an action input named `OBAAF_LANE` was "not an env". They now expect the findings.

### Review

One Opus 5.5 reviewer that did not write the code reviewed the slice. Its first pass found the full suite green, Expectrail's 43 findings unchanged, and six blocking findings, each fixed and tested in `tests/test_pins_egress_declaration_bypasses.py`:

1. **Slow paths.** The first version's download pattern (`\bgit\b[^\n]*\b(clone|...)`) and the new `ssh` and `sudo` parts of the process pattern were quadratic: 37 s on a 12 KB line repeating `gh repo`, 10 s on 96 KB of `ssh `. Both are now read word by word on each line; the same inputs take under a second.
2. **False positives of `local-after-download`** on common workflows: a cache with a multi-line path (`~/.cargo/registry`), `unzip` into `$HOME/.local`, `git checkout -b`, `git submodule update`, `git config ... safe.directory`, and any artifact download. The rule now names only what can bring code from outside the run's commit over the action's path (see above).
3. **False positives of the agent reading**: every action input was searched with the agent patterns, and `aider` and `cline` are ordinary words ("vous aider bientôt" in a French comment made a stale-bot job an agent job, high OBAAF-GHA-003). Inputs are now read as commands, and only a command whose first word is an agent's counts.
4. **Paths not resolved** in `local-from-checkout`: `path: ./ext/../ext2`, an absolute path, and `uses: ./.github/../ext/deploy` got past it.
5. **A document claim the code contradicted**: the description said "clones, downloads or unpacks", and `curl -o`, `gh release download`, `degit` and another repository's artifact were not reported. The commands are now listed in the description, and those named are reported.
6. **An empty image** (`include: [{container: ''}]`, the usual way to run some matrix rows on the runner) was reported as unpinned. It is no container now; that GitHub reads it so is not verified.

Also fixed from its non-blocking points: `_credential_like` no longer takes `author` or `cache-key` for a credential; the process words are matched as written (lower case), and `org.gradle.daemon=false` is not a daemon; an agent as a step's `shell`, the default shell or an `env` value run as `$AGENT` is found; the job-id test now has a finding in the second job; a placeholder in both a key and its value is one finding; a single `.github/OBAAF.yml` on a file system that ignores case is the file the checker reads, not a look-alike; a name of any length is compared. Kept, and stated: `echo "no daemon here"` and `--grep spawn` count as leaving a process (failing closed); Cherokee look-alike letters are not mapped.

A second pass, on the fixes, found the full suite green, Expectrail unchanged, every first-pass case answered, and three blocking findings, each fixed and tested: (1) `uses: ./` after any download was `local-after-download` (the top directory was empty, and the empty text is in every line); downloads before an action at the workspace root are now not read, and say so; (2) a top directory found inside a URL (`https://raw.githubusercontent.com/myorg/.github/...`) counted; only a workspace path at or under it counts now, or a clone of a repository of that name; (3) an agent behind `bash -c`, `sh -lc` in a `docker://` step, `sudo -u runner`, `nice -n 10` or `timeout -s KILL 5m` was in no lane: a shell's `-c` argument is read again as commands, and the values of a wrapper's options are skipped. Also from its non-blocking points: `run: $AGENT -p` with `env: {AGENT: claude}` is found (the step's env put into the script); the guide says configured agent patterns count only at the start of a command outside scripts. Kept, and stated: a line of free text that begins with an agent's name and the words its pattern needs (`aider and cline are supported` at the start of a release body) is read as a command; a cache path written as a glob, and a download's target on another line, are not followed. A third pass, on those fixes, found two blocking findings, fixed and tested: `git clone --depth 1 URL` and `git clone -b main URL` got past the clone check (an option's value was taken for a folder), so the values of git's value-taking options are skipped and `gh repo clone` is read the same way; and the step's env values put into its script were searched anywhere, so prose in an env value (`--notes "$NOTES"` with "works with aider and cline") made an agent job: the result is now read as commands, like an input. From its non-blocking points, a fetch and its target are paired within one command, not one line. Kept, and stated: only the step's own `env` is put into its script, and a fourth nested `bash -c` is not read. A fourth pass found nothing blocking: every earlier case answered, the substituted script adding matches and never removing one, no slow path in the new readers (400 KB lines in under 2 s), the full suite green and Expectrail unchanged. Left from it, not blocking: `git clone --ref-format reftable URL` (an option that takes a value and is not on the list) gets past the clone-by-name check, and `env: {MODEL: claude}` with `llm --model $MODEL -p` is not an agent job. Found, outside this slice: a 105 KB `run:` of `claude ` repeated takes 23 s with the old checker and this one, in the catalog's agent patterns, and a 48 KB line of `curl actions/x; ` repeated takes 3.2 s in the upload patterns, with the old checker too: issue #179.

### What changed for adopters

- A gate can fail where it passed: a 64-digit ref, an image written as an expression, a service written as text, a `./` action from another repository, a called workflow's unpinned action at medium, a placeholder with an escape or in lower case, an agent given to another action or spelt with quotes, a firewall policy with another key, a step after the egress action that is not exactly upload-artifact, a cache or process that may reach the scratch directory, a key-named variable outside the confined command, a lane variable in another spelling or place, a second configuration, a merge key or a job id that is not text.
- Every v0.2 acceptance of OBAAF-GHA-023 needs accepting again: the place is now a fact. Acceptances of the other four rules keep their identity where the finding did not change.
- Some findings go away: `$/` references, a placeholder in a comment, 41 zeros, the firewall label written twice.
- No change on this repository or on Expectrail.

#### Every attempt of reviewer A (OBAAF-GHA-008, 009, 023), before and after the fixes

What the checker reported for the attempt's rule on each attempt's workflow, with the checker before slice 2d.2f and after it, review fixes included. "(cannot-tell)" and "(fixed)" are the finding's state; "+ file error" means the file is also reported as an error, which fails the check. The attempt numbers are the ones used above.

| # | Rule | Before | Now |
| --- | --- | --- | --- |
| 001 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 002 | GHA-008 | OBAAF-GHA-008 high action | OBAAF-GHA-008 high action |
| 003 | GHA-008 | nothing | nothing |
| 004 | GHA-008 | nothing | OBAAF-GHA-008 medium action |
| 005 | GHA-008 | nothing | OBAAF-GHA-008 high action |
| 006 | GHA-008 | nothing | OBAAF-GHA-008 medium reusable-workflow |
| 007 | GHA-008 | OBAAF-GHA-008 medium reusable-workflow | OBAAF-GHA-008 medium reusable-workflow |
| 008 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 009 | GHA-008 | nothing | OBAAF-GHA-008 medium action |
| 010 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 011 | GHA-008 | OBAAF-GHA-008 medium action | nothing |
| 012 | GHA-008 | OBAAF-GHA-008 low reusable-workflow | nothing |
| 013 | GHA-008 | nothing | OBAAF-GHA-008 medium local-from-checkout |
| 014 | GHA-008 | nothing | OBAAF-GHA-008 medium local-from-checkout |
| 015 | GHA-008 | nothing | nothing |
| 016 | GHA-008 | OBAAF-GHA-008 medium container | OBAAF-GHA-008 medium container |
| 017 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium container |
| 018 | GHA-008 | OBAAF-GHA-008 medium action | nothing |
| 019 | GHA-008 | OBAAF-GHA-008 medium container | OBAAF-GHA-008 medium container |
| 020 | GHA-008 | nothing | nothing |
| 021 | GHA-008 | nothing | OBAAF-GHA-008 medium container |
| 022 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 023 | GHA-008 | nothing | OBAAF-GHA-008 medium container |
| 024 | GHA-008 | OBAAF-GHA-008 medium image | OBAAF-GHA-008 medium image |
| 025 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 026 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 027 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 028 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 029 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 030 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 031 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 032 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 033 | GHA-008 | nothing | OBAAF-GHA-008 medium image |
| 034 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 035 | GHA-008 | OBAAF-GHA-008 medium image | OBAAF-GHA-008 medium image |
| 036 | GHA-008 | OBAAF-GHA-008 medium image | OBAAF-GHA-008 medium image |
| 037 | GHA-008 | nothing | OBAAF-GHA-008 medium image-unreadable |
| 038 | GHA-008 | nothing | OBAAF-GHA-008 medium image + file error |
| 039 | GHA-008 | OBAAF-GHA-008 medium image | OBAAF-GHA-008 medium image |
| 040 | GHA-008 | OBAAF-GHA-008 medium image | OBAAF-GHA-008 medium image |
| 041 | GHA-008 | nothing | nothing |
| 042 | GHA-008 | nothing | OBAAF-GHA-008 medium image |
| 043 | GHA-008 | OBAAF-GHA-008 medium image | OBAAF-GHA-008 medium image |
| 044 | GHA-008 | nothing | OBAAF-GHA-008 medium action + file error |
| 045 | GHA-008 | nothing | OBAAF-GHA-008 medium action + file error |
| 046 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 047 | GHA-008 | nothing | nothing |
| 048 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 049 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 050 | GHA-008 | OBAAF-GHA-008 low action | OBAAF-GHA-008 medium action |
| 051 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 052 | GHA-008 | OBAAF-GHA-008 low action | OBAAF-GHA-008 low action |
| 053 | GHA-008 | OBAAF-GHA-008 low image | OBAAF-GHA-008 medium image |
| 054 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 055 | GHA-008 | OBAAF-GHA-008 low action | OBAAF-GHA-008 low action |
| 056 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 057 | GHA-008 | OBAAF-GHA-008 medium reusable-workflow | OBAAF-GHA-008 medium reusable-workflow |
| 058 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 059 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 060 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 061 | GHA-008 | nothing + file error | nothing + file error |
| 062 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 063 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 064 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 065 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 066 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action + file error |
| 067 | GHA-008 | nothing + file error | nothing + file error |
| 068 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action + file error |
| 069 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 070 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 071 | GHA-008 | nothing + file error | nothing + file error |
| 072 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 073 | GHA-008 | OBAAF-GHA-008 medium container | OBAAF-GHA-008 medium container |
| 074 | GHA-008 | nothing | OBAAF-GHA-008 medium action |
| 075 | GHA-008 | nothing | OBAAF-GHA-008 medium action |
| 076 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 077 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 078 | GHA-008 | nothing + file error | nothing + file error |
| 079 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 080 | GHA-009 | nothing | nothing |
| 081 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 082 | GHA-009 | nothing | nothing + file error |
| 083 | GHA-009 | nothing | nothing + file error |
| 084 | GHA-009 | nothing | nothing |
| 085 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 086 | GHA-009 | nothing + file error | nothing + file error |
| 087 | GHA-009 | nothing + file error | nothing + file error |
| 088 | GHA-009 | nothing + file error | nothing + file error |
| 089 | GHA-009 | nothing | nothing |
| 090 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 091 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 092 | GHA-009 | nothing | OBAAF-GHA-009 medium + file error |
| 093 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 094 | GHA-009 | nothing | nothing |
| 095 | GHA-009 | nothing | nothing |
| 096 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 097 | GHA-009 | nothing + file error | nothing + file error |
| 098 | GHA-009 | nothing + file error | nothing + file error |
| 099 | GHA-009 | nothing + file error | nothing + file error |
| 100 | GHA-009 | nothing | nothing |
| 101 | GHA-009 | nothing | nothing |
| 102 | GHA-009 | nothing + file error | nothing + file error |
| 103 | GHA-009 | nothing | OBAAF-GHA-009 medium + file error |
| 104 | GHA-009 | nothing | OBAAF-GHA-009 medium |
| 105 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 106 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 107 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 108 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 109 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 110 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 111 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 112 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 113 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 114 | GHA-023 | OBAAF-GHA-023 high | nothing |
| 115 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 116 | GHA-023 | OBAAF-GHA-023 high | nothing |
| 117 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 118 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 119 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 120 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 121 | GHA-023 | nothing | nothing |
| 122 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 123 | GHA-023 | nothing | OBAAF-GHA-023 high |
| 124 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 125 | GHA-023 | OBAAF-GHA-023 high | OBAAF-GHA-023 high |
| 126 | GHA-008 | OBAAF-GHA-008 medium action | OBAAF-GHA-008 medium action |
| 127 | GHA-009 | OBAAF-GHA-009 medium | OBAAF-GHA-009 medium |
| 128 | GHA-008 | nothing | OBAAF-GHA-008 medium image-unreadable |
| 129 | GHA-008 | nothing | OBAAF-GHA-008 medium image-unreadable |
| 130 | GHA-008 | nothing | nothing |
| 131 | GHA-008 | nothing | OBAAF-GHA-008 medium image-unreadable |
| 132 | GHA-008 | nothing + file error | nothing + file error |
| 133 | GHA-008 | nothing | OBAAF-GHA-008 medium image-expression |
| 134 | GHA-008 | nothing | OBAAF-GHA-008 medium image |
| 135 | GHA-008 | OBAAF-GHA-008 low reusable-workflow | OBAAF-GHA-008 medium reusable-workflow |
| 136 | GHA-008 | OBAAF-GHA-008 medium reusable-workflow | OBAAF-GHA-008 medium reusable-workflow |
| 137 | GHA-008 | nothing | OBAAF-GHA-008 medium container |
| 138 | GHA-008 | traceback (ValueError: Exceeds the limit (4300 digits) for integer string conversion; use s) | OBAAF-GHA-008 medium image-unreadable |
| 139 | GHA-008 | traceback (ValueError: Exceeds the limit (4300 digits) for integer string conversion; use s) | OBAAF-GHA-008 medium image-unreadable |
| 140 | GHA-008 | traceback (ValueError: Exceeds the limit (4300 digits) for integer string conversion; use s) | OBAAF-GHA-008 medium action + file error |
| 141 | GHA-008 | traceback (ValueError: Exceeds the limit (4300 digits) for integer string conversion; use s) | nothing + file error |
| 142 | GHA-008 | traceback (ValueError: Exceeds the limit (4300 digits) for integer string conversion; use s) | OBAAF-GHA-008 medium action + file error |
| 143 | GHA-008 | nothing | nothing |
| 144 | GHA-008 | nothing + file error | nothing + file error |
| 145 | GHA-008 | nothing | OBAAF-GHA-008 medium local-after-download |
| 146 | GHA-008 | nothing | nothing |
| 147 | GHA-008 | nothing | OBAAF-GHA-008 medium image-unreadable |

#### Every attempt of reviewer B (OBAAF-GHA-020, OBAAF-CFG-001), before and after the fixes

What the checker reported for the attempt's rule on each attempt's workflow, with the checker before slice 2d.2f and after it, review fixes included. "(cannot-tell)" and "(fixed)" are the finding's state; "+ file error" means the file is also reported as an error, which fails the check. The attempt numbers are the ones used above.

| # | Rule | Before | Now |
| --- | --- | --- | --- |
| 201 | GHA-020 | nothing | nothing |
| 202 | GHA-020 | nothing | nothing |
| 203 | GHA-020 | OBAAF-GHA-020 low none | OBAAF-GHA-020 low none |
| 204 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 205 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 206 | GHA-020 | OBAAF-GHA-020 low firewall-runner | OBAAF-GHA-020 low firewall-runner |
| 207 | GHA-020 | OBAAF-GHA-020 low firewall-runner | OBAAF-GHA-020 low firewall-runner |
| 208 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 209 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | nothing |
| 210 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 211 | GHA-020 | nothing | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 212 | GHA-020 | nothing | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 213 | GHA-020 | nothing | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 214 | GHA-020 | nothing | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 215 | GHA-020 | nothing | nothing |
| 216 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 217 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 218 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 219 | GHA-020 | nothing | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 220 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 221 | GHA-020 | nothing | nothing |
| 222 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 223 | GHA-020 | nothing | nothing |
| 224 | GHA-020 | OBAAF-GHA-020 low firewall-runner | OBAAF-GHA-020 low firewall-runner |
| 225 | GHA-020 | nothing | nothing |
| 226 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 227 | GHA-020 | nothing | nothing |
| 228 | GHA-020 | nothing | nothing |
| 229 | GHA-020 | nothing | nothing |
| 230 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 231 | GHA-020 | OBAAF-GHA-020 low firewall-runner (cannot-tell) | OBAAF-GHA-020 low firewall-runner (cannot-tell) |
| 232 | GHA-020 | nothing | nothing |
| 233 | GHA-020 | nothing | nothing |
| 234 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 235 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 236 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 237 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 238 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 239 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action |
| 240 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 241 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 242 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 243 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 244 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 245 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 246 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 247 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 248 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 249 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 250 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 251 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 252 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action |
| 253 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 254 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action |
| 255 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 256 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 257 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 258 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 259 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 260 | GHA-020 | nothing | nothing |
| 261 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 262 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 263 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 264 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 265 | GHA-020 | nothing | nothing |
| 266 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 267 | GHA-020 | nothing | nothing |
| 268 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 269 | GHA-020 | OBAAF-GHA-020 low egress-action (cannot-tell) | OBAAF-GHA-020 low egress-action (cannot-tell) |
| 270 | GHA-020 | nothing | nothing |
| 271 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 272 | GHA-020 | nothing | nothing |
| 273 | GHA-020 | nothing + file error | nothing + file error |
| 274 | GHA-020 | nothing | nothing |
| 275 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 276 | GHA-020 | nothing | nothing |
| 277 | GHA-020 | nothing | nothing |
| 278 | GHA-020 | nothing | nothing |
| 279 | GHA-020 | nothing | OBAAF-GHA-020 low none |
| 280 | GHA-020 | nothing | OBAAF-GHA-020 low none |
| 281 | GHA-020 | nothing | OBAAF-GHA-020 low none |
| 282 | GHA-020 | nothing | OBAAF-GHA-020 low none |
| 283 | GHA-020 | nothing | OBAAF-GHA-020 low none |
| 284 | GHA-020 | nothing | OBAAF-GHA-020 low none |
| 285 | GHA-020 | nothing | OBAAF-GHA-020 low none |
| 286 | GHA-020 | OBAAF-GHA-020 low none | OBAAF-GHA-020 low none |
| 287 | GHA-020 | nothing | nothing |
| 288 | GHA-020 | OBAAF-GHA-020 low none | OBAAF-GHA-020 low none |
| 289 | GHA-020 | nothing | nothing |
| 290 | GHA-020 | nothing | nothing |
| 291 | GHA-020 | OBAAF-GHA-020 low unverified-monitor (cannot-tell) | OBAAF-GHA-020 low unverified-monitor (cannot-tell) |
| 292 | GHA-020 | OBAAF-GHA-020 low unverified-monitor (cannot-tell) | OBAAF-GHA-020 low unverified-monitor (cannot-tell) |
| 293 | GHA-020 | OBAAF-GHA-020 low declared | OBAAF-GHA-020 low declared |
| 294 | GHA-020 | OBAAF-GHA-020 low awf (cannot-tell) | OBAAF-GHA-020 low awf (cannot-tell) |
| 295 | GHA-020 | nothing | nothing |
| 296 | GHA-020 | nothing | nothing |
| 297 | GHA-020 | OBAAF-GHA-020 low firewall-runner | OBAAF-GHA-020 low firewall-runner |
| 298 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 299 | GHA-020 | OBAAF-GHA-020 low firewall-runner | OBAAF-GHA-020 low firewall-runner |
| 300 | GHA-020 | OBAAF-GHA-020 low egress-action | OBAAF-GHA-020 low egress-action |
| 301 | CFG-001 | OBAAF-CFG-001 high job-not-a-lane | OBAAF-CFG-001 high job-not-a-lane |
| 302 | CFG-001 | OBAAF-CFG-001 high job-not-a-lane | OBAAF-CFG-001 high job-not-a-lane |
| 303 | CFG-001 | OBAAF-CFG-001 high job-not-a-lane | OBAAF-CFG-001 high job-not-a-lane |
| 304 | CFG-001 | OBAAF-CFG-001 high job-misnamed | OBAAF-CFG-001 high job-misnamed |
| 305 | CFG-001 | nothing | OBAAF-CFG-001 high job-misnamed |
| 306 | CFG-001 | nothing | OBAAF-CFG-001 high job-misnamed |
| 307 | CFG-001 | nothing | OBAAF-CFG-001 high job-misnamed |
| 308 | CFG-001 | nothing | OBAAF-CFG-001 high job-misnamed |
| 309 | CFG-001 | nothing | OBAAF-CFG-001 high job-misnamed |
| 310 | CFG-001 | nothing | OBAAF-CFG-001 high job-misnamed |
| 311 | CFG-001 | nothing | OBAAF-CFG-001 high workflow-misnamed |
| 312 | CFG-001 | OBAAF-CFG-001 high step-env | OBAAF-CFG-001 high step-env |
| 313 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 314 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 315 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 316 | CFG-001 | OBAAF-CFG-001 high container-env | OBAAF-CFG-001 high container-env |
| 317 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 318 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 319 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 320 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 321 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 322 | CFG-001 | nothing | nothing |
| 323 | CFG-001 | nothing | nothing |
| 324 | CFG-001 | OBAAF-CFG-001 high job-not-a-lane | OBAAF-CFG-001 high job-not-a-lane |
| 325 | CFG-001 | OBAAF-CFG-001 low step-env | OBAAF-CFG-001 low step-env |
| 326 | CFG-001 | OBAAF-CFG-001 high entry-no-job | OBAAF-CFG-001 high entry-no-job |
| 327 | CFG-001 | OBAAF-CFG-001 high entry-no-file | OBAAF-CFG-001 high entry-no-file |
| 328 | CFG-001 | OBAAF-CFG-001 high entry-not-a-lane | OBAAF-CFG-001 high entry-not-a-lane |
| 329 | CFG-001 | OBAAF-CFG-001 high entry-no-file | OBAAF-CFG-001 high entry-no-file |
| 330 | CFG-001 | OBAAF-CFG-001 high entry-no-job | OBAAF-CFG-001 high entry-no-job |
| 331 | CFG-001 | OBAAF-CFG-001 high entry-no-job | OBAAF-CFG-001 high entry-no-job |
| 332 | CFG-001 | OBAAF-CFG-001 high entry-no-file | OBAAF-CFG-001 high entry-no-file |
| 333 | CFG-001 | OBAAF-CFG-001 high entry-no-file | OBAAF-CFG-001 high entry-no-file |
| 334 | CFG-001 | OBAAF-CFG-001 high entry-not-a-lane | OBAAF-CFG-001 high entry-not-a-lane |
| 335 | CFG-001 | nothing | configuration error, exit 2 |
| 336 | CFG-001 | nothing | configuration error, exit 2 |
| 337 | CFG-001 | nothing | configuration error, exit 2 |
| 338 | CFG-001 | nothing | nothing |
| 339 | CFG-001 | nothing | OBAAF-CFG-001 high workflow-elsewhere + file error |
| 340 | CFG-001 | nothing | nothing |
| 341 | CFG-001 | OBAAF-CFG-001 low step-env | OBAAF-CFG-001 low step-env |
| 342 | CFG-001 | nothing | nothing |
| 343 | CFG-001 | OBAAF-CFG-001 high step-env | OBAAF-CFG-001 high step-env |
| 344 | CFG-001 | OBAAF-CFG-001 high entry-no-file | nothing |
| 345 | CFG-001 | OBAAF-CFG-001 high job-misnamed | OBAAF-CFG-001 high job-misnamed |
| 346 | CFG-001 | OBAAF-CFG-001 high jenkins-not-a-lane | OBAAF-CFG-001 high jenkins-not-a-lane |
| 347 | CFG-001 | nothing | OBAAF-CFG-001 high jenkins-misnamed |
| 348 | CFG-001 | nothing | OBAAF-CFG-001 high jenkins-scripted |
| 349 | CFG-001 | OBAAF-CFG-001 high jenkins-computed | OBAAF-CFG-001 high jenkins-computed |
| 350 | CFG-001 | nothing | OBAAF-CFG-001 high jenkins-misnamed |
| 351 | CFG-001 | OBAAF-CFG-001 high step-env | OBAAF-CFG-001 high step-env |
| 352 | CFG-001 | nothing | OBAAF-CFG-001 high elsewhere |
| 353 | CFG-001 | nothing | nothing |
| 354 | CFG-001 | OBAAF-CFG-001 low job-misnamed | OBAAF-CFG-001 low job-misnamed |
| 355 | CFG-001 | OBAAF-CFG-001 high job-not-a-lane; OBAAF-CFG-001 high step-env | OBAAF-CFG-001 high job-not-a-lane; OBAAF-CFG-001 high step-env |
| 356 | GHA-020 | nothing | nothing |
| 357 | GHA-020 | nothing | nothing |
| 358 | GHA-020 | nothing | nothing |
| 359 | GHA-020 | nothing | nothing |
| 360 | GHA-020 | nothing | OBAAF-GHA-020 low egress-action (cannot-tell) |

## 2d.2g: the settings rules

Run `wryneck`, 2026-11-15, on a copy of `flagship` at `0aa319a`. Two Opus 5.5 reviewers that did not write the settings audit attacked its fifteen rules in parallel: reviewer A OBAAF-SET-001, 002, 003, 009, 010, 011, 012, 014 and 015 (166 attempts: 9 ways past, 5 false positives, 2 slow cases, 14 under a stated limit, 136 held), reviewer B OBAAF-SET-004, 005, 006, 007, 008 and 013 (149 attempts: 22 ways past, 7 false positives, 2 slow cases, 10 under a stated limit, 108 held). A way past here is a shape GitHub's API returns, or a workflow its author writes, for which a rule said "no finding" or "does not apply" (or a lower severity than its description gives) where the settings show the problem. Every attempt was built from the hand-written `admin-token` recording (GitHub's REST reference examples) with one answer changed, and a small tree of workflow files; nothing was run against GitHub. Every way past that is fixed is a test in `tests/test_settings_bypasses.py` (62 tests after the three reviews; of the first 42, 28 of the 38 that are not about time failed on the old code and the other 10 check that ordinary cases still read as before, and of the four about time three fail on it (a RecursionError on 1,500 chained jobs, 2.8 s on the called matrix, a method it lacks) while the 40-job ladder did not finish in two minutes).

Pages read in the session (reviewer A): GitHub's reference for deployment branch policies (Ruby's `File.fnmatch`, wildcards do not match `/`, `type` is branch or tag), the changelog of 2026-11-02 on `pull_request_target` (public repositories only), the reference for Actions permissions (`sha_pinning_required`, the three approval policies, the read and write defaults), the page on reusing workflows ("can be only downgraded"), the changelogs of 2025-08-15 (SHA pinning) and 2026-10-28 (workflow lockfiles); reviewer B read the changelog of 2025-11-07 (`GITHUB_SHA` for `pull_request_target` is the default branch's latest commit). Not read, because the session's requests for them were not answered: GitHub's reference for Actions policies, "Managing GitHub Actions settings for a repository", the events page and the REST rules page. Everything else the record marks "not verified" rests on what the reviewers know.

### OBAAF-SET-001 and OBAAF-SET-002: environments

**Got through, now fixed.**

- **An environment named by a number** (A004, A028, A048): `environment: {name: 010}` was compared as `"8"` (YAML 1.1 octal) and `environment: 0o10` as `"0o10"`, where YAML 1.2, GitHub's reader, gives 10 and 8. `OBAAF-SET-001` reported the wrong name as missing, and `OBAAF-SET-002` said nothing. The audit now takes the checker's own reading of the environment, so a number, `true` or `false`, plainly or under `name:`, is "cannot tell" for both rules; a quoted name is read as written.
- **An audited branch was trusted without its rules being read** (A016, A017): the "cannot tell" for an environment limited to a branch that was not audited asked for `--branch`, and naming the branch turned it into "no finding", even when the branch had no rule at all or did not exist. A branch that was audited now counts only for what its rules show: with no rule requiring an approval, anyone with write access can push a job there that names the environment, which is a finding when the environment has no reviewers (medium, low with no secret); a limit on who may push (a ruleset's `update` rule, classic restrictions, `lock_branch`) or a `required_deployments` rule is "cannot tell", because who that lets push is not compared with who can push (the review's first pass found that the first version called such a branch closed); where the rules were not read in full (A017: the branch does not exist, and what GitHub sends for it is not read as a rule) it is "cannot tell". This holds for the default branch too, which is how the first adopter's `main-only` environment is now reported (see below).
- **A backslash in a branch policy** (A037): `ma\in` is `main` to Ruby's `File.fnmatch`, which GitHub's reference names; the rule compared names as text. A backslash now makes a policy a pattern. The case is contrived; the fix costs nothing.

**Under stated limits:** a pattern other than all stars is medium whatever it admits (A008), a tag pattern likewise (A009), a pattern with reviewers is not reported (A010), and an environment with no secret is low (A042).

### OBAAF-SET-003: where a secret is stored

**Got through, now fixed** (A053, recorded by the reviewer under a stated limit, fixed because it is the rule's own risk): a protected secret copied into a second environment that any branch may use and that asks nobody was reported by no rule, because no job named that environment. Any job on any branch can name it. It is now high. A copy in an environment with a branch pattern of only `*` and `/` counts as open too (the review's first pass); a copy in an environment with another limit or with reviewers is still not reported (stated in the rule's description).

### OBAAF-SET-004: who can bypass a branch's rules

**Got through, now fixed.**

- **The GitHub Actions app as a bypass actor** (B002, B030): an `Integration` actor with id 15368 that may always bypass lets any workflow's token push past the ruleset, and anyone who can push a branch can add a workflow there that asks for `contents: write`. It was medium; it is now high, with that reason. That the app's id is the actor's id was not verified against GitHub.
- **"exempt" read as the narrower bypass** (B011, recorded under a stated limit, fixed because the limit was wrong): GitHub's `current_user_can_bypass` says "exempt" for a bypass that is not even shown. Only "pull_requests_only" is narrower now; "always", "exempt" and any other word are the wider one.

**False positive fixed** (B017): a classic rule that requires no check and no review, not holding administrators, was reported as letting them skip "its required checks and reviews".

**Under stated limits:** a bypass only when merging a pull request is low (B003, B024, B026), a classic review allowance is medium (B004), a role counts only for exactly that role (B006).

### OBAAF-SET-005 and OBAAF-SET-013: approvals

All 32 attempts held. These rules read GitHub's answer for the rules in force on a branch, never a ruleset's `conditions`, so the ref-pattern attempts (`~DEFAULT_BRANCH`, `~ALL`, excludes, rulesets in evaluate mode) do not reach them.

### OBAAF-SET-006 to OBAAF-SET-008: required checks

**Got through, now fixed.**

- **Settings that stop every run were not read** (B152 to B155): with GitHub Actions turned off, with the only reporting job in a workflow GitHub refuses (the repository requires pinned actions and it uses `actions/checkout@v4`; `OBAAF-SET-015` said so itself), or with an enforced policy that blocks `pull_request` for the file (`OBAAF-SET-009` said so itself), `OBAAF-SET-006` said the required check is reported and `OBAAF-SET-007` that it reports on every pull request. They now read those settings: such a job reports nothing, a blocked event starts nothing, and a file GitHub may refuse or not start is never counted as reporting: an unpinned action beside a lockfile, which is not read; another repository's action or reusable workflow where `allowed_actions` is `local_only` (GitHub words it as allowing the owner's actions and reusable workflows, by the second review, not verified); a file whose events an enforced policy the audit does not understand may block; and a file that calls one GitHub does not or may not run, or one that was not read (the second and third reviews found callers of refused and missing files still counted). A finding for a check whose only job GitHub does not run needs, like every other `OBAAF-SET-006` finding, that no job's token may write checks or statuses, unless Actions is off. Where the settings were not read, the rules take every file as running, and their line in the report says so ("assumed: ..."), whatever their answers; this one is not a "cannot tell", because the settings need an administrator's token and without one every check rule would answer nothing (decision D-066).
- **Names the two YAML readers read differently** (B072 to B076, B095, B142): `name: 0` and `name: false` made the checker fall back to the job's id; `name: 012` is 10 here and 12 to GitHub, `12:30` is 750 here and text there, a matrix value `08` is text here and 8 there. A `name` that is not text, and a name or matrix value whose source YAML 1.2 reads otherwise, are now names that cannot be written out ("cannot tell"); whole numbers written plainly and quoted values are read as before.
- **Files GitHub may read otherwise** (B081 to B084): the only reporting job in `ci.YML`, in a file named `.yml`, in a symbolic link, or named through a merge key (which the checker reports as a problem of the file, and no settings rule read). Such a file's jobs are never counted as reporting now, nor is a caller of such a file, nor a file in a linked `.github` or `.github/workflows` directory; every problem the checker reports in a file counts, except one about the names of a step's inputs (the first version kept only four kinds, and the second review showed that it dropped steps and jobs GitHub refuses). Whether GitHub runs `ci.YML` or follows a link is not verified; the answer is right either way.
- **`pull_request_target` counted as reporting on the pull request** (B106): that event runs on the latest commit of the default branch (changelog of 2025-11-07, read), so its check is not on the commit the requirement waits on. Whether GitHub counts it anyway is not established, so a required check that only such a job reports is "cannot tell" for `OBAAF-SET-007`. For `OBAAF-SET-008` such a job counts as any other: a check nobody requires fails without blocking a merge whether or not it counts on the pull request (the first version made it "cannot tell" there too, which the review showed hid the incident fixture's `scan.yml#scan` finding).
- **Two jobs that report one check name** (B132, B133): GitHub weighs one check run of a name (not verified), so a failing job can be hidden by a passing one. `OBAAF-SET-008` is "cannot tell" for a required name that more than one job that may run on pull requests into the branch reports; a name nobody requires is still a finding for each job.
- **A classic rule's checks folded to one app per name** (B098, B125): a check required from another app and from GitHub Actions lost the other app's requirement. Every app is kept now. Whether GitHub lets one classic rule list a check twice is not verified.

**False positives fixed.** A plain job that `if:` skips on pull requests, or that needs such a job, was reported by `OBAAF-SET-007` as never reporting; a skipped job reports as passed, as the rule's own fix says. Reviewer B's own attempts (B103, B104) used a matrix job, and the review showed that the verdict was wrong for them: `if:` is decided before a matrix expands, so a skipped matrix job (or caller) reports its bare name and the required `test (3.13)` stays pending. Those two still give findings, correctly (not verified against GitHub). A called workflow's job with `continue-on-error: true` (B135) was asked to be required. **Kept:** a job with `if: false` (B143) and a called job that `if:` skips on pull requests (B147) are still counted by `OBAAF-SET-008`, now in the rule's description.

**Under stated limits:** the few refusals the audit knows (B080, B093), an unfiltered push counted as every pull request (B105, B119), and `concurrency` (B117, counted as a way past by the reviewer's judgement; now in the description).

### OBAAF-SET-009 and OBAAF-SET-010: Actions policies

**Got through, now fixed** (A108; and A076, a false positive): a policy's `repository_name` and `repository_id` conditions were accepted and never read, so an organisation policy that allows `pull_request_target` everywhere but this repository counted as allowing it here, and one aimed at another repository counted as blocking events here. A repository condition other than "every repository" now makes the policy "cannot tell". Whether GitHub lists such a policy for a repository it leaves out is not verified.

**Under stated limits:** how a path pattern is matched (A071, A074, A112), a `workflow_call` beside other events (A080), a policy that also restricts actors (A110).

### OBAAF-SET-011, OBAAF-SET-012 and OBAAF-SET-014

`OBAAF-SET-011` and `OBAAF-SET-014` held (`OBAAF-SET-014` under its stated limits: whether the repository has self-hosted runners, A167, A171). **False positives fixed** in `OBAAF-SET-012` (A144, A145): a called job whose only caller grants `contents: read`, and a caller whose called workflow declares its permissions, were reported as getting the repository's write default; GitHub's page on reusing workflows (read) says the called workflow "can be only downgraded". A workflow nothing here calls may be called from elsewhere and is still reported.

### OBAAF-SET-015: pinning

**Got through, now fixed** (A182, A183): the audit judged pins with the checker's old pattern, which took a 64-digit ref (a tag or a branch on github.com) and a SHA followed by a line break. It now uses the checker's pin, 40 lower-case hex digits and nothing else. **False positives fixed:** `$/path` (A186) is local; with `.github/workflows/actions.lock` (A188; GitHub's changelog of 2026-10-28, read) an action that is not pinned in the file is "cannot tell", because the lockfile may pin it and is not read. **Under stated limits:** the actions inside a local composite action (A185) or a called workflow (A194).

### Time

- **`Job.triggers` followed `needs` afresh on every path** (A200, A201, B150): 22 jobs that each need every earlier one (3 KB) took 4.5 s, 24 took 19 s, and each further job doubled it, in `obaaf audit` and in `obaaf check`, which uses the same method. Each job's answer is now worked out once per workflow, its needed jobs first and without recursion (1,500 chained jobs are read), and in a file whose `needs` form a cycle, which GitHub refuses, no job is narrowed by the jobs it needs. A 40-job ladder now takes well under a second.
- **Called matrix names were written out before the cap dropped them** (B151): 4 callers with 256 matrix combinations calling 60 jobs of 256 each took 3 s (18 s at 36 KB). The names are now counted first.

### What changed for the first adopter

Expectrail at `f7bce42` (a read-only copy of `.github` and `AGENTS.md`; nothing under `fresh-*` was read): `obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes` gives the same findings, errors and notes with the old and the new code. `obaaf audit` against GitHub's own answers recorded for it on 2026-11-13 (with and without the token the workflow had) gives one new finding: `OBAAF-SET-001`, medium, environment `main-only`, limited to `main`, which requires no approval and does not limit who may push, so any account with write access can merge an unreviewed pull request whose job names `main-only` and reads its keys. That is the same environment the brief's first incident was about, closed one level further down; whether `main` still requires no approval was not read live. No other result changed, and `OBAAF-SET-006`'s line now says ("assumed: ...") that it took every workflow file as running, because the recordings hold no Actions permissions.

### Review

One Opus 5.5 sub-agent that wrote none of it reviewed the slice. It checked the memoised `Job.triggers` against the old code on 9,000 random workflows without a cycle (the same answer every time, whatever order the jobs were asked in) and 2,000 with one (only ever wider), and that the cache cannot go stale or be shared between workflows.

- **First pass: 8 blocking findings**, all fixed and tested:
  1. `OBAAF-SET-007` took a skipped matrix job or caller for one that reports.
  2. A limit on who may push made a branch "closed" without reading who it lets push.
  3. A lockfile, and a policy the audit does not understand, left files counted as running.
  4. The doubt about a file did not reach its callers, nor files in a linked directory.
  5. The "taken as running" note vanished whenever the rule had any result; it is now its own field, `assumed`, shown on the rule's line whatever the answer.
  6. `OBAAF-SET-008` turned an unrequired `pull_request_target` check into "cannot tell".
  7. `OBAAF-SET-008` did the same for a shared name nobody requires.
  8. The finding for a stopped file skipped the test that no token may write checks.

  Of 9 non-blocking findings, these were fixed: a quadratic walk of the jobs' nodes, doubt from every checker problem (narrowed, then widened again in the second pass), `allowed_actions`, SET-003's idea of "open", two bypass modes in the docs, a muddled changelog line, and `required_deployments` read as no gate. Two are now stated limits: approvals a push does not dismiss, and job ids YAML 1.2 reads as numbers.
- **Second pass** (a fresh Opus 5.5 sub-agent, given the first pass's findings): seven of the eight fixes held, and one held only for its case. It found 4 blocking defects, all now fixed and tested:
  1. `allowed_actions: local_only` was read as "this repository only", but GitHub's own wording allows the owner's actions; it now marks the file as one GitHub may refuse.
  2. A caller of a refused file still counted as reporting.
  3. `pull_request_target` filtered by a branch pattern counted as running on every pull request.
  4. Doubt kept only four kinds of checker problem, which dropped steps and jobs GitHub refuses.

  Of 3 non-blocking findings, two were fixed: an evaluate-mode policy, or one whose events cover the file, no longer makes the file doubtful; a code owner's review makes a branch "cannot tell" for `OBAAF-SET-001`. One is left: `OBAAF-SET-007` leaves out a paths-filtered reporter in a file GitHub may not run, so that finding moves to `OBAAF-SET-006`'s "cannot tell".
- **Third pass** (a fresh Opus 5.5 sub-agent, on the second pass's fixes only): all four held for the cases named. It found 3 more blocking defects, all fixed and tested:
  1. The exemption for problems about a step's input names matched a phrase, which a workflow can quote in a trigger or a permission. It now matches the start of the problem as the checker writes it (the job id, the step number, then the phrase). Only a job id that GitHub refuses could still forge a match, and the audit does not check job ids (issue #182).
  2. Under `local_only`, a reusable workflow from another repository was not counted as remote.
  3. A caller of a workflow file that is missing, or was not read, still counted as reporting.

  Two non-blocking findings were also fixed. The pinning requirement is now weighed before `local_only`, so a refused file is refused. A policy whose enforcement value is not understood, and whose rules are only about actors, no longer counts as covering every event; an enforced policy of actors only is still not compared, as before.
- **Fourth pass** (a fresh Opus 5.5 sub-agent, on the third pass's fixes only): no blocking defect; every change moves an answer towards "cannot tell" or a finding, and ordinary cases read as before. Its non-blocking findings are in issue #182: `uses: ./` alone and `$/` calls are not compared, job ids are not checked against GitHub's form, an empty list of selected actions is not read as blocking, and the caller loop is quadratic in the length of a chain of calls (1.2 s for 1,500). Wording it found too strong was corrected; the last commit after it changes only wording.

#### Every attempt of reviewer A, before and after the fixes

| Attempt | Rule | What was tried | GitHub's basis, as the reviewer gave it | Before | After | Reviewer's verdict (before) |
| --- | --- | --- | --- | --- | --- | --- |
| A001 | SET-001 | env open to any branch, no reviewers, holds secrets | none needed (the rule's own reading) | finding high | finding high | held |
| A002 | SET-001 | job names the env in upper case | env names case-insensitive (not verified) | finding high | finding high | held |
| A003 | SET-001 | env as mapping with name and url | none needed (the rule's own reading) | finding high | finding high | held |
| A004 | SET-001 | `environment: {name: 010}`; open env "010" exists; rule reads "8" | YAML 1.2 core schema reads `010` as 10 and `0o10` as 8; YAML 1.1 reads `010` as 8 (yaml.org, not verified); what GitHub's reader does is not verified | finding medium | cannot tell | way past |
| A005 | SET-001 | env named by `${{ inputs.target }}` | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A006 | SET-001 | custom branch policy `*` | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | finding high | finding high | held |
| A007 | SET-001 | custom branch policy `**/*` | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | finding high | finding high | held |
| A008 | SET-001 | custom branch policy `?*`, no reviewers | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | finding medium | finding medium | under a stated limit |
| A009 | SET-001 | tag policy `*`, no reviewers | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | finding medium | finding medium | under a stated limit |
| A010 | SET-001 | `release/*` with required reviewers | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | no finding | no finding | under a stated limit |
| A011 | SET-001 | `protected_branches: true` | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | cannot tell | cannot tell | held |
| A012 | SET-001 | custom policies with zero entries | no branch may deploy (not verified) | no finding | no finding | held |
| A013 | SET-001 | wait timer only, no reviewers | none needed (the rule's own reading) | finding high | finding high | held |
| A014 | SET-001 | reviewers, self-review allowed, admins may bypass | none needed (the rule's own reading) | finding medium | finding medium | held |
| A015 | SET-001 | limited to unaudited branch `feature-x` | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | cannot tell | cannot tell | held |
| A016 | SET-001 | limited to `release`, audited with --branch, release unprotected | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified); push by anyone with write access to an unprotected branch (not verified) | no finding | finding medium | way past |
| A017 | SET-001 | limited to `release`, audited, branch does not exist (404) | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified); anyone with write access can create a branch (not verified) | no finding | cannot tell | way past |
| A018 | SET-001 | job names an env the settings lack | GitHub creates a referenced env (not verified) | finding medium | finding medium | held |
| A019 | SET-001 | env named in a workflow_call-only file | none needed (the rule's own reading) | finding high | finding high | held |
| A020 | SET-001 | env name with trailing space in quotes | trimming not established (not verified) | finding medium | finding medium | held |
| A021 | SET-001 | env named only by protected_secrets | none needed (the rule's own reading) | finding high | finding high | held |
| A022 | SET-001 | `main` branch + `v*` tag policy, no reviewers | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | finding medium | finding medium | held |
| A023 | SET-001 | env secrets refused (403) | none needed (the rule's own reading) | finding high | finding high | held |
| A024 | SET-001 | branch policies refused (403) | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A025 | SET-001 | env name via YAML anchor/alias | YAML anchors supported since 2025-09 (not verified) | finding high | finding high | held |
| A026 | SET-001 | bare `environment: 010` | YAML 1.2 core schema reads `010` as 10 and `0o10` as 8; YAML 1.1 reads `010` as 8 (yaml.org, not verified); what GitHub's reader does is not verified | cannot tell | cannot tell | held |
| A027 | SET-001 | policy `main` with no `type` field (as REST example) | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) | no finding | no finding | held |
| A028 | SET-001 | bare `environment: 0o10`; open env "8" exists | YAML 1.2 core schema reads `010` as 10 and `0o10` as 8; YAML 1.1 reads `010` as 8 (yaml.org, not verified); what GitHub's reader does is not verified | finding medium | cannot tell | way past |
| A030 | SET-002 | pull_request_target job names open env | [changelog 2025-11-07](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/) (not verified) | finding high | finding high | held |
| A031 | SET-002 | `on: issue_comment` as text | none needed (the rule's own reading) | finding high | finding high | held |
| A032 | SET-002 | `on: {workflow_run: null}` flow mapping | none needed (the rule's own reading) | finding high | finding high | held |
| A033 | SET-002 | `if: github.event_name == 'PUSH'` on [push, issues] | GitHub expressions compare strings ignoring case (not verified) | does not apply | does not apply | held |
| A034 | SET-002 | `if: github.event_name != 'Push'` on [push, issues] | GitHub expressions compare strings ignoring case (not verified) | finding high | finding high | held |
| A035 | SET-002 | env limited to default branch `main` | [changelog 2025-11-07](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/) (not verified) | finding high | finding high | held |
| A036 | SET-002 | env limited to `release` only | [changelog 2025-11-07](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/) (not verified) | no finding | no finding | held |
| A037 | SET-002 | policy `ma\in` (fnmatch escape of `main`) | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified) names Ruby File.fnmatch; GitHub's flags not verified | no finding | finding high | way past |
| A038 | SET-002 | policy `{main,release}` (braces) | [branch-policies ref](https://docs.github.com/ko/enterprise-cloud@latest/rest/deployments/branch-policies) (verified); braces need FNM_EXTGLOB (not verified) | no finding | no finding | held |
| A039 | SET-002 | tag policy named `main` | [changelog 2025-11-07](https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/) (not verified) | no finding | no finding | held |
| A040 | SET-002 | env `protected_branches: true` | none needed (the rule's own reading) | finding high | finding high | held |
| A041 | SET-002 | env with required reviewers | none needed (the rule's own reading) | no finding | no finding | held |
| A042 | SET-002 | env holds no secret, job reads none | none needed (the rule's own reading) | no finding | no finding | under a stated limit |
| A043 | SET-002 | PRT caller -> local reusable job names env | none needed (the rule's own reading) | finding high | finding high | held |
| A044 | SET-002 | PRT caller -> remote reusable workflow | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A045 | SET-002 | `needs` + `if: always()` keeps PRT | none needed (the rule's own reading) | finding high | finding high | held |
| A046 | SET-002 | `workflow_run.event == 'PUSH'` | GitHub expressions compare strings ignoring case (not verified) | does not apply | does not apply | held |
| A047 | SET-002 | env secrets refused, job reads none | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A048 | SET-002 | A004's `{name: 010}` in a PRT job | YAML 1.2 core schema reads `010` as 10 and `0o10` as 8; YAML 1.1 reads `010` as 8 (yaml.org, not verified); what GitHub's reader does is not verified | no finding | cannot tell | way past |
| A050 | SET-003 | incident: protected `*_API_KEY` also a repo secret | none needed (the rule's own reading) | finding high | finding high | held |
| A051 | SET-003 | protected pattern in lower case | secret names are case-insensitive, stored upper case (not verified) | finding high | finding high | held |
| A052 | SET-003 | list-form protected name stored as org secret | none needed (the rule's own reading) | finding high | finding high | held |
| A053 | SET-003 | protected secret copied into a second open env no job names | none needed (the rule's own reading) | no finding | finding high | under a stated limit |
| A054 | SET-003 | no config; env+repo copy, read as `secrets['X']` | none needed (the rule's own reading) | finding medium | finding medium | held |
| A055 | SET-003 | no config; env+org copy, `secrets: inherit` | none needed (the rule's own reading) | finding medium | finding medium | held |
| A056 | SET-003 | no config; read as `secrets.model_api_key` | secret names are case-insensitive, stored upper case (not verified) | finding medium | finding medium | held |
| A057 | SET-003 | config env in another case | none needed (the rule's own reading) | finding high | finding high | held |
| A058 | SET-003 | config names an env that does not exist | none needed (the rule's own reading) | finding high | finding high | held |
| A059 | SET-003 | org secrets refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A060 | SET-003 | protected pattern with `?` | none needed (the rule's own reading) | finding high | finding high | held |
| A061 | SET-003 | env-only secret read by a job | none needed (the rule's own reading) | no finding | no finding | held |
| A062 | SET-003 | one env's secrets refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A063 | SET-003 | repo secret listed in lower case | secret names are case-insensitive, stored upper case (not verified) | finding high | finding high | held |
| A064 | SET-003 | secret read by computed index | none needed (the rule's own reading) | finding medium | finding medium | held |
| A065 | SET-003 | configuration that does not load | none needed (the rule's own reading) | finding medium | finding medium | held |
| A070 | SET-009 | incident: policy allows PRT+dispatch, workflow adds workflow_run | none needed (the rule's own reading) | finding medium | finding medium | held |
| A071 | SET-009 | exclude `.github/*.yml` (Python `*` crosses `/`) | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | no finding | no finding | under a stated limit |
| A072 | SET-009 | include `.github/workflows/*.yml` | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | finding medium | finding medium | held |
| A073 | SET-009 | include with leading `/` | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | finding medium | finding medium | held |
| A074 | SET-009 | include with leading `./` | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | no finding | no finding | under a stated limit |
| A075 | SET-009 | `.yaml` file | none needed (the rule's own reading) | finding medium | finding medium | held |
| A076 | SET-009 | org policy whose repository_name names another repo | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | finding medium | cannot tell | false positive |
| A077 | SET-009 | `on: workflow_run` as text | none needed (the rule's own reading) | finding medium | finding medium | held |
| A078 | SET-009 | `on:` as list | none needed (the rule's own reading) | finding medium | finding medium | held |
| A079 | SET-009 | `on:` mapping with an anchor | none needed (the rule's own reading) | finding medium | finding medium | held |
| A080 | SET-009 | workflow_call beside PRT | none needed (the rule's own reading) | no finding | no finding | under a stated limit |
| A081 | SET-009 | policy in evaluate mode | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | finding low | finding low | held |
| A082 | SET-009 | policy disabled | none needed (the rule's own reading) | no finding | no finding | held |
| A083 | SET-009 | event rule + actor rule | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | finding medium | finding medium | held |
| A084 | SET-009 | allowed_events empty | none needed (the rule's own reading) | finding medium | finding medium | held |
| A085 | SET-009 | `schedule` not allowed | none needed (the rule's own reading) | finding medium | finding medium | held |
| A086 | SET-009 | enforcement `Active` (case) | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A087 | SET-009 | policy with no rules | none needed (the rule's own reading) | no finding | no finding | held |
| A088 | SET-009 | conditions null | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A089 | SET-009 | organisation policy over ~ALL | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | finding medium | finding medium | held |
| A090 | SET-009 | policies refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A091 | SET-009 | allowed_events holds a number | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A092 | SET-009 | two enforced policies, one allows | none needed (the rule's own reading) | finding medium | finding medium | held |
| A100 | SET-010 | public, PRT, no policy | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | finding medium | finding medium | held |
| A101 | SET-010 | active policy allows PRT for the file | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | no finding | no finding | held |
| A102 | SET-010 | allowing policy in evaluate mode | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | cannot tell | cannot tell | held |
| A103 | SET-010 | allowing policy disabled | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | finding medium | finding medium | held |
| A104 | SET-010 | private repository | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | does not apply | does not apply | held |
| A105 | SET-010 | internal repository | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | does not apply | does not apply | held |
| A106 | SET-010 | policies refused | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | cannot tell | cannot tell | held |
| A107 | SET-010 | allowing policy targets another file | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | finding medium | finding medium | held |
| A108 | SET-010 | org policy allows PRT, repository_name excludes this repo | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified); whether such a policy is listed for the repo: not verified | no finding | cannot tell | way past |
| A109 | SET-010 | `on: |` block scalar gives `pull_request_target\n` | GitHub's handling of the name not verified | does not apply | does not apply | held |
| A110 | SET-010 | allowing policy also restricts actors | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | no finding | no finding | under a stated limit |
| A111 | SET-010 | workflow file `t.YAML` | none needed (the rule's own reading) | finding medium | finding medium | held |
| A112 | SET-010 | allowing policy path `*` | [control workflow execution](https://docs.github.com/en/actions/how-tos/administer/control-workflow-execution) (verified; no path syntax given); [policies REST ref](https://docs.github.com/en/rest/actions/policies) (could not fetch) | no finding | no finding | under a stated limit |
| A113 | SET-010 | only-push policy for another file | [changelog 2026-11-02](https://github.blog/changelog/2026-11-02-pull_request_target-blocked-by-default-december-2) (verified) | finding medium | finding medium | held |
| A120 | SET-011 | incident: env-only secret passed to reusable workflow | [reusing workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations) (verified) | finding medium | finding medium | held |
| A121 | SET-011 | passed as input under `with:` | [reusing workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations) (verified) | finding medium | finding medium | held |
| A122 | SET-011 | passed name in lower case | secret names are case-insensitive, stored upper case (not verified) | finding medium | finding medium | held |
| A123 | SET-011 | `secrets: inherit`, called job reads it without env | [reusing workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations) (verified) | finding medium | finding medium | held |
| A124 | SET-011 | inherit, called job declares `Release` | none needed (the rule's own reading) | no finding | no finding | held |
| A125 | SET-011 | inherit, called env by expression | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A126 | SET-011 | inherit to remote workflow | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A127 | SET-011 | computed secret name passed | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A128 | SET-011 | nested inherit | none needed (the rule's own reading) | finding medium | finding medium | held |
| A129 | SET-011 | secret also an org secret | none needed (the rule's own reading) | no finding | no finding | held |
| A130 | SET-011 | env secrets refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A131 | SET-011 | `secrets: Inherit` | none needed (the rule's own reading) | finding medium | finding medium | held |
| A132 | SET-011 | inherit, called job declares another env | none needed (the rule's own reading) | finding medium | finding medium | held |
| A133 | SET-011 | inherit, read in called workflow's `env:` | none needed (the rule's own reading) | finding medium | finding medium | held |
| A140 | SET-012 | default write, job with no permissions | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | finding medium | finding medium | held |
| A141 | SET-012 | workflow `permissions: {}` | none needed (the rule's own reading) | does not apply | does not apply | held |
| A142 | SET-012 | job `permissions:` null | none needed (the rule's own reading) | finding medium | finding medium | held |
| A143 | SET-012 | workflow `read-all` | none needed (the rule's own reading) | does not apply | does not apply | held |
| A144 | SET-012 | called workflow w/o permissions; only caller grants read | [reusing workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations) (verified) ("can be only downgraded") | finding medium | does not apply | false positive |
| A145 | SET-012 | caller w/o permissions; called workflow declares read | [reusing workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations) (verified) | finding medium | does not apply | false positive |
| A146 | SET-012 | default `Write` | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | cannot tell | cannot tell | held |
| A147 | SET-012 | workflow permissions refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A148 | SET-012 | job `write-all` | none needed (the rule's own reading) | does not apply | does not apply | held |
| A149 | SET-012 | default read | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | no finding | no finding | held |
| A150 | SET-012 | permissions via merge key `<<` | merge keys unsupported by GitHub: [frenck.dev](https://frenck.dev/github-actions-yaml-anchors-aliases-merge-keys/) (search result only, not verified) | does not apply | does not apply | held |
| A160 | SET-014 | public, first_time_contributors, self-hosted | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | finding high | finding high | held |
| A161 | SET-014 | all_external_contributors | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | no finding | no finding | held |
| A162 | SET-014 | first_time_contributors_new_to_github | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | finding high | finding high | held |
| A163 | SET-014 | `[Self-Hosted, linux]` | none needed (the rule's own reading) | finding high | finding high | held |
| A164 | SET-014 | runner group only | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A165 | SET-014 | matrix runner incl. self-hosted | none needed (the rule's own reading) | finding high | finding high | held |
| A166 | SET-014 | `"self-hosted, linux"` one label | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A167 | SET-014 | hosted runners only | none needed (the rule's own reading) | cannot tell | cannot tell | under a stated limit |
| A168 | SET-014 | private, fork PRs run and get secrets | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | finding high | finding high | held |
| A169 | SET-014 | private, fork PRs get write token | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | finding high | finding high | held |
| A170 | SET-014 | private, fork PRs do not run | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | no finding | no finding | held |
| A171 | SET-014 | private, fork PRs run unapproved on self-hosted | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | no finding | no finding | under a stated limit |
| A172 | SET-014 | internal, fork PRs get secrets | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | finding high | finding high | held |
| A173 | SET-014 | unknown approval value | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | finding high | finding high | held |
| A174 | SET-014 | `runs-on: {labels: self-hosted}` | none needed (the rule's own reading) | finding high | finding high | held |
| A175 | SET-014 | self-hosted job in a workflow_call file | none needed (the rule's own reading) | finding high | finding high | held |
| A176 | SET-014 | approval setting refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A177 | SET-014 | private fork settings refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A178 | SET-014 | runner by `${{ inputs.runner }}` | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A179 | SET-014 | custom labels only `[linux, x64, gpu]` | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A180 | SET-015 | pinning required, tag ref | [changelog 2025-08-15](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/) (verified) | finding medium | finding medium | held |
| A181 | SET-015 | short SHA | [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) | finding medium | finding medium | held |
| A182 | SET-015 | 64-hex ref (a tag or branch on github.com) | [changelog 2025-08-15](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/) (verified); [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) (tags refused) | no finding | finding medium | way past |
| A183 | SET-015 | 40-hex SHA + `\n` in a quoted string | [changelog 2025-08-15](https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/) (verified) | no finding | finding medium | way past |
| A184 | SET-015 | `docker://` step | [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) | does not apply | does not apply | held |
| A185 | SET-015 | local composite action using a tag inside | [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) (refused) | no finding | no finding | under a stated limit |
| A186 | SET-015 | `$/` self-repository action | [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) (passes) | finding medium | no finding | false positive |
| A187 | SET-015 | reusable workflow at a tag | [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) (passes) | no finding | no finding | held |
| A188 | SET-015 | tags locked by .github/workflows/actions.lock | [changelog 2026-10-28](https://github.blog/changelog/2026-10-28-github-actions-workflow-lockfiles-are-generally-available/) (verified); repo-settings docs page (could not fetch); [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) (passes) | finding medium | cannot tell | false positive |
| A189 | SET-015 | not required, all pinned | none needed (the rule's own reading) | finding low | finding low | held |
| A190 | SET-015 | `sha_pinning_required` absent | [Actions permissions REST ref](https://docs.github.com/en/rest/actions/permissions) (verified) | cannot tell | cannot tell | held |
| A191 | SET-015 | Actions permissions refused | none needed (the rule's own reading) | cannot tell | cannot tell | held |
| A192 | SET-015 | upper-case 40-hex SHA | GitHub's acceptance not verified | finding medium | finding medium | held |
| A193 | SET-015 | tag inside a `parallel` step group | none needed (the rule's own reading) | finding medium | finding medium | held |
| A194 | SET-015 | remote reusable workflow at SHA using tags inside | [classmethod test](https://dev.classmethod.jp/en/articles/github-actions-require-sha-pinning/) (read; third party, not GitHub) (refused) | no finding | no finding | under a stated limit |
| A195 | SET-015 | tag in a local called workflow | none needed (the rule's own reading) | finding medium | finding medium | held |
| A196 | SET-015 | 40-hex SHA + trailing space | none needed (the rule's own reading) | finding medium | finding medium | held |
| A200 | SET-002 | 22 jobs, each `needs` all before (3 KB) | none needed (the rule's own reading) | does not apply (4.5 s) | does not apply | traceback / hang |
| A201 | SET-012 | 31 jobs, each `needs` the two before (2.6 KB) | none needed (the rule's own reading) | finding medium (7.3 s) | finding medium | traceback / hang |
| A202 | SET-002 | chain of 60 local reusable workflows from PRT | none needed (the rule's own reading) | finding high | finding high | held |
| A203 | SET-015 | 400-step anchor aliased by 150 jobs (25 KB) | none needed (the rule's own reading) | finding medium | finding medium | held |

#### Every attempt of reviewer B, before and after the fixes

| Attempt | Rule | What was tried | GitHub's basis, as the reviewer gave it | Before | After | Reviewer's verdict (before) |
| --- | --- | --- | --- | --- | --- | --- |
| B001 | SET-004 | recorded incident: OrganizationAdmin always, one admin account | https://docs.github.com/en/rest/repos/rules (not verified); recording | finding high | finding high | held |
| B002 | SET-004 | Integration 15368 (GitHub Actions app) always; 1 admin + 2 write. Any author can push a workflow whose GITHUB_TOKEN pushes to main | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets (not verified): apps can be bypass actors; a job's GITHUB_TOKEN acts as the GitHub Actions app | finding medium | finding high | way past (medium; description says high when everyone who can push can bypass) |
| B003 | SET-004 | Integration 15368, bypass_mode pull_request | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets (not verified) | finding low | finding low | under a stated limit (docs: a pull-request-only bypass is low) |
| B004 | SET-004 | classic bypass_pull_request_allowances.apps = github-actions | https://docs.github.com/en/rest/branches/branch-protection (not verified) | finding medium | finding medium | under a stated limit (docs: a classic allowance is medium) |
| B005 | SET-004 | DeployKey actor, actor_id null, always | https://docs.github.com/en/rest/repos/rules (not verified) | finding medium | finding medium | held |
| B006 | SET-004 | RepositoryRole write (4) always; admins exist beside | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets (not verified) | finding medium | finding medium | under a stated limit (docs: whether a role extends to higher roles is not established) |
| B007 | SET-004 | maintain + write roles always, accounts exactly 1 maintain + 1 write | https://docs.github.com/en/rest/repos/rules (not verified) | finding high | finding high | held |
| B008 | SET-004 | custom repository role id 81234 always | https://docs.github.com/en/rest/repos/rules (not verified) | finding medium | finding medium | held (medium; coverage unknowable) |
| B009 | SET-004 | bypass_mode exempt on admin + write roles | https://docs.github.com/en/rest/repos/rules (not verified) | finding high | finding high | held |
| B010 | SET-004 | bypass_mode null | - | finding high | finding high | held |
| B011 | SET-004 | list withheld, current_user_can_bypass = exempt | https://docs.github.com/en/rest/repos/rules (not verified) | finding low | finding medium | under a stated limit (docs: words other than always/never read as narrower; exempt is the wider mode) |
| B012 | SET-004 | only required_deployments (gate) + deletion | https://docs.github.com/en/rest/repos/rules (not verified) | finding high | finding high | held |
| B013 | SET-004 | only an update rule | https://docs.github.com/en/rest/repos/rules (not verified) | does not apply | does not apply | held |
| B014 | SET-004 | unknown rule type is the ruleset's only rule | - | cannot tell | cannot tell | held |
| B015 | SET-004 | empty bypass_actors [] | https://docs.github.com/en/rest/repos/rules (not verified) | cannot tell | cannot tell | held |
| B016 | SET-004 | rule from org ruleset 77 not in the repository's list | https://docs.github.com/en/rest/repos/rules (not verified) | cannot tell | cannot tell | held |
| B017 | SET-004 | classic rule with no checks and no reviews (only force-push/deletion), enforce_admins false | https://docs.github.com/en/rest/branches/branch-protection (not verified) | finding medium | no finding | false positive (medium; a ruleset of the same content is not-applicable, and the message claims checks and reviews that do not exist) |
| B018 | SET-004 | classic enforce_admins false, all pushers admins | https://docs.github.com/en/rest/branches/branch-protection (not verified) | finding high | finding high | held |
| B019 | SET-004 | classic allowances present and empty | https://docs.github.com/en/rest/branches/branch-protection (not verified) | no finding | no finding | held |
| B020 | SET-004 | classic allowances without teams | https://docs.github.com/en/rest/branches/branch-protection (not verified) | cannot tell | cannot tell | held |
| B021 | SET-004 | OrganizationAdmin always, two admins | - | finding medium | finding medium | held |
| B022 | SET-004 | Team always | - | finding medium | finding medium | held |
| B023 | SET-004 | EnterpriseOwner always | - | finding medium | finding medium | held |
| B024 | SET-004 | every push role in pull_request mode (every author can merge their own PR unreviewed) | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets (not verified) | finding low | finding low | under a stated limit (docs: pull-request-only bypass is low) |
| B025 | SET-004 | user-owned repo, sole admin, admin role always | - | finding high | finding high | held |
| B026 | SET-004 | OrganizationAdmin pull_request mode, sole owner | - | finding low | finding low | under a stated limit |
| B027 | SET-004 | list withheld, current_user_can_bypass = always | - | finding medium | finding medium | held |
| B028 | SET-004 | ruleset conditions exclude refs/heads/main but GitHub lists its rules for main | https://docs.github.com/en/rest/repos/rules (not verified): rules for a branch are GitHub's own evaluation | finding high | finding high | held (the rules use GET rules/branches, not conditions) |
| B029 | SET-004 | collaborators unread, OrganizationAdmin always | - | finding medium | finding medium | held |
| B030 | SET-004 | Integration 15368 always, default token read-only | https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets (not verified) | finding medium | finding high | way past (same class as B002) |
| B158 | SET-004 | list withheld, current_user_can_bypass = pull_requests_only | - | finding low | finding low | held |
| B031 | SET-005 | recorded incident: 1 approval, 1 account | recording | finding medium | finding medium | held |
| B032 | SET-005 | admin + write, 1 approval | https://docs.github.com/en/rest/collaborators/collaborators (not verified) | no finding | no finding | held |
| B033 | SET-005 | admin + triage + read | https://docs.github.com/en/rest/collaborators/collaborators (not verified) | finding medium | finding medium | held |
| B034 | SET-005 | classic 2 + ruleset 1, two accounts | https://docs.github.com/en/rest/branches/branch-protection (not verified) | finding medium | finding medium | held |
| B035 | SET-005 | classic reviews without a count | https://docs.github.com/en/rest/branches/branch-protection (not verified) | cannot tell | cannot tell | held |
| B036 | SET-005 | require_code_owner_review, 1 approval | https://docs.github.com/en/rest/repos/rules (not verified) | cannot tell | cannot tell | held |
| B037 | SET-005 | 0 approvals + require_last_push_approval | https://docs.github.com/en/rest/repos/rules (not verified) | cannot tell | cannot tell | held |
| B038 | SET-005 | required_reviewers team minimum 2 | https://docs.github.com/en/rest/repos/rules (not verified) | cannot tell | cannot tell | held |
| B039 | SET-005 | pull_request rule without parameters | - | cannot tell | cannot tell | held |
| B040 | SET-005 | count as text "1" | - | cannot tell | cannot tell | held |
| B041 | SET-005 | count -1 | - | cannot tell | cannot tell | held |
| B042 | SET-005 | collaborators refused | - | cannot tell | cannot tell | held |
| B043 | SET-005 | collaborators' second page fails (partial read) | https://docs.github.com/en/rest/collaborators/collaborators (not verified) | cannot tell | cannot tell | held |
| B044 | SET-005 | unknown pull_request parameter | - | cannot tell | cannot tell | held |
| B045 | SET-005 | classic protection refused | - | cannot tell | cannot tell | held |
| B046 | SET-005 | repository ruleset 1 + organisation ruleset 3, three accounts | https://docs.github.com/en/rest/repos/rules (not verified) | finding medium | finding medium | held |
| B047 | SET-005 | update rule beside 1 approval | - | cannot tell | cannot tell | held |
| B048 | SET-005 | classic push restrictions beside 1 approval | - | cannot tell | cannot tell | held |
| B159 | SET-005 | outside collaborator with write access | https://docs.github.com/en/rest/collaborators/collaborators (not verified) | no finding | no finding | held |
| B050 | SET-013 | workflows may approve, 1 approval | https://docs.github.com/en/rest/actions/permissions (not verified) | finding medium | finding medium | held |
| B051 | SET-013 | workflows may approve, 0 approvals | - | no finding | no finding | held |
| B052 | SET-013 | 1 approval + code owner | - | cannot tell | cannot tell | held |
| B053 | SET-013 | 2 approvals + code owner | - | finding medium | finding medium | held |
| B054 | SET-013 | approvals only from a classic rule | - | finding medium | finding medium | held |
| B055 | SET-013 | classic reviews with no count | - | cannot tell | cannot tell | held |
| B056 | SET-013 | workflow permissions refused | - | cannot tell | cannot tell | held |
| B057 | SET-013 | 1 approval + require_last_push_approval | - | finding medium | finding medium | held |
| B058 | SET-013 | 0 by count, team minimum 1 on every file | - | cannot tell | cannot tell | held |
| B059 | SET-013 | workflows may not approve | - | no finding | no finding | held |
| B060 | SET-013 | branch rules refused | - | cannot tell | cannot tell | held |
| B061 | SET-013 | classic refused, ruleset asks 2 | - | finding medium | finding medium | held |
| B062 | SET-013 | classic 1 approval + code owners only | - | cannot tell | cannot tell | held |
| B070 | SET-006 | recorded matrix job reports "test (3.13)" | recording | no finding | no finding | held |
| B071 | SET-006 | required "Build", job "build" (letter case) | https://docs.github.com/en/rest/branches/branch-protection (not verified): how GitHub compares context case is not established | finding medium | finding medium | held (if GitHub compares exactly; otherwise a false positive) |
| B072 | SET-006 | job id build with `name: 0`: audit falls back to the id | https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified): the check is the job's name; 0 is a value, not an absent name | no finding | cannot tell | way past |
| B073 | SET-006 | job id build with `name: false` | https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified) | no finding | cannot tell | way past |
| B074 | SET-006 | `name: 012` read as octal 10 (YAML 1.1); GitHub reads YAML 1.2 (OBAAF's yamlutil says so for booleans) | https://yaml.org/spec/1.2.2/#1032-tag-resolution (not verified) | no finding | cannot tell | way past |
| B075 | SET-006 | matrix value 08: PyYAML keeps text "08", YAML 1.2 gives 8; required "test (08)" | https://yaml.org/spec/1.2.2/#1032-tag-resolution (not verified); https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified) | no finding | cannot tell | way past (depends on GitHub typing 08 as a number) |
| B076 | SET-006 | same matrix, required "test (8)" | https://yaml.org/spec/1.2.2/#1032-tag-resolution (not verified) | finding medium | cannot tell | false positive (same cause as B075) |
| B077 | SET-006 | matrix of decimals 3.10 | - | cannot tell | cannot tell | held |
| B078 | SET-006 | computed job name | - | cannot tell | cannot tell | held |
| B079 | SET-006 | caller ci / called test | https://docs.github.com/en/actions/sharing-automations/reusing-workflows (not verified) | no finding | no finding | held |
| B080 | SET-006 | caller calls a local file without on.workflow_call (GitHub refuses the caller) | https://docs.github.com/en/actions/sharing-automations/reusing-workflows (not verified) | no finding | no finding | under a stated limit (workflows.py _refused: "what it does not know is read as a file that runs") |
| B081 | SET-006 | only reporter is in ci.YML | checker/workflow.py discover(): "Whether GitHub runs ci.YML ... is not established" | no finding | cannot tell | way past (not established is read as runs) |
| B082 | SET-006 | only reporter is in a file named .yml | as B081 | no finding | cannot tell | way past (as B081) |
| B083 | SET-006 | only reporter is a symlink to a file outside .github/workflows | https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified): GitHub reads the committed blob; a link's blob is its target path | no finding | cannot tell | way past |
| B084 | SET-006 | job name merged in through `<<: *base` | checker/workflow.py:2573 says what GitHub makes of `<<` is not established | no finding | cannot tell | way past (read merged; the checker's own problem note is dropped) |
| B085 | SET-006 | only reporter in .github/workflows/sub/ | https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified) | finding medium | finding medium | held |
| B086 | SET-006 | only reporter in an uncalled workflow_call-only file | - | finding medium | finding medium | held |
| B087 | SET-006 | a job may write checks | - | cannot tell | cannot tell | held |
| B088 | SET-006 | default token unread, a job declares no permissions | - | cannot tell | cannot tell | held |
| B089 | SET-006 | job name with a trailing space | not verified | finding medium | finding medium | held (if GitHub keeps the space) |
| B090 | SET-006 | `On:` instead of `on:` | - | finding medium | finding medium | held |
| B091 | SET-006 | required with no app | - | cannot tell | cannot tell | held |
| B092 | SET-006 | flow mappings, folded block scalar name, comment | - | no finding | no finding | held |
| B093 | SET-006 | unknown job key (timeout: 10), GitHub refuses the file | https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified) | no finding | no finding | under a stated limit (_refused knows few refusals) |
| B094 | SET-006 | matrix of a number and a text axis | https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified) | no finding | no finding | held |
| B095 | SET-006 | `name: 12:30` read as 750 (YAML 1.1 sexagesimal) | https://yaml.org/spec/1.2.2/#1032-tag-resolution (not verified) | no finding | cannot tell | way past (same class as B074) |
| B096 | SET-006 | matrix caller and matrix callee | https://docs.github.com/en/actions/sharing-automations/reusing-workflows (not verified) | no finding | no finding | held |
| B097 | SET-006 | own repository called by full name at a ref | - | cannot tell | cannot tell | held |
| B098 | SET-006 | classic checks: "build" from app 999 and from Actions; folded to one app per context | https://docs.github.com/en/rest/branches/branch-protection (not verified): whether one classic rule can list a context under two apps is not established | no finding | cannot tell | way past (only for an app id below 15368) |
| B099 | SET-006 | same two requirements in a ruleset | - | cannot tell | cannot tell | held |
| B125 | SET-006 | same folding through the public branch view | not verified | no finding | cannot tell | way past (as B098) |
| B127 | SET-006 | duplicate key in the workflow | - | cannot tell | cannot tell | held |
| B128 | SET-006 | integration_id as text "15368" | - | cannot tell | cannot tell | held |
| B129 | SET-006 | job id `true:` with no name | - | no finding | cannot tell | held |
| B151 | SET-006 | 4 matrix callers x 60 matrix jobs (14 KB) | - | finding medium (2.9 s) | finding medium | hang (about 3 s; 36 KB took 18 s) |
| B152 | SET-006 | Actions disabled for the repository (enabled: false) | https://docs.github.com/en/rest/actions/permissions (not verified) | no finding | finding medium | way past (snapshot holds the setting; the check rules do not read it) |
| B154 | SET-006 | sha_pinning_required and the reporting job uses actions/checkout@v4 | https://docs.github.com/en/rest/actions/permissions (not verified); OBAAF-SET-015's own message: "GitHub refuses a workflow that uses an action that is not pinned" | no finding | finding medium | way past (OBAAF-SET-015 reports the refusal; OBAAF-SET-006 still counts the check) |
| B157 | SET-006 | classic contexts only, no checks list | https://docs.github.com/en/rest/branches/branch-protection (not verified) | cannot tell | cannot tell | held |
| B100 | SET-007 | recorded pull_request workflow | - | no finding | no finding | held |
| B101 | SET-007 | paths filter | - | finding medium | finding medium | held |
| B102 | SET-007 | types [labeled] | - | finding medium | finding medium | held |
| B103 | SET-007 | reporting job skipped by `if: github.event_name == 'push'` on pull requests | https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/using-conditions-to-control-job-execution (not verified): a skipped job reports success; the rule's own fix text says so | finding medium | finding medium | false positive |
| B104 | SET-007 | reporting job needs a job that `if:` skips | https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/using-conditions-to-control-job-execution (not verified) | finding medium | finding medium | false positive |
| B105 | SET-007 | only `on: push` (fork PRs never get the check) | docs/settings-audit.md:187 and :247 | no finding | no finding | under a stated limit |
| B106 | SET-007 | only pull_request_target | https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/ (verified: "GITHUB_SHA will point to the latest commit on that branch", the default branch); that a run's checks attach to its GITHUB_SHA is not verified | no finding | cannot tell | way past |
| B107 | SET-007 | workflow_run | - | finding medium | finding medium | held |
| B108 | SET-007 | workflow_dispatch | - | cannot tell | cannot tell | held |
| B109 | SET-007 | merge_group only, no queue | - | finding medium | finding medium | held |
| B110 | SET-007 | branches [main] | - | no finding | no finding | held |
| B111 | SET-007 | branches ['releases/**'] | - | cannot tell | cannot tell | held |
| B112 | SET-007 | branches-ignore [main] | - | finding medium | finding medium | held |
| B113 | SET-007 | branches with a ! entry | - | cannot tell | cannot tell | held |
| B114 | SET-007 | types [opened, synchronize] | - | no finding | no finding | held |
| B115 | SET-007 | types: opened (text) | - | finding medium | finding medium | held |
| B116 | SET-007 | pull_request filters through an alias with paths | - | finding medium | finding medium | held |
| B117 | SET-007 | workflow concurrency group shared by every PR, cancel-in-progress | https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/control-the-concurrency-of-workflows-and-jobs (not verified): a queued run cancels the pending one in its group | no finding | no finding | way past (judgement: a cause the description does not list) |
| B118 | SET-007 | `if: false` on the reporting job (always skipped = success) | https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/using-conditions-to-control-job-execution (not verified) | no finding | no finding | held |
| B119 | SET-007 | pull_request paths-ignore beside an unfiltered push | docs/settings-audit.md:247 | no finding | no finding | under a stated limit |
| B120 | SET-007 | types [labeled] beside push branches-ignore | - | cannot tell | cannot tell | held |
| B121 | SET-007 | job limited by `if:` to pull_request_target in a workflow with pull_request (skipped = success on the head) | https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/using-conditions-to-control-job-execution (not verified) | no finding | cannot tell | held |
| B122 | SET-007 | caller job in a paths-filtered workflow | - | finding medium | finding medium | held |
| B123 | SET-007 | `Pull_Request:` beside workflow_dispatch | - | cannot tell | does not apply | held |
| B124 | SET-007 | same name from a PR workflow and a push-only workflow | - | no finding | no finding | held |
| B126 | SET-007 | folded classic apps seen by 007 | - | finding medium | finding medium | held |
| B153 | SET-007 | Actions disabled (enabled: false) | https://docs.github.com/en/rest/actions/permissions (not verified) | no finding | does not apply | way past (as B152) |
| B155 | SET-007 | active Actions policy allows only push for ci.yml | https://docs.github.com/en/rest/actions/policies (not verified); OBAAF-SET-009's own message: "fails at startup with no job" | no finding | finding medium | way past (OBAAF-SET-009 reports the block; OBAAF-SET-007 says every PR) |
| B130 | SET-008 | unrequired lint job | - | finding medium | finding medium | held |
| B131 | SET-008 | lint with continue-on-error: true | - | no finding | no finding | held |
| B132 | SET-008 | two workflows, two jobs reporting "test (3.13)"; the requirement waits on the latest check run of a name | https://docs.github.com/en/rest/checks/runs (not verified): check runs are filtered by name, latest by default | no finding | cannot tell | way past |
| B133 | SET-008 | two jobs in one workflow with the same name | https://docs.github.com/en/rest/checks/runs (not verified) | no finding | cannot tell | way past (as B132) |
| B134 | SET-008 | matrix, one of two values required | - | finding medium | finding medium | held |
| B135 | SET-008 | called workflow's lint job has continue-on-error: true | https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax (not verified): a job that calls a reusable workflow cannot set continue-on-error | finding medium | no finding | false positive (minor) |
| B136 | SET-008 | deploy job skipped by `if:` on PRs | - | no finding | no finding | held |
| B137 | SET-008 | branch pattern decides | - | cannot tell | cannot tell | held |
| B138 | SET-008 | continue-on-error as an expression | - | finding medium | finding medium | held |
| B139 | SET-008 | lint required only from app 999 | - | cannot tell | cannot tell | held |
| B140 | SET-008 | unknown required_status_checks parameter | - | cannot tell | cannot tell | held |
| B141 | SET-008 | no required check at all | - | finding medium | finding medium | held |
| B142 | SET-008 | job named 012 (octal 10), "10" required | https://yaml.org/spec/1.2.2/#1032-tag-resolution (not verified) | no finding | cannot tell | way past (as B074) |
| B143 | SET-008 | job with `if: false` (never runs) counted | https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/using-conditions-to-control-job-execution (not verified) | finding medium | finding medium | false positive (minor) |
| B144 | SET-008 | unrequired lint on pull_request_target | - | finding medium | finding medium | held |
| B145 | SET-008 | lint with an `if:` on draft | - | finding medium | finding medium | held |
| B146 | SET-008 | classic checks read in full, app null | - | finding medium | finding medium | held |
| B147 | SET-008 | called workflow's deploy job is skipped by `if:` on PRs, counted as unrequired | https://docs.github.com/en/actions/writing-workflows/choosing-when-your-workflow-runs/using-conditions-to-control-job-execution (not verified) | finding medium | finding medium | false positive (minor) |
| B150 | SET-008 | 30 jobs each needing the two before (2.5 KB) | - | finding medium (4.0 s) | finding medium | hang (about 4 s; 31 jobs about 7 s; x1.6 per job) |
| B156 | SET-008 | unrequired lint in a workflow refused for an unpinned action | - | finding medium | no finding | held (either way it fails without blocking) |

## 2d.2h: the repository and instruction-file rules

Run `dipper`, 2026-11-15, on a copy of `flagship` at `340e4aa`. Two Opus 5.5 reviewers that did not write the three rules attacked them in parallel: reviewer A took how CODEOWNERS is read and matched and which files OBAAF-REPO-001 counts (118 attempts: 30 ways past, 38 ways past not verified against GitHub, 1 false positive and 3 not verified, 4 slow cases, 6 under a stated limit, 36 held); reviewer B took OBAAF-INS-001 and how instruction files are found, which OBAAF-REPO-002 uses too (127 attempts: 57 ways past, 13 not verified, 9 false positives, 2 slow cases, 9 out of the rule's scope, 37 held). A way past here is a repository in which GitHub would ask no code owner to review a change to a CI definition or an agent instruction file, or in which an agent reads text a reviewer cannot see, while OBAAF reports nothing or less. Every case is a small tree run through `obaaf check`; nothing was run against GitHub or an agent. Every class of way past that is fixed has a test in `tests/test_repo_instruction_bypasses.py` (83 tests: the 13 of the third review pass, the 5 of the fourth, the 3 of the fifth and the 3 of the sixth are described there. Before the third there were 59. Of the 54 there were before the second review pass, on the old code 29 fail by assertion, 2 stop on another error, 12 stop on a name that does not exist there, so they show what the new code does rather than what the old code missed, one does not finish in 40 seconds, and 10 pass: they check that ordinary cases read as before, or that a defect the review found in the first fixes is not there; the 5 added after the second pass check defects of the second version).

Pages read in the session. Reviewer A, GitHub's ["About code owners"](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners): the three places and their order, "Each CODEOWNERS file assigns the code owners for a single branch", the base branch, "CODEOWNERS files must be under 3 MB in size. A CODEOWNERS file over this limit will not be loaded", the syntax exceptions (`\#`, `!`, `[ ]` "doesn't work"), the `@username` or `@org/team-name` form, write access, "CODEOWNERS paths are case sensitive", "If any line in your CODEOWNERS file contains invalid syntax, that line will be skipped", "To protect a repository fully against unauthorized changes, you also need to define an owner for the CODEOWNERS file itself", and the example file (inline comments, a pattern with no owner, `docs/*`, last match wins); and ["Workflow syntax"](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax) for `uses: ./path`. The fetch tool returns at most 125 characters per quote, so long sentences were read in pieces. The page says nothing about links, encodings, a byte-order mark, line ends or whitespace, so every case that turns on those is "not verified". Reviewer B read each tool's own page for the file names it relies on: Claude Code ([memory](https://code.claude.com/docs/en/memory), [skills](https://code.claude.com/docs/en/skills.md)), Codex ([AGENTS.md](https://learn.chatgpt.com/docs/agent-configuration/agents-md.md)), GitHub Copilot ([custom instructions support](https://docs.github.com/en/copilot/reference/custom-instructions-support), [repository instructions](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions), [skills](https://docs.github.com/en/copilot/how-tos/use-copilot-agents/cloud-agent/create-skills), [hooks](https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-hooks), and the [changelog of 2026-07-17](https://github.blog/changelog/2026-07-17-copilot-code-review-customization-and-configurability-improvements/): code review reads instructions "from the head branch of the pull request instead of the base branch"), Cursor ([rules](https://docs.cursor.com/context/rules), [MCP](https://cursor.com/docs/mcp.md)), [Gemini CLI](https://geminicli.com/docs/cli/gemini-md/), [Windsurf](https://docs.devin.ai/windsurf/plugins/cascade/memories.md), [Cline](https://docs.cline.bot/customization/cline-rules.md), [Junie](https://junie.jetbrains.com/docs/guidelines-and-memory.html), [Amazon Q](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/context-project-rules.md), [Kiro](https://kiro.dev/docs/steering/), [Zed](https://zed.dev/docs/ai/rules), [Aider](https://aider.chat/docs/usage/conventions.html), [OpenCode](https://opencode.ai/docs/rules/), [Augment](https://docs.augmentcode.com/setup-augment/guidelines), [Amp](https://ampcode.com/docs/customize/agents-md) and [VS Code](https://code.visualstudio.com/docs/agents/reference/custom-instructions-reference.md). Not read: Roo Code's page (the request was not answered), so `.roo/` is not added. The quotes came through a tool that extracts page text.

### OBAAF-REPO-001 and OBAAF-REPO-002: how CODEOWNERS is read

**Got through, now fixed.**

- **Owners were never checked for form** (A003 to A016, A025, A026, A052, A092, A094, A099, A105 to A109, A113): any word after a pattern counted as an owner, `octocat`, `@`, `@org/`, `TODO`, `*`, a full-width `＠`, a quoted owner, and OBAAF's own template placeholder `@your-org/build-owners`. A rule whose owners are not all `@user`, `@org/team` or an e-mail address (the form check acceptances already use), or that names `@your-org/`, now gives no owner, and as the last match it takes ownership away; the finding names the line. GitHub may skip such a line instead ("that line will be skipped"), in which case an earlier rule could still own the file and OBAAF reports a file GitHub would give an owner; the cost of that reading is a finding where the line can be corrected.
- **Python split lines and words where GitHub probably does not** (A017 to A024, A093, A095; not verified): `splitlines` ended a line at U+2028, U+0085, a form feed and more, so a comment could hide a rule from GitHub and show it to OBAAF; `split` broke a word at a no-break space. A line now ends at a line feed (a carriage return before it is dropped) and words are split at spaces and tabs only.
- **A `#` anywhere started a comment** (A028, A096; A029 was a false positive): a comment now begins at a `#` at the start of a line or after a space or tab, as in GitHub's example; a `#` inside an owner makes the owner malformed.
- **Bytes that are not UTF-8** (A025, A026) were replaced and the owner still counted. A CODEOWNERS file that is not UTF-8 is now an error.
- **The 3 MB limit** (A057, A058): a file of 3,000,000 bytes or more (the lower reading of "3 MB") is reported as not loaded, for both rules.
- **Links and letter case at the three places** (A060 to A062, A111): a link was followed, to a file outside the repository too, and a link to nothing made OBAAF look in the next place. A link, or an entry that is not a plain file, at one of the three places is now an error, as `.github/egress-firewall.yaml` already was; the name is compared with the folder's listing, so `codeowners` on a file system that ignores case is not `CODEOWNERS`.
- **`**` beside other characters** (A037 to A039, A097; not verified): `/.github/work**` and `/.cursor**` matched whole trees. As in gitignore, `**` crosses folders only in a leading `**/`, a `/**/` and a trailing `/**`; elsewhere it is `*`.
- **Time** (A101 to A104): every pattern was compiled again for every path and some backtracked; A104 did not finish in two minutes, and the author of a pull request chooses the CODEOWNERS file the check reads. Patterns are now compiled once and asked from the last rule up, a rule whose plain text the path does not contain is skipped without compiling it, a pattern with more than one wildcard inside a folder or more than one across folders runs on an automaton whose time is linear in the path, and more than 2,000,000 comparisons of a pattern with a path, or 30,000,000 looks at a rule, is an error. A101 (60,000 rules) now takes under a second and the others under half a second.

### OBAAF-REPO-001: which files need an owner

**Got through, now fixed.**

- **The files that decide what the check accepts** (A066 to A070, A072 to A074): the CODEOWNERS file itself (GitHub's own page says to give it an owner), the checker's configuration in any of its three places, the baseline given with `--baseline`, and the firewall policy OBAAF clears OBAAF-GHA-020 from, needed no owner, and an unowned configuration could silence OBAAF-REPO-001 itself with an ignore entry (A069, A070). They are now a second OBAAF-REPO-001 finding (`gate-no-owner`), with each place the configuration is looked for while there is none (any change could add one), each CODEOWNERS place GitHub looks in before the one in use, the firewall policy's place whether or not there is a policy, a baseline or configuration given by path when it is in the repository (also when the path reaches the repository through a link), and, for each of these that is a link, the file it leads to. No ignore or baseline entry accepts this finding, and `--write-baseline` leaves it out: an acceptance would be the unowned file vouching for itself. An entry that names it is reported as not counting, with that reason.
- **Local actions, the lockfile, a new workflow and links** (A075, A076, A078 to A083): the `action.yml` of every `uses: ./path` and `$/path` step (with `..` resolved, and the target of an `action.yml` that is a link), `.github/workflows/actions.lock`, and a new workflow file are now CI definitions. A new workflow counts as owned only when the rules give every name it could have an owner: the last rule that matches every name `X.yml` must give one, and no later rule that can match some such name may give none (decided on the pattern's automaton, the same on every run; see the second review pass below), so that owning `ci.yml` by name, `*.yml`, or a pattern written for the label does not pass while the next workflow has no owner. A workflow that is a link is checked by its own path and by its target's, and an absolute local path no longer appears in a finding (A083).

**Not fixed, now stated limits.** Scripts a workflow runs (A077), Jenkinsfiles in folders Jenkins discovery skips and a Jenkinsfile that is a link (A085, A086, A088; left for the Jenkins tranche, which owns that discovery), whether an owner exists and has write access, and the base branch: on a pull request OBAAF reads that pull request's CODEOWNERS, while GitHub requests the base branch's owners. A byte-order mark before the first rule (A027) and an escaped space (A056) still give no owner, which is wrong if GitHub strips the mark or honours the escape; neither is documented.

### OBAAF-REPO-002 and OBAAF-INS-001: which files are instruction files

**Got through, now fixed.**

- **Names from the tools' own pages** (B005, B007, B037 to B040, B043, B044, B046 to B052, and B056, not verified): `AGENTS.override.md`, `REVIEW.md` (Copilot code review, which reads the pull request's own copy), `.github/skills/`, `.agents/`, `.github/hooks/`, `.cursor/mcp.json`, `.cline/`, `.junie/`, `.amazonq/`, `.kiro/`, `.rules`, `.augment/` and `.augment-guidelines` are now instruction files.
- **Files read in every folder** (B006, B008, B030, B041, B042, B054): `AGENTS.override.md`, `CLAUDE.local.md`, `.aider.conf.yml`, `.cursor/`, `.windsurf/` and `.claude/` are matched in any folder.
- **Skipped folders** (B009 to B018, B024): `build/`, `dist/`, `node_modules/`, `.venv/`, `Library/` and the rest were skipped at every depth, so a Claude skill named `build` was never read. In a git work tree the files git tracks are read, which is what a pull request changes and a checkout holds (git runs with no hook, no file-system monitor and no `GIT_*` variables); elsewhere every folder but `.git` is walked. More than 2,000,000 entries is an error, never a pass.
- **Links** (B019, B021 to B025): a linked `CLAUDE.md`, rule or skill folder was skipped. Each real file is now found once by its own path, and a link inside the repository adds the names an agent uses for the files behind it, a folder that holds the link included (since the third review pass), and a link back into a folder already entered on the way once more, once for each link and set of patterns that could match beneath its name, by whichever way reaches it first (since the fourth), through at most eight links, 1,000,000 entries looked at behind links, 100,000,000 characters of names and targets tested or built behind links and 200,000 instruction files and links reached (past that, an error, with what was found so far still checked); each file is read and scanned once however many names lead to it, and one name is kept for each file and link that leads to it; the link, and the file read through it, need an owner too; a link out of the repository, to nothing or to something that is neither a file nor a folder is named in a note and in OBAAF-REPO-002, and not read, when it or a name a pattern gives beneath it (other than through a leading `**/`) would be an instruction file.
- **Letter case** (B001 to B004, not verified): names are matched without regard to case, as an agent on macOS or Windows opens them.

**Not fixed, now stated limits.** Files an instruction file pulls in by reference (B026 to B029, B031 to B033, B036: `@path` imports, Gemini's `context.fileName`, Aider's `read:`, OpenCode's `instructions`, VS Code's `chat.instructionsFilesLocations`); the referring file is found, the referenced one is not. Roo Code's names (B053), which were not verified.

### OBAAF-INS-001: what counts as hidden

**Got through, now fixed.**

- **A hand-written list** (B058 to B062, B064 to B066, B068 to B070, and B072, not verified): every format character (Unicode category Cf: U+206A to U+206F, U+FFF9 to U+FFFB, U+1D173 to U+1D17A, U+13430 to U+1343F, U+1BCA0 to U+1BCA3), every control character but tab, line feed and carriage return, U+2028 and U+2029, the Hangul fillers, the Khmer inherent vowels, the braille blank, the Mongolian selectors and the default-ignorable code points not yet assigned are now reported.
- **A selector after a digit** (B077): one bit per digit could be carried by U+FE0E or U+FE0F after a digit, `#` or `*`; such a selector now counts unless U+20E3 follows (a keycap).
- **Text that is not UTF-8** (B083, B085, B093, B126; not verified on the agent's side): UTF-16, UTF-32 and a NUL byte were read as replacement characters and passed. B126 is the sharpest: a `.gitattributes` line `working-tree-encoding=UTF-16LE-BOM` keeps the committed file as UTF-8, which GitHub shows, while the checkout OBAAF scans is UTF-16. A file that is not UTF-8 (pictures and archives by their suffix aside) is now a finding identified by a digest of its bytes, as is a file over 2,000,000 bytes; a NUL is a control character.
- **Time** (B095, B096): each character's line was found and hashed again, so 40,000 characters on one line took 8 s. Line and paragraph bounds are found once and each is hashed once; B095 now takes under a second and B096 (400,000 characters in 1.2 MB) 1.2 s, all of it the scan itself.
- **A direction control reaches past its line** (B103, not verified on GitHub's renderer): an accepted U+202E stayed accepted while the lines below it, which rendered Markdown joins into its paragraph, were rewritten. A direction control's digest now covers its whole paragraph, between blank lines (the fact reads "in a paragraph with sha256").

**False positives, now fixed** (B108, B109 but for Malayalam's old chillu spelling, B111, B112): ZWNJ and ZWJ between letters or marks of a script that joins (Arabic and its supplements, Syriac, Thaana, the Indic scripts from Devanagari to Sinhala, Tibetan, Myanmar, Khmer, Mongolian), the England, Scotland and Wales flags (only those three tag sequences), and one presentation selector after a base of Unicode's emoji variation sequences.

**Not fixed, now stated limits.** Joiners between emoji (B078), and between letters of a script that joins, can still carry a bit each. Soft hyphens (B110), right-to-left marks in Hebrew text (B113), ideographic and standardized variation selectors (B114, B115) and the zero-width space in Thai (B116) are still reported: each can carry text, and none is common in instruction files. Out of the rule's scope and recorded only: HTML comments, collapsed sections and link-reference comments in Markdown, which hide text on the rendered view (B097 to B099), escapes in YAML and JSON (B100, B101), whitespace (B067), stacked combining marks (B082) and `linguist-generated` (B127).

### What changed for the first adopter

Expectrail at `efdd1b1` (a read-only copy without anything under `fresh-*`): `obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes` gives the same 44 findings, errors and notes with the old and the new code. After the third review pass, at `3c7ee5c9`, as a copy and as a git work tree of that copy, the code before the slice, the second pass's code and the third pass's code give the same 44 findings, errors and notes. Its CODEOWNERS gives `/.github/` and `/AGENTS.md` to an owner in a valid form, so the new gate finding does not appear, and the only instruction file found, before and after, is `AGENTS.md`. OBAAF's own repository (`*` owned by both maintainers) has no new finding either; `REVIEW.md`, a log of human reviews, is now counted as an instruction file (Copilot code review reads a file of that name) and is owned.

`obaaf proposal check` and the other attest commands use the same scan for patches and comments, so a patch or comment holding a form feed, an escape character or another character the scan now reports is refused where it passed.

### Review

One Opus 5.5 sub-agent that wrote none of it reviewed the slice after the fixes above (first version, `fb16fbb`). It confirmed that the automaton, the regular expression and the plain-text check agree on 200,000 random patterns, that 30,000 fuzzed CODEOWNERS files give no traceback, that Expectrail's output is the same byte for byte, and that Persian, Hindi, Sinhala, CJK and emoji text gives no new false positive. It found 14 blocking defects, all fixed and tested in `ReviewFixesTest`:

1. Following links visited a folder again on every path to it, so 40 committed links made the walk stop at its limit with only a note, and a payload in `.claude/` went unreported (the old code reported it). Each real file is now found once, links add names without walking again, and a limit is an error.
2. The selector and joiner exemptions carried many bits: a selector after any mathematical symbol (`|`, `=`) and a joiner between any letters at or above U+0590 (Han, kana, bold Latin). They are now limited to the bases of emoji variation sequences and to scripts that join (narrowed again in the second pass).
3. A direction control on each of 40,000 lines took 58 s (each paragraph searched again). Bounds are now found once.
4. A file too large to scan was digested on its first 2 MB, so text appended later kept the acceptance. The whole file is digested.
5. The new-workflow names were fixed, so `/.github/workflows/(a*` owned them. Random names were tried at first; the second pass showed they could still be beaten and made the gate random, so a new workflow is now decided from the rules (see below).
6. A CODEOWNERS place GitHub looks in before the one in use needed no owner. It does now.
7. A configuration that is a link kept its target unowned. The target counts.
8. A baseline given through a linked folder (macOS's `/tmp`) was dropped from the list. It is found.
9. `uses: ./.github/../tools/x` was skipped and a linked `action.yml` kept its target unowned. Both count.
10. With no CODEOWNERS file, or one GitHub does not load, an unowned configuration still accepted OBAAF-REPO-001 and 002. Those findings take no acceptance either.
11. An owner with a no-break space or a control character got an owner, because the owner check strips spaces. Such an owner gives no owner.
12. Office, WebAssembly and compiled files in a skill folder were each a high finding, and an installed `node_modules` that ships an AGENTS.md (cytoscape does) gave OBAAF-REPO-002 on a local run. Those suffixes are not scanned, and in a git work tree only tracked files count.
13. The comparison budget counted the cheap plain-text looks, so `*` plus 3,000 package rules and 700 skill files was an error. Only full comparisons count against it; looks have a budget of their own.
14. Claims: the before-and-after tables had been built from an earlier run, and their script did not show the encoding and size findings; the changelog's count of ways past backed by a source was wrong; two attempts (A082, A083) had no test. The tables are rebuilt from the final code, the count is 87 (30 of reviewer A's and 57 of reviewer B's), and the tests are added.

Of 11 non-blocking findings, these were fixed: `?` in the last segment is now one level, like `*`; the dead `_pattern_to_regex` is removed; the folder link's own path needs an owner; `.GitHub/CODEOWNERS` on a file system that ignores case is not `.github/CODEOWNERS`; the firewall policy's place counts whether or not there is a policy; the attest commands' change is now stated. Left as they are: an indented CODEOWNERS line is read as a rule (A053; GitHub's behaviour is not documented, now a stated limit); there are no new-workflow names without a `.github/workflows` folder; each run lists the repository twice; code inside local composite and JavaScript actions is not counted (a stated limit); `test_the_name_is_matched_exactly` passes on the old code on Linux; and a CODEOWNERS file saved with a byte-order mark gives a finding no entry can accept, if GitHub strips the mark.

- **Second pass** (a fresh Opus 5.5 sub-agent, on the fixes above, `a456896`): fixes 6 to 11 and 13 held; no unacceptable finding could be cleared by a path glob, a v0.1 baseline or `--write-baseline` then `--baseline`; a hostile `GIT_DIR`, `GIT_INDEX_FILE`, `GIT_CONFIG_PARAMETERS` or `core.fsmonitor` ran nothing; files committed with `-f`, paths with new lines or bytes that are not UTF-8, and a worktree whose `.git` is a file were found; Expectrail was byte-identical as a copy and as a git work tree. It found 8 blocking defects, all fixed (fixes 3 and 7 got their tests only in the third pass):
  1. The search the advisory notes make called discovery without catching its limit, so one link to an ancestor folder (`docs/up -> ..`) in a repository of 1,000 tracked files ended `obaaf check` in a traceback, and with an agent lane the same link failed the check (each such link gave up to 256 names per file). A link to a folder that holds it (`.`, `..`, the root) is now named and not followed (every file behind it is already found by its own path), and the notes catch the limit.
  2. A ninth link in a chain stopped the search with nothing said. Past eight links (not a loop) it is an error.
  3. A checked-out submodule's files (a `.claude` submodule) were not listed by git, where the old walk read them. git now lists them (`--recurse-submodules`).
  4. Fix 12 let a text file named `.bin`, `.db` or `.DS_Store` carry hidden characters unscanned. Such a name is skipped only when its bytes are not UTF-8 text or hold a NUL.
  5. Random names could still be beaten (`*.*.yml` or `R*` with no owner leaves `release.prod.yml` and `Release.yml` unowned) and made the gate's answer change from run to run. A new workflow is now decided from the rules: the last rule that matches every name `X.yml` (tested with a character no pattern holds, in three lengths) must give an owner, and no later rule that can match some such name (decided on the pattern's automaton) may give none. The answer is the same on every run.
  6. Joiners between marks (`क` then `ं` with ZWJ or ZWNJ, sixty times) and after an Indic mark before a space passed. A joiner is now allowed only between two letters of a script that joins, or after a virama and before such a letter; Malayalam's old chillu spelling (virama, ZWJ, space) is reported again, since Unicode 5.1 has chillu letters. A gap between two letters can still hold a joiner, a non-joiner or nothing, about 1.58 bits.
  7. On Windows, `git` was found by name, and Windows looks in the current folder first, so a `git.exe` committed to the repository could run (not run here; no Windows). git is now found on the `PATH` and never run from inside the repository or the current folder.
  8. `uses: ./` and 300 letters ended the check in a traceback (the path was too long for the file system; older than this slice). It is taken as absent.

  Non-blocking, left as they are: `--write-baseline` leaves an unacceptable finding out without saying why, and `baseline migrate` carries such entries over and counts them; an untracked instruction file in a git work tree is not looked at and no note says so, nor which listing was used when git refuses; `_glob_to_regex` does not match a folder whose name holds a line feed (as before); discovery runs twice per check (13 s on a 510,000-entry tree outside git); a selector after an arrow (U+2190 to U+21FF) passes. Fixed: the test counts above (29 by assertion and 2 by other errors, not 31 by assertion) and a stray line in this record.

- **Third pass** (a fresh Opus 5.5 sub-agent, run `bittern`, on the second pass's fixes, `4f1309e`; about 52 attempts). Run `dipper`'s claim had lapsed with the second pass's fixes pushed and unreviewed. Confirmed: `docs/up -> ..` with 1,000 tracked files takes 0.35 s with the payload reported; chains of eight links work and a ninth is an error; the new-workflow decision agrees with brute force over 2,800 names on 10,000 fuzzed patterns; long, NUL and surrogate local action paths give no traceback in text, JSON or SARIF; 50,000-rule, 1 MB CODEOWNERS files take at most 3.2 s; a hostile `core.fsmonitor` is not run; JSON and SARIF keep their shape; on ten cloned repositories (gemini-cli, biome, codex, ruff, home-assistant, langchain, n8n, workers-sdk, sentry, vscode) and eight more CODEOWNERS files, no traceback or error, and the only new gate findings are the intended ones. It found 9 blocking defects, all fixed and tested in `ThirdReviewTest` (13 tests; on the second pass's code 7 fail by assertion or find nothing, 3 stop on a name that does not exist there, and 3 do not finish within 12 to 40 seconds):
  1. A link to a folder that holds it was named only when `name/_` matched a pattern, so `.github -> .` hid the root's `copilot-instructions.md`, `prompts/` and `skills/` (the first fixes reported them), `.vscode -> .` hid a root `mcp.json`, and `.vscode` leading out of the repository was in neither the note nor OBAAF-REPO-002. Such a link is now followed like any link to a folder: every file behind it is found by the name an agent uses (and, since the fourth pass, a folder already entered on the way is entered again once when a pattern could match beneath the new name). A link out, to nothing or to a pipe (which stalled the read outside git) is named when it or a name a pattern gives beneath it would be an instruction file; a name reached only through a leading `**/` does not count, or every link out would.
  2. The new-workflow decision asked each distinct letter of a rule in turn: a 12 KB rule of 4,000 distinct letters took 26 s. The states reachable after any name are now found in one pass over the pattern (0.003 s for that rule; equal to the old answer on 90,000 random cases).
  3. Each name reached through a link was read and scanned again: 400 links to one 814 KB file took 66 s. Each file is now read and scanned once (0.5 s); since the sixth pass's re-review it is also reported once, with the other names.
  4. git was refused when it lay anywhere under the current folder, so from `/` every git was refused and untracked files counted again (an installed `node_modules` with an AGENTS.md). git is now the first one in an absolute folder of the `PATH` that is outside the repository; relative entries are skipped, so the current folder never supplies it. When the folder holds `.git` and git is not used, a note says that untracked files were looked at.
  5. Python 3.10 and 3.11 have older Unicode tables, so U+0890, U+0891 and U+13439 to U+1343F were reported on Python 3.13 and passed on 3.11. The format characters of Unicode 15.1 are now listed; Python 3.11, 3.12 and 3.13 report the same 4,271 code points (3.10 not run here; CI runs it).
  6. A submodule's files were owned by their inner paths, which GitHub never sees: a pull request changes them only by moving the submodule's entry. Such a file now needs its owner on the entry (`tools/sub`).
  7. A file with a binary name was skipped when one byte was not UTF-8 or it held a NUL, so text with one `\xff` hid tag characters (the code before the slice reported them). Such a file is now skipped only when its bytes look binary: more than one byte in eight, or at least eight and more than one in 64, of its first 64 KiB is a NUL, another control character or part of no UTF-8 character. Otherwise it is read like any file: text with a stray byte is a `not-utf8` finding. A picture over 2,000,000 bytes is no longer a `too-large` finding.
  8. The owner form refused user names that end in a hyphen or hold two in a row, which older accounts keep (Home Assistant's CODEOWNERS names `@freeDom-` and `@viiru-`), so the unacceptable gate finding could not be passed but by dropping the owner. CODEOWNERS owners may now take those forms; an acceptance's owner keeps the stricter form.
  9. Claims: the record still described new workflows by random names; the upgrade note said an accepted direction-control finding is new only when its paragraph has more than its line (every one is new); the record said the second pass's fixes were all tested; the rule's description and the changelog said a selector passes only after a base of Unicode's emoji variation sequences, while about 3,900 code points (the pictograph and arrow ranges) let it pass; the decision said a link to a folder that holds it is named. Each now says what the code does; the selector's reach is a stated limit.

  Non-blocking: fixed, the "is a directory" error for a link to a folder that holds it whose own name matches (now followed), the configuration guide's "rest of its paragraph" (the digest covers the whole paragraph), and a changelog typo. Left as they are: langchain's `./langchain/.github/actions/uv_setup` after a checkout into `langchain` asks for an owner of a path that does not exist (acceptable, and the stricter reading); no new-workflow names without a `.github/workflows` folder.

- **Fourth pass** (a fresh Opus 5.5 sub-agent, run `bittern`, on the third pass's fixes, `1edb579`; about 30 attempts). Confirmed: `.github -> .` and `.vscode -> .` report the root's files; the one-pass reach agrees with the old fixed point on 120,000 random patterns; `find_git` never ran the repository's git (a relative PATH entry, a PATH folder or a git that links into the repository, only the repository's git on the PATH, which gives the walk note); Python 3.11, 3.12 and 3.13 report the same 4,271 code points; older user names own; instruction and CI files in submodules, nested ones included, are owned by the entry; identical findings on the ten cloned repositories and on Expectrail. It found 5 blocking defects, all fixed and tested in `FourthReviewTest` (5 tests; each fails on the third pass's code):
  1. A link back into a folder already entered on the way was skipped, so `.github -> cfg` with `cfg/instructions -> .` hid `cfg/evil.instructions.md`, which an agent reads as `.github/instructions/evil.instructions.md` (the third pass's code reported nothing; the second's an error). Such a link is now followed again at most once on a way through the links, once for each link and set of patterns that could match beneath its name (by whichever way reaches it first; the fifth pass showed another first link on such a way may go unnamed, while the file is still found, owned and scanned), and never when none could: the patterns name at most two folders, so one more entry finds every file a deeper name would.
  2. Three slow cases of a few KiB: 1,000 links to nothing with 3,400-character paths took 27 s (each ran every pattern to the end; now 1.8 s: a pattern stops when it dies or reaches a `**` that takes everything, and a leading `**/` pattern starts only where its own text is found); 5,000 submodule entries took 28 s (each path was compared with each entry; now its folders are looked up); 995 links to a folder of 2,000 files took 20 s and 171 s with long names (each name was tested in full against every pattern; now the short tail is tested against the patterns that start with `**/`, and the whole name only against those the link's name brings in, with the same answers on 60,000 random cases; at most 500,000 entries were looked at behind links, then an error; the fifth pass found that took 46 s on long names, see there). One name is kept for each file and link that leads to it, so 50 links to their own folder in `.claude/` take 3 s and no error.
  3. A gate file inside a submodule (`obaaf.yml -> vendor/policy/obaaf.yml`, or `--baseline vendor/policy/baseline.json`) was owned by its inner path, so the finding no entry can accept could be passed. Gate files now go through the same mapping as the others.
  4. A U+FFFD written in the text counted as a stray byte, so 20 of them made text with tag characters and one bad byte look binary under a `.db` name. Stray bytes are now counted one by one, as bytes that decode to nothing (and DEL counts as a control character).
  5. The rule's description and the changelog said a link out is named when "a name beneath it" would match, and that a link is followed "once for each folder it leads to"; the code leaves out names reached only through a leading `**/`, and did not enter a folder twice. Both now say what the code does; a link out named `docs` to a folder that holds an AGENTS.md is a stated limit.

  Non-blocking, fixed: real archives and documents with text inside (a tar of a text file, a stored zip, an uncompressed PDF) were reported at high; a file named as a picture, archive, document or compiled file that begins as such a file begins (PNG, JPEG, GIF, PDF, zip, gzip, tar, fonts, ELF, SQLite and others) is now not scanned. Left: a submodule that is not checked out (`actions/checkout`'s default) at an instruction path, or reached through a link, is not reported (older than the slice; the checkout decides what the check sees); on Python 3.10 a joiner before a letter added in Unicode 14 is reported where 3.11 lets it pass (not verified; no 3.10 here); invalid bytes count one by one only since this pass.

- **Fifth pass** (a fresh Opus 5.5 sub-agent, run `bittern`, on the fourth pass's fixes, `ba9c3e4`; 18 trees, the ten clones, and 7,000 random trees compared with every name up to seven folders deep). Confirmed: no file in the random trees missed (the fourth pass's code missed 18), no file and link pair the fourth pass found lost, no name a deeper re-entry alone would give, the tail shortcut equal to the full name for ASCII names, the gate file in a submodule mapped, the ten clones identical. It found 5 blocking defects, all fixed and tested in `FifthReviewTest` (3 tests) and the corrected `FourthReviewTest`:
  1. The shortcut put names in lower case with `str.lower()`, while the patterns compare as `re.IGNORECASE` does (`ſ` is `s`, `ı` and `İ` are `i`), so `.github/inſtructions -> ../docs`, `.gıthub -> docs` and `a/.windſurf -> ../docs` were instruction folders to the patterns and not to the shortcut. Characters are now compared as the patterns compare them.
  2. A file read by a text name behind a link to a binary name (`CLAUDE.md -> notes.pdf` beginning `%PDF-`, `AGENTS.md -> helper.exe` beginning `MZ`) was skipped by its beginning. Whether a file is a picture, archive or compiled file is now decided by the name the agent reads.
  3. Time: 300 links back into a folder at a 3,764-character path took 53 s, 440 links to the root 19 s, and 400 links to the root over 1,250 deep files 46 s. The signature is now computed only when needed, the folders a pattern names are looked up among the name's folders, and which files under a folder match the `**/` patterns is found once for each folder however many links lead to it (now 3.8 s, 3.9 s and 3.9 s). The limit on entries looked at behind links is 1,000,000; a tree of 100,000 files with six links to its top (2.9 s) and 600 links to a folder of 2,000 files no longer fail.
  4. `.github/workflows/actions.lock` leading into a submodule was owned by its inner path. It now goes through the same mapping.
  5. The description said a link back into a folder is followed again "once on that way"; the re-entry is once for each link and set of patterns, by whichever way reaches it first, so another first link on the same way may go unnamed (the fourth pass's code named neither; the file is still found, owned and scanned). The description and the decision now say so. The rule's comments no longer say every name gets a finding: one is kept for each file and link.

  Non-blocking, left: links in the middle of a chain never need an owner, only the first (older than this pass).

- **Sixth pass** (a fresh Opus 5.5 sub-agent, run `bittern`, on the fifth pass's fixes, `493d60f`; 11 attempts, two of them every code point against every pattern character). Confirmed: `_same` agrees with `re.IGNORECASE` on every code point; the per-folder cache gives what testing every name gave; the random trees give byte-identical answers to the fifth pass's code; the ten clones are byte-identical; the claims hold. It found no way past and 2 blocking slow cases, both fixed and tested in `SixthReviewTest`: 3,000-character names behind 100 links over 10,000 files (31.5 s; the fifth pass's code took 15 s to the old limit's error), and 100 links behind a 3,000-character name to a folder of 1,990 links to nothing (24.5 s; the code before took 90 s). The characters of names tested behind links now count against a limit of 100,000,000, past which the search is an error (1.7 s and 4.5 s for the two, the check included). Its re-review of that fix found two more paths the count left out, both older than the fix: a link to a file tested its 3,000-character target for each of 199,000 names (17.8 s), and names built for files under a folder whose link brings no pattern were not counted (11.2 s and a 604 MB report). A target is now tested once for each link and counted, and every name built counts (1.7 s, and 2.1 s with the error); `test_a_long_target_and_long_built_names_are_counted`. A last check of that fix found 300 links to one file of 100,000 zero-width spaces made a 2 GB report, one finding with every character for each name; a file is now reported once, on its own path when that is an instruction file and otherwise on the first name, with the other names as a fact (0.8 s, 10 MB, as one such file gave before the slice). Its check found that only the hidden-character finding carried the names, so a file not UTF-8 or too large, once accepted, stayed accepted when one more name came to lead to it (`CLAUDE.md -> legacy.md` passed); every kind now carries them (`test_a_new_name_for_an_accepted_file_is_a_new_finding`). Non-blocking, left: `re`'s `$` matches before a final newline, so a name ending in a newline was taken for an AGENTS.md by the full test and is not by the shortcut (no agent reads it so; the file is found by its own path); and `.` in `(?:.*/)?` does not match a newline, so an AGENTS.md in a folder whose name holds a newline is not found (older than the slice). `obaaf check` runs the search twice (once for the rules and once for the advisory notes), which doubles every time above.

#### Every attempt of reviewer A, before and after the fixes

| Attempt | Rule | What was tried | GitHub's basis, as the reviewer gave it | Before | After | Reviewer's verdict (before) |
| --- | --- | --- | --- | --- | --- | --- |
| A001 | REPO-001 | Control: `/.github/workflows/ @octo-org/ci` | O1, page A | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A002 | REPO-001 | Control: no CODEOWNERS anywhere | L1, L2 | REPO-001 "no CODEOWNERS file" | REPO-001 no CODEOWNERS | held |
| A003 | REPO-001 | Only owner is `octocat` (no `@`) | O1 (form), I1 or O7: either the line is skipped or no owner is assigned; no earlier rule, so no owner | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A004 | REPO-001 | Only owner is `@` alone | O1, O7 | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A005 | REPO-001 | Only owner is `@octo-org/` (empty team) | O1, O7 | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A006 | REPO-001 | Only owner is `ci@example` (e-mail without a dotted domain) | O4; whether GitHub could match such an address: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A007 | REPO-001 | Only owner is `@octocat,` (trailing comma) | O1/O7; whether GitHub strips punctuation: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A008 | REPO-001 | Only owner is `@alice,@bob` (comma-joined) | O1, O6 (owners are listed on the line, separated by spaces in every example); comma splitting: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A009 | REPO-001 | Only owner is `@octocat.` (trailing period) | O7; GitHub's username character set is not on page A: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A010 | REPO-001 | Only owner is `@-octocat` (leading hyphen) | as A009: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A011 | REPO-001 | Only owner is the word `TODO` | O1, I1/O7 | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A012 | REPO-001 | Only owner is `*` | O1, I1/O7 | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A013 | REPO-001 | Only owner `@оctocat` with a Cyrillic о | O7; that usernames are ASCII is not on page A: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A014 | REPO-001 | Only owner `@octo<U+200B>cat` (zero-width space inside) | as A013: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A015 | REPO-001 | Only owner `＠octocat` (FULLWIDTH COMMERCIAL AT) | O1: not the `@username` form | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A016 | REPO-001 | Only owner `<ci@example.com>` | O4; whether GitHub strips `<>`: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A017 | REPO-001 | Pattern and owner joined by U+00A0 NO-BREAK SPACE: `/.github/workflows/<NBSP>@octocat`. Python `str.split()` splits there | N0: GitHub's field separators are not documented; not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A018 | REPO-001 | Same with U+3000 IDEOGRAPHIC SPACE | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A019 | REPO-001 | Same with U+001F UNIT SEPARATOR (Python counts it as whitespace) | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A020 | REPO-001 | `# CI owners<U+2028>/.github/workflows/ @octocat`: one comment line to a reader splitting on LF; two lines to `str.splitlines()` | C1 (lines beginning with `#` are comments); GitHub's line ends: N0, not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A021 | REPO-001 | Same with U+0085 NEL | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A022 | REPO-001 | Same with a lone CR | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A023 | REPO-001 | Same with form feed (OBAAF itself says FF ends no line, D7) | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A024 | REPO-001 | Same with U+001E RECORD SEPARATOR | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A025 | REPO-001 | Only owner `@octocat` followed by byte 0xFF (not UTF-8); read with `errors="replace"` | N0; not verified | none | error: is not UTF-8 text (byte 29), so the checker cannot tell which owners GitHub reads from it | way past (not verified) |
| A026 | REPO-001 | Only owner `@octo<NUL>cat` | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A027 | REPO-001 | UTF-8 BOM before the only owning line | N0; if GitHub strips a BOM the file is owned and OBAAF is wrong, otherwise OBAAF is right: not verified | REPO-001 (ci.yml) | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | false positive (not verified) |
| A028 | REPO-001 | Only owner `@octocat#ci-team`: OBAAF cuts at any `#` and keeps `@octocat` | C1 shows an inline comment after a space only; a `#` inside a token: not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A029 | REPO-001 | `/.github/ @octocat` then `/.github/workflows/#legacy` (no owner): OBAAF reads an owner-less `/.github/workflows/` | C1, G1 (gitignore takes `#` as a comment only at the start); not verified | REPO-001 (ci.yml) | REPO-001 gate files: obaaf.yml | false positive (not verified) |
| A030 | REPO-001 | `\#ci.yml @octocat` with workflow `.github/workflows/#ci.yml` | X1 | REPO-001 (#ci.yml) | REPO-001 CI files: #ci.yml, (new).yaml, (new).yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A031 | REPO-001 | `/.github/ @octocat` then `!/.github/workflows/` | X2 | none (owned by @octocat) | REPO-001 gate files: obaaf.yml | held |
| A032 | REPO-001 | Only rule `!/.github/workflows/ @octocat` | X2 | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A033 | REPO-001 | Only rule `/.github/workflows/[a-z]*.yml @octocat` | X3 | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A034 | REPO-001 | `/.github/ @octocat` then owner-less `/.github/[w]orkflows/` | X3 | none | REPO-001 gate files: obaaf.yml | held |
| A035 | REPO-001 | `/.GitHub/Workflows/ @octocat` | K1 | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A036 | REPO-001 | Rule for `ci.yml`, workflow named `CI.yml` | K1 | REPO-001 (CI.yml) | REPO-001 CI files: (new).yaml, (new).yml, CI.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A037 | REPO-001 | `/.github/work** @octocat`: OBAAF turns `**` into `.*`, crossing `/` | G1 (in gitignore, `**` not next to a slash is a plain `*`) and P3 (a wildcard last segment matches one level); not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A038 | REPO-001 | `/.github/**.yml @octocat` | as A037; not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, obaaf.yml | way past (not verified) |
| A039 | REPO-001 | Only rule `/.github** @octocat` (also "covers" CODEOWNERS) | as A037; not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A040 | REPO-001 | `/.github/workflows/* @octocat` | P3 | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A041 | REPO-001 | `workflows/ @octocat` | P4 | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A042 | REPO-001 | `.github/workflows @octocat` (no slashes at the ends) | P2 (`/apps/github` without a slash names a subdirectory) | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A043 | REPO-001 | `/.github/workflows/ci.yml/ @octocat` (trailing slash on a file) | G1 (gitignore: trailing slash matches directories only) | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A044 | REPO-001 | `/.github/work* @octocat` | P3 by analogy (one level); not verified | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A045 | REPO-001 | `/.github/*/ @octocat` | G1; not verified | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A046 | REPO-001 | `/.github/workflows/c?.yml @octocat` | G1 (`?` is not among X0's exceptions); not verified | none | REPO-001 CI files: (new).yaml, (new).yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A047 | REPO-001 | Only rule `/ @octocat` | not verified (OBAAF matches nothing; GitHub's reading unknown) | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A048 | REPO-001 | `/*/workflows @octocat` | G1; not verified | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A049 | REPO-001 | Owning rule, then owner-less `*.yml` | P1, P2 | REPO-001 | REPO-001 CI files: (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A050 | REPO-001 | Owning rule, then `/.github/ # @octocat` (owner only in a comment) | C1, P2 | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A051 | REPO-001 | Pattern on one line, `@octocat` on the next | O6 | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A052 | REPO-001 | `/.github/workflows/ @octocat` then `/.github/workflows/ octocat-bot` | I1 (line skipped: owned) vs O7 (no owner): which applies is not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 3); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A053 | REPO-001 | Owning line indented with three spaces | N0; G1 (gitignore keeps leading spaces in a pattern); not verified | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A054 | REPO-001 | Tab between pattern and owner | not verified | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A055 | REPO-001 | CRLF line ends | not verified | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A056 | REPO-001 | Workflow `my ci.yml`, rule `/.github/workflows/my\ ci.yml @octocat`: OBAAF splits at the space | N0; escaped spaces not documented: not verified | REPO-001 (my ci.yml) | REPO-001 CI files: (new).yaml, (new).yml, my ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | false positive (not verified) |
| A057 | REPO-001 | Valid owning rules after 3.24 MB of comments | S1, S2 | none | REPO-001 not loaded | way past |
| A058 | REPO-002 | As A057, AGENTS.md owned by a rule in the over-size file | S1, S2 | none | REPO-001 not loaded; REPO-002: AGENTS.md | way past |
| A059 | REPO-001 | `.github/CODEOWNERS` is a directory; root CODEOWNERS owns | L2 (a directory is not a CODEOWNERS file); not verified | none | error: is not a plain file, and whether GitHub then looks in the next place has not been establis | held |
| A060 | REPO-001 | `.github/CODEOWNERS` is a link to `tools/owners.txt`, which owns; OBAAF follows the link | N0; what GitHub reads from a link (git stores the target path as the blob): not verified. OBAAF refuses links for the egress policy (D6) | none | error: is a symbolic link, and what GitHub reads from a link has not been established; make it a  | way past (not verified) |
| A061 | REPO-001 | `.github/CODEOWNERS` is a dangling link; root CODEOWNERS owns; OBAAF skips to the root file (D3) | L2; whether GitHub stops at the link: not verified | none | error: is a symbolic link, and what GitHub reads from a link has not been established; make it a  | way past (not verified) |
| A062 | REPO-001 | `.github/CODEOWNERS` is an absolute link to a file outside the repository with `* @octocat`; OBAAF reads that file | not verified (GitHub cannot read outside the repository) | none | error: is a symbolic link, and what GitHub reads from a link has not been established; make it a  | way past (not verified) |
| A063 | REPO-001 | Owning rules in lowercase `.github/codeowners` (Linux) | L1 names `CODEOWNERS`, K1; whether GitHub accepts other letter case: not verified (if it does, this is a false positive) | REPO-001 "no CODEOWNERS file" | REPO-001 no CODEOWNERS | held |
| A064 | REPO-001 | Comment-only `.github/CODEOWNERS`; root CODEOWNERS `* @octocat` | L2 | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A065 | REPO-001 | Only `docs/CODEOWNERS`, owning | L1, L2 | none | REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, CODEOWNERS | held |
| A066 | REPO-001 | `/.github/workflows/ @octocat` only: CODEOWNERS itself has no owner, so a pull request that only edits CODEOWNERS (deleting the line) needs no owner review; the next one changes workflows freely | F1, F2, B2 | none | REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A067 | REPO-001 | `* @octocat` then owner-less `/.github/CODEOWNERS` | F1, P2 | none | REPO-001 gate files: .github/CODEOWNERS | way past |
| A068 | REPO-001 | `.github/obaaf.yml` (the checker's configuration: ignore entries, lanes, jenkins.exclude) has no owner | CODEOWNERS: no rule matches, so no owner (P2); D5 says it should be owned | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yml | way past |
| A069 | REPO-001 | Workflows unowned; `.github/obaaf.yml` (unowned) adds an ignore entry for OBAAF-REPO-001 with owner, reason, expiry | as A068 | REPO-001 state=suppressed (does not fail) | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yml; REPO-001 CI files: (new).yaml, (new).yml, ci.yml [suppressed] | way past |
| A070 | REPO-001 | CODEOWNERS owns `/.github/obaaf.yml`; a new root `obaaf.yml` (another location the checker reads, unowned) adds the same ignore entry | as A068 | REPO-001 state=suppressed | REPO-001 gate files: .github/egress-firewall.yaml, obaaf.yml; REPO-001 CI files: (new).yaml, (new).yml, ci.yml [suppressed] | way past |
| A071 | REPO-001 | Control: root `Jenkinsfile`, no rule for it | page A (no rule matches) | REPO-001 (Jenkinsfile) | REPO-001 CI files: Jenkinsfile; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A072 | REPO-001 | As A071 plus unowned root `obaaf.yml` with `jenkins: {exclude: [Jenkinsfile]}`: the Jenkinsfile leaves REPO-001 with no acceptance, owner or expiry | as A068 | none | REPO-001 gate files: .github/egress-firewall.yaml, obaaf.yml | way past |
| A073 | REPO-001 | `--baseline obaaf-baseline.json`; the baseline (accepts findings) has no owner | D1 (OBAAF's own advice); page A | none | REPO-001 gate files: obaaf-baseline.json, obaaf.yml | way past |
| A074 | REPO-001 | `.github/egress-firewall.yaml` (OBAAF clears the agent egress finding from it, rules.py `_native_firewall`) has no owner | page A; GitHub firewall behaviour itself not verified | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A075 | REPO-001 | Workflow runs `uses: ./.github/actions/build`; `action.yml` there has no owner | W3 | none | REPO-001 CI files: .github/actions/build/action.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A076 | REPO-001 | Workflow runs `uses: ./`; root `action.yml` has no owner | W3 | none | REPO-001 CI files: action.yml; REPO-001 gate files: obaaf.yml | way past |
| A077 | REPO-001 | Workflow runs `./scripts/release.sh`; script has no owner | D8 (how the project builds and releases); D5 owns `/scripts/` | none | REPO-001 gate files: obaaf.yml | way past |
| A078 | REPO-001 | `/.github/workflows/*.yml @octocat`; `.github/workflows/actions.lock` has no owner | whether GitHub reads `actions.lock`: not verified | none | REPO-001 CI files: (new).yaml, actions.lock; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A079 | REPO-001 | Rule names the one file `/.github/workflows/ci.yml`; any new workflow file has no owner | W2, page A | none | REPO-001 CI files: (new).yaml, (new).yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A080 | REPO-001 | `*.yml @octocat`; a new `.yaml` workflow has no owner | W1 | none | REPO-001 CI files: (new).yaml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml | way past |
| A081 | REPO-001 | `.github/workflows/ci.yml` is a link to `ci/ci.yml`; CODEOWNERS owns `/ci/` only. OBAAF checks `ci/ci.yml` (it resolves the link) | page A: `/ci/` does not match `.github/workflows/ci.yml`; a pull request can replace the link with a file. Whether Actions follows links: not verified, not needed | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A082 | REPO-001 | `.github/workflows` is a link to `ci/workflows`; `/ci/` owned | as A081 | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A083 | REPO-001 | `.github/workflows/ci.yml` links to a file outside the repository; `/.github/workflows/` owned | the path is owned per page A | REPO-001 naming the absolute local path `<repo>/.github/workflows/ci.yml` | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | false positive |
| A084 | REPO-001 | Workflow the checker cannot parse | page A | REPO-001 (ci.yml) + parse error | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml; error: cannot parse YAML: while parsing a flow sequence in "<unicode string>", line 3, column 6:  | held |
| A085 | REPO-001 | `build/Jenkinsfile` (in a directory discovery skips) | page A; which Jenkinsfile a job runs is Jenkins configuration, not GitHub | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A086 | REPO-001 | `vendor/ci/Jenkinsfile` | as A085 | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A087 | REPO-001 | Jenkinsfile seven directories deep | D2 states the six-directory limit | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | under a stated limit |
| A088 | REPO-001 | Root `Jenkinsfile` is a link to `ci/pipeline.groovy` | Jenkins following the link: not verified; the link path itself has no owner | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A089 | REPO-001 | Pipeline at `ci/release.groovy` | D2 (use `jenkins.files`) | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | under a stated limit |
| A090 | REPO-001 | `--platform github` with an unowned Jenkinsfile | CLI help: "which CI definitions to check" | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | under a stated limit |
| A091 | REPO-001 | Control: `/Jenkinsfile @octocat` | page A | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A092 | REPO-002 | `AGENTS.md octocat` (no `@`) | O1, I1/O7 | none | REPO-001 gate files: obaaf.yml; REPO-002: AGENTS.md (bad owner, line 2) | way past |
| A093 | REPO-002 | `AGENTS.md<NBSP>@octocat` | not verified | none | REPO-001 gate files: obaaf.yml; REPO-002: AGENTS.md | way past (not verified) |
| A094 | REPO-002 | `/.claude/ @octo-org/` | O1, O7 | none | REPO-001 gate files: obaaf.yml; REPO-002: .claude/settings.json (bad owner, line 2) | way past |
| A095 | REPO-002 | `# agents<U+2028>CLAUDE.md @octocat` | not verified | none | REPO-001 gate files: obaaf.yml; REPO-002: CLAUDE.md | way past (not verified) |
| A096 | REPO-002 | `/.mcp.json @octocat#mcp` | not verified | none | REPO-001 gate files: obaaf.yml; REPO-002: .mcp.json (bad owner, line 2) | way past (not verified) |
| A097 | REPO-002 | `/.cursor** @octocat` covering `.cursor/rules/style.mdc` | as A037, not verified | none | REPO-001 gate files: obaaf.yml; REPO-002: .cursor/rules/style.mdc | way past (not verified) |
| A098 | REPO-001 | Owner `@this-user-does-not-exist-4711` | O7; OBAAF is offline (D4), no sentence says REPO-001 cannot see accounts | none | REPO-001 gate files: obaaf.yml | under a stated limit |
| A099 | 001+002 | OBAAF's own `CODEOWNERS.example` copied as is (`@your-org/build-owners`) | O2, O3, O7: a team of another organisation has no write access to the repository | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 9); REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml (bad owner, line 9); REPO-002: AGENTS.md (bad owner, line 16) | way past |
| A100 | REPO-002 | `.github/CODEOWNERS` owns `.github/` only; root CODEOWNERS owns AGENTS.md | L2 | REPO-002 (AGENTS.md) | REPO-001 gate files: obaaf.yml; REPO-002: AGENTS.md | held |
| A101 | REPO-002 | 60,000 rules (1.97 MB, under S1) | S1 | correct REPO-002, 25.6-28.8 s over three runs | REPO-001 gate files: obaaf.yml; REPO-002: AGENTS.md, CLAUDE.md | slow |
| A102 | REPO-001 | Rule `*a*a*a*a*a*a*a*a*b` and a workflow named `a`×45`.yml` | - | none, 8.1-9.0 s | REPO-001 gate files: obaaf.yml | slow |
| A103 | REPO-002 | Rule `**/**/**/**/**/**/**/**/zz`, instruction file 31 directories deep under `.claude/` | - | none, 1.9-2.9 s | REPO-001 gate files: obaaf.yml | slow |
| A104 | REPO-001 | Rule `*a`×12`*b`, same workflow name | - | killed after 120 s | REPO-001 gate files: obaaf.yml | slow |
| A105 | REPO-001 | Only owner `@octo-org/ci-team/extra` | O1; not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A106 | REPO-001 | Only owner `@octocat:` | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A107 | REPO-001 | Only owner `"@octocat"` (quoted) | O1: does not start with `@` | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past |
| A108 | REPO-001 | Only owner `@a--b` | not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A109 | REPO-001 | Template placeholder alone: `/.github/workflows/ @your-org/build-owners` and the same for CODEOWNERS | O2, O3, O7 | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/CODEOWNERS, .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml (bad owner, line 2) | way past |
| A110 | REPO-001 | `/.github/workflows/\* @octocat` | G1 (`\*` is a literal star in gitignore) | REPO-001 | REPO-001 CI files: (new).yaml, (new).yml, ci.yml; REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | held |
| A111 | REPO-001 | Lowercase `.github/codeowners`, run with a simulated case-insensitive file system (macOS default): `Path.is_file()` on `.github/CODEOWNERS` finds it | K1 ("GitHub uses a case sensitive file system"); whether GitHub accepts the lowercase name: not verified. Simulated, not a real APFS run | none | REPO-001 no CODEOWNERS | way past (not verified) |
| A112 | REPO-001 | Owner `ci@example.com` (well-formed e-mail) | O4, O5: account and managed-user status cannot be seen offline (D4) | none | REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | under a stated limit |
| A113 | REPO-001 | `/.github/workflows/ @alice, @bob` | I1 (whole line skipped: no owner) vs O7 (only `@alice,` dropped: @bob owns): not verified | none | REPO-001 CI files: (new).yaml, (new).yml, ci.yml (bad owner, line 1); REPO-001 gate files: .github/egress-firewall.yaml, .github/obaaf.yaml, .github/obaaf.yml, obaaf.yml | way past (not verified) |
| A114 | REPO-002 | `docs/*` with `docs/agents/AGENTS.md` | P3 | REPO-002 | REPO-001 gate files: obaaf.yml; REPO-002: docs/agents/AGENTS.md | held |
| A115 | REPO-001 | `.circleci/config.yml` with no owner | REPO-001 text names workflow files and Jenkinsfiles only | none | REPO-001 gate files: obaaf.yml | under a stated limit |
| A116 | REPO-001 | Control for A075: `/.github/` owns the local action | page A | none | REPO-001 gate files: obaaf.yml | held |
| A117 | REPO-001 | Empty `.github/workflows/`, no Jenkinsfile, CODEOWNERS `/src/` | W2 | exit 2 "no CI definitions found ... nothing was checked" |  | held |
| A118 | REPO-001 | Template (team renamed) plus a root Jenkinsfile: the template has no Jenkinsfile rule though REPO-001's fix text asks for one | page A | REPO-001 (Jenkinsfile) | REPO-001 CI files: Jenkinsfile; REPO-001 gate files: obaaf.yml | held |

#### Every attempt of reviewer B, before and after the fixes

| Attempt | Target | What was tried | Basis, as the reviewer gave it | Before | After | Reviewer's verdict (before) |
| --- | --- | --- | --- | --- | --- | --- |
| B001 | discovery | `agents.md` (lower case) at the root, holding a tag-character payload | not verified: on a case-insensitive file system (macOS APFS default, Windows NTFS) an open of AGENTS.md returns agents.md; no vendor page says so | none | INS-001 on `agents.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `agents.md` [new] | way past (not verified) |
| B002 | discovery | `Agents.md` (title case) at the root | not verified (as above) | none | INS-001 on `Agents.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `Agents.md` [new] | way past (not verified) |
| B003 | discovery | `CLAUDE.MD` (upper-case extension) at the root | not verified (as above) | none | INS-001 on `CLAUDE.MD`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `CLAUDE.MD` [new] | way past (not verified) |
| B004 | discovery | `claude.md` in a subdirectory (`src/claude.md`) | not verified (as above) | none | INS-001 on `src/claude.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `src/claude.md` [new] | way past (not verified) |
| B005 | discovery | `AGENTS.override.md` at the root (Codex reads it before AGENTS.md) | Codex: "In each directory along the path, it checks for `AGENTS.override.md`, then `AGENTS.md`," https://learn.chatgpt.com/docs/agent-configuration/agents-md.md | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.override.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 2: `AGENTS.md, AGENTS.override.md` [new] | way past |
| B006 | discovery | `services/api/AGENTS.override.md` (per-directory override, nested) | Codex: "Starting at the project root (typically the Git root), Codex walks down to your current working directory." + the sentence above. https://learn.chatgpt.com/docs/agent-configuration/agents-md.md | none | INS-001 on `services/api/AGENTS.override.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `services/api/AGENTS.override.md` [new] | way past |
| B007 | discovery | `REVIEW.md` at the root (Copilot code review instructions) | GitHub: code review on GitHub.com uses "Agent instructions (using `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` or `REVIEW.md` files)." https://docs.github.com/en/copilot/reference/custom-instructions-support | none | INS-001 on `REVIEW.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `REVIEW.md` [new] | way past |
| B008 | discovery | `packages/web/CLAUDE.local.md` (nested local memory file) | Claude: "Claude also discovers `CLAUDE.md` and `CLAUDE.local.md` files in subdirectories under your current working directory." https://code.claude.com/docs/en/memory | none | INS-001 on `packages/web/CLAUDE.local.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `packages/web/CLAUDE.local.md` [new] | way past |
| B009 | discovery | `build/AGENTS.md` (a committed `build/` folder, as in many Go/C/Kubernetes-style repos) | GitHub: "You can create one or more `AGENTS.md` files, stored anywhere within the repository." https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions | none | INS-001 on `build/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `build/AGENTS.md` [new] | way past |
| B010 | discovery | `dist/CLAUDE.md` (committed `dist/`, normal for JavaScript GitHub Actions) | Claude: CLAUDE.md files in subdirectories "are included when Claude reads files in those subdirectories." https://code.claude.com/docs/en/memory | none | INS-001 on `dist/CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `dist/CLAUDE.md` [new] | way past |
| B011 | discovery | `node_modules/tool/AGENTS.md` (committed node_modules, still seen in JavaScript actions) | GitHub: AGENTS.md "stored anywhere within the repository" https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions | none | INS-001 on `node_modules/tool/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `node_modules/tool/AGENTS.md` [new] | way past |
| B012 | discovery | `venv/AGENTS.md`, `.venv/CLAUDE.md`, `__pycache__/AGENTS.md` (committed virtualenv/cache folders) | GitHub: AGENTS.md "stored anywhere within the repository" https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions; realistic only for badly kept repos | none | INS-001 on `.venv/CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 3: `.venv/CLAUDE.md, __pycache__/AGENTS.md, venv/AGENTS.md` [new] | way past |
| B013 | discovery | a Claude skill named `build`: `.claude/skills/build/SKILL.md` (SKIP_DIRS applies inside `.claude/`) | Claude: project skills live at "`.claude/skills/<skill-name>/SKILL.md`" https://code.claude.com/docs/en/skills.md | none | INS-001 on `.claude/skills/build/SKILL.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.claude/skills/build/SKILL.md` [new] | way past |
| B014 | discovery | Claude rules in a `build/` subfolder: `.claude/rules/build/ci.md` | Claude: "All `.md` files are discovered recursively, so you can organize rules into subdirectories like `frontend/` or `backend/`" https://code.claude.com/docs/en/memory | none | INS-001 on `.claude/rules/build/ci.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.claude/rules/build/ci.md` [new] | way past |
| B015 | discovery | Copilot path-specific instructions in `.github/instructions/build/ci.instructions.md` | GitHub: "Optionally, create subdirectories of `.github/instructions` to organize your instruction files." https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions | none | INS-001 on `.github/instructions/build/ci.instructions.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.github/instructions/build/ci.instructions.md` [new] | way past |
| B016 | discovery | Cursor rules in `.cursor/rules/dist/release.mdc` | Cursor: "Cursor discovers rules by scanning this folder, so nested subfolders work" https://cursor.com/help/customization/rules.md | none | INS-001 on `.cursor/rules/dist/release.mdc`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.cursor/rules/dist/release.mdc` [new] | way past |
| B017 | discovery | Unity/Unreal-named folders: `Library/AGENTS.md`, `Saved/AGENTS.md`, `Binaries/CLAUDE.md`, `Intermediate/AGENTS.md` | GitHub: AGENTS.md "stored anywhere within the repository" https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/add-custom-instructions/add-repository-instructions; in Unity `Library/` is normally ignored, so realism is low | none | INS-001 on `Binaries/CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 4: `Binaries/CLAUDE.md, Intermediate/AGENTS.md, Library/AGENTS.md, Save...` [new] | way past |
| B018 | discovery | `docs/build/GEMINI.md` (skipped folder at depth) | Gemini CLI: when a tool touches a path "the CLI automatically scans for `GEMINI.md` files in that directory and its ancestors up to a trusted root." https://geminicli.com/docs/cli/gemini-md/ | none | INS-001 on `docs/build/GEMINI.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `docs/build/GEMINI.md` [new] | way past |
| B019 | discovery | `CLAUDE.md` is a symlink to `notes/style.txt`, which holds the payload | Claude docs show symlinked memory files ("ln -s AGENTS.md CLAUDE.md"); open() follows symlinks. https://code.claude.com/docs/en/memory | none | INS-001 on `CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 2: `CLAUDE.md, notes/style.txt` [new] | way past |
| B020 | discovery | control: `AGENTS.md` -> `CLAUDE.md` where CLAUDE.md is a real file with the payload | control (target itself matches a pattern) | INS-001 on `CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `CLAUDE.md` [new] | INS-001 on `AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 2: `AGENTS.md, CLAUDE.md` [new] | held |
| B021 | discovery | `.claude/rules/shared.md` is a symlink to `shared/rules.md` | Claude: "The `.claude/rules/` directory supports symlinks ... Symlinks are resolved and loaded normally" https://code.claude.com/docs/en/memory | INS-001: none; REPO-002 lists 1: `.claude/rules/style.md` [new] | INS-001 on `.claude/rules/shared.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 3: `.claude/rules/shared.md, .claude/rules/style.md, shared/rules.md` [new] | way past |
| B022 | discovery | skill folder symlink: `.claude/skills/deploy` -> `tools/deploy-skill/` (SKILL.md in target) | Claude: "a `<skill-name>` entry in the enterprise, personal, or project location can be a symlink to a directory elsewhere on disk. Claude Code reads `SKILL.md` from the target" https://code.claude.com/docs/en/skills.md | none | INS-001 on `.claude/skills/deploy/SKILL.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 3: `.claude/skills/deploy, .claude/skills/deploy/SKILL.md, tools/deploy...` [new] | way past |
| B023 | discovery | whole `.cursor/rules` folder is a symlink to `config/cursor-rules/` | not verified for Cursor (its pages do not mention symlinks); path resolution follows a symlinked directory for any program | none | INS-001 on `.cursor/rules/style.mdc`: 72 char(s), first U+E0049 [new]; REPO-002 lists 3: `.cursor/rules, .cursor/rules/style.mdc, config/cursor-rules/style.mdc` [new] | way past (not verified) |
| B024 | discovery | whole `.claude` folder is a symlink to `build/claude/` (settings.json, CLAUDE.md, skills all inside a skipped folder) | Claude documents `.claude/CLAUDE.md`, `.claude/skills/`, `.claude/rules/` (https://code.claude.com/docs/en/memory); a symlinked directory is resolved by the OS for every path below it | none | INS-001 on `.claude/CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 5: `.claude, .claude/CLAUDE.md, .claude/settings.json, build/claude/CLA...` [new] | way past |
| B025 | discovery | `CLAUDE.md` is an absolute symlink out of the repository (`/etc/hostname`) | Claude follows symlinked CLAUDE.md (as above); the target is whatever the runner has at that path | none | INS-001: none; REPO-002 lists 1: `CLAUDE.md` [new] | way past |
| B026 | discovery | CLAUDE.md imports `@docs/agent-guide.md`; the payload is in the imported file | Claude: "CLAUDE.md files can import additional files using `@path/to/import` syntax. Imported files are expanded and loaded into context at launch" https://code.claude.com/docs/en/memory | INS-001: none; REPO-002 lists 1: `CLAUDE.md` [new] | INS-001: none; REPO-002 lists 1: `CLAUDE.md` [new] | way past |
| B027 | discovery | GEMINI.md imports `@./docs/context.md` | Gemini CLI: content from other files is pulled in "using the `@file.md` syntax" https://geminicli.com/docs/cli/gemini-md/ | INS-001: none; REPO-002 lists 1: `GEMINI.md` [new] | INS-001: none; REPO-002 lists 1: `GEMINI.md` [new] | way past |
| B028 | discovery | `.gemini/settings.json` sets `context.fileName` to `CONTEXT.md`; payload in CONTEXT.md | Gemini CLI: "To specify a different name or a list of names, use the `context.fileName` property." https://geminicli.com/docs/cli/gemini-md/ | INS-001: none; REPO-002 lists 1: `.gemini/settings.json` [new] | INS-001: none; REPO-002 lists 1: `.gemini/settings.json` [new] | way past |
| B029 | discovery | `.aider.conf.yml` has `read: CONVENTIONS.md`; payload in CONVENTIONS.md | Aider: "You can also configure aider to always load your conventions file in the `.aider.conf.yml` config file:" (`read: CONVENTIONS.md`) https://aider.chat/docs/usage/conventions.html | INS-001: none; REPO-002 lists 1: `.aider.conf.yml` [new] | INS-001: none; REPO-002 lists 1: `.aider.conf.yml` [new] | way past |
| B030 | discovery | `services/api/.aider.conf.yml` (config in the current directory, not the root) with a hidden character in `test-cmd` | Aider looks for the file in "Your home directory.", "The root of your git repo.", "The current directory." https://aider.chat/docs/config/aider_conf.html | none | INS-001 on `services/api/.aider.conf.yml`: 2 char(s), first U+202E [new]; REPO-002 lists 1: `services/api/.aider.conf.yml` [new] | way past |
| B031 | discovery | `opencode.json` lists `docs/guidelines.md` under `instructions`; payload there | OpenCode: "You can specify custom instruction files in your `opencode.json`" (example `"instructions": ["CONTRIBUTING.md", "docs/guidelines.md", ".cursor/rules/*.md"]`) https://opencode.ai/docs/rules/ | INS-001: none; REPO-002 lists 1: `opencode.json` [new] | INS-001: none; REPO-002 lists 1: `opencode.json` [new] | way past |
| B032 | discovery | AGENTS.md @-mentions `@docs/amp-notes.md` (Amp includes it) | Amp: "To include other files as context, @-mention them in agent files." https://ampcode.com/docs/customize/agents-md | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B033 | discovery | a discovered Cursor rule references `@docs/rule-extra.md` | Cursor: "Use @filename.ts to include files in your rule's context." https://docs.cursor.com/context/rules | INS-001: none; REPO-002 lists 1: `.cursor/rules/base.mdc` [new] | INS-001: none; REPO-002 lists 1: `.cursor/rules/base.mdc` [new] | way past |
| B034 | discovery | control: a skill's supporting file `.claude/skills/review/reference.md` | control (inside `.claude/**`) | INS-001 on `.claude/skills/review/reference.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 2: `.claude/skills/review/SKILL.md, .claude/skills/review/reference.md` [new] | INS-001 on `.claude/skills/review/reference.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 2: `.claude/skills/review/SKILL.md, .claude/skills/review/reference.md` [new] | held |
| B035 | discovery | control: `.github/instructions/py.instructions.md` with `applyTo` | control (`.github/instructions/**`) | INS-001 on `.github/instructions/py.instructions.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.github/instructions/py.instructions.md` [new] | INS-001 on `.github/instructions/py.instructions.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.github/instructions/py.instructions.md` [new] | held |
| B036 | discovery | `.vscode/settings.json` adds `docs/ai` via `chat.instructionsFilesLocations`; payload in `docs/ai/style.instructions.md` | VS Code: "The `setting(chat.instructionsFilesLocations)` setting adds search locations." https://code.visualstudio.com/docs/agents/reference/custom-instructions-reference.md | none | none | way past |
| B037 | discovery | `.github/skills/release/SKILL.md` | GitHub: "create a `.github/skills`, `.claude/skills`, or `.agents/skills` directory in your repository." / "Existing skills within the `.github/skills` directory can also be used by Copilot code review automatically" https://docs.github.com/en/copilot/how-tos/use-copilot-agents/cloud-agent/create-skills | none | INS-001 on `.github/skills/release/SKILL.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.github/skills/release/SKILL.md` [new] | way past |
| B038 | discovery | `.agents/skills/release/SKILL.md` | GitHub (same quote) https://docs.github.com/en/copilot/how-tos/use-copilot-agents/cloud-agent/create-skills | none | INS-001 on `.agents/skills/release/SKILL.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.agents/skills/release/SKILL.md` [new] | way past |
| B039 | discovery | `.github/hooks/policy.json` (commands the agent runs on events) | GitHub: "For Copilot CLI and Copilot cloud agent, you can define repository hooks in `.github/hooks/*.json`." https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-hooks | none | INS-001 on `.github/hooks/policy.json`: 1 char(s), first U+202E [new]; REPO-002 lists 1: `.github/hooks/policy.json` [new] | way past |
| B040 | discovery | `.cursor/mcp.json` (project MCP servers) | Cursor: "Create `.cursor/mcp.json` in your project for project-specific tools." https://cursor.com/docs/mcp.md | none | INS-001 on `.cursor/mcp.json`: 1 char(s), first U+200B [new]; REPO-002 lists 1: `.cursor/mcp.json` [new] | way past |
| B041 | discovery | nested Cursor rules: `packages/web/.cursor/rules/style.mdc` | Cursor: "Subdirectories can include their own .cursor/rules directory scoped to that folder." https://docs.cursor.com/context/rules | none | INS-001 on `packages/web/.cursor/rules/style.mdc`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `packages/web/.cursor/rules/style.mdc` [new] | way past |
| B042 | discovery | nested Windsurf rules: `packages/web/.windsurf/rules/style.md` | Windsurf: "All `.windsurf/rules` directories within your current workspace and its sub-directories" https://docs.devin.ai/windsurf/plugins/cascade/memories.md | none | INS-001 on `packages/web/.windsurf/rules/style.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `packages/web/.windsurf/rules/style.md` [new] | way past |
| B043 | discovery | Cline `.cline/rules/style.md` | Cline: "Workspace rules go in `.clinerules/` or `.cline/rules/` at your project root." https://docs.cline.bot/customization/cline-rules.md | none | INS-001 on `.cline/rules/style.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.cline/rules/style.md` [new] | way past |
| B044 | discovery | Junie `.junie/guidelines.md` | Junie: "`.junie/guidelines.md` file or `.junie/guidelines/` folder – Junie's legacy format for guidelines (still supported)." https://junie.jetbrains.com/docs/guidelines-and-memory.html | none | INS-001 on `.junie/guidelines.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.junie/guidelines.md` [new] | way past |
| B045 | discovery | control: Junie `.junie/AGENTS.md` | Junie: "`.junie/AGENTS.md` file in the project root." https://junie.jetbrains.com/docs/guidelines-and-memory.html | INS-001 on `.junie/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.junie/AGENTS.md` [new] | INS-001 on `.junie/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.junie/AGENTS.md` [new] | held |
| B046 | discovery | Junie `.junie/rules/style.md` and `.junie/playbook.md` | Junie: "`AGENTS.md` file in the project root, combined with `.junie/playbook.md` and every `.junie/rules/*.md` file, if present." https://junie.jetbrains.com/docs/guidelines-and-memory.html | none | INS-001 on `.junie/playbook.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 2: `.junie/playbook.md, .junie/rules/style.md` [new] | way past |
| B047 | discovery | Amazon Q `.amazonq/rules/style.md` | Amazon Q: "Project rules are defined in Markdown files in the project's `{{project-root}}/.amazonq/rules` folder." https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/context-project-rules.md | none | INS-001 on `.amazonq/rules/style.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.amazonq/rules/style.md` [new] | way past |
| B048 | discovery | Amazon Q MCP config `.amazonq/default.json` and legacy `.amazonq/mcp.json` | Amazon Q: "If you select local scope, the configuration is stored in .amazonq/default.json within your current project." / "At the local scope: .amazonq/mcp.json" https://docs.aws.eu/amazonq/latest/qdeveloper-ug/mcp-ide.html | none | INS-001 on `.amazonq/default.json`: 1 char(s), first U+200B [new]; REPO-002 lists 2: `.amazonq/default.json, .amazonq/mcp.json` [new] | way past |
| B049 | discovery | Kiro steering `.kiro/steering/product.md` | Kiro: "Workspace steering files reside in your project root folder under `.kiro/steering/`" https://kiro.dev/docs/steering/ | none | INS-001 on `.kiro/steering/product.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.kiro/steering/product.md` [new] | way past |
| B050 | discovery | Kiro MCP `.kiro/settings/mcp.json` | Kiro: "Workspace Level: `.kiro/settings/mcp.json`" https://kiro.dev/docs/mcp/configuration/ | none | INS-001 on `.kiro/settings/mcp.json`: 1 char(s), first U+200B [new]; REPO-002 lists 1: `.kiro/settings/mcp.json` [new] | way past |
| B051 | discovery | Zed `.rules` at the root | Zed: "Zed supports including .rules files at the top level of worktrees" https://zed.dev/docs/ai/rules | none | INS-001 on `.rules`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.rules` [new] | way past |
| B052 | discovery | Augment `.augment/rules/style.md` and `.augment-guidelines` | Augment: "Rules are files that live in the `.augment/rules` directory." / "You can add an `.augment-guidelines` file to the root of a repository" https://docs.augmentcode.com/setup-augment/guidelines | none | INS-001 on `.augment-guidelines`: 72 char(s), first U+E0049 [new]; REPO-002 lists 2: `.augment-guidelines, .augment/rules/style.md` [new] | way past |
| B053 | discovery | Roo Code `.roo/rules/style.md`, `.roorules`, `.roomodes` | not verified: the vendor page https://docs.roocode.com/features/custom-instructions could not be fetched in this session | none | none | way past (not verified) |
| B054 | discovery | nested Claude skills: `packages/web/.claude/skills/lint/SKILL.md` | Claude: Nested "`<subdir>/.claude/skills/<skill-name>/SKILL.md`" ... "a session started above it loads the skill once Claude works on files there." https://code.claude.com/docs/en/skills.md | none | INS-001 on `packages/web/.claude/skills/lint/SKILL.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `packages/web/.claude/skills/lint/SKILL.md` [new] | way past |
| B055 | discovery | control: `.claude/CLAUDE.md` | Claude: "A project CLAUDE.md can be stored in either `./CLAUDE.md` or `./.claude/CLAUDE.md`." https://code.claude.com/docs/en/memory | INS-001 on `.claude/CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.claude/CLAUDE.md` [new] | INS-001 on `.claude/CLAUDE.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.claude/CLAUDE.md` [new] | held |
| B056 | discovery | Windsurf workflows `.windsurf/workflows/deploy.md` | not verified (no vendor page read for workflows) | none | INS-001 on `.windsurf/workflows/deploy.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `.windsurf/workflows/deploy.md` [new] | way past (not verified) |
| B057 | INS-001 | `.github/workflows/copilot-setup-steps.yml` with a right-to-left override in a `run:` line | GitHub runs this workflow to prepare the coding agent; it is a CI file, so REPO-001 owns it and INS-001 does not scan it | none | none | out of scope |
| B058 | INS-001 | U+206A/U+206B (deprecated format characters, Cf) as a binary channel carrying an instruction | Unicode: U+206A..U+206F are Cf and Default_Ignorable_Code_Point (rendered invisibly) | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+206A [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B059 | INS-001 | U+FFF9/U+FFFA (interlinear annotation anchors, Cf) as a binary channel | Unicode: U+FFF9..U+FFFB are Cf format controls | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+FFF9 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B060 | INS-001 | U+1D173/U+1D174 (musical symbol begin/end beam, Cf) as a binary channel | Unicode: U+1D173..U+1D17A are Cf and Default_Ignorable_Code_Point | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+1D173 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B061 | INS-001 | U+13430/U+13431 (Egyptian hieroglyph format controls, Cf) as a binary channel | Unicode: U+13430..U+1343F are Cf | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+13430 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B062 | INS-001 | U+180B/U+180C (Mongolian free variation selectors) as a binary channel | Unicode: U+180B..U+180D and U+180F are Default_Ignorable_Code_Point (U+180E is flagged, they are not) | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+180B [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B063 | INS-001 | U+2028 / U+2029 inside a line | Unicode: Zl/Zp separators; they break lines but do not hide text | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 2 char(s), first U+2028 [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B064 | INS-001 | U+115F/U+1160 (Hangul choseong/jungseong fillers) as a binary channel; U+3164 and U+FFA0 fillers | Unicode: U+115F, U+1160, U+3164, U+FFA0 are Default_Ignorable_Code_Point (Lo letters that render blank) | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 338 char(s), first U+115F [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B065 | INS-001 | U+2800 braille pattern blank (So) as a binary channel with U+3000 | Unicode: U+2800 renders as an empty cell; not Cf or default-ignorable, so only visible as extra blank space | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 177 char(s), first U+2800 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B066 | INS-001 | U+17B4/U+17B5 (Khmer inherent vowels, Mn, zero width) as a binary channel | Unicode: U+17B4..U+17B5 are Default_Ignorable_Code_Point | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+17B4 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B067 | INS-001 | space characters (U+00A0, U+2000..U+200A, U+202F, U+205F, U+3000, U+1680) at line end as whitespace steganography | Unicode: Zs spaces are visible blank space; a payload needs a decoder; flagging them costs false positives | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | out of scope |
| B068 | INS-001 | unassigned default-ignorables U+FFF0..U+FFF8 and U+2065 as a binary channel | Unicode: these are Default_Ignorable_Code_Point (reserved), so renderers show nothing | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+FFF0 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B069 | INS-001 | plane-14 unassigned default-ignorables: ASCII shifted to U+E0080+ (one code point per character, like tags) | Unicode: U+E0080..U+E00FF and U+E01F0..U+E0FFF are Default_Ignorable_Code_Point; whether a model reads them is not verified | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 42 char(s), first U+E00E3 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B070 | INS-001 | U+1BCA0/U+1BCA1 (shorthand format controls, Cf) as a binary channel | Unicode: U+1BCA0..U+1BCA3 are Cf and Default_Ignorable_Code_Point | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 336 char(s), first U+1BCA0 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B071 | INS-001 | prepended concatenation marks U+0600..U+0605, U+06DD, U+070F, U+0890, U+08E2, U+110BD (Cf) | Unicode: Cf but rendered with a visible glyph (number signs); U+070F may render invisibly (not verified) | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 11 char(s), first U+0600 [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B072 | INS-001 | C0/C1 control characters: ANSI conceal (ESC [8m ... ESC [0m) hiding a sentence, plus U+0080/U+0081 as a binary channel | ECMA-48: SGR 8 conceals text in terminals (git diff in a terminal, cat); GitHub web rendering of C0/C1 not verified | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 338 char(s), first U+001B [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past (not verified) |
| B073 | INS-001 | control: tag characters (ASCII smuggling) | Unicode: U+E0000..U+E007F tags | INS-001 on `AGENTS.md`: 42 char(s), first U+E0063 [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 42 char(s), first U+E0063 [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B074 | INS-001 | tag payload riding inside an England subdivision flag (U+1F3F4 + tag letters + payload + U+E007F) | Unicode: emoji tag sequences use U+E0020..U+E007E then CANCEL TAG | INS-001 on `AGENTS.md`: 49 char(s), first U+E0067 [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 49 char(s), first U+E0067 [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B075 | INS-001 | control: variation-selector byte smuggling (one emoji followed by VS17..VS256 bytes) | Unicode: U+E0100..U+E01EF; the 'emoji smuggling' encoding | INS-001 on `AGENTS.md`: 42 char(s), first U+E0153 [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 42 char(s), first U+E0153 [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B076 | INS-001 | control: U+FE00..U+FE0D after letters | Unicode: standardized variation selectors | INS-001 on `AGENTS.md`: 3 char(s), first U+FE00 [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 3 char(s), first U+FE00 [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B077 | INS-001 | bit channel through the exemption: digits each followed by U+FE0E (0) or U+FE0F (1) | Unicode: FE0E/FE0F after a digit are allowed by scan_hidden (keycap base); one bit per digit; some platforms draw digit+FE0F in emoji style, so not invisible everywhere | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 48 char(s), first U+FE0E [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B078 | INS-001 | bit channel through the exemption: zero-width joiner present (1) or absent (0) between adjacent emoji | Unicode: ZWJ between two Extended_Pictographic characters is allowed by scan_hidden even when the pair forms no RGI sequence | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | way past |
| B079 | INS-001 | control: a run of U+FE0F after one emoji | Unicode: only one presentation selector is meaningful | INS-001 on `AGENTS.md`: 3 char(s), first U+FE0F [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 3 char(s), first U+FE0F [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B080 | INS-001 | control: byte-order mark in the middle of the file | Unicode: U+FEFF ZWNBSP | INS-001 on `AGENTS.md`: 1 char(s), first U+FEFF [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+FEFF [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B081 | INS-001 | control: two byte-order marks at the start | Unicode: only the first is a BOM | INS-001 on `AGENTS.md`: 1 char(s), first U+FEFF [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+FEFF [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B082 | INS-001 | combining marks stacked on a base ('Zalgo') over a sentence | Unicode: Mn marks are visible; they obscure but do not hide | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | out of scope |
| B083 | INS-001 | AGENTS.md saved as UTF-16LE with BOM, containing U+202E and tag characters | read_text(utf-8, errors=replace) turns it into U+FFFD + NUL-interleaved ASCII; whether agents decode UTF-16 is not verified; git shows NUL-bearing files as binary | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | way past (not verified) |
| B084 | INS-001 | AGENTS.md as UTF-16BE without BOM | an agent would have to guess UTF-16 with no BOM; not verified that any does | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B085 | INS-001 | AGENTS.md as UTF-32LE with BOM | as UTF-16LE; not verified | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | way past (not verified) |
| B086 | INS-001 | UTF-8 with stray invalid bytes next to a U+202E | invalid bytes become U+FFFD; the valid hidden character is still decoded | INS-001 on `AGENTS.md`: 1 char(s), first U+202E [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B087 | INS-001 | overlong 4-byte UTF-8 encoding of U+202E (F0 82 80 AE) | Unicode/RFC 3629: overlong forms are ill-formed; conformant decoders (Python, WHATWG, Rust, Go) yield U+FFFD | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B088 | INS-001 | CESU-8 (surrogate halves) encoding of tag characters | Unicode: surrogate code points are ill-formed in UTF-8; conformant decoders yield U+FFFD | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B089 | INS-001 | Windows-1252 file with byte 0xAD (soft hyphen in cp1252) inside words | OBAAF sees U+FFFD (visible); a cp1252 reader sees soft hyphens (which only split words); not verified any agent decodes cp1252 | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B090 | INS-001 | UTF-7 encoded U+202E ('+ICo-') | no mainstream agent decodes UTF-7; the text is visible ASCII | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B091 | INS-001 | valid in two encodings: ASCII text whose UTF-16LE reading contains U+202E ('. ' at an even offset) | a decoder would need to choose UTF-16 with no BOM; not verified any agent does | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B092 | INS-001 | CR-only line endings around a hidden character | Python universal newlines turn CR into LF | INS-001 on `AGENTS.md`: 1 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B093 | INS-001 | NUL byte at the top of AGENTS.md: git and GitHub's diff treat the file as binary, so a reviewer sees no text at all | git diffs a file with a NUL near its start as binary (verified locally with git 2.43: 'Binary files ... differ'); GitHub PR view and agent reading of such a file not verified | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+0000 [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past (not verified) |
| B094 | INS-001 | 10 MB single line with no hidden characters (time) | linear scan | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new]; took 3.2 s | INS-001 on `AGENTS.md`: too large to scan; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B095 | INS-001 | 40,000 zero-width spaces on one line (120 KB file) | _line_digests hashes the whole line once per hidden character: O(n^2) | INS-001 on `AGENTS.md`: 40000 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new]; took 8.0 s | INS-001 on `AGENTS.md`: 40000 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | slow |
| B096 | INS-001 | 200 lines of 2,000 zero-width spaces each (1.2 MB) | same cost per line | INS-001 on `AGENTS.md`: 400000 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new]; took 5.0 s | INS-001 on `AGENTS.md`: 400000 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new]; took 1.3 s | slow |
| B097 | INS-001 | HTML comment `<!-- ... -->` holding an instruction (hidden on GitHub's rendered Markdown view) | GitHub's Markdown renderer does not display HTML comments; the rule is about Unicode characters | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | out of scope |
| B098 | INS-001 | collapsed `<details>` block | collapsed by default on the rendered view, but one click away | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | out of scope |
| B099 | INS-001 | Markdown link-reference 'comment' `[//]: # (...)` | not rendered on GitHub's Markdown view | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | out of scope |
| B100 | INS-001 | YAML escapes in a skill's front matter: `description: "Lint\U000E0049..."` (ASCII on disk, tag characters after parsing) | YAML double-quoted \U escapes decode to the code point; the escape text is visible in the diff | INS-001: none; REPO-002 lists 1: `.claude/skills/lint/SKILL.md` [new] | INS-001: none; REPO-002 lists 1: `.claude/skills/lint/SKILL.md` [new] | out of scope |
| B101 | INS-001 | JSON escapes `\u202e` in `.mcp.json` args | JSON \u escapes decode to the code point; escape text is visible | INS-001: none; REPO-002 lists 1: `.mcp.json` [new] | INS-001: none; REPO-002 lists 1: `.mcp.json` [new] | out of scope |
| B102 | identity | accepted: a ZWNJ in a Persian word; then a tag payload is added on another line | facts list changes, so the finding is new | INS-001 on `AGENTS.md`: 73 char(s), first U+200C [new]; REPO-002 lists 1: `AGENTS.md` [accepted] | INS-001 on `AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B103 | identity | accepted: a line holding only U+202E (stray override); later the following lines of the same Markdown paragraph are rewritten (reversed text the override now displays backwards) | UAX #9 X8 ends overrides only at a paragraph end; in rendered Markdown, source lines of one paragraph are one HTML block, so the override reaches lines the digest does not cover; GitHub's rendering not verified | INS-001 on `AGENTS.md`: 1 char(s), first U+202E [accepted]; REPO-002 lists 1: `AGENTS.md` [accepted] | INS-001 on `AGENTS.md`: 1 char(s), first U+202E [new]; REPO-002 lists 1: `AGENTS.md` [new] | way past (not verified) |
| B104 | identity | accepted: one ZWSP on a line; then a second ZWSP is added to the same line | the line digest changes | INS-001 on `AGENTS.md`: 2 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [accepted] | INS-001 on `AGENTS.md`: 2 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B105 | identity | accepted: U+202E on a line with an invalid byte 0xFF; then the byte is changed to 0xFE | both decode to U+FFFD, so the digest and the identity are equal; matters only to a non-UTF-8 reader (not verified) | INS-001 on `AGENTS.md`: 1 char(s), first U+202E [accepted]; REPO-002 lists 1: `AGENTS.md` [accepted] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B106 | identity | accepted: a ZWSP on a line; the same line is then duplicated elsewhere in the file | the facts list keeps duplicates, so the finding is new | INS-001 on `AGENTS.md`: 2 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [accepted] | INS-001 on `AGENTS.md`: 2 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B107 | identity | accepted: U+202E on a line; text after a U+2028 on the same LF-line is changed | the digest runs to the next LF, past U+2028 | INS-001 on `AGENTS.md`: 1 char(s), first U+202E [new]; REPO-002 lists 1: `AGENTS.md` [accepted] | INS-001 on `AGENTS.md`: 2 char(s), first U+202E [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B108 | false-positive | Persian with ZWNJ: «می‌خواهم کد را به‌روز کنم» | Unicode: ZWNJ is required in Persian orthography | INS-001 on `AGENTS.md`: 2 char(s), first U+200C [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B109 | false-positive | Sinhala «ශ්‍රී» and Malayalam/Hindi conjunct control with ZWJ/ZWNJ | Unicode Core Spec ch. 12/13: ZWJ/ZWNJ select conjunct and half forms in Indic scripts | INS-001 on `AGENTS.md`: 4 char(s), first U+200D [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+200D [new]; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B110 | false-positive | German with soft hyphens (word-processor output): Donau­dampf­schiff­fahrt | Unicode: U+00AD is an ordinary hyphenation hint | INS-001 on `AGENTS.md`: 3 char(s), first U+00AD [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 3 char(s), first U+00AD [new]; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B111 | false-positive | subdivision flags England, Scotland, Wales | Unicode TS #51: RGI emoji tag sequences 🏴+gbeng/gbsct/gbwls+CANCEL TAG | INS-001 on `AGENTS.md`: 18 char(s), first U+E0067 [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B112 | false-positive | emoji with U+FE0F whose base lies outside `_is_pictographic`: ▶️ ◀️ ▪️ ▫️ ◻️ ◼️ Ⓜ️ ⤴️ ⤵️ 〰️ 〽️ ㊗️ ㊙️ | Unicode emoji-variation-sequences.txt lists all of these bases | INS-001 on `AGENTS.md`: 13 char(s), first U+FE0F [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B113 | false-positive | Hebrew with a right-to-left mark after a number: «גרסה 2.0‏ (בטא)» | Unicode: RLM is the standard way to place neutrals in RTL text; it is a direction-affecting mark, so flagging it is arguably intended | INS-001 on `AGENTS.md`: 1 char(s), first U+200F [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+200F [new]; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B114 | false-positive | Japanese ideographic variation sequence in a place name: 葛󠄀飾区 | Unicode IVD: U+E0100.. after CJK ideographs select registered glyphs | INS-001 on `AGENTS.md`: 1 char(s), first U+E0100 [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+E0100 [new]; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B115 | false-positive | standardized variation sequences: ∩︀ (U+2229 U+FE00) and Myanmar U+1000 U+FE00 | Unicode StandardizedVariants.txt | INS-001 on `AGENTS.md`: 2 char(s), first U+FE00 [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 2 char(s), first U+FE00 [new]; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B116 | false-positive | Thai with ZWSP word-break hints: ภาษา​ไทย | Unicode: ZWSP marks word boundaries in Thai/Khmer/Lao | INS-001 on `AGENTS.md`: 1 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 1 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | false positive |
| B117 | false-positive | control: emoji ZWJ sequences 🏳️‍🌈 👩🏽‍💻 🧑‍🤝‍🧑 ❤️‍🔥 🏴‍☠️ 🏃‍♀️ 🐻‍❄️ 👁️‍🗨️ | Unicode TS #51 RGI ZWJ sequences | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B118 | false-positive | control: keycaps and text presentation 1️⃣ #️⃣ *️⃣ ↔︎ ©️ ™️ and French narrow no-break space | Unicode emoji-variation-sequences.txt | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B119 | traceback | directory name that is not valid UTF-8 holding AGENTS.md | Linux allows any bytes in names; git stores them | INS-001 on `\udcff\udcfe/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `\udcff\udcfe/AGENTS.md` [new] | INS-001 on `\udcff\udcfe/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `\udcff\udcfe/AGENTS.md` [new] | held |
| B120 | traceback | `AGENTS.md` is a directory; `CLAUDE.md` is a dangling symlink | edge cases of the walk | none | INS-001: none; REPO-002 lists 1: `CLAUDE.md` [new] | held |
| B121 | traceback | `AGENTS.md` is a FIFO (named pipe) | git cannot store a FIFO; checks the walk does not block | none | none | held |
| B122 | traceback | every line separator Python knows (VT, FF, FS, GS, RS, NEL, U+2028, U+2029) next to hidden characters | scan_hidden and _line_digests split lines differently; checks the offsets agree | INS-001 on `AGENTS.md`: 9 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: 17 char(s), first U+200B [new]; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B123 | traceback | AGENTS.md 300 folders deep | explicit stack, no recursion | INS-001 on `d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d...` [new] | INS-001 on `d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/AGENTS.md`: 72 char(s), first U+E0049 [new]; REPO-002 lists 1: `d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d/d...` [new] | held |
| B124 | traceback | 2,000 nested AGENTS.md files (time) | REPO-002 lists five and counts all | INS-001: none; REPO-002 lists 2000: `pkg0/m0/AGENTS.md, pkg0/m1/AGENTS.md, pkg0/m10/AGENTS.md, pkg0/m11/...` [new] | INS-001: none; REPO-002 lists 2000: `pkg0/m0/AGENTS.md, pkg0/m1/AGENTS.md, pkg0/m10/AGENTS.md, pkg0/m11/...` [new] | held |
| B125 | traceback | AGENTS.md that is only a byte-order mark | edge case | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | held |
| B126 | INS-001 | `.gitattributes` gives AGENTS.md `working-tree-encoding=UTF-16LE-BOM`: the blob (GitHub view, PR diff) is plain UTF-8 text with U+202E and tags, the checkout OBAAF scans is UTF-16LE (this case is that checkout) | git 2.43 verified locally: `git show` prints UTF-8 text, `git clone` writes FF FE + UTF-16LE; whether an agent then decodes the UTF-16 checkout is not verified | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001 on `AGENTS.md`: not UTF-8; REPO-002 lists 1: `AGENTS.md` [new] | way past (not verified) |
| B127 | INS-001 | `.gitattributes` marks AGENTS.md `linguist-generated=true`, so its diff is collapsed in pull requests | GitHub: linguist-generated paths are "hidden by default in diffs." https://docs.github.com/en/repositories/working-with-files/managing-files/customizing-how-changed-files-appear-on-github; not a Unicode character | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | INS-001: none; REPO-002 lists 1: `AGENTS.md` [new] | out of scope |

## 2d.2i: Jenkins files and credentials

Run `smew`, 2026-11-15, on a copy of `flagship` at `c86e058`. The Jenkins adapter's rules are advisory, but they turn a gate red like the others, so what it reads and the four rules about the credentials a stage holds were attacked by three Opus 5.5 reviewers that did not write them. Reviewer A took which Jenkinsfiles are found and read (28 attempts; a safety classifier stopped its turn before it reached OBAAF-JEN-001). Reviewer B took OBAAF-JEN-013, 014 and 015 and how a binding's variables are read (104 attempts: 49 ways past, 4 false positives, 1 slow case, 50 held). Reviewer C was then given OBAAF-JEN-001 alone, at `c031eff`, after the first fixes (98 attempts: 26 missed, 2 reported lower, 70 held, no false positive). A way past here is a Jenkinsfile in which Jenkins, by its documentation or Groovy's semantics, would expose the credential as the rule describes, or would run a file, while OBAAF reports nothing, less, or "pass"; "unknown" is not a way past. Every case is a small tree or file run through `obaaf check`; nothing was run on a Jenkins controller.

Every class of way past that is fixed has a test in `tests/test_jenkins_files_credentials.py`: 124 cases (76 ways past from the three sets, 6 safe forms beside them, and 25, 6, 4, 4 and 3 cases the first to fifth review passes wrote) and 17 other tests of discovery, line ends, time and narrower forms. On the code before the slice, 110 of the 124 cases fail: the 14 that pass are the 6 safe forms, 3 of the first review's cases that the first fixes had broken (a list changed after it was assigned, twice, and a helper nested in itself), and 3 of the second review's and 2 of the fourth's, which check that quoted text, a step called with a string and `new` are not taken for names whose value is unknown. Of the 17 other tests, 15 fail on that code and 2 pass: a credential named `release-signer` (a KMS signer, as in OBAAF's own Jenkins template) is not signing material, and App Store Connect, upload-key and provisioning-profile names in a workflow are not either.

Sources the reviewers read: the Credentials Binding steps page on jenkins.io (interpolation, the variables each binding sets, Azure's defaults), plugins.jenkins.io for the Generic Webhook Trigger, the GitLab plugin and AWS credentials, Groovy's syntax page (interpolation, slashy strings, a backslash before a line end), the Android `apksigner`, sigstore `cosign import-key-pair`, `docker trust key load` and Microsoft's certificate import pages, and the Jenkinsfile book on a mirror of jenkins.io. Several pages could not be fetched in the session (jenkins.io's Jenkinsfile book, groovy-lang.org's syntax page, the GitHub and GitLab branch source plugins, the Pipeline AWS plugin); the cases that rest on them are marked "not verified". Reviewer A checked the lone-CR case by parsing the file with the Groovy 3 grammar in a local jar, without running it.

### Which Jenkinsfiles are read

In a git work tree OBAAF now looks at every file git lists (and nothing outside the repository: a `jenkins.files` entry that is absolute or holds `..`, and a file under a folder link out of the repository, are errors, which the review found read), tracked or not committed and not ignored, in any folder and at any depth: which file a Jenkins job runs is set on the controller and can be any path, and the old walk skipped `build/`, `vendor/`, `target/` and thirteen other folder names, and everything below six folders, without a word (A001, A002, A004; the same cases left by 2d.2h as A085 and A086). More names count (`Jenkinsfile2`, `JenkinsfileRelease`, `release-jenkinsfile`; A008). A Jenkinsfile that is a link is read, under its own path, when it leads to a file in the repository, and is an error otherwise (A003; A088 of 2d.2h). Outside a git work tree the folders are walked as before, and the folders not entered are named in a note. What is left out is said: a file named like a Jenkinsfile with a document or data suffix (A009), a file `jenkins.exclude` drops (A012), and a `jenkins.files` pattern that matches nothing; `**/` in a pattern also matches no folder (A010), and a named path is read in a folder the walk skips (A011). A Jenkinsfile that is now found needs a code owner under OBAAF-REPO-001 like the others (A025).

Groovy ends a line at a lone carriage return too: with lone-CR line ends a `//` comment on the first line hid the whole pipeline, which passed (A018). A backslash before a line end inside a string removes both, as in Groovy, where it was kept as a line end (B057).

### The bindings

A closure given as the last argument (`withCredentials([...], { ... })`) is the step's body (B023, C031); a binding written with a map (`string([credentialsId: ..])`) is read (B025, B073); a binding list held in a variable, under `bindings:` or built with `+` is followed, and one the checker cannot follow is a binding of unknown credentials in unknown variables (B024, B072, C021, C096); a wrapper step in `options { }` binds for the stage (C022, C098). The variables a binding sets when the file does not name them are secrets: AWS's two keys, Azure's four values, `gitUsernamePassword`'s two (the last not verified), those `withAWS` sets, and any `...Variable` or `envVar` a wrapper names at any depth (`withVault`) (B026 to B029, B102). A file binding written as a map and `sshagent`'s `SSH_AUTH_SOCK` hold paths, not secrets (B022, B041). A list changed after it was assigned (`b << x`, `b.add(x)`, `b += x`) is not taken for the list first assigned, and a binding the checker cannot read, a method that returns one included, is a binding of unknown credentials in unknown variables (from the review).

Code reached through a value runs where it is called: a closure passed to a method of the file runs where the method calls it, in any argument (B034, C041); a closure, a method pointer (`this.&build`) or a map of closures assigned in the file runs at `body()`, `body.call()`, `f()`, `tasks.build()` or `parallel tasks` (C027, C029, C030, C034, C043, C097); `steps.sh`, `this.sh` and `this.build()` are `sh` and `build()` (C026, C040, C072, C088). From the review: a method pointer as the last argument, maps built with `tasks.put('a', {...})` or `tasks.a = {...}` and called as `tasks['a']()`; a closure runs with the closures of the place it was written (two helpers that both call their parameter `body` no longer expand without end), and every such expansion counts against the file's budget of 5,000 (a map of closures that doubled per level took over 100 seconds at 26 levels).

### OBAAF-JEN-001

Besides the bindings and the code above: a change request's branch name in a multibranch job is `PR-<n>`, and also `PR-<n>-head` and `PR-<n>-merge` (GitHub with both discovery strategies) and `MR-<n>` (GitLab), not verified against the plugins' pages (C052 to C054); `GIT_BRANCH` is tested like `BRANCH_NAME` (C055); `not { not { x } }` and `||` keep that a condition holds for every change request (C056, C057); an agent's command is recognised in the script as the shell reads it, with continued lines joined and the file's literal variables put in (C062, C063, C070). Agent CLIs the catalogue does not know (`cursor-agent`, `pipx run aider-chat`, `aider` alone; C071, C074, C095) are left to slice 2d.5, which owns the agent catalogue.

### OBAAF-JEN-013

A secret copied into another variable, a method's parameter or a `withEnv` entry is still a secret, transitively (B013, B014, B018, B033); an environment variable whose name is computed (`env[n]`) inside a binding, and any interpolation inside a binding whose variables the file does not name, are "unknown" (B030); so are, from the review, `env."${n}"`, `System.getenv(n)`, `env.getAt(n)` and a variable holding one of them, and a lower-case name whose value the checker never saw (a closure's parameter, `it`, a destructured name), while a closure that returns the secret is the secret; the arguments of `docker.image(...).inside`, `withRun`, `run` and `withDockerContainer` are checked, since they become the `docker run` command line (B042).

### OBAAF-JEN-014

More names are signing material (`release.jks`, `secring.gpg`, `signing.asc`, a credential named `GPG`, Gradle's `signingInMemoryKey`, `ios-dist-cert`, `artifact-signer-key`, an upload key; B046, B048 to B050, B052 to B054), and so is any `certificate` binding (B047). Not `signer` alone: OBAAF's own Jenkins template names `obaaf-release-signer` a credential that can only ask a KMS to sign. More commands load a key: `signtool` in any letter case, any `security import` but of a public certificate file, `apksigner --key`, `certutil -importPFX`, `cosign import-key-pair`, `docker trust key load`, `osslsigncode`, `openssl dgst -sign`, `ssh-keygen -Y sign` (B060 to B064, B066, B067, B074, B075). Lines continued with `\` (shell), `^` (cmd) or a backtick (PowerShell) are joined, and literal variables, interpolated or not, put in, before the commands are matched (B055, B056, B059, and the review's cases); the scan runs once per call (the review found a long `openssl dgst` line in B097's tree of methods taking 66 seconds). A certificate binding written as a map counts too. A publish in the stage's `post` block makes the finding high (B068). `cosign --key=awskms://` is a key in a KMS, like `--key awskms://` (B065). These names and commands are shared with OBAAF-GHA-018, so a workflow is read the same way. Not `ASC` alone (App Store Connect's `ASC_KEY_ID`), a name that only begins with `GPG_` (`GPG_FINGERPRINT`), an upload key (`SENTRY_UPLOAD_KEY`), or importing a provisioning profile: the review found those on ordinary workflows.

### OBAAF-JEN-015

A token built from literals in the file is a token written in the file: a variable, a GString of variables, `+`, `.trim()`, an `environment` value (B078 to B080, B094, B096); a map argument is read (B081); GitLab's webhook secret is `secretToken` (B086, B087); a token the file computes is "unknown" (B089).

### Time

A method of the file called many times records its steps once per call; each step's call is now classified once (B097: a 2.9 KB file of 15 methods each calling the next twice took 7.5 seconds; it takes under 2, and the step classifier runs fewer than 100 times instead of 49,922).

### Not fixed

A pipeline under a name no Jenkinsfile has (A006) is read only when `jenkins.files` names it. A file a Jenkinsfile `load()`s needs no code owner (A026); the Jenkins rules say "unknown" for it. A command named through a shell variable (B058). `X = credentials('id')` of a secret-file credential is still read as a secret (B040): the Jenkinsfile does not say the credential's kind. The three agent CLIs above (C071, C074, C095).

### What changed for the first adopter

Expectrail has no Jenkinsfile. At `ec4c1f55` (a copy without anything under `fresh-*`, committed to a fresh git work tree), `obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes` gives the same 35 files and 44 findings, with no new error or note, before and after. `obaaf check .` on this repository gives the same 10 files and 1 accepted finding.

### Review

A fourth Opus 5.5 sub-agent reviewed the fixes at `b3793ef` with about 60 Jenkinsfiles of its own, each run on the old and the new code, and found 8 blocking faults: two helpers that both name their closure `body` expanded without end, and so did a map of closures that runs itself; a map of closures that doubled per level did not finish; a list changed after it was assigned was taken for the list first assigned, a regression (the old code said "computed credential IDs"); `jenkins.files` read files outside the repository (`../x`, `/etc/passwd`, a file under a folder link); the signing scan ran once per expansion, not per call (66 s); ways past left in classes the slice said were fixed (computed environment names in other spellings, a secret through a closure's parameter or result, a method returning a binding, method pointers and other ways to build a map of closures, cmd and PowerShell continuations, interpolated command variables, a certificate binding written as a map); false positives on ordinary workflows from the shared signing lists (`ASC_KEY_ID`, `SENTRY_UPLOAD_KEY`, `GPG_FINGERPRINT`, a provisioning profile); and the docs named OBAAF-GHA-014 where the rule that shares the lists is OBAAF-GHA-018. Each is fixed and its case is a test.

The same sub-agent re-ran its cases on the fixes (`0c38cb0`): all 8 were fixed, and one new blocking fault was found in the same class as the third: a list changed through a method's parameter or through another name (`def c = b; c << ...`) was still taken for the list first assigned. A list is now followed into `withCredentials` only when its name is used nowhere else in the file; otherwise it is a binding of unknown credentials. It also found `binding.getVariable(...)` with a computed name not read as a computed name (fixed), and noise from the new "unknown" for lower-case names: quoted text, a step called with a string (`tool "maven-3"`) and `new` were taken for names (fixed), while a `for` or `.each` variable, a `catch` variable and the parameter of a method nothing calls still give "unknown" inside a binding. That changes the coverage report, not the exit status, and is left as it is: the checker cannot tell what those names hold. Two notes are left too: closures nested through helpers now expand up to the file's budget of 5,000, so a 5 KB file of 12 helpers that each call their closure twice around 300 steps takes about 7 seconds (the same shape written with methods took 11.6 seconds before the slice, so the cost is not new); and names such as `release-key.asc` match only through `KEY_ASC`, `PRIVATE_ASC`, `SECRET_ASC` or `SIGNING_ASC`.

A third pass (`0d610a3`) confirmed the list fix (a list used in two bindings gives two findings, one also printed with `echo` becomes "unknown", never a silent pass) and found one blocking fault in the noise fix: a closure parameter holding the secret, written `${t as String}` or inside a nested GString `${"${t}".trim()}`, was no longer "unknown". A name before `as`, `in` or `instanceof` is no longer taken for a step call, and quoted text that interpolates is read for names. The ASC names are anchored at a word boundary. Left as a note: a list changed inside a string interpolation (`echo "${creds << ...}"`) is still followed.

A fourth pass (`32b5aa4`) found the same class in one more spelling: `$t` without braces inside nested quoted text (`${"$t".trim()}`, `${"Authorization:$t"}`) was still silent, as it had been before. Quoted text with double quotes is now replaced by what it interpolates (`${...}` and `$name`), read again for names, and single-quoted text by nothing, which also removes the words of quoted text from the names (`${tool "m-${v}"}` no longer reads `m`).

A fifth pass (`fcf053c`) found that the regular expression that found quoted text stopped at a quote inside `${...}` (`${"Bearer ${t ?: "X"}"}`) and that its placeholder read as an argument after a name (`${"""Bearer ${t}"""}`), so two more spellings were silent. Quoted text and `${...}` are now followed together by a small scanner (escapes, triple quotes, nesting to 50 levels, beyond which the text is read as it is), what a double-quoted text interpolates is ended by a `;`, and only text that interpolates nothing reads as an argument. Every spelling the five passes wrote is "unknown"; `"\$" + "{t}"`, single-quoted `'$t'` and the words of quoted text are not names.

A sixth pass (`6671776`) found nothing blocking: every secret spelling it had, and six new ones, gave "unknown"; unterminated quotes and `${`, a backslash at the end, 200 levels of nesting and 20,000 random strings neither crashed nor looped. Its two notes were fixed in `fc0fb21`, which a last check confirmed changes no result: `$name` was matched on a copy of the rest of the text (5 seconds on 800 KB, now 0.13), and the scanner ran once per expansion of a step and is now cached by its text (B097's tree with one long interpolated `sh` took 11 seconds and takes 5.6; it took 8.4 before the slice, and what remains is that older cost).

### The attempts

| ID | Rule | Case | Source | Before (at `c86e058`, C at `c031eff`) | After (at the slice's head) | Result |
| --- | --- | --- | --- | --- | --- | --- |
| A001 | JEN-001 | a Jenkinsfile under each SKIP_DIRS name (except .git) plus a clean root Jenkinsfile | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['.godot/ci/Jenkinsfile', '.gradle/ci/Jenkinsfile', '.idea/ci/Jenkinsfile', '.venv/ci/Jenkinsfile', 'Binaries/ci/Jenkinsfile', 'DerivedDataCach... | way past; fixed |
| A002 | JEN-001 | Jenkinsfile at depth 7 (a/b/c/d/e/f/g/Jenkinsfile) and at depth 6 | local run | exit 1: read=Jenkinsfile,p/q/r/s/t/u/Jenkinsfile; OBAAF-JEN-001 findings=high@p/q/r/s/t/u/Jenkinsfile:6; coverage=Jenkinsfile:not applicable;p/q/r/s/t/u/Jenk... | exit 1; files=['Jenkinsfile', 'a/b/c/d/e/f/g/Jenkinsfile', 'p/q/r/s/t/u/Jenkinsfile']; JEN-001 high a/b/c/d/e/f/g/Jenkinsfile:6; JEN-001 high p/q/r/s/t/u/Jen... | way past; fixed |
| A003 | JEN-001 | root Jenkinsfile is a link to ci/pipeline.groovy | local run | exit 2: error: no CI definitions found under . (Jenkinsfiles): nothing was checked. Point obaaf check at a repository root, its .github/workflows directory, ... | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:6; notes=[] | held (error: nothing checked; does not name the link) |
| A004 | JEN-001 | folder link jenkins -> build/ (script path jenkins/Jenkinsfile), clean root Jenkinsfile | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile', 'build/Jenkinsfile']; JEN-001 high build/Jenkinsfile:6; notes=[] | way past; fixed |
| A005 | JEN-001 | letter case: JENKINSFILE, jenkinsfile in Build/, VENDOR/, Target/ | local run | exit 1: read=Build/JENKINSFILE,Target/JenkinsFile.release,VENDOR/jenkinsfile; OBAAF-JEN-001 findings=high@Build/JENKINSFILE:6;high@Target/JenkinsFile.release... | exit 1; files=['Build/JENKINSFILE', 'Target/JenkinsFile.release', 'VENDOR/jenkinsfile']; JEN-001 high Build/JENKINSFILE:6; JEN-001 high Target/JenkinsFile.re... | held |
| A006 | JEN-001 | pipeline only at ci/pipeline.groovy (a script path Jenkins accepts), clean root Jenkinsfile | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile']; ; notes=[] | way past; not fixed, stated limit: a pipeline under a name no Jenkinsfile has (`ci/pipeline.groovy`) is read only when `jenkins.files` names it; which file a... |
| A007 | JEN-001 | pipeline only at .jenkins/release.gvy and ci/deploy (no Jenkinsfile anywhere) | local run | exit 2: error: no CI definitions found under . (Jenkinsfiles): nothing was checked. Point obaaf check at a repository root, its .github/workflows directory, ... | exit 2; not JSON: error: no CI definitions found under . (Jenkinsfiles): nothing was checked. Point obaaf check at a repository root, its .github/workflows d... | held (exit 2, nothing checked) |
| A008 | JEN-001 | names without a separator: Jenkinsfile2, JenkinsfileRelease, release-jenkinsfile | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile', 'Jenkinsfile2', 'JenkinsfileRelease', 'release-jenkinsfile']; JEN-001 high Jenkinsfile2:6; JEN-001 high JenkinsfileRelease:6; J... | way past; fixed |
| A009 | JEN-001 | refused suffixes: Jenkinsfile.yml/.yaml/.json/.xml/.properties/.txt/.bak/.orig/.md/.html | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile']; ; notes=['Not read as Jenkinsfiles because of their suffix: Jenkinsfile.bak, Jenkinsfile.html, Jenkinsfile.json, Jenkins'] | way past (low); not read, now named in a note: a file named like a Jenkinsfile with a document or data suffix |
| A010 | JEN-001 | jenkins.files glob ci/**/*.groovy does not match ci/release.groovy (fnmatch, not gitignore) | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile', 'ci/release.groovy']; JEN-001 high ci/release.groovy:6; notes=[] | way past (config); fixed |
| A011 | JEN-001 | jenkins.files names build/release.groovy explicitly; build/ is in SKIP_DIRS | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile', 'build/release.groovy']; JEN-001 high build/release.groovy:6; notes=[] | way past (config); fixed |
| A012 | JEN-001 | jenkins.exclude pattern 'test*' also drops the real pipeline testing/Jenkinsfile; is it said? | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile']; ; notes=['Left out by jenkins.exclude: testing/Jenkinsfile.'] | way past (config, low); fixed |
| A013 | JEN-001 | jenkins.exclude ['*'] drops every Jenkinsfile including the root one | local run | exit 2: error: no CI definitions found under . (Jenkinsfiles): nothing was checked. Point obaaf check at a repository root, its .github/workflows directory, ... | exit 2; not JSON: error: no CI definitions found under . (Jenkinsfiles): nothing was checked. Point obaaf check at a repository root, its .github/workflows d... | held (exit 2) |
| A014 | JEN-001 | UTF-8 byte-order mark at the start | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=high@Jenkinsfile:6; coverage=Jenkinsfile:fail | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:6; notes=[] | held |
| A015 | JEN-001 | bytes that are not UTF-8 (Latin-1 in a comment and in an echo string) | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=high@Jenkinsfile:8; coverage=Jenkinsfile:fail | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:8; notes=[] | held |
| A016 | JEN-001 | NUL byte between statements | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=high@Jenkinsfile:7; coverage=Jenkinsfile:fail; file-unknowns=line 3: statement not analyzed (line 3: unexpec... | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:7; notes=[] | held |
| A017 | JEN-001 | CRLF line ends | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=high@Jenkinsfile:6; coverage=Jenkinsfile:fail | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:6; notes=[] | held |
| A018 | JEN-001 | lone CR line ends, file starts with a // comment line | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:not applicable | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:7; notes=[] | WAY PAST (silent pass); fixed |
| A019 | JEN-001 | lone CR line ends, no comments | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:unknown; file-unknowns=line 1: statement not analyzed (line 1: unexpected 'stages') | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:6; notes=[] | held (unknown) |
| A020 | JEN-001 | file over 1 MiB (padding comment) | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=none; coverage=Jenkinsfile:unknown; errors=Jenkinsfile: not analyzed: line 1: file exceeds 1048576 bytes | exit 1; files=['Jenkinsfile']; ; cov=['Jenkinsfile:unknown']; errors=['Jenkinsfile: not analyzed: line 1: file exceeds 1048576 bytes']; notes=[] | held |
| A021 | JEN-001 | a directory named Jenkinsfile (holding ci.groovy) and no other pipeline | local run | exit 2: error: no CI definitions found under . (Jenkinsfiles): nothing was checked. Point obaaf check at a repository root, its .github/workflows directory, ... | exit 2; not JSON: error: no CI definitions found under . (Jenkinsfiles): nothing was checked. Point obaaf check at a repository root, its .github/workflows d... | held |
| A022 | JEN-001 | target is a subfolder of the repository (obaaf check svc) holding svc/Jenkinsfile | local run | exit 1: read=Jenkinsfile; OBAAF-JEN-001 findings=high@Jenkinsfile:6; coverage=Jenkinsfile:fail | exit 1; files=['Jenkinsfile']; JEN-001 high Jenkinsfile:6; notes=[] | held |
| A023 | JEN-001 | single file pipeline.gvy given with --platform auto | local run | exit 1: read=none; OBAAF-JEN-001 findings=none; errors=pipeline.gvy: cannot parse YAML: mapping values are not allowed here in "<unicode string>", line 6, co... | exit 1; files=['pipeline.gvy']; ; errors=['pipeline.gvy: cannot parse YAML: mapping values are not allowed here\n in "<unicode string>", line 6']; notes=[] | held (YAML error, not silent) |
| A024 | JEN-001 | --platform auto discovery with .github/workflows present and ci/Jenkinsfile.release | local run | exit 1: read=ci/Jenkinsfile.release; OBAAF-JEN-001 findings=high@ci/Jenkinsfile.release:6; coverage=ci/Jenkinsfile.release:fail | exit 1; files=['.github/workflows/ci.yml', 'ci/Jenkinsfile.release']; JEN-001 high ci/Jenkinsfile.release:6; notes=[] | held |
| A025 | REPO-001 | CODEOWNERS owns only /Jenkinsfile; ci/Jenkinsfile.release and build/Jenkinsfile exist | local run | exit 1: read=Jenkinsfile,ci/Jenkinsfile.release; OBAAF-REPO-001 findings=medium@.github/CODEOWNERS:1;medium@.github/CODEOWNERS:1 | exit 1; files=['Jenkinsfile', 'build/Jenkinsfile', 'ci/Jenkinsfile.release']; REPO-001 medium .github/CODEOWNERS:1; REPO-001 medium .github/CODEOWNERS:1; not... | way past (partial: build/Jenkinsfile not named); fixed |
| A026 | REPO-001 | CODEOWNERS owns /Jenkinsfile; Jenkinsfile load()s ci/steps.groovy (pipeline code, unowned) | local run | exit 1: read=Jenkinsfile; OBAAF-REPO-001 findings=medium@.github/CODEOWNERS:1; file-unknowns=line 2: load(): Groovy loaded at run time is not analyzed | exit 1; files=['Jenkinsfile']; REPO-001 medium .github/CODEOWNERS:1; notes=[] | way past (REPO-001); not fixed, stated limit: a file a Jenkinsfile `load()`s needs no owner under OBAAF-REPO-001; the Jenkins rules say "unknown" for it |
| A027 | REPO-001 | CODEOWNERS lower-case /jenkinsfile (GitHub patterns are case-sensitive) vs file Jenkinsfile | local run | exit 1: read=Jenkinsfile; OBAAF-REPO-001 findings=medium@.github/CODEOWNERS:1;medium@.github/CODEOWNERS:1 | exit 1; files=['Jenkinsfile']; REPO-001 medium .github/CODEOWNERS:1; REPO-001 medium .github/CODEOWNERS:1; notes=[] | held |
| A028 | REPO-001 | CODEOWNERS '/ci/ @org' then ownerless '/ci/Jenkinsfile.release' (last match wins, no owner) | local run | exit 1: read=ci/Jenkinsfile.release; OBAAF-REPO-001 findings=medium@.github/CODEOWNERS:1;medium@.github/CODEOWNERS:1 | exit 1; files=['ci/Jenkinsfile.release']; REPO-001 medium .github/CODEOWNERS:1; REPO-001 medium .github/CODEOWNERS:1; notes=[] | held |
| B001 | JEN-013 | control: `sh "... ${TOKEN}"` in withCredentials string() | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B002 | JEN-013 | `"$TOKEN"` (no braces) | groovy-lang.org core-syntax: GString, slashy and dollar-slashy strings interpolate; \$ escapes | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B003 | JEN-013 | `"${env.TOKEN}"` | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B004 | JEN-013 | `"${TOKEN.trim()}"` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B005 | JEN-013 | triple-double-quoted `"""curl -u ${USER}:${PASS}"""` (usernamePassword) | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L8 vars PASS, USER | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B006 | JEN-013 | slashy string `sh(/curl -H X:$TOKEN .../)` | groovy-lang.org core-syntax: GString, slashy and dollar-slashy strings interpolate; \$ escapes | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B007 | JEN-013 | dollar-slashy `sh($/curl -H X:${TOKEN} .../$)` | groovy-lang.org core-syntax: GString, slashy and dollar-slashy strings interpolate; \$ escapes | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B008 | JEN-013 | concatenation in command form `sh 'curl -H X:' + TOKEN` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B009 | JEN-013 | `sh String.format('curl -H X:%s', TOKEN)` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B010 | JEN-013 | `sh('curl -H X:'.plus(TOKEN))` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B011 | JEN-013 | `"${[TOKEN].join()}"` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B012 | JEN-013 | environment `CREDS = credentials('repo')`, `"${CREDS_PSW}"` | jenkins.io Jenkinsfile book: environment credentials() sets X, X_USR, X_PSW | 013 fail: 013 medium L10 vars CREDS_PSW | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:10; notes=[] | held |
| B013 | JEN-013 | secret copied to a local: `def t = TOKEN; sh "curl ${t}"` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:10; notes=[] | way past; fixed |
| B014 | JEN-013 | command built in a variable: `def cmd = "curl ${TOKEN}"; sh cmd` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:10; notes=[] | way past; fixed |
| B015 | JEN-013 | `sh(returnStdout: true, script: "curl ${TOKEN}").trim()` | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L9 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:9; notes=[] | held |
| B016 | JEN-013 | `bat "curl -u %USER%:${PASS}"` | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L8 vars PASS | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B017 | JEN-013 | `powershell` and `pwsh` with `${TOKEN}` | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L8 vars TOKEN; 013 medium L9 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; JEN-013 medium Jenkinsfile:9; notes=[] | held |
| B018 | JEN-013 | `withEnv(["T2=${TOKEN}"]) { sh "curl ${env.T2}" }` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:9; notes=[] | way past; fixed |
| B019 | JEN-013 | reverse: escaped `\$TOKEN` in a GString | groovy-lang.org core-syntax: GString, slashy and dollar-slashy strings interpolate; \$ escapes | 013 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | held |
| B020 | JEN-013 | reverse: single-quoted `'curl $TOKEN'` | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | held |
| B021 | JEN-013 | reverse: `file(...)` binding path `"${KCFG}"` | jenkins.io Credentials Binding: file variable is the file location | 013 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | held |
| B022 | JEN-013 | reverse: map-form `[$class: 'FileBinding', variable: 'KCFG']`, `"${KCFG}"` | same as B021: FileBinding is the file binding's class | 013 fail: 013 medium L8 vars KCFG | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | false positive; fixed |
| B023 | JEN-013 | closure as last positional argument: `withCredentials([...], { sh "${TOKEN}" })` | Groovy semantics: a GString is evaluated where it is written (not verified on a page); a trailing closure and a last closure argument are the same call | 013 not applicable | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | way past; fixed |
| B024 | JEN-013 | binding list held in a variable: `def b = [string(...)]; withCredentials(b) {...}` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:10; notes=[] | way past; fixed |
| B025 | JEN-013 | binding call with a map argument: `string([credentialsId: .., variable: 'TOKEN'])` | Groovy semantics: named arguments arrive as one Map, so f(a: 1) and f([a: 1]) are the same call (not verified on a page) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | way past; fixed |
| B026 | JEN-013 | AWS binding default variables: `[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws']`, `"${AWS_SECRET_ACCESS_KEY}"` | plugins.jenkins.io/aws-credentials: the example 'will automatically setup environment variables AWS_ACCESS_KEY_ID & AWS_SECRET_ACCESS_KEY' | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | way past; fixed |
| B027 | JEN-013 | `azureServicePrincipal('sp')` defaults, `"${AZURE_CLIENT_SECRET}"` | jenkins.io Credentials Binding steps page: clientSecretVariable 'If empty, default value is AZURE_CLIENT_SECRET' | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | way past; fixed |
| B028 | JEN-013 | `withAWS(credentials: 'aws') { sh "${env.AWS_SECRET_ACCESS_KEY}" }` | Pipeline AWS plugin: withAWS sets AWS_* environment variables (not verified) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | way past (not verified); fixed |
| B029 | JEN-013 | `withVault(... secretValues: [[envVar: 'TOKEN', ...]])`, `"${TOKEN}"` | HashiCorp Vault plugin: envVar names the variable that holds the secret (not verified) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:9; notes=[] | way past (not verified); fixed |
| B030 | JEN-013 | variable name computed: `def n = 'TOK' + 'EN'; sh "${env[n]}"` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:unknown']; notes=[] | way past; fixed |
| B031 | JEN-013 | `sh label: 'x', script: "curl ${TOKEN}"` (command form, named) | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B032 | JEN-013 | `sh([script: "curl ${TOKEN}"])` (map argument) | jenkins.io Credentials Binding steps page: double quotes 'potentially less secure, as the secret is interpolated by Groovy' | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B033 | JEN-013 | file method parameter: `def callApi(t) { sh "curl ${t}" }` called with `TOKEN` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:2; notes=[] | way past; fixed |
| B034 | JEN-013 | closure given to a file method that binds around it: `withApi { sh "${TOKEN}" }` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:13; notes=[] | way past; fixed |
| B035 | JEN-013 | nested GString `"curl ${"-H X:${TOKEN}"}"` | groovy-lang.org core-syntax: GString, slashy and dollar-slashy strings interpolate; \$ escapes | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B036 | JEN-013 | `"\\$TOKEN"` (escaped backslash, then interpolation) | groovy-lang.org core-syntax: GString, slashy and dollar-slashy strings interpolate; \$ escapes | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B037 | JEN-013 | lazy GString `"${-> TOKEN}"` | groovy-lang.org core-syntax: closure expressions in GStrings (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B038 | JEN-013 | `sh "${env['TOKEN']}"` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B039 | JEN-013 | ternary script `sh(script: ok ? "curl ${TOKEN}" : 'true')` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L10 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:10; notes=[] | held |
| B040 | JEN-013 | reverse: environment `credentials()` of a secret file, `"${KUBECFG}"` | jenkins.io Jenkinsfile book: a Secret file credential gives the file's location (not read on this mirror) | 013 fail: 013 medium L10 vars KUBECFG | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:10; notes=[] | false positive (debatable, not verified); kept: `X = credentials('id')` of a secret-file credential holds a path, but the Jenkinsfile does not say the creden... |
| B041 | JEN-013 | reverse: `sshagent(['deploy'])` and `"${env.SSH_AUTH_SOCK}"` (a socket path) | sshagent sets SSH_AUTH_SOCK to the agent socket (not verified) | 013 fail: 013 medium L8 vars SSH_AUTH_SOCK | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | false positive (not verified); fixed |
| B042 | JEN-013 | `docker.image('x').inside("-e T=${TOKEN}")` (secret on the docker run command line) | Docker Pipeline: inside() passes args to docker run (not verified); beyond the rule's sh/bat/powershell list | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:9; notes=[] | way past (outside the rule's step list; not verified); fixed |
| B043 | JEN-013 | `writeFile text: "${TOKEN}"` (not a command line) | jenkins.io: the process-list exposure is for command steps | 013 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | held (out of the rule) |
| B044 | JEN-013 | `String.join(' ', 'curl', TOKEN)` via list join `['curl', TOKEN].join(' ')` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 013 fail: 013 medium L8 vars TOKEN | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | held |
| B045 | JEN-014 | control: `file(credentialsId: 'gpg-signing-key')` + `gpg --batch --import` | rule text | 014 fail: 014 medium L7 binding (gpg-signing-key); 014 medium L8 command | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; JEN-014 medium Jenkinsfile:8; notes=[] | held |
| B046 | JEN-014 | binding id `release.jks` (Java keystore), variable `STORE` | a .jks file is a Java keystore (Oracle keytool docs, not read) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B047 | JEN-014 | `certificate(credentialsId: 'release', keystoreVariable: 'STORE', passwordVariable: 'STOREPASS')` | jenkins.io Credentials Binding: certificate binding sets a 'temporary keystore location' | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B048 | JEN-014 | binding id `secring.gpg` (GnuPG secret keyring) | GnuPG: secring.gpg is the secret keyring (not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 high Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B049 | JEN-014 | binding id `signing.asc` (armored private key) | not verified | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B050 | JEN-014 | variable `ORG_GRADLE_PROJECT_signingInMemoryKey` | vanniktech gradle-maven-publish: signingInMemoryKey (not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B051 | JEN-014 | camelCase variable `signingKey` | rule text | 014 fail: 014 medium L7 binding (signingKey) | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | held |
| B052 | JEN-014 | environment `GPG = credentials('release-gpg')` | jenkins.io Jenkinsfile book: environment credentials() sets X, X_USR, X_PSW | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:4; notes=[] | way past; fixed |
| B053 | JEN-014 | binding id `ios-dist-cert` (Apple distribution certificate) | not verified | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B054 | JEN-014 | binding id `artifact-signer-key` | rule text | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B055 | JEN-014 | `cosign sign \` continued on the next line with `--key` | a shell joins a line ending in a backslash (POSIX, not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B056 | JEN-014 | `gpg --batch \` continued, `--import key.asc` on the next line | as B055 | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B057 | JEN-014 | Groovy line continuation in `'''` (backslash-newline removed by Groovy) | groovy-lang.org core-syntax: 'It is possible to strip that character by escaping the newline with a backslash' | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B058 | JEN-014 | gpg through a shell variable `GPG=gpg; $GPG --batch --import key.asc` | not verified (shell semantics) | 014 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | way past; not fixed, stated limit: a command named through a shell variable (`$GPG --import`) |
| B059 | JEN-014 | command in a Groovy variable: `def imp = 'gpg --batch --import key.asc'; sh imp` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:9; notes=[] | way past; fixed |
| B060 | JEN-014 | `bat 'SignTool sign /f cert.pfx /p %P% app.exe'` (letter case) | learn.microsoft.com writes the tool 'SignTool'; Windows names are case-insensitive (not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B061 | JEN-014 | `security import "$P12" -k build.keychain` (path in a variable) | macOS security(1) import (not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B062 | JEN-014 | `apksigner sign --key release.pk8 --cert release.x509.pem` | developer.android.com/tools/apksigner: --key 'contains the signer's private key' | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B063 | JEN-014 | `certutil -user -p %P% -importPFX cert.pfx` | learn.microsoft.com 'Importing an SPC into a Certificate Store': certutil -importPFX | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B064 | JEN-014 | `cosign import-key-pair --key key.pem` | docs.sigstore.dev import-keypair: 'To use a local key not generated by Cosign for signing, the key must be imported' | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B065 | JEN-014 | reverse: `cosign sign --key=awskms://alias/release` (KMS, `=` form) | pflag accepts --flag=value (not verified) | 014 fail: 014 medium L7 command | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | false positive (not verified); fixed |
| B066 | JEN-014 | `docker trust key load release.pem --name ci` | docs.docker.com trust key load: 'Load a private key file for signing' | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B067 | JEN-014 | `osslsigncode sign -pkcs12 cert.pfx` | osslsigncode README (not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B068 | JEN-014 | severity: `gpg --import` in steps, `mvn deploy` in the same stage's `post { success }` | rule text: 'High when the stage also publishes' | 014 fail: 014 medium L7 command | exit 1; files=['Jenkinsfile']; JEN-014 high Jenkinsfile:7; notes=[] | way past (severity); fixed |
| B069 | JEN-014 | severity control: `gpg --import` and `mvn deploy` in the same steps | rule text | 014 fail: 014 high L7 command | exit 1; files=['Jenkinsfile']; JEN-014 high Jenkinsfile:7; notes=[] | held |
| B070 | JEN-014 | `powershell 'Import-PfxCertificate -FilePath cert.pfx ...'` | learn.microsoft.com Import-PfxCertificate | 014 fail: 014 medium L7 command | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | held |
| B071 | JEN-014 | `jarsigner -keystore` and `gpg2 --pinentry-mode loopback --passphrase "$P" --import` | rule text | 014 fail: 014 medium L7 command; 014 medium L8 command | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; JEN-014 medium Jenkinsfile:8; notes=[] | held |
| B072 | JEN-014 | binding list in a variable: `def c = [file(credentialsId: 'gpg-signing-key', ..)]; withCredentials(c)` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:8; notes=[] | way past; fixed |
| B073 | JEN-014 | binding call with a map argument: `file([credentialsId: 'gpg-signing-key', variable: 'KEYFILE'])` | Groovy semantics: named arguments arrive as one Map, so f(a: 1) and f([a: 1]) are the same call (not verified on a page) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | way past; fixed |
| B074 | JEN-014 | `ssh-keygen -Y sign -f "$KEY"` with `sshUserPrivateKey(credentialsId: 'artifact-signer')` | OpenSSH ssh-keygen(1) -Y sign (not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:8; notes=[] | way past (not verified); fixed |
| B075 | JEN-014 | `openssl dgst -sha256 -sign "$KEY"` with `file(credentialsId: 'release-key')` | OpenSSL dgst -sign (not verified) | 014 pass | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:8; notes=[] | way past (not verified); fixed |
| B076 | JEN-015 | control: `GenericTrigger(genericVariables: .., token: 'abc123secret')` | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L4 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | held |
| B077 | JEN-015 | token first, double-quoted, no interpolation | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L4 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | held |
| B078 | JEN-015 | token in a variable defined in the file: `def T = 'abc123secret'` ... `token: T` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:5; notes=[] | way past; fixed |
| B079 | JEN-015 | token in a GString: `token: "${T}"` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:5; notes=[] | way past; fixed |
| B080 | JEN-015 | token by concatenation: `token: 'abc123' + 'secret'` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | way past; fixed |
| B081 | JEN-015 | map argument: `GenericTrigger([token: 'abc123secret', ...])` | Groovy semantics: named arguments arrive as one Map, so f(a: 1) and f([a: 1]) are the same call (not verified on a page) | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | way past; fixed |
| B082 | JEN-015 | scripted `properties([pipelineTriggers([GenericTrigger(token: ..)])])` | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L1 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:1; notes=[] | held |
| B083 | JEN-015 | `properties([...])` inside declarative `script { }` | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L8 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:8; notes=[] | held |
| B084 | JEN-015 | map form `[$class: 'GenericTrigger', token: ..]` | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L1 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:1; notes=[] | held |
| B085 | JEN-015 | reverse: `tokenCredentialId: 'gwt-token'` only | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | held |
| B086 | JEN-015 | GitLab `gitlab(triggerOnPush: true, secretToken: 'abc...')` | plugins.jenkins.io/gitlab-plugin: secretToken listed for the declarative gitlab trigger | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | way past; fixed |
| B087 | JEN-015 | GitLab map form `[$class: 'GitLabPushTrigger', secretToken: '...']` | plugins.jenkins.io/gitlab-plugin: '$class: 'GitLabPushTrigger',' with 'secretToken: project_token,' | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:1; notes=[] | way past; fixed |
| B088 | JEN-015 | short token `'x1'` | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L4 GenericTrigger token '...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | held |
| B089 | JEN-015 | `token: env.JOB_NAME` (the job's name is the token) | plugins.jenkins.io/generic-webhook-trigger shows 'token: env.JOB_NAME,' | 015 pass | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:unknown']; notes=[] | way past (debatable); fixed |
| B090 | JEN-015 | command form without parentheses: `GenericTrigger token: '...', causeString: 'x'` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 015 fail: 015 medium L4 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | held |
| B091 | JEN-015 | full class name `$class: 'org.jenkinsci.plugins.gwt.GenericTrigger'` | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L1 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:1; notes=[] | held |
| B092 | JEN-015 | trigger built in a file method: `def t() { GenericTrigger(token: '...') }` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 015 fail: 015 medium L2 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:2; notes=[] | held |
| B093 | JEN-015 | token and tokenCredentialId both given | plugins.jenkins.io/generic-webhook-trigger: 'token: 'abc123''; 'using a token always runs the triggered jobs with SYSTEM privileges' | 015 fail: 015 medium L4 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | held |
| B094 | JEN-015 | `token: 'abc123secret'.trim()` | Groovy semantics: a GString is evaluated where it is written (not verified on a page) | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:4; notes=[] | way past; fixed |
| B095 | JEN-015 | severity: credentials bound in the pipeline -> high | rule text | 015 fail: 015 high L4 GenericTrigger token 'abc...' | exit 1; files=['Jenkinsfile']; JEN-015 high Jenkinsfile:4; notes=[] | held |
| B096 | JEN-015 | token from the environment block: `environment { HOOK = 'abc123secret' }`, `token: env.HOOK` | not verified (when declarative evaluates triggers) | 015 pass | exit 1; files=['Jenkinsfile']; JEN-015 medium Jenkinsfile:7; notes=[] | way past (not verified); fixed |
| B097 | all | slow: methods calling the next twice, 14 deep, 20 sh steps in the last (file of ~2.9 KB) | - | 013 fail: 20 x '013 medium vars TOKEN' (L58-L77) \| 014 fail: 20 x '014 high command' (L58-L77); 014 high L80 binding (gpg-signing-key) \| 015 unknown (9 x '... | exit 1; files=['Jenkinsfile']; JEN-012 high Jenkinsfile:58; JEN-014 high Jenkinsfile:58; JEN-005 medium Jenkinsfile:58; JEN-013 medium Jenkinsfile:58; JEN-01... | slow; fixed |
| B098 | JEN-014 | slow: one sh line with 400 `cosign sign` and no `--key` (~6 KB) | - | 014 pass [0.28 s] | exit 0; files=['Jenkinsfile']; ; cov=['Jenkinsfile:pass']; notes=[] | held |
| B099 | JEN-014 | control for B060: lowercase `signtool sign /f cert.pfx` | rule text | 014 fail: 014 medium L7 command | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | held |
| B100 | JEN-014 | control for B061: `security import cert.p12 -k build.keychain` | rule text | 014 fail: 014 medium L7 command | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | held |
| B101 | JEN-014 | severity: pipeline-level `SIGNING_KEY = credentials(..)`, publish in a later stage | rule text | 014 fail: 014 high L4 binding (SIGNING_KEY, SIGNING_KEY_PSW, SIGNING_KEY_USR) | exit 1; files=['Jenkinsfile']; JEN-014 high Jenkinsfile:4; notes=[] | held |
| B102 | JEN-013 | `gitUsernamePassword(credentialsId: 'repo', gitToolName: 'git')` default `GIT_PASSWORD` | git plugin: the binding sets GIT_USERNAME and GIT_PASSWORD (not verified; not on the bindings page read) | 013 pass | exit 1; files=['Jenkinsfile']; JEN-013 medium Jenkinsfile:8; notes=[] | way past (not verified); fixed |
| B103 | JEN-014 | `cosign sign --key env://COSIGN_PRIVATE_KEY` | rule text | 014 fail: 014 medium L7 command | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:7; notes=[] | held |
| B104 | JEN-014 | import through a method of the file: `def importKey() { sh 'gpg --batch --import key.asc' }` | rule text | 014 fail: 014 medium L2 command | exit 1; files=['Jenkinsfile']; JEN-014 medium Jenkinsfile:2; notes=[] | held |
| C001 | JEN-001 | baseline withCredentials([string]) + ./gradlew |  | medium line 6 | medium line 6 | held |
| C002 | JEN-001 | withCredentials(bindings: [...]) |  | medium line 6 | medium line 6 | held |
| C003 | JEN-001 | single binding, no list |  | medium line 6 | medium line 6 | held |
| C004 | JEN-001 | usernamePassword |  | medium line 6 | medium line 6 | held |
| C005 | JEN-001 | usernameColonPassword |  | medium line 6 | medium line 6 | held |
| C006 | JEN-001 | sshUserPrivateKey (keyFileVariable only) |  | medium line 6 | medium line 6 | held |
| C007 | JEN-001 | certificate (keystoreVariable) |  | medium line 6 | medium line 6 | held |
| C008 | JEN-001 | file binding |  | medium line 6 | medium line 6 | held |
| C009 | JEN-001 | [$class: 'StringBinding'] map |  | medium line 6 | medium line 6 | held |
| C010 | JEN-001 | environment credentials() pipeline level |  | medium line 3 | medium line 3 | held |
| C011 | JEN-001 | environment credentials() stage level |  | medium line 5 | medium line 5 | held |
| C012 | JEN-001 | sshagent(['k']) |  | medium line 6 | medium line 6 | held |
| C013 | JEN-001 | withAWS(credentials: 'k') |  | medium line 6 | medium line 6 | held |
| C014 | JEN-001 | docker.withRegistry(url, 'id') |  | medium line 7 | medium line 7 | held |
| C015 | JEN-001 | withVault(configuration, vaultSecrets) |  | medium line 6 | medium line 6 | held |
| C016 | JEN-001 | withKubeConfig([credentialsId]) |  | medium line 6 | medium line 6 | held |
| C017 | JEN-001 | wrap([$class: 'VaultBuildWrapper']) |  | medium line 6 | medium line 6 | held |
| C018 | JEN-001 | configFileProvider([configFile(...)]) |  | medium line 6 | medium line 6 | held |
| C019 | JEN-001 | credential id by concatenation |  | medium line 6 | medium line 6 | held |
| C020 | JEN-001 | credential id as GString |  | medium line 6 | medium line 6 | held |
| C021 | JEN-001 | withCredentials(bindings: listVariable) |  | no finding; coverage not applicable | medium line 1 | missed; fixed |
| C022 | JEN-001 | options { withAWS(credentials:) } (declarative wrapper option) |  | no finding; coverage not applicable | medium line 5 | missed; fixed |
| C023 | JEN-001 | steps in script { } inside binding |  | medium line 7 | medium line 7 | held |
| C024 | JEN-001 | scripted node { stage { withCredentials } } |  | medium line 4 | medium line 4 | held |
| C025 | JEN-001 | method defined in file, called inside binding |  | medium line 6 | medium line 6 | held |
| C026 | JEN-001 | method called as this.runTests() |  | no finding; coverage pass | medium line 6 | missed; fixed |
| C027 | JEN-001 | method pointer this.&runTests called inside binding |  | no finding; coverage pass | medium line 7 | missed; fixed |
| C028 | JEN-001 | steps.withCredentials(...) |  | medium line 3 | medium line 3 | held |
| C029 | JEN-001 | closure in variable, .call() inside binding |  | no finding; coverage pass | medium line 4 | missed; fixed |
| C030 | JEN-001 | closure in variable, body() inside binding |  | no finding; coverage pass | medium line 4 | missed; fixed |
| C031 | JEN-001 | withCredentials(list, closureVariable) |  | no finding; coverage not applicable | medium line 4 | missed; fixed |
| C032 | JEN-001 | each { } loop inside binding |  | medium line 7 | medium line 7 | held |
| C033 | JEN-001 | scripted parallel map literal inside binding |  | medium line 3 | medium line 3 | held |
| C034 | JEN-001 | parallel branches map built before, parallel called inside binding |  | no finding; coverage not applicable | medium line 5 | missed; fixed |
| C035 | JEN-001 | declarative matrix with binding in steps |  | medium line 10 | medium line 10 | held |
| C036 | JEN-001 | nested stages, binding in pipeline env |  | medium line 3 | medium line 3 | held |
| C037 | JEN-001 | post { always { withCredentials } } |  | medium line 5 | medium line 5 | held |
| C038 | JEN-001 | scripted: binding outside any stage |  | medium line 3 | medium line 3 | held |
| C039 | JEN-001 | stage('x', { ... }) closure as argument |  | medium line 3 | medium line 3 | held |
| C040 | JEN-001 | steps.sh inside binding |  | no finding; coverage pass | medium line 3 | missed; fixed |
| C041 | JEN-001 | closure passed as first (non-last) method argument |  | no finding; coverage pass | medium line 2 | missed; fixed |
| C042 | JEN-001 | closure passed as trailing arg to method with binding (control) |  | medium line 2 | medium line 2 | held |
| C043 | JEN-001 | map of closures, tasks.build() inside binding |  | no finding; coverage pass | medium line 4 | missed; fixed |
| C044 | JEN-001 | when { changeRequest() } |  | high line 7 | high line 7 | held |
| C045 | JEN-001 | when { not { changeRequest() } } |  | no finding; coverage pass | none; pass | held |
| C046 | JEN-001 | when { branch 'PR-*' } |  | high line 7 | high line 7 | held |
| C047 | JEN-001 | when { expression { env.CHANGE_ID } } |  | high line 7 | high line 7 | held |
| C048 | JEN-001 | when { anyOf { branch 'main'; changeRequest() } } |  | high line 7 | high line 7 | held |
| C049 | JEN-001 | when { beforeAgent true; changeRequest() } |  | high line 8 | high line 8 | held |
| C050 | JEN-001 | scripted if (env.CHANGE_ID) inside script |  | high line 8 | high line 8 | held |
| C051 | JEN-001 | when { branch 'main' } (keeps CRs out) |  | no finding; coverage pass | none; pass | held |
| C052 | JEN-001 | when { branch 'MR-*' } (GitLab merge requests) |  | no finding; coverage pass | high line 7 | missed; fixed |
| C053 | JEN-001 | when { not { branch 'PR-*' } } (GitLab MR-<n> still reach) |  | no finding; coverage pass | medium line 7 | missed; fixed |
| C054 | JEN-001 | when { not { branch pattern: 'PR-\\d+', REGEXP } } (PR-1-head / PR-1-merge) |  | no finding; coverage pass | medium line 7 | missed; fixed |
| C055 | JEN-001 | if (env.GIT_BRANCH.startsWith('PR-')) (multibranch GIT_BRANCH = PR-<n>) |  | no finding; coverage pass | high line 8 | missed; fixed |
| C056 | JEN-001 | when { expression { env.BRANCH_NAME != 'main' } } |  | medium line 7 | high line 7 | lower; fixed |
| C057 | JEN-001 | when { not { not { changeRequest() } } } |  | medium line 7 | high line 7 | lower; fixed |
| C058 | JEN-001 | when { expression { two statements } } (unevaluable) |  | no finding; coverage unknown (line 5: credential(s) 'k' (line 7) reach steps whose stage condition the checker cannot evaluate, so it cannot) | none; unknown | held |
| C059 | JEN-001 | def isPR = env.CHANGE_ID != null; if (isPR) |  | no finding; coverage unknown (line 8: credential(s) 'k' (line 9) reach steps whose stage condition the checker cannot evaluate, so it cannot) | none; unknown | held |
| C060 | JEN-001 | agent: claude -p (direct, main only) |  | high line 7 | high line 7 | held |
| C061 | JEN-001 | agent: aider --yes (main only) |  | high line 7 | high line 7 | held |
| C062 | JEN-001 | agent: command in a Groovy variable |  | no finding; coverage pass | high line 9 | missed; fixed |
| C063 | JEN-001 | agent: whole command in variable, sh cmd |  | no finding; coverage pass | high line 9 | missed; fixed |
| C064 | JEN-001 | agent: bash -c 'claude -p ...' |  | high line 7 | high line 7 | held |
| C065 | JEN-001 | agent: npx @anthropic-ai/claude-code -p |  | high line 7 | high line 7 | held |
| C066 | JEN-001 | agent: env X=1 gemini -p |  | high line 7 | high line 7 | held |
| C067 | JEN-001 | agent: docker.image().inside { opencode run } |  | high line 9 | high line 9 | held |
| C068 | JEN-001 | agent: bat 'claude -p' |  | high line 7 | high line 7 | held |
| C069 | JEN-001 | agent: powershell 'copilot -p' |  | high line 7 | high line 7 | held |
| C070 | JEN-001 | agent: claude \<newline> -p (shell line continuation) |  | no finding; coverage pass | high line 7 | missed; fixed |
| C071 | JEN-001 | agent: pipx run aider-chat (package name) |  | no finding; coverage pass | none; pass | missed; not fixed, left to slice 2d.5 (agent tools): `pipx run aider-chat` is not in the agent catalogue |
| C072 | JEN-001 | agent: steps.sh 'claude -p' |  | no finding; coverage pass | high line 8 | missed; fixed |
| C073 | JEN-001 | agent: repo script runs claude (ci/review.sh) |  | high line 7 | high line 7 | held |
| C074 | JEN-001 | agent: aider as last word of script |  | no finding; coverage pass | none; pass | missed; not fixed, left to slice 2d.5: `aider` with no argument is not matched |
| C075 | JEN-001 | line comment containing } and withCredentials |  | medium line 6 | medium line 6 | held |
| C076 | JEN-001 | block comment containing } |  | medium line 6 | medium line 6 | held |
| C077 | JEN-001 | strings containing } before sh |  | medium line 6 | medium line 6 | held |
| C078 | JEN-001 | slashy string containing } and // |  | medium line 7 | medium line 7 | held |
| C079 | JEN-001 | dollar-slashy string containing } / |  | medium line 7 | medium line 7 | held |
| C080 | JEN-001 | triple-single-quoted script with ' and } |  | medium line 6 | medium line 6 | held |
| C081 | JEN-001 | all on one line with semicolons |  | medium line 1 | medium line 1 | held |
| C082 | JEN-001 | CRLF line endings and tabs |  | medium line 6 | medium line 6 | held |
| C083 | JEN-001 | arguments split over lines |  | medium line 8 | medium line 8 | held |
| C084 | JEN-001 | unicode escape in step name (\u0073h) |  | no finding; coverage unknown (line 7: statement not analyzed (line 7: unexpected '\\')) | none; unknown | held |
| C085 | JEN-001 | unicode escape in withCredentials name |  | no finding; coverage unknown (line 6: statement not analyzed (line 6: unexpected '\\')) | none; unknown | held |
| C086 | JEN-001 | GString with closure in interpolation inside binding |  | medium line 6 | medium line 6 | held |
| C087 | JEN-001 | 'withCredentials' only in a string/comment (no binding) |  | no finding; coverage not applicable | none; not applicable | held |
| C088 | JEN-001 | this.sh inside binding |  | no finding; coverage pass | medium line 3 | missed; fixed |
| C089 | JEN-001 | load 'ci/build.groovy' inside binding |  | no finding; coverage unknown (line 4: load(): Groovy loaded at run time is not analyzed) | none; unknown | held |
| C090 | JEN-001 | docker.build inside binding |  | medium line 3 | medium line 3 | held |
| C091 | JEN-001 | scripted if (env.BRANCH_NAME == 'main') { binding } |  | no finding; coverage pass | none; pass | held |
| C092 | JEN-001 | if (env.CHANGE_ID) {} else { binding } |  | no finding; coverage pass | none; pass | held |
| C093 | JEN-001 | binding around echo only |  | no finding; coverage pass | none; pass | held |
| C094 | JEN-001 | agent in another stage, binding in main-only stage |  | no finding; coverage pass | none; pass | held |
| C095 | JEN-001 | agent CLI outside catalog: cursor-agent -p (main only) |  | no finding; coverage pass | none; pass | missed; not fixed, left to slice 2d.5: `cursor-agent` is not in the agent catalogue |
| C096 | JEN-001 | withCredentials(bindings: [list] + extra) |  | no finding; coverage not applicable | medium line 6 | missed; fixed |
| C097 | JEN-001 | this.&runTests.call() inside binding |  | no finding; coverage pass | medium line 6 | missed; fixed |
| C098 | JEN-001 | stage options { withCredentials } (not verified Jenkins accepts it) |  | no finding; coverage not applicable | medium line 5 | missed; fixed |


## 2d.2k: pipeline code and pins

Run `brant`, 2026-11-17, on a copy of `flagship` at `9b806db`. Three Opus 5.5 reviewers that did not write the Jenkins rules were set on the six rules run `gadwall` had split off as 2d.2j (OBAAF-JEN-002, 003, 004, 006, 007, 008). The one on OBAAF-JEN-004 and 008 (reviewer C) wrote 85 attempts: 48 ways past, 2 weaker, 7 false positives, 2 slow cases, 26 held. The one on OBAAF-JEN-003 and 007 (B) wrote 111; its classes need a model of which stages share a workspace, so they are recorded below as 2d.2j's starting points and not fixed here. The one on OBAAF-JEN-002 and 006 (A) was stopped by a safety classifier before its first case. This tranche is OBAAF-JEN-004 and 008.

The fixes then went through nine review passes by fresh Opus 5.5 sub-agents, each given the code and the claims, not the author's view of them, and a tenth check of the last two-line fix. Blocking findings per pass: 16, 21, 11, 8, 5, 8, 2, 2, 1, then none. Every case a pass wrote that the fixes changed is a test in `tests/test_jenkins_code_pins.py` (the attack's cases under their ids, each pass's under `V1-` to `V9-`): 81 of reviewer C's cases (56 of them give another result on the code before the slice), and 214 cases in all, beside unit tests of the version, Dockerfile, container-command and YAML readers. Each class below names the attempts that showed it.

### OBAAF-JEN-004: code the reviewers did not approve

- **Any receiver.** `load` and `evaluate` were read only as those two names. Now any call whose last name is `load` or `evaluate` is code loading when its receiver is the script (`this`, `steps`, a variable or parameter given `this`), and so are `Eval.me/x/xy/xyz`, a GroovyShell, GroovyClassLoader or GroovyScriptEngine's `parse`, `run` and `evaluate` (made with `new`, `newInstance`, a qualified name or an import alias, and through copies), `parseClass`, a JSR-223 engine's `eval`, `.call` on a pointer, a pointer to `load` or `Eval.me` held in a variable or passed as an argument (`list.each(this.&load)`), and Job DSL (`jobDsl`, and the older `step([$class: 'ExecuteDslScripts'])` in both spellings), which runs on the controller (C006, C007, C009 to C011, C014, C015, C017, C021; the reviews' V1-003, 004, 010, 053, V2-030 to 040, V3-001 to 007, 049, V4-060 to 112). A receiver that may be something else (`props.load(...)`, `xpath.evaluate(...)`, a library's global variable) is "unknown" for OBAAF-JEN-004 only, not a finding (V1-005, 071, 088).
- **Reviewed text.** Literal text, a variable only ever assigned one literal, `readTrusted` and `libraryResource` are not findings (C018, C019). A variable assigned anything else anywhere (a parameter, a closure's or loop's variable, `this.x`, `binding.x`, `binding['x']`, `setVariable`, `setProperty`, two different literals) is not reviewed text (V1-001, V2-037, 038, 046, V3-003, 004, 020). Groovy built from a parameter or a change's text is a finding on any branch (C008).
- **Libraries.** A `library` step's retriever is read: `legacySCM(scm)` (also through a variable and `this.scm`) is the build's own checkout, high; a remote or other setting the file does not fix is medium, high when it comes from a parameter or a change's text; credentials and values the file fixes do not count (C004, C013, V1-006 to 009). A version read from a workspace file, directly or through a variable, is high (C082, V1-008). A `library(...)` at the root of a chain of properties is recorded (V1-077).
- **Conditions.** `GIT_BRANCH` compared with `==`, `!=` or `==~` is read as `BRANCH_NAME` is, so `env.GIT_BRANCH ==~ /PR-\d+/` reaches change requests (C012).

### OBAAF-JEN-008: images, libraries and agent CLIs that can move

- **Images.** A docker agent's image given as a value is put in from what the file fixes or is "unknown" (C029, C030); a pod spec is read as YAML, aliases once each and at most 50,000 nodes (C039 to C044, C078); a containerTemplate in a closure or a list the file builds is read or "unknown" (C037, C038); a Dockerfile that a `dockerfile` agent, `docker.build` or a script's `docker build` reads is read in its folder, with comments dropped before continuations, every leading parser directive (`# escape=`), heredocs on RUN, COPY and ADD, exec-form RUN, global ARGs and build arguments for FROM, a stage's ARG and ENV (ENV first) for RUN, stage names, `COPY --from` and `RUN --mount=...,from=` (C033, C034, C073, V1-011 to 015, V2-003, 004, 024 to 026, V3-039, 040); `docker`, `podman` and `nerdctl` run, create and pull are read where a command starts, after keywords, assignments, `sudo`, `env`, `timeout`, `xargs` and `bash -c`, with their global options, and not after `echo` or in a comment (C036, V1-021 to 024, V2-020 to 023, V3-014 to 017); an image the job builds or tags itself is not a registry reference, but a `pull` always is (V3-046, V4-001 to 100).
- **Agent CLIs.** Only an exact version passes: npm `@1.2.3`, pip `==1.2.3` (spaces allowed) or `===`; a range, a tag, a wildcard, extras without a version and a version set at run time do not (C048 to C054, C056, C068). Quotes are taken off first (V5-080 to 082). The installer's subcommand, its first word that is not an option, decides whether a package is installed; `uninstall`, `view`, `ls` are not installs (C062, V1-033, 087, V2-005, 006). pip names are compared as pip compares them (V1-031, 032). Install scripts count however they are fetched and run (`wget`, `bash <(curl ...)`, `| sudo bash`, PowerShell `irm ... | iex`, a known installer URL in any command) (C057 to C061, C071, C072, V2-015); `claude update` and `npm update -g` after an agent install, in any step, are updates (C064, V2-007, 008, V4-070); installs in the repository's scripts, `pip install -r` files (every `-r` and `-c`, nested ones), and `package.json` without a lockfile (npm aliases and peer dependencies included) are read, in the folder the command runs in: `dir()`, `cd`, `pushd` and `popd`, `cd -`, `--prefix`, a subshell's or a command substitution's `cd` ending with it, `$WORKSPACE` as the checkout; a folder that cannot be told is "unknown" (C066, C067, C069, C070, C075, V1-035 to 037, 075, V2-016 to 019, V3-032 to 037, V7-, V8-, V9-). A package named at run time is "unknown" (V1-074, V2-009, 010).
- **What the script sets.** A shell variable is put in only when the script sets it to one literal before the command; `read`, `for`, `declare`, `printf -v`, `mapfile`, `unset`, `+=` and `eval` make it unknown, and so does `source` or `.` of a file that is not plainly outside the checkout (an absolute path, `~`, `$HOME`, `$NVM_DIR`, a virtual environment's `bin/activate` leave the variables as they were). Environment values are the script's starting variables. Groovy's own variables go into a script only where Groovy interpolates it (V2-011 to 014, 069, 070, V3-008 to 013, V4-152 to 160, V5-060, 102, V6-).
- **Libraries.** A library named by a value is put in or "unknown"; a library is high when any stage runs an agent or publishes (C023, C024, C027).
- **Messages.** Text from a file is escaped (quotes, backslashes, backticks, control characters) and cut at 120 characters, so it cannot end the quoted part of a message or start a new line (V1-041, V2-057). A pinned install is "pass", not "not applicable".

### Time

The patterns that took seconds on long input are linear or bounded: a 3,000-line pod spec took 13.7 s (C078, now 0.3 s); one line of 8,000 `curl` words 7.5 s (C079; 2.6 s now, all of it in the upload patterns of issue #179); 2,000 `docker run` words 6.5 s and 8,000 `pip install` words 3.7 s (V1-061, 063; 0.3 s and 0.5 s). Each step's script is read once per call and folder, each repository script, Dockerfile, pod spec and requirements file once.

### Not fixed

An upper-case 40-hex library version is still called a branch (C025; whether Jenkins' Git retriever takes it was not checked). `load` of a path just written from `readTrusted` is still a finding (C076). Agents the catalogue does not name (`@qwen-code/qwen-code`, C081) are slice 2d.5's. Shell branches are read one after the other, so a `pushd` in each arm of an `if` misplaces the folder, and `pushd -n` is taken for a move (the tenth check's P002, P006). A case pattern's `)` closes a subshell early (V8's Z010). `docker build -` and `IMAGE_ID=$(docker build -q .)` are "named at run time". A method run under many `dir()` calls is read once per folder, which costs time (150 folders: 13 s). The native Claude Code installer updates itself unless told not to, which a pinned install does not show (from the reviewers' reading of its documentation; not checked).

### What changed for the first adopter

Expectrail has no Jenkinsfile. At `49226b6c` (a copy without anything under `fresh-*`, committed to a fresh git work tree), `obaaf check . --baseline .github/obaaf-baseline.json --fail-on low --no-fixes` gives byte-identical text and JSON before and after: 36 files, 57 findings. On this repository `obaaf check .` is byte-identical. For the three Jenkins templates (`templates/jenkins`) the findings and the exit status are the same; OBAAF-JEN-008's coverage changes from "not applicable" to "unknown", because each installs OBAAF's own setup requirements from a checkout of another repository, which the checker cannot read. The other Jenkins rules give the same results before and after on all 111 of reviewer B's cases.

### The attempts

Reviewer C, at `9b806db`; "After" is what the test holds.

| ID | Rule | Case | Before (at `9b806db`) | After | Result |
| --- | --- | --- | --- | --- | --- |
| C001 | JEN-004 | @Library('shared-lib@${BRANCH_NAME}') _ (single-quoted, so the version is the literal text ${BRANCH_NAME}) | 004 unknown (generic library-trust); 008 medium@1 'loaded at ${BRANCH_NAME}, a branch or tag that can move' | unknown | held |
| C002 | JEN-004 | library "shared-lib@${params.LIB_VERSION}" in script{} | 004 high@7 version taken from params.LIB_VERSION; 008 not applicable | finding (high) | held |
| C003 | JEN-004 | library('shared-lib@' + params.LIB_VERSION) (concatenation) | 004 unknown@7 'library step names a library computed at run time'; 008 not applicable | unknown | held |
| C004 | JEN-004 | library identifier: 'ci-lib@main', retriever: modernSCM([$class: 'GitSCMSource', remote: params.LIB_REPO]): library code from a repository chosen by a build parameter | 004 no finding; unknown only generic (library trust; unresolved step modernSCM); 008 medium@8 'main' | finding (high) | way past; fixed |
| C005 | JEN-004 | library identifier: "shared-lib@${ver}", changelog: false with def ver = env.CHANGE_BRANCH ?: env.BRANCH_NAME | 004 high@8 version from CHANGE_BRANCH | finding (high) | held |
| C006 | JEN-004 | def runCi(s) { s.load('ci/build.groovy') }; runCi(this) in an unconditioned stage (change requests reach it) | 004 pass, no unknown; 008 not applicable | finding (medium) | way past; fixed |
| C007 | JEN-004 | class CiRunner { def script; def run() { script.load('ci/build.groovy').build() } }; new CiRunner(this).run() | 004 unknown only generic 'class CiRunner' (statement not analyzed), no load finding | unknown | way past; fixed |
| C008 | JEN-004 | evaluate("${params.GROOVY}") in when { branch 'main' }: Groovy text from a parameter (GString arg is skipped as Str) | 004 unknown only 'evaluate(): Groovy loaded at run time is not analyzed' (rule skips isinstance(arg, Str)) | finding (medium) | held |
| C009 | JEN-004 | def cfg = Eval.me(readFile('ci/config.groovy')): evaluates workspace Groovy | 004 pass; 008 not applicable | finding (medium) | way past; fixed |
| C010 | JEN-004 | new GroovyShell(this.binding).evaluate(readFile('ci/steps.groovy')) | 004 pass; 008 not applicable | finding (medium) | way past; fixed |
| C011 | JEN-004 | jobDsl targets: 'jobs/**/*.groovy' in an unconditioned stage: Job DSL Groovy from the workspace runs on the controller | 004 unknown only generic 'calls 1 step(s) not built into Jenkins (jobDsl); probably shared-library or plugin code' | finding (high) | way past; fixed |
| C012 | JEN-004 | load 'ci/pr.groovy' under when { expression { env.GIT_BRANCH ==~ /PR-\d+/ } } (a PR-only stage) | 004 no finding: step cr='no' (checked with model.build); held only by generic 'load(): Groovy loaded at run time is not analyzed' | finding (high) | held |
| C013 | JEN-004 | library identifier: 'self@pr', retriever: legacySCM(scm): library code from the change's own checkout | 004 no finding; unknown only generic (library trust; unresolved legacySCM); 008 medium@7 'pr' | finding (high) | way past; fixed |
| C014 | JEN-004 | new GroovyShell(binding).parse(readFile('ci/steps.groovy')).run() | 004 pass | finding (medium) | way past; fixed |
| C015 | JEN-004 | this.class.classLoader.parseClass(readFile('ci/Steps.groovy')).newInstance().run(this) | 004 pass | finding (medium) | way past; fixed |
| C016 | JEN-004 | this."load"('ci/build.groovy') (method name as a string) | 004 medium@6 loads Groovy from the workspace | finding (medium) | held |
| C017 | JEN-004 | jobDsl scriptText: readFile('seed/jobs.groovy'), sandbox: true | 004 unknown only generic unresolved-step (jobDsl) | finding (high) | way past; fixed |
| C018 | JEN-004 | evaluate(libraryResource('org/ci/steps.groovy')) from a library pinned to a full SHA (safe) | 004 medium@7 'evaluates Groovy text read at run time. For a change request the workspace holds the change's own files' | unknown | false positive; fixed |
| C019 | JEN-004 | def helperCode = 'echo "static helper"'; evaluate(helperCode): text written in the Jenkinsfile (safe) | 004 medium@7 evaluates Groovy text read at run time | unknown | false positive; fixed |
| C020 | JEN-004 | evaluate(readTrusted('ci/steps.groovy')) (the recommended form; safe) | 004 no finding; unknown only generic evaluate() | unknown | held |
| C021 | JEN-004 | withCi { s -> s.evaluate(readFile('ci/steps.groovy')) } with withCi(Closure body) { body.call(this) } | 004 unknown only generic unresolved-step 's.evaluate' ('probably shared-library or plugin code') | unknown | way past; fixed |
| C022 | JEN-004 | when { branch 'main' }: checkout of another repository at params.CI_REF, then load 'ci-scripts/deploy.groovy' | 004 no finding; only generic load() unknown | unknown | held |
| C023 | JEN-008 | environment { CI_LIB = 'shared-lib@main' }; library env.CI_LIB: a literal branch, through the environment | 008 not applicable (no finding, no unknown); 004 unknown 'names a library computed at run time' | finding (medium) | way past; fixed |
| C024 | JEN-008 | environment { LIB_REF = 'main' }; library "shared-lib@${env.LIB_REF}" | 008 not applicable; 004 medium 'version computed at run time' | finding (medium) | way past; fixed |
| C025 | JEN-008 | @Library('ci-lib@<40 upper-case hex>') _ | 008 medium@1 'a branch or tag that can move' | not in the tests (stated limit) | false positive; not fixed, stated limit: an upper-case 40-hex library version is still called a branch (Jenkins' Git retriever not checked) |
| C026 | JEN-008 | @Library('ci-lib@<40 lower-case hex>') _ (pinned; safe) | 008 pass | pass | held |
| C027 | JEN-008 | @Library('ai-review-lib@main') whose step aiReviewPrepare() runs in the stage that runs claude -p | 008 medium@1 (description promises high for references used by agent stages) | finding (high) | weaker; fixed |
| C028 | JEN-008 | libraries { lib('ci-lib@v1.2') } directive | 008 medium@3 'v1.2' | finding (medium) | held |
| C029 | JEN-008 | agent { docker { image params.BUILD_IMAGE } } (default node:20) | 008 not applicable (no finding, no unknown) | unknown | way past; fixed |
| C030 | JEN-008 | def BUILD_IMAGE = 'node:20'; stage agent { docker { image BUILD_IMAGE } } | 008 not applicable | finding (low) | way past; fixed |
| C031 | JEN-008 | agent { docker 'node:20' } | 008 low@2 not pinned | finding (low) | held |
| C032 | JEN-008 | agent { docker { image 'node:20@sha256:<64 hex>' } } (pinned; safe) | 008 pass | pass | held |
| C033 | JEN-008 | agent { dockerfile true } with Dockerfile 'FROM node:20' | 008 not applicable (Dockerfile not read) | finding (low) | way past; fixed |
| C034 | JEN-008 | docker.build('app-ci', '-f ci/Dockerfile .').inside { } with 'FROM python:3' | 008 not applicable | finding (low) | way past; fixed |
| C035 | JEN-008 | def db = docker.image('postgres:16'); db.withRun(...) { } | 008 low@3 not pinned | finding (low) | held |
| C036 | JEN-008 | sh 'docker run --rm -v "$PWD":/src -w /src node:20 npm test' | 008 not applicable | finding (low) | way past; fixed |
| C037 | JEN-008 | def containers = [containerTemplate(name: 'node', image: 'node:20', ...)]; podTemplate(containers: containers) | 008 not applicable | unknown | way past; fixed |
| C038 | JEN-008 | Declarative kubernetes { containerTemplate { name 'node'; image 'node:20@sha256:<64 hex>' ... } } (pinned; safe) | 008 low@4 "Image '?' ... not pinned" | pass | false positive; fixed |
| C039 | JEN-008 | pod yaml with flow mapping: containers: [{name: node, image: "node:20", ...}] | 008 not applicable | finding (low) | way past; fixed |
| C040 | JEN-008 | pod yaml written as JSON: {"spec": {"containers": [{"name": "node", "image": "node:20"}]}} | 008 not applicable | finding (low) | way past; fixed |
| C041 | JEN-008 | pod yaml with a quoted key: "image": node:20 | 008 not applicable | finding (low) | way past; fixed |
| C042 | JEN-008 | pod yaml with a space before the colon: image : node:20 | 008 not applicable | finding (low) | way past; fixed |
| C043 | JEN-008 | pod yaml image as a folded block scalar: image: >-\n  node:20@sha256:<64 hex> (pinned; safe) | 008 low@2 "Image '>-' ... not pinned" | pass | false positive; fixed |
| C044 | JEN-008 | yamlFile 'ci/pod.yaml' with initContainers: - {name: init, image: busybox} (flow) and a pinned main container | 008 pass (busybox missed) | finding (low) | way past; fixed |
| C045 | JEN-008 | podTemplate(containers: [containerTemplate(name: 'node', image: 'node:20', ...)]) | 008 low@1 | finding (low) | held |
| C046 | JEN-008 | matrix axis NODE, agent { docker { image "node:${NODE}" } } | 008 unknown 'image reference node:${NODE} is computed at run time' | unknown | held |
| C047 | JEN-008 | def img = 'node:20'; docker.image(img).inside { } | 008 unknown 'an image reference is computed at run time' | finding (low) | held |
| C048 | JEN-008 | npm install -g @anthropic-ai/claude-code@^2.0.0 (range) | 008 pass | finding (high) | way past; fixed |
| C049 | JEN-008 | npm install --global @google/gemini-cli@preview (dist-tag) | 008 pass | finding (high) | way past; fixed |
| C050 | JEN-008 | npm i -g @anthropic-ai/claude-code@2 (major-only range) | 008 pass | finding (high) | way past; fixed |
| C051 | JEN-008 | pip install "aider-chat>=0.80" | 008 not applicable (package regex lookahead fails at '>') | finding (high) | way past; fixed |
| C052 | JEN-008 | pip install aider-chat[playwright] (extras) | 008 not applicable | finding (high) | way past; fixed |
| C053 | JEN-008 | pip install "aider-chat==0.86.*" (wildcard) | 008 pass | finding (high) | way past; fixed |
| C054 | JEN-008 | pip install aider-chat~=0.86 | 008 not applicable | finding (high) | way past; fixed |
| C055 | JEN-008 | sh ''' with backslash-newline inside the Groovy string (Groovy joins the lines): npm install -g \ @anthropic-ai/claude-code | 008 high@6 installed without a fixed version | finding (high) | held |
| C056 | JEN-008 | environment { CLAUDE_VERSION = 'latest' }; sh 'npm i -g @anthropic-ai/claude-code@$CLAUDE_VERSION' | 008 pass | finding (high) | way past; fixed |
| C057 | JEN-008 | curl -fsSL https://claude.ai/install.sh -o install.sh && bash install.sh (download, then run) | 008 not applicable | finding (high) | way past; fixed |
| C058 | JEN-008 | wget -qO- https://claude.ai/install.sh \| bash | 008 not applicable | finding (high) | way past; fixed |
| C059 | JEN-008 | bash <(curl -fsSL https://claude.ai/install.sh) | 008 not applicable | finding (high) | way past; fixed |
| C060 | JEN-008 | curl -fsSL https://claude.ai/install.sh \| sudo bash | 008 not applicable | finding (high) | way past; fixed |
| C061 | JEN-008 | curl -fsSL https://claude.ai/install.sh \| /bin/bash | 008 not applicable | finding (high) | way past; fixed |
| C062 | JEN-008 | npm uninstall -g @anthropic-ai/claude-code \|\| true (removal; safe) | 008 high@6 'installed without a fixed version' | not applicable | false positive; fixed |
| C063 | JEN-008 | curl -fsSL https://claude.ai/install.sh \| bash -s 2.0.14 (installer told a fixed version) | 008 high@6 'installs whatever version the script fetches': the reason given is wrong, the conclusion holds because the native install auto-updates | finding (high) | held |
| C064 | JEN-008 | npm i -g @anthropic-ai/claude-code@2.0.14, then claude update (moves to the latest version) | 008 pass | finding (high) | way past; fixed |
| C065 | JEN-008 | npm i -g @anthropic-ai/claude-code@2.0.14 @openai/codex@0.46.0 (both pinned; safe) | 008 pass | pass | held |
| C066 | JEN-008 | shell line continuation: npm install -g \\<newline>  @anthropic-ai/claude-code (backslash reaches the shell) | 008 not applicable | finding (high) | way past; fixed |
| C067 | JEN-008 | def AGENT_PKG = '@anthropic-ai/claude-code'; sh "npm install -g ${AGENT_PKG}" | 008 not applicable | finding (high) | way past; fixed |
| C068 | JEN-008 | sh "npm install -g @anthropic-ai/claude-code@${params.CLAUDE_VERSION}" (default latest) | 008 pass (only JEN-009 reports the interpolation) | finding (high) | way past; fixed |
| C069 | JEN-008 | sh './ci/install-agent.sh' whose file runs npm install -g @anthropic-ai/claude-code | 008 not applicable (the script is read for agent detection but not for JEN-008) | finding (high) | way past; fixed |
| C070 | JEN-008 | package.json devDependencies @anthropic-ai/claude-code: latest, no lockfile; sh 'npm install'; sh 'npx claude -p ...' | 008 not applicable | finding (high) | way past; fixed |
| C071 | JEN-008 | powershell 'irm https://claude.ai/install.ps1 \| iex' | 008 not applicable | finding (high) | way past; fixed |
| C072 | JEN-008 | environment { AGENT_INSTALLER = 'https://claude.ai/install.sh' }; sh 'curl -fsSL "$AGENT_INSTALLER" \| bash' | 008 not applicable | finding (high) | way past; fixed |
| C073 | JEN-008 | agent { dockerfile { filename 'ci/agent.Dockerfile' } } whose file runs RUN npm install -g @anthropic-ai/claude-code (FROM pinned) | 008 not applicable | finding (high) | way past; fixed |
| C074 | JEN-008 | npx -y @anthropic-ai/claude-code -p ... | 008 high@5 | finding (high) | held |
| C075 | JEN-008 | pip install -r ci/requirements-agent.txt containing aider-chat; then aider --message | 008 not applicable | finding (high) | way past; fixed |
| C076 | JEN-004 | writeFile file: 'ci/steps.groovy', text: readTrusted('ci/steps.groovy'); load 'ci/steps.groovy' (loads the trusted text; safe) | 004 medium@7 loads Groovy from the workspace | not in the tests (stated limit) | false positive; not fixed, stated limit: `load` of a path just written from `readTrusted` is still a finding |
| C077 | JEN-008 | agent { docker { image 'node:20' } } for a pipeline whose stage runs claude -p | 008 high@2 | finding (high) | held |
| C078 | JEN-008 | kubernetes yaml with 3000 blank lines before containers: (pinned image) | 13.73s; 008 pass. POD_IMAGE ~7s and JEN-006's hostPath pattern ~7s | pass | slow; fixed |
| C079 | JEN-008 | sh 'echo curl curl ... (8000 words)' on one line | 7.51s; 008 not applicable (AGENT_INSTALL_SCRIPT backtracking) | not in the tests (stated limit) | slow; partly fixed: the install pattern is linear now; the remaining 2.5 s is the upload patterns of #179 |
| C080 | JEN-008 | kubernetes pod yaml image node:20; stage runs claude -p in container('node') | 008 high@2 | finding (high) | held |
| C081 | JEN-008 | npm install -g @qwen-code/qwen-code@latest; qwen -p ... (agent not in the catalogue) | 008 not applicable (JEN-007 also silent) | not in the tests (stated limit) | way past; not fixed, left to slice 2d.5: `@qwen-code/qwen-code` is not in the agent catalogue |
| C082 | JEN-004 | library "ci-lib@${readFile('.ci-lib-version').trim()}": version from a workspace file a change request can edit | 004 medium@7 'computed at run time' (rule severity high; a parameter gets high) | finding (high) | weaker; fixed |
| C083 | JEN-008 | pip install aider-chat==0.86.1 (pinned; safe) | 008 pass | pass | held |
| C084 | JEN-004 | load 'ci/pr.groovy' under when { changeRequest() } (baseline for C012) | 004 high@7 | finding (high) | held |
| C085 | JEN-004 | library "ci-lib@${env.GIT_BRANCH}" in a PR-only stage with credentials | 004 high@8 version from GIT_BRANCH | finding (high) | held |


## 2d.4b2: the steps of local composite actions

Slice 2d.4b2 (decision D-083) reads a local composite action's steps as the job's for every rule, in a second pass. Its starting points were ways past recorded above: a checkout of the head given to a local action as an input (2d.2c), a cache and a publish inside one (attempts 015 and 111 of 2d.2e), and an unpinned action inside one (attempt 015 of 2d.2f). Each is now a finding on the action's step, held by `tests/test_local_action_steps.py`, whose main test compares 14 cases with the same steps written in the job.

Two Opus 5.5 sub-agents that did not write it reviewed it in turn, on 2026-11-18.

- **First pass, 115 attempts.** Blocking:
  1. an `if:` YAML gives as `false` or `0` inside the action was dropped under the using step's `if:`, so a check that never runs cleared OBAAF-GHA-016 and 017;
  2. a more severe case of a rule on the same step was dropped (`gh attestation verify` after an action that writes `GITHUB_PATH`);
  3. a text too long once its inputs were put in was left as written, and one reference to `inputs` the checker did not work out kept the whole expression as written (OBAAF-GHA-010 lost, `(inputs).title`);
  4. costs: an action read again for each use (102.7 s), no bound for the check (77 s for 30 jobs), aliases counted once (57.8 s and 1.8 GB);
  5. a false claim that a cache inside an action is reported on its own step;
  6. lanes added to the job changed a first-pass finding's reason (a trusted job made an effect job).

  All fixed by class.
- **Second pass, 66 attempts and a fuzz of 1,458 malformed actions** (no crash). Blocking:
  1. steps of an action that share a name collapsed into one finding, so a baseline's count of an entry covered a new risky step;
  2. a "cannot tell" finding on a job's own step kept the first pass's digest of what feeds its value, which did not cover a `GITHUB_ENV` write inside the action;
  3. a constant input became an expression, so a docker build with `push: false` was read as a publish;
  4. a `with:` written as one expression was read with the action's defaults, and nothing said;
  5. OBAAF-GHA-023 did not read the actions;
  6. worse control verdicts from the second pass were dropped (OBAAF-GHA-005's "no outsider's input" verified beside a fetch of a pull request's code in the action).

  All fixed by class: a first-pass finding of the same case is now replaced by the second pass's, never less severe or nearer to cleared.
- **Third pass, 37 attempts, on the second pass's fixes.** Blocking:
  1. the fix for a constant input opened a way past in `if:`: `if: ${{ inputs.verify }}` given `''` became no condition, so a check GitHub skips counted (OBAAF-GHA-016 and 017 lost). An expression in `if:` or `continue-on-error` is no longer turned into text;
  2. OBAAF-GHA-015's release case was dropped beside the first pass's `capability` at the same severity; another case is now added where the action's steps put the job in a lane;
  3. OBAAF-GHA-023 read an action's steps once per workflow, so a second use, in the same job or another, gave nothing; each use is now read.

  A test of 114 workflows with five actions that do nothing risky found no change of identity, severity or state. A separate case showed that the digest of a "cannot tell" finding on a step after any local action changes, which D-083 now states. A fourth pass, by the same reviewer on these fixes, found nothing blocking; it noted that a YAML alias between two steps of one action gives OBAAF-GHA-023 for each step, where the same alias in a job gives one (the safe direction, stated in D-083).

**Left, stated in D-083:** an action's `outputs` read in the job; the secrets rules, which read the job's own text; OBAAF-GHA-015 `capability` (medium) beside the second pass's high finding for a job whose action publishes; OBAAF-GHA-014 and 016 twice for a job that publishes in its own step after an action that publishes; nesting more than ten deep is a note (as in 2d.4a); a `./` path whose letter case differs from the folder's (as in 2d.4a).

## 2d.4b3a: what a called local workflow is given

Slice 2d.4b3a (decision D-084) reads a called local workflow's `inputs` with what each calling job of the repository hands them, and names in OBAAF-GHA-003's and 004's `inherited` findings what each caller grants. Its starting point was a way past recorded above (2d.2c): a `pull_request_target` workflow that hands the pull request's head to a local workflow as `inputs.ref`, which checks it out, was "cannot tell" at medium since slice 2d.4b1. It is now OBAAF-GHA-002 high, and an outsider's text handed to an input and expanded in a script is OBAAF-GHA-010.

**Review.** An Opus 5.5 sub-agent that did not write the slice ran about 120 cases on the checker before and after it. No finding of the code before disappeared or became less severe. It found:
- **Costs** (blocking): the values callers hand were read again for each alias, with no bound, before any text was put in: 100 jobs each handing 100 aliases of a 100 KB value took 128 s, 10,000 inputs sharing a 200 KB default took 1.9 GB and, at 20,000, a `MemoryError` traceback. Now each value is read once, counted each time it is given, and a workflow that names no input outside `on` is not worked on at all. An 85 KB text given through 100 aliases of a step took 26 s; aliases are now counted where the rules read them. 1,700 callers handing distinct values to 100 steps (9.2 M characters) took 26 s; the check's bound is now 2,000,000 characters. `granted` was quadratic (1,000 agent jobs and 2,000 callers, 22 s) and is now worked out once per workflow.
- **A way past the new reading:** an outsider's text in the caller's matrix (`matrix: {b: ['${{ github.event.comment.body }}']}`, `with: {x: ${{ matrix.b }}}`) or a needed job's output, handed on and expanded in a script, gave no OBAAF-GHA-010, where the same written in one workflow does. The caller's matrix values and needed jobs' outputs are now followed, one level deep.
- **A name with a letter outside ASCII** (`ſ:`) was dropped without a word; it is now read as given to every input, with a note.
- **Values at the top of the workflow** (`run-name`, `concurrency`) were not put in, though the code's own description said so; they are.
- **The `granted` text** said a caller that only another repository calls grants the repository's default, and did not say that a workflow which can also start on `push` holds the default then; both are corrected.
- The generated rule catalogue was not rebuilt (two tests failed), and the decision, the changelog and the upgrading rows were missing.

**Second pass** (the same sub-agent, on the fixes): eight of the ten were fixed and the ninth partly. It found two blocking faults in the new following of the caller's matrix: a 1 KB caller whose matrix doubles through aliases at each of 22 levels ended in a `MemoryError` traceback (its text was made before it was counted; a value or default given as such an alias did too, since the first version), and a wide matrix scanned again for each reference took 147 s for a 48 KB repository. Now a value's size is counted before its text is made, and each caller's matrix and jobs are indexed once. Not blocking: a harmless 5 KB repository (256 services read in 25 lines of one script) failed on the per-text bound of 100,000 characters, now 1,000,000, and the error names which bound was passed; `needs.*`, `toJSON(needs)`, a computed job name, two levels of outputs, an output that reads its own job's matrix and a matrix made from an output still passed an outsider's text without a word, and are now followed to three levels; a secret in a needed job's output gave a false OBAAF-GHA-001 on the called workflow, and is now moved under `caller.`, since GitHub does not pass such an output on. No finding of the code before was lost or lowered on about 120 cases.

**Third pass** (a second Opus 5.5 sub-agent, fresh, on the whole slice, 352 case repositories): six blocking findings. `needs.*.result` read the needed jobs' outputs, a false OBAAF-GHA-010 on the usual "notify on failure" job; an `include` written as one expression was passed over, a way past; five `env` values read by 200 steps each took 57 s inside the bounds; OBAAF-GHA-013's fork-safe runner selector was raised from info to medium once `inputs.runner` was put into `runs-on`; `${PREFIX}` in a value, written `${{PREFIX}}` in a `format()` template, made a condition without `${{ }}` read as text, so it stopped narrowing to `push` (a false OBAAF-GHA-002 high); and a step named `Check out for ${{ inputs.os }}` changed name with the caller's matrix, so an unrelated pinning acceptance stopped matching. Now `needs.x.result` gives nothing, such an `include` gives every name, `env` text is counted for each step it reaches, `runs-on` and `name` are left as written, and literal text is an argument of `format()`, never its template. Not blocking: an input handed `production` as an environment makes the job a release job (right, and now in the upgrading row). No finding was lost or lowered.

**Fourth pass** (the same sub-agent, on the fixes, 406 cases): the fork-safe runner selector written as a list or a `labels:` mapping was still raised to medium (now the whole `runs-on` is left as written), and a 400 KB value made by a short list of aliases, read through `env` by 250 steps of a local action or through `defaults.run.shell` by 800 steps, took 30 to 44 s (now the values handed to one input are bounded at 50,000 characters, and `defaults` is counted per step as `env` is). Not blocking: GitHub's escape `${{ '${{' }}` in a value stopped a bare condition narrowing again (now written `${ {` in any string); a false error on one 10 KB repository built to pass the bound (stated in D-084); facts of 2d.4b2's local-action findings written differently (stated in D-084).

**Fifth pass** (the same sub-agent, 406 cases): eight 25 KB values read through the workflow's `env` by 4,000 steps of local actions took 120 s, because the count per step left out the steps of local actions (now counted once they are known, and past the bound the values are put back as written); and the new 50,000-character bound for one input failed a reusable "run this script" workflow that 20 jobs each hand a 2.9 KB script (now 500,000). A `runs-on` list shared by alias with another place is left as written there too (base's reading, not blocking).

**Sixth pass** (the same sub-agent, 406 cases): after the values were put back, the local steps were read again and counted twice, a false error past the check's 10,000 steps that cost four jobs their local steps and OBAAF-GHA-002 high (now the count, the notes and the errors go back to where they stood first). Not blocking, stated in D-084: the lanes worked out from the values put in stay after a put-back.

Every class is a test in `tests/test_called_workflow_inputs.py`.

**Held** (each before and after the fixes): `INPUTS.BODY`, `inputs['body']`, `(inputs).body`, `toJSON(inputs)`, `inputs.*`, `fromJSON(toJSON(inputs)).body`, `inputs.x || 'x'`, `format('}}{0}', inputs.x)`; on the caller's side upper-case keys, flow mappings, block scalars, mixed text, `toJSON(github.event)`, keys with space, duplicates in two cases, `~:`, `1:`, `true:`, `with:` as a list, a scalar or one expression; chains of three, cycles, a workflow that calls itself; `$/` and `@main` calls; workflow, job and step `env`, github-script, a local composite action inside the called workflow, the called job's matrix, `parallel`, `if:` without braces; aliases between an input's default and a step; head references in their usual forms; no traceback for values that are mappings, lists, numbers, null or true, for inputs declared as a list, null or text, for unterminated `${{` on either side, or for deep nesting. `granted` never said read where a caller grants write (`write-all`, `read-all`, a value GitHub does not document, upper-case scopes, `permissions:` with no value, chains, cycles, two callers).

**Left, stated in D-084:** a job's `runs-on` and a job's and step's `name` are not put in (OBAAF-GHA-013 stays "other labels" at medium for a runner handed as an input); the other rules that read a called job's undeclared permissions as unknown; a caller's value followed more than three levels, and a step's output inside a needed job's output; an agent CLI named only through an input; and what a called workflow does counted for its caller, slice 2d.4b3b.

## 2d.4b3b: what a called local workflow does

Slice 2d.4b3b (decision D-085) counts what a called local workflow's jobs do for the job that calls it. Its starting points were four attempts recorded above: 026 of 2d.2d (a `pull_request_target` workflow calls a local workflow, with `secrets: inherit`, whose job publishes in environment `production`), and 034, 035 and 103 of 2d.2e (a release job that calls a local workflow which restores a cache or publishes, and a called release job whose caller sets `cache-mode: none`). The attempts' own files were not kept, so each is a test written from its description in `tests/test_called_workflow_effects.py`.

| Attempt | Before (flagship at `db7fd5a`) | Now |
| --- | --- | --- |
| 026 | The called job gets OBAAF-GHA-015 with the caller's `pull_request_target` (since 2d.4b1); the calling job is "trusted (default)" | The calling job is a release job ("calls ..., whose job 'publish' is a release job"); OBAAF-GHA-018 on it is high |
| 034 | A declared release job that calls a workflow whose job restores a cache gets only OBAAF-GHA-006 low `no-cache-mode` | OBAAF-GHA-006 high `called-restores`, naming the step; `cache-mode: none` on the calling job clears it |
| 035 | The called release job that restores gets OBAAF-GHA-006 high `restores`, as new, though its only caller sets `cache-mode: none` | The same finding, "cannot tell": every caller in the repository forbids restoring, and a caller in another repository is not seen |
| 103 | The called job that publishes gets OBAAF-GHA-014 and 016; the calling job is "trusted (default)" | The same findings on the called job; the calling job is a release job |

**First review** (an Opus 5.5 sub-agent that did not write the slice, about 90 attempts, base and new compared on each; 14 held, 3 blocking):
- **A false finding at high** (blocking): the first version counted every called job's restores for a release caller, so a test job with `setup-node` `cache: npm` beside a publishing job that needs it but downloads nothing gave the caller OBAAF-GHA-006 high, where the same two jobs in one workflow give nothing; and a local action in a job that does not release counted as restoring. Now only a declared release job is held to the called jobs' restores, and only those of called jobs that are not release jobs themselves (a release job's own are its own finding); a job that is a release job only through the call gets `needed-job-restores` as the same jobs in one workflow would.
- **OBAAF-CFG-001 lowered** (blocking): a stray `OBAAF_LANE: release` under a calling job's `with:` dropped from high to low, because the call put the job in the release lane and the declaration was taken as redundant; a lane a call gives holds the job to fewer rules than a declared one, so it is no longer taken as redundant.
- **A traceback** (blocking): a `cache-mode` of 5,000 hexadecimal digits on any job raised `ValueError` from `Job.cache_mode`, which the new pass reads for every called job (the code before raised it for release jobs and for `pull_request_target` jobs, in `cache_write_low_trust` too); both now read the value with `as_text`.
- **The outside caller's event** was narrowed away by a needed job (`needs: a` with `if: github.event_name == 'pull_request_target'`): a caller in another repository runs the needed job too, so the needed job no longer narrows that event away. `!(github.event_name != 'x')` and `contains(fromJSON(...), github.event_name)` are not read, and stated in D-085.
- **A way past** (not a regression): a calling job that needs a job restoring a cache and uploading an artifact, whose called job downloads it and publishes, gave nothing, where one workflow gives `needed-job-restores`; it now does.
- **Not blocking, fixed:** counts were added up along paths, so a diamond said "2 in all" for one step and a 30-level lattice "1,073,741,824" (now distinct entries, and a digest that does not depend on the path, up to 2,000 distinct entries; past them the digest can depend on the order of the parts, stated in D-085); the callers' control was given beside a call by `owner/repo/...@ref` that may be this repository (now not); a calling job declared `trusted` lost the note `classify` gives; OBAAF-GHA-015 `capability` on a job the call made a release job said "cannot tell whether it releases" (now kind `capability-call`); the lane's reason read "whose job 'build' set in the checker configuration"; a declared release job between two calls had no callers' control; the work was done for every job of every workflow (now only for workflows some job calls); and the docstring of `_only_called_forbidding`.

**Second review** (the same sub-agent, on the fixes; about 100 attempts, every first-pass case run again; 11 of 13 fixes held, 2 blocking):
- **A false finding at high** (blocking): `needed-job-restores` was given to a calling job when any called job downloaded the run's artifacts, so an `e2e` job that downloads and tests, beside a release job that publishes from a fresh checkout, gave it, where one workflow gives nothing. Now only a called release job's download counts for a job the call makes a release job (any called job's, for one declared a release job).
- **A way past** (blocking): a workflow between a declared release job and the job that restores dropped `called-restores`, because the job between was a release job through its own call and passed nothing on. A job that is a release job only through a call now passes on what its called jobs restore.
- **Not blocking, fixed:** the needed job that narrows an outside caller's event is now read for that event (a needed job with `if: github.event_name == 'push'` rules out `pull_request_target`); a needed job that is itself a call (`build: uses: ./.github/workflows/build.yml`) now restores what its called jobs restore, a gap in the code before too; past 2,000 entries the message said "more than 0" (the larger part is now kept, so the count is a true lower bound); the documents said OBAAF-GHA-008 rises to high on a calling job, which it never does (a local call is not a pin), and lacked a row for a declared calling job's `needed-job-restores`.

**Third review** (a fresh Opus 5.5 sub-agent, about 80 comparisons of the code before and after over 30 case repositories, 30 sweeps and 13 cost runs; 3 blocking):
- **A cost** (blocking): whether a caller in another repository may run a needed job was worked out again for every job that needs it and every event its `if:` names, so a 79 KB reusable workflow of 128 jobs with conditions of their own, needed by jobs whose `if:` names every event, took 399 s (0.6 s before the slice). It is now kept once for each job and event; the same file takes 2.4 s.
- **A way past** (blocking): a release job that needs a job calling a workflow whose release job restores a cache got no `needed-job-restores`, where the same jobs in one workflow get it, because only the restores of called jobs that are not release jobs were counted. A needed job that calls now restores what any job it calls restores.
- **The order of jobs** (blocking): the steps named in `called-restores` were in the order they were found, so swapping two called jobs made an acceptance stop matching, below the 2,000-entry bound that D-085 named for it. They are now sorted.
- **Not blocking, fixed:** the callers' control on `needed-job-restores` said to set `cache-mode: none` on the job itself, which cannot clear that kind (now: on the jobs it needs that restore); the rule's description said any release job that calls is reported, where only a declared one is; a call by name written `me/repo/./.github/workflows/x.yml@ref` had no note; the `capability-call` message said the called jobs are held to the release rules with the caller's triggers, which their own `if:` can rule out; a changelog sentence was too broad. **Stated, not changed:** a caller in a file that does not parse is not seen (the check fails on that file's error); the jobs that need a job whose `if:` names an event for an outside caller are not given the event; SARIF's rule help for OBAAF-GHA-006 changes with the description.

**Fourth review** (the same sub-agent, on the fixes; about 60 attempts, each compared with the code before): no blocking finding, and the eleven fixes hold. Its points: an upgrading row still gave the old fix for `needed-job-restores` (corrected); past 2,000 entries the steps named are the kept part's (now said in D-085); `a/b//.github/workflows/x.yml@r`, with two slashes, is not taken for a call by name, so the callers' control is still given (how GitHub reads that form is not established; the finding is "cannot tell" and fails); and the adversarial files of the third review still take about three times as long as before the slice (2.6 s against 0.75 s for 79 KB), linear in jobs, needs and events.

Every class is a test in `tests/test_called_workflow_effects.py`.

## 2d.5c2c: options built in code in another language

OBAAF-GHA-026 in code given to an interpreter, a github-script script, and PowerShell and cmd steps (`src/obaaf/checker/agent_code.py`, D-095). The first version was attacked by an Opus 5.5 sub-agent that did not write it: 379 probes, checked against python3 3.13, node 22, bun, perl, ruby, php and mawk with a stub program that prints its arguments where those ran (pwsh, deno, gawk and cmd were not installed; those cases rest on their documentation).

It found, in classes: a `${{ }}` expression and an unquoted heredoc's expansions read as plain text (both pass an option to the program); a value put into a string's own quotes taken for one word; PowerShell and cmd read by a regular expression to the end of a line (no continuations, groups, `&`, curly quotes or `Start-Process`); a list joined into a shell string; lists made or changed in ways the first reader did not follow (`list(...)`, tuples, `shlex.split`, annotations, attributes, copies, `push(@c, ...)`); tokenizer faults (a `/` in a regular expression's class, Ruby's `?"`, Perl's `$'`, `{s}` read as `s///`); calls without brackets (`system %(...)`, `system <<~CMD`); the interpreter reader's options (`python3 -I -c`, `perl -Mautodie -e`, `awk -v`, and `php -r`, whose code was never read); a crash (a string holding the reader's own marker name ended the whole check with a traceback); and three super-linear inputs (names given the program thousands of times, Perl and PHP subscripts that do not close). False positives: every string that started with the program was read as a command line (`f"claude exited with {rc}"`), every `"--" + x` in code that named the tool was "cannot tell" (argparse), and PowerShell lines were "cannot tell" for a variable inside quotes, a redirection or `Get-Command claude`.

A second Opus 5.5 sub-agent, which wrote none of it either, reviewed the fixed version: 418 probes (about 45 run in the languages), 180,000 random inputs (no crash), 32 mutations (21 killed). Blocking: a line break inside brackets ended a join, so code as black and prettier format it was silent; and four inputs took 7 to 26 s (a list of names, `/[` repeated, a long literal put into many holes, a chain of names). Non-blocking: the JavaScript forms `exec.exec('claude -p x', flags)`, `{shell: true}` and `exec.exec('bash', ['-c', ...])`; joined lists in a name; the tokenizer in valid code (a regular expression after `if (...)`, HTML-like comments, Ruby's `%=`, PHP's inline HTML); awk fields; PowerShell blocks, `Start-Process` switches and comma lists; cmd's `%VAR%` inside quotes (put in as text before quotes are read); a crash that the first fixes for its findings introduced (an `AttributeError` on a list joined in a name), caught when its probes were run again on them; false "cannot tell" for the program's name in JavaScript calls that run nothing (`core.group('claude', fn)`), for lists built from literals (`args.push('--verbose')`), for a logged list (`console.log(...args)`) and for `$env:NAME` in PowerShell. Each is fixed or stated, and its probes are `CASES_2` in the same file, with reasons where the result differs from what it wanted (among them: `$env:F` in PowerShell is now one word, as its own finding B14 asked, so its earlier probes that wanted "cannot tell" for it are quiet; Ruby's `"\#$1"` does not put in `$1`).

Every class is fixed or stated, and each probe is a test case with what is reported now (`tests/agent_code_review_cases.py`, run by `tests/test_agent_code.py`). Differences from what the reviewer wanted, each with its reason in the case file: a value put into a string's quotes is "cannot tell", as the reviewer's own finding A03 showed (two of its probes wanted it quiet); a list held in a name the code does not change is read rather than "cannot tell"; an unquoted PowerShell variable stays "cannot tell" (F-274); PHP's single quotes keep `\x2d` as text (checked with `php -r`), so that probe is not a way past; stated limits for program names given by escapes, pieces or run-time paths, lists in mappings, Perl's `exec { }`, AppleScript, Tcl, and a shell that runs another interpreter.

## 2d.13: what an earlier step writes to GITHUB_ENV

OBAAF-GHA-016 (and OBAAF-GHA-021's checks and OBAAF-GHA-017's provenance commands, which use the same reader) vouched for a check after an earlier step that wrote `PATH=...` to `GITHUB_ENV` (F-278, D-125). The runner's handling was read from actions/runner v2.338.2 and shown on a GitHub-hosted `ubuntu-24.04` runner by CI's job `github-env-premise` (run 44711052227): a stand-in `obaaf` put first on the PATH through the file ran in place of the check, and after `SHELLOPTS=noexec` a step ending in `exit 1` succeeded without running.

One Opus 5.5 sub-agent that wrote none of it attacked five versions, running each bash and dash behaviour it relied on against a mock set of runner files:

| Pass | Attempts | Ways past (root causes) | Found |
| --- | --- | --- | --- |
| 1 | about 115 | 4 | `DYLD_...` on macOS; `$GITHUB_\<line break>ENV`; the output file's path changed into the env file's (the runner names a step's files side by side with one suffix); a write in the step's `shell` |
| 2 | about 92 | 5, and a slow case | other copies of the output file's path (`set --`, `for`, `read`, `printf -v`, a name reference, `sed`); a substitution nested in `${...}`; a continued line in an `env` value; a write in the job's `env` or matrix; `$'GITHUB_\x45NV'`; two quadratic regular expressions |
| 3 | about 54 | 4 | `tee`'s own output sent to the env file; `$'\0012'` in an `sh` step (dash); `1<>`, which writes over an earlier line; a container's `env` |
| 4 | about 39 | 1 | a continued line splitting `<>` |
| 5 | about 21 | 0 | |

The second version searched for listed constructs; from the third on, every file command's variable in a bash script is read with the lexer and accepted only as a plain redirection target or `tee`'s file, which also removed most of the second version's false positives. Each way past is a test in `tests/test_github_env_steering.py`. Stated and not fixed: a name or a path a script assembles otherwise (a glob over the runner's temporary folder, `env | sed`, `/proc` through a group redirected to an output), what a program or action an earlier step runs writes, and a line break that a variable, a file or a command's output puts in a value at run time. Known false positives, by design: Python, PowerShell or an action that names a file command, a tool given the output file's path, `options: -e TZ=UTC` on a container, and `&&\` with no space before the backslash in a script that writes `GITHUB_ENV`.

## 2d.14: a job that may publish, and image pushes

OBAAF-GHA-006 was silent on a job outside the release lane that restores a cache and then holds a publishing credential (#289, found by the zizmor parity test); the slice adds the `capability-restores` and `capability-needed-job-restores` cases, and image pushes the release lane did not read (D-126). One Opus 5.5 sub-agent that wrote none of it attacked each version, with the workflows of 20 public projects (sparse clones of `.github`) diffed against `flagship` each time and buildx v0.39.0's own `bake --print` used to confirm how it reads outputs and overrides:

| Pass | Attempts | Ways past | False positives | Found |
| --- | --- | --- | --- | --- |
| 1 | about 230 | 13 | about 16 | permissions a caller grants a called job not counted; `workflow_call` not counted for `contents: write`; options before `buildx`/`imagetools`; any expression in an output or bake override, a cache import (`--cache-from type=registry`) or `type=registry` anywhere on a line taken for a push (two docker/buildx workflows became release jobs); a local action counted as a cache step though its steps were read; capability and release findings side by side; the new command pattern tripling the time of a 120 KB line; the sample's numbers misstated |
| 2 | about 270 | about 28 (8 kinds) | about 7 | expressions in `-o`/`--output` and bake's `--set` not read as in inputs; an expression in a bake key split by the key reader; bake's `+=`; quoted CSV fields and trimmed keys; bounding the existing `--push` pattern made a long continued command fall silent; a nested local action recognised by name only; `*.args.PUSH=true`; `--outputs=`; `docker image build`, `docker builder build`, `docker buildx b` |
| 3 | about 370 | 7 (3 kinds), and a slow case | 3, documented | a chain of `-o,` that made the command pattern quadratic (132 s at 100 KB); a `;` or `&` in a quoted argument hid the output; an expression with spaces before `type=` on a command line; a contrived name collision between an unreadable nested action and the step after it |
| 4 | about 300 | 3 quoting edge cases (an escaped quote inside a quoted argument, the `'\''` idiom, a `}` inside an expression) and commands 8 to 16 KB long | 0 | a crafted line of `docker build` and `-o,` chains, linear but 60 times `flagship`'s cost; the output piece is now 256 characters and stops at a space before the next option |
| 5 | about 250 | 0 new (an output longer than 256 characters before its `type=` or `push=`, stated) | 0 | an expression could hold a space and the next option, so a crafted line of `${{ docker build -o ... }}` blocks took minutes; an expression piece now stops at a space before an option too. On every line the reviews built, a search costs at most about six times the older `--push` pattern's on the same line (a full check about four times), and it is linear; a sixth look confirmed the fix and lost nothing of 223 probes |

Each way past and false positive is a test in `tests/test_gha006_may_publish.py`, except the name collision. Stated and not fixed: an unreadable local action inside a composite action followed at once by a step named after it (`<name>: ...`), which is then taken as read; options written before `buildx` or `imagetools`; an output option more than 8,192 characters into its command or after an unquoted `;`, `&` or `|` in it; what a bake file says; a credential passed under another name to a called workflow that restores a cache; `contents: write` on other events; permissions nobody declares; a `$/` action whose file cannot be read is not a cache step for a release job (older than this slice); an expression in a `docker` output that a comma could turn into another type; image pushes by other tools.

## 2d.2j: agent stages and workspaces

Run `tern`, 2026-11-20, from `flagship` at `1261b92`. Two sets of attempts: reviewer B's 111 on OBAAF-JEN-003 and 007 at `9b806db` (run `brant`, 2026-11-17, kept below as they were recorded), and 115 by a new Opus 5.5 reviewer on OBAAF-JEN-002, 003, 006 and 007 at `d9e268d`, the first commit of this slice.

**What changed.** The classes behind most of reviewer B's ways past were that OBAAF-JEN-003 read an agent and an effect as sharing a workspace only inside one stage (C1), and that it cannot follow what a script's values are (A1). This slice builds C1: the model records a workspace for every step, and the rule follows a workspace across stages, post blocks, `reuseNode`, `ws()`, `stash` and `unarchive`; the table is in [jenkins.md](jenkins.md). A1, and commands the checker does not recognise as an agent or an effect, are not this slice's: they are tracked in #330.

Of reviewer B's rows, these are fixed and tested in `tests/test_jenkins_workspaces.py`:
- ways past B002 to B010 and B107: high (B006 through the stash);
- false positives B073 to B075 and B102: no finding;
- false positive B103 (a push before the agent): medium, not no finding. Jenkins keeps the workspace between builds, so what the agent leaves there (a Git hook, `.git/config`) is in place for the push in the next build. It clears in a fresh pod or after a full clean;
- B080 still holds (a `ws()` on the same node is written by the same user);
- B077 and B078 (a container with `--network none`, `unshare --net`) are not cleared. A socket mounted into the container is a way out whatever the network. Whether `unshare` can be undone depends on what the user may run (`sudo`, a setuid helper), which the file does not show;
- B076 (a helper method's parameter) is #330's class.

The other rows are commands and values the checker does not recognise (#330).

The new review: 43 ways past, 7 false positives, 2 slow, 3 unsure and 60 held. The review-driven commit fixed 34 of the ways past, 2 of the false positives and both slow cases, each by class:
- **Docker run options** are read as docker splits them (grouped short options, attached values, `--mount`, `CAP_` names, `--device`, `--privileged=false`), not by a list of patterns.
- **Pod specs** are parsed as YAML, which also reads JSON. `podTemplate`'s own arguments count.
- **`agent none` on a stage** keeps the agent the steps run on.
- **`node(POD_LABEL)`** is the pod itself.
- **`retry` and `waitUntil`** repeat their body.
- **Persistent pod workspace volumes** are kept between pods and builds.
- **A partial `cleanWs`** is not a clean.
- **Label expressions** are compared by the labels they require.
- **Indexes** replace the scans that made a 1.4 KB file take 12.5 s.

Not fixed and listed in jenkins.md: matrix cells (R104), values that carry an agent's output (R029 to R031), `copyArtifacts` of the running build (R027), a later step on the host running what a no-network agent wrote (R076), what an agent leaves outside the workspace (R106), options in a variable (R078, R079), and a matrix axis as a label (R093). The case files are not kept in the repository; the tests hold the cases that were fixed.

| Id | Rule | What the file does | Result at `d9e268d` | Verdict | After the fixes (statuses of 002, 003, 006, 007) |
| --- | --- | --- | --- | --- | --- |
| R001 | 003 | top agent; Fix then Push | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R002 | 003 | `agent{node{label}}` | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R003 | 003 | `retry{push; claude}` | M | way past | fixed: high; 2:unknown 3:fail 6:n/a 7:fail |
| R004 | 003 | `for{push; claude}` | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R005 | 003 | `waitUntil{push; claude}` | M | way past | fixed: high; 2:unknown 3:fail 6:n/a 7:fail |
| R006 | 003 | matrix, no agent, then Push | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R007 | 003 | matrix agent, Fix+Push per cell | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R008 | 003 | stage docker, no reuseNode | U | held | 2:unknown 3:unknown 6:pass 7:fail |
| R009 | 003 | `reuseNode(true)` | H | held | 2:unknown 3:fail 6:pass 7:fail |
| R010 | 003 | `reuseNode 'true'` | H | held | 2:unknown 3:fail 6:pass 7:fail |
| R011 | 003 | `docker image:, reuseNode: true` | H | held | 2:unknown 3:fail 6:pass 7:fail |
| R012 | 003 | `reuseNode false` | U | held | 2:unknown 3:unknown 6:pass 7:fail |
| R013 | 003 | same customWorkspace, different labels | U | held | 2:unknown 3:unknown 6:n/a 7:fail |
| R014 | 003 | same `ws('/srv/ci/shared')`, different labels | P | way past (minor) | fixed: unknown; 2:unknown 3:unknown 6:n/a 7:fail |
| R015 | 003 | node in node, same label | U | held | 2:unknown 3:unknown 6:n/a 7:fail |
| R016 | 003 | `.inside` agent, push on host | H | held | 2:unknown 3:fail 6:pass 7:fail |
| R017 | 003 | withDockerContainer, then publish | H | held | 2:unknown 3:fail 6:pass 7:fail |
| R018 | 003 | podTemplate, two `container()` | H | held | 2:pass 3:fail 6:pass 7:fail |
| R019 | 003 | 2 pods, same PVC workspaceVolume | P | way past | fixed: unknown; 2:pass 3:unknown 6:pass 7:fail |
| R020 | 003 | k8s PVC workspace, push before agent | P | way past | fixed: medium; 2:pass 3:fail 6:pass 7:fail |
| R021 | 003 | podTemplate PVC, push before agent | P | way past | fixed: medium; 2:pass 3:fail 6:pass 7:fail |
| R022 | 003 | stage `agent none`, post push | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R023 | 003 | parallel own agents, failFast | U | held | 2:unknown 3:unknown 6:n/a 7:fail |
| R024 | 003 | `node` inside `script` | U | held | 2:unknown 3:unknown 6:n/a 7:fail |
| R025 | 003 | stash/unstash map forms | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R026 | 003 | stash name from a variable | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R027 | 003 | archiveArtifacts then copyArtifacts (same build) | P | way past (unsure) | not fixed: listed as a limit (copyArtifacts of the running build); 2:unknown 3:pass 6:n/a 7:fail |
| R028 | 003 | archiveArtifacts then `unarchive` | P | way past | fixed: high; 2:unknown 3:fail 6:n/a 7:fail |
| R029 | 003 | `env.NOTES=readFile` into a build job parameter | P | way past | not fixed: values, #330; 2:unknown 3:pass 6:n/a 7:fail |
| R030 | 003 | file text into a commit message, then push | P | way past (minor) | not fixed: values, #330; 2:unknown 3:pass 6:n/a 7:fail |
| R031 | 003 | claude stdout into a build job parameter | P | way past | not fixed: values, #330; 2:unknown 3:pass 6:n/a 7:fail |
| R032 | 003 | stash tree-a / unstash tree-b | P | held | 2:unknown 3:pass 6:n/a 7:fail |
| R033 | 003 | stash in a later parallel branch | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R034 | 003 | cleanWs INCLUDE pattern | P | way past | fixed: medium; 2:unknown 3:fail 6:n/a 7:fail |
| R035 | 003 | post always `cleanWs(cleanWhenSuccess:false)` | P | way past | fixed: medium; 2:unknown 3:fail 6:n/a 7:fail |
| R036 | 003 | cleanWs EXCLUDE `.git/**` | P | way past | fixed: medium; 2:unknown 3:fail 6:n/a 7:fail |
| R037 | 003 | deleteDir under `if` | M | held | 2:unknown 3:fail 6:n/a 7:fail |
| R038 | 003 | deleteDir in catchError | M | held | 2:unknown 3:fail 6:n/a 7:fail |
| R039 | 003 | `dir('build'){deleteDir}` | M | held | 2:unknown 3:fail 6:n/a 7:fail |
| R040 | 003 | post always `cleanWs()` | P | held | 2:unknown 3:pass 6:n/a 7:fail |
| R041 | 003 | cleanWs notFailBuild | P | held (unsure) | 2:unknown 3:pass 6:n/a 7:fail |
| R042 | 003 | cleanWs in a `when` stage | M | held | 2:unknown 3:fail 6:n/a 7:fail |
| R043 | 003 | publish; agent in post failure | M | held | 2:unknown 3:fail 6:n/a 7:fail |
| R044 | 003 | docker agent, push before agent | M | held | 2:pass 3:fail 6:pass 7:fail |
| R045 | 003 | method parameter carries the command | not applicable | way past (B057's class) | not fixed: #330; 2:unknown 3:n/a 6:n/a 7:n/a |
| R046 | 003 | two closures in one node | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R047 | 003 | two unknown-step bodies | U | held | 2:unknown 3:unknown 6:unknown 7:fail |
| R048 | 003 | closure variable in two nodes | U | held | 2:unknown 3:unknown 6:n/a 7:fail |
| R049 | 003 | library step body inside node | M | held | 2:unknown 3:fail 6:unknown 7:fail |
| R050 | 003 | two methods nothing calls | U | held | 2:unknown 3:unknown 6:n/a 7:fail |
| R051 | 003 | dir+timeout+retry after agent | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R052 | 003 | scripted parallel map | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R053 | 003 | effect closure called after agent | H | held | 2:unknown 3:fail 6:n/a 7:fail |
| R054 | 006/007 | `-v /var/run:/var/run` | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R055 | 006/007 | `--mount type=bind,source=/` | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R056 | 006/007 | `-v/var/run/docker.sock` (no space) | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R057 | 006/007 | `--volumes-from` | P/P | way past (unsure) | fixed: JEN-006 unknown, JEN-007 not cleared; 2:pass 3:pass 6:unknown 7:fail |
| R058 | 006/007 | `--cap-add CAP_SYS_ADMIN` | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R059 | 006/007 | `--cap-add SYS_MODULE` | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R060 | 006/007 | `--device /dev/sda` | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R061 | 006/007 | `label=disable`, `systempaths=unconfined` | P/P | unsure | fixed: JEN-006 high; 2:pass 3:pass 6:fail 7:fail |
| R062 | 006/007 | `--volume "/:/host"` | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R063 | 006 | containerd.sock mount | 006 P, 007 F | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R064 | 007 | `-v /tmp:/tmp` | P | unsure | JEN-007 not cleared; the finding names the mounted path; 2:pass 3:pass 6:pass 7:fail |
| R065 | 006/007 | `--userns host` | H/F | held | 2:pass 3:pass 6:fail 7:fail |
| R066 | 006 | `--privileged=false` | H | false positive | fixed: no finding; 2:pass 3:pass 6:pass 7:pass |
| R067 | 007 | `--net=none` | P | held | 2:pass 3:pass 6:pass 7:pass |
| R068 | 007 | `--network-alias` | P | held | 2:pass 3:pass 6:pass 7:pass |
| R069 | 007 | `--network container:x` | F | held | 2:pass 3:pass 6:pass 7:fail |
| R070 | 007 | `--add-host` | P | held | 2:pass 3:pass 6:pass 7:pass |
| R071 | 006/007 | `-itv docker.sock` | P/P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R072 | 006 | `--network "host"` | 006 P | way past | fixed; 2:pass 3:pass 6:fail 7:fail |
| R073 | 007 | `aiAgent` step under `--network none` | P | way past | fixed: JEN-007 not cleared; 2:pass 3:pass 6:pass 7:fail |
| R074 | 007 | `sandbox.inside` (library object) | U | held | 2:unknown 3:unknown 6:unknown 7:unknown |
| R075 | 007 | stage `agent none` under top-level docker `--network none` | F | false positive | fixed: pass; 2:pass 3:pass 6:pass 7:pass |
| R076 | 007 | gradlew on the host runs files the no-network agent wrote | P | way past (design) | not fixed: listed as a limit; 2:unknown 3:pass 6:pass 7:pass |
| R077 | 007 | AI step in stage post | P | held | 2:pass 3:pass 6:pass 7:pass |
| R078 | 007 | args variable holding `'--network none'` | F | false positive (minor) | not fixed: computed options stay a finding; 2:pass 3:pass 6:unknown 7:fail |
| R079 | 007 | `"--network ${NET}"`, `NET='none'` | F | false positive (minor) | not fixed: computed options stay a finding; 2:pass 3:pass 6:unknown 7:fail |
| R080 | 007 | build `--network host`, run `none` | P | held | 2:pass 3:pass 6:pass 7:pass |
| R081 | 007 | withDockerContainer `args:` | P | held | 2:pass 3:pass 6:pass 7:pass |
| R082 | 007 | `withRun` (body runs on host) | F | held | 2:unknown 3:pass 6:n/a 7:fail |
| R083 | 006 | podTemplate+node(POD_LABEL), token mounted | P | way past | fixed: high; 2:pass 3:pass 6:fail 7:fail |
| R084 | 006 | declarative k8s token (control) | H | held | 2:pass 3:pass 6:fail 7:fail |
| R085 | 006 | privileged; AI in `agent none` stage | M | way past | fixed: high; 2:pass 3:pass 6:fail 7:fail |
| R086 | 006 | R085 without `agent none` | H | held | 2:pass 3:pass 6:fail 7:fail |
| R087 | 006 | `hostPathVolume` docker.sock | P | way past | fixed: high; 2:pass 3:pass 6:fail 7:fail |
| R088 | 006 | `containerTemplate(privileged:true)` | P | way past | fixed: high; 2:pass 3:pass 6:fail 7:fail |
| R089 | 006 | JSON spec: privileged, automount false | H for the token | way past | fixed: privileged found, token not; 2:pass 3:pass 6:fail 7:fail |
| R090 | 006 | JSON spec privileged, mvn build | P | way past | fixed: high; 2:pass 3:n/a 6:fail 7:n/a |
| R091 | 002 | `node('!windows')` | label U | way past | fixed: the unknown says the expression requires no label; 2:unknown 3:pass 6:n/a 7:fail |
| R092 | 002 | `def where='built-in'; node(where)` | floating U | way past | fixed: high; 2:fail 3:pass 6:n/a 7:fail |
| R093 | 002 | matrix axis value `built-in` | floating U | way past | not fixed: matrix axis values stay an unknown; 2:unknown 3:pass 6:n/a 7:fail |
| R094 | 002 | `linux -> built-in` | H | held | 2:fail 3:n/a 6:n/a 7:n/a |
| R095 | 002 | `Built-In` | H | false positive (unsure) | unchanged (labels compared without case, as before); 2:fail 3:n/a 6:n/a 7:n/a |
| R096 | 002 | `linux \ | \ | !linux` | not fixed: a tautology reads as the label linux; 2:unknown 3:pass 6:n/a 7:fail |
| R097 | 002 | `!(!master)` | H | held | 2:fail 3:n/a 6:n/a 7:n/a |
| R098 | 002 | `built-in&&linux` | H | held | 2:fail 3:n/a 6:n/a 7:n/a |
| R099 | 002 | `'built-in'` in single quotes | U | held (unsure) | 2:unknown 3:n/a 6:n/a 7:n/a |
| R100 | 002 | built-in top agent; AI in `agent none` stage | M | way past | fixed: high; 2:fail 3:pass 6:n/a 7:fail |
| R101 | 002 | `linux` vs `(linux)` | U | way past (minor) | fixed: unknown; 2:unknown 3:unknown 6:n/a 7:fail |
| R102 | 002 | release stage without `when` | U (+ JEN-001 medium) | unsure (design) | unchanged; 2:unknown 3:unknown 6:n/a 7:fail |
| R103 | 002 | scripted shared label | M | held | 2:fail 3:unknown 6:n/a 7:fail |
| R104 | 003 | matrix agent: Fix cell a, Push cell b | H | false positive | not fixed: listed as a limit; 2:unknown 3:fail 6:n/a 7:fail |
| R105 | 003 | per-build `ws()` path | M | held (unsure) | 2:unknown 3:fail 6:n/a 7:fail |
| R106 | 003 | post always `cleanWs`; agent writes `$HOME` | P | way past (design) | not fixed: listed as a limit; 2:unknown 3:pass 6:n/a 7:fail |
| R107 | 003 | `linux && docker` vs `linux` | P | way past | fixed: unknown; 2:unknown 3:unknown 6:n/a 7:fail |
| R108 | 003 | `linux` vs `' linux '` | P | way past (minor) | fixed: unknown; 2:unknown 3:unknown 6:n/a 7:fail |
| R109 | 003 | dockerfile reuseNode stage post publish | H | held | 2:unknown 3:fail 6:pass 7:fail |
| R110 | 003 | labels from variables | U | held | 2:unknown 3:pass 6:n/a 7:fail |
| R111 | 007 | mount path containing "socks5" | F | false positive (minor) | JEN-007 not cleared; the finding names the mounted path; 2:pass 3:pass 6:pass 7:fail |
| R112 | 007 | nested stages+post in a no-network container | P | held | 2:pass 3:pass 6:pass 7:pass |
| R113 | 003 | 150 pushes + 150 agent steps | M, 0.27 s | held | 2:unknown 3:fail 6:n/a 7:fail |
| R114 | 003 | 400+400 steps, 30 KB | 3.99 s | slow | fixed: 0.22 s; 2:unknown 3:fail 6:n/a 7:fail |
| R115 | 003 | 1.4 KB file, methods expanded 60 times | 12.5 s | slow | fixed: 0.34 s; 2:unknown 3:fail 6:n/a 7:fail |

### Second pass, on `3d797e0`

The same reviewer re-ran R001 to R115 on the fixes and wrote 62 more. No earlier case got worse. It confirmed every claimed fix but one: R019, two pods on one named workspace claim, share its directory for certain, so it is now high, not unknown. It also asked for R101 to pair in OBAAF-JEN-002, which it now does. The new attempts: 26 ways past (15 of them blocking, 5 of those resting on behaviour the reviewer was not sure of), 9 false positives, 1 slow, 25 held. The third commit of #331 fixes 24 of the ways past, 8 of the false positives and the slow case, by class. Each is a test in `SecondReviewTest`. The options are read both as a shell and as blanks split them. Docker's booleans, path cleaning and `--mount` CSV are followed. System folders count whole and not their subfolders. Pod specs read string booleans and projected tokens and report what they cannot read. A computed label in a pod template is the pod. Label expressions are parsed with Jenkins's operators. `WsCleanup` and `WipeWorkspace` clean.

| Id | Rule | What the file does | Result at `3d797e0` | Verdict | Now |
| --- | --- | --- | --- | --- | --- |
| R116 | 006/007 | `--network none --privileged=t` | P/P | blocking way past | fixed: docker's booleans |
| R117 | 006 | `-v //var/run://var/run` | 006 P | blocking way past | fixed: paths cleaned |
| R118 | 006/007 | `--mount type=bind,Source=/var/run` | P/P | blocking way past | fixed: keys in any case |
| R119 | 006/007 | `--mount 'type=bind,"src=/var/run",…'` | P/P | blocking way past | fixed: CSV fields |
| R120 | 006 | `--mount …,src=../../../../../..` | 006 P | blocking way past (unsure) | fixed: a relative source with `..` counts |
| R121 | 006/007 | `--use-api-socket` | P/P | blocking way past | fixed |
| R122 | 006/007 | `--device-cgroup-rule='b *:* rwm'` | P/P | blocking way past | fixed |
| R123 | 006/007 | `-e 'A\' -e 'B --privileged -e 'C=1` | P/P | blocking way past (unsure) | fixed: both readings count, a backslash is an unknown |
| R124 | 006/007 | `-e X=\ --privileged` | P/P | way past (unsure) | fixed: same |
| R125 | 006/007 | `-v \\.\pipe\docker_engine:…` | P/P | way past | fixed |
| R126 | 006/007 | `-v C:\:C:\host` | P/P | way past | fixed |
| R127 | 006 | `-v /var/run/docker.sock` (one field) | high | false positive | fixed: an anonymous volume |
| R128–R130, R132, R133 | 006 | `/run/`, `type=BIND`, `cap_dac_read_search`, `-v=`, `/run/../` | high | held | held |
| R131 | 006 | `--security-opt label:type:spc_t` | P | unsure | now high (`label=type…` counts) |
| R134 | 006 | `-v /root/.m2:/root/.m2` (Jenkins's Maven tutorial) | high | blocking false positive | fixed: a folder inside a system folder is not host access |
| R135 | 006 | read-only `/etc/localtime`, `/etc/passwd`, `/etc/group` | high | blocking false positive | fixed |
| R136 | 006 | `$HOME/.m2`, `/home/jenkins/.gradle` | P | held | held |
| R137 | 006 | `-v /dev/shm:/dev/shm` | high | false positive | fixed |
| R138 | 003 | `step([$class:'WsCleanup'])` before push | medium | false positive (earlier) | fixed |
| R139 | 003 | checkout with `WipeWorkspace` | medium | false positive (earlier) | fixed |
| R140, R142 | 003 | `cleanWs([cleanWhenSuccess:false])`; all `cleanWhen*` true | M / P | held | held |
| R141 | 003 | `cleanWs(patterns: [])` | medium | false positive (minor) | not fixed: any `patterns` is read as partial |
| R143 | 006 | `privileged: "true"` (string) | P | way past (unsure) | fixed: string booleans count |
| R144 | 006 | privileged pod past a 20,000-node walk (aliases) | P | blocking way past | fixed: aliases are walked within a larger cap, and a spec too large is an unknown |
| R145 | 006 | `hostUsers: false` | high | blocking false positive | fixed: `hostUsers` is not read |
| R146 | 006 | automount false, projected `serviceAccountToken` | P | way past | fixed |
| R147 | 006 | a second YAML document sets automount false | P | way past (unsure) | fixed: only the first document counts for the token, and more than one is an unknown |
| R148 | 006 | custom tag forces the fallback; JSON-form privileged | wrong reason | way past (unsure) | fixed: the fallback reads JSON forms and says the spec was not read |
| R149, R150 | 006 | merge key; privileged initContainer | high | held | held |
| R151 | 006 | an env value that mentions `docker.sock` | high | false positive | fixed: only a hostPath's path counts |
| R152 | 006 | capabilities `add:` as one string | P | held | held |
| R153 | 002 | `docker -> linux` | label unknown | way past | fixed: an expression that requires no label selects like `agent any` |
| R154 | 003 | `sandbox -> gpu` vs `trusted` | P | way past | fixed: unknown |
| R155 | 003 | `linux <-> sandbox` vs `trusted` | P | way past (minor) | fixed: unknown |
| R156 | 002 | quoted `"built-in && x"` | unknown | held | held |
| R157 | 006 | `podTemplate(label: label) { node(label) }` | P | blocking way past | fixed: a computed label in a pod template is the pod |
| R158 | 006 | `node("${POD_LABEL}")` | P | blocking way past | fixed |
| R159 | 006 | `hostPathWorkspaceVolume(hostPath: '/')` | P | blocking way past | fixed |
| R160 | 003 | YAML volume named `workspace-volume` on a claim | P | way past (unsure) | not fixed: listed in jenkins.md |
| R161, R162 | 003 | `$class` map form; `dynamicPVC` | M / P | held | held |
| R163 | 006 | `containerTemplate(privileged: 'true')` | P | way past (unsure) | fixed |
| R164 | 006 | `volumes:` list held in a variable | unknown | held | held |
| R165–R168 | 003 | `options { retry }` at pipeline and stage level; retry in a method; with conditions | H, M, H, H | held | held |
| R169 | 002 | `environment { RUN_ON = 'built-in' }` + `label "${env.RUN_ON}"` | floating unknown | way past (unsure) | not fixed: listed in jenkins.md |
| R170 | 002 | `@Field final String WHERE='master'` | high | held | held |
| R171 | 002 | AI on `linux && docker`, publish on `linux` | unknown | way past (minor) | fixed: labels that require a common one pair |
| R172–R174 | all | ordinary podTemplate; default pod; `ws()` paths on different labels | clean | held | held |
| R175, R176 | 006/007 | 3,000-deep YAML; 4,000 `-v` | — | held | held |
| R177 | 006 | six 1,200-deep pod specs, 15 KB | 5.0 s | slow | fixed: 0.01 s, an unknown |

### Third pass, on `0521213`

The reviewer re-ran R001 to R177; no case got worse, and it confirmed the second pass's fixes. 35 new attempts: 11 ways past, 5 false positives, 19 held. The fourth commit of #331 fixes these:

| Id | Rule | What the file does | Result at `0521213` | Verdict | Now |
| --- | --- | --- | --- | --- | --- |
| R180 | 006 | `--label description='mounts -v /var/run:/var/run …'` | high | false positive (contrived) | not fixed: the blank-split reading, listed in jenkins.md |
| R183 | 006 | `/sys/fs/cgroup:ro` | high | false positive (unsure) | fixed: read-only cgroups are ordinary |
| R184 | 006 | `/var/lib/jenkins/.m2:/root/.m2` | high | false positive | fixed: only the controller's secrets, jobs, nodes, users and workspaces count inside its home |
| R185 | 006 | `-v /home/jenkins:/home/jenkins` with an agent | pass | way past | fixed: a user's whole home counts |
| R186 | 006/007 | `--network none -v /run/user/1000:…` | 006 pass | way past | fixed: rootless Docker's socket folder |
| R187 | 006 | `/root/.ssh:ro` | pass | way past (unsure of scope) | fixed: a home's credential folders count |
| R188 | 006 | `/etc:/host/etc:ro` | pass | way past (minor) | fixed: read-only is ordinary only for program folders |
| R191 | 002 | `node('built-in && !master')`, agent step | unknown | blocking way past | fixed: the built-in node carries one of its two labels |
| R192 | 002 | 200 nested brackets around `built-in` | floating unknown | way past (minor) | not fixed: an expression too deep to read is an unknown |
| R200 | 003 | same claim, mounted read-only by the agent's pod | high | false positive (minor) | not fixed: listed in jenkins.md |
| R201 | 003 | NFS `/exports/ws` and `/exports/ws/`, one server | pass | way past (minor) | fixed: paths cleaned |
| R202 | 003 | the same NFS path on two servers | high | false positive | fixed: the server is part of the key |
| R204 | 003 | `hostPathWorkspaceVolume` `/srv/ws` and `/srv/ws/` | pass | way past (minor) | fixed: unknown |
| R205 | 002/003 | `node(params.STATIC_AGENT)` inside a pod template | 003 pass | way past | fixed: only `POD_LABEL` or the template's label variable is the pod |
| R206 | 002 | `node(params.TARGET ?: 'built-in')` inside a pod template | pass | blocking way past | fixed: the floating unknown is back |
| R208 | 006 | `privileged: 1` | pass | way past (unsure) | fixed: 1 counts as true |

### Fourth pass, on `6614662`

The reviewer re-ran R001 to R212: only the cases the third commit names changed, as intended. 18 new attempts on that commit's diff: 6 ways past (3 blocking), 1 false positive, 1 unsure, 10 held. The fifth commit of #331 fixes these:

| Id | What the file does | Result at `6614662` | Verdict | Now |
| --- | --- | --- | --- | --- |
| R217 | `podTemplate(label: "ci-${env.BUILD_NUMBER}")` and `node("ci-${env.BUILD_NUMBER}")` | 006 pass | blocking way past | fixed: the same label text is the pod |
| R218 | `def label = 'ci-pod'; podTemplate(label: label)` and `node('ci-pod')` | 006 pass | way past | fixed: the literal the variable holds |
| R222 | `/var/lib/jenkins/init.groovy.d`, `/plugins`, read-write | pass | blocking way past | fixed: the controller's home counts but its caches |
| R223 | `-v /var/jenkins_home:/jh` | pass | blocking way past | fixed |
| R224 | `/home/jenkins/agent` | pass | way past | fixed |
| R225 | `/home/jenkins/.ssh/known_hosts:ro` | high | false positive | fixed |
| R226 | `~/.netrc`, `~/.git-credentials` | pass | way past | fixed: credential files |
| R227 | `/var/lib/jenkins/secret.key:ro` | pass | way past (minor) | fixed |
| R229 | NFS servers `nfs1.example` and `NFS1.example` | pass | way past (minor) | fixed: server names without case |
| R230 | `privileged: 2` | pass | unsure | now high: any number but 0 counts |
| R213–R216, R219–R221, R228 | `master`, `!built-in \|\| master`, `master && !built-in`, `!(built-in -> linux)`, dotted homes, a credential folder at depth, `secrets/../.m2`, NFS without a server | as expected | held | held |

### Fifth pass, on `5f44ddc`

The reviewer re-ran R001 to R230: only the cases the fourth commit names changed. Of 8 new attempts, 6 held. One was a way past: R234, the Git plugin's mirrors under `/var/lib/jenkins/caches`, which the controller fetches into, were taken for a build cache. One was a false positive: R235, read-only `/home/jenkins/agent/tools`. Both are fixed in the sixth commit of #331: `caches` no longer counts as a build cache, and an agent's root is read like the controller's home. Not changed: R232, a read-only `~/.npmrc`, is reported as the host's credentials, because the token in it is exposed. R238, a `node('linux')` inside `podTemplate(label: 'linux')`, is read as the pod and is listed in jenkins.md. The reviewer re-ran R001 to R238 on the sixth commit: only R234 and R235 changed, and it found nothing blocking. Its two remaining points are listed in jenkins.md: writable `tools`, and a job named `tools`.

CI then caught what the review had not timed: OBAAF-JEN-002's shared-label pairing compared every allocation with every other, so 4,000 `node()` blocks on one label took 4.9 s here (0.46 s on `flagship`), past CI's 10 s limit on Python 3.10. The pairing is now indexed, the machine question asks one agent step per workspace within a budget, and label requirements are cached. The reviewer re-ran R001 to R245 on each change. R239 to R243 check that the indexed pairing finds what the old loop found, and they all held. R244 and R245, 4,000-allocation files, now take under 2 s.

### Reviewer B's attempts (2026-11-17)

Reviewer B's 111 attempts on OBAAF-JEN-003 and 007, at `9b806db`: 71 ways past, 14 false positives, 3 slow cases, 23 held. The case files themselves were not kept, so each row says what the file did. What the 2026-11-20 work fixed is listed above.

| ID | Rule | Case | At `9b806db` | Verdict |
| --- | --- | --- | --- | --- |
| B001 | both | control: claude -p and git push in one stage | exit=1 time=0.31s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B002 | JEN-003 | top-level agent any; stage Fix runs claude -p, next stage Push runs git push in the same workspace | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B003 | JEN-003 | agent stage, then pipeline-level post { success { git push } } | exit=1 time=0.30s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B004 | JEN-003 | parent stage with nested sequential stages Fix (claude) and Ship (git push) | exit=1 time=0.28s; JEN-003 pass; JEN-007 fail low@8[Maintain > Fix] | way past |
| B005 | JEN-003 | scripted node { stage Fix claude; stage Push git push } | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B006 | JEN-003 | agent stage on label sandbox stashes the tree; stage on label trusted unstashes and pushes | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@7[Fix] | way past |
| B007 | JEN-003 | docker agent with reuseNode true runs npx claude-code; next stage npm publish in the same workspace | exit=1 time=0.28s; JEN-003 pass; JEN-007 fail low@12[Fix] | way past |
| B008 | JEN-003 | nested stage Fix runs claude; parent stage's post { success } pushes | exit=1 time=0.28s; JEN-003 pass; JEN-007 fail low@8[Maintain > Fix] | way past |
| B009 | JEN-003 | scripted: claude -p outside any stage in node{}, git push in a stage of the same node | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@3[pipeline] | way past |
| B010 | JEN-003 | agent writes NOTES.md; next stage passes it to build job: 'release' | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B011 | JEN-003 | bash -c "git commit && git push" (push after && inside quotes) | exit=1 time=0.30s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B012 | JEN-003 | /usr/bin/git push in the agent stage | exit=1 time=0.27s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B013 | JEN-003 | git -c "user.name=CI Bot" push (option value with a space) | exit=1 time=0.25s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B014 | JEN-003 | git --git-dir .git --work-tree . push (option value as separate word) | exit=1 time=0.28s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B015 | JEN-003 | git \ newline push (shell line continuation) | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B016 | JEN-003 | def pushCmd = 'git push origin HEAD:main'; sh pushCmd | exit=1 time=0.30s; JEN-003 pass; JEN-007 fail low@7[Fix] | way past |
| B017 | JEN-003 | helper def gitCmd(String args) { sh "git ${args}" }; gitCmd('push origin HEAD:main') | exit=1 time=0.28s; JEN-003 pass; JEN-007 fail low@9[Fix] | way past |
| B018 | JEN-003 | sh './ci/push-branch.sh'; the repo script runs git push | exit=1 time=0.27s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B019 | JEN-003 | sh 'make push-fix'; the Makefile target runs git push | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B020 | JEN-003 | git subtree push --prefix docs origin gh-pages | exit=1 time=0.28s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B021 | JEN-003 | gh api -X PUT repos/o/r/contents/<path> writes a commit without git push | exit=1 time=0.25s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B022 | JEN-003 | gh api -X PUT repos/o/r/pulls/N/merge merges a PR | exit=1 time=0.25s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B023 | JEN-003 | bat: "C:\Program Files\Git\cmd\git.exe" push | exit=1 time=0.25s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B024 | JEN-003 | glab mr merge (GitLab analogue of gh pr merge) | exit=1 time=0.25s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B025 | JEN-003 | git push --dry-run only (nothing is pushed) | exit=1 time=0.26s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | false positive |
| B026 | JEN-003 | echo "... do not git push from CI" (text only) | exit=1 time=0.26s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | false positive |
| B027 | JEN-003 | git commit --amend && git -C . push --force | exit=1 time=0.30s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B028 | JEN-003 | sudo -u release sh -c "git push origin HEAD:main" (quote right before git) | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B029 | JEN-003 | build job: "deploy-${env.BRANCH_NAME}" (computed job) | exit=1 time=0.27s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B030 | JEN-003 | triggerRemoteJob (Parameterized Remote Trigger plugin) | exit=1 time=0.28s; JEN-003 unknown unknown@7: calls 1 step(s) that are not built into Jenkins or defined in this fil; JE | held |
| B031 | JEN-003 | httpRequest POST ${JENKINS_URL}job/deploy/buildWithParameters (known step, no unknown) | exit=1 time=0.31s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B032 | JEN-003 | curl -X POST $JENKINS_URL/job/deploy/build | exit=1 time=0.30s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B033 | JEN-003 | java -jar jenkins-cli.jar build deploy | exit=1 time=0.33s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B034 | JEN-003 | mvn compile jib:build (builds and pushes an image) | exit=1 time=0.27s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B035 | JEN-003 | /kaniko/executor --destination registry/app:latest | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B036 | JEN-003 | buildah push registry/app:latest | exit=1 time=0.27s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B037 | JEN-003 | npm run release; package.json script runs npm publish | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B038 | JEN-003 | docker \ newline push (line continuation) | exit=1 time=0.27s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B039 | JEN-003 | bash -c "docker push registry/app:latest" (quote right before docker) | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B040 | JEN-003 | docker.build(...) then img.push() inside withRegistry | exit=1 time=0.26s; JEN-003 fail high@10[Fix]; JEN-007 fail low@6[Fix] | held |
| B041 | JEN-003 | step([$class: 'S3BucketPublisher', ...]) uploads to S3 | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B042 | JEN-003 | python3 -m twine upload dist/* | exit=1 time=0.33s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B043 | both | $(command -v claude) -p ... | exit=1 time=0.32s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B044 | both | environment { AGENT_BIN = 'claude' }; sh '$AGENT_BIN -p ...' | exit=1 time=0.27s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B045 | both | bat 'claude.cmd -p ...' (npm shim on Windows) | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B046 | both | bat 'Claude -p ...' (Windows command names are case-insensitive) | exit=1 time=0.32s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B047 | both | claude --append-system-prompt "Be terse; never ask" -p ... (';' inside a quoted option before -p) | exit=1 time=0.37s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B048 | both | npx -y opencode-ai@0.15.0 run "..." (package in agent_packages) | exit=1 time=0.32s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B049 | both | codex e --full-auto "..." | exit=1 time=0.30s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B050 | both | cat .ci/prompt.md \| gemini --yolo (no -p) | exit=1 time=0.28s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B051 | both | python3 ci/autofix.py; subprocess.run(["claude", "-p", ...]) | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B052 | both | dir('ci') { sh './autofix.sh' } (script read from repo root, not ci/) | exit=1 time=0.30s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B053 | both | sh 'cd tools && ./autofix.sh' | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B054 | both | writeFile file: 'autofix.sh', text: 'claude -p ...'; sh 'sh autofix.sh' | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B055 | both | sh 'make autofix'; Makefile runs claude -p | exit=1 time=0.30s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B056 | both | sh 'npm run autofix'; package.json script runs claude -p | exit=1 time=0.31s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B057 | both | def run(String cmd) { sh cmd }; run('claude -p ...') in Fix, run('make test') later | exit=1 time=0.32s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B058 | both | def cmd = 'claude -p ...'; sh cmd; then cmd = 'echo done' | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B059 | both | def agentCmd = ['claude','-p',...].join(' '); sh agentCmd | exit=1 time=0.29s; JEN-003 unknown unknown@7: calls 1 step(s) that are not built into Jenkins or defined in this fil; JE | held |
| B060 | both | sh 'cl\u0061ude -p ...' (unicode escape) | exit=1 time=0.27s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B061 | both | powershell Start-Process -FilePath claude -ArgumentList @('-p', ...) | exit=1 time=0.34s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B062 | both | repo script ci/autofix.sh: claude \ newline --model x \ newline -p | exit=1 time=0.31s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B063 | both | ci/maintain.sh calls ./ci/autofix.sh, which runs claude -p (two levels) | exit=1 time=0.34s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B064 | both | node_modules/.bin/claude -p | exit=1 time=0.30s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B065 | both | aiAgent step | exit=1 time=0.30s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B066 | both | withEnv(['AGENT=claude']) { sh '${AGENT} -p ...' } | exit=1 time=0.32s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B067 | both | npx -y @qodo/command@0.20.0 ... (package in agent_packages; flags from knowledge) | exit=1 time=0.31s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B068 | both | shared-library step runClaude(...) | exit=1 time=0.35s; JEN-003 unknown unknown@7: calls 1 step(s) that are not built into Jenkins or defined in this fil; JE | held |
| B069 | both | load 'ci/helpers.groovy' then helpers.autofix() | exit=1 time=0.29s; JEN-003 unknown unknown@7: load(): Groovy loaded at run time is not analyzed]; JEN-007 unknown unknow | held |
| B070 | both | docker run -v $PWD:/work image claude -p ... | exit=1 time=0.27s; JEN-003 fail high@7[Fix]; JEN-007 fail low@6[Fix] | held |
| B071 | both | echo "Tip: ... claude -p ..." plus a real git push | exit=1 time=0.31s; JEN-003 fail high@7[Docs]; JEN-007 fail low@6[Docs] | false positive |
| B072 | JEN-007 | npm uninstall -g @anthropic-ai/claude-code only | exit=1 time=0.31s; JEN-003 pass; JEN-007 fail low@6[Clean image] | false positive |
| B073 | JEN-003 | scripted: two node blocks on different labels, stages with computed names (both read as '?') | exit=1 time=0.29s; JEN-003 fail high@13[?]; JEN-007 fail low@6[?] | false positive |
| B074 | JEN-003 | scripted: two stages named 'Work' in node('sandbox') and node('trusted'); push of another repo on trusted | exit=1 time=0.29s; JEN-003 fail high@11[Work]; JEN-007 fail low@4[Work] | false positive |
| B075 | JEN-003 | one scripted stage holding node('sandbox') { claude } and node('trusted') { push of another repo } | exit=1 time=0.29s; JEN-003 fail high@9[Nightly]; JEN-007 fail low@4[Nightly] | false positive |
| B076 | JEN-007 | def run(cmd){sh cmd}; stage Test run('make test'), stage Review run('claude -p ...'): Test flagged | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@2[Test],low@2[Review] | false positive |
| B077 | JEN-007 | docker agent args '--network none' plus a unix socket to a local model | exit=1 time=0.32s; JEN-003 pass; JEN-007 fail low@11[Review] | false positive |
| B078 | JEN-007 | unshare --net --map-root-user claude -p ... | exit=1 time=0.31s; JEN-003 pass; JEN-007 fail low@6[Review] | false positive |
| B079 | both | only a shell comment mentions claude -p and git push; runs make lint | exit=1 time=0.30s; JEN-003 fail high@6[Check]; JEN-007 fail low@6[Check] | false positive |
| B080 | JEN-003 | claude in the workspace; ws("${WORKSPACE}@docs") checks out another repo and pushes | exit=1 time=0.27s; JEN-003 fail high@9[Review]; JEN-007 fail low@6[Review] | held |
| B081 | JEN-007 | declarative parallel stages Claude and Codex | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@8[Review > Claude],low@12[Review > Codex] | held |
| B082 | both | matrix axis AGENT_CMD values 'claude -p','gemini -p'; sh "${AGENT_CMD} ..." | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B083 | JEN-007 | environment OBAAF_EGRESS set | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@8[Review] | held |
| B084 | both | agent and push in a stage's post { failure } | exit=1 time=0.26s; JEN-003 fail high@9[Test]; JEN-007 fail low@8[Test > post failure] | held |
| B085 | JEN-007 | scripted parallel map of two agent closures in one stage | exit=1 time=0.26s; JEN-003 pass; JEN-007 fail low@5[Review] | held |
| B086 | JEN-007 | matrix of 3 cells running claude | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@12[Review > Run] | held |
| B087 | both | def s='ab'; s = "${s}" x250; sh "echo ${s}": 2 lines, 1 KB | exit=1 time=7.08s; JEN-003 not applicable; JEN-007 not applicable | slow |
| B088 | both | gemini --yolo "..." > gemini.log (positional prompt, output redirected) | exit=1 time=0.34s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B089 | both | bash array args=(... -p "..."); claude "${args[@]}" | exit=1 time=0.32s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B090 | both | \claude -p ... (backslash skips shell aliases) | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B091 | JEN-003 | sshagent(deploy key) { claude -p "... commit and push it to main" --dangerously-skip-permissions } | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@7[Fix] | way past |
| B092 | JEN-003 | docker compose build && docker compose push | exit=1 time=0.30s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B093 | JEN-003 | curl -X POST -F raw.asset1=@dist/app.tar.gz to the Nexus components API | exit=1 time=0.29s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B094 | JEN-003 | gcloud builds submit --tag gcr.io/acme/app:latest | exit=1 time=0.30s; JEN-003 pass; JEN-007 fail low@6[Fix] | way past |
| B095 | both | def agentCmd() { return 'claude -p' }; sh "${agentCmd()} '...'" | exit=1 time=0.30s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B096 | both | environment AGENT_BIN='claude'; sh "${env.AGENT_BIN} -p ..." | exit=1 time=0.32s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B097 | both | control: environment AGENT_BIN='claude'; sh '${AGENT_BIN} -p ...' | exit=1 time=0.26s; JEN-003 fail high@10[Fix]; JEN-007 fail low@9[Fix] | held |
| B098 | both | def bin = env.CLAUDE_BIN ?: 'claude'; sh "${bin} -p ..." | exit=1 time=0.27s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B099 | both | sh readFile('ci/autofix.txt') and sh readFile('ci/push.txt') | exit=1 time=0.26s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B100 | both | control: docker.image.inside > withCredentials > timeout > retry > sh(label:, returnStdout:, script: npx claude-code -p), then sshagent push | exit=1 time=0.28s; JEN-003 fail high@21[Fix]; JEN-007 fail low@11[Fix] | held |
| B101 | both | docker build --build-arg CLI_PACKAGE=@anthropic-ai/claude-code@1.0.0 ... && docker push (agent never run) | exit=1 time=0.29s; JEN-003 fail high@7[Tools image]; JEN-007 fail low@6[Tools image] | false positive |
| B102 | JEN-003 | top-level closures review{claude} and release{git push} called in stages on labels sandbox and trusted | exit=1 time=0.28s; JEN-003 fail high@6[pipeline]; JEN-007 fail low@2[pipeline],low@2[Review] | false positive |
| B103 | JEN-003 | git push to a mirror, then claude -p summarises to a file (push runs before the agent) | exit=1 time=0.30s; JEN-003 fail high@6[Mirror]; JEN-007 fail low@7[Mirror] | false positive |
| B104 | both | 12 levels of methods each calling the next twice (budget test) | exit=1 time=0.67s; JEN-003 unknown unknown@24: call to f0() not expanded (recursion or too many calls); line 25: call; J | held |
| B105 | other (JEN-011) | 2500 sha256sum -c steps and 2500 aws s3 cp steps in one stage, 216 KB | exit=1 time=2.60s; JEN-003 not applicable; JEN-007 not applicable | slow |
| B106 | other (JEN-011) | 5000 sha256sum -c and 5000 aws s3 cp steps, 433 KB | exit=1 time=9.14s; JEN-003 not applicable; JEN-007 not applicable | slow |
| B107 | JEN-003 | script { stage('Agent') { claude } ; git push } inside declarative stage Fix | exit=1 time=0.28s; JEN-003 pass; JEN-007 fail low@8[Fix > Agent] | way past |
| B108 | both | def autofixScript = './ci/autofix.sh'; sh autofixScript | exit=1 time=0.28s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B109 | both | sh '"$WORKSPACE/ci/autofix.sh"' | exit=1 time=0.30s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B110 | both | sh './ci/autofix' (script without .sh suffix) | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |
| B111 | both | def agentCmd = 'claude' + ' -p ...'; sh agentCmd | exit=1 time=0.29s; JEN-003 not applicable; JEN-007 not applicable | way past |

## 2d.2l: release approvals

Rule: OBAAF-JEN-005, release without an approval by a named person. Reviewer: one Opus 5.5 sub-agent that did not write the rule, given the code, the rule's text and what the Pipeline: Input Step plugin documents (an abort, or a timeout around the step, throws and stops the build unless caught; `submitter` goes through `Util.fixEmptyAndTrim`; a Declarative stage asks for its `input` before its `when` unless `beforeInput true`). 2026-11-21, run `ptarmigan`. Every attempt is a case in `tests/test_jenkins_approvals.py`, with what the rule said before the slice and what it says now.

**Result before the fixes:** 140 attempts (155 fixture files, some duplicates or invalid): 47 ways past, 9 false positives, 11 answers weaker than due, 6 over-cautious, 67 held. Before the slice the rule asked only whether some `input` step came before the first publish.

| Class | Ways past and false positives | What changed |
| --- | --- | --- |
| The input's abort does not stop the publish | 7 ways past: `try { input } catch (e) {}`, `catchError`, `warnError`, `timeout` in a catch, the same in Declarative `script` blocks | An input counts only when its failure stops the build, as a check does for OBAAF-JEN-011 and 012; an input inside the same `catchError` or `try` block as the publish, before it, still counts |
| The input may be skipped | 17 ways past: a `when` with `beforeInput true` or on the stage's `steps`, Scripted `if`, `else`, `switch`, loops that may run zero times (`for`, `.each`, `.times`), `&&`, `||` and `?:`, a `post { failure }` input, a method nothing calls, a closure never called | Every condition on the input must also guard the publish. Iteration methods, short-circuit operators and `?:` are now conditions in the model, as `for` was. Steps read where a closure or an uncalled method is written are marked and never count as an approval |
| Parallel branches, order, second publishes | 10 ways past, 3 false positives: an input in a sibling parallel branch, only the first publish tested, a publish in `post { always \| aborted \| failure }` or a `catch` block, a closure assigned before and called after | Every publishing stage is tested. No input gates a publish in a failure path. A publish read only where its closure is written is "cannot tell" unless it is also read where it is called |
| Submitter values | 10 ways past, 11 weaker: `''`, blank, `null`, `'\u0020'`, the Declarative `submitter ''` or `null`, a repeated key, a later spread, the group `authenticated` | Blank, empty and `null` are no submitter (a finding), trimmed as Java's `String.trim()` does; the last key wins; a spread or a map variable is "cannot tell"; a map given as the only argument is read; `authenticated` is a finding. The lexer now decodes `\uXXXX` in strings |
| Spellings | 4 false positives: `input(m)`, `input([..])`, `input(*: m)`, a labelled statement | Read as above; a file part of which was not read gives "cannot tell" for a missing approval, not a finding |
| Publishes the rule does not see | 3: a command in a variable, `gradlew jib`, `buildah push` | Not changed: publish detection is OBAAF-JEN-012's reader, left to 2d.2 |
| Crashes and slow inputs | none; 2 false positives where a call was not expanded | "Cannot tell", as above |

**Stated limits** (each a case in `LIMITS`): an input whose abort sets a flag that guards the publish does not count, nor one in a Scripted `finally` block, nor one inside `catchError(catchInterruptions: false)` (only the innermost catching block is recorded); all three fail closed, as a finding. A submitter or a map held in a variable, a method parameter or a concatenation of literals is "cannot tell". A shared-library step that might approve is not read; the file-wide note says so. Not verified on a live Jenkins: that `authenticated` lets every signed-in user respond, and that Groovy's last repeated key is the one the step receives.

**Review of the fixes** (a second Opus 5.5 sub-agent, 2026-11-21, about 85 attempts at `7c46a65`; each is an `R-` case in the test file): 6 blocking classes, all fixed by class in the model, which every Jenkins rule shares:
- the two branches of a `?:` and the cases of a `switch` had one condition label, so an input in one branch counted for a publish in the other (now each branch and case is its own condition, labelled by line, column and inlined call);
- a condition's text left out its operator, so `== 'main'` and `!= 'main'` were one condition, and `expression { ... }` left out its body (both now in);
- a condition on a parameter of a method the file inlines meant the same at every call (`onlyIf(params.ASK) { input }`, `onlyIf(true) { publish }`; it is now qualified by the call);
- the "same catching block" test compared the block's line, so a helper's `try` or `catchError` called twice was one block (now one number per walk of a block);
- `beforeAgent` and `beforeInput` were part of a `when`'s text, so two stages under `branch 'main'` differed (now left out), and `beforeOptions true`, which Jenkins evaluates before input, was not read (now read as `beforeInput`);
- a `catch` that throws only under an `if` counted as rethrowing (now only a throw or `error` that always runs counts, so a check there no longer counts for OBAAF-JEN-011 and 012 either).

A second pass on those fixes (about 35 attempts at `78fb08c`, each an `R2-` case) found three more classes, also fixed: a condition's text was still a flat list of names and strings, so `> 5` and `> 0`, `in ['prod']` and `in ['dev', 'prod']`, grouping, closure arguments and `expression { return ... }` collapsed (conditions are now compared by their whole structure, shown as the readable text with a digest); a condition inside an inlined method was tied to the call only when it named a parameter directly (now any condition there that reads more than `env`, `params`, `currentBuild` or an upper-case variable, or calls anything, is tied to the call); and a closure given to an inlined method that never calls it was read as running (now it is marked as maybe never running). It also found that the narrowed rethrow test missed a `throw` inside `stage { }` in a catch block (now steps that run their body once are followed, and `steps.error` counts).

A third pass (13 attempts at `3ec6a50`, each an `R3-` case) found two more, also fixed: an upper-case name, or one called `params` or `env`, was taken for the build's own value even when it was the inlined method's parameter or a variable the file declares (now any name the file declares ties the condition to the call); and a trailing closure was bound to the first parameter, so `def withTimeout(int m = 60, Closure body)` never ran its body (it now binds to the last parameter, as Groovy does). A fourth pass (15 attempts at `33929df`, each an `R4-` case) found that "declared" was collected while walking, so a method defined below its use, or a closure parameter (which the parser does not keep), could still pass an upper-case parameter as the build's own value; declared names are now collected before the walk, and only the environment variables Jenkins sets count as the build's own. A fifth pass found that the first version of that collection took `env.VERSION = ...` for a declaration of `env`, which tied every helper's `env.BRANCH_NAME` condition to its call; only a bare name, `this.x` or `binding.x` is declared by an assignment now (`R5-` cases). A sixth check found that a variable Jenkins sets could still be shadowed by a form the reader does not see (`def (BRANCH_NAME, x) = ...`, a closure's `{ BRANCH_NAME -> }`, `binding.setVariable`); inside a helper, only properties of `env`, `params` and `currentBuild` now count as the build's own, and a bare name ties the condition to the call (`R6-` cases; conservative for a helper that tests a bare `BRANCH_NAME`). A last check found that a parameter read inside an interpolation (`"${c}" == 'true'`, `env."${key}"`) was invisible to that test; a condition holding an interpolation is now tied to the call (`R7-` cases). It also confirmed that binding a trailing closure to the last parameter makes a helper's `withCredentials` reach the closure's steps (new, true OBAAF-JEN-001 and 013 findings). The third pass also measured a cost: a helper with a long condition called 1,500 times took 33 s (now 0.45 s, against 0.41 s before the slice), and found that the condition labels had changed OBAAF-JEN-011's message, which a v0.1 baseline entry matches on (the label's readable part is now the text from before the slice, and only its hidden part tells conditions apart).

More iteration methods (`sum`, `sort`, `findIndexOf` and others) are conditions. Left as stated limits, each in `LIMITS`: conditions with the same text count as one even where a variable, a file or a random value changes between them; `\u0020` in slashy strings; a computed map key; `x?.with { }`; a ternary continued on the next line; an input in an outer catching block for a publish in an inner one (conservative); `retry` around an input; an unread statement anywhere makes a missing approval "cannot tell"; a helper's condition is tied to each call even when both calls pass the same value, and a catch that throws on both branches of an `if`/`else` or leaves with `return` counts as swallowing (all conservative). The parser keeps no `?.` or `*.`, and no type after `as` or `instanceof`, so conditions that differ only there are one condition; a condition longer than 4,000 characters is told apart by its place in the file.

## 2d.2m: artifacts from another build

Rule: OBAAF-JEN-010, an artifact from another build used by a moving reference (issue #341, decision D-129). Reviewer: one Opus 5.5 sub-agent that did not write the rule, given the code, the rule's text and the copyartifact plugin's selectors, on 2026-11-21 at `651cb4e`. Every attempt is a case in `tests/test_jenkins_artifact_transfer.py` (`CASES`), with what the rule said before and says now.

**Result before the fixes:** 120 attempts: 51 ways past, 8 false positives, 5 wrong severities, 3 slow cases (466 bytes of nested helpers took 2.4 s in this rule, 744 bytes 11.7 s), and 7 "cannot tell" where the file decides.

| Class | Ways past and false positives | What changed |
| --- | --- | --- |
| A check accepted by its text | 22 ways past: `sha256sum -c` after the publish, with `\|\| true`, in `catchError`, `warnError` or `try`, with `returnStatus`, under `if (params.VERIFY)`, inside an `echo` or a comment, `echo obaaf verify release`, after `exit 0`, `&`, `set +e`, a `#!` line without `-e`, a pipe, in a parallel branch, a closure never called, a later stage with the same name | Only `obaaf verify release`, read by the reader of slice 2d.2e as a command whose failure stops the `sh` script, after the copy and before each publish it covers, outside catching blocks, failure paths, parallel branches and conditions the publish and copy do not share |
| A check that ties nothing to a build record | 6: sums that came with the copy, `--ignore-missing`, `cosign verify` of another image, a check in another folder, on another node, for another copy | Any check but `obaaf verify release` makes the copy "cannot tell" |
| Spellings of the copy | 8 ways past, 4 false positives: `step([$class: 'CopyArtifact'])`, `script.copyArtifacts` in a helper, `this.steps.copyArtifacts`, a method pointer, a computed method name; a map as the only argument, in a variable, spread | `copyArtifacts` on any receiver and `step` with a `CopyArtifact` class are copies; arguments as Groovy builds them; a variable only when it has one value; any other place the file names copyArtifacts or the class is "cannot tell" |
| The selector by its name | 11: `specific('lastSuccessfulBuild')`, a display name, `params`, `env`, `${...}`, `?:`, `upstream(fallbackToLastSuccessful: true)`, a spread after `selector:`, a computed project with a fixed number | `specific` is fixed only for digits or a `build` result's number; other text moves; computed values are "cannot tell"; selector maps by `$class` |
| Fetches without the copy step | 5: `curl`, `wget` and `httpRequest` of `.../lastSuccessfulBuild/artifact/`, JFrog CLI, an S3 "latest" key | Jenkins artifact and workspace URLs are read; other tools are a stated limit |
| Severity and stages | 5 wrong severities: a publish in the stage's `post`, a publish before the copy, stages with one name or computed names, a copy in a class method | High when an unchecked publish after the copy is in its stage, post blocks included; stage names are a stated limit |
| Copies that never run | 2 false positives: a copy in a method or closure nothing calls | "Cannot tell", unless the same copy is also read where it runs |
| Cost | 3 slow cases | Each publish's latest check is worked out once per set of copy conditions, guard keys once per step, and more than 150,000 comparisons is "cannot tell" |

**Review of the fixes** (a second Opus 5.5 sub-agent, about 230 attempts at `0b0c0ba`; each blocking class is an `R` case in `REVIEW_CASES`): about 50 ways past in 11 classes, 11 of them regressions, 9 false positives and 1 cost case, all fixed by class:
- a check counted for a publish in `post { failure }` or `always`, in a `catch` or `finally` block, or before the copy in the same `retry` block (such a publish is now never cleared);
- `returnStatus` given by a variable or a spread map (only an absent or `false` one lets the check count);
- variables resolved file-wide by name: a map changed after it was declared, a selector or `build` variable that is also a parameter, a loop or closure variable, or set through `this.` or `binding.setVariable`, and plugin symbols redefined by the file or called on another object (now resolved only as D-129 says);
- URLs: a `..` segment, a URL split by quotes, a job's workspace, a URL in `environment` or a variable;
- the class named by `new`, an import, a computed `$class` or a computed method name;
- false positives: a `#!/bin/bash` script with `set -euo pipefail` or a single command, a script whose `#!` is not at its very start (Jenkins runs it with `sh -xe`), a copy and its check under one condition, `copyArtifacts(base + [...])` read as the default selector, `CopyArtifactPermissionProperty`, a closure defined and called;
- `selector: null`, which is the default;
- 30 nested `if` blocks around a check and a publish in nested helpers (2.6 s in this rule at 1.3 KB; now "cannot tell" at once, as more than 150,000 comparisons). The rest of the checker still takes about 6 s on that input, as it did before the slice.

**Second review** (the same sub-agent, about 220 earlier attempts re-run and about 60 new at `55b4383`; each blocking class is an `R2_` case in `REVIEW2_CASES`): about 26 ways past in 6 classes, 3 of them regressions, all fixed by class:
- a variable read by its one declaration while a closure's parameter, an alias, an argument, a use inside an interpolated string or a binding write could change it (now a variable is read only when the file names it in exactly one other place and writes no binding or property);
- a copy's own condition clearing a check under the same condition, when the copy makes it false at the check (`if (!fileExists('app.jar'))`; now only conditions on parameters alone are shared);
- a closure called where the checker reads it and run again by `parallel` after the check (a copy in a closure is now always "cannot tell");
- a loop that publishes before it copies (a loop around the copy now counts like a `retry` block);
- a URL kept in a Groovy variable;
- 120 parameter conditions on copies in nested helpers (5.5 s in this rule at 4.5 KB; the budget now counts the copies' sets of conditions).

**Third review** (the same sub-agent, about 280 earlier attempts re-run and about 28 new at `957f17d`; each blocking class is an `R3_` case in `REVIEW3_CASES`): about 13 ways past in 3 classes, fixed by class:
- a declaration in another method or block gave the read its value, while the read was a script property a getter (`def getSel()`), `propertyMissing` or a property write could set (now the declaration must be in a block that encloses the read, with no method between, and the source is no longer searched for binding words, which a comment could hold);
- `$NAME` in a single-quoted script read as a Groovy or `environment` value when the shell or a `withEnv` sets it itself (now the text as written is always read too, and what it shows counts);
- `params` reassigned in the file (left as a stated limit; contrived).

On this repository the slice changes one result: `templates/jenkins/obaaf-release-publish.Jenkinsfile` line 74 is OBAAF-JEN-010 "cannot tell" instead of a pass, because its copy's build number is computed and its checks follow `export PATH=...` (#344). Expectrail has no Jenkinsfile and is unchanged.

A fourth pass (19 new attempts at `e9203ff`) found no blocking fault; its one minor class, a read before the declaration on the same line, is fixed (the place is compared by line and column) and is case `R4_01`.

**Stated limits** (each a case in `LIMITS` or written in D-129): other download tools and object-store keys are not read; two Scripted stages with one name, or computed names, are one stage for the severity; what counts as publishing is the shared detector's (`curl -X PUT --data-binary` and `scp` are not publishes); a copy in a class method, a spread map and `downstream` are "cannot tell"; a digest check is "cannot tell" whatever it checks; an `echo` of an artifact URL counts as a fetch; conditions are compared by their structure (`if (go)` twice is one condition even when `go` changes), and code after a conditional `return` is not treated as conditional, both as for OBAAF-JEN-011 and 012 (slice 2d.2).

## 2d.2n: a provenance check before the publish

Rule: OBAAF-JEN-012, a publish without an earlier check of the artifact's provenance, approvals and agent records that stops it (decision D-130). Before the slice the rule searched each script's text for `obaaf verify release` (or a provenance-only check) with a regular expression, counted a check read where an uncalled closure is written, and counted any check before a publish in a failure path. The slice reads checks with the shell reader of slice 2d.2e, as OBAAF-JEN-010 does since 2d.2m. Every attempt is a case in `tests/test_jenkins_provenance.py` (`CASES`, 363 in all), with what the rule said at `a4b2dc0` and says now; `LIMITS` gives, for each case whose answer is a stated limit, the answer the reviewer judged right and why the rule gives another.

**First attempt** (an Opus 5.5 attacker that did not write the rule, 206 attempts on the slice's first version, `6e508a8`, 2026-11-21). The first version was wrong on 79 (8 ways past, 25 false positives of which 24 were also there at `a4b2dc0`, 42 "cannot tell" where the file decides, 4 findings where it cannot tell); the rule at `a4b2dc0` was wrong on 69. Fixed by class:
- Groovy text in the script (`"... ${EXTRA}"` with `EXTRA = '|| true'`, concatenation, a method parameter) was read as written: now "cannot tell";
- `obaaf verify release --pre-approval`, which skips the approvals, counted as the full check: now a provenance check (medium);
- a check in a method or closure nothing calls counted where it is written, or turned every finding into "cannot tell";
- an `echo` argument, a comment and `--help` gave "cannot tell" where they are no check;
- `.trim()` before a `#!` line, a computed `returnStatus` and a path to `obaaf` are "cannot tell".

**First review** (a second Opus 5.5 sub-agent, 116 attempts at `699d7d3`): 8 blocking findings, fixed by class:
- a publish in a failure path after a check outside it (a stage's `post { always }` in a later stage, a `catch` after the check) became high: now a stage's post block after a check in an earlier stage is checked, the pipeline's post block is high whatever comes before it, and a `catch` or `finally` block after a check is "cannot tell" (how far the `try` body reaches is not compared);
- a check closure run by a call the model does not follow (`parallel(verify: verify)`, an alias, a method pointer) was dropped, giving high: a check read only where it is written and never seen called now makes the file's unchecked publishes "cannot tell";
- a publish closure also run through such a call was decided only where it is called, and a publish in an uncalled method written below the check counted as checked: a publish read where it is written is now always "cannot tell";
- `.trim()` on part of a concatenated script was missed; argparse abbreviations (`--pre`, `--hel`) and shell variables among the check's words (`$VERIFY_FLAGS`) were taken literally; build numbers read as digits let `|| exit ${BUILD_NUMBER}` through; `OUT="$(obaaf verify release ...)"` was no check;
- a test claimed more than it checked (renamed and narrowed).

**Second review** (the same sub-agent, 35 new attempts at `ad4d91b`): 3 blocking findings, fixed: a stage's post block was recognised by its stage name (a Scripted `stage('post build')` inside the pipeline's post block passed; a check in a stage named `post build checks` was ignored), so the model now records which stage's post block a step is in (`Ctx.post_owner`); `--pr` is `--pre-approval` to argparse, `-ho` asks for help, an unquoted `$ARTIFACTS` or backticks among the check's arguments may add options (now any expansion there is "cannot tell"); a wrapper's own `-h` was taken for the check's.

**Third review** (the same sub-agent, 50 attempts at `912249c`): no blocking finding. It ran 1,371 Jenkinsfile texts from the Jenkins test files through every rule before and after the second-review change: identical for every rule but OBAAF-JEN-012. OBAAF-JEN-010 changed in one case only, as intended: a `#!/bin/bash -ne` line now reads the script as running nothing.

**Result.** No attempt in the file is quiet where the reviewer judged a finding or "cannot tell", except three forms the Jenkins model did not read before the slice either (a method named `sh`, a closure helper called with a trailing closure; cases R56, R61, N01). No answer is a finding where the rule was quiet at `a4b2dc0` and quiet was right, except Q13 (a check closure run through `parallel(name: closure)` and also called after the publish) and T11 (`--actor -h`, which argparse refuses with status 2).

**Stated limits** (148 cases, each in `LIMITS`): most are "cannot tell" where the file decides, because the reader of slice 2d.2e vouches for a command only on a line of its own after lines it can read (`; true`, `&& echo ok`, `set -Eeuo pipefail`, a here-document, `export PATH=`, wrappers such as `timeout`, `docker run`, `sudo`; #347), Groovy values are not resolved, expansions among the check's arguments are not followed, `bat`, `powershell` and `pwsh` are not read, and failure handlers are not compared with how far their `try` body reaches. Some findings remain where the rule was already wrong at `a4b2dc0`: the older text reading decides where the reader does not vouch and takes `set -Eeuo`, `set -eE` and a last-line check under `#!/bin/bash` for ignored failures; a `returnStatus: true` step followed by `if (rc != 0) { error ... }` is no check; `catchError` before `post { success }`, a check in `finally`, nested `catchError`, a typed `catch`; a check in a `load`ed file or shared-library step.

On this repository the slice changes one result: `templates/jenkins/obaaf-release-publish.Jenkinsfile` is OBAAF-JEN-012 "cannot tell" instead of a pass, because its checks follow `export PATH=...` (#344). Expectrail has no Jenkinsfile and is unchanged.

## 2d.2o: a publish after a failed or skipped check

Rule: OBAAF-JEN-011, a publish in a failure path, or a check before a publish whose failure does not stop it (decision D-131). Before the slice the rule found a check with two regular expressions over the script's text and read only the first kind (`verify_commands`) for a failure the script ignores, with the same text search OBAAF-JEN-012 used before slice 2d.2n. It decided whether a check stops a publish with `gates()`, which never let a check in the same catching block as the publish stop it. The slice reads every check from the command's words with the shell reader of slice 2d.2e, compares them as OBAAF-JEN-012's `provenance_gates` does, and says "cannot tell" where the file does not decide. Every attempt is a case in `tests/test_jenkins_failure_paths.py` (`CASES`, 394 in all), with what the rule says after the slice (asserted) and what it said at `75dae58` (recorded); `LIMITS` names the 102 whose answer differs from the reviewer's judgement, and why.

**First attempt** (an Opus 5.5 attacker that did not write the rule, 172 attempts on the rule as it was at `75dae58`, 2026-11-21). The rule was wrong on 74: 43 ways past (39 should be findings, 4 cannot tell), 31 false positives, and 3 inputs that took 2.8 to 4.1 seconds. Fixed by class:
- a checksum or signature check (`sha256sum -c`, `shasum -c`, `cosign verify`) was never read for a failure it ignores, so `|| true`, `set +e`, a pipe or a `#!` line without `-e` passed: every check is now read the same way;
- the older reading searched the rest of the line: `set -e` or `pipefail` anywhere in the script counted, even after the check or inside an `echo`; `set +o errexit`, `set +ex`, a backslash-continued `|| true` and `trap 'exit 0' EXIT` were missed; `|| exit 1`, `|| { ...; exit 1; }`, a `||` in a comment, a `|` in a quoted argument and an `echo` of the command were read as ignoring the failure. Now the reader vouches for the check, or a short list of forms that decide on their own gives the reason, or it is "cannot tell";
- a check named by a path or inside `bash -c` was no check: now "cannot tell"; `gpg --verify` is a check (OBAAF-JEN-010 already counted it);
- a check and the publish in the same script were never compared, and a check in a failure path that ignores its failure was dropped even when a publish ran after it;
- `post { notBuilt }` was not a failure path (this also changes OBAAF-JEN-005, 010 and 012, which share the list);
- a computed `returnStatus`, and a check read only where an uncalled closure or method is written, counted as a check that stops the publish: now "cannot tell";
- a check and the publish in the same `catchError`, `warnError` or `try` block were reported, though a failed check skips the rest of the block;
- a publish in a later stage's post block was reported after a Verify stage whose failure skips it;
- a guard on the build's result in a Declarative `post` block, and a catching block before a publish that runs only on `post { success }` or under such a guard, gave high: now "cannot tell" (what the block sets the result to is not read);
- every check was compared with every publish: now once per kind of publish, so 2,000 checks and 2,000 uploads take a fraction of a second.

**Review passes** (one Opus 5.5 sub-agent that did not write the rule, 2026-11-21; its attempts are the cases whose ids start with V, V2 to V6). Each pass found classes, each fixed by class before the next:
- **First pass** (77 attempts on `50b7e2d`, 8 blocking): a check in a later stage hid a publish in an earlier stage's post block; a check the reader could not read skipped the place test (a parallel branch, a catching block); the first result-guarded publish ended the search for a later one; one verdict per step let a passing check hide a swallowed one; 15 false highs (`gpgv` as an argument, a trap on any signal, `set +e` in a subshell, a function or a here-document, `& wait $!`, `rc=$?; exit $rc`, `exit ${PIPESTATUS[0]}`, bat `|| exit /b 1`); a line of 120 KB took 5 s; five messages differed from the older rule's for the same check and publish.
- **Second pass** (53 on `009a801`, 6 blocking): a check after words that were not listed wrappers (`uv run`, `docker run`, `sudo -u ci`) became no check; `cd d && check || true` lost its `|| true`; a catching block's "cannot tell" hid a step that ignores its own failure; four message wordings; six false highs (`pid=$!; wait $pid`, text inside a string that runs over lines, an uncalled function, `{ check; } > log`, a bare `exit`); 30,000 checks on one line took 149 s.
- **Third pass** (52 on `5ddafa5`, 7 blocking): a 20 KB base64 word took 6.7 s (a path prefix in the program pattern); `set -o errexit -o nounset -o pipefail` was read to its first option only; a package name, a commit message or a printed string read as a swallowed check; a trap on ERR that exits 1, an `if`/`else`, a function with `{` on the next line, `exec`; a comment ending in a backslash swallowed the next line; a bat check behind `if exist`; three message wordings.
- **Fourth to sixth passes** (18, 10 and 12 attempts on `32735f1`, `60be83f` and `9e12b4c` and after, the last ones single items): continued lines (6.7 s for 4,000), runners not listed (`gosu`, `fakeroot`), an escaped backslash at a line's end, `case` patterns ending a function, `grep -c`, a publish written before the check in the same step, `sudo apt-get install gpgv` after a runner, `bash -lc`, a runner's option values (`sudo -u git`), `ghcr.io` read as `gh`, an assignment's value, `apt-get -y purge`, `ssh -y`. A check on `533c5e8` found nothing blocking; the speed change after CI's timing failure (`24b2235`) moved one line-start test across lines, found by the same reviewer and fixed (`. file` after a line ending in `;`), and a second speed change (one placeholder for each run of lines that cannot change the reading) briefly lost a command after a non-breaking space, also found and fixed.

**Result.** No attempt is quiet where the reviewer judged a finding or "cannot tell", except four forms the Jenkins model did not read before the slice either: a publish closure run through `parallel` in a post block (F37), a publish or check command kept in a variable (F38, R37), and a `return` that leaves only a `script {}` block (X10). Every message the older rule gave for a check and a publish it still names is unchanged, checked on every case and on 1,767 Jenkinsfile texts from the test files; the exceptions are where the finding now names a later publish (VB01 to VB03, VG03, V3q07) and V3p15, where the older reading took `set +e` inside an `echo` for a command. Outside OBAAF-JEN-011, only `post { notBuilt }` moves: OBAAF-JEN-012 from quiet to high, OBAAF-JEN-005 to its failure-path message, OBAAF-JEN-010 to medium for a later stage's `notBuilt` block.

**Stated limits** (102 cases, each in `LIMITS`): most are "cannot tell" where the file decides, because the reader of slice 2d.2e vouches for a command only on a line of its own after lines it can read (`if`, `&&`, `;` lists, subshells, `bash -c`, `set -o` lines, `export PATH=`; #347), Groovy values are not resolved, `powershell` and other `#!` programs are not read, a script that may keep the failure itself (`wait $!`, `rc=$?`) is not followed, and what catchError, warnError or a catch block sets the build's result to is not read. Some findings remain where the reviewer judged quiet: the status tested in Groovy (`if (rc != 0) error ...`), conditions compared by how they are written, `skipStagesAfterUnstable()`, nested catching blocks compared by the inner one, and which check is meant to stop which publish.

**Speed.** The attacker's three slow inputs (2.8 to 4.1 s at `75dae58`) and the review passes' slow inputs take about as long as at `75dae58` (under 1.2 s), except two adversarial ones that are linear but slower: 30,000 checks on one line (2.4 s; 0.9 s at `75dae58`) and 40,000 check lines (4.5 s; 1.1 s), where every line is split into words by both the reader and the rule.

On this repository the slice changes one result: `templates/jenkins/obaaf-release-publish.Jenkinsfile` gets two OBAAF-JEN-011 "cannot tell" (its checks follow `export PATH=...`, #344), as OBAAF-JEN-012 already did; exit status, JSON fields and SARIF are otherwise unchanged. Expectrail has no Jenkinsfile and is byte-identical in text, JSON, SARIF and `--no-fixes` output.

## 2d.2: untrusted text in a command

Rule: OBAAF-JEN-009, text others control built into a command or into Groovy code before it runs (decision D-132). Before the slice the rule searched each interpolation's text for names (`_UNTRUSTED_RE`, `_PARAM_RE` and the names of tainted variables), so whatever hid a name from that search hid the source.

**First attempt** (an Opus 5.5 attacker that did not write the rule, 172 attempts on the rule as it was at `653b153`, 2026-11-22; ids A001 to A172; the run that took the slice added 29, ids B-a01 to B-a30). The rule was wrong on 124 of the 172: 77 ways past, 41 false positives, 4 wrong severities and 2 slow inputs. Fixed by class, with a reader of each value's syntax tree (`src/obaaf/checker/jenkins/values.py`):
- the source spelled otherwise: `env?.X`, a comment before the dot, `env.change_title` (Jenkins reads environment names without regard to case), `env.getEnvironment().X`, `env[n]` and `env."${n}"` with `n` a literal, `def p = params`, `def e = env`, `this.env.X`;
- `\u0024{...}`, which Groovy 2.4 (the version Jenkins runs) turns into an interpolation before lexing;
- taint set only by assignment to a plain name: `sb << x`, `.append`, `list.add`, `map.put`, `m.t = x`, `env.setProperty`, `binding.setVariable`, `this.T = x`, `withEnv` entries built with `+`, `def (a, b) = [...]`;
- bindings the rule never read: closure and `for` parameters, a closure variable called, named arguments into a `Map` parameter, varargs, a method's return value;
- commit text lost through `.split('\n')[0]`, `git rev-list --format`, `git cat-file -p`, a format in a variable, `%%B` in `bat`, a second git command on a line; file names from `git diff --name-only`; branch names from git commands;
- sources not listed: `gitlabTriggerPhrase`, ghprb e-mail variables, Bitbucket Push and Pull Request variables (from its README's table), pipeline-github's `pullRequest`, `currentBuild.changeSets` and build causes, `input` answers, parameters declared with `properties([parameters([...])])` and read by bare name; Generic Webhook header variables (lower-cased by the plugin) and a variables list held in a variable;
- sinks not read: `def s = this; s.sh`, `this.&sh`, `sh(*: opts)`, Docker Pipeline's `build`, `run`, `withRun`, `push`, `tag`, `pull` and `inside(args)`, Publish Over SSH `execCommand`, `bat`'s `%NAME%` (cmd expands it before parsing), `Eval.me`, `GroovyShell`, Job DSL, and `build` parameters in a variable, in the `$class` form, from `params.collect`, or wrapped in `.trim()` or `?:`;
- false positives from judging names in text: ternaries and comparisons choosing literals, numbers and booleans derived from the value, `replaceAll` whitelists, URL and base64 encoding, `booleanParam` and `choice`, `env.Y` after `env['X'] = value`, and a method on a literal (`'a,b'.split(',')`) making every Jenkins rule "cannot tell";
- a wrong severity for a webhook payload variable holding `$` or an object (medium; now high unless its path ends in a number, count, identifier or state).

**First review pass** (a second Opus 5.5 sub-agent that did not write the fix, 203 attempts and 66 size probes on `b8e1ce4`; its JEN-009 cases are the ids starting R1-). It found 11 blocking classes, each fixed by class:
- the new skipping of comments inside `${...}` read `//` in a slashy regex (`replaceFirst(/^https?:\/\//, '')`) as a comment, so the whole file could not be read: removed; an interpolation the parser cannot read is now "cannot tell" instead;
- one parameter or variable named `env` or `params` anywhere turned off the build's own for the whole file: removed (a method's own `params` is read as the build's, a stated limit);
- `env.TARGET` for a declared string parameter, and `env.X` set from an uncalled method's parameter, were quiet;
- `.replace('[^...]', '')` (a literal replace), `.asType(String)` and the file's own method named like a safe one were read as clearing the value;
- `body.setDelegate(config)` in a `vars/` step was not read;
- helpers that each call the next twice took up to 9.5 seconds: a method's result is now worked out once for each set of argument sources, and the reader has a budget for the whole file;
- `getProperty(k)` over a literal list of names raised a TypeError, so every rule said "cannot tell";
- chained `sb << 'a' << x` and `sb.append('a').append(x)`, `this` held in a variable or parameter not named `script` or `steps`, `bat`'s `%NAME:~0,5%`, lower-case names and a script held in a variable, a closure alias or a closure in a map, named arguments with a trailing closure, and a method ending in an assignment were not followed;
- one loop's implicit `it` over a tainted value made every `it` in the file tainted: an implicit `it` now holds the value only inside its own closure;
- messages changed for a map read through its property (`cfg.title (from ...)` where the base said `cfg (from ...)`): restored;
- the documentation claimed more than the code (nothing lost, every caller value "cannot tell", messages unchanged) and said nothing of what the shared model's changes do to OBAAF-JEN-013 (a key held in a variable, `env['T'] = TOKEN`, changed its messages; new findings through `this.T =` and `env.setProperty`): the JEN-013 messages are restored and the new findings are stated.
Non-blocking notes it made, also handled: a chain of 2,000 calls exhausted the stack (the reader now reads past 150 levels by the names in the text); more than eight nested helpers passed (now twelve, then "cannot tell"); `%%NAME%%` and a Groovy local were read as `bat` variables; the whitelist accepted space and `=`; `git status | wc -l` was read as file names; `$.after`, `$.action` and `$.pull_request.merged` were high. Still open from it: a `\u000a` in a comment moves later line numbers by one (as Groovy 2.4 counts it), stated in the changelog.

**Second review pass** (the same sub-agent, 65 new cases, 102 probes and its 203 first-pass cases re-run, on `13ba10c`; ids R2-). It confirmed B1 to B4, B7 and B10 fixed and found seven blocking classes in the new code, each fixed:
- the implicit `it` was given only where a variable was assigned, so a nested loop over `it.items`, `for (e in it.items)`, `run(it)` and `env['MSG'] = it` lost the value; and a closure alias called made `it` a file-wide name again: every judgement during the walk now gets the enclosing body's `it`, an implicit `it` is never recorded as a name, and the innermost body with its own `it` decides for each step;
- the per-file budget ran out on a 43 KB file and then let `${e.CHANGE_TITLE}` pass: past either budget a value is now at least "cannot tell";
- still slow (4.7 and 5.7 s on 35 and 43 KB, base 1.4 and 2.0 s): the method-result cache now keys on the state of the names the method can read rather than on every change, so those files take 1.6 to 2.3 s (the third pass found that key incomplete; see below);
- the cache reused a result computed under a recursion cut or a spent budget, and named the first caller's variable for the second (`q(t)` then `q(u)`): a result computed under a cut is not kept, and the key holds the arguments as given;
- `bat`'s `%JOB_NAME%%CHANGE_TITLE%` was quiet (two adjacent names), and `%NAME%` of a value from a caller outside the file passed: names are now read left to right with `%%` as a literal, and a caller's value is "cannot tell";
- a comment inside `${...}` holding `}` made the step low or quiet instead of high: the lexer now skips comments inside `${...}` and reads a slashy or dollar-slashy string there as text, so the whole expression is read (the first pass's regex case still parses);
- the record still held a template marker, and the guide's words on `it` and on the budget were wrong.
Non-blocking notes handled: an inner literal loop inside a tainted loop was high; `${}` was "cannot tell"; `env.getEnvironment().keySet()` (names, not values) was high. The other misses it listed are stated limits.

**Third review pass** (the same sub-agent, 59 new cases, its 268 earlier cases re-run, and 1,734 Jenkinsfile texts from the base's Jenkins tests run through base and change for every rule, on `a3d687c`; ids R3-). It confirmed the second pass's findings fixed and found three blocking classes, each fixed:
- the method-result cache could still reuse a stale result: a key held in a variable (`env[k]` with `k = 'T'`) or a value stored as `m.t` was not part of its key, the twelve-method cut was cached and returned only the names in the text, and recursion cut by name returned nothing for `f(b, null)`: the key now also holds the literals the method's words hold and the dotted keys under them, a result computed under a cut is not kept (from the fourth and fifth passes: a recursion cut or the twelve-method cut is kept for the same place in the chain, the call stack being part of the key; a result computed after a budget ran out, or with part of it more than 150 levels deep, never is), past twelve methods the call is read by its names and is at least "cannot tell", and a recursive call returns what it is given;
- slow inputs under 50 KB: the lexer looked back over the whole interpolation before each `/` (9.6 s for 22,000 divisions; base 0.06 s), and the cache key read every word of a 2,500-name helper on every call: the lexer now looks back over spaces only and checks the deadline, the key's cost counts against the budget, and the per-file budget is about 300,000 steps (the largest text in that corpus used about 4,000);
- `${tool 'M3'}` and `${tool name: 'jdk17', type: 'jdk'}`, a common idiom, were "cannot tell": command syntax inside `${...}` is now read as a statement.
Non-blocking notes handled: `${i++ / 2}` and `a$/2` were read as strings; a multi-line slashy string inside `${...}` was refused; `bat`'s `50% done %X%` was a false positive and `%ProgramFiles(x86)%%X%` a miss (names now run from each `%` to the next, as cmd reads them). Left as stated limits: a closure defined in a tainted loop and called with no arguments keeps the loop's `it` (errs towards a finding); a value worked out for an uncalled method's parameter can reach a step outside it as "cannot tell"; a twelve-method chain whose names show only a branch name is low, which a build parameter drops.

**Fourth review pass** (the same sub-agent, 15 new cases, its 327 earlier cases and the corpus re-run, on `836ea94`; ids R4-). It found three blocking items, each fixed: a caller's value stored as a map property (`opts.target = config.target` in a `vars/` step) passed, because the reader looked dotted keys up only among tainted values (older than the slice's later passes; base was quiet too): it now reads them among caller values as well; a 43 KB size case took 1.2 s (base 0.24 s), because results computed after a budget ran out were never kept, so every call expanded the helper chain again: a call is no longer expanded once a budget is spent, and the call stack is part of the key, so the case takes 0.36 s; and this record gave a wrong figure for the corpus. Non-blocking, handled: a block comment directly before a slashy string inside `${...}` made the file unreadable. Left: a recursive method whose result is a number still carries its argument's source (as before the slice); `${println x}` is reported though its value is null (as before).

**Fifth review pass** (the same sub-agent, 11 new cases and its 342 earlier cases and the corpus re-run, on `1833b81`; ids R5-). It found two holes in the new caching, each a pass, both fixed: a result computed with part of it more than 150 levels deep (read by names only) was cached and reused for a plain call, and the cache key did not hold map properties that hold a caller's value (`opts.target = config.target`, walked after an earlier call). Such results are no longer cached, and the key holds those properties. Left: a nested-looking comment (`/* a /* b */`) before a slashy string holding `//` inside `${...}` makes the file unreadable, so every rule is "cannot tell". A closing check of these two fixes by the same sub-agent (on `cd4cb70`) found nothing blocking; it noted that a map property written with `this.` and read without it, or the reverse, is not linked (as before the slice).

**Stated limits** (each a case in `LIMITS` with its reason): taint is kept by name for the whole file and never cleared (an implicit `it` excepted); keys of one map are not told apart, and a map's property is followed only when read as that property; containers filled through another name, closures in lists or passed to methods, curried closures, parameter defaults, `env` inside a map, `docker` held in another variable and `Runtime.exec` are not followed; a guard on the value (`==~`, `when { branch }`, an `if`, the webhook's `regexpFilter`) is not read; quoting in Groovy is not recognised; a whitelist keeping `-` can still let the value add an option; workspace files' contents are not counted as untrusted; `writeFile` then a later run is not followed; a computed step name, `invokeMethod`, a method called on a closure parameter and an interpolation the parser cannot read make the file or step "cannot tell"; past the reader's budget a value is at least "cannot tell"; a closure variable given to `each(f)`, a closure in a map called through an index, a `bat` script variable assigned twice, `this.sb << x`, `def s = sb << x` and an alias of `env.getEnvironment()` used whole are not followed. No stated limit is quiet where something was judged unless the rule was quiet there before the slice too (a test holds this).

## Review of #365: a check under a changed `PATH` (OBAAF-JEN-010, 011 and 012)

Pull request #365 (the lead session's, for #344) moved the publish template's `export PATH` into
`withEnv(["PATH+OBAAF=..."])`, and its test asserted that OBAAF-JEN-010, 011 and 012 then passed. They passed because
the shell reader read only the check's own script: the same `withEnv` with a folder from the workspace
(`PATH+X=${env.WORKSPACE}/tools`) cleared all three. The review made such a check "cannot tell" (decision D-135; the
record of cases is `tests/test_jenkins_check_environment.py`).

**Attack on the first version** (an Opus 5.5 sub-agent that did not write it, about 285 attempts on `16872fb`, each
run through the checker; Groovy and Jenkins were not run). Four classes got past it, each fixed with cases:

- Groovy octal escapes were not decoded (`'\120ATH'` was read as `120ATH`), in every Jenkins rule;
- `env` reached through the script object or a variable holding it (`this.env.setProperty`, `script.env['PATH']`,
  `steps.env`, `def s = this; s.env.PATH`, `getProperty('env')`);
- `withEnv` called through another receiver (`s.withEnv`), a method pointer, a quoted name, or in `options { }`;
- writes in Groovy the walker does not walk: a `when { expression { } }`, a method an `environment` value or another
  directive calls, a GString, a `for` loop's start.

Non-blocking items handled: a matrix axis and a credential binding's variable around the step are read; the
file-wide part is worked out once (2,000 assignments and 2,000 checks took 4.2 s, 6,300 took 27 s; now 1.2 and 3.4 s).
Stated limits: the agent's own environment (`tools { }`, a container's image or `-e` options, a pod template's
`envVars`, wrappers such as `withPythonEnv`), `env` handed on through a list or map, and false "cannot tell" for a
parameter or local named `env`, a copy from `env.getEnvironment()`, a comment or string showing a write, and names
such as `PYTHON_VERSION`.

**Second attack pass** (the same sub-agent, about 265 attempts on `9f9ffee`). The four classes were fixed (the attacker's 39
cases `unknown`), but the second version found writes to `env` in Groovy the walker does not walk with a scan of the
file's text, and that scan was got past with an alias of `env`, a comment between `env` and the name, `(env)`, a
`\u0050` escape, a triple-quoted or quoted name, `this."env"`, a multiple assignment, a computed setter name, a
method pointer (`env.&setProperty`), `env.identity { }`, `getProperty('e' + 'nv')`, a computed `withEnv` or a
pointer to one; and one 256 KiB line of `env[` took 135 s. The scan is replaced by a reading of every node of the
parsed file, and of every `${...}` parsed as statements; a call or pointer whose name is computed, and a statement
the parser could not read near `env`, are "cannot tell". The same pass found the lexer change correct: colour codes
give the verdicts they gave, `'\174\174 true'` and `'\046'`, which passed, now give their findings, and slashy
strings are not decoded.

**Third attack pass** (the same sub-agent, about 360 attempts on `6007f19`). All earlier cases were `unknown` and
the slow inputs took under a quarter of a second. It got past the node reading with `env` reached as a value:
through a ternary, `?:`, `as`, a method's or closure's result, a closure whose `delegate` is `env` (the usual
Jenkins configuration idiom), a script property (`this.e = env`); and with Groovy the parser keeps no node for (a
method's parameter default, a switch case label). Now any use of `env` other than a read, a write or a method call
on it counts as a name the checker cannot read, and those texts, a loop's header and a postfix `++` are searched.
Code from outside the file that runs in a `when` expression (`load`, a shared-library step) is not read by any rule
there, before or after this change (#370). The claims reviewer's third pass found that writes inside a `${...}` were
reported with the interpolation's own line numbers and that an unreadable statement there was looked for in the
file's first lines; both are fixed, and a loop bounded by an `env` value no longer counts.

**Fourth attack pass** (the same sub-agent, about 220 attempts on `75146e9`). All earlier cases were `unknown`. It
got past with `getProperty('env')` on a closure's `owner`, `delegate` or `thisObject`, a computed property of one
of them, a pointer to `getProperty`, a `\u0065nv` escape in the texts the parser drops (they were searched before
the escapes were translated), `getProperty` with a computed name in a default or a loop's header, and a case label
over several lines; it also found false "cannot tell" for `buildInfo.env.collect()` and a YAML file's `env`. Each
is fixed: `getProperty` and `getAt` reach `env` on any receiver, a property named `env` counts on a receiver that
can be the script (or where it is written to), the texts are translated first and searched for `getProperty` too,
and a case label runs to the next case.

**Fifth attack pass** (the same sub-agent, about 100 attempts on `3bb3520`). It found `getProperty('env')` on a
method's result or an index (`me().getProperty('env')`, `[this][0].getAt('env')`, `getOwner().getProperty`) and
`this['env']` or `this.'env'` in the dropped texts, both fixed; and, needing data flow, `this` through a ternary,
`it`, `owner.owner`, now read, and `me().env`, a stated limit with other reflection the checker does not model.
A last pass (about 60 attempts on `8d98aea`) found a triple-quoted `env` in the dropped texts, fixed; and the claims
reviewer found that `targets.each { echo(it.env) }` was "cannot tell", so a parameter's or `it`'s `env` now counts
only where it is written to or given a method that may set a variable, and a variable given one is followed.

**Claims review** (a second Opus 5.5 sub-agent): the template is "cannot tell" for its `PATH` change only (replacing
both `withEnv` calls with `dir('.')` gives three passes); a check under such a variable before a publish in a later
stage's failure-path `post` block gives a new high OBAAF-JEN-011, which the texts now say; `--revision-file`
accepted only 40 or 64 lower-case hex digits with at most one line ending, refused every other file it could read
with exit 2 and gave no traceback; a FIFO with no writer waits. Its second pass found the computed setter name the
attack found too.

## 2d.18: an agent named through the `env` a step runs with

Issue #377 (found by the reviewer of slice 2d.16): `$a$b --dangerously-skip-permissions -p review` with `a: cla` and
`b: ude` in the job's `env` got no OBAAF-GHA-026 and no agent lane. On `flagship` `660f824` the wider class was that
the lanes put only the step's own `env` into its command lines: `run: $CLAUDE -p "review"` with `CLAUDE` in the
workflow's `env` and a model key in the step's was in no agent lane, so no agent rule applied. Now the lanes put in
the step's own `env` over its job's over its workflow's, a local action read for an agent is given the same, and
OBAAF-GHA-026's cheap put-in is tried on every script with a `$` (decision D-139; the cases are
`tests/test_env_named_agent.py`).

**Review** (one Opus 5.5 sub-agent that did not write it, six passes, each run through the checker against `660f824`):

- *First pass* (77 attempts on `032a527`: 29 ways past, 15 of them in the slice's scope; 10 false errors; 4 costs).
  Four of its five blocking findings were in a first version that also worked out `${{ }}` expressions reading `env`;
  the fifth was an old test (below). The
  readings of every `||` in a step were multiplied together, so five `${{ env.X || 'd' }}` were an error of the file.
  `toJSON(env.AGENT)`, `join(env.AGENT, '')`, `(env).AGENT` and `env[env.KEY]` were read as empty. A file's author
  could make the check 4 to 65 times slower (about 627 s against 9.6 s). That part was taken out and is slice 2d.19,
  with these cases as its starting points. An old test of slice 2d.17 that asserted "the lanes do not read the
  workflow's `env`" now expects the lanes' errors past D-138's bound.
- *Second pass* (20 attempts on `fe0cefa`: 4 ways past, 4 false errors). A local action whose four
  `${{ inputs.x || 'default' }}` make 16 readings of `--prompt "$PROMPT"` was an error for a 13 KB prompt in the
  job's `env` (as it was on the base for a prompt in the using step's own `env`): such a step's bound is now as many
  times as wide as its `run` or `with:` readings. A filter of the job's names by the words of the action's files
  missed a script path handed in through `with:` (`$TOOLS/review.sh`), a name in another letter case, and one with
  `-` in it.
- *Third pass* (8 attempts on `e6c9b94`: 5 ways past). The filter missed names when a `uses:` key was handed in, and
  `$TOOLS-dir`; with the workflow's ledger filled, the second pass's local steps were skipped in silence.
- *Fourth pass* (5 attempts on `aa1b565`: 5 ways past). The filter missed a name the inputs make only once put in
  (`${{ inputs.a }}${{ inputs.b }}` with defaults `$TO` and `OLS`, the caller's `with:`, or `'$TO'` after `||`),
  through a repository script. The filter was removed: the action is given the whole `env` and read again for each
  job whose values differ.
- *Fifth pass* (4 attempts on `2f6284e`) and *sixth pass* (on `59b6e3c`, a cache of OBAAF-GHA-026's cheap put-in per
  step, after CI's Python 3.10 job ran a 400-job test at 30.5 s against its 30 s limit): no blocking finding; the
  cache gave the same output as the head before it on 104 cases.

Stated, not fixed (D-139): `${{ env.X }}` in a workflow's own step (slice 2d.19); what an earlier step writes to
`GITHUB_ENV`; an `env` written as one expression; a container's `env`; an `env` value that is itself an expression;
the second pass's silent skip of a local step past the workflow's ledger, the lanes resting on slice 2d.4a's own
ledger there; a heavy local action read once for each of many jobs whose `env` differs, which can pass the check's
units (an error); slice 2d.17's many-callers false error, which now reaches a called workflow's `env`.

## 2d.19: `${{ }}` expressions that read `env` in a step's command lines

Issue #382, from the first review of 2d.18: `run: ${{ env.AGENT }} -p review` with `AGENT: claude` in the job's `env`
was in no agent lane on `flagship` `b17f5f0`, so no agent rule applied. Now the lanes work such expressions out
(`checker/env_expr.py`, decision D-142; the cases are `tests/test_env_expressions.py`, 69 tests).

**Review** (one Opus 5.5 sub-agent that did not write it, four passes, each compared with `b17f5f0`):

- *First pass* (on `0fcffb3`: about 87 workflow cases and 14 timed cost runs; 5 blocking findings). Nine
  `${{ inputs.k || env.K }}` in one `helm` command were an error (a value from another context doubled each
  expression's readings, 2^9 past 256); an index of 4,000 unknown keys built 16,000,000 values (56 times the base's
  time), `fromJSON` re-parsed one 380 KB value 5,000 times (25 times), and copies of lines were bounded per step but
  not per workflow (31 times the memory); `casefold` took `ß` for `SS` and the Kelvin sign for `k` where GitHub
  compares letter by letter, and Windows folded `ß` into `SS`; names YAML reads as numbers, booleans or null were
  dropped. Not blocking: a number index was not taken whole, an unknown `format` template dropped its arguments, `-1`
  was refused. All fixed; each is a test.
- *Second pass* (on `890d422`; 1 blocking). The values in every reading were not counted before the text was made:
  100 lines of five computed indexes over 1,000-character values took 768 MB. Not blocking: refused steps each
  worked to their own bound; `join(env.*)` left out names YAML reads otherwise; .NET's simple case mapping of
  U+1FB3. Fixed: the plan counts the text before anything is made, against the workflow's room, and the work of a
  refused plan is charged.
- *Third pass* (on `8ec9bf1`; 1 blocking). Each step's key held the whole `env` (1 GB for 2,000 steps over 5,000
  entries); the new ledger counted values twice (false errors where `$NAME` passes). Fixed: the key holds only the
  entries the expressions can read, as a digest; the ledger counts each text once.
- *Fourth pass* (on `2bf73c7`: 26 probes of the key's names, 2 shapes of D-084's values put in place, 3 cost
  cases): no blocking finding and no way past; the time on the cost cases is 1.3 to 1.4 times the base's.

Stated, not fixed (D-142): OBAAF-GHA-026 reads options through these expressions only as its medium "cannot
tell" (slice 2d.19c); an expression in another action's inputs, a `docker://` step's arguments, a step's `shell` or
an `env` value; what an earlier step writes to `GITHUB_ENV`; pwsh `$env:X` and cmd `%X%`; the `$NAME` put-in of
D-139 on Windows still merges names as written; more than 1,024 readings of one line (eleven
`${{ github.ref == 'refs/heads/main' && env.PROD || env.DEV }}` in one command) is an error.

## 2d.19c: OBAAF-GHA-026 reads the options `${{ env }}` expressions give

Slice 2d.19c (#382, the rest of 2d.19; D-143). One Opus 5.5 sub-agent that wrote none of it attacked `Rules._env_expressions_worked` in three passes, with a fourth check of the last fix: about 240 attempts, each run against the base (`flagship` `db6e0ed`) and the change, side by side. What GitHub does was read from its pages and the runner's behaviour as recorded in #387, not run.

**First pass (d72ca60, the first version, which trusted any reading whose names were set): 6 blocking, about 117 attempts.** Ways past, each base medium and quiet with the change:

- a value of another context beside a known one: `${{ inputs.flags || env.SAFE }}`, `format('{0} {1}', env.BASE, inputs.extra)`, `join(matrix.f, env.SEP)`, `matrix.f || env.EMPTY`, the same in github-script and the egress action's command (`env_expr` leaves out a value it does not know beside a known one, and reads one as empty inside `format` and `join`);
- several readings of a line, read together: `startsWith(env.MODE, 'safe') && '--model sonnet' || '--dangerously-skip-permissions'` before a heredoc, so the second reading was inside the first's heredoc; and two letter cases on `runs-on: ${{ matrix.os }}`;
- an `env` value that holds `${{ }}` (`"--model sonnet # ${{ vars.EXTRA }}"`), which GitHub works out first;
- a local action's step given its caller's `${{ env.X }}` input, worked out with the action step's own `env`;
- writers of the `env` context the older pattern misses: `${{ github.env }}`, `::set-env` with `ACTIONS_ALLOW_UNSECURE_COMMANDS`, a github-script step's `c['export' + 'Variable']`;
- a crash: more than 4,096 values for one name (`Env.lookup` raised).

Also a cost: 20 steps of ten two-valued expressions took 51 s against 3.6 s. **Fixed by class:** only expressions that read nothing but `env` and literals, with `format` and `join` as the only functions; one reading per line; no value holding `${{`; no local action's step; the wider writer pattern and any earlier github-script step; the reader's refusals caught.

**Second pass (6b6bd85): 2 blocking, about 90 attempts.** `fromJSON` is parsed by Python's `json.loads`, stricter than the runner's reader (single quotes, names without quotes, comments, text after the value, trailing commas), and a refused text was read as empty: five forms quiet. Searching every earlier step's text for every step was quadratic and expanded YAML aliases: 75 s for 6,000 steps, and 1 GB and 60 s for a 1 KB alias bomb. **Fixed:** `fromJSON`, `toJSON` and every function but `format` and `join` refuse; the first step that may write is found once for the job, each mapping read once (`Rules._first_env_writer`); `_runner_file`, `set_env_`, `toJSON(github)` and `@actions/core` added to the pattern.

**Third pass (bccc066): 0 blocking, about 30 attempts.** It found a writer in a job's or workflow's `defaults.run.shell` not read (not verified that the runner runs such a shell as written); fixed in 99e3058, which a fourth check confirmed (the two cases medium, the alias bomb 0.66 s against the base's 0.47 s, nothing else changed).

**Held:** `toJSON(env.X)` before it was refused, values breaking out of quotes, a multi-line value carrying a second command, letter case on hosted Linux, macOS and Windows and on unknown runners, the composite precedence of a step's `env`, YAML aliases of `script` and `with.run`, 28 odd or invalid expressions (no new error), 6,000 steps at parity.

**Stated limits (D-143):** a writer the checker cannot see (a script file the step runs, an action's own code or `pre:`) can set a name it takes as known, as for `$NAME` (D-139); a composite action's step that GitHub would run with the option stays medium; a 100 KB value read by eleven tools in one step costs what the same file written with `$V` costs (66 s against the base's 3.9 s for the expression, 51.6 s for `$V`).

## 2d.19d: an `env` written as one expression, in the lanes

Slice 2d.19d (#382, part (a) of what F-418 left in 2d.19; D-144). One Opus 5.5 sub-agent that wrote none of it reviewed it in three passes. It tried about 213 workflow forms, each against the base (`flagship` `03b3c9b`) and the change, with controls that have the agent's name written out. It also fuzzed 500,000 random lines against the one-try-per-piece search, and timed 23 cost cases. What GitHub does was read from its pages and #387, not run. The cases and scripts were in the review's scratch directory and are not kept; each fixed finding below is a test in `tests/test_env_scope_expression.py`, and the stated limits and known false errors are not all tests.

**First pass (8f336cd: an error for every such expression anywhere in a line, and `env: ${{ matrix.KEY }}` read through a written matrix, one table for each choice of mapping): 2 blocking, 103 forms, 11 cost cases.**

- **Cost.** Each table rebuilt the outer scopes on every reading. 4,000 workflow `env` entries under 256 matrix mappings over 300 steps took 121.9 s against 13.7 s; 60,000 entries over 5 steps took 1.73 GB against 127 MB. Past a cache capped at 64 scopes, an 88 KB file took 336 s against 17 s, and a 42 KB one gave 300 false ledger errors where the base gave none.
- **Ways past.** A local composite action under such a scope (stated, F-421); `$AGENT` (D-139's limit); a key YAML 1.2 reads otherwise (`0o7`) taken as settling a name.
- **False errors.** Readings multiplied across mappings (two references over 33 mappings past 1,024 readings); an agent lane no combination runs; one expression in one matrix value making the whole scope unread; every `echo`/`mkdir` line under such a scope (an existing OBAAF-GHA-010 test failed).

**Fixed by class (bf72ad0):**
- The matrix reading is gone. Every such scope is unread.
- Its value makes no reading, as a value of another context.
- The step is an error only where the value stands where a command's program goes.
- `0o7` settles nothing; a falsy value under `&&` is empty.
- The error names the nearest scope.

**Second pass (bf72ad0): 1 blocking, 83 forms, 30 controls, 9 cost cases.**

- **Ways past.** Program places the first check did not read, which the lanes read when the name is written out:
  - the shell's words (`if ...; then`, `do`, `!`);
  - another expression before it;
  - wrappers outside its list (`xvfb-run`, `strace -f`, `flock`, `find -exec`, `su -c`, `uv run`, `poetry run`, `watch`, `systemd-run`, `exec -a`, `docker exec`);
  - `bash --noprofile --norc -eo pipefail -c`, `pwsh -c`, `cmd /c`;
  - a redirection first.
- **False errors.** The first word of a line a backslash continues; quoted brackets and separators; a heredoc line; the idiom's program places.
- **Cost.** At parity.

**Fixed by class (4b7b66b):**
- The line is also tried with the probe as the name in the catalog's own patterns for an agent's command line, wherever they need a keyword after the name.
- The program place skips the shell's words and a redirection.
- A continued line is read joined only.

**Third pass (4b7b66b): 1 blocking, 27 new forms, 69 rerun, 3 cost cases.**

- **Cost.** The patterns with the probe backtracked quadratically over a run of spaces: a 12 KB line took 52.2 s against 0.4 s.
- **Ways past.**
  - Another expression's known value read as `x` (`xvfb-run ${{ env.AGENT }} ${{ env.F }} x` with `F: -p`).
  - A package's name (stated).
  - A PowerShell backtick or a cmd caret continuation.
  - A line break between the name and its keyword (stated).
- **The one-try-per-piece argument.** It held on 300,000 random lines; it rests on the patterns' shape.
- **False errors.** The class is any word followed by an agent's keyword (`psql -h ${{ env.H }} -p 5432`), not only an option before a subcommand (stated).

**Fixed by class (a067faf):**
- The keyword is searched for once in the rest of each piece, and the name's place is checked by hand: the 12 KB line takes 0.48 s against 0.44 s.
- A test holds every strict catalog pattern to the shape.
- Another expression that reads `env` is read as its first known value.
- Backtick and caret continuations are joined.
- The error says which place it found.

**Fourth pass (a067faf and the documents): 0 blocking, 9 forms, 300,000 random lines against the third pass's regex (no disagreement), 4 cost cases.** A copy of the rest of the piece for each probe grew with the square of probes side by side (40,000 in 1.15 s; a 960 KB line 15.5 s against 6.4 s); a bash line ending in a backtick hid the next line's Cline or Aider name; only the first known value of another expression is put in (stated); document corrections. **Fixed (the commit after 34de9c9):** what is before a probe is checked first and the rest is searched where it stands (960 KB, 6.5 s against 6.2 s); a joined line's next lines are read again on their own, at most 32 lines joined; the documents corrected.

**Held:**
- The fast path: JSON and `--lanes` byte-identical with the base on the 42 fixture workflows and on this repository.
- OBAAF-GHA-026: findings identical in all 236 case folders.
- Scope precedence, the cut at the nearest unread scope, and the ledger accounting of the new refusal (charged once for each cached key, as for `Unread`).
- Comparisons, `contains`, `!` and `&&` on such a value are not errors.

**Stated limits (D-144):**
- A value from such a scope that holds a whole command at another place in a line.
- A package's name.
- Cline's and Aider's names behind a wrapper the lanes do not know.
- A line break between the name's place and its keyword.
- A repository's own `agents.commands`.
- `$AGENT` (D-139).
- A local composite action's steps (left in 2d.19 with its item (b)).
- Another expression on the line read as its first known value only.
- **Known false errors:** quoted brackets and separators, a heredoc line, `command -v ${{ env.TOOL }}`, and any word from such a scope followed by an agent's keyword.

