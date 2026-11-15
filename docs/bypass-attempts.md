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
| Still open | The rest of 2d.2: the Jenkins rules, the repository and instruction-file rules, the settings rules; see [the plan](flagship.md) | | |

The rest of this page is tranches 2d.2b, [2d.2c](#2d2c-what-a-run-checks-out), [2d.2d](#2d2d-triggers-scripts-and-release-jobs), [2d.2e](#2d2e-release-and-effect-jobs) and [2d.2f](#2d2f-pins-egress-and-declarations).

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

**Not fixed, stated as limits.** The repository's default token permissions are not read. An agent wrapped in a local composite action (`uses: ./.github/actions/x`) does not make the job an agent job: slice 2d.4.

### OBAAF-GHA-004 Agent job can request cloud credentials

**Got through, fixed.**

- *A called workflow that declares nothing* got no finding, though its caller can grant `id-token: write`. Now it is reported, case `inherited`.
- *`ID-TOKEN: write`* was a write scope to OBAAF-GHA-003 and nothing to OBAAF-GHA-004. Now a scope in another case counts as that scope (and the file fails the check).

**Not fixed, stated as a limit.** The checker takes the repository default never to include `id-token: write`.

### OBAAF-GHA-005 Secret available to an agent job

**Got through, fixed.**

- *The environment was not part of the finding.* An acceptance written for the agent job in `sandbox` covered it in `production`, where the same reference reads production's secret (an environment's secret takes precedence over a repository secret of the same name). Now the environment is a fact.

**Not fixed, stated as limits.** In a local reusable agent workflow, the finding names the secret parameter (`MODEL_KEY`), not the secret the caller maps onto it (`PROD_DEPLOY_KEY`), and the calling job is not an agent job, so changing the mapping raises nothing: slice 2d.4. Secrets that reach the agent through artifacts, caches, files or another job's outputs are not followed. `Secrets: inherit` with a capital S is not read (GitHub very probably rejects the key; not verified).

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

**Not fixed, stated as limits.** A local composite action given the head SHA (`uses: ./.github/actions/checkout-pr`), and a reusable workflow called from a `pull_request_target` workflow that checks out `github.event.pull_request.head.sha` or `inputs.ref`: the called workflow is read with its own trigger, `workflow_call`, and the caller has no steps. Both belong to slice 2d.4 (local reusable workflows and composite actions) and are in its entry. Values passed between steps through `GITHUB_ENV` or files are not followed. A line that names the pull request's code but runs a command the list does not name is not reported: reporting every use of a pull request's number would report every bot that comments.

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

**Got through, not fixed here:** a local reusable workflow called from a `pull_request` job runs on `self-hosted` with no finding in either file (attempt 027; slice 2d.4), and an agent CLI the checker does not know (attempt 041, `goose`, `cursor-agent`; slice 2d.5). **False positive kept:** a runner group used for GitHub's larger runners is high, because a group may hold either and the checker fails closed.

### OBAAF-GHA-015 Release workflow started by untrusted input

**Got through, now fixed.** Publishing the lists did not name (attempts 101 to 116, 184, 193): `gh release edit`, `gh api .../releases`, `git push --tags`, `aws` with options before `s3`, a command continued on the next line or with its name quoted, `docker buildx build --push`, `docker image push`, `pnpm -r publish`, `cargo +stable publish`, `createRelease(` in github-script, `scripts/release`, `firebase deploy`, `vercel --prod`, `curl -T`, a `docker://` step, `pypa/gh-action-pypi-publish` (which the first round of fixes counted only as a capability, at medium); environments named `live`, `prd`, `pypi`, `npm`, `crates`, `gh-pages`, `cd`; an environment built by `format` read as complete; and the release reason too general to identify the job (attempt 150: an acceptance for a registry inside the job covered `npm publish`), now with the release steps as facts. The skua classes: environments named by a matrix, the reason and environment not facts, and severity on `pull_request` against OBAAF-GHA-001's.

**Got through, not fixed here:** a local reusable workflow or composite action that publishes (attempts 026, 111; slice 2d.4); deploying with `id-token: write` and a cloud role (attempt 117, not verified; `id-token: write` alone is not counted, because it also signs and attests); `check_suite`, `check_run` and `status` as triggers (attempt 163, not verified; they are not in the list of events outsiders can cause for any rule, issue opened). **By design:** an environment named in plain text lowers the finding to medium (attempt 169), as for OBAAF-GHA-001; GitHub creates an environment that does not exist with no protection, which `obaaf audit` reads. **False positives kept:** a command named in an `echo` (185) and a push to a registry inside the job (146). **Fixed:** `kitchen`, `restore-drill`, `reproducibility`, `product-docs-preview`, `keystore`, `datastore` and `firestore` taken for release environments (`switch-matrix` still is: `switch` is a console a studio releases to) (a first fix read names word by word and lost `euproduction`, `prodeu` and `appstoreconnect`; the review of the slice found it, and names are again matched anywhere, with those words taken out first), and `SUBMODULE_DEPLOY_KEY` and `NODE_AUTH_TOKEN` taken for publishing secrets.

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

**False positives kept** (failing closed): the check and the upload in one step (166; the rule asks for an earlier step), `"obaaf" verify` with the name quoted (187), a check in a `docker://` step's arguments (182) or a local action (183, slice 2d.4), a check in a subshell `( ... )` (116, newly reported: write it without the parentheses), an `if:` on the check step that is always true for the workflow's triggers (159), and chains through a job with `if: always()` (174, 228, not verified). **Under stated limits:** whether the files verified are the files uploaded (148, 149).

### OBAAF-GHA-017 Release builds without provenance

**Got through, now fixed.** A provenance step that never runs or whose failure is ignored (190 `if: false`, 191 a job no trigger reaches, 192 `continue-on-error`), its text in a comment or an `echo` (193, 194), an attestation of an SBOM only (195 `actions/attest` with `sbom-path`, 196 `cosign attest --type spdxjson`), and "verified elsewhere" accepted from any verify text in the job, after the upload (198) or in an `echo` (200, which also lowered OBAAF-GHA-016 to medium). **Got through, not fixed here:** an attestation job that signs other files than the publishing job uploads and is not tied to it by `needs` (199), and an attestation job that needs a job with `if: false` (201); both are stated limits.

### OBAAF-GHA-022 Agent output applied without an approval gate, and OBAAF-GHA-014 Release job not behind a protected environment

Both took any value that was not empty for an environment. **Got through, now fixed.** A blank name (213, 215, 074, 075), an expression that can be blank (216, 221, 079, 080, 078, 110), a variable that may be unset (217, 083), a matrix with a blank value (222, 084), `${{ null }}` (223), an expression on the needed job (231), and a number or `true` (081, 219): an environment now counts only when its name is written as text, or as an expression whose every value the checker can list with none blank; anything else is "cannot tell" for 014 (kinds `blank`, `open`, `unreadable`) and no gate for 022. **Under a stated limit:** an environment with no protection rules (`environment: ci`, 082; `deployment: false`, 241, not verified): whether it has required reviewers is read by `obaaf audit`, not here.

**OBAAF-GHA-014, publishing the lists did not name.** Now an upload: `docker/build-push-action` and `docker/bake-action` with `push` true or set when the job runs (086), `svenstaro/upload-release-action` and `actions/upload-release-asset` (089), `mvn deploy`, `gradle publish`, `sbt publish` (091), `helm`, `oras`, `podman` and `crane` push (092), `aws s3api put-object` (093), `gh` with options before `release` (094), `semantic-release`, `changeset publish`, `goreleaser release` (095), `bun`, `jsr`, `vsce`, `ovsx`, `maturin`, `pdm publish` and `pod trunk push` (100), github-script `request('POST /repos/.../releases')` (098) and `uploads.github.com` (099). A release job with no upload the lists know is reported when it holds what publishing needs (`packages: write`, a publishing action, a secret whose name says it publishes; kind `capability`), so a deployment through `actions/deploy-pages`, `peaceiris/actions-gh-pages`, `aws-actions/...` or `azure/webapps-deploy` (087, 088, 090) is reported when the job is a release job. **Not counted as publishing, by design:** those deployments in a job that is not otherwise a release job (a documentation site is not a release unless declared one), `rsync`, `scp` and `rclone` (093), `skopeo` (092), dry runs and pushes to `localhost`, a script file (`./release.sh`, `make release`, 095), a command built from a variable (`$D push`, 104), a tag pushed by name (`git push origin v1.2.3`, 099), and a `docker://` step whose image pushes (097). **Got through, not fixed here:** a publish inside a local reusable workflow the release job calls (103, 034; slice 2d.4).

### OBAAF-GHA-006 Release job can read a shared cache

**Got through, now fixed.** Cache steps the closed list missed, or whose inputs it read as text: an action path with `..` (014, now read as the path it names, whether or not GitHub resolves it), a local composite action (015, taken to restore: it is not read, slice 2d.4), `actions-rust-lang/setup-rust-toolchain` (016), cache inputs written as expressions (017, 018, 019, 026) or all inputs as one expression (020), `oven-sh/setup-bun` (021), `pnpm/action-setup` with `cache` (022), `ccache` and `sccache` (023, 024), `docker/bake-action` with `type=gha` (025), `crazy-max/ghaction-github-runtime` and `--cache-from type=gha` in a script (028), github-script with the cache toolkit (029), `jdx/mise-action`, `magic-nix-cache-action` and `mlugg/setup-zig` (105). A release job that downloads artifacts from a job it needs that restores a cache (033), the Clinejection shape: now kind `needed-job-restores`. An acceptance of `actions/cache` with `lookup-only` that also covered `actions/cache/restore` (117) and an accepted low finding that covered steps added later (118): the facts now hold each step's name and the action that restores. **False positives fixed:** `lookup-only: true` (011) and a release job with `cache-mode: write-only` and no cache step (122). **False positives kept:** a cache step whose `if:` never lets it run (032, 111), and a called release job whose caller sets `cache-mode: none` (035, not verified; the checker does not see the caller). **Under stated limits:** a `docker://` cache client (031, not verified), a local reusable workflow that restores (034, slice 2d.4), and a self-hosted runner's local caches (040).

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

**Under stated limits** (now in the rule's description): a local composite action's own `uses` (015, slice 2d.4), impostor commits (a SHA that exists only in a fork of the repository), a tag named like a 40-digit SHA, and what a pinned action fetches when it runs.

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

A second pass, on the fixes, found the full suite green, Expectrail unchanged, every first-pass case answered, and three blocking findings, each fixed and tested: (1) `uses: ./` after any download was `local-after-download` (the top directory was empty, and the empty text is in every line); downloads before an action at the workspace root are now not read, and say so; (2) a top directory found inside a URL (`https://raw.githubusercontent.com/myorg/.github/...`) counted; only a workspace path at or under it counts now, or a clone of a repository of that name; (3) an agent behind `bash -c`, `sh -lc` in a `docker://` step, `sudo -u runner`, `nice -n 10` or `timeout -s KILL 5m` was in no lane: a shell's `-c` argument is read again as commands, and the values of a wrapper's options are skipped. Also from its non-blocking points: `run: $AGENT -p` with `env: {AGENT: claude}` is found (the step's env put into the script); the guide says configured agent patterns count only at the start of a command outside scripts. Kept, and stated: a line of free text that begins with an agent's name and the words its pattern needs (`aider and cline are supported` at the start of a release body) is read as a command; a cache path written as a glob, and a download's target on another line, are not followed. A third pass, on those fixes, found two blocking findings, fixed and tested: `git clone --depth 1 URL` and `git clone -b main URL` got past the clone check (an option's value was taken for a folder), so the values of git's value-taking options are skipped and `gh repo clone` is read the same way; and the step's env values put into its script were searched anywhere, so prose in an env value (`--notes "$NOTES"` with "works with aider and cline") made an agent job: the result is now read as commands, like an input. From its non-blocking points, a fetch and its target are paired within one command, not one line. Kept, and stated: only the step's own `env` is put into its script, and a fourth nested `bash -c` is not read. Found, outside this slice: a 105 KB `run:` of `claude ` repeated takes 23 s with the old checker and this one, in the catalog's agent patterns: issue #179.

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
