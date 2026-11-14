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
| **2d.2b** | **What a job can reach: OBAAF-GHA-001, 003, 004, 005, 018, 024** | **2026-11-14** | `tests/test_reach_bypasses.py` |
| Still open | The rest of 2d.2: see [the plan](flagship.md) | | |

The rest of this page is tranche 2d.2b.

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
- *An environment that is not a name.* `environment: 010` matched a protected `"8"`; a blank name counted as declared. Now a number or true or false is unconfirmed only where it could be the wanted name, a blank or missing name is no environment (high), and a list or mapping is not a name (high). The third reviewer found that the first version of this fix lowered `environment: 1` from high to medium, and its second pass that `environment: 1` was still medium against a protected `"8"`; now the value is unconfirmed only where the wanted name is one of the names it may be (`010` may be `8`, `10` or `010`), read from the text as written. Text this reader keeps as text that a YAML 1.2 reader takes for a number (`0o10`, `1e3`) is treated the same way unless quoted.
- *Fact `via`* said only yes or no, so an acceptance of a caller passing `toJSON(secrets)` covered one with `secrets: inherit` (found by the third reviewer). Now it says which.

**Not fixed, stated as limits.** An environment named by an expression is never evaluated, even `${{ 'staging' }}` or a literal matrix, and stays medium. `environment: {name: release, deployment: false}` counts as `release`: GitHub says the job gets the environment's secrets and its reviewers still apply, and does not say whether its branch policy does. The checker never sees where a secret is stored or an environment's branch rule; `obaaf audit` reads those.
