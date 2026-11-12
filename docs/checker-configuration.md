# Checker configuration

`obaaf check` runs with no configuration. A repository can tune it with a file at `.github/obaaf.yml` (also read from `.github/obaaf.yaml` or `obaaf.yml` at the root), and with two environment variables set on a job.

## Telling the checker about your agents

The checker puts each job in every lane it belongs to (untrusted, agent, effect, release; a job in none of them is trusted) and runs each lane's rules on the jobs in that lane. A job that runs an agent and publishes is in the agent lane and in the release lane, and gets the rules of both. The agent controls run only on jobs in the agent lane. It recognizes an agent by the action a job `uses:`, or by an agent CLI in a `run:` script. The recognized actions and commands live in `src/obaaf/data/detection.yaml`.

The unreleased checker also reads repository `.sh` and `.bash` wrappers to find an agent CLI:

```yaml
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: bash scripts/run-agent.sh   # the agent starts inside the script
```

It can trace a simple copy in the same `run:` block back to the original repository directory, including a symbolic temporary path:

```yaml
      - run: |
          SNAPSHOT=$(mktemp -d)
          cp -r scripts "$SNAPSHOT/scripts"
          bash "${SNAPSHOT}/scripts/run-agent.sh"
```

This is best-effort static inspection. It does not execute shell code or read the
temporary destination. The copy source must be readable within the repository;
symlinks that escape it are not followed. Arbitrary variable assignments, fetched
or generated scripts, copies across separate steps, nested wrapper chains, and
complex shell control flow are not resolved. A copy alias means the source may
be executed; it is not proof of runtime reachability.

Always run `obaaf check . --lanes` and confirm that agent jobs are classified as
`agent` before relying on the findings. When the checker finds agent instruction
files (`AGENTS.md`, `CLAUDE.md`, and the like) but places no job in the agent lane,
it prints an advisory note. For wrappers it cannot resolve, declare the entry
point so the agent controls apply:

```yaml
# .github/obaaf.yml
agents:
  commands:
    - 'run-agent\.sh'          # a Python regular expression, matched against each run: line
  actions:
    - my-org/internal-agent    # a private action that runs an agent, matched as a uses: prefix
```

With that, the `triage` job above is placed in the agent lane, and the agent controls (for example a write token or a secret reaching the job) are reported.

You can also set the lane on a single job explicitly:

```yaml
jobs:
  triage:
    env:
      OBAAF_LANE: agent        # untrusted, agent, effect, release, or trusted
```

A declaration adds a lane. It never takes a job out of a lane the checker inferred, so it can add rules and cannot remove any: declaring `release` on a job that runs an agent leaves it an agent job and makes it a release job as well. Declaring `trusted` adds no lane and removes none; on a job the checker puts in a lane anyway, the reason shown for that lane ends with `declared trusted, which cannot override what the job does`. Case and surrounding space do not matter (`Agent` is `agent`).

`OBAAF_LANE` is read in a job's `env` and in the workflow's `env`, not in a step's. A declaration that does nothing is listed in the notes at the end of the report as ignored, never dropped without a word: a value that is not a lane (a misspelling, an expression, an empty value), or `OBAAF_LANE` on a step. `obaaf check . --lanes` prints the same notes.

When a job is in a lane both because of what it does and because it was declared, the declaration is the reason shown (`set by OBAAF_LANE`, `set in the checker configuration`).

## Lane overrides

```yaml
# .github/obaaf.yml
lanes:
  "release.yml#publish": release
```

A lane override only adds rules, like `OBAAF_LANE`: the job is put in the lane you name as well as the lanes the checker inferred, and if `OBAAF_LANE` names another lane the job is in that one too. A key without `#job` applies to every job in the file. Use the workflow path shown by `--lanes`, for example `.github/workflows/release.yml#publish`, when checking a repository root. The same key applies when you check that one file on its own (`obaaf check .github/workflows/release.yml --config .github/obaaf.yml`).

An entry that does nothing is listed in the notes as ignored: one whose value is not a lane, one that names a job or Jenkins stage the file does not have, and, when a repository is checked, one that names a file the checker did not read. `lanes:` itself must be a mapping; anything else is a configuration error and the check does not run.

`obaaf check . --lanes` shows the first lane a job is in, in the order agent, effect, release, untrusted, and names the others after it: `ci.yml#ship: agent (uses openai/codex-action; also release: uploads or publishes artifacts)`.

## Authority and hygiene

Every rule is one of two categories, reported separately in the summary and in the SARIF output (as `obaaf-category`):

- **authority**: who or what can change, build, release or sign, and the controls that bound an agent's authority. These are the findings to gate on first.
- **hygiene**: pinning and hardening. Today these are `OBAAF-GHA-008` (pin actions and images to a digest) and `OBAAF-GHA-020` (restrict agent egress). They matter, but they should not bury the authority findings, and a pilot does not need to clear every one to be a success.

Gate CI on one category with `--fail-on`:

```bash
obaaf check . --fail-on authority:medium   # fail only on authority findings at medium or above
```

`--fail-on` also accepts a plain severity (`high`, `medium`, `low`) or `never`. A bare category (`authority` or `hygiene`) means that category at low severity and above.

In the unreleased checker, GHA-008 stays high for agent, release and effect jobs.
It is low for other jobs only when their token permissions are explicit and
limited, no secrets are referenced, and no privileged outside event can start
them. Other jobs retain medium pinning findings. Low severity still recommends
pinning; `--fail-on low` includes these findings.

Informational findings are included in text, JSON and SARIF, but do not fail any
severity threshold. SARIF records use their actual reported severity; a rule's
documented default is not necessarily the severity of each occurrence.

<a id="protected-secrets"></a>
## Protected secrets

List the secrets that must never be available outside an environment. Anyone with write access can read a repository secret by pushing a branch with a new workflow, so these belong in an environment limited to the default branch ([GitHub settings](github-settings.md#secrets)):

```yaml
# .github/obaaf.yml
protected_secrets:
  PYPI_TOKEN: release          # must be used only by jobs in the `release` environment
  PRIVATE_SET_TOKEN: private-set
```

A plain list (`protected_secrets: [PYPI_TOKEN]`) accepts any declared environment. Names are case-insensitive and may use `*` and `?` globs, with at least three letters or digits (`*_API_KEY`, not `*_*`). When several entries match a secret, every one applies. OBAAF-GHA-024 is reported, at high severity, for every job that uses a listed secret without the named environment, including jobs that can take every secret (`toJSON(secrets)`, or `secrets[...]` with a computed index). Environment names compare case-insensitively, as GitHub does. An environment named by an expression is reported at medium, because the checker cannot tell which environment it will be.

A job that calls a reusable workflow (`uses:` at job level) cannot declare an environment. Passing it a protected secret is reported, with the advice to declare the environment in the called workflow's job instead. `secrets: inherit` is not reported, because it passes repository and organization secrets only, never an environment's.

The checker refuses a configuration with a setting it does not know, so a misspelt key such as `protected-secrets` cannot turn a rule off silently.

The rule checks the workflow files against what you declared. It cannot see that the secret has actually been removed from the repository and organization, or that the environment's deployment branches are limited, so check those in the settings.

<a id="baseline"></a>
## Adopting the checker without hiding regressions

A project that adopts the checker with existing findings usually starts in reporting mode (`--fail-on never`). Reporting mode lets new findings in unnoticed. A baseline keeps the existing findings visible while failing on anything new:

```bash
obaaf check . --write-baseline .github/obaaf-baseline.json   # record today's findings, once
obaaf check . --baseline .github/obaaf-baseline.json --fail-on low
```

With `--baseline`, a finding recorded in the baseline is still reported, marked `(baseline)` in text, `"baselined": true` in JSON and `baselineState: unchanged` in SARIF, but does not fail the check. Every other finding at or above `--fail-on` fails it. So does a baseline entry at or above `--fail-on` that no longer matches any finding: regenerate the baseline with `--write-baseline` and commit it, so the improvement is locked in and the finding cannot come back unnoticed.

Findings are matched on rule, severity, file, job, step and message, but not line number, so moving code does not churn the baseline. A finding that becomes more severe, or a job that receives an additional secret, no longer matches and counts as new. Findings already ignored by configuration are not written to the baseline, and neither are findings whose ignore entry has expired: renew or remove the entry instead. An entry for a finding that has since been given an ignore entry is not stale. Every entry's fingerprint is recomputed from its rule, severity, file, job, step and message when the baseline is read, and a baseline whose entry does not match is refused, so the text a reviewer reads is the finding that is accepted.

The baseline is a list of accepted risks, so review changes to it like changes to the workflows: put it under CODEOWNERS. A change that adds a line to the baseline is accepting a new finding, and the diff shows exactly which one. Prefer an `ignore` entry, with its reason and expiry, for a finding you have decided does not apply.

## When a finding does not apply

Suppress a finding you have reviewed with an expiring `ignore` entry. Every entry needs a rule, a path, a reason, and an `until` date, and the path may not match everything:

```yaml
# .github/obaaf.yml
ignore:
  - rule: OBAAF-GHA-013
    path: .github/workflows/ci.yml
    job: build
    reason: Reviewed fork selector and ephemeral runner lifecycle, see issue 42
    until: 2027-01-31
```

This is also how to record a reviewed runner pool without suppressing findings
for other jobs. In the unreleased checker, GHA-013 distinguishes:

- A known self-hosted pool, including a literal matrix containing one: high for
  untrusted or agent work.
- An unresolved expression explicitly naming both a standard hosted label and a
  self-hosted alternative: informational, because the selected runner is unknown.
- Other unknown labels or runtime inputs, such as `${{ inputs.runner }}`: medium.

The informational result does not certify a selector as fork-safe or a pool as
ephemeral. Verify where outside contributions execute and how the runner is
destroyed, then record evidence and a review expiry with an entry like the above.
Do not use an ignore entry merely to obtain a green check.

## Trying unreleased checker changes

PyPI 0.1.0 does not contain the changes described above, category-only gates, or
the earlier script-aware detection improvements. Use a separate environment and
install a reviewed, full Git commit SHA when piloting unreleased code:

```bash
python -m pip install "obaaf @ git+https://github.com/Obaaf/OBAAF.git@<reviewed-full-commit-sha>"
obaaf check . --lanes
obaaf check . --fail-on never
obaaf check . --fail-on authority:medium
```

Replace the placeholder with an actual reviewed commit. Until a version bump,
source installs still report `0.1.0`; record the source SHA as well as the version.
For GitHub Actions, `Obaaf/OBAAF/actions/setup-obaaf@<reviewed-full-commit-sha>`
installs that exact checkout using its dependency constraints. A new PyPI release
is a separate maintainer action after validation; these changes are not yet
published there.

## Jenkins

Jenkinsfiles use the same file. `jenkins.files` adds pipelines with other names (globs from the
repository root), `jenkins.exclude` leaves out test fixtures, `agents.steps` names shared-library
steps that run an agent, and lane overrides and ignore entries name a stage as `file#stage` and
`job: <stage>`. See [Jenkins](jenkins.md).

## Egress

`OBAAF_EGRESS` records the egress policy an agent job is meant to run under. It documents intent, it is not enforcement. See `OBAAF-GHA-020` and the agent lane templates for how egress is enforced.

## Reference

The full rule list, with the requirement and fix for each, is in [the pipeline checker rules](../spec/checker-rules.md).
