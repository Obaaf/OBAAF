# Checker configuration

`obaaf check` runs with no configuration. A repository can tune it with a file at `.github/obaaf.yml` (also read from `.github/obaaf.yaml` or `obaaf.yml` at the root), and with two environment variables set on a job.

## Telling the checker about your agents

The checker classifies each job into a lane (untrusted, agent, effect, release, or trusted) and runs the agent controls only on the jobs it places in the agent lane. It recognizes an agent by the action a job `uses:`, or by an agent CLI in a `run:` script. The recognized actions and commands live in `src/obaaf/data/detection.yaml`.

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

Inference wins when it is stricter: a job the checker already infers as agent, effect, release, or untrusted cannot be moved to a lane with fewer rules by `OBAAF_LANE` or by the config.

## Lane overrides

```yaml
# .github/obaaf.yml
lanes:
  "release.yml#publish": release
```

A lane override only adds rules: it can move a trusted job into a stricter lane, but it cannot take a job out of a stricter lane that inference chose. Use the workflow path shown by `--lanes`, for example `.github/workflows/release.yml#publish`, when checking a repository root.

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

## Egress

`OBAAF_EGRESS` records the egress policy an agent job is meant to run under. It documents intent, it is not enforcement. See `OBAAF-GHA-020` and the agent lane templates for how egress is enforced.

## Reference

The full rule list, with the requirement and fix for each, is in [the pipeline checker rules](../spec/checker-rules.md).
