# Checker configuration

`obaaf check` runs with no configuration. A repository can tune it with a file at `.github/obaaf.yml` (also read from `.github/obaaf.yaml` or `obaaf.yml` at the root), and with two environment variables set on a job.

## Telling the checker about your agents

The checker classifies each job into a lane (untrusted, agent, effect, release, or trusted) and runs the agent controls only on the jobs it places in the agent lane. It recognizes an agent by the action a job `uses:`, or by an agent CLI in a `run:` script. The recognized actions and commands live in `src/obaaf/data/detection.yaml`.

A job that launches an agent indirectly, for example through a wrapper script, is not recognized, so its agent controls do not run:

```yaml
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - run: bash scripts/run-agent.sh   # the agent starts inside the script
```

When the checker finds agent instruction files (`AGENTS.md`, `CLAUDE.md`, and the like) but places no job in the agent lane, it prints an advisory note. Declare the entry point so the agent controls apply:

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

A lane override only adds rules: it can move a trusted job into a stricter lane, but it cannot take a job out of a stricter lane that inference chose.

## Authority and hygiene

Every rule is one of two categories, reported separately in the summary and in the SARIF output (as `obaaf-category`):

- **authority**: who or what can change, build, release or sign, and the controls that bound an agent's authority. These are the findings to gate on first.
- **hygiene**: pinning and hardening. Today these are `OBAAF-GHA-008` (pin actions and images to a digest) and `OBAAF-GHA-020` (restrict agent egress). They matter, but they should not bury the authority findings, and a pilot does not need to clear every one to be a success.

## When a finding does not apply

Suppress a finding you have reviewed with an expiring `ignore` entry. Every entry needs a rule, a path, a reason, and an `until` date, and the path may not match everything:

```yaml
# .github/obaaf.yml
ignore:
  - rule: OBAAF-GHA-013
    path: .github/workflows/ci.yml
    reason: Runner pool is ephemeral, see issue 42
    until: 2027-01-31
```

This is also how to handle a runner the checker cannot evaluate. `OBAAF-GHA-013` cannot see the value of a `runs-on` that resolves at run time (for example an expression selecting between a GitHub-hosted and a self-hosted runner), so it reports such a job at medium severity. If you confirm the resolved runner is GitHub-hosted or ephemeral, record that with an `ignore` entry as above.

## Egress

`OBAAF_EGRESS` records the egress policy an agent job is meant to run under. It documents intent, it is not enforcement. See `OBAAF-GHA-020` and the agent lane templates for how egress is enforced.

## Reference

The full rule list, with the requirement and fix for each, is in [the pipeline checker rules](../spec/checker-rules.md).
