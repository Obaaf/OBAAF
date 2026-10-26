# GitHub Actions templates

Reference workflows for OBAAF's four lanes, plus a pipeline check. They are drafts (version 0.1). They pass the offline tests, and `obaaf check` reports one finding for them, on purpose (see [Egress](#egress)). Run the [live acceptance tests](../../docs/live-acceptance-tests.md) in a sandbox repository before relying on them.

| Workflow | Lane | What it is designed to do | Requirements |
| --- | --- | --- | --- |
| [obaaf-untrusted-ci.yml](workflows/obaaf-untrusted-ci.yml) | Untrusted | Builds pull requests, including those from forks (partners should work from forks too), with a read-only token and no secrets, on fresh machines | G3.1, G9.1; FR3 |
| [obaaf-agent-propose.yml](workflows/obaaf-agent-propose.yml) | Agent | Runs an agent that reads only a labeled snapshot, with read-only access, no secrets, no OIDC and no caches, and outputs only a proposal; a separate job signs the agent-run record | R1–R3, R5–R8; FR7, FR9, FR10 |
| [obaaf-agent-apply.yml](workflows/obaaf-agent-apply.yml) | Effect | After a person approves who neither requested the work nor wrote the agent's inputs, verifies the agent-run record and checks the proposal, signs an approval record, then applies the proposal as a pull request from a separate job that holds write access but cannot sign | R4, R8; FR8 |
| [obaaf-release.yml](workflows/obaaf-release.yml) | Release (build) | Builds from a protected tag in isolation, without shared caches or credentials, and signs provenance and a build record in a separate job | G3, G4, G7.1; FR4, FR5, FR11 |
| [obaaf-publish.yml](workflows/obaaf-publish.yml) | Release (publish) | Runs from the default branch when a release build completes: verifies the release and shows the result, waits for a person to approve, verifies again with the approvals, then uploads | G6.1, G6.2, G7.2, G8.3; FR4, FR6 (G5.2 marked, not implemented) |
| [obaaf-pipeline-check.yml](workflows/obaaf-pipeline-check.yml) | - | Runs `obaaf check` on every pull request and push to main | FR12 |

## Install

From a clone of the OBAAF repository:

```bash
obaaf templates install --dest path/to/your/repository \
  --obaaf-repo OWNER/obaaf --obaaf-sha <full commit SHA of the OBAAF release> \
  --repository YOU/YOUR-GAME
```

This copies the workflows into `.github/workflows/`, pins the `setup-obaaf` action to that commit, and adds `.github/obaaf-policy.yaml`, `.github/obaaf.yml`, `.github/obaaf/agent.sh` and `obaaf-sources.yaml`. Until you install them, the templates contain the placeholders `OBAAF_OWNER` and an all-zero SHA, which `obaaf check` reports (`OBAAF-GHA-023`) so they cannot run by accident.

Then:

1. Copy [CODEOWNERS.example](CODEOWNERS.example) to `.github/CODEOWNERS` and replace the team names.
2. Apply [the repository settings](../../docs/github-settings.md): rulesets, the `v*` tag ruleset, the `obaaf-agent-apply` and `release` environments, and the fork pull-request settings. Check the [plan limits](../../docs/github-settings.md#plan-limits): for a private repository, the agent and release lanes need GitHub Enterprise Cloud.
3. Edit the build step in `obaaf-release.yml` (and the asset revision if your assets are not in Git), the upload step in `obaaf-publish.yml`, and the build step in `obaaf-untrusted-ci.yml`.
4. Declare your vendored components in `obaaf-sources.yaml` (or `vendored_binaries: none` if you vendor nothing) and create the manifest: `obaaf manifest create --components obaaf-sources.yaml --out obaaf-manifest.json`. With none, set `build_record.require_sdks: false` in `.github/obaaf-policy.yaml`.
5. If you use agents: replace `.github/obaaf/agent.sh` with your agent, following the contract in its comments, and set up the [inference proxy](../../docs/inference-proxy.md). Set the repository variables `OBAAF_MODEL_ENDPOINT` and `OBAAF_ALLOWED_LABELS`.
6. Run `obaaf check .` and fix anything it reports.
7. Copy [dependabot.yml.example](dependabot.yml.example) to `.github/dependabot.yml` so pinned SHAs stay current.

## How the lanes connect

- The agent lane runs when a maintainer labels an issue `agent`, or a collaborator comments `/agent`. That is cost control only: the agent still runs at the level of everything it reads.
- The effect lane starts when the agent lane completes. Its `approve` job waits for an approval in the `obaaf-agent-apply` environment. Then `obaaf verify agent-run` checks that the record is signed by the agent workflow on the default branch, covers exactly the proposal's files, and names the snapshot and run. The job then checks the proposal against the default branch with `obaaf proposal check --repo .`, signs an approval record, and assembles the agent record. Its `apply` job, which holds write access but no signing identity, checks that it has the same proposal and record, and opens a pull request containing the change and its record in `.obaaf/records/`.
- GitHub starts no workflows for a pull request that a job's own token opened, so the agent's pull request does not get its required checks on its own. A maintainer closes and reopens it to start them, which also shows that a person has looked at it. (Opening it with a GitHub App's token instead would start them, at the cost of a long-lived credential in the effect lane.)
- The release lane starts from a protected `v*` tag. When the build completes, `obaaf-publish.yml` runs from the default branch, so the policy it applies comes from reviewed files.
- The publish workflow's `verify` job checks provenance, the build record, that the released commit is on the protected branch, and every agent record since the policy's `agents.since` commit. It writes the result to the run summary.
- Its `publish` job waits for an approval in the `release` environment, runs the same checks with the approvals, and only then uploads.

## Isolation tiers

The build job runs on GitHub-hosted runners, which start every job on a fresh machine: Tier A. For targets that need your own persistent machines, change `runs-on` to your release-only runner labels and set `OBAAF_TIER: B` in the job's `env`. The build record then states Tier B, which is below SLSA Build Level 3, and the policy's `allowed_tiers` decides whether such builds may ship. A runner whose labels are not standard GitHub-hosted labels must declare its tier the same way.

## Egress

GitHub-hosted runners have no native egress allow-list, so the agent job declares its policy in `OBAAF_EGRESS` and can turn on a blocking runtime monitor (repository variable `OBAAF_EGRESS_MONITOR: harden-runner`, with `OBAAF_ALLOWED_ENDPOINTS`). Because the monitor is optional, `obaaf check` reports `OBAAF-GHA-020` (low) for the agent job until the policy is enforced. Enforce it by making the monitor unconditional, or by running the agent on ephemeral runners behind a network policy; in the second case, record that with an expiring ignore entry in `.github/obaaf.yml`.

## Other files

- [obaaf-policy.example.yaml](obaaf-policy.example.yaml): the policy `obaaf verify release` and `obaaf verify agent-run` read.
- [obaaf-sources.example.yaml](obaaf-sources.example.yaml): vendored components for the binary manifest.
- [obaaf.yml.example](obaaf.yml.example): checker configuration (lane overrides, extra agent patterns, expiring ignores).
- [agent/agent.sh](agent/agent.sh): the example agent, which calls no model.
