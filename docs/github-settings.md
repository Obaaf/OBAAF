# GitHub settings for the OBAAF templates

## OBAAF repository review policy

Changes to OBAAF's `main` branch must go through a pull request. Sean Udeke
(`@seanudeke`) is the required code owner for all files, including
[CODEOWNERS](../.github/CODEOWNERS). Ofonna Nweze and Sean remain project
maintainers; the code-owner rule identifies the mandatory reviewer.

Require one approving code-owner review, dismiss approvals when new changes are
pushed, require approval of the latest push, and resolve review conversations.
Required CI checks must pass with the branch current. Apply protection to
administrators too, prohibit force pushes and branch deletion, and do not grant
review bypasses. After approval, a maintainer may merge the PR; Pages publishes
only after the merged revision passes CI.

GitHub does not let authors approve their own PRs. Sean-authored changes need a
separately agreed review policy; do not bypass this rule to merge them.

See the branch rule under repository Settings > Branches. The initial policy PR
must receive Sean's approval before it is merged.

The templates enforce what a workflow file can enforce. The rest lives in repository settings, which `obaaf check` cannot read. Set these before using the templates, and recheck them when the self-assessment asks for evidence. Menu names follow GitHub's documentation as of October 2026.

## Actions permissions

Under **Settings → Actions → General**:

| Setting | Value | Why |
| --- | --- | --- |
| Workflow permissions | Read repository contents and packages permissions | Jobs get only what their `permissions` block grants (G3.4) |
| Allow GitHub Actions to create and approve pull requests | On only if you use the agent effect lane, which opens pull requests | Without it, the effect lane cannot open its pull request. Require code-owner review on protected branches so a workflow cannot approve its way past review |
| Approval for running fork pull request workflows from contributors | Require approval for all external contributors | A first-time-contributor rule is easy to satisfy with one harmless merged change |
| Private repositories: send write tokens to workflows from pull requests | Off | Fork pull requests must get a read-only token (FR3) |
| Private repositories: send secrets to workflows from pull requests | Off | Fork pull requests must get no secrets (FR3) |

<a id="protect-release-branches"></a>
## Protect release branches and tags

Create a **ruleset** for the default branch and every release branch (Settings → Rules → Rulesets):

- Require a pull request before merging, with at least one approval (two at Tier 4, item 4.1).
- Dismiss stale pull request approvals when new commits are pushed.
- Require review from Code Owners, and approval of the most recent reviewable push.
- Require status checks to pass: the `check` job of `OBAAF pipeline check` and the `build-and-test` job of `OBAAF untrusted CI` (GitHub lists required checks by job name). The untrusted CI template runs on pull requests to `main`; add your release branches to its `branches` list if pull requests target them.
- Block force pushes and restrict deletions.
- Bypass list: empty. Keep emergencies to a documented, logged process.

Create a **tag ruleset** for `v*` that lets only release maintainers create, update or delete matching tags. The release template starts from these tags, so this rule decides who can start a release build. The publish workflow then requires the tagged commit to be on the default branch, so a tag on an unreviewed commit cannot be published (FR4).

Add `.github/CODEOWNERS` from [CODEOWNERS.example](../templates/github-actions/CODEOWNERS.example). It must name owners for workflows, the OBAAF policy and every agent instruction file (G1.2, G8.2).

## Environments

Create two environments (Settings → Environments):

| Environment | Used by | Required reviewers | Other settings |
| --- | --- | --- | --- |
| `obaaf-agent-apply` | the effect lane's `approve` job (`obaaf-agent-apply.yml`) | Maintainers who may approve agent proposals | Prevent self-review on; administrators may not bypass; deployment branches: the default branch only |
| `release` | the `publish` job (`obaaf-publish.yml`) | Release maintainers | Prevent self-review on; administrators may not bypass; deployment branches: the default branch only, because the publish workflow runs from it. Store the upload credentials here as environment secrets |

"Prevent self-review" stops the person who triggered a run from approving it. OBAAF also refuses to count approvals by anyone who started or re-ran the runs involved, and, for the effect lane, by the person who triggered the agent or anyone who wrote its inputs (R4). Only one required reviewer needs to approve an environment, so two-person release uses two environments in sequence (item 4.3, DECISIONS.md D-016).

## Secrets and variables

- Keep store upload credentials only as secrets of the `release` environment. Do not create repository or organization secrets that other workflows could read.
- Repository variables the templates read: `OBAAF_MODEL_ENDPOINT` (the inference proxy), `OBAAF_ALLOWED_LABELS` (labels an agent may propose), and optionally `OBAAF_EGRESS_MONITOR` and `OBAAF_ALLOWED_ENDPOINTS` (agent egress monitor) and `OBAAF_UPLOAD_SARIF`.

<a id="plan-limits"></a>
## Plan limits and compensating controls

Some controls depend on the GitHub plan and the repository's visibility. The details below come from GitHub's documentation as of October 2026; check them for your plan.

| Feature | Public repositories | Private repositories |
| --- | --- | --- |
| Rulesets and branch protection | All current plans | Pro, Team, Enterprise Cloud |
| Push rulesets that restrict file paths (R5) | - | Team and Enterprise |
| Environments and environment secrets | All current plans | Pro, Team, Enterprise |
| Required reviewers and self-review prevention on environments | All current plans | Enterprise only |
| Artifact attestations (`actions/attest`) | All current plans | Enterprise Cloud |
| `cache-mode` | GitHub.com | GitHub.com (not announced for GitHub Enterprise Server) |

**Branch protection on GitHub Free.** Rulesets, branch protection and required code-owner review are not available for private repositories on GitHub Free. Without them, items 1.6, 2.2, 3.7 and 4.1 cannot be enforced, and should be answered no; no OBAAF template can make up for that. The options are a paid plan or a public repository.

**What this means for version 0.1.** The agent and release templates need artifact attestations and environment reviewers. So for a private repository they need GitHub Enterprise Cloud; on the Free, Pro and Team plans, which many small studios use, they do not work:

- `obaaf attest approval` refuses to sign without an approval in the `obaaf-agent-apply` environment, and the attest steps cannot sign at all.
- What does work on every plan: the self-assessment, `obaaf check`, the untrusted-lane template, the binary manifest, and the pipeline check.
- For releases on those plans, sign the provenance and build record as DSSE envelopes with a key held in a cloud key service, set `signing: keys` in the policy, and run `obaaf verify release` before your upload. Version 0.1 has no template for this path.
- Without environment reviewers there are no approvals for the verifier to count, so `release.min_approvals` must be 0, or every release is blocked. The person's approval then has to come from the store: automation uploads only to a test or beta channel, and a person sets the build live there (item 1.3). Record this in the policy file with a comment, and answer items 4.3 and 3.2 from what is actually enforced.
- For agents on those plans, keep agents that read outside content out of private repositories until a merge-review mode for the effect lane exists (DECISIONS.md, D-023).

**Public repositories are signed in public.** For public repositories, GitHub signs attestations through Sigstore's public-good instance and records them in its public transparency log. Treat everything in an OBAAF record as public: the records hold digests, logins, labels and run details, never secrets, and nothing you would not publish should be put into them.
