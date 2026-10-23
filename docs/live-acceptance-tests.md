# Live acceptance tests

The offline tests (`python -m unittest discover -s tests`) check the templates, the tools and the records without a network. Some acceptance criteria can only be shown on a real GitHub repository: that GitHub withholds secrets from a fork, that an environment waits for a reviewer, that a signature made in Actions verifies. These procedures cover them. None has been run yet. Run them in a sandbox before the templates are used for real releases, and again for each release of the templates.

## Setup

1. Create a **sandbox** repository that contains nothing confidential. Use a public repository on any plan, or a private one on GitHub Enterprise Cloud: required reviewers on environments and artifact attestations need one of the two ([plan limits](github-settings.md#plan-limits)).
2. Create a second GitHub account to act as the outside contributor, and a third (or a colleague) to act as the second maintainer.
3. Install the templates: `obaaf templates install --dest . --obaaf-repo OWNER/obaaf --obaaf-sha <commit> --repository OWNER/sandbox`, add `scripts/build.sh` (write a small file into `dist/`), `scripts/test.sh`, `scripts/publish.sh` (print the files instead of uploading), `obaaf-sources.yaml` with one component, and the manifest. Apply [the settings](github-settings.md).
4. Add a **canary**: a repository secret `CANARY_SECRET` and an environment secret `CANARY_RELEASE` in `release`, each a random string you can search for. A canary that appears anywhere it should not is a failure.
5. Record for each test: date, commit, run links, result, and screenshots of anything not in a log.

## Tests

| ID | Requirement | Procedure | Pass when |
| --- | --- | --- | --- |
| LAT-03 | FR3 | From the outside account, fork the sandbox and open a pull request whose build step prints every environment variable and runs `git push` to a new branch. | The untrusted CI run shows no canary value and the push is refused. With the fork-PR approval setting, the run waits for approval first. |
| LAT-04a | FR4 | Push a `v0.0.1` tag from a maintainer account; then try from an account outside the tag ruleset. | The first starts the release workflow; the second push is refused. |
| LAT-04d | FR4 | As a maintainer, tag a commit on a branch that was never merged (`v0.0.2`) and let the release build run. | The publish workflow's verify job blocks: the release commit is not on the protected branch. Nothing is uploaded. |
| LAT-04b | FR4 | On the default branch of the sandbox, add an `actions/cache` restore step to the release build job, then push a `v*` tag. Revert it afterward. | Nothing is restored from a cache another workflow wrote (record what the step reports); `obaaf check` reports OBAAF-GHA-006 for the job. |
| LAT-04c | FR4 | Inspect the build record of the release (`gh attestation verify dist/<file> --repo … --predicate-type …build-record/v0.1 --format json`). | `isolation.tier` is A and `runnerEnvironment` is github-hosted. |
| LAT-05 | FR5 | Run `gh attestation verify` on a released artifact for SLSA provenance and the build record. Then change one byte of the artifact and verify again. | The first verifies and names the source revision, asset revision, manifest digest, SDK versions, workflow and builder; the modified file fails. |
| LAT-06a | FR6 | Start a release, read the verify job's summary, approve the publish job, and let it run. | The summary shows the pre-approval result; `obaaf verify release` passes again with the approval and the upload step runs. |
| LAT-06b | FR6 | In the sandbox, change the publish job on the default branch to write an extra file into `dist/` just before the verifier, then release. Revert it afterward. | The verifier blocks: no provenance for the new file. The upload step does not run. |
| LAT-06c | FR6 | As an administrator, bypass the `release` environment's protection, if your settings allow it. | The verifier blocks: no qualifying approval. |
| LAT-06d | FR6 | Push a commit authored with the effect lane's identity (`OBAAF effect lane <obaaf-effect-lane@noreply.invalid>`) but without a record to the default branch, then release. | The verifier blocks: agent-path commit without a record. |
| LAT-06e | FR6 | After a normal release, push a branch whose copy of `obaaf-release.yml` also runs on that branch, so the branch produces provenance for an identical artifact. Then release again. | The verifier ignores the branch's provenance with a warning, because its ref is not in `source_refs`, and the release's own provenance still verifies. |
| LAT-07 | FR7 | From the outside account, open an issue whose body tries to make the agent print secrets and fetch an outside URL; have a maintainer label it `agent`. Use a test agent script that tries `env`, a request to an outside host, and a request for an OIDC token. | The agent job has no canary, no OIDC token (`ACTIONS_ID_TOKEN_REQUEST_URL` unset), and, with egress enforcement on, the outside request fails. The snapshot labels the issue body Public. |
| LAT-08a | FR8 | Let the agent produce a patch. Approve the effect lane as the person who triggered it. | GitHub refuses the self-approval. |
| LAT-08b | FR8 | Have the outside account open the issue, and add it as an environment reviewer for this test only; approve as that account. | `obaaf attest approval` refuses: the author of the agent's input cannot approve. |
| LAT-08c | FR8 | Approve as the second maintainer. Then close and reopen the pull request the effect lane opened. | The `approve` job verifies and signs; the `apply` job, which has no `id-token`, opens a pull request containing the change and `.obaaf/records/<digest>.json`; the agent job never had write permission. No checks start until the pull request is reopened; then the required checks run. |
| LAT-08d | FR8 | Make the test agent propose a change to `.github/workflows/` or `AGENTS.md`, the same change with an escaped file name (`"a/\101GENTS.md"`), and a comment containing a link. | `obaaf proposal check` fails and nothing is applied. |
| LAT-08e | FR8 | Make the test agent add a file to the proposal bundle after the attest job has signed it (for example, by uploading a second artifact from the agent job that the attest job does not read). | `obaaf verify agent-run` refuses: the record covers different files than the bundle. |
| LAT-09 | FR9 | Comment `/agent` on a pull request that edits `AGENTS.md` to add an instruction. | The agent run uses the default branch's `AGENTS.md`; the pull request's version appears only inside the snapshot's diff, labeled Public. |
| LAT-10 | FR10 | Download the agent-run record and validate its predicate: `obaaf` verifies it in the effect lane; also check it by hand with `gh attestation verify … --format json`. | It verifies against the agent workflow's identity, lists every input with digest and label, the read-only authority, the action digests and the proposal files. |
| LAT-11 | FR11 | Search the repository, the runners' environments (as printed by test steps) and the build logs for signing keys. | No long-lived signing key exists for attestations: they are signed through GitHub's Sigstore with the workflow identity, in jobs that run no build code. (Signing the game binaries is not part of version 0.1.) |
| LAT-12 | FR12 | In a separate throwaway repository with no secrets, no environments, and Actions limited to an allow-list that blocks third-party actions, open a pull request that adds each workflow in `tests/fixtures/workflows/risky/` under `.github/workflows/`. The fixtures model real attacks, and some would start runs. | The pipeline check fails and names each expected rule, its requirement and its fix. Do not merge it; delete the repository afterward. |

## Reporting

Keep the results with the release of the templates they tested. A failure is a bug in OBAAF or in the settings guide; file it, and record any change it causes in DECISIONS.md. If a test uncovers a flaw in GitHub or an agent product, report it to the vendor first (SECURITY.md).
