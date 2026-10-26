# Releasing OBAAF: PyPI and the GitHub Marketplace

*Runbook. Draft. Resolves part of D-011 (how studios obtain OBAAF).*

OBAAF is published to PyPI, so a team installs it with `pip install obaaf`. Publishing the `setup-obaaf` action to the GitHub Marketplace would further reduce friction, giving teams a listing they can discover. This runbook records the one-time PyPI setup and how to cut each release; the Marketplace listing is a separate maintainer action, not enabled automatically.

## Before the first release

- **License.** The license files (`LICENSE`, `LICENSE-docs`, `NOTICE`; see [LICENSING.md](../LICENSING.md)) must be in place; a package without a license should not go to PyPI.
- **Version.** `src/obaaf/__init__.py` holds `__version__`. It is `0.2.0`, the version this release publishes. Set it to the next release version (for example `0.3.0`) in the commit you tag, and back to a `.devN` afterwards. PyPI refuses to overwrite a version, so each release needs a new number.
- **Predicate type URIs (D-007).** Settled in 0.2: the in-toto predicate types and the generic build type live under `https://www.obaaf.com/`, and the site publishes a page at each type URI and each JSON Schema at its `$id`. A changed format gets a new version and a new URI.
- **Decide the scope.** The classifiers mark OBAAF as Alpha (`Development Status :: 3 - Alpha`): it is in active adoption, but it is 0.x and its formats may still change. Update the classifier when that changes.

## Part A — PyPI with trusted publishing (no stored token)

Trusted publishing lets GitHub Actions publish to PyPI using a short-lived OIDC identity, so there is no long-lived API token to leak — the same principle OBAAF applies to agents (R3).

**One-time setup (maintainer):**

1. Create the project on PyPI. The simplest path is a first manual upload, or configure a "pending" trusted publisher before the first run:
   PyPI → your account → *Publishing* → *Add a pending publisher* with: PyPI Project Name `obaaf`, Owner `Obaaf`, Repository `OBAAF`, Workflow name `release-pypi.yml`, Environment `pypi`.
2. In the GitHub repository, create an **Environment** named `pypi` (Settings → Environments) and add a required reviewer. This is the human gate before any upload.
3. Keep [`.github/workflows/release-pypi.yml`](../.github/workflows/release-pypi.yml) and [`.github/obaaf-policy.yaml`](../.github/obaaf-policy.yaml) on the default branch. Pin every action to a full commit SHA (R6); `obaaf check` fails on placeholders.

**Cut a release:** set the version, commit to `main`, and push a protected `v*` tag whose commit is on `main`. Prefer a tag push over `workflow_dispatch`: the policy's `source_refs` are `refs/tags/v*`, so a dispatch from a branch fails `obaaf verify release` after the `pypi` approval. For TestPyPI, dispatch **from the tag ref** and set the repository-url input. Configure the `pypi` environment with required reviewers, prevent self-review, and allow `v*` tag deployments so `approver_not_actor` means something. Residual vs the template release lane: this workflow does not set `cache-mode: none` (GitHub-hosted runners still start clean each job).

The live workflow: `build` builds and smoke-tests the wheel, checks `vendored_binaries: none`, and writes the unsigned build-record predicate; `attest` signs SLSA provenance and that build record with no package install (FR11); `publish` checks out the protected default branch (`fetch-depth: 0`), installs the reviewed CLI with `./actions/setup-obaaf` (never the candidate wheel), reads the run's environment approvals, and runs `obaaf verify release` against `.github/obaaf-policy.yaml` before uploading. That check covers provenance body, build record, `pypi` approvals (approver ≠ actor), github-hosted runners, and agent history. It is dogfood FR6, not full template-lane parity: there is no `workflow_run` publish half and no pre-approval summary job. Anyone can still inspect attestations with `gh attestation verify <file> --repo Obaaf/OBAAF`. After the first release that passes this gate, set `agents.since` in the policy to that commit's full SHA.

## Part B — GitHub Marketplace listing for `setup-obaaf`

The composite action in [`actions/setup-obaaf`](../actions/setup-obaaf/action.yml) installs the pinned toolchain in any runner. A Marketplace listing makes it discoverable.

1. The action already carries the `branding` (icon and color) the Marketplace requires.
2. Draft a GitHub Release for a tag (for example `setup-obaaf-v1.0.0` or the same `v0.1.0`). On the release form, check **Publish this Action to the GitHub Marketplace**, accept the agreement, and pick categories (Security, Utilities).
3. Teams then reference it **by the release commit SHA** (R6), not by `@v1`:
   `uses: Obaaf/OBAAF/actions/setup-obaaf@<sha> # v1.0.0`. The reference templates already expect a pinned SHA, and `obaaf templates install --obaaf-sha <sha>` fills it in. A floating `@v1` tag would contradict R6, so the listing's examples should show the pinned form.

## Pre-built binaries

Single-file binaries (PyInstaller, Nuitka) were suggested but are **not** recommended yet: every CI runner already has Python, so a wheel on PyPI serves the main use case; binaries add build, signing, and supply-chain surface that a two-person team should not take on before the pilot. Revisit only if non-CI, non-Python users appear.
