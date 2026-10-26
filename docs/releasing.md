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
3. Add the workflow below as `.github/workflows/release-pypi.yml`, and **pin the publish action to an exact commit SHA** (R6) — replace the zeros with the SHA of a `pypa/gh-action-pypi-publish` release. The repository's own CI checker (`obaaf check`) will fail on an unpinned action or a left-over placeholder, which is the intended guard.

**Cut a release:** set the version, commit, and push a protected `v0.2.0` tag (or run the workflow by hand). The build job builds an sdist and a wheel with the hash-pinned backend and smoke-tests the wheel; the attest job signs their provenance; the publish job verifies that provenance and uploads them from the `pypi` environment after the reviewer approves.

```yaml
# .github/workflows/release-pypi.yml
# Publish OBAAF to PyPI with trusted publishing (OIDC) — no stored API token.
name: Release to PyPI

on:
  push:
    tags: ["v*"]
  workflow_dispatch:
    inputs:
      repository-url:
        description: "Index (blank = PyPI; https://test.pypi.org/legacy/ for TestPyPI)"
        required: false
        default: ""

permissions: {}

jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0
        with:
          python-version: "3.13"
      # Build with the pinned setuptools backend directly (PEP 517): no build
      # isolation, no extra dependency resolved at build time (R6).
      - name: Build sdist and wheel
        run: |
          set -euo pipefail
          python -m pip install --require-hashes --only-binary=:all: --requirement actions/setup-obaaf/requirements.txt
          rm -rf dist && mkdir -p dist
          python -c "import setuptools.build_meta as b; print(b.build_sdist('dist'))"
          python -c "import setuptools.build_meta as b; print(b.build_wheel('dist'))"
      - name: Smoke-test the wheel
        run: |
          set -euo pipefail
          python -m venv "$RUNNER_TEMP/clean"
          "$RUNNER_TEMP/clean/bin/python" -m pip install --require-hashes --only-binary=:all: --requirement actions/setup-obaaf/requirements.txt
          "$RUNNER_TEMP/clean/bin/python" -m pip install --no-deps dist/obaaf-*.whl
          "$RUNNER_TEMP/clean/bin/python" -m pip check
          "$RUNNER_TEMP/clean/bin/obaaf" --version
          "$RUNNER_TEMP/clean/bin/obaaf" catalog
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with: { name: obaaf-dist, path: dist, if-no-files-found: error, retention-days: 7 }

  attest:
    # Signs SLSA provenance for the built files in a job that runs no build code and
    # holds no PyPI identity (G7.1, FR11). OBAAF's own release follows its release lane.
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      id-token: write       # sign through GitHub's Sigstore; no long-lived signing key
      attestations: write
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with: { name: obaaf-dist, path: dist }
      - name: Sign SLSA provenance for the release files (G7.1)
        uses: actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8 # v4.2.2
        with:
          subject-path: dist/*

  publish:
    needs: [build, attest]
    runs-on: ubuntu-latest
    timeout-minutes: 10
    environment:
      name: pypi
      url: https://pypi.org/project/obaaf/
    permissions:
      id-token: write   # OIDC identity for trusted publishing; no stored token
      attestations: read  # read the provenance the attest job signed
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with: { name: obaaf-dist, path: dist }
      - name: Verify provenance before uploading (G7.1)
        # Uploads nothing unless every file has provenance signed by this workflow, for
        # this ref, on a GitHub-hosted runner.
        env:
          GH_TOKEN: ${{ github.token }}
        run: |
          set -euo pipefail
          for file in dist/*; do
            gh attestation verify "$file" --repo "$GITHUB_REPOSITORY" \
              --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release-pypi.yml" \
              --source-ref "$GITHUB_REF" --deny-self-hosted-runners
          done
      # PIN THIS before enabling (R6): replace the zeros with the exact commit SHA
      # of a pypa/gh-action-pypi-publish release, e.g. `@<sha> # vX.Y.Z`.
      - uses: pypa/gh-action-pypi-publish@0000000000000000000000000000000000000000 # pin to a release SHA
        with:
          packages-dir: dist
          repository-url: ${{ github.event.inputs.repository-url }}
          print-hash: true
```

After the first successful publish, the website quickstart and `README.md` use `pip install obaaf` (updated in this release). From 0.2, the release follows OBAAF's own release lane for provenance: a separate `attest` job, which runs no build code and holds no PyPI identity, signs SLSA provenance for every built file through GitHub's Sigstore, and the `publish` job uploads nothing until `gh attestation verify` confirms that provenance for each file, signed by this workflow for this ref on a GitHub-hosted runner. Anyone can check a downloaded file the same way: `gh attestation verify obaaf-0.2.0-py3-none-any.whl --repo Obaaf/OBAAF`.

From the empty-manifest work (D-033), the `build` job checks the repository's `vendored_binaries: none` claim and writes the unsigned build-record predicate; the `attest` job signs that predicate and SLSA provenance without installing the candidate wheel; `publish` runs `gh attestation verify` for both predicate types (signature, subject, signer, type — not predicate-body policy). Full `obaaf verify release` remains a later dogfood step.

## Part B — GitHub Marketplace listing for `setup-obaaf`

The composite action in [`actions/setup-obaaf`](../actions/setup-obaaf/action.yml) installs the pinned toolchain in any runner. A Marketplace listing makes it discoverable.

1. The action already carries the `branding` (icon and color) the Marketplace requires.
2. Draft a GitHub Release for a tag (for example `setup-obaaf-v1.0.0` or the same `v0.1.0`). On the release form, check **Publish this Action to the GitHub Marketplace**, accept the agreement, and pick categories (Security, Utilities).
3. Teams then reference it **by the release commit SHA** (R6), not by `@v1`:
   `uses: Obaaf/OBAAF/actions/setup-obaaf@<sha> # v1.0.0`. The reference templates already expect a pinned SHA, and `obaaf templates install --obaaf-sha <sha>` fills it in. A floating `@v1` tag would contradict R6, so the listing's examples should show the pinned form.

## Pre-built binaries

Single-file binaries (PyInstaller, Nuitka) were suggested but are **not** recommended yet: every CI runner already has Python, so a wheel on PyPI serves the main use case; binaries add build, signing, and supply-chain surface that a two-person team should not take on before the pilot. Revisit only if non-CI, non-Python users appear.
