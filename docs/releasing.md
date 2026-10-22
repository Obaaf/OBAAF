# Releasing OBAAF: PyPI and the GitHub Marketplace

*Runbook. Draft. Resolves part of D-011 (how studios obtain OBAAF).*

Today a team installs OBAAF from the repository (`pip install git+https://github.com/Obaaf/OBAAF`). Publishing the CLI to PyPI and the `setup-obaaf` action to the GitHub Marketplace removes that friction: `pip install obaaf`, and a Marketplace listing teams can discover. Both are maintainer actions with one-time setup; this runbook has the exact steps. Neither is enabled automatically.

## Before the first release

- **License.** The grant (D-003) must be in place; a package without a license should not go to PyPI.
- **Version.** `src/obaaf/__init__.py` holds `__version__`. It is `0.1.0.dev0`. Set it to the release version (for the first public draft, `0.1.0`) in the commit you tag, and back to a `.devN` afterwards. PyPI refuses to overwrite a version, so each release needs a new number.
- **Predicate type URIs (D-007).** The in-toto predicate URIs use the reserved `obaaf.example` domain. They do not block a `0.1.0` tool release, but decide them before any attestation format is called stable.
- **Decide the scope.** A `0.1.0` release is a pre-alpha draft (the classifiers already say so). That is honest and still lets people `pip install obaaf`.

## Part A — PyPI with trusted publishing (no stored token)

Trusted publishing lets GitHub Actions publish to PyPI using a short-lived OIDC identity, so there is no long-lived API token to leak — the same principle OBAAF applies to agents (R3).

**One-time setup (maintainer):**

1. Create the project on PyPI. The simplest path is a first manual upload, or configure a "pending" trusted publisher before the first run:
   PyPI → your account → *Publishing* → *Add a pending publisher* with: PyPI Project Name `obaaf`, Owner `Obaaf`, Repository `OBAAF`, Workflow name `release-pypi.yml`, Environment `pypi`.
2. In the GitHub repository, create an **Environment** named `pypi` (Settings → Environments) and add a required reviewer. This is the human gate before any upload.
3. Add the workflow below as `.github/workflows/release-pypi.yml`, and **pin the publish action to an exact commit SHA** (R6) — replace the zeros with the SHA of a `pypa/gh-action-pypi-publish` release. The repository's own CI checker (`obaaf check`) will fail on an unpinned action or a left-over placeholder, which is the intended guard.

**Cut a release:** set the version, commit, and push a protected `v0.1.0` tag (or run the workflow by hand). The build job builds an sdist and a wheel with the pinned backend and smoke-tests the wheel; the publish job uploads them from the `pypi` environment after the reviewer approves.

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
          python -m pip install --constraint actions/setup-obaaf/constraints.txt setuptools
          rm -rf dist && mkdir -p dist
          python -c "import setuptools.build_meta as b; print(b.build_sdist('dist'))"
          python -c "import setuptools.build_meta as b; print(b.build_wheel('dist'))"
      - name: Smoke-test the wheel
        run: |
          set -euo pipefail
          python -m venv "$RUNNER_TEMP/clean"
          "$RUNNER_TEMP/clean/bin/python" -m pip install --constraint actions/setup-obaaf/constraints.txt dist/obaaf-*.whl
          "$RUNNER_TEMP/clean/bin/obaaf" --version
          "$RUNNER_TEMP/clean/bin/obaaf" catalog
      - uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with: { name: obaaf-dist, path: dist, if-no-files-found: error, retention-days: 7 }

  publish:
    needs: build
    runs-on: ubuntu-latest
    timeout-minutes: 10
    environment:
      name: pypi
      url: https://pypi.org/project/obaaf/
    permissions:
      id-token: write   # OIDC identity for trusted publishing; no stored token
    steps:
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with: { name: obaaf-dist, path: dist }
      # PIN THIS before enabling (R6): replace the zeros with the exact commit SHA
      # of a pypa/gh-action-pypi-publish release, e.g. `@<sha> # vX.Y.Z`.
      - uses: pypa/gh-action-pypi-publish@0000000000000000000000000000000000000000 # pin to a release SHA
        with:
          packages-dir: dist
          repository-url: ${{ github.event.inputs.repository-url }}
          print-hash: true
```

After the first successful publish, update the website quickstart and `README.md` from `pip install git+https://github.com/Obaaf/OBAAF` to `pip install obaaf`, and consider adding a signed Sigstore attestation of the built distributions (the release lane already signs provenance for game artifacts; the same `actions/attest` step can cover the Python distributions).

## Part B — GitHub Marketplace listing for `setup-obaaf`

The composite action in [`actions/setup-obaaf`](../actions/setup-obaaf/action.yml) installs the pinned toolchain in any runner. A Marketplace listing makes it discoverable.

1. The action already carries the `branding` (icon and color) the Marketplace requires.
2. Draft a GitHub Release for a tag (for example `setup-obaaf-v1.0.0` or the same `v0.1.0`). On the release form, check **Publish this Action to the GitHub Marketplace**, accept the agreement, and pick categories (Security, Utilities).
3. Teams then reference it **by the release commit SHA** (R6), not by `@v1`:
   `uses: Obaaf/OBAAF/actions/setup-obaaf@<sha> # v1.0.0`. The reference templates already expect a pinned SHA, and `obaaf templates install --obaaf-sha <sha>` fills it in. A floating `@v1` tag would contradict R6, so the listing's examples should show the pinned form.

## Pre-built binaries

Single-file binaries (PyInstaller, Nuitka) were suggested but are **not** recommended yet: every CI runner already has Python, so a wheel on PyPI serves the main use case; binaries add build, signing, and supply-chain surface that a two-person team should not take on before the pilot. Revisit only if non-CI, non-Python users appear.
