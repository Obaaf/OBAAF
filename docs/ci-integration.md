# Run OBAAF in CI and before a commit

This page puts `obaaf check` in three places: a required check on every pull request, a SARIF report in GitHub code scanning, and a hook that runs before a commit. It also says what the exit status and the JSON and SARIF reports promise to a script that reads them.

It describes the code after release 0.3.0 (`0.4.0.dev0`). [What to pin](#what-to-pin) says what differs in 0.3.0.

## What to pin

Install the checker from OBAAF's own action, `Obaaf/OBAAF/actions/setup-obaaf`, pinned to a full commit SHA. The action installs OBAAF from the commit you pin, with every dependency taken from its `requirements.txt` by exact version and SHA-256 hash, as wheels only, into a virtual environment under `RUNNER_TEMP`. It then runs `pip check` and adds the environment to the `PATH` of the steps after it. It needs Python 3.10 or later; on macOS and Windows runners run `actions/setup-python` first, or give the interpreter in the `python` input ([the action](../actions/setup-obaaf/action.yml)).

Which commit to pin:

- **The release:** `5162a177955b4f18ba190d048862e66246b4af05`, the commit of tag `v0.3.0`. Its SARIF report carries no errors or notes, an `ignore` entry needs no owner, and a lane declaration that does nothing is a note rather than a finding ([upgrading.md](upgrading.md) lists every difference).
- **The code this page describes:** the examples below pin `a620b95cc18293f57ef385651354a43820dd32e6`, a commit on the integration branch `flagship` that reports `obaaf 0.4.0.dev0`. It is not a release: it was chosen because the session that wrote this page tested it.

Move the pin in a pull request of its own, as [upgrading.md](upgrading.md#how-to-upgrade) describes.

## Exit status and reports

Decide pass or fail from the exit status, not from the report's wording, which changes between versions. The status is the same for every output format:

| Status | Meaning |
| --- | --- |
| 0 | Nothing at or above `--fail-on` counts (a finding counts when it is new or when the checker cannot tell), no baseline entry at or above it is left without its finding, and every file was read |
| 1 | A finding at or above `--fail-on` is not accepted; or a baseline entry at or above it no longer matches a finding; or a file could not be read (whatever `--fail-on` says, `never` included) |
| 2 | The command could not run: an option, the configuration or a baseline is wrong, or there is nothing to check |

[From a report to a gate](from-report-to-gate.md) gives the full table and the path from reading the report to failing a build. `obaaf check . --lanes` is the exception: it lists and judges nothing, so a finding never changes its status, but a file `obaaf check` would report as an error is still 1 and a path with no workflow or Jenkinsfile is still 2.

Choose the format with `--format`, after `check` (`obaaf --format json` is a usage error, status 2), and write the report to a file with `--output FILE`:

```bash
obaaf check . --format json --output obaaf.json --fail-on medium
obaaf check . --format sarif --output obaaf.sarif --fail-on never
```

- **JSON** names its format, `obaaf-check/v0.1`. Each entry under `findings` has `rule`, `path`, `line`, `severity`, `state`, `message` and `fix`, among other fields. `errors` lists what the checker could not read, and `notes` adds context. The fields added since 0.3.0 are listed in [upgrading.md](upgrading.md#what-a-script-that-reads-the-output-will-notice). Since 0.3.0 every top-level field and every field of a finding has been kept under the same format name, and fields have been added; the entries under `baseline.stale` changed (they are the baseline's own entries, so with a converted baseline they have no `fingerprint` or `message`). Nothing yet promises what the next version keeps.
- **SARIF** is version 2.1.0. Findings are under `runs[0].results`. What the checker could not read is an error under `runs[0].invocations[0].toolExecutionNotifications`, with `executionSuccessful: false`.

**GitHub code scanning does not show the notifications.** Going by GitHub's page on its SARIF support, a file the checker could not read, the accepted-risk total and the expiry warnings do not appear there, and an accepted finding is an open alert like any other ([the checker's guide](checker-configuration.md#the-report-begins-with-the-accepted-risk) has the details; no upload has been made to check it). So keep the step that runs `obaaf check` able to fail: that is where an unread file shows.

To see a failing check from a clone of OBAAF:

```bash
obaaf check tests/fixtures/workflows/risky/agent-lane-misspelled.yml --format json --fail-on medium
```

Status 1. Both formats report `OBAAF-GHA-001` at line 10 and `OBAAF-CFG-001` at line 14, and `tests/test_ci_integration.py` checks that the JSON and SARIF reports of a failing gate name the same findings at the same lines.

## A required check in GitHub Actions

Use OBAAF's template [`obaaf-pipeline-check.yml`](../templates/github-actions/workflows/obaaf-pipeline-check.yml). Below it is word for word, with its placeholder `uses:` line replaced by the pin above; a test keeps the two the same. Save it as `.github/workflows/obaaf-pipeline-check.yml`.

What it does:

- **It runs on every pull request and on pushes to `main`**, with a read-only token and without keeping the checkout's credentials.
- **On a pull request it reads the checker configuration from the branch the pull request targets** (`.github/obaaf.yml`, `.github/obaaf.yaml` or `obaaf.yml`, the first that exists, as the checker chooses), so a pull request cannot accept its own findings by editing the configuration. It runs again when a pull request is moved to another target branch (the `edited` event, which also fires on a change to its title or description; a first-time contributor's run may then need approval again). The configuration must be a regular file there: the step cannot follow a link, and fails if it finds one. It can still edit the workflow file itself: require a code owner's review for `.github/` (the template's [CODEOWNERS example](../templates/github-actions/CODEOWNERS.example)).
- **The job writes the SARIF report without failing on findings, then runs the gate** at `--fail-on medium`, and keeps the report as an artifact for 14 days. A file the checker cannot read fails the job at the first command.
- **The `upload` job is off until you set the repository variable `OBAAF_UPLOAD_SARIF` to `true`.** It then sends the report of each push to `main` to code scanning, under the category `obaaf`. Code scanning on a private repository needs GitHub Advanced Security.
- **To require it**, wait for one run, then add the check `check` to the branch's ruleset. That is the job's id; if another workflow also has a job `check`, give this one a `name:` first, so the name you require is not shared. The template has no `merge_group` trigger: with a merge queue, add one, or the required check never reports there. A `merge_group` run reads the configuration in the queued change, as a push does; only the pull-request run reads the target branch's.

If you use a baseline, add `--baseline .github/obaaf-baseline.json` to both `obaaf check` lines. The template does not read the baseline from the target branch: a pull request that edits it needs the same review as one that edits the workflow. On a pull request the configuration is read from a copy outside the repository, so a finding reported in the configuration file itself (`OBAAF-CFG-001`, a lane declaration that does nothing) has another path there than on a push, and a baseline entry for it matches on one and not the other: correct such a declaration rather than accept it.

```yaml
# OBAAF pipeline check (FR12).
#
# Runs `obaaf check` on every pull request and on pushes to main, so a change
# that opens a documented attack path (a secret in an untrusted workflow, a
# write token in an agent job, a cache shared with the release lane, an
# unpinned action, hidden characters in an agent instruction file) fails
# before it merges. The check runs locally on the runner and sends nothing to
# OBAAF or anyone else. On a pull request, the checker configuration (lane
# declarations and ignore entries) comes from the branch it targets, so a pull
# request cannot loosen the configuration. A pull request can still edit this
# workflow file; code-owner review of .github/ is what stops that.
name: OBAAF pipeline check

on:
  pull_request:
    # edited: a pull request moved to another target branch is checked again against that branch.
    types: [opened, synchronize, reopened, edited]
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  check:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Check out the repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      # A pull request cannot bring a directory of its own for the step below to read.
      - name: Remove any .obaaf-base the pull request brings
        if: github.event_name == 'pull_request'
        run: rm -rf .obaaf-base

      # Every name the checker reads its configuration from, in its order.
      - name: Check out the checker configuration from the target branch
        if: github.event_name == 'pull_request'
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          ref: ${{ github.base_ref }}
          path: .obaaf-base
          persist-credentials: false
          sparse-checkout: |
            /.github/obaaf.yml
            /.github/obaaf.yaml
            /obaaf.yml
          sparse-checkout-cone-mode: false

      - name: Set up OBAAF
        uses: Obaaf/OBAAF/actions/setup-obaaf@a620b95cc18293f57ef385651354a43820dd32e6 # 0.4.0.dev0, not a release

      - name: Check workflows, code owners and agent instruction files
        run: |
          set -euo pipefail
          config=()
          if [ "$GITHUB_EVENT_NAME" = pull_request ]; then
            # The first that exists on the target branch, as the checker would choose; none is {}.
            echo '{}' > "$RUNNER_TEMP/obaaf.yml"
            for name in .github/obaaf.yml .github/obaaf.yaml obaaf.yml; do
              if [ -L ".obaaf-base/$name" ]; then
                echo "::error::$name on the target branch is a link, which this step cannot follow; make it a regular file"
                exit 1
              fi
              if [ -f ".obaaf-base/$name" ]; then
                cp ".obaaf-base/$name" "$RUNNER_TEMP/obaaf.yml"
                break
              fi
            done
            rm -rf .obaaf-base
            config=(--config "$RUNNER_TEMP/obaaf.yml")
          fi
          obaaf check . "${config[@]}" --format sarif --output obaaf.sarif --fail-on never
          obaaf check . "${config[@]}" --fail-on medium

      - name: Keep the SARIF report
        if: always()
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: obaaf-check-sarif
          path: obaaf.sarif
          if-no-files-found: ignore
          retention-days: 14

  # Optional: show findings in the Security tab. Code scanning needs GitHub
  # Advanced Security for private repositories; set the repository variable
  # OBAAF_UPLOAD_SARIF to "true" to enable this job.
  upload:
    needs: check
    if: always() && github.event_name == 'push' && vars.OBAAF_UPLOAD_SARIF == 'true'
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
      security-events: write
    steps:
      - name: Download the SARIF report
        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1
        with:
          name: obaaf-check-sarif

      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2 # v4.38.2
        with:
          sarif_file: obaaf.sarif
          category: obaaf
```

**Turn on GitHub's own analysis too.** Where code scanning is available, enable CodeQL's default setup and check that GitHub Actions is among the languages it analyses ([GitHub's guide](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning)). It finds things in workflows that OBAAF does not look for; OBAAF's report sits beside it in the same view as a separate analysis ([uploading a SARIF file](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)).

## A hook before each commit

OBAAF has no hook definition of its own yet, so this uses a local hook in [pre-commit](https://pre-commit.com/) that runs the `obaaf` already on your `PATH`. Install the checker at the same commit in a virtual environment, and activate it before you commit:

```bash
python -m pip install 'obaaf @ git+https://github.com/Obaaf/OBAAF.git@a620b95cc18293f57ef385651354a43820dd32e6'
obaaf --version
python -m pip install pre-commit==4.7.0
```

Note that this install resolves OBAAF's dependencies at install time; only the action above installs them by hash.

`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: local
    hooks:
      - id: obaaf
        name: OBAAF pipeline check
        entry: obaaf check . --fail-on medium
        language: system
        pass_filenames: false
        always_run: true
```

Then run `pre-commit validate-config .pre-commit-config.yaml`, `pre-commit install`, and once `pre-commit run obaaf --all-files`.

- `pass_filenames: false` and the `.` in `entry` make the hook check the working tree, not only the files being committed. pre-commit sets aside unstaged changes to tracked files while hooks run, but untracked files stay, so an untracked `obaaf.yml` or baseline is read. Checked one at a time, a workflow would lose the lane declarations in `.github/obaaf.yml`, and a Jenkinsfile is matched by its file name only ([lane overrides](checker-configuration.md#lane-overrides)).
- `always_run: true` runs it even when no workflow changed, because a change to `.github/obaaf.yml` or `CODEOWNERS` can change the result.
- The hook reads your configuration, not the target branch's: it is for you, and the required check above is for the repository.

## What was run, and what was not

Run by the ChatGPT session that wrote the first version of this page (2026-11-14, Linux, Python 3.12): the action's install step, outside GitHub, with runner-style paths (`pip check` reported no broken requirements and the installed `obaaf --version` printed `0.4.0.dev0`); pre-commit 4.7.0 validating and installing the hook in a scratch repository, where it passed a clean workflow and failed with status 1 on the risky fixture, in two fresh environments.

Run by the review (run `stint`, 2026-11-14, Python 3.13): every exit status and report field on this page, from source at `flagship` `058cbfd` (between `a620b95` and it, the command line and the reports did not change; OBAAF-GHA-005's fifth control and the reading of runner labels did); `obaaf check` on the workflow above with a CODEOWNERS file (no findings at `--fail-on low`). The action itself runs on Linux, macOS and Windows in OBAAF's own CI (`setup-action` jobs). The pins are the template's; the review did not check them against GitHub.

Not run: this workflow on a GitHub runner (including the review's change to the template: the configuration read under all three names, and a pull request's own `.obaaf-base` removed; git's handling of the three patterns was checked locally), an upload to code scanning, a required check in a ruleset, actionlint on the workflow above (it could not be installed in the review's session), and pre-commit in the review's session (no access to PyPI).

## What is still missing

- **OBAAF has no hook definition of its own** (`.pre-commit-hooks.yaml`), and no test runs pre-commit; the tests read the hook's configuration only.
- **No promise about the JSON and SARIF formats.** OBAAF is 0.x, and the format name `obaaf-check/v0.1` did not change when the entries under `baseline.stale` did.
- **The template is the only workflow tested**: its check step is run with bash and a stand-in for `obaaf`, and nothing has run the workflow on GitHub with a pull request.
