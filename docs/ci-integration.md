# Run OBAAF in CI and before a commit

Use `OBAAF CI gate` as the required status check. It scans the repository and exits at the selected threshold. The second job sends the default branch's OBAAF SARIF report to GitHub code scanning. The local hook runs the same gate before a commit.

## Install the checker at a known revision

The official composite action is `Obaaf/OBAAF/actions/setup-obaaf`. The example pins the tested flagship source at `a620b95cc18293f57ef385651354a43820dd32e6`, which reports `obaaf 0.4.0.dev0`. Review and update this pin deliberately. The action takes an optional `python` input, installs hash-checked wheels and its own checkout into a runner temporary environment, runs `pip check` and adds the executable directory to the next step's PATH. It needs Python 3.10 or later. For macOS and Windows runners, use a compatible interpreter supplied by setup-python first. See the [action definition](../actions/setup-obaaf/action.yml).

## Check results and exit codes

Use `obaaf check . --format json` for programmatic consumers and `obaaf check . --format sarif` for code scanning. Put the format option after `check`. Both `obaaf --format json` and `obaaf --format sarif` returned usage status 2. Use `--output FILE` to write the report to a file.

| Normal check exit | Observed input and interpretation |
| --- | --- |
| 0 | A clean workflow passed a medium gate. The risky fixture also returned 0 with `--fail-on never`. Read the findings even when the command succeeds. |
| 1 | The risky fixture failed a medium gate in both output formats. Malformed workflow YAML also returned 1 with `--fail-on never` and produced an error notification in SARIF. |
| 2 | Checking an empty directory reported no CI definitions. Incorrect command syntax also returned 2. |

These observations apply to ordinary report generation. See [From a report to a gate](from-report-to-gate.md) for baseline handling and the distinct behavior of listing lanes.

For a reproducible failure from this checkout, run:

```bash
obaaf check tests/fixtures/workflows/risky/agent-lane-misspelled.yml --format json --fail-on medium
obaaf check tests/fixtures/workflows/risky/agent-lane-misspelled.yml --format sarif --fail-on medium
```

The JSON report identifies its format as `obaaf-check/v0.1`. Its `findings` array includes `rule`, `path`, `line`, `severity`, `message` and `fix`. Inspect `errors` for unread inputs and `notes` for extra context. On this fixture, both formats reported GHA-001 at line 10 and CFG-001 at line 14 (full IDs start with `OBAAF-`). SARIF 2.1.0 places findings under `runs[].results` and tool diagnostics under `runs[].invocations[].toolExecutionNotifications`. The malformed input produced no results, `executionSuccessful: false` and an error notification with descriptor `not-read`. Keep the CLI gate and its logs available to reviewers. See the [checker configuration guide](checker-configuration.md) for which SARIF fields GitHub displays.

## GitHub Actions example

In a repository with code scanning available, enable CodeQL default setup and check that GitHub Actions is included among the languages being analyzed. OBAAF contributes a separate third-party analysis to the same code scanning view. The example runs the read-only gate on pushes and pull requests. Only the default-branch push job requests upload permissions. Its report step keeps the checker's exit code and lets the upload step attempt to publish an available diagnostic report even if parsing failed. After a hosted run, select `OBAAF CI gate` in branch rules. This example reads checker configuration from the revision under review. Require code-owner review for the workflow and checker configuration. The [existing pipeline template](../templates/github-actions/workflows/obaaf-pipeline-check.yml) reads target-branch configuration for pull requests and also contains an optional SARIF upload job. [GitHub default setup](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/configure-code-scanning/configure-code-scanning) and [uploading third-party SARIF](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

Example `.github/workflows/obaaf-check.yml`:

```yaml
name: OBAAF CI integration
on: [push, pull_request]
permissions:
  contents: read
jobs:
  check:
    name: OBAAF CI gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - uses: Obaaf/OBAAF/actions/setup-obaaf@a620b95cc18293f57ef385651354a43820dd32e6
      - run: obaaf check . --fail-on medium
  code-scanning:
    if: github.event_name == 'push' && github.ref == format('refs/heads/{0}', github.event.repository.default_branch)
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - uses: Obaaf/OBAAF/actions/setup-obaaf@a620b95cc18293f57ef385651354a43820dd32e6
      - id: report
        shell: bash
        run: |
          rc=0
          obaaf check . --format sarif --output "$RUNNER_TEMP/obaaf.sarif" --fail-on never || rc=$?
          if test -s "$RUNNER_TEMP/obaaf.sarif"; then
            echo 'written=true' >> "$GITHUB_OUTPUT"
          fi
          exit "$rc"
      - if: ${{ !cancelled() && steps.report.outputs.written == 'true' }}
        uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066
        with:
          sarif_file: ${{ runner.temp }}/obaaf.sarif
          category: obaaf
```

## Pre-commit example

Install the same checker in a local virtual environment and activate it before committing. For the revision above, use:

```bash
python -m pip install 'obaaf @ git+https://github.com/Obaaf/OBAAF.git@a620b95cc18293f57ef385651354a43820dd32e6'
obaaf --version
python -m pip install pre-commit==4.7.0
```

Example `.pre-commit-config.yaml`:

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

Run `pre-commit validate-config`, `pre-commit install` and `pre-commit run obaaf --all-files`. This system hook requires `obaaf` on PATH. `always_run: true` runs the repository check even when the changed files are outside workflow directories. `pass_filenames: false` keeps pre-commit's list of changed files out of the CLI arguments. Checking the root preserves repository configuration and lane paths. A separately checked Jenkinsfile is matched by filename only, and a standalone workflow may need an explicit `--config`. See [lane overrides](checker-configuration.md#lane-overrides).

## Validation boundary

On Linux, the action's actual Bash install step ran with local runner paths. It reported `No broken requirements found.` and the binary in the directory written to GITHUB_PATH returned `obaaf 0.4.0.dev0`. Pre-commit 4.7.0 validated and installed the example in a disposable Git repository. With that binary on PATH the hook passed a clean workflow and returned 1 after the risky fixture was staged. A second fresh environment installed the documented Git pin and pre-commit version. The hook returned 1 on the risky input and 0 on the clean input there too.

The workflow and hook above are proposed configuration. The report step also ran locally with runner-style paths. It wrote SARIF and marked it available for upload on both a finding and a YAML parse failure, with exits 0 and 1 respectively under the report-only threshold. Running the composite action on a GitHub runner, uploading SARIF, observing alerts, and requiring the check in branch rules remain hosted validation steps.
