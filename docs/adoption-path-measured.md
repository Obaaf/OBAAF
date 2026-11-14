# Measuring the existing adoption path

Task 3.1, part of #82. Measured on 2026-11-13 UTC. This is a local adoption experiment, not a production deployment or a comparison of repository security.

## What was measured

The implementation checkout was `flagship` at `eca55a499920cd0ec843107a06963203bf9de613`. Its starting baseline passed: 1321 tests in 42.335 seconds, plus catalogue validation, generated-document validation, repository checking and site build. Adoption used a **separate fresh environment with the PyPI release 0.3.0**, not that development installation. The experiment followed README and docs from `main` at `9acb761025bb22422f6be5f190550c919cd4eec9`. No implementation source, flagship feature descriptions or knowledge from earlier tasks was used to repair the adoption route.

Machine: `Linux-6.18.57-x86_64-with-glibc2.41`, Python 3.12.14, 9 visible logical CPUs. `python -m pip install obaaf` completed in 13.566 seconds. The environment was new, but pip reused cached downloads; this is not a cold-cache benchmark. Installation time depends on the network, mirror, cache and machine.

Two targets were prepared in a previously empty experiment directory:

- **Minimal:** one hand-authored `.github/workflows/ci.yml`, shown below.
- **Public workflow copy:** the five tracked workflow files from `pallets/flask` commit `49943b5a94413a530761350f04e896f76e8d620e`: `lock.yaml`, `pre-commit.yaml`, `publish.yaml`, `tests.yaml`, `zizmor.yaml`. Only `.github/workflows` was copied. The source checkout was not changed. No AGENTS.md appeared in its tracked-file listing. Repository settings, scripts and application files were not included, so the findings are not a claim about Flask's live repository or its settings. (Corrected by the reviewing run: this sentence first said that missing ownership must not be attributed to the full repository; Flask has no CODEOWNERS file at that commit, and 0.3.0 gives the same seven findings on its whole tree.)

The target preparation and public-repository download are outside the timed command totals. Both targets reused the same fresh released-package environment. These are sequential observations, not independent installation trials. No target workflow or application code was executed.

## Time and effort observed

Times are subprocess wall-clock seconds measured with `time.time_ns()`. The raw logs retain exact argv, cwd, UTC start, duration and exit status. Totals below sum executed commands; they exclude reading, authoring, decisions, gaps between commands and target preparation. They do **not** estimate how long a person takes.

| Target | Install to first useful report, summed command time | Through workflow file written | Through local gate validation | Commands through local validation |
| --- | ---: | ---: | ---: | ---: |
| Minimal | 13.841 s | 14.392 s | 14.642 s | 11 |
| Flask workflow copy | 13.856 s | 14.363 s | 14.687 s | 10 |

Environment creation (A01) took 1.880 seconds and is separate from these installation-start totals. Both rows include A02-A04 once; do not add the rows as if two installations were performed. The first useful report is S01/F01: each named findings, locations and suggested fixes and exited 1. Success here means useful output, not a clean audit.

There were **3 hand-authored target-file instances**: one minimal fixture and one gate workflow in each target. The gate contents are identical, so there are 2 distinct authored contents. Five public workflow files were copied automatically. No baseline or OBAAF configuration file was created. The helper scripts and test harness are measurement infrastructure, excluded from those target-file counts.

The adoption decisions used **8 page consultations across 6 distinct documentation files**: README and From a report to a gate once each; adoption guide and checker configuration once each; GitHub settings and Upgrading twice each (a targeted search, then relevant text). Bulk export of docs and later citation verification are excluded from consultation counts. This is a count of this session's page retrievals, not user-effort research.

## Commands and results

`S` means the minimal copy, `F` the public workflow copy, and `A` shared environment setup. Paths are shortened below; the handover logs contain the exact originals. The entire file produced by the manual gate-write helper is the YAML shown later; it does not install a template or change repository settings.

| ID | Command | Seconds | Exit |
| --- | --- | ---: | ---: |
| A01 | `python3 -m venv $AUDIT/task31-release-venv` | 1.880 | 0 |
| A02 | `python -m pip install obaaf` | 13.566 | 0 |
| A03 | `obaaf --version` | 0.031 | 0 |
| A04 | `obaaf --help` | 0.033 | 0 |
| S01 | `obaaf check .` | 0.211 | 1 |
| S02 | `obaaf check . --fail-on never` | 0.225 | 0 |
| S03 | `obaaf check . --lanes` | 0.242 | 0 |
| S04 | `obaaf check . --write-baseline .github/obaaf-baseline.json --owner @example/build --reason 'Synthetic adoption measurement only' --expires 2027-03-31` | 0.030 | 2 |
| S05 | `obaaf templates install --dest . --obaaf-repo Obaaf/OBAAF --obaaf-sha 9acb761025bb22422f6be5f190550c919cd4eec9` | 0.035 | 2 |
| S06 | `python $AUDIT/task31-write-gate.py $AUDIT/task31-adoption/minimal` | 0.019 | 0 |
| S07 | `obaaf check . --fail-on medium` | 0.213 | 1 |
| S08 | `python -c 'import yaml; from pathlib import Path; d=yaml.load(Path('"'"'.github/workflows/obaaf-check.yml'"'"').read_text(),Loader=yaml.BaseLoader); assert d['"'"'on'"'"']==['"'"'push'"'"','"'"'pull_request'"'"']; assert d['"'"'jobs'"'"']['"'"'check'"'"']['"'"'steps'"'"'][-1]['"'"'run'"'"']=='"'"'obaaf check . --fail-on medium'"'"'; print('"'"'Workflow shape checked; gate has no continue-on-error'"'"')'` | 0.037 | 0 |
| F01 | `obaaf check .` | 0.226 | 1 |
| F02 | `obaaf check . --fail-on never` | 0.212 | 0 |
| F03 | `obaaf check . --lanes` | 0.249 | 0 |
| F04 | `obaaf check . --write-baseline .github/obaaf-baseline.json --owner @example/build --reason 'Synthetic adoption measurement only' --expires 2027-03-31` | 0.027 | 2 |
| F06 | `python $AUDIT/task31-write-gate.py $AUDIT/task31-adoption/flask` | 0.019 | 0 |
| F07 | `obaaf check . --fail-on medium` | 0.279 | 1 |
| F08 | `python -c 'import yaml; from pathlib import Path; d=yaml.load(Path('"'"'.github/workflows/obaaf-check.yml'"'"').read_text(),Loader=yaml.BaseLoader); assert d['"'"'on'"'"']==['"'"'push'"'"','"'"'pull_request'"'"']; assert d['"'"'jobs'"'"']['"'"'check'"'"']['"'"'steps'"'"'][-1]['"'"'run'"'"']=='"'"'obaaf check . --fail-on medium'"'"'; print('"'"'Workflow shape checked; gate has no continue-on-error'"'"')'` | 0.045 | 0 |

### Evidence from the runs

**A03**

```text
obaaf 0.3.0
```

**S01**

```text
.github/CODEOWNERS
     1  MEDIUM OBAAF-REPO-001  CI definition files have no code owner
        The repository has no CODEOWNERS file.
        Requirement: G1.1, G1.2, G8.2, R5
        Fix: Add CODEOWNERS rules for `/.github/workflows/` and every Jenkinsfile, and require code-owner review on protected branches (see templates/github-actions/CODEOWNERS.example).

.github/workflows/ci.yml
     9  LOW    OBAAF-GHA-008  Action or container not pinned to a full digest  [job build]
        Action 'actions/checkout@v4' is pinned to 'v4', not a full commit SHA.
        Requirement: G2.1, R6
        Fix: Pin the reference to a full 40-character commit SHA, or an image to its sha256 digest, and keep the version in a comment (for example `uses: actions/checkout@<sha> # v7.0.1`). Let Dependabot propose updates to the pin.

1 workflow file(s) checked.
Authority findings: 0 high, 1 medium, 0 low.
Hygiene findings: 0 high, 0 medium, 1 low.
```

**F01**

```text
        Fix: Run untrusted and agent jobs on GitHub-hosted or ephemeral runners, and keep persistent self-hosted runners for the release lane only.

5 workflow file(s) checked.
Authority findings: 1 high, 4 medium, 2 low.
Hygiene findings: 0 high, 0 medium, 0 low.
```

**S03**

```text
.github/workflows/ci.yml#build: trusted (default)
```

**F03**

```text
.github/workflows/lock.yaml#lock: trusted (default)
.github/workflows/pre-commit.yaml#main: untrusted (builds pull requests)
.github/workflows/publish.yaml#build: trusted (default)
.github/workflows/publish.yaml#create-release: release (uploads or publishes artifacts)
.github/workflows/publish.yaml#publish-pypi: release (uses the 'publish' environment)
.github/workflows/tests.yaml#tests: untrusted (builds pull requests)
.github/workflows/tests.yaml#typing: untrusted (builds pull requests)
.github/workflows/zizmor.yaml#zizmor: untrusted (builds pull requests)
```

**S04**

```text
usage: obaaf [-h] [--version]
             {assess,check,snapshot,manifest,proposal,attest,record,dsse,verify,templates,docs,catalog}
             ...
obaaf: error: unrecognized arguments: --owner @example/build --reason Synthetic adoption measurement only --expires 2027-03-31
```

**S05**

```text
error: templates not found in /workspace/scratch/567d2d60a102/task31-release-venv/lib/python3.12/templates/github-actions; run from a clone of the OBAAF repository or pass --source
```

**S07**

```text
        Fix: Pin the reference to a full 40-character commit SHA, or an image to its sha256 digest, and keep the version in a comment (for example `uses: actions/checkout@<sha> # v7.0.1`). Let Dependabot propose updates to the pin.

2 workflow file(s) checked.
Authority findings: 0 high, 1 medium, 0 low.
Hygiene findings: 0 high, 0 medium, 1 low.
```

**F07**

```text
        Fix: Run untrusted and agent jobs on GitHub-hosted or ephemeral runners, and keep persistent self-hosted runners for the release lane only.

6 workflow file(s) checked.
Authority findings: 1 high, 4 medium, 2 low.
Hygiene findings: 0 high, 0 medium, 0 low.
```

**S08**

```text
Workflow shape checked; gate has no continue-on-error
```

**F08**

```text
Workflow shape checked; gate has no continue-on-error
```

## Stumbles and where the documentation led

| Observation | Documentation | Result and consequence |
| --- | --- | --- |
| The main-branch baseline command does not run on the installed release. | [docs/from-report-to-gate.md:5](https://github.com/Obaaf/OBAAF/blob/9acb761025bb22422f6be5f190550c919cd4eec9/docs/from-report-to-gate.md#L5) says the commands are for code after 0.3.0 and that release lacks `--owner`, `--reason`, `--expires`; step 4 at lines 46–47 still requires them. | S04/F04 exit 2 with unrecognized arguments. This is an explicitly disclosed version gap, not an undocumented parser bug. The stable-install path cannot follow that acceptance sequence verbatim. No development upgrade or risk acceptance was substituted. |
| PyPI installation does not supply the template location the installer expects. | [README.md:70](https://github.com/Obaaf/OBAAF/blob/9acb761025bb22422f6be5f190550c919cd4eec9/README.md#L70) and [docs/adoption-guide.md:37](https://github.com/Obaaf/OBAAF/blob/9acb761025bb22422f6be5f190550c919cd4eec9/docs/adoption-guide.md#L37) tell the reader to install templates after installing the package. | S05 exit 2: templates not found under the venv. Its error directs the reader to a clone or `--source`. That is extra source acquisition outside the pip-only path; no template was installed. The supplied SHA is the pinned documentation commit, not a claim that it is a release tag. |
| The gate command and a ready CI workflow are different deliverables. | [docs/from-report-to-gate.md:87](https://github.com/Obaaf/OBAAF/blob/9acb761025bb22422f6be5f190550c919cd4eec9/docs/from-report-to-gate.md#L87) says configuration and workflow must be written by hand or installed from templates; [docs/upgrading.md:9](https://github.com/Obaaf/OBAAF/blob/9acb761025bb22422f6be5f190550c919cd4eec9/docs/upgrading.md#L9) says to pin the gate. | Authored a small workflow around the documented direct medium gate, pinned to the observed 0.3.0 release. The YAML wiring required manual authoring. This bypasses the unavailable template route, not a failing security check. |
| Both first reports include a missing-owner finding. | README's Quick start supplies `obaaf check path/to/your/repository`; the task calls for a copy of public workflows. | Both first reports include OBAAF-REPO-001 (no CODEOWNERS file). It is not an effect of copying only the workflows: Flask has no CODEOWNERS file at `49943b5`, and 0.3.0 run on Flask's whole tree at that commit gives the same seven findings as on the copy (checked by the reviewing run, which corrected this row). The findings are still not a claim about Flask's live repository or its settings. No owner was invented to silence them. |
| A gate file does not establish a protected merge gate. | [docs/github-settings.md:25](https://github.com/Obaaf/OBAAF/blob/9acb761025bb22422f6be5f190550c919cd4eec9/docs/github-settings.md#L25) requires status checks in repository settings. | Those settings were not changed or checked. Local gate commands return 1 on both targets, as expected for their existing findings. The prepared workflow would run a failing command if the same inputs and environment were used. No hosted run proves that conditional statement here. |

## Files prepared by hand

Minimal `.github/workflows/ci.yml`:

```yaml
name: Example CI
on: push
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          persist-credentials: false
      - run: echo example
```

The following `.github/workflows/obaaf-check.yml` was written into **both copies**. It is an experiment artifact, not a proposed change to either repository. The action pins were copied from the inspected Flask workflow snapshot; their execution was not tested. The OBAAF package pin follows the observed release and the upgrade guide. Python 3.12 is the tested interpreter choice. Hosted runner/setup compatibility is not established by this local check.

```yaml
name: OBAAF pipeline check
on: [push, pull_request]
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # pin observed in Flask snapshot
        with:
          persist-credentials: false
      - uses: actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # pin observed in Flask snapshot
        with:
          python-version: '3.12'
      - run: python -m pip install obaaf==0.3.0
      - run: obaaf check . --fail-on medium
```

S06/F06 timed writing the already-authored YAML, not thinking or typing it. S08/F08 parsed its structure and checked triggers and the final command. This is not actionlint or hosted GitHub validation. Their output also says there is no continue-on-error, but that property was established by inspecting the YAML, not by their assertions. The gate has no baseline, suppression or continue-on-error. Existing medium/high findings continue to fail it. No workflow was pushed, no repository was created and **no real CI run was made**.

## What this measurement does not establish

The documented acceptance-baseline route is blocked on released 0.3.0; a direct gate file was prepared instead, and remains red on these copies. That is not a claim of successful production onboarding. No first-time human, independent adopter, authenticated settings, model call, template execution, action execution or SARIF upload was measured. The small file and public workflow copy were different inputs, not a benchmark of OBAAF detection accuracy.

No product behavior or existing documentation was fixed. A later adoption slice can use the version gap, template-source requirement and manual workflow work as measured friction, then repeat the experiment. Do not turn the summed command times into an onboarding speed promise.

## Checked by the reviewing run (2026-11-14)

*Added by run `sandpiper`, which reviewed this page as `review-gpt` and did not write it, with a second check by a sub-agent that wrote neither the page nor this section.*

- **Reproduced without timings.** PyPI could not be reached from the reviewing session, so release 0.3.0 was built into a wheel from the tag `v0.3.0` and installed with `pip install --no-deps` into a new environment (Python 3.13.18) that took PyYAML and jsonschema from the system's packages. On the same two inputs (the minimal `ci.yml` above, and the five workflow files of `pallets/flask` at `49943b5`, fetched again), A03, S01 to S05, S07, S08, F01 to F04, F07 and F08 gave the exit statuses shown in the table, and the output shown above where the page shows it; only the environment's path in S05's message and the line-wrapping of S04's usage line differed. The two action pins in the gate file are those of Flask's workflows at that commit (`actions/checkout` v7.0.1 and `actions/setup-python` v7.0.0, by their comments there). No time on this page was measured again, and the wheel is not the file on PyPI.
- **What cannot be checked here.** The raw logs this page cites (its "raw logs" and "handover logs") are in the handover archive that the publishing session received and checked (85 files, `SHA256SUMS` all OK, per #140's description); they are not in this repository. Every number that only they hold is internally consistent and was not checked against them: the times, the 42.335 seconds of the first suite run, the 8 consultations of 6 files, and the 3 hand-written files with 2 distinct contents. The six summed times and the two command counts do add up from the command table.
- **Every link above** points at the cited line at `9acb761`, which is on `main`, and the line says what the table says it does.
- **Corrected in place by the reviewing run:** the sentence about the Flask copy under "What was measured" and the missing-owner row of the stumbles table. Both first said the missing-owner finding came from copying only the workflows; Flask has no CODEOWNERS file at `49943b5`, and 0.3.0 run on its whole tree at that commit gives the same seven findings as on the copy. Also "line 46" became "lines 46–47", where the options are.
- **One more stumble a stranger hits on the Flask copy.** Part of why F01 and F07 fail is a medium OBAAF-GHA-013 on `tests.yaml`, "Self-hosted runner used for untrusted work", for `runs-on: ${{ matrix.os || 'ubuntu-latest' }}`. Every value that expression can take is a standard GitHub-hosted label, so the finding is not real; a stranger has to work that out, and can keep it out of the exit status only by accepting it. `flagship` at `d74e6c9` still reports it: #141. This page shows only the last lines of F01, so it does not show which findings fail the gate.
- **One route the page did not try.** Release 0.3.0 has its own way to accept findings: `--write-baseline` without `--owner`, `--reason` and `--expires`, described in that release's `docs/checker-configuration.md` and in `obaaf check --help` (not in its README, the project page on PyPI); `main`'s `upgrading.md` at `9acb761`, which this page consulted, also describes the baseline it writes. On a copy of the minimal target it wrote a baseline whose two entries have no owner, reason or expiry, and `obaaf check . --baseline .github/obaaf-baseline.json` then ended with status 0 ("2 finding(s) accepted by the baseline, 0 new"). The code after 0.3.0, on `flagship` at `d74e6c9`, accepts nothing from that file ("0 finding(s) accepted by the baseline, 2 new", status 1) until it is migrated with `obaaf baseline migrate` ([upgrading.md](upgrading.md)). So "blocked" above means the sequence that [from-report-to-gate.md](from-report-to-gate.md) describes, not every route 0.3.0 has.
- **Still true on `flagship` at `d74e6c9`:** the package's data files do not include the templates (`pyproject.toml` lists `form_template.html` and the files under `obaaf/data`), so `obaaf templates install` after `pip install obaaf` still fails as in S05 (#142); and there is still no `obaaf init`. Slice 3.3 (`obaaf init`, with no file written by hand) is where the path should stop needing a clone, and 3.6 measures the path again.
- **The gate times are command times.** "Through workflow file written" is about 94% `pip install` and does not include writing the YAML, so it cannot be compared with the five and fifteen minutes that slice 3.6 aims at. The gate file's comments name where its pins came from, not their versions, which OBAAF's own OBAAF-GHA-008 fix text asks for.
