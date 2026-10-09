## OBAAF version 0.1 draft

This pull request brings the first draft of the Open Build and Agent Assurance Framework into `main`. Merge it only after you have reviewed it. Nothing here is released or submitted until your employer approves in writing (D-002).

### What it contains

- **Specifications as data** (`src/obaaf/data/`), generated into `spec/`:
  - the game-pipeline integrity profile (28 requirements, Paper 2);
  - the self-assessment (34 items in four tiers);
  - the agent controls R1–R8 (Paper 1).
- **Self-assessment tools.** `obaaf assess` scores answers, and an offline HTML form makes no network requests.
- **Pipeline checker.** `obaaf check` has 26 rules and a test set of 13 risky workflows.
- **Release verifier.** `obaaf verify release` checks provenance, build records, approvals, the protected branch and every agent commit.
- **Agent checks.** `obaaf verify agent-run` and `obaaf proposal check` run before any agent output is applied.
- **GitHub Actions templates** for the untrusted, agent, effect and release lanes, plus a publish workflow that runs from the default branch.
- **Documentation:** guides for every self-assessment item, GitHub settings and plan limits, traceability, live acceptance tests and a glossary.

### How it was checked

- On 2026-10-07, the Windows/Python 3.13 run executed 217 tests and reported 6 failures and 14 errors. The failures involve Unix executable permissions, symbolic-link privileges, a Unix-style mock executable, and line-ending handling. Linux CI is required before claiming the full suite passes.
- All five documentation tests pass, including generated-file consistency, relative links and the confidential-name check.
- The catalog is consistent, and the repository workflow checker reports no findings.
- GitHub workflow linting remains part of CI; its result must be checked after upload.
- None of the live acceptance tests (`docs/live-acceptance-tests.md`) has been run yet.

### Action items and pending decisions

- **Decisions.** 24 entries in `DECISIONS.md` are marked *Proposed*. Accept, change or reject each one, and date it.
- **CODEOWNERS.** Set to `@Ofonna-N` in `.github/CODEOWNERS`. Enable code-owner review when repository settings permit it.
- **Open before release:** D-003 (copyright and affiliation), D-007 (predicate URIs) and D-011 (dependency hashes).
- **Licenses.** Confirm the intended licenses with your employer.

### Known gaps in 0.1

- Agent egress is declared but not enforced by default, and the inference proxy is not built yet.
- Models are not pinned, and game binaries are not code-signed.
- On private repositories, the agent and release lanes need GitHub Enterprise Cloud.


The companion papers are included as editable sources. The old preview PDF and original ZIP archives are excluded because they predate these edits. The papers have not been recompiled in this review.

## Linux CI result

[GitHub Actions validation](https://github.com/Ofonna-N/OBAAF/actions/runs/37713804088) passed for commit `4e679fd` on 2026-10-07. All 217 tests passed on both Python 3.10 and 3.13; workflow linting, the wheel build and smoke test, and the setup action also passed. The Windows-specific failures above remain documented.
