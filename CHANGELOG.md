# Changelog

All notable changes to OBAAF. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow semantic versioning: drafts are numbered 0.x, and version 1.0 follows the first pilot.

## [Unreleased]

### Project status

- OBAAF is no longer described as a public draft: version 0.1 is on PyPI and in active adoption with pilot teams. The website, README, CONTRIBUTING and docs say so, the README and CONTRIBUTING reflect the Apache-2.0 and CC BY 4.0 licenses already in `LICENSING.md`, and the package classifier moves from Pre-Alpha to Alpha (takes effect on PyPI with the next release).

### Checker: act on the first pilot's feedback (issue #19)

- Warn, with an advisory note that does not change the result, when a repository has agent instruction files but no job is classified into the agent lane, and when a job whose name suggests agent work stays in the trusted lane. This surfaces agents launched indirectly (for example through a wrapper script) that the lane inference misses.
- Document the existing `agents.commands` and `agents.actions` configuration, lane overrides, `OBAAF_LANE` and expiring `ignore` entries in [docs/checker-configuration.md](docs/checker-configuration.md), so an indirectly launched agent can be declared.
- Give every checker rule a category, authority or hygiene, and report the two separately in the text summary and the SARIF output (`obaaf-category`), so hygiene findings such as digest pinning do not bury authority findings.
- Add category gating to `--fail-on`: `--fail-on authority:medium` (also `hygiene:low`, or a bare `authority`) fails only on that category, so CI can gate on authority findings without first clearing every pinning finding. Plain `--fail-on high|medium|low|never` is unchanged.
- Note the dynamic `runs-on` limitation in OBAAF-GHA-013 and how to record a confirmed-safe runner with an expiring ignore entry.
- Detect agents launched through a repository script: a trusted job whose `run` step calls a repo script (for example `bash run-agent.sh`) that itself invokes an agent CLI is reclassified into the agent lane, so the agent controls apply. Best-effort, so scripts the checker cannot read still fall back to the advisory note.
- Flag findings that need an architecture change rather than a one-line fix (the agent and effect lane controls OBAAF-GHA-003, GHA-004, GHA-005, GHA-021 and GHA-022) in the text output and as `obaaf-remediation` in JSON and SARIF, pointing to the lane templates.
- Trace simple same-step copies of repository scripts to temporary locations back to their repository source for agent detection. This never executes shell code or reads outside the repository; complex shell flow and generated scripts remain unsupported.
- Report mixed hosted/self-hosted runtime selectors as informational uncertainty, retaining high findings for known self-hosted matrices and medium findings for other unknown runner labels or inputs.
- Lower GHA-008 to low only for ordinary jobs with explicitly limited permissions, no referenced secrets and no privileged outside trigger. Agent, release and effect jobs remain high; other jobs remain medium. SARIF rule metadata reflects the severities actually reported.
- Update first-adoption guidance with lane inspection and a commit-pinned path for trying unreleased code. These changes are not yet published to PyPI. Regression tests cover the runner and severity changes; pilot validation is pending. See [docs/roadmap-0.2.md](docs/roadmap-0.2.md).

### Licensing

- Prepare the license grant (D-003, Proposed): Apache License 2.0 for the code, templates, tools and tests; Creative Commons Attribution 4.0 International for the specifications, guides and documentation, including the data in `src/obaaf/data/`. Add `LICENSE`, `LICENSE-docs` and `NOTICE`; set the package's SPDX expression to `Apache-2.0 AND CC-BY-4.0` with `license-files` in `pyproject.toml` (needs setuptools 77 or later, satisfied by the pinned build backend). The grant takes effect when the maintainers accept D-003 by committing these files.

### Packaging and distribution

- Publish OBAAF to PyPI (D-011): version 0.1.0 is installable with `pip install obaaf`, built and published by a trusted-publishing (OIDC) release workflow ([docs/releasing.md](docs/releasing.md)). Add `branding` to `actions/setup-obaaf` for a future GitHub Marketplace listing. Defer pre-built single-file binaries.

### Public draft publication

- Authorize public repository access and the resource site on October 10, 2026; supersede the employer-approval prerequisite for that publication (D-002).
- Publish the resource guide and generated self-assessment with GitHub Pages, deploying from main after CI succeeds.
- Keep copyright notices, draft validation limits, and intended licensing status explicit. No research-paper submission is included.

### Repository validation

- Pin rpds-py to 0.30.0, which supports the Python 3.10 and 3.13 CI matrix.
- Document intentional deferred token expansion in the Git credential helper so workflow linting preserves its behavior.

### Added

- Version 0.1 draft of all five components, built from the two companion papers and the product specification:
  - the build-integrity profile: 28 requirements in nine families, each with a rationale, a pass-or-fail test, evidence and SSDF and SLSA mappings (FR1);
  - the agent controls R1–R8 with their traceability, GitHub realization and the agent-run record's fields;
  - the self-assessment: 34 items in four tiers, an offline scorer with ranked fixes, a printable checklist and an offline HTML form that cannot make network requests (FR2);
  - GitHub Actions templates for the untrusted, agent, effect and release lanes, and a pipeline-check workflow (FR3–FR11);
  - `obaaf check`, a pipeline checker with 26 rules mapped to the profile, text, JSON and SARIF output, expiring suppressions, and a test set of 13 risky workflows modeled on documented incidents (FR12);
  - `obaaf verify release`, which blocks an upload unless provenance, the build record, release approvals and every agent record since the policy's baseline verify, and the released commit is on the protected branch (FR6);
  - `obaaf verify agent-run`, which checks an agent run's signed record against the proposal and snapshot before the effect lane acts on them (R8, FR8);
  - record generators: `obaaf snapshot`, `obaaf attest agent-run|approval|build-record|slsa`, `obaaf record write`, `obaaf manifest create|check` and `obaaf proposal check`;
  - JSON Schemas for the agent-run, agent-approval and build-record predicates (FR10).
- Guides for every self-assessment item, GitHub settings, the inference-proxy contract, attestation formats, the architecture, live acceptance tests, and a traceability matrix from FR1–FR12 to tests.
- Project documents: decisions log, contributing guide, security policy and licensing status, and a glossary.

### Draft corrections

The following corrections are recorded in the draft. Remaining issues are listed below.

- `obaaf proposal check` reads the patch with Git as well as its own parser, decodes quoted file names, matches protected paths without regard to case, refuses renames, copies, unusual file modes and paths under names starting with `.`, and with `--repo` tests the patch against a temporary index. Four patch forms that previously reached protected files are now refused. The comment filter is stricter.
- The effect lane is split into an `approve` job, which verifies the agent-run record against every proposal file and the snapshot, and an `apply` job, which holds write access but cannot sign. Approvals by anyone who wrote the agent's inputs no longer count.
- Releases are published by a new `obaaf-publish.yml`, which runs from the default branch, verifies before the approval and again after it, and requires the released commit to be on the protected branch. Agent commits are checked from a baseline in the policy rather than from the previous tag.
- The release verifier fails closed on missing certificate fields, requires `source_refs`, ignores a bad extra attestation when a valid one exists, ties each agent record to the commit that adds it, checks it is used once, requires the exact approved diff by default, and checks the agent run's cache, environment and runner. Its `--gh-json` option is removed.
- The checker no longer lets a negated condition, a declared lane or a match-everything ignore entry hide findings, reports unknown runner labels, finds script injection written with index syntax or `toJSON`, treats GitHub Script artifact downloads as effect jobs, does not count a verification whose failure is ignored, and reports provenance-only checks and declared-but-unenforced egress.
- The setup action pins its build backend and installs `cryptography` for key-based verification. The snapshot's default floor is Public, and membership alone no longer raises a label. The binary manifest records symbolic links.
- The generated specifications keep the papers' qualifiers (for example "Build L3, for Tier A" and "PS.4 (draft 1.2)"). Status statements for FR3, FR4, FR7, FR10, FR11 and NFR3 now say what version 0.1 does not do. Guides for items 1.2, 1.6, 2.3, 2.5, 2.10, 3.3, 4.1 and 4.3 are corrected, and the employer-name test no longer contains the names.
- Second round: the checker now sees steps inside `parallel` groups, does not count a `background` verification as a gate, does not narrow triggers through jobs a `success() || …` condition can bypass, requires both checks for an effect job, and reports step forms it cannot read. The verifier compares an agent commit with the approved patch by applying the patch to the commit's parent, refuses other changes in the records directory, shallow clones, and a `--range` that overrides the policy's baseline, and no longer skips the protected-branch check when it lacks the release commit. More agent configuration files are protected. The documents say that the author has not yet reviewed version 0.1, what Free, Pro and Team plans can and cannot do, and that the agent's pull requests need to be reopened to start their checks.

### Still open after review

- Live acceptance tests: none has been run; they need a sandbox repository.
- Egress for agent jobs is declared but not enforced by default, and the inference proxy is not built (D-020).
- Models are not pinned by digest (FR10), and game binaries are not code-signed (D-031).
- A merge-review mode for the effect lane, and a key-signing release template, for private repositories without GitHub Enterprise Cloud (D-023).
- The proposal check's list of agent configuration files has to follow new agent products.
