# Changelog

All notable changes to OBAAF. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow semantic versioning: drafts are numbered 0.x, and version 1.0 follows the first pilot.

## [Unreleased]

### Expressions

Several spellings that no rule reported are now reported. They were found by reading the checker and by an independent review of the first fix. None has been run on GitHub.

- **Secrets.** Secret references are read from an expression's tokens, not matched as text. `secrets.*`, and any other use of the `secrets` context that is not one literal name (for example `contains(secrets, 'x')`), counts as every secret (OBAAF-GHA-001, 005, 024). A secret referenced anywhere in a job is found, including in `outputs`; before, only `env`, `with`, `secrets`, `container`, `services` and `steps` were read.
- **Where an expression ends.** An expression is no longer cut short at a `}}` inside a string, as in `${{ format('}}{0}', secrets.KEY) }}`, which hid whatever followed from every rule that reads expressions.
- **OBAAF-GHA-010.** The rule keeps its text patterns and adds a second pass over the expression's tokens. It now follows a wildcard or computed index (`github.event.*.title`, `github.event.issue.*`, `github.event[inputs.kind].body`), a property of a group or of a function's result (`(github.event.issue).title`, `toJSON(github.event.issue || 1)`), `${{ env.NAME }}` when NAME is set from an outsider-written field, directly, through other env values or through the matrix, and `${{ matrix.x }}` when the job's matrix is built from such a field. It does not follow values set at run time (`GITHUB_ENV`), values passed between jobs or into reusable workflows and composite actions, scripts other than `run` and `actions/github-script`, an `env:` written as one expression that itself reads env or matrix values, or a `with:` written as one expression.
- **Files the checker cannot read are errors, which fail the check:** an expression nested more than 64 levels deep, a text with too many unfinished expressions, a file too large to read in the memory available, a value only an explicit YAML tag produces (`!!set`, `!!pairs`, `!!omap`, `!!binary`, or text under `!!null`), a job or step that is not a mapping, and a file containing U+0085, U+2028 or U+2029 (YAML readers disagree on whether these end a line).

Other changes in behaviour: any string given for `secrets:` on a reusable-workflow call counts as `inherit`; `secrets["KEY"]` (double quotes, which GitHub rejects) and an index that is not a name count as every secret; an expression with no closing `}}` is read to the end of its text; text inside a string, such as `format('secrets.KEY')`, is no longer mistaken for a secret reference (OBAAF-GHA-010 still reports a field named inside a string, as before). Because `obaaf attest` records the secrets a job can read and `obaaf verify release` checks that record, a job that names a secret only in a place that was not read before is now recorded as holding it. Findings for workflows that use none of these spellings are unchanged (checked on this repository's workflows, fixtures and templates, and on Expectrail).

### Settings audit

- New command `obaaf audit`: reads the GitHub settings that workflows depend on and records them in a snapshot file (`obaaf-settings-snapshot/v0.1`). It reads rulesets and who may bypass them, the rules in force on the default branch, classic branch protection, environments and which branches may deploy to them, the names of environment, repository and organisation secrets, Actions permissions, the workflow token's default permissions, approval for fork pull requests, Actions policies, and how many accounts hold each role. **It applies no rule yet**: it reports what the settings are, not whether they are right.
- Every setting is recorded as read, partly read, not read or not applicable. A setting that was not read is listed by name with the reason and with what GitHub's reference says a caller needs; it is never left out. An answer that does not have the documented shape is recorded as not read, not guessed at.
- Read-only by construction: the client sends GET requests and has no other verb. A token is taken from the environment (`GH_TOKEN`, `GITHUB_TOKEN` or `--token-env NAME`), never from the command line, is sent only to the API address the audit was started with, and is not written to any output. With no token the audit reads what GitHub shows anyone about a public repository and asks for nothing else.
- `obaaf audit --from-snapshot FILE` reports from a saved snapshot with no network. `--fail-on-unread` exits 1 when a setting that applies was not read in full. Reading nothing at all (repository not found, rate limited at the first request) exits 1.
- Tested from recordings written by hand from the examples in GitHub's REST reference, and against GitHub itself by a workflow in this repository with the workflow's own token and with no token. It has not been run with a token that can read the administrative settings. See [docs/settings-audit.md](docs/settings-audit.md).

### Protected secrets

- GHA-024 hardening, after an independent review: a computed secret index (`secrets[format(...)]`, `secrets[matrix.k]`) counts as every secret for all rules; the `secrets` context matches in any case; overlapping `protected_secrets` entries all apply; environment names compare case-insensitively; reusable-workflow callers get advice they can follow, and `secrets: inherit` is no longer reported; globs need three letters or digits; unknown configuration settings are refused. The published test set shows the configuration a fixture is checked with.
- New rule OBAAF-GHA-024. List secrets under `protected_secrets` in `.github/obaaf.yml` (optionally with the environment that must hold each one), and the checker reports every job that uses one without declaring that environment. Anyone with write access can read a repository secret by pushing a workflow on a branch; the GitHub settings guide now says so and describes how to keep such secrets in an environment limited to the default branch. Test fixtures can carry a configuration in an `# obaaf-config:` line.

### Baselines

- `obaaf check --write-baseline FILE` records the current findings; `obaaf check --baseline FILE` reports them but fails only on new findings, or on baseline entries that no longer match (so fixes are locked in). Findings match without line numbers. JSON output marks `baselined` and lists stale entries, and SARIF output sets `baselineState`, only when a baseline is used. See docs/checker-configuration.md#baseline. Each entry's fingerprint is recomputed from its visible fields on load (a mismatch is refused), stale entries follow the `--fail-on` threshold and category, and expired ignores are never written into a baseline.

### Fixed

- A negated status function in a job's `if:` (for example `!cancelled() && github.event_name == 'workflow_dispatch'`) no longer stops the checker from narrowing the job's triggers by its event test. Any other negation still does.

### Project

- Governance is adopted rather than draft, and the project now accepts outside contributions under CONTRIBUTING.md; the code of conduct is the Contributor Covenant 2.1 in CODE_OF_CONDUCT.md (D-038).

### Platform scope

- The website, README, adoption guide, glossary, traceability and package description now say that `obaaf check` reads GitHub Actions workflows and, as an advisory auditor, Jenkinsfiles. The templates, `setup-obaaf` and keyless signing remain GitHub Actions only. The site's quickstart runs `obaaf check .`, which covers both.

### Added

- Projects that vendor no binaries can declare `vendored_binaries: none` in `obaaf-sources.yaml`. `obaaf manifest create` writes an empty `obaaf-manifest/v0.1` with `vendoredBinaries: "none"` so the build-record digest binds the claim; empty `components` without that declaration still fails closed (D-033). Set `build_record.require_sdks: false` in the release policy so `obaaf verify release` accepts an empty SDK list.
- OBAAF's own repository commits that empty declaration and, on PyPI release, checks the manifest, signs an OBAAF build record beside SLSA provenance, and runs `obaaf verify release` (provenance body, build record, environment approvals, agent history) before upload.

### Changed

- PyPI publish dogfoods FR6: `.github/obaaf-policy.yaml` (`require_sdks: false`, environment `pypi`, `runner_environments: [github-hosted]`); the publish job checks out the default branch, installs the reviewed CLI via `./actions/setup-obaaf`, and replaces the `gh attestation verify` type-only loop with `obaaf verify release`. Residual vs the template lane: no `workflow_run` split and no pre-approval summary job.

### Jenkins (advisory)

- `obaaf check` now reads Jenkinsfiles (`Jenkinsfile`, `Jenkinsfile.<name>`, `Jenkinsfile-<name>`, `<name>.jenkinsfile`, and globs in `jenkins.files`) alongside workflows, or alone with `--platform jenkins`. A syntax-only parser reads the Groovy without running any of it (D-034). Fifteen rules, OBAAF-JEN-001 to OBAAF-JEN-015, cover credentials that change requests or an agent can reach, builds on the controller and shared agents, agent stages that push or publish, pipeline code from unapproved revisions, approvals, host access from containers and pods, agent egress, unpinned images, libraries and agent CLIs, Groovy-interpolated untrusted text and secrets, moving artifact references, publishing after a failed check, missing release verification, signing keys, and webhook tokens in the file. Each maps to profile requirements and agent controls in the catalog.
- Every Jenkinsfile gets a coverage result per rule (pass, fail, ignored, unknown, not applicable) in text and JSON output, with the reason for each unknown. Controller settings and shared-library code are reported as unknown, never as a pass, and the report states that exit 0 is not a conformance decision (D-036). See [docs/jenkins.md](docs/jenkins.md).
- New configuration: `jenkins.files`, `jenkins.exclude` and `agents.steps`; lane overrides and ignore entries take a Jenkins stage as `file#stage` and `job: <stage>`. `--lanes` lists Jenkins stages.
- OBAAF-REPO-001 also covers Jenkinsfiles, and is retitled "CI definition files have no code owner".
- Release lane on Jenkins (D-037): `templates/jenkins/obaaf-release-build.Jenkinsfile` builds a protected tag with no credentials in a project that builds only tags; `obaaf-release-publish.Jenkinsfile`, a separate job read from the default branch with no parameters, finds the tag build that started it, signs SLSA provenance and the build record through a key service, verifies, waits for a named approver and verifies again before uploading. A `signing: keys` policy example is included.
- `obaaf dsse prepare` and `obaaf dsse assemble` sign records with a key that stays in a key service: `prepare` writes the bytes (or digest) to sign, `assemble` accepts the service's signature (raw or base64, DER or r||s), checks it against the public key and writes the DSSE envelope.
- `obaaf verify release` reads Jenkins evidence: `--approvals` takes the publishing build's JSON from the controller, `--release-run` the JSON of the build that produced the artifacts. The publishing build must have been started by that build alone, which must be the tag build of `release.jenkins_project` and have checked out the release commit. Whoever started either build cannot approve; with `release.approvers` set, only listed people count (on GitHub too). Replays, stage restarts, builds started by hand, unclassified causes and incomplete evidence are blocked.
- Records written in a Jenkins build name it in `run` (controller, job, build URL), marked as self-reported, and the build record says its source came from the Jenkins release job.
- Agent CLI patterns accept options before the prompt flag or subcommand (`claude --model x -p ...`, `codex -m o3 exec`). This also applies to workflows, where such jobs were previously left out of the agent lane.

### Checker

- `obaaf check .github/workflows`, the form the website quickstart shows, checked zero files and passed, because discovery expected a repository root. The checker now accepts a repository root, its `.github` directory or its `.github/workflows` directory, and keeps repository-relative paths. When nothing is found, `obaaf check` exits 2 and says nothing was checked, instead of passing.

## [0.2.0] - 2026-10-26

### Attestation formats (breaking)

- Move the predicate type URIs from the reserved `obaaf.example` domain to the project's domain (D-007): `https://www.obaaf.com/attestation/agent-run/v0.1`, `.../agent-approval/v0.1`, `.../build-record/v0.1`, and the generic SLSA build type `https://www.obaaf.com/buildtypes/generic/v0.1`. The JSON Schemas' `$id` values move with them. The site now publishes a page at each type URI and each schema at its `$id`.
- Records signed with the 0.1 URIs do not verify under this version. Sign new records with the updated templates.

### Supply chain of OBAAF itself

- Install OBAAF's dependencies by hash (D-011): `setup-obaaf` and the PyPI release now install from `actions/setup-obaaf/requirements.txt` with `--require-hashes`, wheels only. `scripts/lock_setup_obaaf.py` generates that file from `constraints.txt` with PyPI's SHA-256 for every file; CI checks it against PyPI and runs the action on Linux, macOS and Windows.
- Sign SLSA provenance for OBAAF's own PyPI release in a separate `attest` job, and verify it with `gh attestation verify` before uploading. Check a downloaded file with `gh attestation verify <file> --repo Obaaf/OBAAF`.

### Papers

- Both companion papers have DOIs on Zenodo: Paper 1, *Untrusted Text, Trusted Tokens*, [10.5281/zenodo.23622566](https://doi.org/10.5281/zenodo.23622566); Paper 2, *Securing the Game Build*, [10.5281/zenodo.23622802](https://doi.org/10.5281/zenodo.23622802). The website, README, generated spec headers, threat model and paper READMEs link to them, and a `CITATION.cff` lists them so GitHub offers a citation.

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
- Update first-adoption guidance with lane inspection and a commit-pinned path for trying unreleased code. Regression tests cover the runner and severity changes; pilot validation is pending. See [docs/roadmap-0.2.md](docs/roadmap-0.2.md).

## [0.1.0] - 2026-10-22

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
