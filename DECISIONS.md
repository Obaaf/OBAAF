# Decisions log

Every design decision in OBAAF, with its reason and the evidence behind it (NFR7). Statuses:

- **Accepted**: decided by the maintainer.
- **Proposed**: documented during the version 0.1 build and implemented as written, but not yet accepted. The maintainer accepts, changes or rejects each one; change the status and add the date when you do.
- **Open**: needs a decision before the step named in it.

| ID | Decision | Status |
| --- | --- | --- |
| D-001 | The framework is named the Open Build and Agent Assurance Framework (OBAAF) | Accepted, 2026-10-05 |
| D-002 | Public draft repository and resource site authorized by maintainer | Accepted, 2026-10-10; supersedes 2026-10-05 |
| D-003 | Copyright notice and ownership; license grant | Proposed, 2026-10-21 |
| D-004 | Titles, rationales and tests for the 28 profile requirements | Proposed |
| D-005 | Not-applicable answers, including item 3.4 | Proposed |
| D-006 | How the self-assessment ranks fixes | Proposed |
| D-007 | Predicate type URIs | Accepted, 2026-10-26 |
| D-008 | Mapping GitHub repository roles to trust levels | Proposed |
| D-009 | Approvals recorded in a second attestation | Proposed |
| D-010 | Agent records travel with the change | Proposed |
| D-011 | How pipeline dependencies are pinned | Accepted, 2026-10-26 |
| D-012 | Retired | Retired, 2026-10-07 |
| D-013 | Implementation language and dependencies | Proposed |
| D-014 | GitHub Actions first | Accepted, 2026-10-05 |
| D-015 | Isolation tier read from the workflow definition | Proposed |
| D-016 | Release approvals checked at upload time | Proposed |
| D-017 | What starts the agent lane | Proposed |
| D-018 | The effect lane opens pull requests only | Proposed |
| D-019 | `cache-mode: none` for release, agent and effect jobs | Proposed |
| D-020 | The inference proxy is specified now and built in version 0.2 | Proposed |
| D-021 | Checker severities and the CI failure threshold | Proposed |
| D-022 | Retired | Retired, 2026-10-07 |
| D-023 | Version 0.1's agent and release lanes need a public repository or GitHub Enterprise Cloud | Proposed |
| D-024 | Releases build from tags and publish from the default branch | Proposed |
| D-025 | Agent commits are checked from a baseline in the policy | Proposed |
| D-026 | The committed change must equal the approved proposal by default | Proposed |
| D-027 | Proposal checks read the patch with Git and fail closed | Proposed |
| D-028 | The effect lane is split, and has its own commit identity | Proposed |
| D-029 | Who may not approve an agent's change | Proposed |
| D-030 | Checker strictness | Proposed |
| D-031 | Code signing of game binaries is deferred | Proposed |
| D-032 | Contributions after release: DCO sign-off and security acknowledgment time | Proposed |
| D-033 | Empty binary manifest for projects that vendor no binaries | Accepted, 2026-10-26 |
| D-034 | Jenkinsfiles are read by a syntax-only parser in Python | Proposed |
| D-035 | The Jenkins adapter sits beside the workflow checker | Proposed |
| D-036 | Jenkins results are advisory, and unknowns are coverage, not findings | Proposed |
| D-037 | The Jenkins release lane signs with a key service and reads approvals from the controller | Proposed |

---

### D-001 Framework name

**Decision.** The framework is the Open Build and Agent Assurance Framework (OBAAF). **Reason.** Chosen by the maintainer. A web search found no existing framework with the name; no trademark search has been done. **Status.** Accepted, 2026-10-05.

### D-002 Release condition

**Decision.** The maintainer authorized making the repository public and publishing the resource site, and stated that written employer approval is not necessary for that publication. Use the default GitHub Pages address until a custom domain is acquired. This supersedes the private-repository requirement accepted on 2026-10-05. It does not grant a license, change copyright ownership, or authorize submission of the research papers. **Status.** Accepted, 2026-10-10.

### D-003 Copyright notice and ownership; license grant

**Decision.** Grant the intended licenses (NFR1): Apache License 2.0 for the code, templates, tools and tests (`src/`, `templates/`, `actions/`, `tests/`); Creative Commons Attribution 4.0 International for the specifications, guides and documentation (`spec/`, `docs/`, and the data in `src/obaaf/data/`). The data files are dual-covered, so the package declares `Apache-2.0 AND CC-BY-4.0`. Copyright is held by Osita Sean Keluo-Udeke, as stated before public draft. The license texts (`LICENSE`, `LICENSE-docs`), the `NOTICE`, the `pyproject.toml` metadata and the [LICENSING.md](LICENSING.md) statement are in place. **Reason.** The licenses were always the intended ones (LICENSING.md); a studio cannot pilot or redistribute OBAAF without a granted license, so the grant is a prerequisite to the independent-studio pilot and to award and funding programs that require an OSI-approved license. **Maintainer acceptance.** Confirm the copyright holder and the affiliation shown on the papers and the repository, then accept by committing these files; change this status to Accepted with the date. Until then the texts are implemented as written but not yet accepted. **Status.** Proposed, 2026-10-21.

### D-004 Profile titles, rationales and tests

**Decision.** Paper 2, Table 4 gives each requirement's statement and mappings. FR1 also requires a test procedure. This repository adds a short title, a rationale, a pass-or-fail test and the evidence to inspect for each of the 28 requirements, in `src/obaaf/data/profile.yaml`. Some tests add thresholds the paper does not state (for example, G6.4's rollback test "within the last six months"). **Reason.** FR1 acceptance criterion. **Review.** Read each entry in [spec/profile.md](spec/profile.md); edit the data file, not the generated document. **Status.** Proposed.

### D-005 Not-applicable answers

**Decision.** Paper 2, DR6 allows N/A only when an item's condition is absent, naming three conditions: no self-hosted updater (item 2.10), no AI agents (items 3.6, 3.7, 4.5) and no target that can build in a container (item 3.3). Item 3.3's N/A condition here reads "fresh container or virtual machine", following the item's own wording, which names both. This repository also allows N/A for item 3.4 when a studio has no persistent release hosts, because Table 9 treats 3.3 and 3.4 as alternatives. No other item can be N/A. **Consequence.** If accepted, Paper 2's DR6 should name the fourth condition. Items 1.2 and 2.8 can also have an absent subject (no automated uploads, no partners); the pilot should show how studios answer them. **Status.** Proposed.

### D-006 Ranking fixes

**Decision.** Open items are ranked by tier (lowest first), then effort (hours, days, weeks), then the number of documented compromises the item would have prevented, then the number it would have detected or limited (Paper 2, Table 7), then item number. **Reason.** DR3 (prioritized by documented attack paths) and DR4 (effort-aware). The Python scorer and the offline form implement the same rule, and a test checks they agree. **Status.** Proposed.

### D-007 Predicate type URIs

**Decision.** OBAAF's in-toto predicate types and its generic SLSA build type live under `https://www.obaaf.com/`, the project's own domain, for example `https://www.obaaf.com/attestation/agent-run/v0.1`. They are defined once in `src/obaaf/predicates.py` and used in the templates. Each type URI resolves to a page that describes its format, and each JSON Schema's `$id` resolves to the schema; `site/build.py` publishes both. A changed format gets a new version and a new URI, and published pages stay as they are. **Reason.** A type URI should be under a namespace the project controls and should lead a reader to the format it names. `www.obaaf.com` is the site's canonical host, so the URIs resolve without depending on a redirect. Version 0.1 used the reserved `obaaf.example` domain until the project had a domain. **Consequence.** Breaking, which is acceptable before 1.0: records signed with the 0.1 URIs do not verify under 0.2 and must be signed again with the 0.2 templates. **Status.** Accepted, 2026-10-26 (previously Open, before release).

### D-008 Trust levels for GitHub roles

**Decision.** The snapshot step asks GitHub for each author's repository role: admin and maintain map to Maintainer; write and triage to Contributor; read and none to Public. Without a role it falls back to `author_association`: OWNER maps to Maintainer, and everything else, including MEMBER and COLLABORATOR, to Public, because those say nothing about write access to this repository. A pull request's changes are always labeled Public. The floor is Public in every repository unless the workflow raises it with `--floor`: the snapshot cannot see who else wrote what the agent's token can read (in a private repository, read-only users and, in internal repositories, every enterprise member). **Reason.** Paper 1, section 3.2 places principals by what they can do; write access can push unprotected branches and apply labels (Contributor). This mapping is right only when repository secrets live in protected environments, as the templates arrange; otherwise write access can read secrets and is Maintainer-equivalent. The security review found the earlier Contributor floor for private repositories, and the Contributor fallback for MEMBER and COLLABORATOR, too generous. **Status.** Proposed.

### D-009 Approvals in a second attestation

**Decision.** Paper 1, Table 3 lists Approvals among the agent-run record's fields, produced by the effect lane. Because approval happens after the attestation step signs, the effect lane signs a second attestation, `agent-approval`, over the same proposal files. The two together form the record. **Consequence.** Paper 1, section 7.3 could say so in one sentence. **Status.** Proposed.

### D-010 Agent records travel with the change

**Decision.** When the effect lane applies a patch, it adds `.obaaf/records/<bundle digest>.json` (the proposal and both signed attestations) in the same commit as the change and names it in an `OBAAF-Agent-Record:` commit trailer. The release verifier finds agent commits by trailer, by an added record file, or by the effect lane's commit identity, and requires each to add exactly one record, named after its digest and used by no other commit in the range. **Reason.** `gh attestation verify` needs the attested file; artifacts expire; a record in the repository is archived with the source and reviewed in the pull request. Requiring the record in the same commit stops an old, valid record from vouching for a later change. **Limit.** A squash merge that combines an agent's change with other changes fails the exact-diff check (D-026). **Status.** Proposed.

### D-011 Pinning pipeline dependencies

**Decision.** Workflows pin every action to a full commit SHA. `actions/setup-obaaf` and the PyPI release workflow install every dependency, including the build backend, from `actions/setup-obaaf/requirements.txt` by exact version and SHA-256 hash, as wheels only (`--require-hashes --only-binary=:all:`). That file lists the hash of every file PyPI publishes for each version, so one list serves every operating system and Python version. It is generated from `constraints.txt` by `scripts/lock_setup_obaaf.py`. CI checks it against PyPI, attaches the expected file to the run when it is out of date, and runs the action on Linux, macOS and Windows. The project's own test and site jobs install OBAAF in editable mode, which pip's hash-checking mode does not support, so they keep the exact versions in `constraints.txt`. **Distribution.** PyPI via OIDC trusted publishing (`pip install obaaf`), documented in [docs/releasing.md](docs/releasing.md). A GitHub Marketplace listing for `setup-obaaf` is documented there; pre-built single-file binaries remain deferred. **Status.** Accepted, 2026-10-26 (previously Open, before release).

### D-033 Empty binary manifest

**Decision.** A project that vendors no binaries declares `vendored_binaries: none` in `obaaf-sources.yaml` (components absent or empty). `obaaf manifest create` writes `format: obaaf-manifest/v0.1` with `vendoredBinaries: "none"`, `components: []` and `entries: []`, so the build-record digest binds the claim. Bare empty `components` without that declaration is rejected. `manifest check` validates the JSON claim and emptiness; it does not re-read the sources file or scan the tree for undeclared binaries. Release policies for such projects set `build_record.require_sdks: false`. An empty claim answers assessment items 1.8 and 2.6 as yes with evidence (the reviewed declaration), not as N/A (D-005 unchanged). **Reason.** G2.1 and FR5 assume a manifest; many non-game projects (including OBAAF) have no vendored binaries and could not previously produce a build record. **Status.** Accepted, 2026-10-26.

### D-012 Retired

This proposal is withdrawn at the maintainer's request. The identifier is reserved and will not be reused. **Status.** Retired, 2026-10-07.

### D-013 Language and dependencies

**Decision.** Python 3.10 or later, with PyYAML and jsonschema; `cryptography` only for verifying key-signed envelopes. Tests use the standard library's `unittest`. **Reason.** Python runs on every CI runner a studio uses; few dependencies keep the tools auditable. **Status.** Proposed.

### D-014 GitHub Actions first

**Decision.** The first reference templates target GitHub Actions; a second CI system follows for version 1.0, chosen from pilot data. Requirements stay tool-neutral (NFR6). **Reason.** The specification's scope and roadmap. **Status.** Accepted, 2026-10-05.

### D-015 Isolation tier from the workflow definition

**Decision.** The build record's isolation tier comes from the workflow file: a build job on standard GitHub-hosted runner labels is Tier A, including single-CPU runners, which start each job in a fresh container rather than a new virtual machine (Paper 2 counts a fresh container as Tier A); a self-hosted job, or one whose labels are not standard hosted labels, must declare `OBAAF_TIER` as a literal A or B. The build job never reports its own tier. **Reason.** FR4 requires the build record to state the tier; reading it from the workflow definition, as Paper 1 does for an agent's authority, keeps a compromised build from misreporting it. The publish workflow then checks that the release commit, and so the workflow file, is on the protected branch (D-024). **Limit.** Whether a self-hosted Tier A runner is really destroyed after each job is still a claim in the workflow. **Status.** Proposed.

### D-016 Release approvals checked at upload time

**Decision.** The publish job reads its own run's approvals from GitHub's approvals API, and `obaaf verify release` counts distinct approvers other than anyone who pushed the tag or started or re-ran the release or publish run (`--actor`, repeatable). Approvals are not part of the build record, which is signed before approval. The approvals API covers every attempt of the run; an approval from an earlier attempt still counts, because every attempt publishes the same artifacts from the same release run. **Consequence.** An administrator who bypasses the environment leaves no approval, so the release is blocked. GitHub environments proceed after one approval, so two-person release (item 4.3) uses two environments in sequence, and covers only the pipeline's path, not the store's own interface (see the F6 guide). **Status.** Proposed.

### D-017 What starts the agent lane

**Decision.** The agent template runs when a maintainer labels an issue `agent`, or a collaborator comments `/agent`. **Reason.** Cost control only: the agent still runs at the level of everything it reads, as Paper 1 requires, because invoker checks do not establish context trust. **Status.** Proposed.

### D-018 The effect lane opens pull requests only

**Decision.** The effect lane turns an approved patch into a branch and a pull request; it never pushes to a protected branch. The merge then needs ordinary review. Comments and allow-listed labels are applied directly. **Reason.** Two endorsements for code (the environment approval and the merge review), one for low-risk effects. **Status.** Proposed.

### D-019 Using GitHub's `cache-mode`

**Decision.** Release, agent and effect jobs set `cache-mode: none`. **Reason.** GitHub's changelogs describe `cache-mode`, enforced with scoped cache tokens ([September 2026](https://github.blog/changelog/2026-09-10-control-github-actions-cache-access-with-cache-mode)), and a read-only cache default for untrusted triggers that use the default branch's cache scope, such as `pull_request_target`, `issue_comment` and `workflow_run` runs that follow a pull request from a fork ([June 2026](https://github.blog/changelog/2026-06-26-read-only-actions-cache-for-untrusted-triggers)). The June change ships to GitHub.com and GitHub with data residency; neither changelog says when either reaches GitHub Enterprise Server, where the checker's other cache rules still apply. **Status.** Proposed; recheck GitHub Enterprise Server before release.

### D-020 Inference proxy

**Decision.** Version 0.1 specifies the proxy's contract ([docs/inference-proxy.md](docs/inference-proxy.md)) and ships a stub agent that calls no model, so the lanes can be tested end to end. A reference proxy is planned for version 0.2. **Reason.** R3 and FR7 keep the model credential outside the agent job; a proxy is a server that needs its own design review. **Status.** Proposed.

### D-021 Checker severities

**Decision.** High: a documented attack path is open. Medium: a safeguard is missing. Low: hardening. CI fails on medium and above. **Status.** Proposed.

### D-022 Retired

This proposal is withdrawn at the maintainer's request. The identifier is reserved and will not be reused. **Status.** Retired, 2026-10-07.

### D-023 Plan scope of version 0.1

**Decision.** Version 0.1's agent and release templates need artifact attestations and environment reviewers, so for private repositories they need GitHub Enterprise Cloud. Version 0.1 says so plainly ([github-settings.md](docs/github-settings.md#plan-limits), [traceability.md](docs/traceability.md)) instead of offering weaker substitutes, and NFR3 is marked as not met for private repositories on other plans. **Planned.** A merge-review mode for the effect lane (the protected branch's review as the approval, recorded and checked) and a key-signing release template, both for studios on the Team plan. **Consequences.** On plans without environment reviewers, `release.min_approvals` must be 0, and the person's approval comes from the store (a person sets builds live, item 1.3). On GitHub Free, release branches in a private repository cannot be protected at all, so items 1.6, 2.2, 3.7 and 4.1 cannot be met there. **Reason.** The consistency review found that the earlier Team-plan advice could not work: `obaaf attest approval` refuses to sign without an environment approval. **Status.** Proposed.

### D-024 Releases build from tags and publish from the default branch

**Decision.** `obaaf-release.yml` builds and attests on a push of a protected `v*` tag. A separate `obaaf-publish.yml`, started by `workflow_run` and therefore run from the default branch, verifies the release before anyone approves it (the result goes to the run summary), waits for the `release` environment, verifies again with the approvals, and uploads. The verifier requires the released commit to be on the policy's protected branch (`release.branch`, default `main`), and blocks when it is not given the repository and the release commit to check this; `release.branch: ""` turns the check off for repositories that release from several branches. **Reason.** The specification's FR4 says releases start only from a protected branch, and the security review showed that a workflow run by a tag push uses the workflow file and policy from the tagged commit, so a tag on an unreviewed commit could switch the checks off. Running publication from the default branch, and checking ancestry, closes that path while keeping tag-based release builds, which game teams expect. **Status.** Proposed.

### D-025 Agent commits are checked from a baseline in the policy

**Decision.** `obaaf verify release` checks agent-authored commits from the policy's `agents.since` commit to the released commit, or the whole history when `agents.since` is not set. When the policy sets `agents.since`, a `--range` on the command line is refused, so the range cannot be narrowed outside the reviewed policy. A shallow clone is refused too. Maintainers move the baseline forward in a reviewed change to the policy, only to a commit whose release passed. **Reason.** The earlier range started at the previous `v*` tag, and the security review showed that tagging a blocked commit (for example a release candidate) dropped the bad commit out of the next range. A baseline that only a reviewed policy change can move has no such gap. **Cost.** Without a baseline, every agent commit in history is verified on every release. A signed "published" marker could replace the manual baseline later. **Status.** Proposed.

### D-026 The committed change must equal the approved proposal

**Decision.** `agents.require_exact_diff` defaults to true: the verifier blocks a release when an agent commit's change differs from the approved patch, or when a commit that changes files names a record with no patch. "Differs" is decided by applying the approved patch to the commit's parent in a temporary index and comparing the result with the commit, outside the records directory, so the same lines moved to another place with identical surroundings are caught (the second security review showed that comparing diff text without line numbers missed this). **Reason.** With the default off, an old valid record could accompany any change with only a warning (security review). **Consequence.** Maintainers merge agent pull requests unchanged and make follow-up changes in separate pull requests. **Status.** Proposed.

### D-027 Proposal checks read the patch with Git and fail closed

**Decision.** `obaaf proposal check` takes the touched paths from Git itself (`git apply --numstat`, forwards and in reverse, and `--summary`), compares them with its own strict parser, and refuses the patch when they disagree, when it contains anything but plain git-format file changes, renames, copies, binaries, symbolic links, submodules or unusual modes, or when it touches a protected path or any path under a name starting with `.` (unless allowed). With `--repo` it also applies the patch to a temporary index of the default branch and checks the result. Comments are refused if they contain `](`, `]:`, `<`, `//`, `www.`, URL schemes or email addresses. **Reason.** The security review found four patch forms (quoted octal names, quoted instruction files, and two kinds of old-style hunks) that reached protected files, and Markdown forms that slipped past the comment filter. **Cost.** Some harmless proposals are refused; a person can make those changes instead. **Status.** Proposed.

### D-028 The effect lane is split, and has its own commit identity

**Decision.** The effect lane has an `approve` job (the environment approval, `obaaf verify agent-run`, the proposal check, the approval record, with `id-token` but read-only contents) and an `apply` job (write access, no `id-token`), which checks the record's digest and applies the patch. Its commits use the identity `OBAAF effect lane <obaaf-effect-lane@noreply.invalid>`, which the policy lists in `agents.effect_identities`. **Reason.** No job should hold both a signing identity and write access while it handles agent output (security review), and commits that other workflows make as `github-actions[bot]` should not be mistaken for agent changes. **Status.** Proposed.

### D-029 Who may not approve an agent's change

**Decision.** An approval does not count if it comes from anyone who started or re-ran the agent run or the effect run, the principal who triggered the agent, or anyone who wrote one of the agent's inputs, such as the issue's author. **Reason.** Paper 1, R4 requires approval by someone other than the requester; the security review showed that the author of an issue, who wrote the agent's task, could otherwise approve its result. **Status.** Proposed.

### D-030 Checker strictness

**Decision.** A declared lane (`OBAAF_LANE` or the configuration) can move a job only into a lane with stricter rules, never out of the agent, effect, release or untrusted lane the checker infers. On pull requests, the pipeline check reads its configuration from the target branch. Ignore entries cannot match every file. Runner labels that are not standard GitHub-hosted labels are reported at medium (OBAAF-GHA-013). OBAAF-GHA-016 counts only a verification whose failure stops the upload, and reports a provenance-only check at medium. OBAAF-GHA-020 reports an egress policy that is only declared, or enforced by a monitor that runs only under a condition. OBAAF-GHA-021 needs both the record verification and the proposal check, and reports one alone at medium. Steps inside `parallel` groups are checked like other steps; a `background: true` verification does not count as a gate; a job whose `if:` uses `success()` in an `||`, or `always()`, `failure()` or `cancelled()`, is treated as able to run after the jobs it needs failed or were skipped; and a step the checker cannot read (no `run` or `uses`, and not a known step form) is an error. **Reason.** Each closes a gap the first or second security review demonstrated. **Consequence.** The installed templates keep one low finding (OBAAF-GHA-020) until egress is enforced. **Status.** Proposed.

### D-031 Code signing of game binaries is deferred

**Decision.** Version 0.1 signs attestations through Sigstore but does not sign the game binaries themselves (Windows Authenticode, Apple, Android). The publish workflow marks where a managed signing step goes: after verification, in a job that runs no build code, followed by an attestation of the signed files. FR11 and G5.2 are marked as partly met. **Reason.** Signing services differ by platform and need the pilot's studios to choose; the consistency review found the earlier claims overstated. **Status.** Proposed.

### D-032 Contributions after release

**Decision.** After public release, contributions need a Developer Certificate of Origin sign-off (`git commit -s`), and security reports get an acknowledgment within five working days (SECURITY.md). **Reason.** The DCO is a light-weight, common way to record the right to contribute; five working days is achievable for one maintainer. **Status.** Proposed.

### D-034 Jenkinsfiles are read by a syntax-only parser in Python

**Decision.** `obaaf check` reads Jenkinsfiles with its own Groovy tokenizer and parser, written in Python, instead of the pinned JVM syntax helper the Jenkins integration design proposed. It never compiles, loads classes or evaluates expressions, and stops at 1 MiB, 400,000 tokens, 64 levels of nesting or 10 seconds per file. **Reason.** The design's requirement is that analysis runs no Groovy and has bounded failure; a JVM helper meets it only with a separately packaged runtime, image digest and dependency review, while the Python parser ships inside the existing package and has no dependencies. It is a structural reader for the constructs Jenkins pipelines use, not a full Groovy grammar: statements it cannot read are recorded as not analyzed and make the file's coverage unknown. The Declarative linter of a disposable controller remains the right compatibility oracle for the fixtures. **Consequence.** Groovy syntax the parser does not know lowers coverage instead of crashing; the parser was run over 512 public pipeline files with no file-level failure. **Status.** Proposed.

### D-035 The Jenkins adapter sits beside the workflow checker

**Decision.** The Jenkins rules live in `src/obaaf/checker/jenkins/` and share the catalog, findings, ignores, reports and CLI with the workflow checker, without first extracting platform-neutral contracts under `src/obaaf/ci/`. **Reason.** Extracting contracts first would touch every workflow rule before any Jenkins rule exists, and the design itself requires that GitHub Actions behavior be preserved; adding beside it leaves the 26 workflow and repository rules and their tests unchanged. **Consequence.** The contracts (CiContext, PipelineModel and the rest) are extracted when the evidence and admission phases need a shared model. **Status.** Proposed.

### D-036 Jenkins results are advisory, and unknowns are coverage, not findings

**Decision.** The OBAAF-JEN rules report what a Jenkinsfile shows. What only the controller can show (authorization, build authorization, agent placement, library trust and version overrides, Replay, credential scopes, network policy), and code the file does not contain (shared-library steps, `load`, generated parallel branches), is reported as a coverage unknown per rule, never as a pass. Unknowns do not change the exit status in advisory mode; the report says that exit 0 is not a conformance decision. Generic file transfer (`scp`, `rsync`, `sshPublisher`, `ftpPublisher`) is not treated as publishing. **Reason.** The design requires that missing evidence never appear as an empty finding list, and that enforcement come only with authenticated controller evidence. Counting generic transfer as publishing produced high findings on pipelines that only copy test reports. **Consequence.** A clean Jenkins report means nothing was found in the file. Enforcement, controller inventory and signed Jenkins run evidence are later phases. **Status.** Proposed.

### D-037 The Jenkins release lane signs with a key service and reads approvals from the controller

**Decision.** On Jenkins, the release lane is two jobs: a build job in the repository's multibranch project that builds tags with no credentials, and a publish job, read only from the default branch, that resolves the tag through the SCM, copies exactly that build's artifacts, signs SLSA provenance and the build record as DSSE envelopes through a key service (`obaaf dsse prepare` and `assemble`), and runs `obaaf verify release` before and after a named approver. The verifier reads Jenkins approvals from the publishing build's JSON (`ApproverAction`, `CauseAction`), does not count whoever started either build, and blocks Replays and stage restarts. Run identity in Jenkins records comes from the build's environment and is marked self-reported. **Reason.** Jenkins has no per-job identity the public Sigstore service accepts; credentials scoped to a multibranch project reach every branch and pull request; and the controller, not the pipeline, is where approvals are recorded. **Consequence.** The lane's guarantees depend on controller settings OBAAF cannot see yet (who may Replay or configure the publish job, credential scope, agent use); docs/jenkins.md lists them. Signed controller evidence comes with the inventory phase. **Status.** Proposed.

---

## Open questions from the specification

- [ ] Which CI system to support after GitHub Actions? The pilot will show what studios use.
- [x] Confirm the scope of the intended licenses (CC BY 4.0 for specifications, Apache 2.0 for code): granted in D-003, Proposed 2026-10-21. Confirming the copyright holder and affiliation remains the maintainers' acceptance step.
- [ ] Decide the affiliation shown on the papers and the repository (D-003).
- [ ] Ask app stores and game platforms whether they would accept build provenance alongside uploads.

## Notes for the companion papers

Building version 0.1 surfaced points the papers may want to reflect. None changes their argument.

1. **Approvals (Paper 1, section 7.3).** Approvals come after the agent-run record is signed, so they need their own attestation (D-009).
2. **N/A conditions (Paper 2, DR6).** Item 3.4 needs the condition "no persistent build hosts" (D-005).
3. **Two-person release (Paper 2, item 4.3).** A GitHub environment proceeds after one approval; two-person release needs two environments or a store-side control (D-016).
4. **Plan limits (Paper 1, Table 6; spec NFR3).** On GitHub Free, Pro and Team plans, required reviewers for environments and artifact attestations work only in public repositories; private repositories need GitHub Enterprise Cloud for attestations. Small studios with private repositories need the compensating controls in [docs/github-settings.md](docs/github-settings.md#plan-limits).
5. **New platform controls.** GitHub's changelogs describe `cache-mode` and read-only cache access for untrusted triggers that use the default branch's cache (`pull_request_target`, `issue_comment`, and `workflow_run` runs that follow fork pull requests; not every `workflow_run`), and actions/checkout version 7 refuses to check out fork pull-request code under `pull_request_target` and `workflow_run` unless explicitly allowed. GitHub backported the protection to every supported major version except v1 in July 2026, but workflows pinned to a commit SHA, as OBAAF's are, get it only when they move to a release that includes it. Both narrow the Clinejection and pwn-request paths. Verify the dates and scope before citing them.
6. **Public transparency log.** For public repositories, GitHub signs attestations through Sigstore's public-good instance and records them in its public transparency log. Check exactly what the log stores before saying so in the papers; OBAAF treats everything in its records (logins, digests, labels) as public.
7. **Winnti build compromises (Paper 2, Table 7).** The table puts their detection or limitation at Tier 4, but one of the deciding items, 3.4 (reimaging), is a Tier 3 item. Either the tier or the item list needs a fix.
8. **G1.2 and SLSA Source Level 4 (Paper 2, Tables 4 and 8).** Table 4 maps G1.2 to "Source L4, for the build definition", while Table 8 maps Source L4 only to item 4.1 (two approvers). SLSA v1.2 Level 4 asks for review by one trusted person other than the author, so item 4.1 goes beyond it, and G1.2's own review (item 2.2) may be the closer match.
9. **Two-person release covers the pipeline path (Paper 2, item 4.3).** A pipeline approval does not stop someone using a hijacked developer session in the store's own interface. Item 4.3 is fully met only if every path to setting a build live needs two people, which few stores support directly.
10. **Single-CPU GitHub-hosted runners.** They start each job in a fresh container, not a new virtual machine (Paper 1, section 3.1 notes this). Paper 2 counts a fresh container as Tier A; the papers may want to say so explicitly for agent jobs (R7).
