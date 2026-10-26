# Roadmap to version 0.2

Version 0.1 is the first release, now in active adoption. The first external pilot ([issue #19](https://github.com/Obaaf/OBAAF/issues/19)) ran `obaaf check` on a production repository with dozens of workflows, self-hosted runners, and an LLM agent driven through a shell script, and reported that the checker is a useful advisory audit but not yet a reliable repository-wide gate. This roadmap turns that feedback into the 0.2 plan. The items under "Done in this change" shipped in the commit that added this file.

## Done in this change

- An advisory note when a repository has agent instruction files but no job is classified into the agent lane, and when a trusted job is named like agent work. This surfaces agents launched indirectly, which the lane inference misses.
- Documented the existing `agents.commands` and `agents.actions` configuration, lane overrides, `OBAAF_LANE` and expiring `ignore` entries in [checker configuration](checker-configuration.md), so an indirectly launched agent can be declared.
- An authority or hygiene category on every rule, reported separately in the text summary and the SARIF output, so hygiene findings such as digest pinning do not bury authority findings.
- The dynamic `runs-on` limitation is documented in OBAAF-GHA-013, with an `ignore` entry as the workaround for a confirmed-safe runner.

## Planned for 0.2

1. **Script-aware agent detection (high). Shipped.** A trusted job whose `run` step calls a repository script that invokes an agent CLI is reclassified into the agent lane, so the agent controls apply without configuration. Best-effort: scripts the checker cannot read fall back to the advisory note.
2. **Finding profiles for CI gating (high). Shipped.** `--fail-on` now accepts a category, for example `--fail-on authority:medium`, so CI can gate on authority findings without first clearing every hygiene finding. See the [checker configuration](checker-configuration.md) guide.
3. **Dynamic `runs-on` handling (medium). Implemented, with regression tests; pilot validation pending.** Unresolved selectors that explicitly name both hosted and self-hosted alternatives are informational. Known self-hosted matrices remain high and other unknown labels or inputs remain medium. Reviewed pools can use exact-job, expiring exceptions with evidence; a declaration does not verify runtime isolation.
4. **Soften hygiene outside the release and agent lanes (medium). Implemented, with regression tests; pilot validation pending.** GHA-008 is low for ordinary jobs only with explicitly limited token permissions, no referenced secrets, and no privileged outside trigger. Agent, release and effect jobs stay high; other jobs stay medium.
5. **Maturity framing in the output (medium). Shipped.** Findings that need the agent and effect lane architecture (OBAAF-GHA-003, GHA-004, GHA-005, GHA-021 and GHA-022) are flagged as such in the output and as `obaaf-remediation` in JSON and SARIF, pointing to the lane templates.
6. **Predicate type URIs under the project's domain (D-007). Shipped.** The agent-run, approval and build-record types and the generic build type live under `https://www.obaaf.com/`, and each resolves to a page describing its format. Breaking for records signed with the 0.1 URIs.
7. **Hash-pinned install (D-011). Shipped.** `setup-obaaf` and the PyPI release install every dependency by SHA-256 from a generated `requirements.txt`; CI checks it against PyPI and on Linux, macOS and Windows.
8. **Signed provenance for OBAAF's own release. Shipped.** The PyPI release signs SLSA provenance in a separate job and uploads nothing until `gh attestation verify` passes for every file.

## Found while releasing OBAAF with its own controls

OBAAF's release does not yet write an OBAAF build record or run `obaaf verify release` on itself. `obaaf attest build-record` requires a binary manifest, and a manifest requires at least one vendored component, so a project that vendors no binaries, such as OBAAF itself and many teams outside games, cannot produce a build record. Planned for 0.3: let a project declare that it vendors no binaries, then release OBAAF through the full release lane and `obaaf verify release`.

## Data wanted

The follow-up copied-wrapper gap has an implementation for simple `cp` snapshots
inside a single `run:` block. It reads only the repository source. Arbitrary
shell data flow and external or generated scripts still require agent declarations.
One copied-wrapper regression check covers the wrapper change.
`tests/test_severity_regressions.py` covers the runner and severity changes: where
GHA-008 drops to low, where it must stay medium or high, which runner selectors are
informational, and that informational findings are never gated. These are unit
tests on synthetic workflows, not pilot validation. Issue #19 stays open until a
pilot confirms the new severities on a real repository.

These changes are not on PyPI. The configuration guide documents commit-pinned
source installation for pilots; publishing a new version remains a separate step.

The pilot offered anonymized finding counts by rule. Those counts will tune rule severities and the authority and hygiene split, and will inform item 4.
