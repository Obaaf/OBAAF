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
3. **Dynamic `runs-on` handling (medium).** Configuration to declare known-ephemeral or fork-safe runner pools, and an `info` severity for runner expressions the checker cannot resolve, so they are not reported as hard findings.
4. **Soften hygiene outside the release and agent lanes (medium).** Reconsider the severity of digest pinning (OBAAF-GHA-008) for non-release, non-agent jobs, informed by the pilot's finding counts.
5. **Maturity framing in the output (medium). Shipped.** Findings that need the agent and effect lane architecture (OBAAF-GHA-003, GHA-004, GHA-005, GHA-021 and GHA-022) are flagged as such in the output and as `obaaf-remediation` in JSON and SARIF, pointing to the lane templates.

## Data wanted

The pilot offered anonymized finding counts by rule. Those counts will tune rule severities and the authority and hygiene split, and will inform item 4.
