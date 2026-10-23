# Roadmap to version 0.2

Version 0.1 is a public draft. The first external pilot ([issue #19](https://github.com/Obaaf/OBAAF/issues/19)) ran `obaaf check` on a production repository with dozens of workflows, self-hosted runners, and an LLM agent driven through a shell script, and reported that the checker is a useful advisory audit but not yet a reliable repository-wide gate. This roadmap turns that feedback into the 0.2 plan. The items under "Done in this change" shipped in the commit that added this file.

## Done in this change

- An advisory note when a repository has agent instruction files but no job is classified into the agent lane, and when a trusted job is named like agent work. This surfaces agents launched indirectly, which the lane inference misses.
- Documented the existing `agents.commands` and `agents.actions` configuration, lane overrides, `OBAAF_LANE` and expiring `ignore` entries in [checker configuration](checker-configuration.md), so an indirectly launched agent can be declared.
- An authority or hygiene category on every rule, reported separately in the text summary and the SARIF output, so hygiene findings such as digest pinning do not bury authority findings.
- The dynamic `runs-on` limitation is documented in OBAAF-GHA-013, with an `ignore` entry as the workaround for a confirmed-safe runner.

## Planned for 0.2

1. **Script-aware agent detection (high).** Best-effort scanning of scripts a workflow calls (for example `bash run-agent.sh`) for an agent CLI, so an agent launched indirectly reaches the agent lane without configuration. This cannot be sound in general, so it stays best-effort and pairs with the misclassification warning shipped here.
2. **Finding profiles for CI gating (high). Shipped.** `--fail-on` now accepts a category, for example `--fail-on authority:medium`, so CI can gate on authority findings without first clearing every hygiene finding. See the [checker configuration](checker-configuration.md) guide.
3. **Dynamic `runs-on` handling (medium).** Configuration to declare known-ephemeral or fork-safe runner pools, and an `info` severity for runner expressions the checker cannot resolve, so they are not reported as hard findings.
4. **Soften hygiene outside the release and agent lanes (medium).** Reconsider the severity of digest pinning (OBAAF-GHA-008) for non-release, non-agent jobs, informed by the pilot's finding counts.
5. **Maturity framing in the output (medium).** Make the output say when a finding (for example the agent lane controls OBAAF-GHA-003 and OBAAF-GHA-005) calls for an architecture change rather than a one-line fix, and point to the lane templates as the path.

## Data wanted

The pilot offered anonymized finding counts by rule. Those counts will tune rule severities and the authority and hygiene split, and will inform item 4.
