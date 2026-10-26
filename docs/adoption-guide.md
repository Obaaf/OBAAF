# Adopting OBAAF in a small studio

This guide is for a studio of fewer than 50 people, where one engineer owns the build system part-time and nobody owns security. It goes tier by tier; each tier is useful on its own. Effort figures are the self-assessment's initial estimates and will be checked in the pilot.

## 1. Take the self-assessment (an hour)

For a command-by-command example with fictional answers, see the
[self-assessment walkthrough](self-assessment-walkthrough.md).

Open the [offline form](../assessment/obaaf-self-assessment.html) in a browser, or run:

```bash
obaaf assess init --output answers.yaml
obaaf assess score answers.yaml
```

Answer each question from the evidence named beside it, not from memory. Two people answering separately and comparing is better still: where you disagree, look at the evidence together. Save the answers; you will repeat the assessment in 90 days.

The result is your tier and a ranked list of what to fix first. Each item links to its guide.

## 2. Reach Tier 1, Accounted (hours per item)

Tier 1 establishes who and what can publish or sign. None of it needs new tools, with one exception: protecting release branches in a private GitHub repository needs a paid plan (see [plan limits](github-settings.md#plan-limits)).

- Turn on multi-factor authentication for every publishing account ([item 1.1](guides/F6-distribution.md#item-1-1)).
- Use a dedicated upload account ([1.2](guides/F6-distribution.md#item-1-2)), and make a person set builds live ([1.3](guides/F6-distribution.md#item-1-3)).
- List your build and signing machines ([1.4](guides/F3-build-execution.md#item-1-4)), your keys ([1.5](guides/F5-signing.md#item-1-5)), and your SDKs and plugins ([1.8](guides/F2-intake.md#item-1-8)).
- Protect release branches ([1.6](guides/F1-source-and-assets.md#item-1-6)) and give everyone an individual account ([1.7](guides/F1-source-and-assets.md#item-1-7)).

## 3. Reach Tier 2, Controlled (days per item)

Tier 2 separates release builds from untrusted work and removes standing credentials. On GitHub Actions, the templates do much of it.

**Check your plan first.** For a private repository, the release and agent templates need GitHub Enterprise Cloud: artifact attestations, and required reviewers on environments, are not available for private repositories on the Free, Pro or Team plans. On those plans, a public repository works, or you can use the tools with `signing: keys` and your own pipeline; see the [plan limits](github-settings.md#plan-limits). The untrusted-lane template and the checker work on every plan.

1. Run `obaaf check . --fail-on never` and review the findings. If you use agents, first run `obaaf check . --lanes` and verify their classification. Agent authority controls can require a separate proposal and effect lane, not just workflow edits. The [configuration guide](checker-configuration.md) explains declarations and the unreleased `--fail-on authority:medium` gate; PyPI 0.1.0 does not have that category gate.
2. Install the templates: `obaaf templates install --dest . --obaaf-repo OWNER/obaaf --obaaf-sha <commit> --repository YOU/GAME`.
3. Apply the [GitHub settings](github-settings.md): rulesets, environments, fork-PR approvals, CODEOWNERS.
4. Create the binary manifest ([2.6](guides/F2-intake.md#item-2-6)).
5. Move release builds to the [release](../templates/github-actions/workflows/obaaf-release.yml) and [publish](../templates/github-actions/workflows/obaaf-publish.yml) templates, which build without shared caches or credentials and keep upload credentials in the publish job's environment ([2.1](guides/F3-build-execution.md#item-2-1), [2.4](guides/F3-build-execution.md#item-2-4), [2.7](guides/F4-caches.md#item-2-7)).
6. Move signing keys out of files, into hardware, a key service or the platform's signing ([2.3](guides/F5-signing.md#item-2-3)). If you run your own launcher or patcher, make it check update signatures ([2.10](guides/F6-distribution.md#item-2-10)).
7. Write the procedures the templates cannot: asset quarantine ([2.5](guides/F2-intake.md#item-2-5)), SDK review ([2.11](guides/F2-intake.md#item-2-11)), revocation ([2.9](guides/F5-signing.md#item-2-9)), partner access ([2.8](guides/F9-partners.md#item-2-8)), alerts ([2.12](guides/F6-distribution.md#item-2-12)).

## 4. Reach Tier 3, Verified (days to weeks)

Tier 3 produces and checks provenance and isolates builds.

- The release template signs provenance and a build record, and the publish template verifies them before upload ([3.1](guides/F7-provenance.md#item-3-1), [3.2](guides/F7-provenance.md#item-3-2)). Write `.github/obaaf-policy.yaml` from the example.
- Build every target you can in fresh environments, and reimage the rest on a schedule ([3.3](guides/F3-build-execution.md#item-3-3), [3.4](guides/F3-build-execution.md#item-3-4)).
- Limit where release hosts can send data ([3.5](guides/F3-build-execution.md#item-3-5)).
- If you use AI agents, move them to the agent and effect lane templates ([3.6](guides/F8-agents.md#item-3-6), [3.7](guides/F8-agents.md#item-3-7)).
- Roll out live updates in stages, and rehearse a rollback ([3.8](guides/F6-distribution.md#item-3-8)).
- Archive each release's artifacts, symbols and provenance read-only ([3.9](guides/F7-provenance.md#item-3-9)).

## 5. Reach Tier 4, Assured (weeks)

Tier 4 adds two-person control and independent verification: two approvers ([4.1](guides/F1-source-and-assets.md#item-4-1)), independent rebuilds ([4.2](guides/F4-caches.md#item-4-2)), two-person set-live ([4.3](guides/F6-distribution.md#item-4-3)), release-lane derived data ([4.4](guides/F4-caches.md#item-4-4)) and verified agent records ([4.5](guides/F8-agents.md#item-4-5)).

## If you do not use GitHub Actions

The profile and the self-assessment are tool-neutral. `obaaf check` also reads Jenkinsfiles, as an advisory auditor: it reports what a Jenkinsfile shows and lists what only the controller can show as unknown ([Jenkins](jenkins.md)). The templates are GitHub Actions only, for now; Jenkins job templates and enforcement are planned (see [what is not built yet](jenkins.md#what-is-not-built-yet)). Meanwhile, the tools work on any CI system that runs Python:

- `obaaf manifest`, `obaaf attest slsa` and `obaaf attest build-record` produce the records.
- A key held in a key service signs them.
- `obaaf verify release`, with `signing: keys` in the policy, checks them before upload.
