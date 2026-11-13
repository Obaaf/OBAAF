# OBAAF documentation

| Document | For | What it covers |
| --- | --- | --- |
| [Adoption guide](adoption-guide.md) | Studios | Tier by tier, what to do and which template or guide helps |
| [Guides F1–F9](guides/) | Studios | How to fix each self-assessment item, by control family |
| [From a report to a gate](from-report-to-gate.md) | Build engineers | Moving `obaaf check` from something you read to something that fails a build, step by step, with the exit status of each step |
| [Upgrading](upgrading.md) | Build engineers | What to pin, how to move to a newer OBAAF, and what changes between 0.3.0 and the code after it |
| [GitHub settings](github-settings.md) | Build engineers | Repository settings the templates depend on, and plan limits |
| [Templates](../templates/github-actions/README.md) | Build engineers | Installing and adapting the GitHub Actions workflows |
| [Settings audit](settings-audit.md) | Build engineers | `obaaf audit`: what it reads of a repository's GitHub settings, the fifteen rules it applies to them and to the workflow files, what it needs to read each setting, and how it says what it could not tell |
| [The settings audit on the first adopter](expectrail-settings-audit.md) | Everyone | One read-only run of `obaaf audit` against Expectrail, a project of one of OBAAF's authors, on 2026-11-13: each finding judged, what could not be read, and the six incidents then and now |
| [The first adopter: Expectrail](expectrail-case-study.md) | Everyone | A case study of Expectrail, a project of one of OBAAF's authors: what OBAAF caught there and what it could not, from public facts, with every number about Expectrail recomputed and the other figures cited, and what has changed since |
| [Inference proxy](inference-proxy.md) | Build engineers | The contract for keeping model credentials out of agent jobs |
| [Architecture](architecture.md) | Reviewers | Components, lanes, trust levels, what enforces what, limits |
| [Records and attestations](attestations.md) | Reviewers, platforms | The snapshot, agent-run, approval and build-record formats |
| [Traceability](traceability.md) | Reviewers | Each functional requirement, where it is built, and how it is tested |
| [Live acceptance tests](live-acceptance-tests.md) | Maintainers | Procedures for a sandbox GitHub repository |
| [Glossary](glossary.md) | Everyone | Plain-language meanings of the terms used here |
| [Landscape](landscape.md) | Everyone | Other tools that check GitHub Actions and repository settings, what each found on the same repositories, dated and sourced |
| [Flagship plan](flagship.md) | Maintainers | The plan and progress of the work to make the core hold up in real use |
| [Egress control: design](egress-control.md) | Maintainers, security engineers | The design of the action that limits an agent command's network access: what it wraps, what it adds, what it will not stop, and the escape tests it has to pass. Not built yet |

The specifications themselves are in [`spec/`](../spec/), generated from the data in [`src/obaaf/data/`](../src/obaaf/data/).

## Guides by control family

- [F1 Source and assets](guides/F1-source-and-assets.md): items 1.6, 1.7, 2.2, 4.1
- [F2 Intake of third-party code, SDKs, and assets](guides/F2-intake.md): items 1.8, 2.5, 2.6, 2.11
- [F3 Build execution](guides/F3-build-execution.md): items 1.4, 2.1, 2.4, 3.3, 3.4, 3.5
- [F4 Derived data and caches](guides/F4-caches.md): items 2.7, 4.2, 4.4
- [F5 Signing](guides/F5-signing.md): items 1.5, 2.3, 2.9
- [F6 Distribution and updates](guides/F6-distribution.md): items 1.1, 1.2, 1.3, 2.10, 2.12, 3.8, 4.3
- [F7 Provenance](guides/F7-provenance.md): items 3.1, 3.2, 3.9
- [F8 Automation and AI agents](guides/F8-agents.md): items 3.6, 3.7, 4.5
- [F9 Partners](guides/F9-partners.md): item 2.8
