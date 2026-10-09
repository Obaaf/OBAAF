# OBAAF documentation

| Document | For | What it covers |
| --- | --- | --- |
| [Adoption guide](adoption-guide.md) | Studios | Tier by tier, what to do and which template or guide helps |
| [Guides F1–F9](guides/) | Studios | How to fix each self-assessment item, by control family |
| [GitHub settings](github-settings.md) | Build engineers | Repository settings the templates depend on, and plan limits |
| [Templates](../templates/github-actions/README.md) | Build engineers | Installing and adapting the GitHub Actions workflows |
| [Inference proxy](inference-proxy.md) | Build engineers | The contract for keeping model credentials out of agent jobs |
| [Architecture](architecture.md) | Reviewers | Components, lanes, trust levels, what enforces what, limits |
| [Records and attestations](attestations.md) | Reviewers, platforms | The snapshot, agent-run, approval and build-record formats |
| [Traceability](traceability.md) | Reviewers | Each functional requirement, where it is built, and how it is tested |
| [Live acceptance tests](live-acceptance-tests.md) | Maintainers | Procedures for a sandbox GitHub repository |
| [Glossary](glossary.md) | Everyone | Plain-language meanings of the terms used here |

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
