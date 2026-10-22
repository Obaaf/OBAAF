# Governance

*Draft, for maintainer confirmation. It records how OBAAF is already run and sets out how the project adds maintainers and makes decisions. It changes nothing about copyright ([LICENSING.md](LICENSING.md)).*

OBAAF is a free, open project (NFR1). This document states who decides what, how changes are made, and how someone becomes a maintainer. The aim is a structure a new contributor — or an external reviewer — can understand at a glance.

## Maintainers

The project is run by its maintainers, who together hold merge authority and are accountable for its direction and security.

| Maintainer | Primary area |
| --- | --- |
| Osita Sean Keluo-Udeke | Research lead — specification, the agent controls, the companion papers |
| Ofonna Nweze | Implementation lead — the tools, tests, and GitHub integration |

Both maintain the project across all areas; the "primary area" names where each leads when a decision is otherwise tied.

## How decisions are made

- **Day to day:** lazy consensus. A maintainer proposes a change as an issue or pull request; if no other maintainer objects within a reasonable time, it proceeds.
- **Significant or architectural changes** (the specification, the controls, the threat model, licensing, the release process, adding or removing a maintainer) are recorded in [DECISIONS.md](DECISIONS.md) as a numbered decision, moving from *Proposed* to *Accepted* once the maintainers agree. The decisions log is the project's record of why things are the way they are.
- **Disagreements** are resolved by the maintainers together; where they cannot agree, the lead for the relevant area (above) decides, and the decision and its reason are recorded.

## Contributing

Anyone may contribute. Proposals come in as issues and pull requests under [CONTRIBUTING.md](CONTRIBUTING.md), which requires a Developer Certificate of Origin sign-off (`git commit -s`). Security issues follow [SECURITY.md](SECURITY.md) and are not reported in public issues. OBAAF's own agent controls govern any AI-assisted contribution to this repository.

## Becoming a maintainer

The project actively wants to grow beyond its two founders, including with maintainers from other organizations.

- **Criteria:** a sustained record of high-quality contributions (code, specification, review, or community work), good judgment on security, and the trust of the existing maintainers.
- **Process:** any maintainer may nominate a contributor; the nomination is recorded as a decision in [DECISIONS.md](DECISIONS.md) and takes effect on the agreement of the existing maintainers. A maintainer may step down at any time, and inactivity over a long period may move a maintainer to emeritus status by the same recorded process.

## Code of conduct

The project follows the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). Reports of unacceptable behavior go to the maintainers. *(Adopting it as a `CODE_OF_CONDUCT.md` file in the repository is a recommended next step.)*

## Changes to this document

Changes to OBAAF's governance are themselves significant decisions: they are proposed as a pull request, recorded in [DECISIONS.md](DECISIONS.md), and take effect on maintainer agreement.
