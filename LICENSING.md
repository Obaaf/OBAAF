# Licensing

OBAAF is free and open (NFR1). Two licenses apply, by material:

| Material | License | Text |
| --- | --- | --- |
| Code, templates, tools and tests (`src/`, `templates/`, `actions/`, `tests/`) | Apache License 2.0 | [LICENSE](LICENSE) |
| Specifications, guides and documentation (`spec/`, `docs/`, and the data in `src/obaaf/data/`) | Creative Commons Attribution 4.0 International (CC BY 4.0) | [LICENSE-docs](LICENSE-docs) |

Copyright (c) 2026 Osita Sean Keluo-Udeke.

The data in `src/obaaf/data/` is both: it is the specification (CC BY 4.0) and it ships inside the Python package the code uses (Apache-2.0). The package therefore declares the SPDX license expression `Apache-2.0 AND CC-BY-4.0`, with both texts listed as license files, in [pyproject.toml](pyproject.toml). The split is also recorded in [NOTICE](NOTICE).

## Reusing OBAAF

- **Code (Apache-2.0).** You may use, modify and redistribute it, including commercially, provided you keep the copyright and license notices, state significant changes, and include a copy of [LICENSE](LICENSE) and the [NOTICE](NOTICE) text. The license includes an express patent grant and provides the software "as is", without warranty.
- **Specifications and documentation (CC BY 4.0).** You may share and adapt them, including commercially, provided you credit the project — for example: *"Based on OBAAF (Open Build and Agent Assurance Framework) by Osita Sean Keluo-Udeke, CC BY 4.0"* — link to the license, and indicate if you made changes.

Reusing a data file from `src/obaaf/data/` as part of the running tool falls under Apache-2.0; reusing its content as specification falls under CC BY 4.0. Either license is available for that content; pick the one that fits your use.

## Attribution and status

Project contributors: Ofonna Nweze and Osita Sean Keluo-Udeke. The companion research papers are the independent work of Osita Sean Keluo-Udeke. Software package attribution is recorded in [pyproject.toml](pyproject.toml).

Sean led the research. Ofonna handled implementation, testing, and GitHub integration, with Sean contributing across the project. These contribution roles do not change the copyright notice.

The maintainer authorized public repository access and website publication on October 10, 2026 ([DECISIONS.md](DECISIONS.md), D-002). The license grant on this page is tracked as [D-003](DECISIONS.md); confirming the copyright holder and the affiliation shown on the papers and the repository is the maintainers' acceptance step. The project does not imply endorsement by any government agency or by the research author's employer.
