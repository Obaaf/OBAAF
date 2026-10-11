# Licensing

**No license is granted yet.** Copyright (c) 2026 Osita Sean Keluo-Udeke. All rights reserved. Public access does not grant a reuse license.

Project contributors: Ofonna Nweze and Osita Sean Keluo-Udeke. The companion
research papers are authored by Osita Sean Keluo-Udeke. Software package
attribution is recorded separately in `pyproject.toml`.

Sean led the research. Ofonna handled implementation, testing, and GitHub
integration, with Sean contributing across the project. These contribution
roles do not change the copyright notice or the release conditions below.

OBAAF is meant to be free and open (NFR1). The intended licenses are:

| Material | Intended license |
| --- | --- |
| Specifications, guides and documentation (`spec/`, `docs/`, the data in `src/obaaf/data/`) | Creative Commons Attribution 4.0 International (CC BY 4.0) |
| Code, templates and tools (`src/`, `templates/`, `actions/`, `tests/`) | Apache License 2.0 |

The maintainer authorized public repository access and website publication on October 10, 2026 and removed the employer-approval prerequisite for that publication (see [DECISIONS.md](DECISIONS.md), D-002). The licenses above remain intended, not granted: adding license texts and confirming their scope is a separate maintainer decision. Copyright ownership and paper affiliations are unchanged.

The data in `src/obaaf/data/` is both: it is the specification, and it ships inside the Python package that the code uses. When licenses are granted, the package's license metadata should say so, for example with the SPDX expression `Apache-2.0 AND CC-BY-4.0` and a note naming which files each covers.

Before granting the intended licenses:

1. Add `LICENSE` (Apache-2.0 text) and `LICENSE-docs` (CC BY 4.0 text) at the root, and the SPDX license expression to `pyproject.toml`, covering the data files as described above.
2. Replace this file's first paragraph with the license notice.
3. Record the license decision in DECISIONS.md and CHANGELOG.md.
