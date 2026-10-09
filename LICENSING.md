# Licensing

**No license is granted yet.** Copyright (c) 2026 Osita Sean Keluo-Udeke. All rights reserved until public release.

OBAAF is meant to be free and open (NFR1). The intended licenses are:

| Material | Intended license |
| --- | --- |
| Specifications, guides and documentation (`spec/`, `docs/`, the data in `src/obaaf/data/`) | Creative Commons Attribution 4.0 International (CC BY 4.0) |
| Code, templates and tools (`src/`, `templates/`, `actions/`, `tests/`) | Apache License 2.0 |

These licenses take effect only when the project is publicly released. Release requires the written approval of the author's employer, which has not yet been given (see [DECISIONS.md](DECISIONS.md), D-002 and D-003). Until then, this repository must stay private.

The data in `src/obaaf/data/` is both: it is the specification, and it ships inside the Python package that the code uses. The package's license metadata must say so, for example with the SPDX expression `Apache-2.0 AND CC-BY-4.0` and a note naming which files each covers.

When approval arrives, the release checklist is:

1. Add `LICENSE` (Apache-2.0 text) and `LICENSE-docs` (CC BY 4.0 text) at the root, and the SPDX license expression to `pyproject.toml`, covering the data files as described above.
2. Replace this file's first paragraph with the license notice.
3. Record the approval and the release in DECISIONS.md and CHANGELOG.md.
