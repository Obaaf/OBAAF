# Contributing

OBAAF accepts contributions under the rules below. Version 0.x formats may still change before 1.0, so open an issue before a large change.

## Ground rules

- **Public sources only.** Everything in this repository comes from public standards, public documentation and public research. Never add employer configuration, code or architecture, or anything covered by a platform's nondisclosure agreement (NFR9). If in doubt, leave it out and ask.
- **Data first.** The profile, agent controls, self-assessment, checker rules and documented cases live in `src/obaaf/data/`. Edit the data, then run `obaaf docs build` to regenerate `spec/` and the offline form. Never edit generated files by hand; CI fails if they drift.
- **Stable IDs.** Requirement, item and rule IDs never change meaning. Retire an ID rather than reuse it (NFR7).
- **Every change to a requirement has a reason.** Record design decisions in [DECISIONS.md](DECISIONS.md) and user-visible changes in [CHANGELOG.md](CHANGELOG.md).
- **Tests with every rule.** A new checker rule comes with a workflow in `tests/fixtures/workflows/risky/` that it must catch, and the installed templates must still pass `obaaf check` with no findings other than the documented egress finding (`OBAAF-GHA-020`, see [the templates](templates/github-actions/README.md#egress)).

## Checks before a pull request

```bash
python -m unittest discover -s tests -v
obaaf docs build --check
obaaf catalog
obaaf check .
```

## Review responsibility

The maintainers review, edit and test changes before merging them. Contributors are responsible for their submissions and must have the right to contribute them under the project's applicable terms. Proposed decisions remain pending in [DECISIONS.md](DECISIONS.md) until explicitly accepted, changed or rejected.

## Licenses

OBAAF is licensed under Apache-2.0 for code and CC BY 4.0 for documentation; see [LICENSING.md](LICENSING.md). Contributions are accepted under the same licenses, with a Developer Certificate of Origin sign-off (`git commit -s`).
