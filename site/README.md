# OBAAF website

The public website says what OBAAF's latest release does and what is only in the development
version, and how to try it. It has a home page (`index.html`) and five pages: a quickstart, where
to read the rule catalogue, a dated reading of the landscape comparison, the Expectrail case
study, and the papers. The five pages link to each other and to the home page; the home page does
not link to them yet (plan slice 4.4). The site also carries the browser self-assessment and the
pages that describe OBAAF's attestation formats.
It uses no external fonts, analytics, or client-side package dependencies. The home page, the
five pages and the format pages read without JavaScript; the self-assessment needs it, because
its questions are written into the page by a script.
Public draft publication was authorized by the maintainer on October 10, 2026.
The repository remains a draft; see [LICENSING.md](../LICENSING.md) for reuse terms.

## Build and preview

From the repository root, install OBAAF from this checkout as CI does, then build:

```bash
python -m pip install --constraint actions/setup-obaaf/constraints.txt -e .
python site/build.py
python -m http.server 8080 --directory site/_site
```

Open `http://localhost:8080`. The builder writes only into `site/_site` (or the directory given
with `--output`), and validates local references and anchors. It does not empty that directory
first, so delete it before a build if earlier files should not be there. It copies `index.html`,
`quickstart.html`, `rules.html`, `comparison.html`, `case-study.html`, `papers.html`,
`styles.css` and `main.js`; writes `.nojekyll`; writes the questionnaire, `assessment.html`; and
writes a page for each of OBAAF's predicate types and its generic build type, under
`attestation/` and `buildtypes/`, and each predicate type's JSON Schema at its `$id`, under
`schemas/` (decision D-007). The settings snapshot's schema, which also has an `$id` under
`https://www.obaaf.com/`, is not published.
The questionnaire uses `obaaf.render.form_html`, preserving the package's questions
and scoring rules. Answers stay in the browser and are not uploaded to a server. The builder uses
whichever `obaaf` is installed, so with `pip install obaaf` (the latest release) the questionnaire
you preview is the release's, not the one that would deploy.

## Hosting

GitHub Pages uses GitHub Actions as its source. [The deployment workflow](../.github/workflows/pages.yml)
runs after CI succeeds on a push to main, or by manual dispatch on main. After CI, it checks out
`main` and stops unless `main` is still the revision CI tested; a manual dispatch publishes the
head of `main` without that check. It builds the dedicated site directory, uploads only that
directory, and deploys through the `github-pages` environment, which is meant to be restricted to
main (a repository setting, not in the workflow, and not checked when this was written).
The build has read-only repository access; only deployment receives Pages write
and OIDC permissions. Pull-request CI builds the site without publishing it.
So the site shows `main` as of its last successful deployment: a change merged into
another branch is not published until that branch reaches `main`.

The home page, the five pages and the format pages name `https://www.obaaf.com/` as their
canonical host, and the format pages' URIs are under it (decision D-007); the self-assessment
names no canonical address. GitHub Pages' own address for this repository is
`https://obaaf.github.io/OBAAF/`. Whether `www.obaaf.com` is set as the Pages custom domain, and
whether its DNS points there, was not checked when this was written (2026-11-15): neither the
repository's Pages settings nor the domain's DNS could be read from the session that wrote it. If
it is not, configure the domain's DNS and the Pages custom domain, verify HTTPS, and check all
links after the change.
