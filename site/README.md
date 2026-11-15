# OBAAF website

The public website says what OBAAF's latest release does and what is only in the development
version, and how to try it. It has a home page (`index.html`) and five pages behind it: a
quickstart, where to read the rule catalogue, a dated reading of the landscape comparison, the
Expectrail case study, and the papers. It also carries the browser self-assessment and the pages
that describe OBAAF's attestation formats.
It uses no external fonts, analytics, or client-side package dependencies, and its content reads
without JavaScript.
Public draft publication was authorized by the maintainer on October 10, 2026.
The repository remains a draft; see [LICENSING.md](../LICENSING.md) for reuse terms.

## Build and preview

From the repository root, after installing OBAAF:

```bash
python site/build.py
python -m http.server 8080 --directory site/_site
```

Open `http://localhost:8080`. The builder writes only into `site/_site` (or the directory given
with `--output`), and validates local references and anchors. It copies `index.html`,
`quickstart.html`, `rules.html`, `comparison.html`, `case-study.html`, `papers.html`,
`styles.css` and `main.js`; writes `.nojekyll`; writes the questionnaire, `assessment.html`; and
writes a page for each of OBAAF's predicate types and its generic build type, under
`attestation/` and `buildtypes/`, and each JSON Schema at its `$id`, under `schemas/` (decision
D-007).
The questionnaire uses `obaaf.render.form_html`, preserving the package's questions
and scoring rules. Answers stay in the browser and are not uploaded to a server.

## Hosting

GitHub Pages uses GitHub Actions as its source. [The deployment workflow](../.github/workflows/pages.yml)
runs after successful CI on main, or by manual dispatch on main. It checks out the
tested revision, builds the dedicated site directory, uploads only that directory,
and deploys through the `github-pages` environment restricted to main.
The build has read-only repository access; only deployment receives Pages write
and OIDC permissions. Pull-request CI builds the site without publishing it.
So the site shows what is on `main`: a change merged into another branch is not published until
that branch reaches `main`.

Every page names `https://www.obaaf.com/` as its canonical host, and the format pages' URIs are
under it (decision D-007). GitHub Pages' own address for this repository is
`https://obaaf.github.io/OBAAF/`. Whether `www.obaaf.com` is set as the Pages custom domain, and
whether its DNS points there, was not checked when this was written (2026-11-15): neither the
repository's Pages settings nor the domain's DNS could be read from the session that wrote it. If
it is not, configure the domain's DNS and the Pages custom domain, verify HTTPS, and check all
links after the change.
