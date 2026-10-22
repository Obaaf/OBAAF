# OBAAF team resource site

The public resource site introduces the framework, provides the browser assessment,
explains the Netflix demonstration, and offers guidance for leads and engineers.
It uses no external fonts, analytics, or client-side package dependencies.
Public draft publication was authorized by the maintainer on October 10, 2026.
The repository remains a draft; see [LICENSING.md](../LICENSING.md) for reuse terms.

## Build and preview

From the repository root, after installing OBAAF:

```bash
python site/build.py
python -m http.server 8080 --directory site/_site
```

Open `http://localhost:8080`. The builder copies only the homepage, CSS, JavaScript,
`.nojekyll`, and the generated questionnaire. It validates local references and anchors.
The questionnaire uses `obaaf.render.form_html`, preserving the package's questions
and scoring rules. Answers stay in the browser and are not uploaded to a server.

## Hosting

The site is hosted at https://obaaf.github.io/OBAAF/. GitHub Pages uses GitHub
Actions as its source. [The deployment workflow](../.github/workflows/pages.yml)
runs after successful CI on main, or by manual dispatch on main. It checks out the
tested revision, builds the dedicated site directory, uploads only that directory,
and deploys through the `github-pages` environment restricted to main.
The build has read-only repository access; only deployment receives Pages write
and OIDC permissions. Pull-request CI builds the site without publishing it.

No custom domain is configured. Once `obaaf.ai` is acquired, configure its DNS and
Pages domain, verify HTTPS, and check all links after the change.
