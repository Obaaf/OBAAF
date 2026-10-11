# OBAAF team resource site

This static site is a review preview for a future GitHub Pages resource. Public
publication is disabled: this PR adds no deployment workflow, Pages configuration,
or licence grant. The release conditions in [LICENSING.md](../LICENSING.md) apply.

The site introduces the framework, provides the existing browser assessment,
explains the Netflix demonstration, and separates guidance for leads and engineers.
It uses no external fonts, analytics, application services, or client-side package
dependencies. Resource links intentionally lead to the private repository during
draft review and currently require repository access.

## Build and preview

From the repository root, after installing OBAAF:

```bash
python site/build.py
python -m http.server 8080 --directory site/_site
```

Open `http://localhost:8080`. The dedicated `_site` directory contains the homepage,
CSS, JavaScript, `.nojekyll`, and the generated questionnaire. The builder copies
only those files, not the papers, private package sources, or repository contents.
It checks local file references and HTML anchors.

The questionnaire is generated with `obaaf.render.form_html`; do not maintain a
second copy of its questions or scoring rules. It prohibits network requests via
its content security policy. External documentation opens only when a user follows
a reference link. Answers are not uploaded to a server.

## Before public launch

1. Confirm written release approval and applicable licensing.
2. Have the maintainers review the site claims, attribution, demonstration exception,
   and the assessment's applicability to the intended audience.
3. Confirm public availability of every linked resource and update links as needed.
4. Add and review a Pages deployment workflow with the appropriate permissions and
   environment protection; select GitHub Actions as the Pages source.
5. Test the published site under its repository subpath on desktop and mobile.

The current CI job builds and checks the site. It does not publish a preview or
upload an artifact that might distribute the draft to another audience.
