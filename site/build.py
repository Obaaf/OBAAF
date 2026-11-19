"""Build the public resource site from its explicit asset list."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

import html
import json
import re
from importlib import resources

from obaaf import predicates, render
from obaaf.catalog import data_text

SOURCE = Path(__file__).resolve().parent

class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.references = []
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if 'id' in values:
            self.ids.add(values['id'])
        for attr in ('href', 'src'):
            if attr in values:
                self.references.append(values[attr])

def validate(output):
    pages = {}
    for path in output.rglob('*.html'):
        parser = Links()
        parser.feed(path.read_text(encoding='utf-8'))
        if path.name == 'assessment.html':
            # The form creates these headings from the same catalog in renderItems().
            parser.ids.update(f"tier-{tier['id']}" for tier in render.form_data()['tiers'])
        pages[path.resolve()] = parser
    for path, parser in pages.items():
        for reference in parser.references:
            parsed = urlsplit(reference)
            if parsed.scheme or parsed.netloc:
                continue
            target = (path.parent / unquote(parsed.path)).resolve() if parsed.path else path
            if not target.is_relative_to(output.resolve()) or not target.is_file():
                raise ValueError(f'{path.name}: missing or unsafe local link {reference}')
            if parsed.fragment and target in pages and unquote(parsed.fragment) not in pages[target].ids:
                raise ValueError(f'{path.name}: missing anchor {reference}')


# Pages behind OBAAF's type URIs (DECISIONS.md, D-007). Each in-toto predicate type
# URI and the generic build type resolve to a page that describes the format, and each
# schema's $id resolves to the schema file itself.
FORMATS = {
    "agent-run": ("Agent-run record", "The files of the proposal bundle",
                  "obaaf attest agent-run", "the agent lane's attest job",
                  "In the reference workflow a separate trusted job constructs the record and treats "
                  "the agent's trace as untrusted."),
    "agent-approval": ("Approval record", "The files of the proposal bundle",
                       "obaaf attest approval", "the effect lane's approve job",
                       "Records who approved applying the proposal. In the reference workflow "
                       "`obaaf attest approval` checks the supplied approvals for a reviewer outside "
                       "the requester list before writing the record."),
    "build-record": ("Build record", "The release artifacts",
                     "obaaf attest build-record", "the release lane's attest job",
                     "Records how a release artifact was built. The source, assets, manifest, SDK "
                     "entries and isolation fields identify their reporters."),
}
DOCS = "https://github.com/Obaaf/OBAAF/blob/main/docs/attestations.md"


def _inline(text):
    """Escape text and turn `code` spans into <code> elements."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text, quote=False))


def _page(title, canonical, depth, body):
    up = "../" * depth
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} | OBAAF</title>
  <link rel="canonical" href="{canonical}">
  <link rel="stylesheet" href="{up}styles.css">
  <style>.format code{{overflow-wrap:anywhere}}</style>
</head>
<body>
<header class="header wrap"><a class="brand" href="{up}index.html">OBAAF</a></header>
<main id="main" class="format section wrap">
{body}
</main>
</body>
</html>
"""


def write_formats(output):
    """Publish a page per predicate type and build type, and the schemas at their $id."""
    for name, (label, subjects, command, signer, description) in FORMATS.items():
        uri = predicates.OBAAF_TYPES[name]
        schema_rel = predicates.SCHEMA_FOR_TYPE[uri]
        schema_text = data_text(schema_rel)
        schema = json.loads(schema_text)
        schema_id = predicates.SCHEMA_ID[uri]
        if schema.get("$id") != schema_id:
            raise ValueError(f"{schema_rel}: $id {schema.get('$id')!r} does not match {schema_id!r}")
        schema_path = output / schema_id.removeprefix(predicates.NAMESPACE + "/")
        schema_path.parent.mkdir(parents=True, exist_ok=True)
        schema_path.write_text(schema_text, encoding="utf-8")
        page_dir = output / uri.removeprefix(predicates.NAMESPACE + "/")
        page_dir.mkdir(parents=True, exist_ok=True)
        depth = len(page_dir.relative_to(output).parts)
        schema_link = "../" * depth + schema_path.relative_to(output).as_posix()
        body = f"""<div class="section-label">IN-TOTO PREDICATE TYPE</div>
<h2>{label}, version 0.1</h2>
<p class="large">{_inline(description)}</p>
<p><strong>Type URI.</strong> <code>{uri}</code></p>
<p><strong>Subjects.</strong> {subjects}, each identified by its SHA-256 digest.</p>
<p><strong>Written by.</strong> <code>{command}</code>. The command writes an unsigned predicate. In the configured GitHub reference workflow, {signer} signs through GitHub's Sigstore using the workflow identity.</p>
<p><strong>JSON Schema.</strong> <a href="{schema_link}">{schema_id}</a></p>
<p><strong>Documentation.</strong> <a href="{DOCS}">Records and attestation formats</a></p>
<p class="caption">Version 0.1 may change before OBAAF 1.0. A changed format gets a new version and a new URI; this page and its schema stay as published.</p>"""
        (page_dir / "index.html").write_text(_page(f"{label}, version 0.1", uri, depth, body), encoding="utf-8")

    uri = predicates.GENERIC_BUILD_TYPE
    page_dir = output / uri.removeprefix(predicates.NAMESPACE + "/")
    page_dir.mkdir(parents=True, exist_ok=True)
    depth = len(page_dir.relative_to(output).parts)
    body = f"""<div class="section-label">SLSA BUILD TYPE</div>
<h2>Generic build, version 0.1</h2>
<p class="large">The <code>buildType</code> of SLSA v1 provenance written by <code>obaaf attest slsa</code>, for CI systems that do not generate provenance themselves. On GitHub Actions, OBAAF uses the provenance GitHub generates instead.</p>
<p><strong>Type URI.</strong> <code>{uri}</code></p>
<p><strong>External parameters.</strong> <code>source</code> gives the repository URI and ref, alongside any parameters passed to the command.</p>
<p><strong>Internal parameters.</strong> None.</p>
<p><strong>Resolved dependencies.</strong> The source repository at the built commit.</p>
<p><strong>Documentation.</strong> <a href="{DOCS}">Records and attestation formats</a></p>"""
    (page_dir / "index.html").write_text(_page("Generic build, version 0.1", uri, depth, body), encoding="utf-8")

def write_schemas(output):
    """Publish every JSON Schema OBAAF ships whose $id is under its namespace at that $id (D-007),
    not only the predicate types' (flagship slice 4.6, issue #176: the settings snapshot's was not
    published). A schema whose $id is elsewhere, names no .json file under schemas/ once resolved, or is
    another schema's, stops the build, as does a file that is not a JSON object."""
    written = {}
    folder = (output / "schemas").resolve()
    for entry in sorted(resources.files("obaaf.data").joinpath("schemas").iterdir(), key=lambda e: e.name):
        if not entry.name.endswith(".json"):
            continue
        text = entry.read_text(encoding="utf-8")
        try:
            schema = json.loads(text)
        except ValueError as exc:
            raise ValueError(f"schemas/{entry.name}: not JSON ({exc})") from None
        schema_id = schema.get("$id") if isinstance(schema, dict) else None
        if not isinstance(schema_id, str) or not schema_id.startswith(predicates.NAMESPACE + "/schemas/"):
            raise ValueError(f"schemas/{entry.name}: $id {schema_id!r} is not under {predicates.NAMESPACE}/schemas/")
        path = (output / schema_id.removeprefix(predicates.NAMESPACE + "/")).resolve()
        # Resolved, so `schemas/../x.json` is caught too (found by the review of slice 4.6).
        if not path.is_relative_to(folder) or path.suffix != ".json":
            raise ValueError(f"schemas/{entry.name}: $id {schema_id!r} does not name a .json file under schemas/")
        if path in written:
            raise ValueError(f"schemas/{entry.name}: $id {schema_id!r} is also the $id of schemas/{written[path]}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        written[path] = entry.name
    return sorted(written.values())


ASSESSMENT_CANONICAL = predicates.NAMESPACE + "/assessment.html"
ASSESSMENT_NOSCRIPT = (
    '<noscript><p>This questionnaire needs JavaScript, which is off in this browser. The same questions '
    'are in <a href="https://github.com/Obaaf/OBAAF/blob/main/spec/self-assessment.md">the self-assessment</a>, '
    'and the command line scores them: <code>obaaf assess init</code> writes an answer file to fill in, and '
    '<code>obaaf assess score</code> scores it.</p></noscript>')


def assessment_page():
    """The questionnaire from `obaaf.render.form_html`, with the site's navigation, its canonical address
    (D-007) and a note for a browser without JavaScript, whose questions the form's script writes
    (flagship slice 4.6). The offline form, built from the same template, is not changed."""
    page = render.form_html(link_base='https://github.com/Obaaf/OBAAF/blob/main/')
    for old, new in (
            ('<header>', '<header>\n<nav aria-label="Resource site"><a href="index.html">Back to the OBAAF field guide</a></nav>'),
            ('</head>', f'<link rel="canonical" href="{ASSESSMENT_CANONICAL}">\n</head>'),
            # Before the element, not in it: the form's CSS styles the first tier as `:first-child`
            # (found by the review of slice 4.6).
            ('<div id="tiers"></div>', f'{ASSESSMENT_NOSCRIPT}<div id="tiers"></div>')):
        if page.count(old) != 1:
            raise ValueError(f"assessment.html: expected one {old!r} in the form, found {page.count(old)}")
        page = page.replace(old, new, 1)
    return page


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=SOURCE / '_site')
    args = parser.parse_args()
    output = args.output.resolve()
    # Build into a dedicated directory; never copy the whole repository.
    if output == SOURCE or output == SOURCE.parent:
        parser.error('output must be a dedicated build directory')
    output.mkdir(parents=True, exist_ok=True)
    for name in ('index.html', 'quickstart.html', 'rules.html', 'comparison.html',
                 'case-study.html', 'papers.html', 'styles.css', 'main.js'):
        (output / name).write_bytes((SOURCE / name).read_bytes())
    (output / 'assessment.html').write_text(assessment_page(), encoding='utf-8')
    (output / '.nojekyll').write_text('', encoding='utf-8')
    write_formats(output)
    write_schemas(output)
    validate(output)
    print(f'Site built and local links validated: {output}')

if __name__ == '__main__':
    main()
