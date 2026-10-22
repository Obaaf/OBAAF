"""Build the public resource site from its explicit asset list."""
import argparse
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

from obaaf import render

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
    for path in output.glob('*.html'):
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

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=SOURCE / '_site')
    args = parser.parse_args()
    output = args.output.resolve()
    # Build into a dedicated directory; never copy the whole repository.
    if output == SOURCE or output == SOURCE.parent:
        parser.error('output must be a dedicated build directory')
    output.mkdir(parents=True, exist_ok=True)
    for name in ('index.html', 'styles.css', 'main.js'):
        (output / name).write_bytes((SOURCE / name).read_bytes())
    assessment = render.form_html(link_base='https://github.com/Obaaf/OBAAF/blob/main/')
    assessment = assessment.replace('<header>',
        '<header>\n<nav aria-label="Resource site"><a href="index.html">Back to the OBAAF field guide</a></nav>', 1)
    (output / 'assessment.html').write_text(assessment, encoding='utf-8')
    (output / '.nojekyll').write_text('', encoding='utf-8')
    validate(output)
    print(f'Site built and local links validated: {output}')

if __name__ == '__main__':
    main()
