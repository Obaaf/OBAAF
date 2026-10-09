"""The documents agree with the data, and every relative link resolves (NFR7)."""

import hashlib
import re
import unittest

from helpers import ROOT, run_cli

from obaaf import render

LINK = re.compile(r"(?<!!)\[[^\]]*\]\(([^)\s]+)\)")
SKIP_DIRS = {".git", "tests", "node_modules"}


def markdown_files():
    for path in sorted(ROOT.rglob("*.md")):
        if not set(path.relative_to(ROOT).parts) & SKIP_DIRS:
            yield path


def anchors(path):
    text = path.read_text(encoding="utf-8")
    found = set(re.findall(r'id="([^"]+)"', text))
    for line in text.splitlines():
        if line.startswith("#"):
            found.add(render.anchor(line.lstrip("#").strip()))
    return found


class GeneratedDocumentsTest(unittest.TestCase):
    def test_generated_files_are_up_to_date(self):
        stale = render.build(ROOT, check_only=True)
        self.assertEqual([p.relative_to(ROOT).as_posix() for p in stale], [],
                         "run 'obaaf docs build' and commit the result")

    def test_cli_docs_check_and_catalog(self):
        self.assertEqual(run_cli("docs", "build", "--check", "--root", ROOT)[0], 0)
        self.assertEqual(run_cli("catalog")[0], 0)


class LinksTest(unittest.TestCase):
    def test_relative_links_and_anchors_resolve(self):
        problems = []
        for path in markdown_files():
            text = path.read_text(encoding="utf-8")
            text = re.sub(r"```.*?```", "", text, flags=re.S)
            for target in LINK.findall(text):
                if re.match(r"^[a-z]+:", target) or target.startswith("mailto:"):
                    continue
                file_part, _, anchor = target.partition("#")
                dest = (path.parent / file_part).resolve() if file_part else path
                if not dest.exists():
                    problems.append(f"{path.relative_to(ROOT)}: missing {target}")
                elif anchor and dest.suffix == ".md" and anchor not in anchors(dest):
                    problems.append(f"{path.relative_to(ROOT)}: missing anchor {target}")
        self.assertEqual(problems, [])

class ConfidentialMaterialTest(unittest.TestCase):
    """NFR9: no employer names in any text file of the repository.

    The names are not written here either: the test compares salted SHA-256 digests of every word
    and every pair of adjacent words (so a name split by a space or a hyphen is found too) with the
    digests of the names.
    """

    SALT = "obaaf-nfr9:"
    BLOCKED = {
        "5de48d29baa3b81c1986ff95145ddde9136c8261a678beb53ccbc0217a4d28fb",
        "f2b0e3f9250d43c677311b072dc27f01220a979e6090a0bc12913f54b7d68aaa",
    }

    def tokens(self, text):
        words = re.findall(r"[a-z0-9]+", text.lower())
        yield from words
        yield from (a + b for a, b in zip(words, words[1:]))

    def test_no_employer_names_in_any_text_file(self):
        found = []
        for path in sorted(ROOT.rglob("*")):
            rel = path.relative_to(ROOT)
            if not path.is_file() or rel.parts[0] in (".git",) or "__pycache__" in rel.parts:
                continue
            try:
                text = path.read_bytes().decode("utf-8")
            except UnicodeDecodeError:
                continue  # not text
            for token in set(self.tokens(text)):
                if hashlib.sha256((self.SALT + token).encode()).hexdigest() in self.BLOCKED:
                    found.append(rel.as_posix())
                    break
        self.assertEqual(found, [], "employer names found (NFR9)")

    def test_the_check_finds_names_however_they_are_written(self):
        # Self-test with a stand-in name, so the check is known to work without writing a real one.
        salt, blocked = self.SALT, {hashlib.sha256((self.SALT + "examplecorp").encode()).hexdigest()}
        for text in ("ExampleCorp", "example corp", "Example-Corp", "EXAMPLE_CORP"):
            tokens = set(self.tokens(text))
            self.assertTrue(any(hashlib.sha256((salt + t).encode()).hexdigest() in blocked for t in tokens), text)


if __name__ == "__main__":
    unittest.main()
