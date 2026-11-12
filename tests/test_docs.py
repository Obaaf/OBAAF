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


class WhichVersionTheDocumentsSayTest(unittest.TestCase):
    """Between two releases the version is a .devN number, and nothing generated calls that a release."""

    def test_the_version_is_a_release_or_the_development_number_before_one(self):
        from obaaf import __version__

        # 0.4.0, or 0.4.0.dev0 on the way to it. A new shape (a release candidate, say) needs its own wording
        # in the notes below and its own line in the release workflow's check before it is used.
        self.assertRegex(__version__, r"\A\d+\.\d+\.\d+(\.dev\d+)?\Z")

    def test_a_release_is_three_numbers_and_nothing_else(self):
        for version in ("0.3.0", "1.10.2"):
            self.assertTrue(render.is_release(version), version)
        for version in ("0.4.0.dev0", "0.4.1.dev12", "1.0.0rc1", "1.0.0a1", "0.4.0dev0", "0.4.0-dev0",
                        "0.4.0.DEV0", "0.4", "0.4.0.1", "0.4.0 "):
            self.assertFalse(render.is_release(version), version)

    def test_a_release_is_described_as_before(self):
        self.assertEqual(
            render.draft_note("0.3.0"),
            "*Generated for OBAAF 0.3, in active adoption with pilot teams. The content may change in OBAAF 0.4 "
            "based on pilot feedback; open design decisions are tracked in [DECISIONS.md](../DECISIONS.md).*")
        self.assertEqual(
            render.form_note("0.3.0"),
            "OBAAF 0.3.0, in use with pilot teams. It may change in OBAAF 0.4 based on pilot feedback.")
        self.assertIn("OBAAF 1.10, in active adoption", render.draft_note("1.10.2"))
        self.assertIn("in OBAAF 1.11 based on", render.form_note("1.10.2"))

    def test_a_development_version_is_not_described_as_a_release(self):
        # The release it leads to is named in full: 0.4.1.dev0 comes before 0.4.1, and 0.4 is already out.
        for version, leads_to in (("0.4.0.dev0", "0.4.0"), ("0.4.1.dev2", "0.4.1"), ("1.10.0.dev3", "1.10.0")):
            draft, form = render.draft_note(version), render.form_note(version)
            self.assertIn(f"a development version of OBAAF ({version}), not by a release", draft)
            self.assertIn(f"OBAAF {version}, a development version and not a release", form)
            for note in (draft, form):
                self.assertIn(f"before OBAAF {leads_to} is released", note)
                # What is said of a release must not be said of the code between two of them.
                self.assertNotIn("pilot", note)
                self.assertNotIn("adoption", note)

    def test_the_generated_files_carry_the_note_for_this_version(self):
        from obaaf import __version__

        for name in ("profile.md", "agent-controls.md", "self-assessment.md", "checker-rules.md"):
            self.assertIn(render.draft_note(__version__), (ROOT / "spec" / name).read_text(encoding="utf-8"), name)
        form = (ROOT / "assessment" / "obaaf-self-assessment.html").read_text(encoding="utf-8")
        self.assertIn(f'<p class="draft-note">{render.form_note(__version__)}</p>', form)
        self.assertIn(f"Form version {__version__}.", form)
        self.assertNotIn("{{", form.split("<script", 1)[0])   # no placeholder left unfilled in the page

    def test_a_report_does_not_claim_a_release_that_does_not_exist(self):
        import json

        from obaaf import __version__, checker
        from obaaf.checker import report

        # SARIF wants Semantic Versioning, which writes a development version as a pre-release.
        self.assertEqual(report.semantic_version("0.4.0.dev0"), "0.4.0-dev.0")
        self.assertEqual(report.semantic_version("1.10.2.dev13"), "1.10.2-dev.13")
        self.assertEqual(report.semantic_version("0.3.0"), "0.3.0")
        risky = ROOT / "tests" / "fixtures" / "workflows" / "risky" / "pwn-request.yml"
        driver = json.loads(report.to_sarif(checker.check(risky)))["runs"][0]["tool"]["driver"]
        self.assertEqual(driver["version"], __version__)
        self.assertEqual(driver["semanticVersion"], report.semantic_version(__version__))
        if not render.is_release():
            self.assertNotRegex(driver["semanticVersion"], r"\A\d+\.\d+\.\d+\Z")


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
