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

    def test_the_version_is_one_the_tools_can_read(self):
        from obaaf import __version__

        # A release (0.4.0) or the development number before it (0.4.0.dev0). Nothing else is used here,
        # and the notes below and the SARIF report's semanticVersion both rely on this shape.
        self.assertRegex(__version__, r"\A\d+\.\d+\.\d+(\.dev\d+)?\Z")
        self.assertEqual(render.is_release(), ".dev" not in __version__)

    def test_a_release_is_described_as_before(self):
        self.assertEqual(
            render.draft_note("0.3.0"),
            "*Generated for OBAAF 0.3, in active adoption with pilot teams. The content may change in OBAAF 0.4 "
            "based on pilot feedback; open design decisions are tracked in [DECISIONS.md](../DECISIONS.md).*")
        self.assertEqual(
            render.form_note("0.3.0"),
            "OBAAF 0.3.0, in use with pilot teams. It may change in OBAAF 0.4 based on pilot feedback.")
        self.assertTrue(render.is_release("0.3.0"))
        self.assertTrue(render.is_release("1.10.2"))

    def test_a_development_version_is_not_described_as_a_release(self):
        for version, line in (("0.4.0.dev0", "0.4"), ("1.10.0.dev3", "1.10")):
            self.assertFalse(render.is_release(version))
            for note in (render.draft_note(version), render.form_note(version)):
                self.assertIn(version, note)
                self.assertIn("not", note)
                self.assertIn(f"before OBAAF {line} is released", note)
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

    def test_the_release_workflow_refuses_a_tag_that_is_not_the_version(self):
        text = (ROOT / ".github" / "workflows" / "release-pypi.yml").read_text(encoding="utf-8")
        build, rest = text.split("\n  attest:", 1)
        # In the first job, on a tag, before the artifacts are handed to the jobs that sign and upload.
        self.assertIn("if: github.ref_type == 'tag'", build)
        self.assertIn('if [ "v$version" != "$TAG" ]; then', build)
        self.assertLess(build.index('if [ "v$version" != "$TAG" ]; then'), build.index("actions/upload-artifact"))
        self.assertIn("TAG: ${{ github.ref_name }}", build)   # through the environment, never pasted into the script
        self.assertNotIn("${{ github.ref_name }}", build.split("run: |")[-1])


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
