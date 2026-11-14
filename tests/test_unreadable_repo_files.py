"""Slice 2d.8 (from #155): a repository file the checks need and cannot read is an error, and
`obaaf check --lanes` refuses the options `obaaf check` refuses."""

import os
import unittest
from pathlib import Path
from unittest import mock

from helpers import TempDir, run_cli

from obaaf import checker
from obaaf.checker import repo as repo_checks

WORKFLOW = "on: push\npermissions: {}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"


def repository(tmp: Path) -> Path:
    root = tmp / "repo"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "x.yml").write_text(WORKFLOW, encoding="utf-8")
    return root


class UnreadableCodeownersTest(unittest.TestCase):
    @unittest.skipUnless(os.path.exists("/proc/self/mem"), "needs /proc/self/mem, which gives an I/O error on read")
    def test_check_and_lanes_report_an_error_not_a_traceback(self):
        with TempDir() as tmp:
            root = repository(tmp)
            (root / ".github" / "CODEOWNERS").symlink_to("/proc/self/mem")
            code, out, err = run_cli("check", str(root), "--fail-on", "never")
            self.assertEqual(code, 1, err)
            self.assertNotIn("Traceback", err)
            self.assertIn(".github/CODEOWNERS: cannot be read", out + err)
            result = checker.check(root)
            self.assertFalse([f for f in result.findings if f.rule in ("OBAAF-REPO-001", "OBAAF-REPO-002")])
            code, out, err = run_cli("check", str(root), "--lanes")
            self.assertEqual(code, 1, err)
            self.assertIn(".github/CODEOWNERS: cannot be read", err)

    def test_the_reader_raises_for_a_file_it_cannot_read(self):
        with TempDir() as tmp:
            root = repository(tmp)
            (root / ".github" / "CODEOWNERS").write_text("* @owner\n", encoding="utf-8")
            with mock.patch.object(Path, "read_text", side_effect=PermissionError(13, "Permission denied")):
                with self.assertRaises(repo_checks.UnreadableFile) as caught:
                    repo_checks.read_codeowners(root)
            self.assertEqual(caught.exception.rel, ".github/CODEOWNERS")


class UnreadableInstructionFileTest(unittest.TestCase):
    def test_an_instruction_file_that_cannot_be_read_is_an_error(self):
        with TempDir() as tmp:
            root = repository(tmp)
            (root / ".github" / "CODEOWNERS").write_text("* @owner\n", encoding="utf-8")
            (root / "AGENTS.md").write_text("Be careful.\n", encoding="utf-8")
            real = Path.read_text

            def read_text(self, *args, **kwargs):
                if self.name == "AGENTS.md":
                    raise PermissionError(13, "Permission denied")
                return real(self, *args, **kwargs)

            with mock.patch.object(Path, "read_text", read_text):
                result = checker.check(root)
            self.assertIn("AGENTS.md: cannot be read: Permission denied", result.errors)

    def test_a_directory_that_cannot_be_listed_is_a_note(self):
        with TempDir() as tmp:
            root = repository(tmp)
            (root / "locked").mkdir()
            real = Path.iterdir

            def iterdir(self):
                if self.name == "locked":
                    raise PermissionError(13, "Permission denied")
                return real(self)

            with mock.patch.object(Path, "iterdir", iterdir):
                result = checker.check(root)
            self.assertEqual(result.errors, [])
            self.assertTrue(any("locked/" in note and "could not be listed" in note for note in result.notes),
                            result.notes)


class FoldersThatCannotBeEnteredTest(unittest.TestCase):
    """Found by the review: a folder that can be listed but not entered ended both commands in a
    traceback, from `is_file` on a CODEOWNERS place and from `is_symlink` in the walk."""

    def test_a_codeowners_place_that_cannot_be_looked_in_is_an_error(self):
        with TempDir() as tmp:
            root = repository(tmp)
            real = Path.is_file

            def is_file(self):
                if self.parent.name == "docs":
                    raise PermissionError(13, "Permission denied")
                return real(self)

            with mock.patch.object(Path, "is_file", is_file):
                result = checker.check(root)
            self.assertIn("docs/CODEOWNERS: cannot be read: Permission denied", result.errors)

    def test_entries_that_cannot_be_looked_at_make_a_note(self):
        with TempDir() as tmp:
            root = repository(tmp)
            (root / ".github" / "CODEOWNERS").write_text("* @owner\n", encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "AGENTS.md").write_text("x\n", encoding="utf-8")
            real = Path.is_symlink

            def is_symlink(self):
                if self.parent.name == "sub":
                    raise PermissionError(13, "Permission denied")
                return real(self)

            with mock.patch.object(Path, "is_symlink", is_symlink):
                result = checker.check(root)
            self.assertEqual(result.errors, [])
            self.assertTrue(any("sub/" in note for note in result.notes), result.notes)


class LanesRefusesWhatCheckRefusesTest(unittest.TestCase):
    def test_lanes_takes_no_option_that_writes(self):
        with TempDir() as tmp:
            root = repository(tmp)
            for options in (["--write-baseline", str(tmp / "b.json")], ["--output", str(tmp / "out.txt")]):
                with self.subTest(options=options):
                    code, _, err = run_cli("check", str(root), "--lanes", *options)
                    self.assertEqual(code, 2, err)
                    self.assertIn("writes nothing", err)

    def test_options_check_refuses_end_lanes_with_2(self):
        with TempDir() as tmp:
            root = repository(tmp)
            for options in (["--fail-on", "bogus"], ["--baseline", str(tmp / "missing.json")], ["--owner", "@x"],
                            ["--baseline", "a.json", "--write-baseline", "b.json"]):
                with self.subTest(options=options):
                    code, _, err = run_cli("check", str(root), "--lanes", *options)
                    self.assertEqual(code, 2, err)
                    code, _, _ = run_cli("check", str(root), *options)
                    self.assertEqual(code, 2)
            code, out, _ = run_cli("check", str(root), "--lanes", "--fail-on", "medium")
            self.assertEqual(code, 0)
            self.assertIn("x.yml#a", out)


if __name__ == "__main__":
    unittest.main()
