"""A patch from the public CLI replays as the proven bytes on native Git."""

import os
from datetime import date, timedelta
import subprocess
import unittest

from helpers import TempDir, run_cli


class FixPatchTest(unittest.TestCase):
    def setUp(self):
        tmp = TempDir()
        outside = tmp.__enter__()
        self.addCleanup(tmp.__exit__)
        self.root = outside / "source"
        self.patch = outside / "review.patch"
        flows = self.root / ".github/workflows"
        flows.mkdir(parents=True)
        self.workflow = flows / "build.yml"
        self.workflow.write_bytes(b"on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                                  b"    steps:\n      - uses: actions/checkout@v4\n")
        self.config = self.root / ".github/policý review.yml"
        self.git("init", "-q")
        self.git("config", "core.autocrlf", "false")

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def policy(self, ending, final):
        until = (date.today() + timedelta(days=28)).isoformat().encode()
        lines = [b"ignore:", b"  - rule: OBAAF-GHA-008", b"    path: .github/workflows/build.yml",
                 b"    reason: reviewed for adoption", b"    until: " + until]
        return ending.join(lines) + (ending if final else b"")

    def export(self, *extra):
        return run_cli("fix", self.root, "--config", self.config, "--owner", "@team",
                       "--patch", self.patch, *extra)

    def test_git_checks_and_applies_exact_bytes(self):
        for ending in (b"\n", b"\r\n"):
            for final in (False, True):
                with self.subTest(ending=ending, final=final):
                    before = self.policy(ending, final)
                    self.config.write_bytes(before)
                    self.git("add", ".")
                    code, text, err = self.export()
                    self.assertEqual(code, 0, err)
                    self.assertIn("You are accepting risk (1 finding)", text)
                    self.assertEqual(self.config.read_bytes(), before)
                    self.git("apply", "--check", str(self.patch))
                    self.git("apply", str(self.patch))
                    expected = before.replace(b"- rule:", b'- owner: "@team"' + ending + b"    rule:")
                    self.assertEqual(self.config.read_bytes(), expected)
                    self.patch.unlink()

    def test_generated_gate_patch_uses_the_proven_workflow(self):
        from importlib.resources import files
        from obaaf.fix_gate import BASELINE, _candidate
        from obaaf.init import WORKFLOW

        workflow = self.root / WORKFLOW
        before = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
        workflow.write_bytes(before)
        expected = _candidate(before, BASELINE, "medium")
        self.assertIsNotNone(expected)
        self.assertNotEqual(before, expected)
        code, _, err = run_cli("fix", self.root, "--gate", "medium", "--patch", self.patch)
        self.assertEqual(code, 0, err)
        self.assertEqual(workflow.read_bytes(), before)
        self.git("apply", "--check", str(self.patch))
        self.git("apply", str(self.patch))
        self.assertEqual(workflow.read_bytes(), expected)

    def test_existing_destination_and_conflicting_outputs_preserve_both_files(self):
        source = self.policy(b"\n", True)
        self.config.write_bytes(source)
        self.patch.write_bytes(b"prior review\n")
        for extra in ((), ("--apply",)):
            code, _, _ = self.export(*extra)
            self.assertEqual(code, 2)
            self.assertEqual(self.config.read_bytes(), source)
            self.assertEqual(self.patch.read_bytes(), b"prior review\n")

    def test_no_proven_change_leaves_no_patch(self):
        self.config.write_bytes(b"ignore: []\n")
        code, _, _ = self.export()
        self.assertEqual(code, 1)
        self.assertFalse(self.patch.exists())

    @unittest.skipUnless(os.name == "nt", "Windows directory junction")
    def test_windows_refuses_reparse_before_creating_patch(self):
        self.config.write_bytes(self.policy(b"\n", True))
        outside = self.root.parent / "other"
        outside.mkdir()
        link = self.root / "junction"
        result = subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(outside)],
                                capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(os.rmdir, link)
        code, _, err = self.export()
        self.assertEqual(code, 2)
        self.assertIn("reparse point", err)
        self.assertFalse(self.patch.exists())
