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


class FixPatchReviewTest(unittest.TestCase):
    """review-gpt #368: what git apply would apply elsewhere, skip or hide is refused."""

    setUp, git, policy, export = FixPatchTest.setUp, FixPatchTest.git, FixPatchTest.policy, FixPatchTest.export

    def test_a_folder_below_the_top_of_the_work_tree_is_refused(self):
        # From the top, git apply changed the top folder's own `.github/obaaf.yml`, which the proof
        # never read; from the folder, it skipped the patch. Both exited 0.
        source = self.policy(b"\n", True)
        self.config.write_bytes(source)
        inner = self.root / "svc"
        (inner / ".github/workflows").mkdir(parents=True)
        (inner / ".github/workflows/build.yml").write_bytes(self.workflow.read_bytes())
        inner_config = inner / ".github/policý review.yml"
        inner_config.write_bytes(source)
        self.git("add", ".")
        code, _, err = run_cli("fix", inner, "--config", inner_config, "--owner", "@team", "--patch", self.patch)
        self.assertEqual(code, 2, err)
        self.assertIn("top folder of the Git work tree", err)
        self.assertFalse(self.patch.exists())
        self.assertEqual(self.config.read_bytes(), source)
        self.assertEqual(inner_config.read_bytes(), source)

    def test_a_gate_below_the_top_of_the_work_tree_is_refused(self):
        from importlib.resources import files
        from obaaf.init import WORKFLOW

        inner = self.root / "svc"
        (inner / WORKFLOW).parent.mkdir(parents=True)
        (inner / WORKFLOW).write_bytes(files("obaaf.data").joinpath("init-workflow.yaml").read_bytes())
        self.git("add", ".")
        code, _, err = run_cli("fix", inner, "--gate", "medium", "--patch", self.patch)
        self.assertEqual(code, 2, err)
        self.assertFalse(self.patch.exists())

    def test_a_hidden_or_transformed_target_is_refused(self):
        source = self.policy(b"\n", True)
        self.config.write_bytes(source)
        self.git("add", ".")
        for hide, attribute in ((("update-index", "--assume-unchanged"), None),
                                (("update-index", "--skip-worktree"), None),
                                (None, "ident"), (None, "filter=lfs")):
            with self.subTest(hide=hide, attribute=attribute):
                if hide:
                    self.git(*hide, str(self.config.relative_to(self.root)))
                if attribute:
                    (self.root / ".gitattributes").write_text(f"*.yml {attribute}\n")
                code, _, err = self.export()
                self.assertEqual(code, 2, err)
                self.assertFalse(self.patch.exists())
                if hide:
                    self.git(hide[0], hide[1].replace("--", "--no-"), str(self.config.relative_to(self.root)))
                if attribute:
                    (self.root / ".gitattributes").unlink()
        code, _, err = self.export()
        self.assertEqual(code, 0, err)

    def test_a_failed_write_leaves_no_patch_and_a_retry_succeeds(self):
        import errno
        from unittest import mock

        self.config.write_bytes(self.policy(b"\n", True))
        self.git("add", ".")
        with mock.patch("obaaf.fix_patch.os.write", side_effect=OSError(errno.ENOSPC, "No space left on device")):
            code, _, err = self.export()
        self.assertEqual(code, 2, err)
        self.assertFalse(self.patch.exists())
        code, _, err = self.export()
        self.assertEqual(code, 0, err)
        self.git("apply", "--check", str(self.patch))

    def test_git_ends_a_line_only_at_a_line_feed(self):
        from pathlib import Path
        from obaaf.fix_patch import save_patch
        from obaaf.fix_proof import Edit

        target = self.root / "notes.txt"
        before = b"one\rtwo\nthree\nfour\r"
        after = b"one\rtwo\nTHREE\nfour\r"
        target.write_bytes(before)
        save_patch(self.root, self.patch, (Edit(Path("notes.txt"), before, after, ()),))
        self.git("apply", "--check", str(self.patch))
        self.git("apply", str(self.patch))
        self.assertEqual(target.read_bytes(), after)

    def test_outside_a_work_tree_the_patch_is_written(self):
        import shutil
        from pathlib import Path
        from obaaf.fix_patch import save_patch
        from obaaf.fix_proof import Edit

        shutil.rmtree(self.root / ".git")
        probe = subprocess.run(["git", "-C", str(self.root), "rev-parse", "--is-inside-work-tree"], capture_output=True)
        if probe.returncode == 0:
            self.skipTest("the temporary folder is inside a Git work tree")
        target = self.root / "notes.txt"
        target.write_bytes(b"a\n")
        save_patch(self.root, self.patch, (Edit(Path("notes.txt"), b"a\n", b"b\n", ()),))
        done = subprocess.run(["git", "apply", str(self.patch)], cwd=self.root, capture_output=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(target.read_bytes(), b"b\n")
