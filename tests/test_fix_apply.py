"""Apply writes only the fresh proven diff, and only to clean tracked files."""

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from helpers import run_cli
from obaaf import fix_apply
from obaaf.fix_apply import apply_edits, apply_lock
from obaaf.fix_proof import Edit, ProofError


@unittest.skipUnless(os.name == "posix" and shutil.which("git"), "requires POSIX and Git")
class FixApplyTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.git("init", "-q")
        self.config = Path(".github/obaaf.yml")
        workflows = self.root / ".github/workflows"
        workflows.mkdir(parents=True)
        (workflows / "ci.yml").write_text("on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
                                          "    steps:\n      - run: echo hello\n")
        (self.root / self.config).write_text("lanes:\n  .github/workflows/ci.yml#build: trused\n")
        (self.root / self.config).chmod(0o750)
        self.other = Path("policy.json")
        (self.root / self.other).write_bytes(b'{"version":1}\n')
        self.git("add", ".")
        self.commit()

    def git(self, *args):
        return subprocess.run(["git", *args], cwd=self.root, check=True,
                              env={k: v for k, v in os.environ.items() if not k.startswith("GIT_")},
                              capture_output=True).stdout

    def commit(self):
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.org", "commit", "-qm", "fixture")

    def edits(self):
        return tuple(Edit(path, (self.root / path).read_bytes(), new, (("key",),))
                     for path, new in ((self.config, b"lanes: {}\n"), (self.other, b'{"version":2}\n')))

    def install(self, edits):
        with apply_lock(self.root) as fd:
            apply_edits(self.root, fd, edits)

    def test_cli_preview_and_apply_diff_agree_repeat_is_noop(self):
        code, preview, err = run_cli("fix", self.root)
        self.assertEqual(code, 0, err)
        (self.root / "local-notes").write_text("unrelated")
        code, applied, err = run_cli("fix", self.root, "--apply")
        self.assertEqual(code, 0, err)
        self.assertIn(preview.split("--- a/")[1].split("Run again")[0], applied)
        self.assertEqual((self.root / self.config).read_bytes(), b"lanes:\n  .github/workflows/ci.yml#build: trusted\n")
        self.assertEqual(stat.S_IMODE((self.root / self.config).stat().st_mode), 0o750)
        code, repeat, err = run_cli("fix", self.root, "--apply")
        self.assertEqual(code, 0, err)
        self.assertIn("No proven changes to apply", repeat)
        self.assertEqual(self.git("diff", "--cached"), b"")
        self.assertEqual((self.root / "local-notes").read_text(), "unrelated")

    def test_dirty_second_target_is_detected_before_preparing_any_output(self):
        for kind in ("unstaged", "staged", "untracked"):
            with self.subTest(kind=kind):
                self.git("reset", "--hard", "-q", "HEAD")
                (self.root / self.other).write_bytes(b'{"version":7}\n')
                if kind == "staged":
                    self.git("add", self.other)
                elif kind == "untracked":
                    self.git("rm", "--cached", self.other)
                edits = self.edits()
                with patch("obaaf.fix_apply._install") as install, self.assertRaises(ProofError):
                    self.install(edits)
                install.assert_not_called()
                self.assertEqual((self.root / self.config).read_bytes(), edits[0].before)
                self.assertEqual((self.root / self.other).read_bytes(), edits[1].before)
                self.assertEqual(list(self.root.rglob(".obaaf-apply-*")), [])

    def test_changing_a_tracked_file_after_proof_is_withheld(self):
        edits = self.edits()
        (self.root / self.other).write_bytes(b"another editor")
        with self.assertRaisesRegex(ProofError, "since the preview"):
            self.install(edits)
        self.assertEqual((self.root / self.other).read_bytes(), b"another editor")
        self.assertEqual((self.root / self.config).read_bytes(), edits[0].before)

    def test_second_install_failure_restores_original_bytes_inode_and_mode(self):
        edits = self.edits()
        original = [(self.root / e.path).stat() for e in edits]
        link = os.link
        def fail_second(src, dst, **kwargs):
            if dst == self.other.name and src.endswith(".new"):
                raise OSError("second target unavailable")
            return link(src, dst, **kwargs)
        with patch.object(os, "link", side_effect=fail_second), self.assertRaisesRegex(OSError, "second target"):
            self.install(edits)
        for edit, info in zip(edits, original):
            path = self.root / edit.path
            self.assertEqual(path.read_bytes(), edit.before)
            self.assertEqual(path.stat().st_ino, info.st_ino)
            self.assertEqual(path.stat().st_mode, info.st_mode)
        self.assertFalse(list(self.root.rglob(".obaaf-apply-*")))

    def test_other_apply_cannot_observe_an_intermediate_transaction(self):
        with apply_lock(self.root):
            code, _, err = run_cli("fix", self.root, "--apply")
            self.assertEqual(code, 2)
            self.assertIn("another apply", err)

    def test_concurrent_writer_keeps_its_version_and_previous_target_is_rolled_back(self):
        edits = self.edits()
        install = fix_apply._install
        def other_writer(target):
            if target.edit.path == self.other:
                (self.root / self.other).write_text("independent edit")
            install(target)
        with patch.object(fix_apply, "_install", side_effect=other_writer), self.assertRaises(ProofError):
            self.install(edits)
        self.assertEqual((self.root / self.other).read_text(), "independent edit")
        self.assertEqual((self.root / self.config).read_bytes(), edits[0].before)
        self.assertFalse(list(self.root.rglob(".obaaf-apply-*")))

    def test_proof_reruns_after_render_before_installing(self):
        from obaaf import fix
        render = fix._render
        def change_input(*args):
            render(*args)
            (self.root / ".github/workflows/ci.yml").write_text("invalid: [")
        with patch.object(fix, "_render", change_input):
            code, _, err = run_cli("fix", self.root, "--apply")
        self.assertEqual(code, 2, err)
        self.assertIn("trused", (self.root / self.config).read_text())

    def test_crlf_checkout_compares_canonical_git_bytes_and_preserves_line_endings(self):
        (self.root / ".gitattributes").write_text("*.yml text eol=crlf\n")
        self.git("add", ".gitattributes")
        self.commit()
        (self.root / self.config).unlink()
        self.git("checkout-index", "-f", "--", self.config)
        self.assertIn(b"\r\n", (self.root / self.config).read_bytes())
        code, _, err = run_cli("fix", self.root, "--apply")
        self.assertEqual(code, 0, err)
        data = (self.root / self.config).read_bytes()
        self.assertIn(b"trusted\r\n", data)
        self.assertNotIn(b"\n", data.replace(b"\r\n", b""))

    def test_ignored_worktree_stat_flags_do_not_obscure_dirty_bytes(self):
        self.git("update-index", "--assume-unchanged", self.other)
        (self.root / self.other).write_bytes(b"independent edit")
        with self.assertRaisesRegex(ProofError, "unstaged"):
            self.install(self.edits())
        self.assertEqual((self.root / self.other).read_bytes(), b"independent edit")

    def annotated(self):
        if not hasattr(os, "setxattr"):
            self.skipTest("filesystem xattrs unavailable")
        try:
            os.setxattr(self.root / self.config, "user.project-note", b"preserve this annotation")
        except OSError as exc:
            self.skipTest(f"filesystem xattrs unavailable: {exc}")

    def test_apply_preserves_owner_group_permissions_and_extended_attributes(self):
        self.annotated()
        path = self.root / self.config
        original = path.stat()
        code, _, err = run_cli("fix", self.root, "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(os.getxattr(path, "user.project-note"), b"preserve this annotation")
        self.assertEqual((path.stat().st_uid, path.stat().st_gid, path.stat().st_mode),
                         (original.st_uid, original.st_gid, original.st_mode))
        self.assertFalse(list(self.root.rglob(".obaaf-apply-*")))

    @unittest.skipUnless(shutil.which("setfacl"), "requires POSIX ACL utility")
    def test_access_acl_and_inherited_acl_are_reconciled(self):
        path = self.root / self.config
        try:
            subprocess.run(["setfacl", "-m", f"u:{os.getuid()}:r--", str(path)], check=True, capture_output=True)
            subprocess.run(["setfacl", "-m", f"d:u:{os.getuid()}:rw-", str(path.parent)], check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            self.skipTest(f"filesystem ACLs unavailable: {exc}")
        key = "system.posix_acl_access"
        acl = os.getxattr(path, key)
        code, _, err = run_cli("fix", self.root, "--apply")
        self.assertEqual(code, 0, err)
        self.assertEqual(os.getxattr(path, key), acl)

    def test_unrepresentable_attribute_refuses_before_moving_any_target(self):
        self.annotated()
        edits = self.edits()
        with patch.object(os, "setxattr", side_effect=PermissionError("attribute cannot be copied")), \
             patch.object(fix_apply, "_install") as install, self.assertRaisesRegex(ProofError, "extended attributes"):
            self.install(edits)
        install.assert_not_called()
        for edit in edits:
            self.assertEqual((self.root / edit.path).read_bytes(), edit.before)
        self.assertFalse(list(self.root.rglob(".obaaf-apply-*")))

    def test_failed_preparation_reports_any_stage_it_could_not_clean(self):
        self.annotated()
        unlink = os.unlink
        def deny_new(name, **kwargs):
            if str(name).endswith(".new"):
                raise PermissionError("cannot remove temporary file")
            return unlink(name, **kwargs)
        with patch.object(os, "setxattr", side_effect=PermissionError("attribute cannot be copied")), \
             patch.object(os, "unlink", side_effect=deny_new), self.assertRaises(ProofError) as error:
            self.install(self.edits())
        retained, = self.root.rglob(".obaaf-apply-*.new")
        self.assertIn(str(retained.relative_to(self.root)), str(error.exception))
        self.assertIn("attribute cannot be copied", str(error.exception))

    def test_final_proof_compares_results_to_the_already_displayed_preview(self):
        from obaaf import fix
        render = fix._render
        def add_workflow(*args):
            render(*args)
            path = self.root / ".github/workflows/test.yml"
            path.write_text("on: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n"
                            "    steps:\n      - uses: actions/checkout@v4\n")
        with patch.object(fix, "_render", add_workflow):
            code, _, err = run_cli("fix", self.root, "--apply")
        self.assertEqual(code, 2, err)
        self.assertIn("changed since the displayed preview", err)
        self.assertIn("trused", (self.root / self.config).read_text())

    def test_concurrent_chmod_on_installed_target_survives_rollback(self):
        edits = self.edits()
        install = fix_apply._install
        def chmod_after_install(target):
            install(target)
            if target.edit.path == self.config:
                (self.root / self.config).chmod(0o711)
        with patch.object(fix_apply, "_install", chmod_after_install), self.assertRaises(ProofError) as error:
            self.install(edits)
        config = self.root / self.config
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o711)
        self.assertEqual(config.read_bytes(), edits[0].after)
        self.assertEqual((self.root / self.other).read_bytes(), edits[1].before)
        backup, = self.root.rglob(".obaaf-apply-*.original")
        self.assertIn(str(backup.relative_to(self.root)), str(error.exception))
        self.assertEqual(backup.read_bytes(), edits[0].before)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o750)
