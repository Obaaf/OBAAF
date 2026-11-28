"""Private adoption-fix copies preserve checker-visible inputs without writing to the source."""

import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from obaaf.fix_copy import PrivateCopyError, private_copy


@unittest.skipUnless(os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW"), "requires no-follow opens")
class FixCopyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "project"
        self.root.mkdir()

    def git(self, *args):
        subprocess.run(["git", *args], cwd=self.root, check=True, capture_output=True,
                       env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")})

    def test_copies_working_bytes_mode_and_relative_links_and_cleans_after_client_error(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        script = scripts / "run"
        script.write_bytes(b"working bytes\n")
        script.chmod(0o751)
        (self.root / "tools").symlink_to("scripts", target_is_directory=True)
        (scripts / "indirect").symlink_to("../tools/run")
        with self.assertRaisesRegex(RuntimeError, "client error"):
            with private_copy(self.root) as dest:
                self.assertEqual(stat.S_IMODE(dest.stat().st_mode), 0o700)
                self.assertEqual(os.readlink(dest / "scripts/indirect"), "../tools/run")
                self.assertEqual((dest / "scripts/indirect").read_bytes(), script.read_bytes())
                self.assertEqual(stat.S_IMODE((dest / "scripts/run").stat().st_mode), 0o751)
                (dest / "scripts/indirect").write_bytes(b"new")
                raise RuntimeError("client error")
        self.assertFalse(dest.exists())
        self.assertEqual(script.read_bytes(), b"working bytes\n")

    def test_candidate_inside_source_is_skipped(self):
        internal = self.root / "tmp"
        internal.mkdir()
        with patch.object(tempfile, "tempdir", str(internal)), patch.dict(os.environ, TMPDIR=str(internal)):
            with private_copy(self.root) as dest:
                self.assertFalse(dest.is_relative_to(self.root))
                self.assertFalse(any(os.path.lexists(p / ".git") for p in (dest, *dest.parents)))
                self.assertEqual(list((dest / "tmp").iterdir()), [])
        self.assertEqual(list(internal.iterdir()), [])

    def test_rejects_external_links_and_links_to_git(self):
        directory = self.root / "sub"
        directory.mkdir()
        cases = ("/not-read", "../../not-read", "../.git/config")
        for target in cases:
            with self.subTest(target=target):
                link = directory / "pointer"
                link.symlink_to(target)
                try:
                    with self.assertRaises(PrivateCopyError):
                        with private_copy(self.root):
                            self.fail("unrelocatable link was accepted")
                finally:
                    link.unlink()

    def test_link_boundary_is_checked_after_intermediate_links_expand(self):
        (self.root / "sub").mkdir()
        (self.root / "sub/up").symlink_to("..")
        (self.root / "reference").symlink_to("sub/up/../outside")
        with self.assertRaisesRegex(PrivateCopyError, "outside"):
            with private_copy(self.root):
                self.fail("a link through another link left the source")

    def test_hard_links_are_not_silently_replaced_with_independent_files(self):
        original = self.root / "one"
        original.write_text("same inode")
        os.link(original, self.root / "two")
        with self.assertRaisesRegex(PrivateCopyError, "hard-linked"):
            with private_copy(self.root):
                self.fail("hard-link relationship would be lost")

    def test_nested_metadata_and_special_files_are_declined(self):
        nested = self.root / "vendor"
        nested.mkdir()
        (nested / ".git").write_text("gitdir: somewhere")
        with self.assertRaisesRegex(PrivateCopyError, "Git metadata"):
            with private_copy(self.root):
                self.fail("nested repository was copied")
        (nested / ".git").unlink()
        os.mkfifo(nested / "pipe")
        with self.assertRaisesRegex(PrivateCopyError, "special file"):
            with private_copy(self.root):
                self.fail("FIFO was copied")

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_git_copy_uses_working_bytes_and_retains_ordinary_untracked_files(self):
        self.git("init")
        (self.root / "AGENTS.md").write_text("tracked version")
        self.git("add", "AGENTS.md")
        (self.root / "AGENTS.md").write_text("working version")
        (self.root / "local.txt").write_text("untracked")
        with private_copy(self.root) as dest:
            self.assertFalse((dest / ".git").exists())
            self.assertEqual((dest / "AGENTS.md").read_text(), "working version")
            self.assertEqual((dest / "local.txt").read_text(), "untracked")
        (self.root / "sub").mkdir()
        (self.root / "sub/AGENTS.md").write_text("untracked instructions")
        with self.assertRaisesRegex(PrivateCopyError, "different instruction files"):
            with private_copy(self.root):
                self.fail("index and directory scan disagree")

    @unittest.skipUnless(shutil.which("git"), "requires Git")
    def test_root_linked_worktree_supported_but_uninitialized_gitlink_declined(self):
        self.git("init")
        self.git("-c", "user.name=Test", "-c", "user.email=test@example.org",
                 "commit", "--allow-empty", "-m", "first")
        worktree = self.root.parent / "linked"
        self.git("worktree", "add", "--detach", str(worktree))
        self.assertTrue((worktree / ".git").is_file())
        with private_copy(worktree) as dest:
            self.assertFalse((dest / ".git").exists())
        self.git("update-index", "--add", "--cacheinfo", "160000," + "1" * 40 + ",vendor")
        with self.assertRaises(PrivateCopyError):
            with private_copy(self.root):
                self.fail("an uninitialized submodule was copied")
