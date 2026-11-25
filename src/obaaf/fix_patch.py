"""Write only the bytes of a proven edit as a Git unified diff."""

from __future__ import annotations

import difflib
import errno
import os
from pathlib import Path, PureWindowsPath
import subprocess

from obaaf.checker.workflow import one_line
from obaaf.fix_proof import ProofError


def _header_path(prefix, path):
    # Git's C-style quoting makes tabs, spaces, quotes and non-ASCII filenames
    # unambiguous. Octal escapes encode filename bytes, independently of locale.
    name = prefix + os.fsencode(path.as_posix())
    if all(33 <= c < 127 and c not in b'"\\' for c in name):
        return name
    return b'"' + b"".join(bytes((c,)) if 32 <= c < 127 and c not in b'"\\'
                           else b"\\%03o" % c for c in name) + b'"'


def _lines(data):
    # Git ends a line only at a line feed. bytes.splitlines also ends one at a lone CR, which gave a
    # patch Git refused (review-gpt #368).
    lines = data.split(b"\n")
    last = lines.pop()
    return [line + b"\n" for line in lines] + ([last] if last else [])


def _patch_lines(edits):
    for edit in edits:
        left = _header_path(b"a/", edit.path)
        right = _header_path(b"b/", edit.path)
        yield b"diff --git " + left + b" " + right + b"\n"
        for line in difflib.diff_bytes(difflib.unified_diff, _lines(edit.before), _lines(edit.after), left, right):
            if line.endswith(b"\n"):
                yield line
            else:
                yield line + b"\n"
                yield b"\\ No newline at end of file\n"


# Variables that move the repository or the work tree Git uses. They are refused rather than followed.
GIT_LOCATION = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_ATTR_SOURCE")
# Kept for these queries, unlike fix_apply._git: the caller's own configuration (attributes, ignore rules,
# core.worktree, files it includes) and search limits, which their `git apply` will use too (third
# review of review-gpt #368). The queries are read-only and run no filter.
GIT_KEPT = ("GIT_CONFIG", "GIT_CEILING_DIRECTORIES")
TOP_ONLY = ("--patch needs the top folder of the Git work tree: git apply reads the patch's paths from there, "
            "so a patch from a folder below it would change other files or none")


def _query(git, root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k.startswith(GIT_KEPT)}
    env.pop("LANGUAGE", None)
    env.update(GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="", GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    command = [str(git), "--literal-pathspecs", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args]
    try:
        return subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProofError(f"Git could not be run: {exc}") from exc


def _answer(git, root, *args):
    done = _query(git, root, *args)
    if done.returncode:
        raise ProofError("Git could not read the repository: " + one_line(done.stderr.decode(errors="replace").strip()))
    return done.stdout


def check_git_targets(root, edits):
    """Refuse a patch that `git apply` would apply to other files, skip, or hide (review-gpt #368).

    Git reads a patch's paths from the top of the work tree it finds. From a checked folder below
    the top, the patch would change a file the proof never read, or, run in that folder, nothing at
    all, with exit 0 both times. Outside any work tree Git reads them from the folder it runs in, so
    the checked folder itself is right. Where neither the folder nor one above it holds `.git`, that
    is taken as outside; otherwise Git must run and either say this is the top or that there is no
    repository, and any other answer (no Git, a repository owned by another user) refuses. The
    per-file refusals are those of `--apply` that matter to Git as well: a target Git would not show
    as changed (assume-unchanged, skip-worktree, ignored), and a checkout transformation `--apply`
    also refuses."""
    from obaaf.checker.repo import find_git

    named = sorted(name for name in GIT_LOCATION if name in os.environ)
    if named:
        raise ProofError(f"--patch cannot tell which work tree git apply would use while {', '.join(named)} "
                         "is set; unset it and rerun")
    marked = any(os.path.lexists(folder / ".git") for folder in (root, *root.parents))
    git = find_git(root)
    if not git:
        if marked:
            raise ProofError(f"{TOP_ONLY}, and no git program on the PATH can confirm this folder is it")
        return
    done = _query(git, root, "rev-parse", "--is-inside-work-tree")
    if done.returncode:
        # Only the answer of Git's search for a repository. A `.git` file whose target has gone gives
        # "not a git repository: PATH" and would hide a work tree above it (fourth review of #368).
        if not marked or b"not a git repository (or any" in done.stderr:
            return
        raise ProofError(f"{TOP_ONLY}, and Git could not read the repository here: "
                         + one_line(done.stderr.decode(errors="replace").strip()))
    top = _answer(git, root, "rev-parse", "--show-toplevel").rstrip(b"\n") if done.stdout == b"true\n" else b""
    try:
        same = bool(top) and os.path.samestat(os.stat(os.fsdecode(top)), os.stat(root))
    except OSError:
        same = False
    if not same or _answer(git, root, "rev-parse", "--show-prefix") != b"\n":
        raise ProofError(TOP_ONLY + "; run obaaf fix on the top folder")
    for edit in edits:
        name = edit.path.as_posix()
        listed = _answer(git, root, "ls-files", "-v", "-z", "--", name)
        # `H` is a plain tracked entry; an untracked target lists nothing.
        if listed and listed != b"H " + os.fsencode(name) + b"\0":
            raise ProofError(f"{name}: Git's index marks it assume-unchanged or skip-worktree (or it has a "
                             "conflict), so Git would not show the change; clear it with git update-index first")
        # check-ignore takes no literal pathspec; ls-files does.
        if not listed and _answer(git, root, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", name):
            raise ProofError(f"{name}: Git ignores this untracked file, so Git would not show the change")
        attrs = _answer(git, root, "check-attr", "-z", "filter", "ident", "working-tree-encoding", "--", name)
        if any(value not in (b"unspecified", b"unset") for value in attrs.rstrip(b"\0").split(b"\0")[2::3]):
            raise ProofError(f"{name}: a filter, ident or working-tree-encoding attribute would make git apply "
                             "write other bytes than the proven ones")


def _reserved(path):
    # Path.is_reserved is deprecated from Python 3.13, which has os.path.isreserved on Windows.
    isreserved = getattr(os.path, "isreserved", None)
    return isreserved(path) if isreserved else PureWindowsPath(path).is_reserved()


def _write_new(target, data):
    # Exclusive creation also refuses directories and existing links. Binary mode preserves both diff
    # framing and the proved file's own line endings on Windows. On any failure, closing included,
    # the file this call created is removed, so a retry is not refused for an empty or partial patch
    # (review-gpt #368).
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o666)
    created = None
    try:
        created = os.fstat(fd)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "the patch file took no bytes")
            view = view[written:]
        fd, closing = None, fd
        os.close(closing)
    except BaseException:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            if created is not None and os.path.samestat(created, os.lstat(target)):
                os.unlink(target)
        except OSError:
            pass
        raise


def save_patch(root, destination, edits):
    path = Path(destination)
    try:
        parent = path.parent.resolve(strict=True)
    except RuntimeError as exc:  # a link loop, before Python 3.13
        raise ValueError(f"the patch destination's folder cannot be resolved: {exc}") from exc
    if any(part.casefold() == ".git" for part in (*parent.parts, path.name)):
        raise ValueError("a patch file cannot be saved in Git metadata")
    if os.name == "nt" and (_reserved(path) or ":" in path.name):
        raise ValueError("the patch destination must be an ordinary file")
    check_git_targets(root, edits)
    _write_new(parent / path.name, b"".join(_patch_lines(edits)))
    print("Saved the proven diff to " + one_line(str(path)) + ".")
