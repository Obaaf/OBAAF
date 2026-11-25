"""Write only the bytes of a proven edit as a Git unified diff."""

from __future__ import annotations

import difflib
import os
from pathlib import Path, PureWindowsPath

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


def check_git_targets(root, edits):
    """Refuse a patch that `git apply` would apply to other files, skip, or hide (review-gpt #368).

    Git reads a patch's paths from the top of the work tree it finds. From a checked folder below
    the top, the patch would change a file the proof never read, or, run in that folder, nothing at
    all, with exit 0 both times. Outside any work tree Git reads them from the folder it runs in, so
    the checked folder itself is right. The per-file refusals are those of `--apply` that matter to
    Git as well: a flag that hides the change from `git status`, and a checkout transformation that
    makes the written file differ from the proven bytes."""
    from obaaf.checker.repo import find_git
    from obaaf.fix_apply import _git

    git = find_git(root)
    if not git:
        return
    try:
        inside = _git(git, root, "rev-parse", "--is-inside-work-tree")
    except ProofError:
        return
    top = _git(git, root, "rev-parse", "--show-toplevel").rstrip(b"\n") if inside == b"true\n" else b""
    try:
        same = bool(top) and os.path.samestat(os.stat(os.fsdecode(top)), os.stat(root))
    except OSError:
        same = False
    if not same or _git(git, root, "rev-parse", "--show-prefix") != b"\n":
        raise ProofError("--patch needs the top folder of the Git work tree: git apply reads the patch's "
                         "paths from there, so a patch from a folder below it would change other files or "
                         "none; run obaaf fix on the top folder")
    for edit in edits:
        name = edit.path.as_posix()
        listed = _git(git, root, "ls-files", "-v", "-z", "--", name)
        # `H` is a plain tracked entry; an untracked target lists nothing.
        if listed and listed != b"H " + os.fsencode(name) + b"\0":
            raise ProofError(f"{name}: Git's index marks it assume-unchanged or skip-worktree (or it has a "
                             "conflict), so Git would not show the change; clear it with git update-index first")
        attrs = _git(git, root, "check-attr", "-z", "filter", "ident", "working-tree-encoding", "--", name)
        if any(value not in (b"unspecified", b"unset") for value in attrs.rstrip(b"\0").split(b"\0")[2::3]):
            raise ProofError(f"{name}: a filter, ident or working-tree-encoding attribute would make git apply "
                             "write other bytes than the proven ones")


def _reserved(path):
    # Path.is_reserved is deprecated from Python 3.13, which has os.path.isreserved on Windows.
    isreserved = getattr(os.path, "isreserved", None)
    return isreserved(path) if isreserved else PureWindowsPath(path).is_reserved()


def _write_new(target, data):
    # Exclusive creation also refuses directories and existing links. Binary mode preserves both diff
    # framing and the proved file's own line endings on Windows. On any failure the file this call
    # created is removed, so a retry is not refused for an empty or partial patch (review-gpt #368).
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(target, flags, 0o666)
    try:
        created = os.fstat(fd)
        view = memoryview(data)
        while view:
            view = view[os.write(fd, view):]
    except BaseException:
        os.close(fd)
        try:
            if os.path.samestat(created, os.lstat(target)):
                os.unlink(target)
        except (OSError, NameError):
            pass
        raise
    os.close(fd)


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
