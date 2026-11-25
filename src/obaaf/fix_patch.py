"""Write only the bytes of a proven edit as a Git unified diff."""

from __future__ import annotations

import difflib
import errno
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


# Variables that move the work tree, the repository or the attributes Git uses. OBAAF's own Git queries
# run without any GIT_ variable (fix_apply._git), so with one set the user's `git apply` could read the
# patch's paths from another folder than the one checked (second review of review-gpt #368).
GIT_LOCATION = ("GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_ATTR_SOURCE")
# Configuration given in the environment is common (URL rewrites, credential helpers), so it is refused
# only where it names a key that moves the work tree or the attributes.
GIT_LOCATION_KEYS = ("core.worktree", "core.attributesfile")
TOP_ONLY = ("--patch needs the top folder of the Git work tree: git apply reads the patch's paths from there, "
            "so a patch from a folder below it would change other files or none")


def check_git_targets(root, edits):
    """Refuse a patch that `git apply` would apply to other files, skip, or hide (review-gpt #368).

    Git reads a patch's paths from the top of the work tree it finds. From a checked folder below
    the top, the patch would change a file the proof never read, or, run in that folder, nothing at
    all, with exit 0 both times. Outside any work tree Git reads them from the folder it runs in, so
    the checked folder itself is right. A folder is taken to be outside one only when neither it nor
    a folder above it holds `.git`; otherwise Git must run and say this is the top, and a failure
    (no Git, a repository owned by another user) refuses. The per-file refusals are those of
    `--apply` that matter to Git as well: a target Git would not show as changed (assume-unchanged,
    skip-worktree, ignored), and a checkout transformation `--apply` also refuses."""
    from obaaf.checker.repo import find_git
    from obaaf.fix_apply import _git

    named = sorted(name for name in GIT_LOCATION if name in os.environ)
    count = os.environ.get("GIT_CONFIG_COUNT", "")
    keys = [os.environ.get(f"GIT_CONFIG_KEY_{i}", "") for i in range(int(count))] if count.isdigit() else []
    if (any(key.strip().lower() in GIT_LOCATION_KEYS for key in keys)
            or any(key in os.environ.get("GIT_CONFIG_PARAMETERS", "").lower() for key in GIT_LOCATION_KEYS)):
        named.append("a GIT_CONFIG variable naming core.worktree or core.attributesFile")
    if named:
        raise ProofError(f"--patch cannot tell which work tree git apply would use while {', '.join(named)} "
                         "is set; unset it and rerun")
    marked = any(os.path.lexists(folder / ".git") for folder in (root, *root.parents))
    git = find_git(root)
    try:
        if not git:
            raise ProofError("no git program was found on the PATH")
        inside = _git(git, root, "rev-parse", "--is-inside-work-tree")
    except ProofError as exc:
        if marked:
            raise ProofError(f"{TOP_ONLY}, and Git could not say whether this is it ({exc}); "
                             "run obaaf fix where Git can read the repository") from exc
        return
    top = _git(git, root, "rev-parse", "--show-toplevel").rstrip(b"\n") if inside == b"true\n" else b""
    try:
        same = bool(top) and os.path.samestat(os.stat(os.fsdecode(top)), os.stat(root))
    except OSError:
        same = False
    if not same or _git(git, root, "rev-parse", "--show-prefix") != b"\n":
        raise ProofError(TOP_ONLY + "; run obaaf fix on the top folder")
    for edit in edits:
        name = edit.path.as_posix()
        listed = _git(git, root, "ls-files", "-v", "-z", "--", name)
        # `H` is a plain tracked entry; an untracked target lists nothing.
        if listed and listed != b"H " + os.fsencode(name) + b"\0":
            raise ProofError(f"{name}: Git's index marks it assume-unchanged or skip-worktree (or it has a "
                             "conflict), so Git would not show the change; clear it with git update-index first")
        # check-ignore takes no literal pathspec, which _git always sets; ls-files does.
        if not listed and _git(git, root, "ls-files", "-z", "--others", "--ignored", "--exclude-standard", "--", name):
            raise ProofError(f"{name}: Git ignores this untracked file, so Git would not show the change")
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
