"""Install the already-proven bytes of an adoption preview on clean Git targets."""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
import hashlib
import os
import secrets
import stat
import subprocess

from obaaf.checker import repo
from obaaf.fix_proof import Edit, ProofError


XATTR_FUNCTIONS = ("listxattr", "getxattr", "setxattr", "removexattr")


@contextmanager
def apply_lock(root):
    try:
        import fcntl
    except ImportError as exc:
        raise ProofError("applying edits needs POSIX directory locking") from exc
    # Python has these only on Linux; without them the access controls cannot be kept, so refuse
    # before the preview rather than after it (added by the review, review-gpt #282).
    if not all(hasattr(os, fn) for fn in XATTR_FUNCTIONS):
        raise ProofError("applying edits is supported only on Linux: it needs Python's extended attribute "
                         "functions to keep each file's access controls; edit the files by hand from the preview")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProofError("another apply holds the repository lock; rerun when it finishes") from exc
        yield fd
    finally:
        os.close(fd)


def _git(git, root, *args, optional=False):
    # No repository-defined hooks, filters, replacements or lazy fetch. Read metadata,
    # including the index, without refreshing it in the working tree.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="", GIT_OPTIONAL_LOCKS="0")
    command = [str(git), "--literal-pathspecs", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", *args]
    try:
        done = subprocess.run(command, cwd=root, env=env, capture_output=True, timeout=120)
    except subprocess.SubprocessError as exc:
        raise ProofError("Git could not establish clean tracked targets") from exc
    if optional and done.returncode == 1:
        return b""
    if done.returncode:
        raise ProofError("Git could not establish clean tracked targets")
    return done.stdout


def _git_entry(git, root, path):
    name = os.fsencode(path)
    head = _git(git, root, "ls-tree", "-z", "HEAD", "--", str(path))
    staged = _git(git, root, "ls-files", "-z", "--stage", "--", str(path))
    if not head or not staged:
        raise ProofError(f"{path}: apply requires an existing tracked file in HEAD and the index")
    meta, _, tail = head.partition(b"\t")
    mode, kind, oid = meta.split()
    if (kind != b"blob" or mode not in (b"100644", b"100755") or tail != name + b"\0"
            or staged != mode + b" " + oid + b" 0\t" + name + b"\0"):
        raise ProofError(f"{path}: staged changes or unsupported Git entry; no clean target")
    # `H` is a plain tracked entry. Lower case is assume-unchanged and `S` skip-worktree: Git would
    # not show the written change in `git status` or `git diff` (added by the review, review-gpt #282).
    if _git(git, root, "ls-files", "-v", "-z", "--", str(path)) != b"H " + name + b"\0":
        raise ProofError(f"{path}: Git's index marks it assume-unchanged or skip-worktree, so Git would not "
                         "show the change; clear the flag with git update-index before applying")
    return mode, oid


def _clean(git, root, path, content, mode):
    git_mode, oid = _git_entry(git, root, path)
    if (git_mode == b"100755") != bool(mode & stat.S_IXUSR):
        raise ProofError(f"{path}: unstaged executable mode change")
    attrs = _git(git, root, "check-attr", "-z", "filter", "ident", "working-tree-encoding", "--", str(path))
    if any(value not in (b"unspecified", b"unset") for value in attrs.rstrip(b"\0").split(b"\0")[2::3]):
        raise ProofError(f"{path}: checkout transformations prevent direct comparison with the committed bytes")

    def blob(data):
        algorithm = "sha256" if len(oid) == 64 else "sha1"
        return hashlib.new(algorithm, b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest().encode()

    if blob(content) != oid:
        # Git reports the effective text/eol attributes and both line-ending styles without
        # invoking external filters. Compare every canonical byte.
        info = _git(git, root, "ls-files", "--eol", "-z", "--", str(path)).partition(b"\t")[0].split()
        attrs = b" ".join(info[2:])
        autocrlf = _git(git, root, "config", "--get", "core.autocrlf", optional=True)
        text_conversion = (attrs.startswith((b"attr/text", b"attr/eol="))
                           or (attrs == b"attr/" and autocrlf.strip().lower() in (b"true", b"input")))
        if (info[:2] != [b"i/lf", b"w/crlf"] or not text_conversion
                or blob(content.replace(b"\r\n", b"\n")) != oid):
            raise ProofError(f"{path}: unstaged changes; commit or restore the target before applying")
    return git_mode, oid


def _parent(stack, root_fd, path):
    if path.is_absolute() or not path.parts or any(n in ("..", ".git") for n in path.parts):
        raise ProofError(f"invalid apply path {str(path)!r}")
    fd = root_fd
    for part in path.parts[:-1]:
        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        stack.callback(os.close, fd)
    return fd


def _attrs(fd):
    if not all(hasattr(os, fn) for fn in XATTR_FUNCTIONS):
        raise ProofError("applying edits is supported only on Linux: it needs Python's extended attribute "
                         "functions to keep each file's access controls")
    return {name: os.getxattr(fd, name) for name in os.listxattr(fd)}


def _set_metadata(fd, target):
    source = target.original
    try:
        info = os.fstat(fd)
        if (info.st_uid, info.st_gid) != (source.st_uid, source.st_gid):
            os.fchown(fd, source.st_uid, source.st_gid)
        os.fchmod(fd, stat.S_IMODE(source.st_mode))
        inherited = _attrs(fd)
        for key in inherited.keys() - target.attrs.keys():
            os.removexattr(fd, key)
        for key, value in target.attrs.items():
            if inherited.get(key) != value:
                os.setxattr(fd, key, value)
        observed = os.fstat(fd)
        if (_attrs(fd) != target.attrs or observed.st_mode != source.st_mode
                or (observed.st_uid, observed.st_gid) != (source.st_uid, source.st_gid)):
            raise ProofError(f"{target.edit.path}: replacement ownership, permissions or extended attributes differ")
    except OSError as exc:
        raise ProofError(f"{target.edit.path}: cannot preserve ownership, permissions or extended attributes: {exc}") from exc


def _read(fd, name):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, dir_fd=fd), "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ProofError(f"{name}: apply requires a regular file")
        data = stream.read()
        attrs = _attrs(stream.fileno())
        after = os.fstat(stream.fileno())
        if (after.st_mtime_ns, after.st_ctime_ns) != (info.st_mtime_ns, info.st_ctime_ns):
            raise ProofError(f"{name}: file changed while being read")
        return data, info, attrs


@dataclass
class _Target:
    edit: Edit
    parent: int
    original: os.stat_result
    attrs: dict
    git_entry: tuple
    stage: str
    backup: str
    displaced: str
    moved: bool = False
    installed: bool = False
    staged: bool = False


def _same(info, other):
    return (info.st_dev, info.st_ino, info.st_mode) == (other.st_dev, other.st_ino, other.st_mode)


def _verify(target, name, expected, original):
    data, info, attrs = _read(target.parent, name)
    if (data != expected or not _same(info, original) or info.st_mode != target.original.st_mode or attrs != target.attrs
            or (info.st_uid, info.st_gid) != (target.original.st_uid, target.original.st_gid)):
        raise ProofError(f"{target.edit.path}: target changed during apply")


def _restore(target):
    """Keep a concurrent writer's version if it replaced our installed file."""
    fd, name = target.parent, target.edit.path.name
    if target.installed:
        # Move the current name aside first, so a later writer cannot be deleted by
        # a check-then-unlink. Restore it without clobbering anything if it is not ours.
        os.rename(name, target.displaced, src_dir_fd=fd, dst_dir_fd=fd)
        try:
            staged = os.stat(target.stage, dir_fd=fd, follow_symlinks=False)
            _verify(target, target.displaced, target.edit.after, staged)
        except BaseException:
            os.link(target.displaced, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.unlink(target.displaced, dir_fd=fd)
            raise
    os.link(target.backup, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    os.unlink(target.backup, dir_fd=fd)
    if target.installed:
        os.unlink(target.displaced, dir_fd=fd)


def _install(target):
    fd, name = target.parent, target.edit.path.name
    os.rename(name, target.backup, src_dir_fd=fd, dst_dir_fd=fd)
    target.moved = True
    _verify(target, target.backup, target.edit.before, target.original)
    # Link only into a vacant name. A file created after the rename survives.
    os.link(target.stage, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
    target.installed = True


def apply_edits(root, root_fd, edits):
    """Preflight the complete set, prepare all replacement bytes, and restore on failure."""
    if not edits:
        return ()
    git = repo.find_git(root)
    if not git or _git(git, root, "rev-parse", "--show-prefix") != b"\n":
        raise ProofError("apply needs the root of a Git working tree")
    if len({e.path for e in edits}) != len(edits):
        raise ProofError("multiple apply edits name the same target")
    with ExitStack() as stack:
        targets = []
        for edit in edits:
            fd = _parent(stack, root_fd, edit.path)
            data, original, attrs = _read(fd, edit.path.name)
            if getattr(original, "st_flags", 0) or attrs.keys() & {"security.capability", "security.ima", "security.evm"}:
                raise ProofError(f"{edit.path}: special filesystem flags, capabilities or signatures require manual review")
            if data != edit.before or original.st_nlink != 1:
                raise ProofError(f"{edit.path}: target changed since the preview was proven")
            entry = _clean(git, root, edit.path, data, original.st_mode)
            prefix = ".obaaf-apply-" + secrets.token_hex(16)
            targets.append(_Target(edit, fd, original, attrs, entry, prefix + ".new", prefix + ".original",
                                   prefix + ".displaced"))
        cleanup_warnings = []

        def discard(t, name):
            try:
                os.unlink(name, dir_fd=t.parent)
            except OSError as exc:
                cleanup_warnings.append(f"Remove the temporary file {t.edit.path.parent / name}: {exc}")

        failure = None
        try:
            for t in targets:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                with os.fdopen(os.open(t.stage, flags, 0o600, dir_fd=t.parent), "wb") as stage:
                    t.staged = True
                    stage.write(t.edit.after)
                    stage.flush()
                    _set_metadata(stage.fileno(), t)
                    os.fsync(stage.fileno())
                # Install and rollback both link into a vacant name. A filesystem without hard links
                # must refuse here, before any original is moved aside (added by the review,
                # review-gpt #282).
                probe = t.stage[:-len(".new")] + ".probe"
                try:
                    os.link(t.stage, probe, src_dir_fd=t.parent, dst_dir_fd=t.parent, follow_symlinks=False)
                except OSError as exc:
                    raise ProofError(f"{t.edit.path}: apply needs a filesystem with hard links; edit the file "
                                     f"by hand from the preview ({exc})") from exc
                discard(t, probe)  # a probe it cannot remove is named, like a stage
            for t in targets:
                if not os.path.samestat((root / t.edit.path.parent).stat(), os.fstat(t.parent)):
                    raise ProofError(f"{t.edit.path}: parent directory changed during apply")
                if _git_entry(git, root, t.edit.path) != t.git_entry:
                    raise ProofError(f"{t.edit.path}: Git target changed after preflight")
                _install(t)
            for t in targets:
                _verify(t, t.backup, t.edit.before, t.original)
                _verify(t, t.edit.path.name, t.edit.after, os.stat(t.stage, dir_fd=t.parent))
                if (_git_entry(git, root, t.edit.path) != t.git_entry
                        or not os.path.samestat((root / t.edit.path.parent).stat(), os.fstat(t.parent))):
                    raise ProofError(f"{t.edit.path}: target or directory changed during apply")
        except BaseException as error:
            failure = error
            for t in reversed(targets):
                if t.moved:
                    try:
                        _restore(t)
                    except (ValueError, OSError) as exc:
                        retained = []
                        for name in (t.backup, t.displaced):
                            try:
                                os.stat(name, dir_fd=t.parent, follow_symlinks=False)
                            except FileNotFoundError:
                                continue
                            except OSError as probe_error:
                                cleanup_warnings.append(f"Could not inspect {t.edit.path.parent / name}: {probe_error}")
                            else:
                                retained.append(str(t.edit.path.parent / name))
                        detail = f" Retained files: {', '.join(retained)}." if retained else ""
                        cleanup_warnings.append(f"Could not restore {t.edit.path}: {exc}.{detail}")
        else:
            for t in targets:
                discard(t, t.backup)
        for t in targets:
            if t.staged:
                discard(t, t.stage)
        if failure is not None:
            if cleanup_warnings:
                raise ProofError(f"{failure}. " + " ".join(cleanup_warnings)) from failure
            raise failure
        return tuple(cleanup_warnings)
