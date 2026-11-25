"""An isolated working-tree snapshot for checking a proposed fix."""

from __future__ import annotations

import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from obaaf.catalog import load
from obaaf.checker import repo


class PrivateCopyError(ValueError):
    """The working tree cannot be copied faithfully enough to prove a fix."""


def _temporary_directory(root: Path) -> tempfile.TemporaryDirectory:
    # tempfile.gettempdir() probes candidates by writing to them. Exclude locations inside
    # the source and Git trees before creating anything, including a probe.
    candidates = [tempfile.tempdir, *(os.environ.get(key) for key in ("TMPDIR", "TEMP", "TMP")),
                  "/tmp", "/var/tmp", "/dev/shm"]
    for name in candidates:
        if not name:
            continue
        try:
            parent = Path(os.fsdecode(name)).resolve(strict=True)
            if parent.is_relative_to(root) or not parent.is_dir():
                continue
            if any(os.path.lexists(folder / ".git") for folder in (parent, *parent.parents)):
                continue
            return tempfile.TemporaryDirectory(prefix="obaaf-proof-", dir=parent)
        except (OSError, RuntimeError):
            continue
    raise PrivateCopyError("no writable temporary directory outside the source and all Git working trees")


def _version(info: os.stat_result) -> tuple:
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _unchanged(before: os.stat_result, after: os.stat_result, relative: Path) -> None:
    if _version(before) != _version(after):
        raise PrivateCopyError(f"working tree changed while copying {str(relative)!r}")


def _copy_tree(fd: int, dest: Path, relative: Path, links: dict[Path, str], device: int) -> None:
    """Read each source child relative to its open parent. A replaced symlink cannot redirect an open."""
    directory = os.fstat(fd)
    if directory.st_dev != device:
        raise PrivateCopyError(f"nested filesystem at {str(relative)!r}")
    for name in os.listdir(fd):
        rel = relative / name
        path = dest / name
        before = os.stat(name, dir_fd=fd, follow_symlinks=False)
        mode = before.st_mode
        if name.casefold() == ".git":
            if rel == Path(".git") and (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                continue
            raise PrivateCopyError(f"nested or unsupported Git metadata at {str(rel)!r}")
        if before.st_dev != device:
            raise PrivateCopyError(f"nested filesystem at {str(rel)!r}")
        if stat.S_ISLNK(mode):
            target = os.readlink(name, dir_fd=fd)
            links[rel] = target
            path.symlink_to(target)
        elif stat.S_ISDIR(mode):
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                _unchanged(before, os.fstat(child), rel)
                path.mkdir(mode=0o700)
                _copy_tree(child, path, rel, links, device)
            finally:
                os.close(child)
            path.chmod(stat.S_IMODE(mode))
        elif stat.S_ISREG(mode):
            if before.st_nlink != 1:
                raise PrivateCopyError(f"hard-linked file at {str(rel)!r} cannot be edited independently")
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            with os.fdopen(os.open(name, flags, dir_fd=fd), "rb") as source:
                _unchanged(before, os.fstat(source.fileno()), rel)
                with path.open("xb") as output:
                    shutil.copyfileobj(source, output)
                _unchanged(before, os.fstat(source.fileno()), rel)
            path.chmod(stat.S_IMODE(mode))
        else:
            raise PrivateCopyError(f"unsupported special file at {str(rel)!r}")
        _unchanged(before, os.stat(name, dir_fd=fd, follow_symlinks=False), rel)
    _unchanged(directory, os.fstat(fd), relative)


def check_link(name: Path, lookup: Callable[[Path], str | Path | None]) -> None:
    # Check components in filesystem order, including links in intermediate directories.
    # Resolving or statting a target before checking its boundary would access the outside tree.
    pos = name.parent
    pending = [name.name]
    hops = 0
    while pending:
        part = pending.pop()
        if part == "..":
            if pos == Path("."):
                raise PrivateCopyError(f"link {str(name)!r} leads outside the source")
            pos = pos.parent
            continue
        pos /= part
        if part.casefold() == ".git":
            raise PrivateCopyError(f"link {str(name)!r} refers to excluded Git metadata")
        link = lookup(pos)
        if link is not None:
            target = Path(link)
            if target.is_absolute():
                raise PrivateCopyError(f"absolute link at {str(pos)!r} cannot be relocated")
            hops += 1
            if hops > 40:
                raise PrivateCopyError(f"unresolved link chain at {str(name)!r}")
            pos = pos.parent
            pending.extend(reversed(target.parts))


def _check_links(links: dict[Path, str]) -> None:
    for name in links:
        check_link(name, links.get)


def _instruction_entries(root: Path, patterns: list[str], git: bool) -> list:
    errors: list[str] = []
    unread: list[str] = []
    how: dict = {}
    entries = repo.find_instruction_entries(root, patterns, unread, errors, how)
    if git and how.get("listing") != "git":
        raise PrivateCopyError("Git could not establish the tracked paths for the source")
    if how.get("gitlinks"):
        raise PrivateCopyError("a repository with submodules cannot be proven on this copy")
    if errors or unread:
        raise PrivateCopyError("the checker could not fully list instruction files for the proof")
    return entries


@contextmanager
def private_copy(root: Path) -> Iterator[Path]:
    """Yield a private working tree without source Git metadata. Remove it on every exit.

    Relative internal links retain their original text. Source and copy must expose the
    same instruction entries to the checker despite its use of Git's index in the source.
    The proof caller also compares full checker results before it changes this copy.
    """
    if os.name != "nt" and (os.open not in os.supports_dir_fd or os.listdir not in os.supports_fd
                            or not hasattr(os, "O_NOFOLLOW")):
        raise PrivateCopyError("this system cannot isolate source reads with no-follow directory descriptors")
    try:
        root = Path(root).absolute()
        if root.is_symlink():
            raise PrivateCopyError("the source root must be a directory, not a symbolic link")
        if os.name != "nt":
            root = root.resolve(strict=True)
        tmp = _temporary_directory(root)
    except (OSError, RuntimeError) as exc:
        raise PrivateCopyError(f"could not prepare the private copy: {exc}") from exc
    with tmp:
        dest = Path(tmp.name)
        try:
            if os.name == "nt":
                from obaaf.fix_copy_windows import copy_tree
                copy_tree(root, dest)
            else:
                fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    source = os.fstat(fd)
                    links: dict[Path, str] = {}
                    _copy_tree(fd, dest, Path("."), links, source.st_dev)
                    _check_links(links)
                    _unchanged(source, root.lstat(), Path("."))
                finally:
                    os.close(fd)
            if (root / ".git").exists():
                patterns = load().detection["instruction_files"]
                if _instruction_entries(root, patterns, True) != _instruction_entries(dest, patterns, False):
                    raise PrivateCopyError("Git's index and the private copy expose different instruction files")
        except (OSError, RuntimeError) as exc:
            raise PrivateCopyError(f"could not complete the private copy: {exc}") from exc
        yield dest
