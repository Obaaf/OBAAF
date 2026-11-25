"""Write only the bytes of a proven edit as a Git unified diff."""

from __future__ import annotations

import difflib
import os
from pathlib import Path

from obaaf.checker.workflow import one_line


def _header_path(prefix, path):
    # Git's C-style quoting makes tabs, spaces, quotes and non-ASCII filenames
    # unambiguous. Octal escapes encode filename bytes, independently of locale.
    name = prefix + os.fsencode(path.as_posix())
    if all(33 <= c < 127 and c not in b'"\\' for c in name):
        return name
    return b'"' + b"".join(bytes((c,)) if 32 <= c < 127 and c not in b'"\\'
                           else b"\\%03o" % c for c in name) + b'"'


def _patch_lines(edits):
    for edit in edits:
        left = _header_path(b"a/", edit.path)
        right = _header_path(b"b/", edit.path)
        yield b"diff --git " + left + b" " + right + b"\n"
        for line in difflib.diff_bytes(difflib.unified_diff, edit.before.splitlines(keepends=True),
                                       edit.after.splitlines(keepends=True), left, right):
            if line.endswith(b"\n"):
                yield line
            else:
                yield line + b"\n"
                yield b"\\ No newline at end of file\n"


def save_patch(destination, edits):
    path = Path(destination)
    parent = path.parent.resolve(strict=True)
    if any(part.casefold() == ".git" for part in (*parent.parts, path.name)):
        raise ValueError("a patch file cannot be saved in Git metadata")
    if os.name == "nt" and (path.is_reserved() or ":" in path.name):
        raise ValueError("the patch destination must be an ordinary file")
    patch = b"".join(_patch_lines(edits))
    target = parent / path.name
    # Exclusive creation also refuses directories and existing links. Binary mode
    # preserves both diff framing and the proved file's own line endings on Windows.
    with target.open("xb") as output:
        created = os.fstat(output.fileno())
        try:
            output.write(patch)
            output.flush()
        except OSError:
            output.close()
            if os.path.samestat(created, target.lstat()):
                target.unlink()
            raise
    print("Saved the proven diff to " + one_line(str(path)) + ".")
