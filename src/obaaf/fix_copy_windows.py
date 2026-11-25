"""Read a Windows proof snapshot without following reparse points.

CreateFile opens the named object itself. It denies writes and deletes while
we inspect and read it. Directory handles remain open while visiting children,
so replacing a parent cannot redirect a later path-based operation.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
import ctypes
from ctypes import wintypes
import msvcrt
import os
from pathlib import Path
import shutil
import stat

from obaaf.fix_copy import PrivateCopyError, _unchanged


_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
_open = _kernel.CreateFileW
_open.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
                  wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
_open.restype = wintypes.HANDLE
class _AttributeTag(ctypes.Structure):
    _fields_ = (("attributes", wintypes.DWORD), ("tag", wintypes.DWORD))


_information = _kernel.GetFileInformationByHandleEx
_information.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
_information.restype = wintypes.BOOL
_close = _kernel.CloseHandle
_close.argtypes = (wintypes.HANDLE,)
_close.restype = wintypes.BOOL
INVALID_HANDLE = wintypes.HANDLE(-1).value
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 1
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000


@contextmanager
def _locked(path):
    handle = _open(str(path), GENERIC_READ, FILE_SHARE_READ, None, OPEN_EXISTING,
                   FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, None)
    if handle == INVALID_HANDLE:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        tag = _AttributeTag()
        # FileAttributeTagInfo (9) describes even reparse tags that lstat follows.
        if not _information(handle, 9, ctypes.byref(tag), ctypes.sizeof(tag)):
            raise ctypes.WinError(ctypes.get_last_error())
        if tag.attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise PrivateCopyError(f"Windows reparse point cannot be isolated: {str(path)!r}")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except BaseException:
        _close(handle)
        raise
    try:
        # The open handle denies replacement and attribute changes at this name.
        yield fd, path.lstat()
    finally:
        os.close(fd)


@contextmanager
def _directory_chain(path):
    with ExitStack() as locks:
        # A volume root cannot be renamed. Pin every named directory below it.
        for folder in (*reversed(path.parents), path):
            if folder != Path(folder.anchor):
                _, info = locks.enter_context(_locked(folder))
                if not stat.S_ISDIR(info.st_mode):
                    raise PrivateCopyError(f"expected a directory at {str(folder)!r}")
        yield


def _copy_children(root, source, dest, device):
    before = source.lstat()
    for name in os.listdir(source):
        child = source / name
        output = dest / name
        rel = child.relative_to(root)
        with _locked(child) as (fd, info):
            if name.casefold() == ".git":
                if rel == Path(".git") and (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    continue
                raise PrivateCopyError(f"nested or unsupported Git metadata at {str(rel)!r}")
            if info.st_dev != device:
                raise PrivateCopyError(f"nested filesystem at {str(rel)!r}")
            if stat.S_ISDIR(info.st_mode):
                output.mkdir()
                _copy_children(root, child, output, device)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                with os.fdopen(fd, "rb", closefd=False) as original, output.open("xb") as copied:
                    shutil.copyfileobj(original, copied)
                output.chmod(stat.S_IMODE(info.st_mode))
            else:
                raise PrivateCopyError(f"hard-linked or unsupported file at {str(rel)!r}")
            _unchanged(info, child.lstat(), rel)
    _unchanged(before, source.lstat(), source.relative_to(root))


def copy_tree(root, dest):
    with _directory_chain(root):
        _copy_children(root, root, dest, root.lstat().st_dev)


def source_bytes(path, limit):
    with _directory_chain(path.parent), _locked(path) as (fd, info):
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise PrivateCopyError(f"expected an ordinary source file at {str(path)!r}")
        with os.fdopen(fd, "rb", closefd=False) as source:
            return source.read(limit)
