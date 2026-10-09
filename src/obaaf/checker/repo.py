"""Repository-level checks: code owners and agent instruction files (R5, G8.2)."""

from __future__ import annotations

import fnmatch
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "Library", "Intermediate", "Saved",
             "DerivedDataCache", ".godot", "Binaries", "build", "dist"}


# ------------------------------------------------------------------ CODEOWNERS
@dataclass
class OwnerRule:
    pattern: str
    owners: list[str]
    line: int


def read_codeowners(root: Path) -> tuple[str | None, list[OwnerRule]]:
    """The CODEOWNERS file GitHub would use (first found of .github/, root, docs/) and its rules."""
    for rel in CODEOWNERS_LOCATIONS:
        path = root / rel
        if path.is_file():
            rules = []
            for number, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
                line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith("\\#") else raw.strip()
                if not line:
                    continue
                parts = line.split()
                rules.append(OwnerRule(pattern=parts[0], owners=parts[1:], line=number))
            return rel, rules
    return None, []


def _pattern_to_regex(pattern: str) -> re.Pattern:
    """Translate a CODEOWNERS (gitignore-style) pattern to a regex over repo-relative paths."""
    anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
    pat = pattern.lstrip("/")
    directory = pat.endswith("/")
    pat = pat.rstrip("/")
    out = ""
    i = 0
    while i < len(pat):
        if pat.startswith("**/", i):
            out += r"(?:.*/)?"
            i += 3
        elif pat.startswith("/**", i) and i + 3 == len(pat):
            out += r"/.*"
            i += 3
        elif pat.startswith("**", i):
            out += r".*"
            i += 2
        elif pat[i] == "*":
            out += r"[^/]*"
            i += 1
        elif pat[i] == "?":
            out += r"[^/]"
            i += 1
        else:
            out += re.escape(pat[i])
            i += 1
    prefix = "" if anchored else r"(?:.*/)?"
    # A pattern matches the path itself or anything beneath it (directories own their contents),
    # except that a wildcard in the last segment matches one level only: GitHub documents that
    # `docs/*` matches docs/getting-started.md but not docs/build-app/troubleshooting.md.
    last = pat.split("/")[-1]
    if directory:
        suffix = r"/.*"
    elif "*" in last and not last.startswith("**"):
        suffix = ""
    else:
        suffix = r"(?:/.*)?"
    return re.compile(f"^{prefix}{out}{suffix}$")


def owners_for(rules: list[OwnerRule], path: str) -> list[str] | None:
    """Owners of `path` (last matching rule wins). None when no rule matches."""
    result = None
    for rule in rules:
        if _pattern_to_regex(rule.pattern).match(path):
            result = rule.owners
    return result


# ------------------------------------------------------------ instruction files
def _glob_to_regex(glob: str) -> re.Pattern:
    out = ""
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            out += r"(?:.*/)?"
            i += 3
        elif glob.startswith("**", i):
            out += r".*"
            i += 2
        elif glob[i] == "*":
            out += r"[^/]*"
            i += 1
        else:
            out += re.escape(glob[i])
            i += 1
    return re.compile(f"^{out}$")


def find_instruction_files(root: Path, patterns: list[str]) -> list[str]:
    regexes = [_glob_to_regex(p) for p in patterns]
    found = []
    for path in _walk(root):
        rel = path.relative_to(root).as_posix()
        if any(rx.match(rel) for rx in regexes):
            found.append(rel)
    return sorted(found)


def _walk(root: Path):
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink():
                continue
            if entry.is_dir():
                if entry.name not in SKIP_DIRS:
                    stack.append(entry)
            elif entry.is_file():
                yield entry


# Characters that are invisible or reorder text (Rules File Backdoor, ASCII smuggling).
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD, 0x034F}
_TAGS = set(range(0xE0000, 0xE0080))
_VS_SUPPLEMENT = set(range(0xE0100, 0xE01F0))
_VS = set(range(0xFE00, 0xFE10))


def _is_pictographic(ch: str) -> bool:
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF) or (0x2600 <= cp <= 0x27BF) or (0x2B00 <= cp <= 0x2BFF) or \
        (0x2190 <= cp <= 0x21FF) or (0x2300 <= cp <= 0x23FF) or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139)


@dataclass
class HiddenChar:
    line: int
    column: int
    codepoint: int
    kind: str

    @property
    def label(self) -> str:
        name = unicodedata.name(chr(self.codepoint), "UNNAMED")
        return f"U+{self.codepoint:04X} {name} ({self.kind}) at line {self.line}, column {self.column}"


def scan_hidden(text: str) -> list[HiddenChar]:
    """Find invisible or bidirectional control characters, allowing those that form emoji."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        for col, ch in enumerate(line, start=1):
            cp = ord(ch)
            prev = line[col - 2] if col > 1 else ""
            nxt = line[col] if col < len(line) else ""
            if cp == 0xFEFF and number == 1 and col == 1:
                continue  # byte-order mark at the start of the file
            if cp in _TAGS:
                found.append(HiddenChar(number, col, cp, "tag character"))
            elif cp in _VS_SUPPLEMENT:
                found.append(HiddenChar(number, col, cp, "variation selector"))
            elif cp in _BIDI:
                found.append(HiddenChar(number, col, cp, "bidirectional control"))
            elif cp == 0x200D and prev and nxt and (_is_pictographic(prev) or ord(prev) in _VS) and _is_pictographic(nxt):
                continue  # zero-width joiner inside an emoji sequence
            elif cp in _ZERO_WIDTH:
                found.append(HiddenChar(number, col, cp, "zero-width or invisible"))
            elif cp in _VS:
                if cp in (0xFE0E, 0xFE0F) and prev and (_is_pictographic(prev) or prev.isdigit() or prev in "#*"):
                    continue  # text or emoji presentation selector after a symbol
                found.append(HiddenChar(number, col, cp, "variation selector"))
    return found


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)
