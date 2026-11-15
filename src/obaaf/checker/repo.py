"""Repository-level checks: code owners and agent instruction files (R5, G8.2).

How each file is read was attacked in plan slice 2d.2h (docs/bypass-attempts.md). CODEOWNERS is read
the way GitHub's documentation describes it ("About code owners"): one rule per line ending at a line
feed, a pattern and its owners separated by spaces or tabs, a comment from a `#` at the start of the
line or after a space or tab, the last matching rule wins, a file of 3 MB or more is not loaded, and an
owner must take the form `@user`, `@org/team` or an e-mail address. Where the documentation is silent
the reading that leaves a file unowned is taken (a line with an owner in another form gives no owner).
"""

from __future__ import annotations

import fnmatch
import os
import re
import subprocess
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

CODEOWNERS_LOCATIONS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")
# GitHub: "CODEOWNERS files must be under 3 MB in size. A CODEOWNERS file over this limit will not be
# loaded". The lower reading of 3 MB is taken, so a file GitHub may not load is never read as loaded.
CODEOWNERS_LIMIT = 3_000_000
# At most this many comparisons of a pattern with a path, and this many looks at a rule (most end at
# a check that the path holds the pattern's plain text); past either the file is an error, never a pass.
MATCH_BUDGET = 2_000_000
STEP_BUDGET = 30_000_000
# OBAAF's own template ships this owner as a placeholder (templates/github-actions/CODEOWNERS.example).
PLACEHOLDER_OWNERS = ("@your-org/",)
# Only the repository's own history is left out of the walk. Folders that are usually build output or
# third-party code (build/, dist/, node_modules/, Library/) are walked too: an agent reads an AGENTS.md
# or a skill folder wherever it is committed (slice 2d.2h).
SKIP_DIRS = {".git"}
# An instruction folder may hold pictures and archives an agent does not read as text; these are
# owned like any other file and not scanned for hidden characters.
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tif", ".tiff", ".pdf", ".zip",
                   ".gz", ".tgz", ".bz2", ".xz", ".7z", ".tar", ".woff", ".woff2", ".ttf", ".otf", ".ttc", ".eot",
                   ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".avif", ".heic", ".psd", ".docx", ".xlsx",
                   ".pptx", ".odt", ".ods", ".odp", ".wasm", ".pyc", ".class", ".jar", ".so", ".dylib", ".dll",
                   ".exe", ".bin", ".sqlite", ".db", ".npy", ".pkl", ".parquet"}
BINARY_NAMES = {".ds_store", "thumbs.db"}


# ------------------------------------------------------------------ CODEOWNERS
@dataclass
class OwnerRule:
    pattern: str
    owners: list[str]
    line: int
    # Why GitHub may not assign these owners: an owner that is not in a form GitHub reads. Such a rule
    # still matches its pattern and gives no owner, so it takes ownership away like a rule that names
    # nobody (GitHub may skip the whole line instead; then an earlier rule could still own the file).
    problem: str | None = None

    @property
    def valid_owners(self) -> list[str]:
        return [] if self.problem else self.owners


@dataclass
class Codeowners:
    """The CODEOWNERS file GitHub would use, as the checker read it."""
    path: str | None
    rules: list[OwnerRule] = field(default_factory=list)
    not_loaded: str | None = None      # why GitHub would not load the file at all


class UnreadableFile(OSError):
    """A file the checks need that exists and could not be read. It is an error for that file, so
    the check fails, rather than a file taken for missing or empty."""

    def __init__(self, rel: str, exc: OSError | None = None, detail: str | None = None) -> None:
        reason = detail if detail is not None else f"cannot be read: {exc.strerror or exc}"
        super().__init__(f"{rel}: {reason}")
        self.rel = rel


def _owner_problem(owner: str) -> str | None:
    from obaaf.checker.acceptance import owner_problem

    odd = next((ch for ch in owner if unicodedata.category(ch)[0] in "ZC"), None)
    if odd is not None:
        return f"its owner {owner[:60]!r} holds U+{ord(odd):04X}, a space or control character"
    if any(owner.lower().startswith(p) for p in PLACEHOLDER_OWNERS):
        return f"its owner {owner[:60]!r} is the placeholder from OBAAF's template"
    return owner_problem(owner)


def _comment_start(line: str) -> int:
    """Where a comment begins: a `#` at the start of the line or after a space or tab (GitHub's
    example: `*.js    @js-owner #This is an inline comment.`). A `#` inside a word is part of it."""
    for i, ch in enumerate(line):
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return i
    return len(line)


def parse_codeowners(text: str) -> list[OwnerRule]:
    """The rules of a CODEOWNERS file. A line ends at a line feed (a carriage return before it is
    dropped); fields are separated by spaces and tabs only, so another space or a line separator is
    part of the word it is in, never a way to start a new line or field."""
    rules = []
    for number, raw in enumerate(text.split("\n"), start=1):
        if raw.endswith("\r"):
            raw = raw[:-1]
        content = raw[:_comment_start(raw)]
        parts = [p for p in re.split(r"[ \t]+", content) if p]
        if not parts:
            continue
        owners = parts[1:]
        problem = None
        for owner in owners:
            found = _owner_problem(owner)
            if found:
                problem = f"line {number}: {found}"
                break
        rules.append(OwnerRule(pattern=parts[0], owners=owners, line=number, problem=problem))
    return rules


def _entry(root: Path, rel: str) -> str | None:
    """`rel` if the exact name is in its folder (listed, not opened, so a file system that ignores case
    does not answer for `codeowners`), else None. Raises UnreadableFile for a folder that is there and
    cannot be listed, and for an entry that is a link or not a plain file: what GitHub reads from such
    an entry has not been established, and it is never a reason to read a file elsewhere."""
    folder, _, name = rel.rpartition("/")
    directory = root / folder if folder else root
    if folder:
        # The folder's own name is compared exactly too (`.GitHub` is not `.github`).
        try:
            if folder not in os.listdir(root):
                return None
        except OSError as exc:
            raise UnreadableFile(rel, exc) from exc
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return None
    except NotADirectoryError:
        return None
    except OSError as exc:
        raise UnreadableFile(rel, exc) from exc
    if name not in names:
        return None
    path = directory / name
    if path.is_symlink():
        raise UnreadableFile(rel, detail="is a symbolic link, and what GitHub reads from a link has not been "
                                         "established; make it a plain file")
    try:
        regular = path.is_file()
    except OSError as exc:
        raise UnreadableFile(rel, exc) from exc
    if not regular:
        raise UnreadableFile(rel, detail="is not a plain file, and whether GitHub then looks in the next place "
                                         "has not been established")
    return rel


def load_codeowners(root: Path) -> Codeowners:
    """The CODEOWNERS file GitHub would use (first found of .github/, root, docs/) and its rules.
    Raises UnreadableFile for one that is there and cannot be read as UTF-8 text."""
    for location in CODEOWNERS_LOCATIONS:
        rel = _entry(root, location)
        if rel is None:
            continue
        path = root / rel
        try:
            with open(path, "rb") as handle:
                data = handle.read(CODEOWNERS_LIMIT)
        except OSError as exc:
            raise UnreadableFile(rel, exc) from exc
        if len(data) >= CODEOWNERS_LIMIT:
            return Codeowners(rel, [], not_loaded=f"it is {CODEOWNERS_LIMIT:,} bytes or more, and GitHub does "
                                                  "not load a CODEOWNERS file of 3 MB or more")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise UnreadableFile(rel, detail=f"is not UTF-8 text (byte {exc.start + 1}), so the checker cannot "
                                             "tell which owners GitHub reads from it") from exc
        return Codeowners(rel, parse_codeowners(text))
    return Codeowners(None)


def read_codeowners(root: Path) -> tuple[str | None, list[OwnerRule]]:
    """The CODEOWNERS file GitHub would use and its rules (a file GitHub would not load has none)."""
    found = load_codeowners(root)
    return found.path, found.rules


# ---------------------------------------------------------------- patterns
def _tokens(pat: str) -> list[tuple[str, str]]:
    """A pattern (without its leading and trailing slash) as tokens. `**` is a wildcard across folders
    only where gitignore makes it one: a leading `**/`, a `/**/` and a trailing `/**`. Any other run
    of asterisks is one `*`, which stays within a folder."""
    out: list[tuple[str, str]] = []
    i = 0
    n = len(pat)
    while i < n:
        if pat.startswith("**/", i) and (i == 0 or pat[i - 1] == "/"):
            out.append(("dirs", ""))          # (?:.*/)? : no folder or any folders
            i += 3
            while pat.startswith("**/", i):   # **/**/ is one
                i += 3
        elif pat.startswith("**", i) and i + 2 == n and i > 0 and pat[i - 1] == "/":
            out.append(("rest", ""))          # the `/` before it is a literal; this is .*
            i += 2
        elif pat[i] == "*":
            while i < n and pat[i] == "*":
                i += 1
            if not out or out[-1][0] != "star":
                out.append(("star", ""))
        elif pat[i] == "?":
            out.append(("one", ""))
            i += 1
        else:
            out.append(("lit", pat[i]))
            i += 1
    return out


class Pattern:
    """One CODEOWNERS pattern, compiled once. A pattern with few wildcards becomes a regular
    expression; one with more is matched by a bit-parallel automaton, which takes time linear in the
    path whatever the pattern, so a pattern written to backtrack cannot stall the check."""

    def __init__(self, pattern: str) -> None:
        self.anchored = pattern.startswith("/") or "/" in pattern.rstrip("/")
        pat = pattern.lstrip("/")
        directory = pat.endswith("/")
        pat = pat.rstrip("/")
        self.tokens = _tokens(pat)
        last = pat.split("/")[-1]
        # A pattern matches the path itself or anything beneath it (directories own their contents),
        # except that a wildcard in the last segment matches one level only: GitHub documents that
        # `docs/*` matches docs/getting-started.md but not docs/build-app/troubleshooting.md.
        if directory:
            self.suffix = "dir"
        elif self.tokens and self.tokens[-1][0] == "rest":
            self.suffix = "none"
        elif ("*" in last and last != "**") or "?" in last:
            self.suffix = "none"
        else:
            self.suffix = "opt"
        # A regular expression backtracks; with at most one wildcard inside a folder and one across
        # folders its cost stays near linear in the path. Anything more goes to the automaton.
        stars = sum(1 for kind, _ in self.tokens if kind == "star")
        globs = sum(1 for kind, _ in self.tokens if kind in ("dirs", "rest"))
        self.regex = self._regex() if stars <= 1 and globs <= 1 else None
        if self.regex is None:
            self._build_automaton()

    def _regex(self) -> re.Pattern:
        parts = {"star": r"[^/]*", "one": r"[^/]", "dirs": r"(?:.*/)?", "rest": r".*"}
        out = "".join(re.escape(arg) if kind == "lit" else parts[kind] for kind, arg in self.tokens)
        prefix = "" if self.anchored else r"(?:.*/)?"
        suffix = {"dir": r"/.*", "opt": r"(?:/.*)?", "none": ""}[self.suffix]
        return re.compile(f"{prefix}{out}{suffix}", re.DOTALL)

    def _build_automaton(self) -> None:
        # States 0..m: state i means the first i steps have matched. `dirs` is three steps: an entry
        # that consumes nothing and may skip the other two, any text, then `/`.
        steps: list[tuple[str, str]] = []
        skip = 0
        for kind, arg in self.tokens:
            if kind == "dirs":
                skip |= 1 << len(steps)
                steps.append(("enter", ""))
                steps.append(("any", ""))
                steps.append(("lit", "/"))
            elif kind == "rest":
                steps.append(("any", ""))
            else:
                steps.append((kind, arg))
        self.m = len(steps)
        self.lit: dict[str, int] = {}
        self.one = self.star = self.any = self.enter = 0
        for i, (kind, arg) in enumerate(steps):
            bit = 1 << i
            if kind == "lit":
                self.lit[arg] = self.lit.get(arg, 0) | bit
            elif kind == "one":
                self.one |= bit
            elif kind == "star":
                self.star |= bit
            elif kind == "any":
                self.any |= bit
            elif kind == "enter":
                self.enter |= bit
        self.eps = self.star | self.any | self.enter
        self.skip = skip
        self.start = self._closure(1)

    def _closure(self, s: int) -> int:
        while True:
            t = s | ((s & self.eps) << 1) | ((s & self.skip) << 3)
            if t == s:
                return s
            s = t

    def match(self, path: str) -> bool:
        if self.regex is not None:
            return self.regex.fullmatch(path) is not None
        done = 1 << self.m
        s = self.start
        for ch in path:
            if ch == "/" and s & done and self.suffix in ("dir", "opt"):
                return True
            slash = ch == "/"
            advance = s & (self.lit.get(ch, 0) | (0 if slash else self.one))
            stay = s & (self.any | (0 if slash else self.star))
            s = self._closure((advance << 1) | stay)
            if slash and not self.anchored:
                s |= self.start
            elif not s and self.anchored:
                return False
        return bool(s & done) and self.suffix in ("none", "opt")


_WILDCARDS = re.compile(r"\*+/?|\?")


class OwnerIndex:
    """The rules of a CODEOWNERS file, each pattern compiled once, asked from the last rule up so that
    the first match is the one that wins. More comparisons than MATCH_BUDGET, or looks at a rule than
    STEP_BUDGET, raise UnreadableFile."""

    def __init__(self, rules: list[OwnerRule], rel: str = "CODEOWNERS") -> None:
        self.rules = rules
        self.rel = rel
        self._compiled: dict[str, Pattern] = {}
        self._required: dict[str, str] = {}
        self.spent = 0
        self.steps = 0

    def rule_for(self, path: str) -> OwnerRule | None:
        for rule in reversed(self.rules):
            self.steps += 1
            if self.steps > STEP_BUDGET:
                raise UnreadableFile(self.rel, detail=f"needs more than {STEP_BUDGET:,} looks at a rule, more than the "
                                                      "checker makes")
            required = self._required.get(rule.pattern)
            if required is None:
                # A run of plain characters any matching path contains (each piece between wildcards
                # is part of one), found without compiling the pattern.
                pieces = _WILDCARDS.split(rule.pattern.strip("/"))
                required = self._required[rule.pattern] = max(pieces, key=len)
            if required not in path:
                continue
            self.spent += 1
            if self.spent > MATCH_BUDGET:
                raise UnreadableFile(self.rel, detail=f"needs more than {MATCH_BUDGET:,} comparisons of a pattern "
                                                      "with a path, more than the checker makes")
            compiled = self._compiled.get(rule.pattern)
            if compiled is None:
                compiled = self._compiled[rule.pattern] = Pattern(rule.pattern)
            if compiled.match(path):
                return rule
        return None

    def owners(self, path: str) -> list[str] | None:
        rule = self.rule_for(path)
        return None if rule is None else rule.valid_owners


def owners_for(rules: list[OwnerRule], path: str) -> list[str] | None:
    """Owners of `path` (last matching rule wins). None when no rule matches; an empty list when the
    rule that wins names nobody, or an owner in a form GitHub does not read."""
    return OwnerIndex(rules).owners(path)


# ------------------------------------------------------------ instruction files
def _glob_to_regex(glob: str, ignore_case: bool = False) -> re.Pattern:
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
    return re.compile(f"^{out}$", re.IGNORECASE if ignore_case else 0)


@dataclass
class InstructionFile:
    """An agent instruction file as found: `rel` is where an agent finds it; `real` is the file in the
    repository it reads when `rel` is or passes through a link (None when no link is on the way);
    `link` is the link entry that was followed (the link a pull request would change); `outside` says
    the link leads out of the repository or to nothing."""
    rel: str
    real: str | None = None
    outside: bool = False
    link: str | None = None


class TooManyFiles(OSError):
    """More entries than the checker looks through: the instruction files cannot all be found."""


# Entries looked at, and names reached through links, before the search for instruction files stops
# with an error (never with a pass).
WALK_LIMIT = 2_000_000
ALIAS_LIMIT = 200_000
LINK_DEPTH = 8


def _git_tracked(root: Path) -> list[str] | None:
    """The files git tracks under `root`, when `root` is the top of a git work tree and git answers;
    None otherwise (the caller then walks the folder). Tracked files are what a pull request changes
    and what a checkout holds, so an installed node_modules or a local build folder is left out. git
    is run with no hook and no file-system monitor, and with GIT_* variables removed, so neither the
    repository's configuration nor the environment can make it run anything else."""
    if not (root / ".git").exists():
        return None
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        done = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                               "-c", "core.hooksPath=/dev/null", "ls-files", "-z", "--cached"],
                              cwd=str(root), env=env, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return sorted({p.decode("utf-8", "surrogateescape") for p in done.stdout.split(b"\0") if p})


def _scan(root: Path, unlisted: list | None) -> tuple[list[str], list[str]]:
    """(regular files, links) under `root`, each real folder once, without following links. Uses git's
    list of tracked files when there is one; otherwise walks every folder but `.git`."""
    tracked = _git_tracked(root)
    files: list[str] = []
    links: list[str] = []
    if tracked is not None:
        for rel in tracked:
            path = root / rel
            try:
                if path.is_symlink():
                    links.append(rel)
                elif path.is_file():
                    files.append(rel)
            except OSError:
                if unlisted is not None:
                    unlisted.append(rel)
        return files, links
    stack = [(root, "")]
    count = 0
    while stack:
        current, prefix = stack.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda e: e.name)
        except OSError:
            if unlisted is not None:
                unlisted.append(prefix.rstrip("/") or ".")
            continue
        for entry in entries:
            count += 1
            if count > WALK_LIMIT:
                raise TooManyFiles(f"the repository has more than {WALK_LIMIT:,} entries, more than the checker "
                                   "looks through for agent instruction files")
            rel = prefix + entry.name
            try:
                if entry.is_symlink():
                    links.append(rel)
                elif entry.is_dir(follow_symlinks=False):
                    if entry.name not in SKIP_DIRS:
                        stack.append((Path(entry.path), rel + "/"))
                elif entry.is_file(follow_symlinks=False):
                    files.append(rel)
            except OSError:
                # A folder that can be listed and not entered: its entries cannot be looked at.
                if unlisted is not None:
                    unlisted.append(prefix.rstrip("/") or ".")
                break
    return sorted(files), sorted(links)


def find_instruction_entries(root: Path, patterns: list[str], unlisted: list | None = None,
                             errors: list | None = None) -> list[InstructionFile]:
    """Agent instruction files under `root`, matched without regard to letter case (an agent on a
    file system that ignores case reads `agents.md` as AGENTS.md). Each real file is found once by its
    own path; a link is followed while it stays inside the repository, and every file reached through
    it is found again by the name an agent uses (through at most LINK_DEPTH links). Raises
    TooManyFiles past WALK_LIMIT entries, and past ALIAS_LIMIT names reached through links unless
    `errors` is given: then the problem is added to it and what was found so far is returned."""
    import bisect as _bisect

    regexes = [_glob_to_regex(p, ignore_case=True) for p in patterns]

    def wanted(rel: str) -> bool:
        return any(rx.match(rel) for rx in regexes)

    try:
        real_root = root.resolve()
    except OSError:
        real_root = root
    files, links = _scan(root, unlisted)
    found: dict[str, InstructionFile] = {rel: InstructionFile(rel) for rel in files if wanted(rel)}
    # (name an agent uses, the link entry first followed, depth, the link's own path in the repository).
    # A name reached through a link leads where the link's own path leads, which is resolved once.
    queue = [(rel, rel, 1, rel) for rel in links]
    resolved: dict[str, tuple | None] = {}
    made = 0
    while queue:
        name, first, depth, key = queue.pop()
        if key not in resolved:
            try:
                target = (root / key).resolve(strict=True)
                resolved[key] = (target.relative_to(real_root).as_posix(), target.is_dir())
            except (OSError, ValueError, RuntimeError):
                resolved[key] = None
        try:
            if resolved[key] is None:
                raise ValueError(key)
            real, is_dir = resolved[key]
        except (OSError, ValueError, RuntimeError):
            # Out of the repository or to nothing: named when a file there would match.
            if wanted(name) or wanted(name + "/_"):
                found.setdefault(name, InstructionFile(name, outside=True, link=first))
            continue
        if not is_dir:
            if wanted(name) or wanted(real):
                found[name] = InstructionFile(name, real=real, link=first)
            continue
        if depth > LINK_DEPTH:
            continue
        prefix = real + "/" if real != "." else ""
        for pool, is_link in ((files, False), (links, True)):
            at = _bisect.bisect_left(pool, prefix) if prefix else 0
            while at < len(pool) and pool[at].startswith(prefix):
                inner = pool[at]
                at += 1
                alias = name + "/" + inner[len(prefix):]
                made += 1
                if made > ALIAS_LIMIT:
                    problem = (f"links lead to more than {ALIAS_LIMIT:,} names, more than the checker follows when it "
                               "looks for agent instruction files")
                    if errors is None:
                        raise TooManyFiles(problem)
                    errors.append(problem)      # what was found so far is still checked
                    return sorted(found.values(), key=lambda f: f.rel)
                if is_link:
                    queue.append((alias, first, depth + 1, inner))
                elif wanted(alias):
                    found.setdefault(alias, InstructionFile(alias, real=inner, link=first))
    return sorted(found.values(), key=lambda f: f.rel)


def find_instruction_files(root: Path, patterns: list[str], unlisted: list | None = None) -> list[str]:
    """The paths of agent instruction files under `root` (see find_instruction_entries)."""
    return [f.rel for f in find_instruction_entries(root, patterns, unlisted)]


# ------------------------------------------------------------ hidden characters
# Characters that are invisible or reorder text (Rules File Backdoor, ASCII smuggling). The scan is by
# Unicode property where Python has one (every format character, every control but tab, line feed and
# carriage return) and by list for invisible characters of other categories (slice 2d.2h).
_BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0x2061, 0x2062, 0x2063, 0x2064, 0xFEFF, 0x180E, 0x00AD, 0x034F}
# Invisible characters that are not format characters: Hangul fillers, Khmer inherent vowels, the
# braille blank, the combining grapheme joiner, and the code points Unicode reserves as default
# ignorable but has not assigned (shown as nothing once assigned).
_INVISIBLE = {0x115F, 0x1160, 0x3164, 0xFFA0, 0x17B4, 0x17B5, 0x2800, 0x034F} | set(range(0x2065, 0x2066)) | \
    set(range(0xFFF0, 0xFFF9)) | set(range(0xE0080, 0xE0100)) | set(range(0xE01F0, 0xE1000))
_TAGS = set(range(0xE0000, 0xE0080))
_VS_SUPPLEMENT = set(range(0xE0100, 0xE01F0))
_VS = set(range(0xFE00, 0xFE10))
_MONGOLIAN_VS = {0x180B, 0x180C, 0x180D, 0x180F}
_KEYCAP = 0x20E3
# The three subdivision flags in Unicode's recommended set: a black flag, tag letters, a cancel tag.
_SUBDIVISION_FLAGS = tuple("\U0001F3F4" + "".join(chr(0xE0000 + ord(c)) for c in code) + "\U000E007F"
                           for code in ("gbeng", "gbsct", "gbwls"))


def _is_pictographic(ch: str) -> bool:
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF) or (0x2600 <= cp <= 0x27BF) or (0x2B00 <= cp <= 0x2BFF) or \
        (0x2190 <= cp <= 0x21FF) or (0x2300 <= cp <= 0x23FF) or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139)


# Bases of Unicode's emoji variation sequences outside the pictograph ranges above.
_EMOJI_BASES = {0x24C2, 0x25AA, 0x25AB, 0x25B6, 0x25C0, 0x25FB, 0x25FC, 0x25FD, 0x25FE, 0x2934, 0x2935, 0x3030,
                0x303D, 0x3297, 0x3299}


def _is_symbol(ch: str) -> bool:
    """A character that may take an emoji or text presentation selector: a pictograph, or another base
    of Unicode's emoji variation sequences. Not every symbol: a selector after `|` or `=` carries a bit."""
    return _is_pictographic(ch) or ord(ch) in _EMOJI_BASES


# Scripts in which a zero-width joiner or non-joiner changes how letters join: Arabic (with its
# supplements and presentation forms), Syriac, Thaana, the Indic scripts from Devanagari to Sinhala,
# Tibetan, Myanmar, Khmer and Mongolian.
_JOINING_SCRIPTS = ((0x0600, 0x06FF), (0x0700, 0x074F), (0x0750, 0x077F), (0x0780, 0x07BF), (0x08A0, 0x08FF),
                    (0x0900, 0x0DFF), (0x0F00, 0x0FFF), (0x1000, 0x109F), (0x1780, 0x17FF), (0x1800, 0x18AF),
                    (0xFB50, 0xFDFF), (0xFE70, 0xFEFF))


def _in_joining_script(ch: str) -> bool:
    cp = ord(ch)
    return any(lo <= cp <= hi for lo, hi in _JOINING_SCRIPTS) and unicodedata.category(ch)[0] in "LM"


def _joins_letters(prev: str, nxt: str) -> bool:
    """A zero-width joiner or non-joiner between two letters or marks of a script that uses them."""
    return bool(prev and nxt) and _in_joining_script(prev) and _in_joining_script(nxt)


@dataclass
class HiddenChar:
    line: int
    column: int
    codepoint: int
    kind: str
    offset: int = -1              # position in the text the scan was given

    @property
    def label(self) -> str:
        name = unicodedata.name(chr(self.codepoint), "UNNAMED")
        return f"U+{self.codepoint:04X} {name} ({self.kind}) at line {self.line}, column {self.column}"


def _kind(cp: int, ch: str) -> str | None:
    if cp in _TAGS:
        return "tag character"
    if cp in _VS_SUPPLEMENT or cp in _VS or cp in _MONGOLIAN_VS:
        return "variation selector"
    if cp in _BIDI:
        return "bidirectional control"
    if cp in _ZERO_WIDTH or cp in _INVISIBLE:
        return "zero-width or invisible"
    category = unicodedata.category(ch)
    if category == "Cf":
        return "zero-width or invisible"
    if category == "Cc" and ch not in "\t\n\r":
        return "control character"
    if category in ("Zl", "Zp"):
        return "control character"
    return None


def scan_hidden(text: str) -> list[HiddenChar]:
    """Find invisible or bidirectional control characters, allowing those that form emoji, a keycap,
    one of the three recommended subdivision flags, or a join between letters of a script that uses
    joiners. Lines are counted at line feeds only (carriage returns are expected to be line feeds
    already), so a form feed or a line separator is a character the scan reports, not a line end."""
    allowed: set[int] = set()
    for flag in _SUBDIVISION_FLAGS:
        at = text.find(flag)
        while at != -1:
            allowed.update(range(at + 1, at + len(flag)))
            at = text.find(flag, at + len(flag))
    found = []
    line, line_start = 1, 0
    length = len(text)
    for offset, ch in enumerate(text):
        if ch == "\n":
            line, line_start = line + 1, offset + 1
            continue
        cp = ord(ch)
        if 0x20 <= cp < 0x7F or ch in "\t\r":
            continue
        kind = _kind(cp, ch)
        if kind is None or offset in allowed:
            continue
        prev = text[offset - 1] if offset > line_start else ""
        nxt = text[offset + 1] if offset + 1 < length and text[offset + 1] != "\n" else ""
        if cp == 0xFEFF and offset == 0:
            continue  # byte-order mark at the start of the file
        if cp == 0x200D and prev and nxt and (_is_pictographic(prev) or ord(prev) in _VS) and _is_pictographic(nxt):
            continue  # zero-width joiner inside an emoji sequence
        if cp in (0x200C, 0x200D) and _joins_letters(prev, nxt):
            continue
        if cp == 0x200D and prev and 0x0900 <= ord(prev) <= 0x0DFF and unicodedata.category(prev) == "Mn":
            continue  # a joiner after an Indic virama at the end of a word (Malayalam chillu forms)
        if cp in (0xFE0E, 0xFE0F) and prev:
            if _is_symbol(prev):
                continue  # text or emoji presentation selector after a symbol
            if (prev.isdigit() and prev.isascii() or prev in "#*") and nxt == chr(_KEYCAP):
                continue  # keycap: a digit, # or *, the selector, then the enclosing keycap
        found.append(HiddenChar(line, offset - line_start + 1, cp, kind, offset))
    return found


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)
