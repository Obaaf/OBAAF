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


# A user (`@name`) or a team (`@org/team`) as a CODEOWNERS file may name one. GitHub's rules for a new
# user name refuse a hyphen at the end or two in a row, but older accounts keep such names (Home
# Assistant's CODEOWNERS names `@freeDom-` and `@viiru-`), so they are read as names here; the form
# for an acceptance's owner (acceptance._HANDLE) stays as it is (the third review of slice 2d.2h).
_CODEOWNERS_HANDLE = re.compile(r"@[A-Za-z0-9][A-Za-z0-9-]{0,38}(?:_[A-Za-z0-9]{1,39})?"
                                r"(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,99})?")


def _owner_problem(owner: str) -> str | None:
    from obaaf.checker.acceptance import _is_email

    odd = next((ch for ch in owner if unicodedata.category(ch)[0] in "ZC"), None)
    if odd is not None:
        return f"its owner {owner[:60]!r} holds U+{ord(odd):04X}, a space or control character"
    if any(owner.lower().startswith(p) for p in PLACEHOLDER_OWNERS):
        return f"its owner {owner[:60]!r} is the placeholder from OBAAF's template"
    if _CODEOWNERS_HANDLE.fullmatch(owner) or _is_email(owner):
        return None
    return f"its owner {owner[:60]!r} is not a user (@name), a team (@org/team) or an e-mail address"


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
        self.kinds = steps
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

    # ---- questions about every name in a folder (a workflow file nobody has written yet)
    def _step(self, s: int, ch: str) -> int:
        slash = ch == "/"
        advance = s & (self.lit.get(ch, 0) | (0 if slash else self.one))
        stay = s & (self.any | (0 if slash else self.star))
        s = self._closure((advance << 1) | stay)
        if slash and not self.anchored:
            s |= self.start
        return s

    def _automaton(self) -> None:
        if not hasattr(self, "m"):
            self._build_automaton()

    def _reach_any(self, s: int) -> int:
        """The states after one or more characters, none of them `/`, from the states `s`: one pass
        over the steps, which only lead forward or to themselves, so the time is linear in the
        pattern (the third review of slice 2d.2h found that asking each character in turn took 26 s
        on a 12 KB rule)."""
        m = self.m
        bits = bin(s)[:1:-1]
        live = [i < len(bits) and bits[i] == "1" for i in range(m + 1)]
        reach = [False] * (m + 1)
        kinds = self.kinds
        for i in range(m + 1):
            got = False
            if i < m and live[i] and kinds[i][0] in ("star", "any"):
                got = True                                   # a wildcard takes the character and stays
            if i >= 1:
                kind, arg = kinds[i - 1]
                if (live[i - 1] or reach[i - 1]) and (kind == "one" or (kind == "lit" and arg != "/")):
                    got = True                               # a step that takes any character but `/`
                if reach[i - 1] and kind in ("star", "any", "enter"):
                    got = True                               # a step that may take nothing
            if i >= 3 and reach[i - 3] and kinds[i - 3][0] == "enter":
                got = True                                   # `**/` taking no folder
            reach[i] = got
        out = 0
        for i in range(m, -1, -1):
            out = (out << 1) | reach[i]
        return out

    def matches_some_child(self, folder: str, suffix: str) -> bool:
        """Whether some name `folder/X<suffix>`, X one or more characters with no `/`, matches."""
        self._automaton()
        done = 1 << self.m
        s = self.start
        for ch in folder + "/":
            if ch == "/" and s & done and self.suffix in ("dir", "opt"):
                return True              # the folder itself, or one above it, matches: so does every name
            s = self._step(s, ch)
        reach = self._reach_any(s)
        for ch in suffix:
            reach = self._step(reach, ch)
        return bool(reach & done) and self.suffix in ("none", "opt")

    def matches_every_child(self, folder: str, suffix: str) -> bool:
        """Whether every name `folder/X<suffix>` matches. X is replaced by a character no pattern holds
        (a pattern that holds it never counts), in three lengths: a run of wildcards that takes all
        three takes every length from one up, and any characters, since a wildcard takes any but `/`."""
        if SENTINEL in "".join(arg for _kind, arg in self.tokens):
            return False
        return all(self.match(f"{folder}/{SENTINEL * n}{suffix}") for n in (1, 2, 31))


# A private-use character standing for "any name" in the questions above.
SENTINEL = "\ue000"

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

    def new_file_owned(self, folder: str, suffix: str) -> tuple[bool, str | None]:
        """Whether every file not written yet, `folder/X<suffix>`, gets an owner: the last rule that
        matches every such name must give one, and no rule after it that can match some such name may
        give none. (owned, the problem of the rule that leaves one unowned, if it says one)."""
        for index in range(len(self.rules) - 1, -1, -1):
            rule = self.rules[index]
            compiled = self._compiled.get(rule.pattern) or Pattern(rule.pattern)
            self._compiled[rule.pattern] = compiled
            if compiled.matches_every_child(folder, suffix):
                if not rule.valid_owners:
                    return False, rule.problem
                for later in self.rules[index + 1:]:
                    if later.valid_owners:
                        continue
                    pattern = self._compiled.get(later.pattern) or Pattern(later.pattern)
                    self._compiled[later.pattern] = pattern
                    if pattern.matches_some_child(folder, suffix):
                        return False, later.problem
                return True, None
        return False, None


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


def find_git(root: Path) -> Path | None:
    """The git program to run: the first one in an absolute folder of the PATH that is not inside
    `root`. A relative or empty PATH entry is skipped, so neither the current folder nor the repository
    can supply it (Windows looks in the current folder first; the PATH is searched here instead). The
    answer does not depend on the current folder (the third review of slice 2d.2h found that from `/`
    every git was refused, so untracked files counted)."""
    names = ["git"]
    if os.name == "nt":
        names = ["git" + ext.lower() for ext in os.environ.get("PATHEXT", ".EXE").split(os.pathsep) if ext]
    try:
        real_root = root.resolve()
    except OSError:
        real_root = root
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if not folder or not os.path.isabs(folder):
            continue
        for name in names:
            candidate = Path(folder) / name
            try:
                if not candidate.is_file() or not os.access(candidate, os.X_OK):
                    continue
                resolved = candidate.resolve()
            except OSError:
                continue
            try:
                resolved.relative_to(real_root)
                continue                 # a git inside the repository is never run
            except ValueError:
                return resolved
    return None


def _run_git(git: Path, root: Path, *args: str) -> bytes | None:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        done = subprocess.run([str(git), "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
                               "-c", "core.hooksPath=/dev/null", *args],
                              cwd=str(root), env=env, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _git_tracked(root: Path, how: dict | None = None) -> list[str] | None:
    """The files git tracks under `root`, when `root` is the top of a git work tree and git answers;
    None otherwise (the caller then walks the folder, and `how["why"]` says why). Tracked files are
    what a pull request changes and what a checkout holds, so an installed node_modules or a local
    build folder is left out; the files of checked-out submodules are included, and `how["gitlinks"]`
    lists the submodules, whose files a pull request changes only through the submodule's own entry.
    git is run with no hook and no file-system monitor and with GIT_* variables removed, so neither the
    repository's configuration nor the environment can make it run anything else."""
    how = how if how is not None else {}
    if not (root / ".git").exists():
        return None
    git = find_git(root)
    if git is None:
        how["why"] = "no git program was found in an absolute folder of the PATH outside the repository"
        return None
    listed = _run_git(git, root, "ls-files", "-z", "--cached", "--recurse-submodules")
    staged = _run_git(git, root, "ls-files", "-z", "--stage") if listed is not None else None
    if listed is None or staged is None:
        how["why"] = "git did not list the tracked files"
        return None
    gitlinks = []
    for record in staged.split(b"\0"):
        meta, _, path = record.partition(b"\t")
        if meta.startswith(b"160000 ") and path:
            gitlinks.append(path.decode("utf-8", "surrogateescape"))
    how["gitlinks"] = sorted(gitlinks)
    return sorted({p.decode("utf-8", "surrogateescape") for p in listed.split(b"\0") if p})


def _scan(root: Path, unlisted: list | None, how: dict | None = None) -> tuple[list[str], list[str]]:
    """(regular files, links) under `root`, each real folder once, without following links. Uses git's
    list of tracked files when there is one; otherwise walks every folder but `.git`. `how["listing"]`
    says which ("git" or "walk")."""
    how = how if how is not None else {}
    tracked = _git_tracked(root, how)
    how["listing"] = "walk" if tracked is None else "git"
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
                             errors: list | None = None, how: dict | None = None) -> list[InstructionFile]:
    """Agent instruction files under `root`, matched without regard to letter case (an agent on a
    file system that ignores case reads `agents.md` as AGENTS.md). Each real file is found once by its
    own path; a link is followed while it stays inside the repository, and every file reached through
    it is found again by the name an agent uses (through at most LINK_DEPTH links). Raises
    TooManyFiles past WALK_LIMIT entries, and past ALIAS_LIMIT names reached through links unless
    `errors` is given: then the problem is added to it and what was found so far is returned."""
    import bisect as _bisect
    import stat as _stat

    combined = re.compile("|".join(f"(?:{_glob_to_regex(p).pattern})" for p in patterns) or r"(?!)", re.IGNORECASE)
    globs = [_glob_steps(p) for p in patterns]

    def wanted(rel: str) -> bool:
        return combined.match(rel) is not None

    def beneath(rel: str) -> bool:
        """Whether some name under the folder `rel` would be an instruction file."""
        return _could_match_beneath(globs, rel)

    try:
        real_root = root.resolve()
    except OSError:
        real_root = root
    files, links = _scan(root, unlisted, how)
    found: dict[str, InstructionFile] = {rel: InstructionFile(rel) for rel in files if wanted(rel)}
    # (name an agent uses, the link entry first followed, depth, the link's own path in the repository,
    # the folders already entered on the way). A name reached through a link leads where the link's own
    # path leads, which is resolved once.
    queue = [(rel, rel, 1, rel, frozenset()) for rel in links]
    resolved: dict[str, tuple | None] = {}
    made = looks = 0

    def stop(problem: str) -> list[InstructionFile]:
        if errors is None:
            raise TooManyFiles(problem)
        errors.append(problem)          # what was found so far is still checked
        return sorted(found.values(), key=lambda f: f.rel)

    while queue:
        name, first, depth, key, chain = queue.pop()
        if key not in resolved:
            try:
                target = (root / key).resolve(strict=True)
                mode = target.stat().st_mode
                kind = "dir" if _stat.S_ISDIR(mode) else "file" if _stat.S_ISREG(mode) else "other"
                resolved[key] = (target.relative_to(real_root).as_posix(), kind)
            except (OSError, ValueError, RuntimeError):
                resolved[key] = None
        entry = resolved[key]
        if entry is None or entry[1] == "other":
            # Out of the repository, to nothing, or to something that is neither a file nor a folder (a
            # pipe would stall the read): named, and not read, when it or a file beneath it would match.
            if wanted(name) or beneath(name):
                found.setdefault(name, InstructionFile(name, outside=True, link=first))
            continue
        real, kind = entry
        if kind == "file":
            if wanted(name) or wanted(real):
                found[name] = InstructionFile(name, real=real, link=first)
            continue
        if real in chain:
            continue                     # a loop of links: every name on it has been seen
        if depth > LINK_DEPTH:
            problem = (f"{first}: more than {LINK_DEPTH} links lead one through another, more than the checker "
                       "follows when it looks for agent instruction files")
            if errors is None:
                raise TooManyFiles(problem)
            if problem not in errors:
                errors.append(problem)
            continue
        # A link to a folder, a folder that holds the link (`.`, `..`, the root) included, is followed
        # once: every file behind it is found again by the name an agent uses (`.github -> .` makes the
        # root's `copilot-instructions.md` an instruction file). The folders entered on the way are not
        # entered again, so a link back to one of them ends there.
        chain = chain | {real}
        prefix = "" if real == "." else real + "/"
        for pool, is_link in ((files, False), (links, True)):
            at = _bisect.bisect_left(pool, prefix) if prefix else 0
            while at < len(pool) and pool[at].startswith(prefix):
                inner = pool[at]
                at += 1
                looks += 1
                if looks > WALK_LIMIT:
                    return stop(f"links lead to more than {WALK_LIMIT:,} entries, more than the checker looks "
                                "through for agent instruction files")
                alias = name + "/" + inner[len(prefix):]
                if not is_link and not wanted(alias):
                    continue
                made += 1
                if made > ALIAS_LIMIT:
                    return stop(f"links lead to more than {ALIAS_LIMIT:,} names, more than the checker follows "
                                "when it looks for agent instruction files")
                if is_link:
                    queue.append((alias, first, depth + 1, inner, chain))
                else:
                    found.setdefault(alias, InstructionFile(alias, real=inner, link=first))
    return sorted(found.values(), key=lambda f: f.rel)


def _glob_steps(glob: str) -> list[tuple[str, str]]:
    """An instruction-file pattern as steps, read as _glob_to_regex reads it, in lower case."""
    steps: list[tuple[str, str]] = []
    i = 0
    while i < len(glob):
        if glob.startswith("**/", i):
            steps.append(("dirs", ""))
            i += 3
        elif glob.startswith("**", i):
            steps.append(("rest", ""))
            i += 2
        elif glob[i] == "*":
            steps.append(("star", ""))
            i += 1
        else:
            steps.append(("lit", glob[i].lower()))
            i += 1
    return steps


def _could_match_beneath(globs: list[list[tuple[str, str]]], folder: str) -> bool:
    """Whether some path `folder/X`, X not empty, matches one of the patterns (without regard to case)
    by what the pattern says of `folder`: a pattern that reaches it only through a leading `**/` (any
    folder may hold an AGENTS.md) does not count, or every link out of the repository would. Each
    pattern is run over `folder/` as a set of positions; one still alive can be completed, since every
    step can take some text."""
    text = (folder + "/").lower()
    for steps in globs:
        n = len(steps)

        def close(states: set) -> set:
            out, todo = set(states), list(states)
            while todo:
                s = todo.pop()
                if isinstance(s, int) and s < n and steps[s][0] in ("dirs", "rest", "star") and s + 1 not in out:
                    out.add(s + 1)
                    todo.append(s + 1)
            return out

        states = close({0})
        for ch in text:
            nxt: set = set()
            for s in states:
                if isinstance(s, tuple):                     # inside the folders of a `**/`
                    nxt.add(s)
                    if ch == "/":
                        nxt.add(s[1] + 1)
                    continue
                if s >= n:
                    continue
                kind, arg = steps[s]
                if kind == "lit" and arg == ch:
                    nxt.add(s + 1)
                elif kind == "star" and ch != "/":
                    nxt.add(s)
                elif kind == "rest":
                    nxt.add(s)
                elif kind == "dirs":
                    nxt.add(("in", s))
                    if ch == "/":
                        nxt.add(s + 1)
            states = close(nxt)
            if not states:
                break
        idle = {("in", 0), 1} if steps and steps[0][0] == "dirs" else set()
        if any(s not in idle and (isinstance(s, tuple) or s < n) for s in states):
            return True
    return False


def find_instruction_files(root: Path, patterns: list[str], unlisted: list | None = None,
                           errors: list | None = None, how: dict | None = None) -> list[str]:
    """The paths of agent instruction files under `root` (see find_instruction_entries)."""
    try:
        return [f.rel for f in find_instruction_entries(root, patterns, unlisted, errors, how)]
    except TooManyFiles as exc:
        if errors is None:
            raise
        errors.append(str(exc))
        return []


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
    return any(lo <= cp <= hi for lo, hi in _JOINING_SCRIPTS)


def _joins_letters(prev: str, nxt: str) -> bool:
    """A zero-width joiner or non-joiner between two letters of a script that joins, or after a virama
    and before a letter of that script (Indic conjuncts and half forms); never between two marks."""
    if not (prev and nxt) or not (_in_joining_script(prev) and _in_joining_script(nxt)):
        return False
    if unicodedata.category(nxt)[0] != "L":
        return False
    return unicodedata.category(prev)[0] == "L" or unicodedata.combining(prev) == 9


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


# Every format character (category Cf) of Unicode 15.1, written out so that an older Python, whose
# Unicode tables are older (3.10 has Unicode 13, 3.11 has 14), reports the same ones: U+0890, U+0891
# and U+13439 to U+1343F were assigned later. A newer Python may report format characters added after
# 15.1 as well (the third review of slice 2d.2h).
_FORMAT_RANGES = ((0x00AD, 0x00AD), (0x0600, 0x0605), (0x061C, 0x061C), (0x06DD, 0x06DD), (0x070F, 0x070F),
                  (0x0890, 0x0891), (0x08E2, 0x08E2), (0x180E, 0x180E), (0x200B, 0x200F), (0x202A, 0x202E),
                  (0x2060, 0x2064), (0x2066, 0x206F), (0xFEFF, 0xFEFF), (0xFFF9, 0xFFFB), (0x110BD, 0x110BD),
                  (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A),
                  (0xE0001, 0xE0001), (0xE0020, 0xE007F))
_FORMAT = frozenset(cp for lo, hi in _FORMAT_RANGES for cp in range(lo, hi + 1))


def _kind(cp: int, ch: str) -> str | None:
    if cp in _TAGS:
        return "tag character"
    if cp in _VS_SUPPLEMENT or cp in _VS or cp in _MONGOLIAN_VS:
        return "variation selector"
    if cp in _BIDI:
        return "bidirectional control"
    if cp in _ZERO_WIDTH or cp in _INVISIBLE or cp in _FORMAT:
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
        if cp in (0xFE0E, 0xFE0F) and prev:
            if _is_symbol(prev):
                continue  # text or emoji presentation selector after a symbol
            if (prev.isdigit() and prev.isascii() or prev in "#*") and nxt == chr(_KEYCAP):
                continue  # keycap: a digit, # or *, the selector, then the enclosing keycap
        found.append(HiddenChar(line, offset - line_start + 1, cp, kind, offset))
    return found


def matches_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, p) for p in patterns)
