"""Deterministic checks on an agent's proposal bundle (R4, FR8, FR9).

The effect lane runs these before applying anything. A proposal bundle is a
directory with up to four files:

    patch.diff   a git-format diff (git diff --no-renames) to apply in a new branch
    comment.md   text to post as a comment
    labels.json  {"add": [...], "remove": [...]}
    meta.json    the agent's notes (untrusted; never acted on)

The checks follow Paper 1, section 7.1: the patch touches no workflow,
instruction or other protected file, and comment text contains no links,
images or HTML.

The patch is read twice, independently. Git reads it (``git apply --numstat``
forwards and in reverse, and ``--summary``), because Git is what applies it; a
strict parser here reads it line by line. Every path Git reports must also be
one the parser found, and every path either of them found must pass. Given the
repository, the patch is also applied to a temporary index, and the resulting
changes, with their file modes, are checked again. That last step is the only
one that sees an existing symbolic link being changed, because a patch need not
mention the file's mode. Anything unexpected fails closed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

from obaaf.attest.common import canonical_json, files_under, sha256_bytes, sha256_file
from obaaf.catalog import load as load_catalog
from obaaf.checker.repo import _glob_to_regex, scan_hidden

ALLOWED_FILES = {"patch.diff", "comment.md", "labels.json", "meta.json"}

# Paths no proposal may touch, whatever --allow-dot-path says. A pattern without "/" matches the
# file name in any directory. The agent instruction files from detection.yaml are added to these.
DEFAULT_PROTECTED = [
    ".github/**", ".obaaf/**", ".git/**", "CODEOWNERS", ".gitmodules", ".gitattributes", ".lfsconfig",
    "obaaf-sources.yaml", "obaaf-manifest.json",
]

# Regular files only: no symbolic links (120000) and no submodules (160000).
ALLOWED_MODES = {"100644", "100755"}
NO_MODE = "000000"

_RENAME_HINT = "renames and copies are not allowed in agent proposals; send a deletion and an addition (git diff --no-renames)"
_INDEX_RE = re.compile(r"index ([0-9a-f]{4,64})\.\.([0-9a-f]{4,64})(?: ([0-9]+))?[ \t]*")
_NAME_LINES = ("rename from ", "rename to ", "rename old ", "rename new ", "copy from ", "copy to ")
_MODE_LINES = ("old mode ", "new mode ", "deleted file mode ", "new file mode ")

# Comment text may not link, embed or load anything. This is deliberately blunt: a comment that
# needs any of these characters is refused, and a person can post it instead.
COMMENT_DENYLIST = [
    (re.compile(r"\]\("), "a Markdown link or image ('](')"),
    (re.compile(r"\]:"), "a Markdown link definition (']:')"),
    (re.compile(r"<"), "'<' (HTML or an autolink)"),
    (re.compile(r"//"), "'//' (a web address)"),
    (re.compile(r"(?i)\bwww\."), "a 'www.' address"),
    (re.compile(r"(?i)\b(?:https?|ftps?|mailto|xmpp):"), "a URL scheme"),
    (re.compile(r"[^\s@<>()\[\]]+@[^\s@<>()\[\]]+\.[^\s@<>()\[\]]+"), "an email address"),
]


@dataclass
class ProposalReport:
    files: list[str] = field(default_factory=list)
    touched: list[str] = field(default_factory=list)
    applied: list[dict] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def add(self, problem: str) -> None:
        if problem not in self.problems:
            self.problems.append(problem)

    def to_dict(self) -> dict:
        out = {"format": "obaaf-proposal-check/v0.1", "ok": self.ok, "files": self.files,
               "touchedPaths": self.touched, "problems": self.problems}
        if self.applied:
            out["appliedChanges"] = self.applied
        return out


# ------------------------------------------------------------------ reading names as Git does
_C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13, '"': 34, "\\": 92}


def c_unquote(text: str) -> tuple[str, int] | None:
    """Decode a C-style quoted name as Git writes it.

    Returns the name and the index just past the closing quote, or None if
    ``text`` is not a complete, valid quoted name of UTF-8 text.
    """
    if not text.startswith('"'):
        return None
    out = bytearray()
    i = 1
    while i < len(text):
        ch = text[i]
        if ch == '"':
            try:
                return out.decode("utf-8"), i + 1
            except UnicodeDecodeError:
                return None
        if ch == "\\":
            nxt = text[i + 1:i + 2]
            if nxt in _C_ESCAPES:
                out.append(_C_ESCAPES[nxt])
                i += 2
                continue
            octal = text[i + 1:i + 4]
            if re.fullmatch(r"[0-3][0-7][0-7]", octal):
                out.append(int(octal, 8))
                i += 4
                continue
            return None
        out += ch.encode("utf-8")
        i += 1
    return None


def _strip_components(name: str, count: int) -> str | None:
    """Remove ``count`` leading components (git apply -p), then collapse repeated slashes."""
    for _ in range(count):
        slash = name.find("/")
        if slash == -1:
            return None
        name = name[slash + 1:]
    return re.sub(r"/{2,}", "/", name)


def _header_name(text: str, tab_ends_name: bool) -> str:
    """The name in a ---, +++, rename or copy line: quoted, or up to the first terminating character."""
    quoted = c_unquote(text)
    if quoted is not None:
        return quoted[0]
    stops = "\r\v\f" + ("\t" if tab_ends_name else "")
    end = min([text.find(c) for c in stops if c in text] or [len(text)])
    return text[:end]


def _git_header_names(rest: str) -> list[str] | None:
    """Both names in a 'diff --git' line, following Git's rules for quoted and unquoted names."""
    if rest.startswith('"'):
        first = c_unquote(rest)
        if first is None:
            return None
        tail = rest[first[1]:].lstrip(" \t\r\v\f")
        if not tail:
            return None
        if tail.startswith('"'):
            second = c_unquote(tail)
            return None if second is None else [first[0], second[0]]
        return [first[0], tail]
    quote = rest.find('"')
    if quote > 0:
        second = c_unquote(rest[quote:])
        return None if second is None else [rest[:quote].rstrip(" \t"), second[0]]
    # Both unquoted: Git takes the split where both names are the same after their prefixes. When
    # there is none (a rename or copy, whose names are on later lines), every split is a candidate.
    splits = [(rest[:i], rest[i + 1:]) for i, ch in enumerate(rest) if ch in " \t"]
    for a, b in splits:
        if _strip_components(a, 1) is not None and _strip_components(a, 1) == _strip_components(b, 1):
            return [a, b]
    return [name for pair in splits for name in pair] or None


def _is_dev_null(text: str) -> bool:
    return re.match(r"/dev/null(?:\s|$)", text) is not None


def parse_patch(text: str) -> tuple[set[str], list[str], int]:
    """Read a git-format patch strictly and independently of Git.

    Returns every path the patch could name (a superset: lines inside hunks
    that look like headers are included), the problems found, and the number
    of 'diff --git' file headers.
    """
    candidates: set[str] = set()
    problems: list[str] = []
    headers = 0

    def add(name: str | None, strip: int, number: int, strict: bool = True) -> None:
        if name is None or _is_dev_null(name):
            return
        stripped = _strip_components(name, strip)
        if stripped is not None:
            candidates.add(stripped)
        elif strict:
            problems.append(f"line {number}: no path after removing the a/ or b/ prefix: {name[:120]}")

    for number, line in enumerate(text.split("\n"), start=1):
        if line.startswith("diff --git "):
            headers += 1
            names = _git_header_names(line[len("diff --git "):])
            if names is None:
                problems.append(f"line {number}: cannot read the file names in: {line[:120]}")
            else:
                for name in names:
                    add(name, 1, number, strict=False)
        elif line.startswith(("--- ", "+++ ")):
            add(_header_name(line[4:], tab_ends_name=True), 1, number)
        elif line.startswith(_NAME_LINES):
            problems.append(_RENAME_HINT)
            prefix = next(p for p in _NAME_LINES if line.startswith(p))
            add(_header_name(line[len(prefix):], tab_ends_name=False), 0, number)
        elif line.startswith(_MODE_LINES):
            mode = line.split(" mode ", 1)[1].strip()
            if mode not in ALLOWED_MODES:
                problems.append(f"line {number}: file mode {mode[:20]} is not allowed; only regular files "
                                f"(100644, 100755) may change, not symbolic links or submodules")
        elif line.startswith("index "):
            match = _INDEX_RE.fullmatch(line)
            if not match:
                problems.append(f"line {number}: unexpected index line: {line[:120]}")
            elif match.group(3) and match.group(3) not in ALLOWED_MODES:
                problems.append(f"line {number}: file mode {match.group(3)} is not allowed; only regular files "
                                f"(100644, 100755) may change, not symbolic links or submodules")
        elif line.startswith(("GIT binary patch", "Binary files ")) or (
                line.startswith("Files ") and line.rstrip().endswith(" differ")):
            problems.append("binary changes are not allowed in agent proposals")
        elif re.match(r"[ +-]?Subproject commit ", line):
            problems.append("submodule changes are not allowed in agent proposals")
    return candidates, problems, headers


# ------------------------------------------------------------------ reading the patch with Git
class GitUnavailable(RuntimeError):
    pass


def _git(args: list[str], cwd: str, env: dict) -> subprocess.CompletedProcess:
    git = shutil.which("git")
    if not git:
        raise GitUnavailable("git is required to check patch.diff and was not found")
    return subprocess.run([git, *args], cwd=cwd, env=env, capture_output=True, timeout=120, check=False)


def _isolated_env(home: str) -> dict:
    """An environment in which Git reads no repository and no system or user configuration."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "HOME": home,
                "XDG_CONFIG_HOME": home, "GIT_CEILING_DIRECTORIES": str(Path(home).parent), "LC_ALL": "C"})
    return env


def _first_line(data: bytes) -> str:
    text = data.decode("utf-8", "replace").strip()
    return text.splitlines()[0][:200] if text else "(no message)"


def _numstat(output: bytes) -> list[tuple[str, str, str]]:
    entries = []
    for chunk in output.split(b"\0"):
        if chunk:
            added, deleted, path = chunk.split(b"\t", 2)
            entries.append((added.decode("ascii", "replace"), deleted.decode("ascii", "replace"),
                            path.decode("utf-8", "surrogateescape")))
    return entries


def git_view(patch_file: Path) -> tuple[list[str], list[str], int]:
    """Paths Git would touch (old and new names), problems Git's view shows, and Git's file count."""
    problems: list[str] = []
    with tempfile.TemporaryDirectory(prefix="obaaf-git-") as tmp:
        home = os.path.join(tmp, "home")
        work = os.path.join(tmp, "work")
        os.mkdir(home)
        os.mkdir(work)
        env = _isolated_env(home)
        source = str(Path(patch_file).resolve())
        forward = _git(["apply", "-p1", "--numstat", "-z", source], work, env)
        if forward.returncode != 0:
            return [], [f"git cannot read patch.diff: {_first_line(forward.stderr)}"], 0
        reverse = _git(["apply", "-p1", "-R", "--numstat", "-z", source], work, env)
        summary = _git(["apply", "-p1", "--summary", source], work, env)
        for result in (reverse, summary):
            if result.returncode != 0:
                return [], [f"git cannot read patch.diff: {_first_line(result.stderr)}"], 0
    fwd, rev = _numstat(forward.stdout), _numstat(reverse.stdout)
    if any(a == "-" or d == "-" for a, d, _ in fwd):
        problems.append("binary changes are not allowed in agent proposals")
    for line in summary.stdout.decode("utf-8", "surrogateescape").splitlines():
        if line.startswith((" rename ", " copy ")):
            problems.append(_RENAME_HINT)
        for mode in re.findall(r"^ (?:create|delete) mode ([0-9]+) ", line) + \
                list(sum(re.findall(r"^ mode change ([0-9]+) => ([0-9]+)", line), ())):
            if mode not in ALLOWED_MODES:
                problems.append(f"file mode {mode} is not allowed; only regular files (100644, 100755) may change, "
                                f"not symbolic links or submodules")
    paths = sorted({p for _, _, p in fwd} | {p for _, _, p in rev})
    return paths, problems, len(fwd)


def simulate(repo: Path, patch_file: Path) -> tuple[list[dict], list[str]]:
    """Apply the patch to a temporary index of ``repo`` at HEAD and list the changes, with modes.

    The working tree and the real index are not touched.
    """
    with tempfile.TemporaryDirectory(prefix="obaaf-index-") as tmp:
        env = {k: v for k, v in os.environ.items()
               if k not in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_PREFIX",
                            "GIT_NAMESPACE", "GIT_OBJECT_DIRECTORY", "GIT_ALTERNATE_OBJECT_DIRECTORIES")}
        env["GIT_INDEX_FILE"] = os.path.join(tmp, "index")
        source = str(Path(patch_file).resolve())
        base = ["-C", str(Path(repo).resolve())]
        steps = [["read-tree", "HEAD"],
                 ["apply", "--cached", "-p1", "--whitespace=nowarn", source],
                 ["diff-index", "--cached", "--raw", "-z", "--no-renames", "HEAD"]]
        result = None
        for args in steps:
            result = _git(base + args, tmp, env)
            if result.returncode != 0:
                return [], [f"the patch does not apply to {repo} at HEAD: {_first_line(result.stderr)}"]
    tokens = result.stdout.split(b"\0")
    changes = []
    i = 0
    while i < len(tokens) - 1:
        meta = tokens[i].decode("ascii", "replace")
        if not meta.startswith(":"):
            i += 1
            continue
        old_mode, new_mode, _old, _new, status = meta[1:].split(" ")
        changes.append({"path": tokens[i + 1].decode("utf-8", "surrogateescape"), "status": status,
                        "oldMode": old_mode, "newMode": new_mode})
        i += 2
    return changes, []


# ------------------------------------------------------------------ path rules
def _normalize(path: str) -> str:
    """Fold case and compatibility forms, and drop trailing dots and spaces Windows ignores."""
    parts = [part.rstrip(" .") or part for part in path.split("/")]
    return unicodedata.normalize("NFKC", "/".join(parts)).casefold()


class PathRules:
    def __init__(self, protected: list[str], allow_dot_paths: list[str]):
        self.protected = [(p, _glob_to_regex(_normalize(p))) for p in protected]
        self.allow_dot = [_glob_to_regex(_normalize(p)) for p in allow_dot_paths]

    def problems(self, path: str) -> list[str]:
        if not path:
            return ["the patch names an empty path"]
        out = []
        if path.startswith("/") or ".." in path.split("/"):
            out.append(f"path escapes the repository: {path!r}")
        if re.search(r"[\x00-\x1f\x7f\\:]", path):
            out.append(f"path contains a control character, backslash or colon: {path!r}")
        hidden = scan_hidden(path)
        if hidden:
            out.append(f"path contains a hidden character ({hidden[0].label}): {path!r}")
        norm = _normalize(path)
        name = norm.rsplit("/", 1)[-1]
        hits = [p for p, rx in self.protected if rx.match(norm) or rx.match(name)]
        if hits:
            out.append(f"patch touches protected path {path} (matches {hits[0]})")
        elif any(part.startswith(".") for part in norm.split("/")) and not any(rx.match(norm) for rx in self.allow_dot):
            out.append(f"patch touches {path}, which is under a name starting with '.'; configuration paths are "
                       f"refused unless allowed with --allow-dot-path")
        return out


def protected_patterns(extra: list[str] | None = None) -> list[str]:
    catalog = load_catalog()
    return DEFAULT_PROTECTED + list(catalog.detection.get("instruction_files", [])) + list(extra or [])


# ------------------------------------------------------------------ the bundle
def bundle_digest(proposal_dir: str | Path) -> str:
    """One digest for a whole proposal bundle: sha256 of its sorted (name, sha256) list."""
    root = Path(proposal_dir)
    listing = [[p.relative_to(root).as_posix(), sha256_file(p)] for p in files_under(root)]
    return sha256_bytes(canonical_json(sorted(listing)))


def _read_text(path: Path, report: ProposalReport) -> str | None:
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        report.add(f"{path.name} is not UTF-8 text")
    except OSError as exc:
        report.add(f"cannot read {path.name}: {exc}")
    return None


def check_patch(patch_file: Path, rules: PathRules, report: ProposalReport, repo: Path | None = None,
                max_paths: int = 100) -> None:
    text = _read_text(patch_file, report)
    if text is None:
        return
    hidden = scan_hidden(text)
    if hidden:
        report.add(f"patch.diff contains {len(hidden)} hidden character(s), first {hidden[0].label}")
    candidates, own_problems, headers = parse_patch(text)
    for problem in own_problems:
        report.add(problem)
    try:
        touched, git_problems, git_files = git_view(patch_file)
    except (GitUnavailable, subprocess.SubprocessError, OSError) as exc:
        report.add(f"cannot check patch.diff with git: {exc}")
        return
    for problem in git_problems:
        report.add(problem)
    report.touched = touched
    if not touched and not git_problems:
        report.add("patch.diff changes no files")
    if git_files != headers:
        report.add(f"git reads {git_files} file change(s) but the patch has {headers} 'diff --git' header(s); "
                   f"only plain git-format diffs are accepted")
    unseen = [p for p in touched if p not in candidates]
    if unseen:
        report.add("git and OBAAF read the patch differently; git also names: " + ", ".join(repr(p) for p in unseen[:5]))
    if len(touched) > max_paths:
        report.add(f"patch.diff touches {len(touched)} paths; the limit is {max_paths}")
    for path in sorted(set(touched) | candidates):
        for problem in rules.problems(path):
            report.add(problem)
    if repo is not None and report.ok:
        changes, problems = simulate(repo, patch_file)
        for problem in problems:
            report.add(problem)
        report.applied = changes
        for change in changes:
            for mode in (change["oldMode"], change["newMode"]):
                if mode not in ALLOWED_MODES and mode != NO_MODE:
                    report.add(f"applying the patch changes {change['path']}, whose mode is {mode}; only regular "
                               f"files may change, not symbolic links or submodules")
            for problem in rules.problems(change["path"]):
                report.add(problem)
            if change["path"] not in touched:
                report.add(f"applying the patch changes {change['path']}, which the check did not see")


def check_comment(text: str, report: ProposalReport) -> None:
    for pattern, what in COMMENT_DENYLIST:
        match = pattern.search(text)
        if match:
            report.add(f"comment contains {what}: {match.group(0)[:60]!r}")
    hidden = scan_hidden(text)
    if hidden:
        report.add(f"comment contains {len(hidden)} hidden character(s), first {hidden[0].label}")


def check_labels(text: str, allowed_labels: list[str] | None, report: ProposalReport) -> None:
    try:
        labels = json.loads(text)
    except ValueError:
        labels = None
    valid = isinstance(labels, dict) and set(labels) <= {"add", "remove"} and all(
        isinstance(v, list) and all(isinstance(x, str) for x in v) for v in labels.values())
    if not valid:
        report.add("labels.json must be an object with only 'add' and 'remove' lists of label names")
        return
    changes = labels.get("add", []) + labels.get("remove", [])
    if changes and allowed_labels is None:
        report.add("labels.json is present but no labels are allowed (pass --allow-label)")
        return
    for label in changes:
        if label not in (allowed_labels or []):
            report.add(f"label not allowed: {label}")


def check(bundle: str | Path, protected: list[str] | None = None, allowed_labels: list[str] | None = None,
          allow_dot_paths: list[str] | None = None, repo: str | Path | None = None,
          expect_digest: str | None = None, max_bytes: int = 1_000_000, max_paths: int = 100) -> ProposalReport:
    """Check a proposal bundle. With ``repo``, also apply the patch to a temporary index of it."""
    report = ProposalReport()
    root = Path(bundle)
    if not root.is_dir():
        report.add(f"proposal bundle not found: {root}")
        return report
    if expect_digest:
        actual = bundle_digest(root)
        if actual != expect_digest.removeprefix("sha256:"):
            report.add(f"the proposal bundle's digest is {actual}, not the approved {expect_digest}")
    present = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink())
    report.files = present
    usable = set()
    for rel in present:
        path = root / rel
        if rel not in ALLOWED_FILES:
            report.add(f"unexpected file in proposal bundle: {rel}")
        elif path.is_symlink():
            report.add(f"symbolic link in proposal bundle: {rel}")
        elif path.stat().st_size > max_bytes:
            report.add(f"{rel} is larger than {max_bytes} bytes")
        else:
            usable.add(rel)
    if not usable & {"patch.diff", "comment.md", "labels.json"}:
        report.add("proposal bundle is empty: expected patch.diff, comment.md or labels.json")

    rules = PathRules(protected_patterns(protected), list(allow_dot_paths or []))
    if "patch.diff" in usable:
        check_patch(root / "patch.diff", rules, report, repo=Path(repo) if repo is not None else None,
                    max_paths=max_paths)
    if "comment.md" in usable:
        text = _read_text(root / "comment.md", report)
        if text is not None:
            check_comment(text, report)
    if "labels.json" in usable:
        text = _read_text(root / "labels.json", report)
        if text is not None:
            check_labels(text, allowed_labels, report)
    return report
