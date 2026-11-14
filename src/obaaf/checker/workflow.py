"""A model of GitHub Actions workflow files for the OBAAF checker.

The model answers the questions the rules ask: what can start this job, what
can its token do, which secrets reach it, does it run an agent, does it upload
releases, and which caches can it read.
"""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterator

from obaaf import yamlutil
from obaaf.catalog import load as load_catalog
from obaaf.checker import expr as expr_mod

LANES = ("untrusted", "agent", "effect", "release", "trusted")
# A job is in every lane it qualifies for, and gets the rules of each. This is the order they are
# shown in; the first one a job is in is the lane `--lanes` names. "trusted" means none of them.
LANE_ORDER = ("agent", "effect", "release", "untrusted")

# Triggers whose payload or initiating actor someone without write access can
# influence, and which run in the base repository's context with its token,
# secrets and default-branch cache scope.
PRIVILEGED_UNTRUSTED_TRIGGERS = {
    "pull_request_target", "issue_comment", "issues", "discussion", "discussion_comment",
    "pull_request_review", "pull_request_review_comment", "workflow_run", "fork", "watch", "gollum",
}
# pull_request runs the pull request's code; forks get a read-only token and no secrets.
PR_TRIGGERS = {"pull_request"}
UNTRUSTED_TRIGGERS = PRIVILEGED_UNTRUSTED_TRIGGERS | PR_TRIGGERS
# Triggers allowed to start a release workflow.
RELEASE_TRIGGERS = {"push", "release", "workflow_dispatch", "workflow_call", "schedule", "repository_dispatch"}
# A workflow_run job whose `if:` admits only runs started by these events (only people with write
# access can cause them) is not outsider-triggerable. It is listed under this name instead.
TRUSTED_WORKFLOW_RUN = "workflow_run (after push, release, dispatch or schedule)"
_TRUSTED_RUN_EVENTS = {"push", "release", "workflow_dispatch", "schedule"}

PERMISSION_SCOPES = {
    "actions", "artifact-metadata", "attestations", "checks", "code-quality", "contents", "deployments",
    "discussions", "id-token", "issues", "models", "packages", "pages", "pull-requests",
    "repository-projects", "security-events", "statuses", "vulnerability-alerts",
}

FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")

# OBAAF's egress action (flagship slice 2c.2), as `owner/repo/path` in lower case.
EGRESS_ACTION = "obaaf/obaaf/actions/egress"
# Standard GitHub-hosted runner labels (ubuntu-latest, ubuntu-24.04-arm, windows-2025, macos-15, ...).
# `\Z`, not `$`, which also matches before a line break at the end (found by the review of 2d.7).
HOSTED_LABEL_RE = re.compile(r"^(ubuntu|windows|macos)-[a-z0-9.-]+\Z")
# A plain value that YAML 1.2's core schema reads as null, true or false, or a number, where this
# reader (YAML 1.1) may keep it as text: `0o0`, `0e0`, `.5`.
_YAML12_SCALAR_RE = re.compile(r"~|null|Null|NULL|true|True|TRUE|false|False|FALSE"
                               r"|[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+"
                               r"|[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
                               r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")
# Step forms that hold no run or uses of their own (background steps, NGA features on GitHub.com).
CONTROL_STEP_KEYS = {"wait", "wait-all", "cancel"}


_LOUD_STATUS_RE = re.compile(r"(always|failure|cancelled)\s*\(", re.I)
_SUCCESS_RE = re.compile(r"success\s*\(", re.I)


def runs_after_failure(cond) -> bool:
    """Whether an `if:` can let a step or job run although an earlier step, or a job it needs,
    failed or was skipped.

    Without a status function GitHub adds an implicit `success() &&`, and the answer is no. The
    answer is yes when `always(`, `failure(` or `cancelled(` appears anywhere in the text, inside a
    string or outside `${{ }}` included: where the text is not what its tokens look like, a status
    function is taken for the worst. `success()` keeps the implicit meaning only when the text is
    one expression and every `success(` in it is a call that is itself one of the conditions joined
    by `&&` at the top (`success() && x`). Anywhere else (`success() || x`, `!success()`,
    `success() == false`, as an argument, inside a string, beside text outside `${{ }}`) the job or
    step is taken to run regardless.
    """
    text = str(cond or "")
    if _LOUD_STATUS_RE.search(text):
        return True
    written = len(_SUCCESS_RE.findall(text))
    if not written:
        return False
    try:
        body = condition_expression(text)
    except (expr_mod.TooComplex, RecursionError):
        return True
    if body is None or body.count("'") % 2:
        return True         # not one expression, or one that ends inside a string
    toks = expr_mod.tokens(body)
    if not _balanced(toks):
        return True
    close = expr_mod._closers(toks)
    lo, hi = _unwrapped(toks, close, 0, len(toks))
    if len(_split(toks, close, lo, hi, "|")) > 1:
        return True
    plain = 0
    for a, b in _split(toks, close, lo, hi, "&"):
        a, b = _unwrapped(toks, close, a, b)
        if b - a == 3 and toks[a][0] == "id" and toks[a][1].lower() == "success" \
                and toks[a + 1:b] == [("op", "("), ("op", ")")]:
            plain += 1
    # Every `success(` the text holds must be one of those calls. One more, in a string or anywhere
    # else, and the condition is not the plain form.
    return plain != written


def _unwrapped(toks: list, close: list, lo: int, hi: int) -> tuple[int, int]:
    """toks[lo:hi] without parentheses that enclose all of it, which change nothing."""
    while hi - lo >= 2 and toks[lo] == ("op", "(") and close[lo] == hi - 1:
        lo, hi = lo + 1, hi - 1
    return lo, hi


# Event fields an outsider can write (OBAAF-GHA-010). Matched inside ${{ }}.
UNTRUSTED_FIELDS = [
    r"github\.event\.(issue|pull_request|discussion)\.(title|body)\b",
    r"github\.event\.(comment|review|review_comment)\.body\b",
    r"github\.event\.pull_request\.head\.(ref|label)\b",
    r"github\.event\.pull_request\.head\.repo\.(name|full_name|description|homepage|default_branch)\b",
    r"github\.event\.(head_commit|commits(\[[^\]]*\]|\.\*)?)\.(message|author\.(name|email)|committer\.(name|email))\b",
    r"github\.event\.workflow_run\.(head_branch|display_title)\b",
    r"github\.event\.workflow_run\.head_commit\.(message|author\.(name|email))\b",
    r"github\.event\.pages(\[[^\]]*\]|\.\*)?\.page_name\b",
    r"github\.head_ref\b",
]
UNTRUSTED_FIELDS_RE = re.compile("|".join(f"(?:{p})" for p in UNTRUSTED_FIELDS))

# The same fields as paths, one accepted set of names per segment (None accepts anything, for an
# array index). Used for the spellings a text pattern cannot follow: `github.event.*.title`,
# `github.event.issue.*`, `github.event[inputs.kind].body` (see expr.reaches).
_TEXT, _WHO, _IDENTITY = {"title", "body"}, {"author", "committer"}, {"name", "email"}
UNTRUSTED_PATHS = [
    ({"github"}, {"event"}, {"issue", "pull_request", "discussion"}, _TEXT),
    ({"github"}, {"event"}, {"comment", "review", "review_comment"}, {"body"}),
    ({"github"}, {"event"}, {"pull_request"}, {"head"}, {"ref", "label"}),
    ({"github"}, {"event"}, {"pull_request"}, {"head"}, {"repo"},
     {"name", "full_name", "description", "homepage", "default_branch"}),
    ({"github"}, {"event"}, {"head_commit"}, {"message"}),
    ({"github"}, {"event"}, {"head_commit"}, _WHO, _IDENTITY),
    ({"github"}, {"event"}, {"commits"}, None, {"message"}),
    ({"github"}, {"event"}, {"commits"}, None, _WHO, _IDENTITY),
    ({"github"}, {"event"}, {"workflow_run"}, {"head_branch", "display_title"}),
    ({"github"}, {"event"}, {"workflow_run"}, {"head_commit"}, {"message"}),
    ({"github"}, {"event"}, {"workflow_run"}, {"head_commit"}, {"author"}, _IDENTITY),
    ({"github"}, {"event"}, {"pages"}, None, {"page_name"}),
    ({"github"}, {"head_ref"}),
]

# A pull request's code (OBAAF-GHA-002, OBAAF-GHA-012), as context references (flagship slice 2d.2c).
# Each is read with the expression reader, so letter case, index syntax, `format`, `join`, `fromJSON` and
# `toJSON` do not hide it, and a value given through `env` is followed to where it is set.
#
# What names the pull request's head commit, branch or repository. Under `head.repo` and
# `head_repository` everything but the few fields below names the fork (its name, owner, clone URLs).
_HEAD_REPO_FLAGS = {"fork", "private", "id", "node_id", "visibility", "archived", "disabled", "is_template"}
# What names a pull request by number (from which `refs/pull/N/head` is built) or its patch.
_PR_NUMBER_PATHS = [
    ("github", "event", "number"), ("github", "event", "pull_request", "number"),
    ("github", "event", "issue", "number"), ("github", "event", "pull_request", "patch_url"),
    ("github", "event", "pull_request", "diff_url"), ("github", "event", "pull_request", "url"),
    ("github", "event", "pull_request", "html_url"),
]
# References that name the base repository's own code, never the pull request's, in the events
# OBAAF-GHA-002 is about: on pull_request_target, workflow_run and the comment and review events,
# `github.sha` and `github.ref` are the base branch's (on pull_request they are the merge commit,
# which OBAAF-GHA-012 treats separately).
BASE_CODE_REFS = frozenset({
    "github.sha", "github.ref", "github.ref_name", "github.base_ref", "github.repository", "github.workflow_sha",
    "github.repository_owner", "github.event.repository.full_name", "github.event.repository.name",
    "github.event.repository.default_branch", "github.event.pull_request.base.sha",
    "github.event.pull_request.base.ref", "github.event.pull_request.base.repo.full_name",
    "github.event.pull_request.base.repo.name", "github.event.pull_request.base.repo.clone_url",
    "github.event.pull_request.base.label", "github.event.repository.owner.login",
    "github.event.repository.clone_url", "github.event.workflow_run.repository.full_name",
    "github.event.workflow_run.repository.default_branch",
})
# The references that are the merge commit when the event is a pull request's own (OBAAF-GHA-012).
MERGE_COMMIT_REFS = frozenset({"github.sha", "github.ref", "github.ref_name"})
# Events whose default checkout, and whose `github.sha` and `github.ref`, are the pull request's
# merge commit (refs/pull/N/merge).
MERGE_REF_EVENTS = frozenset({"pull_request", "pull_request_review", "pull_request_review_comment"})
# Text in a value or a script that names a pull request's code without an expression.
PR_CODE_TEXT_RE = re.compile(
    r"refs/pull/|(?<![\w-])pull/[^\s/'\"]+/(head|merge)\b|/pull/[^\s/'\"]+\.(patch|diff)\b", re.I)
# The same in a script: pull request fields read from the event file, the GitHub CLI or the API, and
# the runner's own variable for the head branch.
PR_CODE_SCRIPT_RE = re.compile(
    r"pull_request\s*\.\s*head\b|pull_request['\"]?\s*\]\s*\[\s*['\"]head|\.head\s*\.\s*(sha|ref)\b|"
    r"\bhead[_.]?(sha|ref)\b|\bheadRef(Oid|Name)\b|\bheadRepository(Owner)?\b|\bGITHUB_HEAD_REF\b|"
    r"\bmerge_commit_sha\b|(?<![\w.-])gh['\"]?\s+pr\s+diff\b", re.I)
# In an `actions/github-script` script, which is read whole: the pull request's number as the API takes it.
_SCRIPT_PR_NUMBER_RE = re.compile(r"\bpull_number\b|context\s*\.\s*issue\s*\.\s*number|"
                                  r"payload\s*\.\s*(pull_request\s*\.\s*)?number", re.I)
# The subcommands of git that bring code into the workspace or read it from a ref.
GIT_CODE_COMMANDS = frozenset({
    "fetch", "pull", "clone", "checkout", "switch", "reset", "worktree", "merge", "rebase", "cherry-pick", "show",
    "apply", "am", "restore", "read-tree", "archive", "submodule", "cat-file",
})
# git's global options that take a value as the next word (`-C DIR`); `--opt=value` is one word.
_GIT_VALUE_OPTIONS = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                                "--config-env", "--exec-path", "--list-cmds", "--attr-source"})
_GH_VALUE_OPTIONS = frozenset({"-R", "--repo", "--hostname"})
# Downloads count when the line fetches an archive, the contents API, raw files or a diff or patch.
_FETCHED_RE = re.compile(r"tarball|zipball|/contents/|codeload\.|raw\.githubusercontent|\.(diff|patch)\b|"
                         r"vnd\.github(\.v3)?\.(diff|patch|raw)|/git/(blobs|trees)|patch_url|diff_url", re.I)
_DOWNLOADERS = frozenset({"curl", "wget", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"})
_SCRIPT_API_RE = re.compile(r"\b(getContent|downloadTarballArchive|downloadZipballArchive|getArchive)\b|"
                            r"format\s*:\s*['\"](diff|patch)['\"]", re.I)
# A command written as an argument list (`['git', 'fetch', ...]`, `exec.exec('git', ['fetch', ...])`), for
# scripts in other languages. The quotes are required, so the pattern cannot backtrack.
_GIT_LIST_RE = re.compile(r"(?<![\w.-])['\"]git(?:\.exe)?['\"]\s*,\s*\[?\s*['\"](" +
                          "|".join(re.escape(c) for c in sorted(GIT_CODE_COMMANDS)) + r")['\"]", re.I)
def _names_pr_code(path: tuple, extracted: bool, numbers: bool) -> bool:
    """Whether a context reference names a pull request's code: its head commit, branch or
    repository, its merge commit, or (with `numbers`) its number or patch. A reference to an object
    that holds one of these counts when something can turn the object into text (`extracted`, a
    wildcard or a computed index); so does a wildcard or computed segment where a name is expected."""
    names = [s.value.lower() if s.kind == expr_mod.NAME else None for s in path]
    loose = extracted or any(n is None for n in names)

    def at(i: int, *accepted: str) -> bool:
        return i < len(names) and (names[i] is None or names[i] in accepted)

    def shorter(i: int) -> bool:          # the reference stops before position i: an object
        return len(names) <= i and loose

    if not at(0, "github"):
        return False
    if len(names) == 1:
        return loose
    if at(1, "head_ref"):
        return True
    if not at(1, "event"):
        return False
    if shorter(2):
        return True
    if at(2, "pull_request"):
        if shorter(3):
            return True
        if at(3, "merge_commit_sha"):
            return True
        if at(3, "head"):
            if shorter(4) or at(4, "sha", "ref", "label", "user"):
                return True
            if at(4, "repo"):
                return shorter(5) or (len(names) > 5 and (names[5] is None or names[5] not in _HEAD_REPO_FLAGS))
            return False
    if at(2, "workflow_run"):
        if shorter(3) or at(3, "head_sha", "head_branch", "head_commit", "pull_requests"):
            return True
        if at(3, "head_repository"):
            return shorter(4) or (len(names) > 4 and (names[4] is None or names[4] not in _HEAD_REPO_FLAGS))
    if at(2, "issue") and (shorter(3) or at(3, "pull_request")):
        return True
    # On a pull request's `synchronize`, `after` is its new head commit; a review and a review comment
    # name the head commit they are about.
    if at(2, "after") or (at(2, "review", "comment") and at(3, "commit_id")):
        return True
    if numbers:
        for wanted in _PR_NUMBER_PATHS:
            if len(names) == len(wanted) and all(n is None or n == w for n, w in zip(names, wanted)):
                return True
    return False


@dataclass
class PrCode:
    """What a value says about a pull request's code: "head" when it names it, "unresolved" when it
    is an expression the checker cannot read to a value (a step's or job's output, an input, a
    variable, an `env` name set nowhere in the file, a reference to anything else), "base" when it
    names only the base repository's code or nothing computed at all. `reads` are the references
    behind the answer (for "base", the base references read)."""

    state: str
    reads: list[str] = field(default_factory=list)


_HEAD, _UNRESOLVED, _BASE = "head", "unresolved", "base"
_NOT_SET = object()


class Env:
    """The env a value can read: mappings from the innermost (a step's) to the outermost (the
    workflow's). A value set in one of them reads only the ones outside it, as GitHub evaluates them,
    so a step's `REF: ${{ env.REF }}` reads the job's REF."""

    def __init__(self, *scopes: Any) -> None:
        self.scopes = [scope if isinstance(scope, dict) else {} for scope in scopes]
        self.names = sorted({str(key) for scope in self.scopes for key in scope})

    def find(self, name: str, start: int = 0, exact: bool = False) -> tuple[Any, int]:
        """The value of `name` in the first scope from `start` that sets it, and that scope's index.
        `${{ env.NAME }}` matches names without regard to case; a shell's `$NAME` (`exact`) does not."""
        wanted = name if exact else name.lower()
        for level in range(start, len(self.scopes)):
            for key, given in self.scopes[level].items():
                if (str(key) if exact else str(key).lower()) == wanted:
                    return given, level
        return _NOT_SET, len(self.scopes)


def env_lookup(*scopes: Any) -> Env:
    return Env(*scopes)


def pr_code(value: Any, env: "Env | None" = None, numbers: bool = True, runtime_only: bool = False,
            start: int = 0, _cache: dict | None = None, _stack: frozenset = frozenset()) -> PrCode:
    """Read a value (a checkout's `ref` or `repository`, or part of a script) for a pull request's
    code. `env` is the env the value can read, from scope `start` outward (None: it cannot read env).
    With `runtime_only` (for scripts, which read many values that name no code), only step and job
    outputs and fields an outsider writes are unresolved, and other references count as nothing.
    Each env name is read once however many values read it, so the time is linear in the env's size."""
    head: set[str] = set()
    unresolved: set[str] = set()
    base: set[str] = set()
    if not isinstance(value, (str, int, float, bool)) and value is not None:
        return PrCode(_UNRESOLVED, ["a value that is not text"])
    text = value if isinstance(value, str) else ""
    if PR_CODE_TEXT_RE.search(text):
        head.add("refs/pull/")
    try:
        bodies = list(expressions(text))
    except expr_mod.TooComplex:
        return PrCode(_UNRESOLVED, ["an expression too complex to read"])
    cache = {} if _cache is None else _cache
    for body in bodies:
        try:
            found = expr_mod.refs(body)
        except (expr_mod.TooComplex, RecursionError):
            unresolved.add("an expression too complex to read")
            continue
        for ref in found:
            shown = expr_mod.dotted(ref.path)
            first = ref.path[0].value.lower() if ref.path[0].kind == expr_mod.NAME else ""
            if _names_pr_code(ref.path, ref.extracted, numbers):
                head.add(shown)
            elif first == "env" and len(ref.path) > 1 and ref.path[1].kind == expr_mod.NAME and env is not None:
                given, level = env.find(ref.path[1].value, start)
                key = (ref.path[1].value.lower(), start)
                if given is _NOT_SET:
                    if not runtime_only:
                        unresolved.add(shown)
                    continue
                if key in _stack:
                    continue                    # a loop: GitHub cannot evaluate it either
                if key not in cache:
                    cache[key] = pr_code(given, env, numbers, runtime_only, level + 1, cache, _stack | {key})
                inner = cache[key]
                target = head if inner.state == _HEAD else unresolved if inner.state == _UNRESOLVED else base
                target.update(inner.reads or [shown])
            elif shown in BASE_CODE_REFS:
                base.add(shown)
            elif runtime_only:
                if first in ("steps", "needs") or any(
                        expr_mod.reaches(ref.path, pattern, ref.extracted) for pattern in UNTRUSTED_PATHS):
                    unresolved.add(shown)
            else:
                unresolved.add(shown)
    if head:
        return PrCode(_HEAD, sorted(head))
    if unresolved:
        return PrCode(_UNRESOLVED, sorted(unresolved))
    return PrCode(_BASE, sorted(base))


def script_lines(text: str, powershell: bool = False) -> list[str]:
    """A script's logical lines: a line ended by a backslash (or, in PowerShell, a backquote) is
    joined to the next."""
    joined = re.sub(r"[\\`][ \t]*\r?\n" if powershell else r"\\[ \t]*\r?\n", " ", text)
    return joined.splitlines()


def _sub_expressions(text: str, replace: "Callable[[str], str]") -> str:
    """`text` with each `${{ ... }}` (to the first `}}`) replaced by `replace(expression)`, in one pass:
    an expression with no end is left as it is."""
    out, pos = [], 0
    while True:
        begin = text.find("${{", pos)
        end = text.find("}}", begin + 3) if begin != -1 else -1
        if end == -1:
            out.append(text[pos:])
            return "".join(out)
        out.append(text[pos:begin])
        out.append(replace(text[begin:end + 2]))
        pos = end + 2


_PLACEHOLDER_RE = re.compile(r"\x00(\d+)\x00")
_SEPARATORS = frozenset({";", "&&", "||", "&", ";;", "\n"})
# How a script reads a variable: `$NAME`, `${NAME...}`, PowerShell's `$env:NAME`, cmd's `%NAME%`,
# Node's `process.env.NAME`, Python's `os.environ['NAME']`, `os.environ.get('NAME')`, `getenv('NAME')`.
_VARIABLE_RE = re.compile(
    r"\$\{?#?!?([A-Za-z_]\w*)|\$env:([A-Za-z_]\w*)|%([A-Za-z_]\w*)%|process\.env\.([A-Za-z_]\w*)|"
    r"os\.environ(?:\.get)?\s*[\[(]\s*['\"]([A-Za-z_]\w*)|getenv\s*\(\s*['\"]([A-Za-z_]\w*)", re.I)
# Where a script sets a variable: `NAME=...` at the start of a command (after `export`, `local`,
# `declare -x` and the like, or `const` and `let` in a script language), `read [-r] NAME`, `for NAME in`,
# `mapfile NAME`.
_ASSIGN_RE = re.compile(
    r"(?:^|[;&|({]\s*|\b(?:export|local|readonly|typeset|declare|const|let|var|set)\s+(?:-\w+\s+)*)"
    r"\$?([A-Za-z_]\w*)(?:\[[^\]]*\])?\s*:?\+?=\s*")
_READ_RE = re.compile(r"\b(?:read|mapfile|readarray)\s+(?:-\w+\s+(?:[^\s-]\S*\s+)?)*([A-Za-z_]\w*)|\bfor\s+([A-Za-z_]\w*)\s+in\b")
# A file a line writes: `> FILE`, `>> FILE`, `-o FILE`, `--output FILE`, `tee FILE`, `-OutFile FILE`.
_WRITES_RE = re.compile(r"(?:>>?|(?<![\w-])-o|--output(?:=|\s)|\btee(?:\s+-a)?|-OutFile)\s*['\"]?([^\s'\";&|<>]+)", re.I)


def _shell_words(line: str) -> list[str] | None:
    """A line split as a POSIX shell splits it, with each `${{ }}` kept as one word (as a
    placeholder), operators as words of their own, and a word that begins with `#` ending the command.
    None when the line cannot be split (an unclosed quote)."""
    try:
        lex = shlex.shlex(line, posix=True, punctuation_chars=";&|()<>")
        lex.whitespace_split = True
        lex.commenters = ""
        return list(lex)
    except ValueError:
        return None


def _commands(words: list[str]) -> list[list[str]]:
    """The commands of a split line: runs of words between `;`, `&&`, `||` and `&`. A pipeline stays
    one command, so `gh pr diff N | git apply` is read together. A word that begins with `#` ends the
    command and the line."""
    out, current = [], []
    for word in words:
        if word.startswith("#"):
            break
        if word in _SEPARATORS:
            if current:
                out.append(current)
            current = []
        else:
            current.append(word)
    if current:
        out.append(current)
    return out


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower()


_CREATE_FLAGS = frozenset({"-c", "-C", "-b", "-B", "--create", "--force-create", "--orphan"})


def _fetching(words: list[str]) -> tuple[str | None, set[int]]:
    """What brings code in among a command's words, if anything ("git SUBCOMMAND", "gh pr checkout",
    which needs nothing else to be the pull request's code, "patch", "gh repo clone", "gh api", or a
    downloader), and the words not to read for what it brings in: the name of a branch that `git
    switch -c NAME` or `git checkout -b NAME` creates, which names nothing fetched."""
    found, skip = None, set()
    for i, word in enumerate(words):
        name = _base(word)
        if name in ("git", "git.exe"):
            j = i + 1
            while j < len(words) and words[j].startswith("-"):
                j += 2 if words[j] in _GIT_VALUE_OPTIONS else 1
            if j < len(words) and words[j].lower() in GIT_CODE_COMMANDS:
                sub = words[j].lower()
                if sub in ("switch", "checkout"):
                    rest = range(j + 1, len(words))
                    created = {k + 1 for k in rest if words[k] in _CREATE_FLAGS and k + 1 < len(words)}
                    if created:
                        skip |= created
                        starts = [k for k in rest if k not in skip and not words[k].startswith("-")
                                  and words[k] not in ("|", "<", ">", "(", ")")]
                        if not starts:
                            continue        # a new branch at the current commit brings nothing in
                return f"git {sub}", skip
        elif name in ("gh", "gh.exe"):
            subs, j = [], i + 1
            while j < len(words) and len(subs) < 2 and words[j] not in ("|", "(", ")", "<", ">"):
                if words[j].startswith("-"):
                    j += 2 if words[j] in _GH_VALUE_OPTIONS else 1
                    continue
                subs.append(words[j].lower())
                j += 1
            if subs[:1] == ["pr"] and subs[1:2] in (["checkout"], ["co"]):
                return "gh pr checkout", skip
            if subs == ["repo", "clone"]:
                found = found or "gh repo clone"
            if subs[:1] == ["api"]:
                found = found or "gh api"
        elif name == "patch":
            return "patch", skip
        elif name in _DOWNLOADERS:
            found = found or name
    return found, skip


def pr_fetch(step: "Step", env: "Env") -> PrCode:
    """Whether a step's scripts bring a pull request's code into the workspace.

    "head": a command that brings code in (git with a subcommand in GIT_CODE_COMMANDS, after any
    global options; `gh repo clone`; `gh api`, curl or wget of an archive, contents or a diff;
    `patch`; the github-script calls for those) together with something that names the pull
    request's code in the same command (a pipeline counts as one): an expression or env value that
    names it, a field read from the event file or the GitHub CLI, `gh pr diff`, `refs/pull/...`,
    the pull request's number, a variable set earlier in the step from any of these, or a file an
    earlier command wrote from any of these. `gh pr checkout` needs nothing more. "unresolved": such
    a command with a step's or job's output, or a field an outsider writes, instead. Values passed
    from other steps (GITHUB_ENV, files) are not followed."""
    text = step.scripts()
    if not text:
        return PrCode(_BASE)
    shell = as_text(step.raw.get("shell") or "").lower()
    head: set[str] = set()
    unresolved: set[str] = set()
    tainted: dict[str, PrCode] = {}
    files: dict[str, PrCode] = {}
    cache: dict = {}

    def read(fragment: str) -> PrCode:
        hits, open_ = set(), set()
        found = pr_code(fragment, env, numbers=True, runtime_only=True, _cache=cache)
        (hits if found.state == _HEAD else open_ if found.state == _UNRESOLVED else set()).update(found.reads)
        marker = PR_CODE_SCRIPT_RE.search(fragment)
        if marker:
            hits.add(one_line(marker.group(0), 60))
        for match in _VARIABLE_RE.finditer(fragment):
            name = next(g for g in match.groups() if g)
            exact = match.group(1) is not None or match.group(4) is not None
            inner = tainted.get(name)
            if inner is None:
                given, level = env.find(name, 0, exact=exact)
                if given is _NOT_SET:
                    continue
                key = ("$" + (name if exact else name.lower()), 0)
                if key not in cache:
                    cache[key] = pr_code(given, env, numbers=True, runtime_only=True, start=level + 1, _cache=cache)
                inner = cache[key]
            (hits if inner.state == _HEAD else open_ if inner.state == _UNRESOLVED else set()).update(inner.reads)
        for name, inner in files.items():
            if re.search(rf"(?<![\w.-]){re.escape(name)}(?![\w.-])", fragment):
                (hits if inner.state == _HEAD else open_ if inner.state == _UNRESOLVED else set()).update(inner.reads)
        if hits:
            return PrCode(_HEAD, sorted(hits))
        return PrCode(_UNRESOLVED, sorted(open_)) if open_ else PrCode(_BASE)

    def note(found: PrCode) -> None:
        if found.state == _HEAD:
            head.update(found.reads)
        elif found.state == _UNRESOLVED:
            unresolved.update(found.reads)

    script = as_text(step.with_.get("script") or "") if (step.action or "").lower().startswith(
        "actions/github-script") else ""
    api = _SCRIPT_API_RE.search(script) if script else None
    if script and (api or _GIT_LIST_RE.search(script)):
        # A github-script script is read whole, because a call is written over several lines: a REST
        # call or an exec of git, and anything in the script that names the pull request's code. The
        # pull request's number counts for a diff, a patch or git, not for reading contents or an
        # archive, which without a ref read the default branch.
        found = read(script)
        number = _SCRIPT_PR_NUMBER_RE.search(script)
        if found.state == _HEAD:
            note(found)
        elif number and (_GIT_LIST_RE.search(script) or (api and api.group(2))):
            head.add(one_line(number.group(0), 60))
        else:
            note(found)

    queue = [(line, 0) for line in script_lines(text, powershell="pwsh" in shell or "powershell" in shell)]
    while queue:
        line, depth = queue.pop(0)
        placeholders: list[str] = []

        def hold(expression: str) -> str:
            placeholders.append(expression)
            return f"\x00{len(placeholders) - 1}\x00"

        held = _sub_expressions(line, hold)
        words = _shell_words(held)
        if words is None:
            # A line the shell reader cannot split (an unclosed quote: a here-document, a string that goes
            # on to the next line) is split roughly: quotes are dropped and operators set apart.
            rough = _sub_expressions(line, lambda expression: re.sub(r"\s", "", expression))
            rough = re.sub(r"(&&|\|\||[;&|()<>])", r" \1 ", re.sub(r"[\"'`]", " ", rough))
            tools = [found[0] for found in (_fetching(command) for command in _commands(rough.split())) if found[0]]
            commands = [(line, "gh pr checkout" if "gh pr checkout" in tools else tools[0] if tools else None)]
        else:
            commands = []
            for command in _commands(words):
                tool, skip = _fetching(command)
                piece = _PLACEHOLDER_RE.sub(lambda m: placeholders[int(m.group(1))],
                                            " ".join(word for k, word in enumerate(command) if k not in skip))
                commands.append((piece, tool))
                # A quoted word with spaces may be a script of its own (`sh -c "git fetch ..."`, `eval`).
                if depth < 2:
                    queue[0:0] = [(_PLACEHOLDER_RE.sub(lambda m: placeholders[int(m.group(1))], word), depth + 1)
                                  for word in command if any(c.isspace() for c in word)]
        if not any(tool for _, tool in commands) and (_GIT_LIST_RE.search(line) or _SCRIPT_API_RE.search(line)):
            commands.append((line, "script"))       # an argument list or a REST call, in a script language
        for piece, tool in commands:
            if tool == "gh pr checkout":
                head.add("gh pr checkout")
            elif tool in _DOWNLOADERS or tool == "gh api":
                # A download brings code in when it fetches an archive, contents or a diff: written in the
                # line, or read from the pull request's patch or diff address.
                found = read(piece)
                if _FETCHED_RE.search(piece) or any(_FETCHED_RE.search(r) for r in found.reads):
                    note(found)
            elif tool:
                note(read(piece))
            # What this command sets or writes, for the commands after it.
            assigned = [m.group(1) for m in _ASSIGN_RE.finditer(piece)] + \
                       [a or b for a, b in _READ_RE.findall(piece)]
            written = [name for name in _WRITES_RE.findall(piece) if not name.startswith("/dev/")]
            if assigned or written:
                found = read(piece)
                if found.state != _BASE:
                    for name in assigned:
                        tainted[name] = found
                    for name in written:
                        files[name] = found
    if head:
        return PrCode(_HEAD, sorted(head))
    if unresolved:
        return PrCode(_UNRESOLVED, sorted(unresolved))
    return PrCode(_BASE)


def _balanced(toks: list) -> bool:
    """Whether every parenthesis and bracket is closed by its own kind, in order. GitHub refuses an
    expression where they are not, so nothing is concluded from one."""
    stack: list[str] = []
    for kind, text in toks:
        if kind != "op":
            continue
        if text in "([":
            stack.append(text)
        elif text in ")]":
            if not stack or stack.pop() != ("(" if text == ")" else "["):
                return False
    return not stack


def _split(toks: list, close: list, lo: int, hi: int, op: str) -> list[tuple[int, int]]:
    """The parts of toks[lo:hi] between each `||` or `&&` (`op` is `|` or `&`) that is not inside
    parentheses or brackets."""
    parts, start, i = [], lo, lo
    while i < hi:
        token = toks[i]
        if token in (("op", "("), ("op", "[")):
            i = min(close[i], hi) + 1
        elif token == ("op", op) and i + 1 < hi and toks[i + 1] == ("op", op):
            parts.append((start, i))
            start = i = i + 2
        else:
            i += 1
    parts.append((start, hi))
    return parts


def _plain_path(toks: list, lo: int, hi: int) -> tuple | None:
    """The names of a context reference that is all of toks[lo:hi] (`github.event_name`,
    `github['event_name']`), in lower case; None for anything else."""
    if lo >= hi or toks[lo][0] != "id":
        return None
    names, i = [toks[lo][1]], lo + 1
    while i < hi:
        if toks[i] == ("op", ".") and i + 1 < hi and toks[i + 1][0] == "id":
            names.append(toks[i + 1][1])
            i += 2
        elif toks[i] == ("op", "[") and i + 2 < hi and toks[i + 1][0] == "str" and toks[i + 2] == ("op", "]"):
            names.append(toks[i + 1][1])
            i += 3
        else:
            return None
    if not all(name.isascii() for name in names):
        return None
    return tuple(name.lower() for name in names)


def _event_test(toks: list, lo: int, hi: int) -> tuple[tuple, bool, str] | None:
    """(path, equal, value) when toks[lo:hi] is exactly one comparison of a context reference with a
    string, `==` or `!=`, either way round. GitHub compares strings without regard to case, so the
    value is returned in lower case; a value with a letter outside ASCII is not read, because what
    GitHub's comparison makes of it has not been established."""
    if hi - lo < 4:
        return None
    if toks[hi - 1][0] == "str" and toks[hi - 2] == ("op", "=") and toks[hi - 3] in (("op", "="), ("op", "!")):
        path, operator, value = _plain_path(toks, lo, hi - 3), toks[hi - 3][1], toks[hi - 1][1]
    elif toks[lo][0] == "str" and toks[lo + 1] in (("op", "="), ("op", "!")) and toks[lo + 2] == ("op", "="):
        path, operator, value = _plain_path(toks, lo + 3, hi), toks[lo + 1][1], toks[lo][1]
    else:
        return None
    if path is None or not value.isascii():
        return None
    return path, operator == "=", value.lower()


_EVENT_NAME = ("github", "event_name")
_RUN_EVENT = ("github", "event", "workflow_run", "event")
_MAX_CONDITION_DEPTH = 200


def _admitted(toks: list, close: list, lo: int, hi: int, events: frozenset, depth: int = 0) -> frozenset:
    """The events, out of `events`, on which the condition toks[lo:hi] can be true.

    It is read as GitHub evaluates it: `||` binds loosest, then `&&`, then a comparison. Only a
    part that is exactly `github.event_name == '<event>'` (or `!=`), or
    `github.event.workflow_run.event == '<event>'`, rules an event out. Any other part (a function,
    a negation, a comparison of a comparison, text inside a string) is taken to be true on every
    event, so the answer can name an event the job never runs on and cannot leave out one it does.
    """
    if depth > _MAX_CONDITION_DEPTH:
        return events
    parts = _split(toks, close, lo, hi, "|")
    if len(parts) > 1:
        out: frozenset = frozenset()
        for a, b in parts:
            out |= _admitted(toks, close, a, b, events, depth + 1)
        return out
    parts = _split(toks, close, lo, hi, "&")
    if len(parts) > 1:
        out = events
        for a, b in parts:
            out &= _admitted(toks, close, a, b, events, depth + 1)
        return out
    if hi - lo >= 2 and toks[lo] == ("op", "(") and close[lo] == hi - 1:
        return _admitted(toks, close, lo + 1, hi - 1, events, depth + 1)
    test = _event_test(toks, lo, hi)
    if test is None:
        return events
    path, equal, value = test
    if path == _EVENT_NAME:
        named = {"workflow_run", TRUSTED_WORKFLOW_RUN} if value == "workflow_run" else {value}
        # In a workflow another workflow calls, `github.event_name` is the caller's event, which the
        # checker does not know, so no test of it rules `workflow_call` out.
        called = events & {"workflow_call"}
        return (events & named if equal else events - named) | called
    if path == _RUN_EVENT and equal:
        # True only for a run that followed a run started by `value`. Other events are left in:
        # the test is false on them, and leaving them in can only add findings.
        return events - {"workflow_run" if value in _TRUSTED_RUN_EVENTS else TRUSTED_WORKFLOW_RUN}
    return events


def condition_expression(cond: str) -> str | None:
    """The expression an `if:` holds, or None when GitHub does not evaluate the text as one
    expression. Without `${{` the whole text is the expression. With it, the text must be exactly one
    `${{ ... }}`: anything outside it, even a space or the line break a block scalar adds, makes the
    value a string, and a string that is not empty counts as true whatever it says."""
    if expr_mod.OPEN not in cond:
        return cond
    if not (cond.startswith(expr_mod.OPEN) and cond.endswith(expr_mod.CLOSE)):
        return None
    body = cond[len(expr_mod.OPEN):-len(expr_mod.CLOSE)]
    return body if expr_mod.bodies(cond)[0] == body else None


@lru_cache(maxsize=4096)
def _narrowed(cond: str, events: frozenset) -> frozenset:
    try:
        body = condition_expression(cond)
        if body is None or body.count("'") % 2:
            return events       # not one expression, or one that ends inside a string
        toks = expr_mod.tokens(body)
        if not _balanced(toks):
            return events
        atoms = events | ({TRUSTED_WORKFLOW_RUN} if "workflow_run" in events else frozenset())
        out = _admitted(toks, expr_mod._closers(toks), 0, len(toks), atoms)
    except (expr_mod.TooComplex, RecursionError):
        return events
    # A run that follows another run is one event with two origins. When both can start the job it
    # is listed as `workflow_run`, the wider of the two.
    return out - {TRUSTED_WORKFLOW_RUN} if "workflow_run" in out else out


def _narrow(events: set[str], cond: str) -> set[str]:
    """Narrow a job's possible triggers by the tests on the event in its `if:`. The condition is
    read from its tokens (see `_admitted`), never by searching its text, so words inside a string, a
    comparison of a comparison, or text outside `${{ }}` cannot make an event disappear."""
    return set(_narrowed(cond, frozenset(events)))


def expressions(value: Any, _seen: set | None = None) -> Iterator[str]:
    """Yield the body of every ${{ }} expression found anywhere in a value (see expr.bodies).

    A mapping or list reached again through a YAML alias is read once: its expressions were already
    yielded, and a file of nested aliases would otherwise take time exponential in its size.
    """
    if isinstance(value, str):
        yield from expr_mod.bodies(value)
    elif isinstance(value, (dict, list)):
        if _seen is None:
            _seen = set()
        if id(value) in _seen:
            return
        _seen.add(id(value))
        if isinstance(value, dict):
            for k, v in value.items():
                yield from expressions(k, _seen)
                yield from expressions(v, _seen)
        else:
            for v in value:
                yield from expressions(v, _seen)


def secret_names(value: Any) -> set[str]:
    """Names of secrets referenced in a value; '*' means every secret: toJSON(secrets), secrets.*,
    a computed index, or any other use of the secrets context that is not one literal name."""
    names: set[str] = set()
    for body in expressions(value):
        names |= expr_mod.secret_refs(body)
    return {n for n in names if n.upper() != "GITHUB_TOKEN"}


@dataclass
class Permissions:
    """Effective token permissions. `declared` is False when the default applies."""

    declared: bool
    mode: str = "map"            # "map", "read-all" or "write-all"
    scopes: dict = field(default_factory=dict)

    @classmethod
    def parse(cls, raw: Any) -> "Permissions | None":
        """The permissions written in a workflow, read the widest way where the text is not one of the
        forms GitHub documents: a string other than `read-all` or `write-all`, or a value of the
        wrong kind, counts as `write-all`, and a scope at any level other than `read` or `none`
        counts as `write`. Such text is also a problem of the file (`permissions_problem`), which
        fails the check; reading it widely keeps any rule that runs from passing it. `None` (the key
        written with no value) is handled by the caller as not declared."""
        if raw is None:
            return None
        if isinstance(raw, str):
            if raw in ("read-all", "write-all"):
                return cls(declared=True, mode=raw)
            return cls(declared=True, mode="write-all")
        if isinstance(raw, dict):
            scopes: dict = {}
            for key, value in raw.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    return cls(declared=True, mode="write-all")
                scopes[key] = value if value in ("read", "none") else "write"
            return cls(declared=True, mode="map", scopes=scopes)
        return cls(declared=True, mode="write-all")

    def level(self, scope: str) -> str:
        """The level of one scope. A scope written in another case, or with spaces round it, counts
        as that scope, so `ID-TOKEN: write` is `id-token` to OBAAF-GHA-004 as it is a write scope to
        OBAAF-GHA-003 (and a problem of the file either way)."""
        if self.mode == "write-all":
            return "write"
        if self.mode == "read-all":
            return "none" if scope == "id-token" else "read"
        levels = [v for k, v in self.scopes.items() if k.strip().translate(_ASCII_LOWER) == scope]
        return max(levels, key=_LEVEL_RANK.__getitem__, default="none")

    def write_scopes(self) -> list[str]:
        if self.mode == "write-all":
            return ["write-all"]
        return sorted(s for s, v in self.scopes.items() if v == "write"
                      and s.strip().translate(_ASCII_LOWER) != "id-token")

    @property
    def oidc(self) -> bool:
        return self.level("id-token") == "write"


_NUMBER_OR_BOOLEAN = re.compile(r"[-+]?(\.?[0-9][0-9a-zA-Z_.:+-]*|\.(inf|nan))|true|false|yes|no|on|off|null|~",
                                re.IGNORECASE)


def _spellings(source: str, value) -> set[str]:
    """The names a plain value written as `source` may be to one YAML reader or another: the text
    as written, and the number or true or false each reading makes of it, in decimal."""
    out = {source.strip().lower(), as_text(value).lower()}
    text = source.strip().lower()
    if len(text) > 100:
        return out
    readings = []
    for read in (lambda t: int(t, 10), lambda t: int(t, 0), lambda t: int(t.replace("_", ""), 0),
                 lambda t: int(t, 8) if re.fullmatch(r"[-+]?0[0-7]+", t) else None, float):
        try:
            readings.append(read(text))
        except (ValueError, OverflowError):
            pass
    for number in readings:
        if number is None:
            continue
        out.add(str(number).lower())
        if isinstance(number, float) and number.is_integer():
            out.add(str(int(number)))
    if text in ("true", "false"):
        out.add(text)
    return out


def scalar_environment_match(value, wanted: str | None, source: str | None = None) -> str:
    """Whether an environment written as a plain number or true or false (`environment: 010`), or
    as text another reader takes for one (`0o10`), can be the one a protected_secrets entry names.
    YAML readers do not agree on what such a value is, so "unsure" where the wanted name is one of
    the names it may be (`010` may be 8, 10 or "010"), else "differs". Where the text as written
    could not be found, "unsure" for any wanted name that looks like a number or true or false."""
    if wanted is None:
        return "unsure"
    if source is None:
        return "unsure" if _NUMBER_OR_BOOLEAN.fullmatch(wanted.strip()) else "differs"
    return "unsure" if wanted.strip().lower() in _spellings(source, value) else "differs"


def environment_match(declared: str, wanted: str | None) -> str:
    """Whether an environment named as text is the one a protected_secrets entry names: "same" for
    the same name, or the same name in another case where both are ASCII (GitHub's environment
    names do not differ by case); "unsure" where they differ only in the case of other letters,
    which Python folds and GitHub may not; "differs" otherwise. A `wanted` of None is any
    environment."""
    if wanted is None or declared == wanted:
        return "same"
    if declared.isascii() and wanted.isascii():
        return "same" if declared.lower() == wanted.lower() else "differs"
    return "unsure" if declared.casefold() == wanted.casefold() else "differs"


_LEVEL_RANK = {"none": 0, "read": 1, "write": 2}
_EVENT_SPELLING = re.compile(r"[a-z][a-z_]*\Z")
_SCOPE_NAME = re.compile(r"[a-z][a-z-]*\Z")


def permissions_problem(raw: Any, where: str) -> str | None:
    """What makes a `permissions` value one the checker cannot tell the meaning of, if anything.
    GitHub documents `read-all`, `write-all`, `{}`, and a mapping of scope names (lower-case letters
    and hyphens) to `read`, `write` or `none`. Anything else (another case, spaces in a quoted
    value, an expression, a number) may not be read as GitHub would read it, whatever that is; it
    is a problem of the file, so the check fails rather than pass a token it may have misread. A
    scope name written in lower-case letters and hyphens that GitHub does not know is read as
    written: GitHub adds scopes, and a list here would fail every file that uses a new one."""
    if raw is None:
        return None
    if isinstance(raw, str):
        if raw in ("read-all", "write-all"):
            return None
        return (f"{where} has permissions written as {shown_value(raw)}, which is not read-all, write-all or a "
                "mapping of scopes, so the checker cannot tell what the token may do")
    if isinstance(raw, dict):
        for key, value in raw.items():
            if not isinstance(key, str) or not _SCOPE_NAME.match(key):
                return (f"{where} names a permission scope as {shown_value(key)}; GitHub's scopes are written in "
                        "lower-case letters and hyphens, so the checker cannot tell which scope it is")
            if not isinstance(value, str) or value not in ("read", "write", "none"):
                return (f"{where} gives permission scope '{key}' the level {shown_value(value)}, which is not read, "
                        "write or none, so the checker cannot tell what the token may do")
        return None
    return (f"{where} has permissions that are neither text nor a mapping ({shown_value(raw)}), so the checker "
            "cannot tell what the token may do")


@dataclass
class Step:
    index: int
    raw: dict
    line: int
    group: int | None = None      # parallel group it belongs to, if any
    background: bool = False      # runs concurrently with later steps (background: true or parallel)

    @property
    def name(self) -> str:
        return as_text(self.raw.get("name") or self.raw.get("id") or self.uses or f"step {self.index + 1}")

    @property
    def uses(self) -> str | None:
        value = self.raw.get("uses")
        return str(value) if value is not None else None

    @property
    def run(self) -> str:
        value = self.raw.get("run")
        return str(value) if value is not None else ""

    @property
    def with_(self) -> dict:
        """The step's inputs, by name with ASCII letters in lower case. GitHub hands an action its
        inputs as environment variables named in upper case, so `REF:` and `ref:` are the same
        input. Only A to Z are folded: what GitHub's upper-casing makes of any other letter is not
        established, so a name with one is left as written and reported as a problem when the file
        is read. So are two names that are the same input. Here the values of such a pair are
        joined, which lets a rule that searches a value see both and can make a rule that compares
        the whole value miss; the problem, which fails the check, is what covers that."""
        value = self.raw.get("with")
        if not isinstance(value, dict):
            return {}
        out: dict = {}
        for name, given in value.items():
            key = input_name(name)
            out[key] = f"{out[key]} {given}" if key in out else given
        return out

    @property
    def env(self) -> dict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else {}

    @property
    def action(self) -> str | None:
        """'owner/repo[/path]' for a remote action, without the ref."""
        if not self.uses or self.uses.startswith(("./", "docker://")):
            return None
        return self.uses.split("@", 1)[0]

    def uses_action(self, prefix: str) -> bool:
        action = self.action
        if not action:
            return False
        return action.lower() == prefix.lower() or action.lower().startswith(prefix.lower() + "/")

    def text(self) -> str:
        """The run script plus a github-script script, for pattern matching."""
        parts = [self.run]
        if self.action and self.action.lower().startswith("actions/github-script"):
            parts.append(str(self.with_.get("script", "")))
        return "\n".join(p for p in parts if p)

    @property
    def confines(self) -> bool:
        """Whether the step uses OBAAF's egress action from OBAAF's repository, which runs its `run`
        input as a command with the network limited. A local copy (`./actions/egress`) is any
        repository's own action and is not taken for it."""
        return (self.action or "").lower() == EGRESS_ACTION

    def scripts(self) -> str:
        """Everything a step runs as a command line: `agent_text()` (the run script, a github-script
        script and the command OBAAF's egress action runs) and a `docker://` step's `entrypoint` and
        `args`, which GitHub hands to the container as its command."""
        parts = [self.agent_text()]
        if self.uses and self.uses.strip().lower().startswith("docker://"):
            for key in ("entrypoint", "args"):
                given = self.with_.get(key)
                if isinstance(given, str):
                    parts.append(given)
        return "\n".join(p for p in parts if p)

    def agent_text(self) -> str:
        """What an agent CLI is looked for in: `text()`, and the command OBAAF's egress action runs,
        which is an agent's command line like any other."""
        parts = [self.text()]
        if self.confines:
            given = self.with_.get("run")
            parts.append(given if isinstance(given, str) else "")
        return "\n".join(p for p in parts if p)


@dataclass
class Job:
    id: str
    raw: dict
    line: int
    workflow: "Workflow"
    steps: list[Step] = field(default_factory=list)
    lane: str = "trusted"
    lane_reason: str = ""
    # Every lane the job is in, and why. The rules ask `in_lane`; `lane` and `lane_reason` are what
    # is shown for the job.
    lanes: dict = field(default_factory=dict)
    lane_notes: list = field(default_factory=list)
    # Indexes of the steps that run a repository script in which an agent CLI was found.
    agent_script_steps: set = field(default_factory=set)
    _secret_names: frozenset | None = field(default=None, repr=False, compare=False)

    def in_lane(self, lane: str) -> bool:
        return lane in self.lanes if self.lanes else self.lane == lane

    def reason_for(self, lane: str) -> str:
        """Why the job is in `lane`, as a finding quotes it."""
        if lane not in self.lanes:
            return self.lane_reason
        notes = self.lane_notes if lane == self.lane else []
        return "; ".join([self.lanes[lane], *notes])

    def add_lane(self, lane: str, reason: str) -> None:
        """Put the job in one more lane. A job never leaves a lane."""
        if lane in LANE_ORDER:
            self.lanes[lane] = reason
        self.settle_lane()

    def settle_lane(self, default_reason: str = "default") -> None:
        present = [lane for lane in LANE_ORDER if lane in self.lanes]
        if not present:
            self.lane, self.lane_reason = "trusted", "; ".join([default_reason, *self.lane_notes])
            return
        self.lane = present[0]
        also = [f"also {lane}: {self.lanes[lane]}" for lane in present[1:]]
        self.lane_reason = "; ".join([self.lanes[self.lane], *also, *self.lane_notes])

    @property
    def name(self) -> str:
        return as_text(self.raw.get("name") or self.id)

    @property
    def env(self) -> dict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else {}

    @property
    def permissions(self) -> Permissions | None:
        """The job's token permissions: its own `permissions`, else the workflow's, else None (the
        default, or a calling workflow's). `permissions:` written with no value is taken as not
        written, the wider of the two readings: what GitHub makes of it is not established, and
        reading it as `{}` would hide a workflow-level `write-all`."""
        if self.raw.get("permissions") is not None:
            return Permissions.parse(self.raw.get("permissions"))
        return self.workflow.permissions

    @property
    def environment_reading(self) -> tuple[str, Any]:
        """How the job's environment is written: ("none", None) when it declares none, or a name
        that is blank or missing (most likely no environment to GitHub, which is the full risk);
        ("literal", name) for a name written as text; ("expression", text) for a name with an
        expression in it; ("scalar", value) for a number or true or false, whose text this reader
        and GitHub's may not agree on (`010`); ("unreadable", value) for a list or a mapping."""
        written = self.raw.get("environment")
        if isinstance(written, dict):
            written = written.get("name")
        if written is None or (isinstance(written, str) and not written.strip()):
            return ("none", None)
        if isinstance(written, str):
            if "${{" in written:
                return ("expression", written)
            # Text this reader keeps as text that another reads as a number or true or false
            # (`0o10`, `1e3`) is a scalar too, unless it was quoted.
            source = self.environment_source()
            if source is not None and source[1] is None and _YAML12_SCALAR_RE.fullmatch(written):
                return ("scalar", written)
            return ("literal", written)
        if isinstance(written, (bool, int, float)):
            return ("scalar", written)
        return ("unreadable", written)

    def environment_source(self) -> tuple[str, str | None] | None:
        """The text of the job's environment name as written in the file, and its quoting style
        (None for a plain value), read from the composed YAML; None where it cannot be found (a
        merge key, a job reached another way)."""
        return self.workflow.environment_sources().get(self.id)

    @property
    def environment(self) -> str | None:
        env = self.raw.get("environment")
        if isinstance(env, dict):
            return as_text(env.get("name") or "") or None
        return as_text(env) if env else None

    @property
    def cache_mode(self) -> str | None:
        value = self.raw.get("cache-mode", self.workflow.raw.get("cache-mode"))
        return str(value) if value is not None else None

    @property
    def runs_on(self) -> list[str]:
        value = self.raw.get("runs-on")
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        if isinstance(value, dict):
            labels = value.get("labels")
            out = ["group:" + str(value.get("group"))] if value.get("group") else []
            if isinstance(labels, str):
                out.append(labels)
            elif isinstance(labels, list):
                out += [str(v) for v in labels]
            return out
        return []

    @property
    def self_hosted(self) -> bool:
        labels = [label.lower() for label in self.runs_on]
        return any(label == "self-hosted" or label.startswith("group:") for label in labels)

    def runner_label_sets(self) -> list[list[str]] | None:
        """Each set of labels the job can run on, with `${{ matrix.x }}` and `${{ matrix.x || 'label' }}`
        resolved from a matrix written out in the file; None when a label comes from an expression that
        cannot be resolved.

        The expression is read from its tokens (flagship slice 2d.7, issue #141). For `matrix.x ||
        'label'` the default is one of the labels wherever a row may lack `x` or give it a value that
        is false to GitHub (an empty text): unless `x` is a key of the matrix with a list of values and
        every `include` entry sets it, a row may lack it, because an `include` entry that cannot be added
        to any combination makes a row of its own. So the sets can be more than the job runs on, never
        fewer. The values of `x` computed when the job runs, an `include` or an `include` entry computed
        when the job runs, a key written in another case (GitHub compares property names without
        regard to case), a key that is not plain ASCII text with no expression, a value YAML 1.2 could
        read as other than text, a YAML merge key (`<<`) anywhere in the file, or any other expression
        leaves the labels unresolved."""
        labels = self.runs_on
        expr = [label for label in labels if "${{" in label]
        if not expr:
            return [labels] if labels else None
        if len(labels) != 1:
            return None
        text = labels[0].strip()
        if not (text.startswith(expr_mod.OPEN) and text.endswith("}}")):
            return None
        found = expr_mod.bodies(text)
        if len(found) != 1 or len(expr_mod.OPEN) + len(found[0]) + 2 != len(text):
            return None
        body = found[0]
        toks = expr_mod.tokens(body)
        if len(toks) < 3 or toks[0] != ("id", "matrix") or toks[1] != ("op", ".") or toks[2][0] != "id":
            return None
        name, rest = toks[2][1], toks[3:]
        default = None
        if rest:
            # `|| 'label'`, and nothing else: the two bars written together, a closed string after them.
            if (len(rest) != 3 or rest[:2] != [("op", "|"), ("op", "|")] or rest[2][0] != "str"
                    or "||" not in body or not body.rstrip().endswith("'")):
                return None
            default = rest[2][1]
        if self.workflow.has_merge_key:
            return None         # a matrix read two ways (found by the second review of 2d.7)
        strategy = self.raw.get("strategy")
        matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
        if not isinstance(matrix, dict):
            return None
        include = matrix.get("include", [])
        if not isinstance(include, list) or not all(isinstance(entry, dict) for entry in include):
            return None
        # Every key must be plain ASCII text with no expression, so that the checker's comparison is
        # GitHub's: a key YAML reads as true or a number, one computed when the job runs, or one with a
        # letter outside ASCII (whose case GitHub may fold otherwise) leaves the labels unresolved
        # (found by the review of 2d.7).
        keys = list(matrix) + [key for entry in include for key in entry]
        if not name.isascii() or any(not isinstance(key, str) or not key.isascii() or expr_mod.OPEN in key
                                     for key in keys):
            return None
        if any(key != name and key.lower() == name.lower() for key in keys):
            return None
        if name in matrix and not isinstance(matrix[name], list):
            return None
        values = list(matrix.get(name) or [])
        extra = [entry[name] for entry in include if name in entry]
        if not values and not extra and default is None:
            return None
        out: list[list[str]] = []
        falsy = False
        for value in values + extra:
            if isinstance(value, str) and _YAML12_SCALAR_RE.fullmatch(value):
                return None     # text to this reader, and maybe a number or false to GitHub's (YAML 1.2)
            if isinstance(value, str) and "${{" not in value:
                if value == "" and default is not None:
                    falsy = True        # `'' || 'label'` is the label
                else:
                    out.append([value])
            elif isinstance(value, list) and all(isinstance(v, str) and "${{" not in v for v in value):
                out.append([str(v) for v in value])
            else:
                return None
        if default is not None:
            may_lack = not (name in matrix and values and all(name in entry for entry in include))
            if may_lack or falsy:
                out.append([default])
        return out or None

    @property
    def runner_kind(self) -> str:
        """github-hosted, self-hosted, or unknown (custom labels, larger runners, unresolved expressions)."""
        if self.self_hosted:
            return "self-hosted"
        sets = self.runner_label_sets()
        if not sets:
            return "unknown"
        kinds = set()
        for labels in sets:
            lower = [label.lower() for label in labels]
            if any(label == "self-hosted" or label.startswith("group:") for label in lower):
                kinds.add("self-hosted")
            elif len(lower) == 1 and HOSTED_LABEL_RE.match(lower[0]):
                kinds.add("github-hosted")
            else:
                kinds.add("unknown")
        for kind in ("self-hosted", "unknown"):
            if kind in kinds:
                return kind
        return "github-hosted"

    @property
    def mixed_runner_expression(self) -> bool:
        """A runtime selector mentioning both hosted and self-hosted alternatives.

        This is uncertainty, not proof that a fork-safe selector is correct. Literal
        matrices are handled by runner_kind and retain findings for known pools.
        """
        if self.runner_label_sets() is not None or self.self_hosted:
            return False
        labels = ' '.join(self.runs_on).lower()
        return ('${{' in labels and 'self-hosted' in labels
                and re.search(r"['\"](?:ubuntu|windows|macos)-[a-z0-9.-]+['\"]", labels) is not None)

    @property
    def reusable(self) -> str | None:
        value = self.raw.get("uses")
        return str(value) if value else None

    @property
    def needs(self) -> list[str]:
        value = self.raw.get("needs")
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            return [str(v) for v in value]
        return []

    def triggers(self, _seen: frozenset = frozenset()) -> set[str]:
        """Workflow triggers that can reach this job, narrowed by simple `if:` tests on the event, and
        by the jobs it needs (a job runs only if they ran, unless its `if:` overrides that)."""
        events = set(self.workflow.triggers)
        cond = self.raw.get("if")
        if isinstance(cond, str):
            events = _narrow(events, cond)
        if self.id in _seen or runs_after_failure(cond):
            return events
        for name in self.needs:
            dep = self.workflow.jobs.get(name)
            if dep is None:
                continue
            allowed = dep.triggers(_seen | {self.id})
            narrowed = set()
            for event in events:
                if event in allowed:
                    narrowed.add(event)
                elif event == "workflow_run" and TRUSTED_WORKFLOW_RUN in allowed:
                    narrowed.add(TRUSTED_WORKFLOW_RUN)
                elif event == TRUSTED_WORKFLOW_RUN and "workflow_run" in allowed:
                    narrowed.add(event)
            events = narrowed
        return events

    def secret_names(self) -> set[str]:
        """Secrets the job can read. The whole job is read, not a list of keys known to take
        secrets, so a reference in a place the checker did not expect (for example `outputs`) is
        still found."""
        if self._secret_names is None:
            names = secret_names(self.workflow.raw.get("env")) | secret_names(self.raw)
            passed = self.raw.get("secrets")
            if isinstance(passed, str) and passed.strip():
                names.add("*inherit")      # the only string GitHub accepts here is `inherit`
            self._secret_names = frozenset(names)
        return set(self._secret_names)

    def runs_agent(self, detection: dict, extra_actions=(), extra_commands=()) -> str | None:
        actions = list(detection.get("agent_actions", [])) + list(extra_actions)
        commands = [re.compile(p, re.M) for p in list(detection.get("agent_commands", [])) + list(extra_commands)]
        for step in self.steps:
            for prefix in actions:
                if step.uses_action(prefix):
                    return f"uses {step.action}"
            text = step.agent_text()
            for rx in commands:
                if text and rx.search(text):
                    return f"runs an agent CLI in '{step.name}'"
        if self.reusable:
            for prefix in actions:
                if self.reusable.lower().startswith(prefix.lower()):
                    return f"calls {self.reusable}"
        return None

    def upload_steps(self, detection: dict) -> list[Step]:
        actions = detection.get("upload_actions", [])
        commands = [re.compile(p, re.M) for p in detection.get("upload_commands", [])]
        out = []
        for step in self.steps:
            if str(step.env.get("OBAAF_STEP", "")).lower() == "publish":
                out.append(step)
                continue
            if any(step.uses_action(a) for a in actions):
                out.append(step)
                continue
            text = step.text()
            if text and any(rx.search(text) for rx in commands):
                out.append(step)
        return out

    def matching_steps(self, actions=(), commands=()) -> list[Step]:
        rxs = [re.compile(p, re.M) for p in commands]
        out = []
        for step in self.steps:
            if any(step.uses_action(a) for a in actions):
                out.append(step)
            elif step.text() and any(rx.search(step.text()) for rx in rxs):
                out.append(step)
        return out


@dataclass
class Workflow:
    path: str
    text: str
    raw: dict
    jobs: dict[str, Job] = field(default_factory=dict)
    error: str | None = None
    problems: list[str] = field(default_factory=list)  # parts the checker cannot see into
    lane_problems: list = field(default_factory=list)  # IdleDeclaration: declarations in the file that do nothing
    digest: str = ""            # sha256 of the file's bytes, when it was read from a file

    @property
    def has_merge_key(self) -> bool:
        """Whether the file has a YAML merge key (`<<`) anywhere: this reader (YAML 1.1) merges it away,
        and a YAML 1.2 reader takes it for a key of that name, so what a mapping holds is read two ways.
        Read once, from the composed nodes; a file that cannot be composed counts as having one."""
        cached = self.__dict__.get("_has_merge_key")
        if cached is None:
            from obaaf.checker.egress import _has_merge_key
            try:
                cached = _has_merge_key(self.text)
            except Exception:       # a file the reader cannot compose: say yes, so nothing is resolved from it
                cached = True
            self.__dict__["_has_merge_key"] = cached
        return cached

    @property
    def triggers(self) -> dict[str, Any]:
        on = self.raw.get("on")
        if isinstance(on, str):
            return {on: None}
        if isinstance(on, list):
            return {as_text(e): None for e in on}
        if isinstance(on, dict):
            return {as_text(k): v for k, v in on.items()}
        return {}

    @property
    def permissions(self) -> Permissions | None:
        """The workflow's own `permissions`, or None. Written with no value it is taken as not
        written (see Job.permissions)."""
        return Permissions.parse(self.raw.get("permissions"))

    def composed(self):
        """The file's YAML node tree (no values constructed), or None if it cannot be composed. Kept
        for the life of the workflow."""
        if "_composed" not in self.__dict__:
            try:
                self.__dict__["_composed"] = yamlutil.yaml.compose(self.text, Loader=yamlutil._Loader)
            except Exception:       # anything the reader refuses: the source is simply not known
                self.__dict__["_composed"] = None
        return self.__dict__["_composed"]

    def environment_sources(self) -> dict:
        """Job id (as written) -> (text, style) of its environment name, for every job whose name is
        a plain mapping entry in the composed file. Built once, so asking for every job costs one
        walk of the file."""
        if "_environment_sources" in self.__dict__:
            return self.__dict__["_environment_sources"]
        yaml = yamlutil.yaml

        def get(node, key):
            found = None
            if isinstance(node, yaml.MappingNode):
                for k, v in node.value:
                    if isinstance(k, yaml.ScalarNode) and k.value == key:
                        found = v
            return found

        out: dict = {}
        jobs = get(self.composed(), "jobs")
        for key, job in (jobs.value if isinstance(jobs, yaml.MappingNode) else []):
            if not isinstance(key, yaml.ScalarNode):
                continue
            env = get(job, "environment")
            if isinstance(env, yaml.MappingNode):
                env = get(env, "name")
            if isinstance(env, yaml.ScalarNode):
                out[key.value] = (env.value, env.style)
        self.__dict__["_environment_sources"] = out
        return out

    @property
    def callable(self) -> bool:
        """Whether another workflow can call this one (`workflow_call`). A called workflow's jobs get
        the token the calling job grants, narrowed by what the called workflow declares."""
        return "workflow_call" in self.triggers

    @property
    def env(self) -> dict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else {}

    def line_of(self, needle: str, after: int = 0) -> int:
        """First line (1-based) at or after `after` containing `needle`, or `after`."""
        for number, line in enumerate(self.text.splitlines(), start=1):
            if number >= after and needle in line:
                return number
        return after or 1


# Characters that some YAML readers treat as a line break and others as ordinary text. Where the
# readers disagree, text after one of them can be a comment to the checker and a value to GitHub.
_DISPUTED_BREAKS = {"\u0085": "U+0085", "\u2028": "U+2028", "\u2029": "U+2029"}


def _unreadable(value: Any, _seen: set | None = None) -> str | None:
    """The first value of a kind the checker does not read (a set, pairs or binary data, which only
    an explicit YAML tag produces), or None. Skipping one silently would be a pass on text nobody
    read."""
    if isinstance(value, (dict, list)):
        if _seen is None:
            _seen = set()
        if id(value) in _seen:
            return None
        _seen.add(id(value))
        for item in (list(value.keys()) + list(value.values())) if isinstance(value, dict) else value:
            found = _unreadable(item, _seen)
            if found:
                return found
        return None
    if isinstance(value, (set, frozenset, tuple, bytes, bytearray)):
        return type(value).__name__
    return None


def parse(path: str, text: str) -> Workflow:
    for char, name in _DISPUTED_BREAKS.items():
        if char in text:
            return Workflow(path=path, text=text, raw={}, error=(
                f"contains the character {name}, which YAML readers do not agree is a line break, so the "
                "checker cannot tell what GitHub would read; remove it"))
    try:
        raw = yamlutil.load(text)
    except Exception as exc:  # yaml errors, duplicate keys
        return Workflow(path=path, text=text, raw={}, error=f"cannot parse YAML: {exc}")
    if not isinstance(raw, dict):
        return Workflow(path=path, text=text, raw={}, error="not a workflow (top level is not a mapping)")
    try:
        odd = _unreadable(raw)
    except RecursionError:
        odd = "nesting too deep to read"
    if odd:
        return Workflow(path=path, text=text, raw={}, error=(
            f"contains a value the checker does not read ({odd}); write it as plain YAML text, lists and mappings"))
    workflow = Workflow(path=path, text=text, raw=raw)
    jobs = raw.get("jobs")
    if not isinstance(jobs, dict):
        workflow.error = "no jobs"
        return workflow
    on = raw.get("on")
    events = [on] if isinstance(on, str) else list(on) if isinstance(on, (list, dict)) else []
    odd = next((event for event in events if not isinstance(event, str) or not _EVENT_SPELLING.match(event)), None)
    if odd is not None:
        # GitHub's event names are lower-case letters and underscores. One written otherwise (another
        # case, a mapping inside the list) is not an event the rules know, and treating it as none
        # would drop an untrusted trigger without a word.
        workflow.problems.append(f"lists a trigger under 'on' written as {shown_value(odd)}, which is not an event "
                                 "name as GitHub writes them (lower-case letters and underscores), so the checker "
                                 "cannot tell which events start the workflow")
    problem = permissions_problem(raw.get("permissions"), "the workflow")
    if problem:
        workflow.problems.append(problem)
    for job_id, job_raw in jobs.items():
        if not isinstance(job_raw, dict):
            workflow.problems.append(f"job '{job_id}' is not a mapping, so the checker cannot check what it does")
            continue
        problem = permissions_problem(job_raw.get("permissions"), f"job '{job_id}'")
        if problem:
            workflow.problems.append(problem)
        job = Job(id=str(job_id), raw=job_raw, line=getattr(job_raw, "line", 0) or jobs.line_of(job_id), workflow=workflow)
        steps = job_raw.get("steps")
        if isinstance(steps, list):
            _add_steps(workflow, job, steps)
        workflow.jobs[job.id] = job
    return workflow


_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def input_name(name) -> str:
    """An input's name as the rules look it up: A to Z in lower case, every other character as
    written (the Kelvin sign is not `k`, and `\u017f` is not `s`)."""
    return str(name).translate(_ASCII_LOWER)


def _input_problem(step_raw: dict) -> str | None:
    """What is wrong with the names under a step's `with:`, if anything: two names that are one
    input to GitHub, or a name with a letter outside ASCII, which GitHub's upper-casing may or may
    not turn into another input's name. Either way the checker cannot tell what the action is given."""
    given = step_raw.get("with")
    seen: dict = {}
    for name in (given if isinstance(given, dict) else ()):
        if isinstance(name, str) and not name.isascii():
            return (f"has an input name with a letter outside ASCII ('{one_line(name, 60)}'), and the checker "
                    "cannot tell which input GitHub takes it for")
        key = input_name(name)
        if key in seen:
            return (f"gives the same input twice under two spellings ('{one_line(seen[key], 60)}' and "
                    f"'{one_line(name, 60)}'), so the checker cannot tell which value GitHub uses")
        seen[key] = name
    return None


def _add_steps(workflow: Workflow, job: Job, steps: list) -> None:
    """Flatten a job's steps, including the steps inside `parallel` groups, in order."""
    groups = 0

    def inputs_checked(raw: dict, number: int) -> None:
        problem = _input_problem(raw)
        if problem:
            workflow.problems.append(f"job '{job.id}', step {number} {problem}")
    for number, step_raw in enumerate(steps, start=1):
        if not isinstance(step_raw, dict):
            workflow.problems.append(f"job '{job.id}', step {number} is not a mapping, so the checker cannot "
                                     "check what it does")
            continue
        line = getattr(step_raw, "line", job.line)
        if "parallel" in step_raw:
            groups += 1
            inner = step_raw.get("parallel")
            if not isinstance(inner, list):
                workflow.problems.append(f"job '{job.id}', step {number}: 'parallel' is not a list of steps")
                continue
            for sub in inner:
                if isinstance(sub, dict):
                    inputs_checked(sub, number)
                    job.steps.append(Step(index=len(job.steps), raw=sub, line=getattr(sub, "line", line),
                                          group=groups, background=True))
            continue
        inputs_checked(step_raw, number)
        if not ({"run", "uses"} & set(step_raw)) and not (CONTROL_STEP_KEYS & set(step_raw)):
            workflow.problems.append(f"job '{job.id}', step {number} has no 'run' or 'uses' and is not a step form "
                                     "the checker knows, so it cannot check what the step does")
        background = str(step_raw.get("background", "")).strip().lower() not in ("", "false")
        job.steps.append(Step(index=len(job.steps), raw=step_raw, line=line, background=background))


def declared_lane(value) -> str | None:
    """The lane a declaration names, or None when it names none. Case and surrounding space do
    not matter, so `Agent` is not silently a different thing from `agent`."""
    if not isinstance(value, str):
        return None
    lane = value.strip().lower()
    return lane if lane in LANES else None


def one_line(text, limit: int | None = None) -> str:
    """`text` as it can be printed on one line. A line break, any other control character, and any
    character Python does not count as printable are shown as escapes (`\\n`, `\\x1b`, `\\u200b`), so
    a name that contains a line break cannot look like another line of a report. The escape is for a
    reader and cannot be undone: a name that spells out `\\n` prints the same way. A text longer than
    `limit` is cut, and its length given."""
    out = "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in str(text))
    if limit and len(out) > limit:
        out = f"{out[:limit]}... ({len(out)} characters)"
    return out


def as_text(value) -> str:
    """`str(value)`, for a value that came out of a YAML file. Python refuses to print an integer of
    more than a few thousand digits in decimal, and YAML reads `0xFF...` of any length as one; such
    a number is given in hexadecimal, which has no limit."""
    try:
        return str(value)
    except ValueError:
        return hex(value) if isinstance(value, int) else repr(type(value).__name__)


def shown_value(value) -> str:
    """A declared value as a note names it: what the author wrote, on one line and bounded."""
    if value is None or value == "":
        return "an empty value"
    if isinstance(value, bool):
        return f"'{str(value).lower()}'"
    if isinstance(value, (list, tuple, set, frozenset)):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    text = as_text(value)
    if not text.isascii():
        # A look-alike letter reads exactly like the lane it imitates; the escape shows the difference.
        text = text.encode("unicode_escape").decode("ascii")
    return f"'{one_line(text, 60)}'"


VALUE_LIMIT = 200


def value_identity(value) -> str:
    """A declared value as what identifies a finding about it. Text, a number and true or false are
    all text to the CI system that reads the variable, so each is its text in quotes; a list, a
    mapping and an empty value are named without quotes, so none can be mistaken for text that
    spells the same words. Text longer than VALUE_LIMIT characters is its length and digest, which
    keeps an acceptance small and still tells two long values apart."""
    if value is None or value == "":
        return "an empty value"
    if isinstance(value, (list, tuple, set, frozenset)):
        return "a list"
    if isinstance(value, dict):
        return "a mapping"
    text = str(value).lower() if isinstance(value, bool) else as_text(value)
    return bounded(text, quoted=True)


def bounded(text: str, quoted: bool = False) -> str:
    """`text` as part of what identifies a finding: itself (in quotes when `quoted`), or its length
    and digest when it is longer than VALUE_LIMIT characters. Unquoted text that itself begins like
    a digest is given as its digest too, so no short text can stand for a long one."""
    if len(text) > VALUE_LIMIT or (not quoted and text.startswith("sha256:")):
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        return f"sha256:{digest} ({len(text)} characters)"
    return f"'{text}'" if quoted else text


_LANE_VARIABLE = "OBAAF_LANE"


def misnamed_lane_variables(env) -> list:
    """The names in an `env` that are OBAAF_LANE in another spelling: other case, spaces round it, a
    hyphen or a space for the underscore. The variable is read under its exact name only, as a
    runner's shell would read it, so such a name declares nothing."""
    out = []
    for name in (env if isinstance(env, dict) else ()):
        if isinstance(name, str) and name != _LANE_VARIABLE and \
                re.sub(r"[\s_-]+", "_", name.strip()).upper() == _LANE_VARIABLE:
            out.append(name)
    return out


@dataclass(frozen=True)
class IdleDeclaration:
    """A lane declaration that does nothing: its value is not a lane, it is written where the
    checker does not read it, or it names a job, a stage or a file that is not there. The job it was
    meant for gets none of the rules the declaration was meant to add, so it is reported as a
    finding (OBAAF-CFG-001) and never dropped without a word.

    This is one written in a workflow or a Jenkinsfile; a `lanes:` entry is judged by the caller,
    which knows every file the configuration covers. `kind` says which case it is. `value` is the
    declared value as `value_identity` gives it and `shown` as a report prints it; `lane` is the
    lane it names when it names one."""
    kind: str
    path: str = ""                # the file it is written in
    line: int = 0
    job: str | None = None
    step: str | None = None
    value: str = ""
    shown: str = ""
    lane: str | None = None
    service: str = ""             # the service whose env holds it
    name: str = ""                # the variable as it is written, when that is not OBAAF_LANE
    name_shown: str = ""          # and as a report prints it
    # The Jenkins stages whose steps the declaration reaches, by label. Steps outside any stage are
    # the empty label, which no stage can have.
    stages: tuple = ()
    # Whether the job is already in the lane the declaration names, so nothing is missing because of it.
    redundant: bool = False

    @classmethod
    def of(cls, kind: str, value, **where) -> "IdleDeclaration":
        return cls(kind=kind, value=value_identity(value), shown=shown_value(value),
                   lane=declared_lane(value), **where)


def key_line(mapping, key, owner_line: int = 0) -> int:
    """The line a key of a parsed mapping is written on, for a mapping that belongs to something
    that starts on `owner_line` (a job, a step, the file). A mapping reached through a YAML alias
    was written above its owner, at the anchor; then the owner's own line is given, which is where
    a reader looks for it."""
    line_of = getattr(mapping, "line_of", None)
    try:
        return max(int(line_of(key)) if line_of else 0, owner_line)
    except (TypeError, ValueError):
        return owner_line


_UNSET = object()


def classify(workflow: Workflow, overrides: dict | None = None, extra_agents: dict | None = None,
             aliases: tuple = ()) -> None:
    """Put each job in every lane it belongs to.

    Inference comes first, and each lane is decided on its own: a job that runs an agent and
    publishes is in the agent lane and in the release lane, and gets the rules of both. A lane
    declared with OBAAF_LANE or in the checker configuration is added to those. A declaration never
    takes a job out of a lane, so it can add rules and cannot remove any. An OBAAF_LANE that does
    nothing (a value that is not a lane, or one set where it is not read) is recorded in
    `workflow.lane_problems`, never dropped without a word. A `lanes:` entry that does nothing is
    for the caller to report: it knows every file the configuration covers.

    `aliases` are other paths the configuration may know this file by: a workflow checked on its
    own is `ci.yml` to the checker and `.github/workflows/ci.yml` in the repository's configuration.
    """
    detection = load_catalog().detection
    overrides = overrides or {}
    extra_agents = extra_agents or {}
    workflow.lane_problems = []
    paths = tuple(dict.fromkeys((workflow.path, *aliases)))

    def problem(found: IdleDeclaration) -> None:
        if found not in workflow.lane_problems:
            workflow.lane_problems.append(found)

    for job in workflow.jobs.values():
        job.lanes = _inferred_lanes(job, detection, extra_agents)
        job.lane_notes = []
        configured = [f"{path}#{job.id}" for path in paths] + list(paths)
        declarations = [(overrides.get(key, _UNSET), "set in the checker configuration", None) for key in configured]
        declarations += [
            (job.env.get("OBAAF_LANE", _UNSET), "set by OBAAF_LANE",
             {"kind": "job-not-a-lane", "job": job.id, "line": key_line(job.env, "OBAAF_LANE", job.line)}),
            (workflow.env.get("OBAAF_LANE", _UNSET), "set by OBAAF_LANE",
             {"kind": "workflow-not-a-lane", "line": key_line(workflow.env, "OBAAF_LANE", 1)}),
        ]
        for name in misnamed_lane_variables(job.env):
            problem(IdleDeclaration.of("job-misnamed", job.env[name], path=workflow.path, job=job.id,
                                       line=key_line(job.env, name, job.line), name=bounded(name),
                                       name_shown=one_line(name, 60)))
        for name in misnamed_lane_variables(workflow.env):
            problem(IdleDeclaration.of("workflow-misnamed", workflow.env[name], path=workflow.path,
                                       line=key_line(workflow.env, name, 1), name=bounded(name),
                                       name_shown=one_line(name, 60)))
        declared: dict = {}
        trusted_why = None
        for value, why, where in declarations:
            if value is _UNSET:
                continue
            lane = declared_lane(value)
            if lane is None:
                if where is not None:
                    problem(IdleDeclaration.of(where["kind"], value, path=workflow.path, line=where["line"],
                                               job=where.get("job")))
            elif lane == "trusted":
                trusted_why = trusted_why or why
            else:
                # The first declaration of a lane gives the reason that is shown, as it did when a
                # job had one lane: the configuration before OBAAF_LANE, the job before the workflow.
                declared.setdefault(lane, why)
        if trusted_why and job.lanes and not declared:
            # `trusted` is all the job was declared, and what it does puts it in a lane anyway.
            job.lane_notes.append("declared trusted, which cannot override what the job does")
        job.lanes.update(declared)
        job.settle_lane(trusted_why or "default")
        for found in _stray_declarations(workflow, job, {id(workflow.raw.get("env")), id(job.raw.get("env"))}):
            problem(found)


def _stray_declarations(workflow: Workflow, job: Job, read: set) -> list:
    """Where a job sets OBAAF_LANE in an `env` the checker does not read it from: a step's, the
    container's, a service's. `read` holds the identities of the two env mappings that are read for
    this job (its own and the workflow's), so an env shared with one of them through a YAML anchor
    is not reported."""
    def stray(env) -> bool:
        return isinstance(env, dict) and "OBAAF_LANE" in env and id(env) not in read

    def found(kind: str, env, line: int, **where) -> IdleDeclaration:
        return IdleDeclaration.of(kind, env["OBAAF_LANE"], path=workflow.path, job=job.id,
                                  line=key_line(env, "OBAAF_LANE", line), **where)

    out = [found("step-env", step.raw["env"], step.line, step=step.name)
           for step in job.steps if stray(step.raw.get("env"))]
    # A `parallel` group is a step to a reader and holds no step of its own in the model.
    steps = job.raw.get("steps")
    for number, group in enumerate(steps if isinstance(steps, list) else (), start=1):
        if isinstance(group, dict) and "parallel" in group and stray(group.get("env")):
            name = as_text(group.get("name") or group.get("id") or f"parallel group at step {number}")
            out.append(found("step-env", group["env"], getattr(group, "line", job.line), step=name))
    container = job.raw.get("container")
    if isinstance(container, dict) and stray(container.get("env")):
        out.append(found("container-env", container["env"], job.line))
    services = job.raw.get("services")
    for name, service in (services.items() if isinstance(services, dict) else ()):
        if isinstance(service, dict) and stray(service.get("env")):
            out.append(found("service-env", service["env"], job.line, service=bounded(str(name))))
    return list(dict.fromkeys(out))


# An environment whose name says where releases go, anywhere in the name (AppProd, awsprod,
# app-store). A name that says it is not production, or comes before it, is taken at its word.
RELEASE_ENVIRONMENT_RE = re.compile(r"release|prod|publish|store|steam|itch|deploy")
NOT_PRODUCTION_RE = re.compile(r"(?<![a-z])(non|pre)[-_. ]?prod")     # not the end of `canon-prod`


def release_environment(name) -> bool:
    return bool(RELEASE_ENVIRONMENT_RE.search(NOT_PRODUCTION_RE.sub(" ", str(name or "").lower())))


def _inferred_lanes(job: Job, detection: dict, extra_agents: dict) -> dict:
    """Every lane the job's own content puts it in, with the reason for each."""
    lanes: dict = {}
    agent = job.runs_agent(detection, extra_agents.get("actions", ()), extra_agents.get("commands", ()))
    if agent:
        lanes["agent"] = agent
    triggers = job.triggers()
    writes = bool(job.permissions and job.permissions.write_scopes())
    if triggers & {"workflow_run", TRUSTED_WORKFLOW_RUN} and writes and _downloads_from_trigger_run(job):
        lanes["effect"] = "applies the output of another workflow's run"
    if job.upload_steps(detection):
        lanes["release"] = "uploads or publishes artifacts"
    elif release_environment(job.environment):
        # Whatever starts the job: a job that a pull request or a comment can start and that uses
        # the production environment is the case OBAAF-GHA-015 exists for.
        lanes["release"] = f"uses the '{job.environment}' environment"
    if triggers and triggers <= PR_TRIGGERS | {"merge_group"} | ({"push"} if "pull_request" in triggers else set()):
        lanes["untrusted"] = "builds pull requests"
    return lanes


ARTIFACT_API_RE = re.compile(
    r"gh\s+run\s+download\b|downloadArtifact|listWorkflowRunArtifacts|/actions/runs/\S*/artifacts|"
    r"/actions/artifacts/\S*/(zip|\{archive_format\})", re.I)


def _downloads_from_trigger_run(job: Job) -> bool:
    for step in job.steps:
        if step.uses_action("actions/download-artifact") or step.uses_action("dawidd6/action-download-artifact"):
            if "workflow_run" in str(step.with_) or step.uses_action("dawidd6/action-download-artifact"):
                return True
        if ARTIFACT_API_RE.search(step.text()):
            return True
    return False


def discover(root: Path) -> list[Path]:
    wf_dir = root / ".github" / "workflows"
    if not wf_dir.is_dir():
        return []
    return sorted(p for p in wf_dir.iterdir() if p.suffix in (".yml", ".yaml") and p.is_file())


def locate(target: Path) -> tuple[Path, list[Path]]:
    """The repository root and workflow files for a directory a user points `obaaf check` at.

    Accepts a repository root or its `.github/workflows` directory itself (the form the
    quickstart once showed), so pointing at the workflows directory no longer checks zero
    files and passes. The root stays the repository root, so CODEOWNERS and instruction
    files are still found and paths read `.github/workflows/<file>`.
    """
    target = target.resolve()
    if target.name == "workflows" and target.parent.name == ".github" and not (target / ".github").exists():
        root = target.parent.parent
        return root, discover(root)
    if target.name == ".github" and (target / "workflows").is_dir():
        return target.parent, discover(target.parent)
    return target, discover(target)
