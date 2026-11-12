"""A model of GitHub Actions workflow files for the OBAAF checker.

The model answers the questions the rules ask: what can start this job, what
can its token do, which secrets reach it, does it run an agent, does it upload
releases, and which caches can it read.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterator

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
# Standard GitHub-hosted runner labels (ubuntu-latest, ubuntu-24.04-arm, windows-2025, macos-15, ...).
HOSTED_LABEL_RE = re.compile(r"^(ubuntu|windows|macos)-[a-z0-9.-]+$")
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

# References to a pull request's code (OBAAF-GHA-002, OBAAF-GHA-012).
PR_HEAD_REF_RE = re.compile(
    r"github\.event\.pull_request\.head\.(sha|ref)\b|github\.head_ref\b|"
    r"github\.event\.workflow_run\.head_(sha|branch)\b|github\.event\.workflow_run\.head_repository\b|"
    r"refs/pull/|github\.event\.issue\.pull_request|github\.event\.pull_request\.merge_commit_sha"
)
PR_FETCH_CMD_RE = re.compile(
    r"(^|[\s;&|(])gh\s+pr\s+checkout\b|git\s+fetch\b[^\n]*\bpull/|git\s+fetch\b[^\n]*refs/pull/|"
    r"git\s+(checkout|switch)\b[^\n]*\$\{\{\s*github\.event\.pull_request\.head"
)


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
        if raw is None:
            return None
        if isinstance(raw, str):
            raw = raw.strip()
            if raw in ("read-all", "write-all"):
                return cls(declared=True, mode=raw)
            return cls(declared=True, mode="map")
        if isinstance(raw, dict):
            return cls(declared=True, mode="map", scopes={str(k): str(v) for k, v in raw.items()})
        return cls(declared=True)

    def level(self, scope: str) -> str:
        if self.mode == "write-all":
            return "write"
        if self.mode == "read-all":
            return "none" if scope == "id-token" else "read"
        return self.scopes.get(scope, "none")

    def write_scopes(self) -> list[str]:
        if self.mode == "write-all":
            return ["write-all"]
        return sorted(s for s, v in self.scopes.items() if v == "write" and s != "id-token")

    @property
    def oidc(self) -> bool:
        return self.level("id-token") == "write"


@dataclass
class Step:
    index: int
    raw: dict
    line: int
    group: int | None = None      # parallel group it belongs to, if any
    background: bool = False      # runs concurrently with later steps (background: true or parallel)

    @property
    def name(self) -> str:
        return str(self.raw.get("name") or self.raw.get("id") or self.uses or f"step {self.index + 1}")

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
        return str(self.raw.get("name") or self.id)

    @property
    def env(self) -> dict:
        value = self.raw.get("env")
        return value if isinstance(value, dict) else {}

    @property
    def permissions(self) -> Permissions | None:
        if "permissions" in self.raw:
            return Permissions.parse(self.raw.get("permissions") if self.raw.get("permissions") is not None else {})
        return self.workflow.permissions

    @property
    def environment(self) -> str | None:
        env = self.raw.get("environment")
        if isinstance(env, dict):
            return str(env.get("name") or "") or None
        return str(env) if env else None

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
        """Each set of labels the job can run on, with `${{ matrix.x }}` resolved from a literal
        matrix; None when a label comes from an expression that cannot be resolved."""
        labels = self.runs_on
        expr = [label for label in labels if "${{" in label]
        if not expr:
            return [labels] if labels else None
        if len(labels) != 1:
            return None
        match = re.fullmatch(r"\$\{\{\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*\}\}", labels[0].strip())
        strategy = self.raw.get("strategy")
        matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
        if not match or not isinstance(matrix, dict):
            return None
        values = matrix.get(match.group(1))
        include = matrix.get("include") if isinstance(matrix.get("include"), list) else []
        extra = [i.get(match.group(1)) for i in include if isinstance(i, dict) and match.group(1) in i]
        if not isinstance(values, list) and not extra:
            return None
        out = []
        for value in (values if isinstance(values, list) else []) + extra:
            if isinstance(value, str) and "${{" not in value:
                out.append([value])
            elif isinstance(value, list) and all(isinstance(v, str) and "${{" not in v for v in value):
                out.append([str(v) for v in value])
            else:
                return None
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
            text = step.text()
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
    def triggers(self) -> dict[str, Any]:
        on = self.raw.get("on")
        if isinstance(on, str):
            return {on: None}
        if isinstance(on, list):
            return {str(e): None for e in on}
        if isinstance(on, dict):
            return {str(k): v for k, v in on.items()}
        return {}

    @property
    def permissions(self) -> Permissions | None:
        if "permissions" not in self.raw:
            return None
        raw = self.raw.get("permissions")
        return Permissions.parse(raw if raw is not None else {})

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
    for job_id, job_raw in jobs.items():
        if not isinstance(job_raw, dict):
            workflow.problems.append(f"job '{job_id}' is not a mapping, so the checker cannot check what it does")
            continue
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
    text = str(value)
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
    text = str(value).lower() if isinstance(value, bool) else str(value)
    return bounded(text, quoted=True)


def bounded(text: str, quoted: bool = False) -> str:
    """`text` as part of what identifies a finding: itself (in quotes when `quoted`), or its length
    and digest when it is longer than VALUE_LIMIT characters."""
    if len(text) > VALUE_LIMIT:
        digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()
        return f"sha256:{digest} ({len(text)} characters)"
    return f"'{text}'" if quoted else text


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
