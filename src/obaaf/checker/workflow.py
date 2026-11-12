"""A model of GitHub Actions workflow files for the OBAAF checker.

The model answers the questions the rules ask: what can start this job, what
can its token do, which secrets reach it, does it run an agent, does it upload
releases, and which caches can it read.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
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


def runs_after_failure(cond) -> bool:
    """Whether an `if:` can let a step or job run although an earlier step, or a job it needs,
    failed or was skipped.

    Without a status function GitHub adds an implicit `success() &&`. With `always()`,
    `failure()` or `cancelled()`, or with `success()` inside an `||` or negated, the job or step
    can run regardless.
    """
    text = str(cond or "").strip()
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    if re.search(r"\b(always|failure|cancelled)\s*\(", text, re.I):
        return True
    return bool(re.search(r"\bsuccess\s*\(", text, re.I) and ("||" in text or re.search(r"!\s*success", text, re.I)))

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


def _narrow(events: set[str], cond: str) -> set[str]:
    """Narrow a job's possible triggers by simple tests on github.event_name in its `if:`."""
    expr = cond.strip()
    if expr.startswith("${{") and expr.endswith("}}"):
        expr = expr[3:-2]
    # A negated status function (`!cancelled()`, common beside `needs.x.result == 'success'`) says
    # nothing about the event, so it cannot invert an event test; drop it before looking for others.
    expr = re.sub(r"!\s*(?:always|cancelled|failure|success)\s*\(\s*\)", "true", expr, flags=re.I)
    if re.search(r"!(?!=)", expr):
        return events  # a negation can invert any test below; do not narrow
    eq_rx = re.compile(r"github\.event_name\s*==\s*['\"]([A-Za-z_]+)['\"]", re.I)
    ne_rx = re.compile(r"github\.event_name\s*!=\s*['\"]([A-Za-z_]+)['\"]", re.I)
    disjuncts = expr.split("||")
    pinned = [{e.lower() for e in eq_rx.findall(d)} for d in disjuncts]
    if all(pinned):
        # Every alternative requires a specific event, so only those events reach the job.
        events &= set().union(*pinned)
    if len(disjuncts) == 1:
        events -= {e.lower() for e in ne_rx.findall(expr)}
    run_rx = re.compile(r"github\.event\.workflow_run\.event\s*==\s*['\"]([A-Za-z_]+)['\"]", re.I)
    run_events = [{e.lower() for e in run_rx.findall(d)} for d in disjuncts]
    if "workflow_run" in events and all(run_events) and set().union(*run_events) <= _TRUSTED_RUN_EVENTS:
        events = (events - {"workflow_run"}) | {TRUSTED_WORKFLOW_RUN}
    return events


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
        value = self.raw.get("with")
        return value if isinstance(value, dict) else {}

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
    lane_problems: list[str] = field(default_factory=list)  # lane declarations that name no lane

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


def _add_steps(workflow: Workflow, job: Job, steps: list) -> None:
    """Flatten a job's steps, including the steps inside `parallel` groups, in order."""
    groups = 0
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
                    job.steps.append(Step(index=len(job.steps), raw=sub, line=getattr(sub, "line", line),
                                          group=groups, background=True))
            continue
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


def not_a_lane(where: str, value) -> str:
    """The note for a declaration whose value names no lane."""
    return (f"{where} to {shown_value(value)}, which is not a lane ({', '.join(LANES)}); "
            "the declaration changes nothing")


_UNSET = object()


def classify(workflow: Workflow, overrides: dict | None = None, extra_agents: dict | None = None,
             aliases: tuple = ()) -> None:
    """Put each job in every lane it belongs to.

    Inference comes first, and each lane is decided on its own: a job that runs an agent and
    publishes is in the agent lane and in the release lane, and gets the rules of both. A lane
    declared with OBAAF_LANE or in the checker configuration is added to those. A declaration never
    takes a job out of a lane, so it can add rules and cannot remove any. A declaration that does
    nothing (a value that is not a lane, OBAAF_LANE on a step) is recorded in
    `workflow.lane_problems`, never dropped without a word.

    `aliases` are other paths the configuration may know this file by: a workflow checked on its
    own is `ci.yml` to the checker and `.github/workflows/ci.yml` in the repository's configuration.
    """
    detection = load_catalog().detection
    overrides = overrides or {}
    extra_agents = extra_agents or {}
    workflow.lane_problems = []
    paths = tuple(dict.fromkeys((workflow.path, *aliases)))

    def problem(text: str) -> None:
        if text not in workflow.lane_problems:
            workflow.lane_problems.append(text)

    for job in workflow.jobs.values():
        job.lanes = _inferred_lanes(job, detection, extra_agents)
        job.lane_notes = []
        configured = [f"{path}#{job.id}" for path in paths] + list(paths)
        declarations = [(overrides.get(key, _UNSET), "set in the checker configuration",
                         f"the checker configuration sets lanes: '{one_line(key, 120)}'") for key in configured]
        declarations += [
            (job.env.get("OBAAF_LANE", _UNSET), "set by OBAAF_LANE",
             f"{one_line(workflow.path, 120)}: job '{one_line(job.id, 80)}' sets OBAAF_LANE"),
            (workflow.env.get("OBAAF_LANE", _UNSET), "set by OBAAF_LANE",
             f"{one_line(workflow.path, 120)} sets OBAAF_LANE"),
        ]
        declared: dict = {}
        trusted_why = None
        for value, why, where in declarations:
            if value is _UNSET:
                continue
            lane = declared_lane(value)
            if lane is None:
                problem(not_a_lane(where, value))
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
        for where in _stray_declarations(job.raw, skip=("env",)):
            problem(f"{one_line(workflow.path, 120)}: job '{one_line(job.id, 80)}' sets OBAAF_LANE in {where}, "
                    "where it is not read (it is read in the job's env and in the workflow's env); "
                    "the declaration changes nothing")
    for where in _stray_declarations(workflow.raw, skip=("env", "jobs")):
        problem(f"{one_line(workflow.path, 120)} sets OBAAF_LANE in {where}, where it is not read (it is read "
                "in a job's env and in the workflow's env); the declaration changes nothing")


def _stray_declarations(raw, skip: tuple = ()) -> list[str]:
    """Where `raw` (a job or a workflow) sets OBAAF_LANE in a place the checker does not read it: a
    step's env, a container's, a service's. `skip` names the top-level keys that are read elsewhere."""
    found: list[str] = []
    seen: set = set()

    def walk(node, trail: tuple, depth: int) -> None:
        if depth > 12 or not isinstance(node, (dict, list)) or id(node) in seen:
            return
        seen.add(id(node))
        if isinstance(node, list):
            for index, item in enumerate(node):
                walk(item, trail + (index + 1,), depth + 1)
            return
        for key, value in node.items():
            if key == "OBAAF_LANE":
                if trail[:1] == ("steps",) and len(trail) > 1:
                    where = f"step {trail[1]}"
                else:
                    where = one_line(".".join(str(part) for part in trail) or "the top level", 80)
                if where not in found:
                    found.append(where)
            elif not (depth == 0 and key in skip):
                walk(value, trail + (str(key),), depth + 1)

    walk(raw, (), 0)
    return found


# An environment whose name says where releases go. `prod` and `itch` must start a word: `switch`
# and `reproduce` are not release environments.
RELEASE_ENVIRONMENT_RE = re.compile(r"release|publish|store|steam|deploy|(?<![a-z])prod|(?<![a-z])itch")


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
    env_name = (job.environment or "").lower()
    if job.upload_steps(detection):
        lanes["release"] = "uploads or publishes artifacts"
    elif RELEASE_ENVIRONMENT_RE.search(env_name):
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
