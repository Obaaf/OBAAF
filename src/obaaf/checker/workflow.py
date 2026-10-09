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

LANES = ("untrusted", "agent", "effect", "release", "trusted")

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

EXPR_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)
SECRET_RE = re.compile(r"\bsecrets\s*(?:\.\s*([A-Za-z_][A-Za-z0-9_-]*)|\[\s*['\"]([^'\"]+)['\"]\s*\])")
ALL_SECRETS_RE = re.compile(r"\b(toJSON|tojson)\s*\(\s*secrets\s*\)", re.I)
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


def expressions(value: Any) -> Iterator[str]:
    """Yield the body of every ${{ }} expression found anywhere in a value."""
    if isinstance(value, str):
        for match in EXPR_RE.finditer(value):
            yield match.group(1)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from expressions(k)
            yield from expressions(v)
    elif isinstance(value, list):
        for v in value:
            yield from expressions(v)


def secret_names(value: Any) -> set[str]:
    """Names of secrets referenced in a value; '*' means every secret (toJSON(secrets))."""
    names: set[str] = set()
    for expr in expressions(value):
        if ALL_SECRETS_RE.search(expr):
            names.add("*")
        for match in SECRET_RE.finditer(expr):
            names.add(match.group(1) or match.group(2))
    names.discard("GITHUB_TOKEN")
    return names


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
        names = secret_names(self.workflow.raw.get("env")) | secret_names(self.raw.get("env"))
        for key in ("with", "secrets", "container", "services", "steps"):
            names |= secret_names(self.raw.get(key))
        if self.raw.get("secrets") == "inherit":
            names.add("*inherit")
        return names

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


def parse(path: str, text: str) -> Workflow:
    try:
        raw = yamlutil.load(text)
    except Exception as exc:  # yaml errors, duplicate keys
        return Workflow(path=path, text=text, raw={}, error=f"cannot parse YAML: {exc}")
    if not isinstance(raw, dict):
        return Workflow(path=path, text=text, raw={}, error="not a workflow (top level is not a mapping)")
    workflow = Workflow(path=path, text=text, raw=raw)
    jobs = raw.get("jobs")
    if not isinstance(jobs, dict):
        workflow.error = "no jobs"
        return workflow
    for job_id, job_raw in jobs.items():
        if not isinstance(job_raw, dict):
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


def classify(workflow: Workflow, overrides: dict | None = None, extra_agents: dict | None = None) -> None:
    """Assign each job a lane.

    Inference comes first. A job inferred to be in the agent, effect, release or untrusted lane
    stays there: neither OBAAF_LANE nor the checker configuration can move it to a lane with fewer
    rules. A declared lane decides only for jobs that inference leaves as trusted, or moves an
    untrusted job into the agent, effect or release lane, whose rules are stricter.
    """
    detection = load_catalog().detection
    overrides = overrides or {}
    extra_agents = extra_agents or {}
    for job in workflow.jobs.values():
        lane, reason = _infer_lane(job, detection, extra_agents)
        override = overrides.get(f"{workflow.path}#{job.id}") or overrides.get(workflow.path)
        explicit = job.env.get("OBAAF_LANE") or workflow.env.get("OBAAF_LANE")
        declared = (override, "set in the checker configuration") if override in LANES else \
            (str(explicit), "set by OBAAF_LANE") if explicit in LANES else (None, "")
        if declared[0] and declared[0] != lane:
            if lane == "trusted" or (lane == "untrusted" and declared[0] in ("agent", "effect", "release")):
                lane, reason = declared
            else:
                reason += f"; declared {declared[0]}, which cannot override what the job does"
        elif declared[0]:
            reason = declared[1]
        job.lane, job.lane_reason = lane, reason


def _infer_lane(job: Job, detection: dict, extra_agents: dict) -> tuple[str, str]:
    agent = job.runs_agent(detection, extra_agents.get("actions", ()), extra_agents.get("commands", ()))
    if agent:
        return "agent", agent
    triggers = job.triggers()
    writes = bool(job.permissions and job.permissions.write_scopes())
    if triggers & {"workflow_run", TRUSTED_WORKFLOW_RUN} and writes and _downloads_from_trigger_run(job):
        return "effect", "applies the output of another workflow's run"
    if job.upload_steps(detection):
        return "release", "uploads or publishes artifacts"
    env_name = (job.environment or "").lower()
    if re.search(r"release|prod|publish|store|steam|itch|deploy", env_name) and not (triggers & UNTRUSTED_TRIGGERS):
        return "release", f"uses the '{job.environment}' environment"
    if triggers and triggers <= PR_TRIGGERS | {"merge_group"} | ({"push"} if "pull_request" in triggers else set()):
        return "untrusted", "builds pull requests"
    return "trusted", "default"


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
