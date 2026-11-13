"""What a repository's workflow files use and assume, for the settings rules.

A settings rule compares a setting with something a workflow depends on: the environment a job names, the
events that start a workflow, the name a job reports as a check, the secrets a job reads. This module reads
those from the workflow files in a clone, with the parser `obaaf check` uses, and returns them as plain
data. It reads files and nothing else: no network, and no setting.

Nothing here judges. What could not be read is recorded as such (a file that does not parse, a job whose
check name is computed), so that a rule can answer "cannot tell" where the workflows did not say.
"""

from __future__ import annotations

import itertools
from pathlib import Path

from obaaf.checker import expr as expr_mod
from obaaf.checker import workflow as wf_mod

FORMAT = "obaaf-workflow-usage/v0.1"
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024
# The events that put a check on a pull request's head commit.
PULL_REQUEST_EVENTS = ("pull_request", "pull_request_target")


def not_read(reason: str) -> dict:
    """The usage of a repository whose workflow files were not read, with the reason."""
    return {"format": FORMAT, "read": False, "reason": reason, "root": "", "files": [], "config": None,
            "config_error": ""}


def _filters(config) -> dict:
    """The filters on one event. A filter that is present is recorded even when it is empty or not a
    list: what it lets through is then not something this module claims to know."""
    config = config if isinstance(config, dict) else {}

    def listed(key: str):
        value = config.get(key)
        if value is None:
            return None
        if isinstance(value, str):
            return [value]
        return [str(v) for v in value] if isinstance(value, list) else []

    return {"paths": "paths" in config or "paths-ignore" in config,
            "branches": listed("branches"), "branches_ignore": listed("branches-ignore"),
            "tags": "tags" in config or "tags-ignore" in config,
            # The activity types the event is limited to (opened, labeled, closed ...), when it is.
            "types": listed("types")}


MAX_MATRIX_NAMES = 256


def _matrix_values(strategy) -> list[str] | None:
    """The bracketed part of each check a matrix job reports ("3.13", "linux, 3.13"), when the matrix
    is written out: lists of text or whole numbers and nothing else. None when it is not, and then the
    names are not guessed: `include`, `exclude`, an expression, or a value GitHub prints in a way of its
    own (a decimal, true or false, a mapping)."""
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict) or not matrix or "include" in matrix or "exclude" in matrix:
        return None
    axes = []
    for values in matrix.values():
        if not isinstance(values, list) or not values:
            return None
        if not all(isinstance(v, (str, int)) and not isinstance(v, bool) and "${{" not in str(v) for v in values):
            return None
        axes.append([str(v) for v in values])
    total = 1
    for axis in axes:
        total *= len(axis)
    if total > MAX_MATRIX_NAMES:
        return None
    return [", ".join(combo) for combo in itertools.product(*axes)]


def _check_name(job: wf_mod.Job) -> dict:
    """The names the job reports as checks. GitHub uses the job's `name`, or its id; a matrix adds the
    values in brackets, and a job that calls a reusable workflow reports `name / job in that workflow`.

    ``names`` is the whole list when it can be written out, and None when it cannot (a computed name, a
    matrix that is not written out, a called workflow that was not read). A job that calls a workflow in
    this repository gets its names once every file has been read (see ``_resolve_calls``)."""
    name = job.name
    strategy = job.raw.get("strategy")
    has_matrix = isinstance(strategy, str) or (isinstance(strategy, dict) and strategy.get("matrix") is not None)
    if "${{" in name:
        return {"kind": "computed", "name": None, "matrix": has_matrix, "names": None}
    values = _matrix_values(strategy) if has_matrix else None
    own = [name] if not has_matrix else None if values is None else [f"{name} ({v})" for v in values]
    if job.reusable:
        return {"kind": "calls", "name": name, "matrix": has_matrix, "names": None, "prefixes": own}
    return {"kind": "matrix" if has_matrix else "static", "name": name, "matrix": has_matrix, "names": own}


def _environment(job: wf_mod.Job):
    """None, {"name": ...} or {"computed": True}. A name GitHub would compute is not guessed."""
    raw = job.raw.get("environment")
    if raw is None or raw == "" or raw == {}:
        return None
    name = job.environment
    if name is None or "${{" in name or not isinstance(raw, (str, dict)):
        return {"computed": True}
    return {"name": name}


def _permissions(job: wf_mod.Job) -> dict:
    """What the job's token may do, where the workflow says. Not declared means the repository's default
    applies, which is a setting; the two answers are then None."""
    found = job.permissions
    if found is None:
        return {"declared": False, "pull_requests_write": None, "writes_checks": None}
    return {"declared": True, "pull_requests_write": found.level("pull-requests") == "write",
            # A token that can write checks or statuses can report a check under any name.
            "writes_checks": "write" in (found.level("checks"), found.level("statuses"))}


def _actions(job: wf_mod.Job) -> tuple[int, list[str]]:
    """How many of the job's steps use an action from another repository, and which of those are not
    pinned to a full commit. Local actions, container images and the reusable workflow a job calls are
    left out; what GitHub's own pinning requirement makes of those was not established."""
    used, loose = 0, []
    for step in job.steps:
        uses = step.uses
        if not uses or uses.startswith(("./", "docker://")):
            continue
        used += 1
        ref = uses.split("@", 1)[1] if "@" in uses else ""
        if not wf_mod.FULL_SHA_RE.match(ref):
            loose.append(uses)
    return used, sorted(set(loose))


def _job(job: wf_mod.Job) -> dict:
    names = job.secret_names()
    passed = job.raw.get("secrets") if job.reusable else None
    # A caller can also hand a secret over as an input, under `with:`.
    handed = (wf_mod.secret_names(passed) | wf_mod.secret_names(job.raw.get("with"))) if job.reusable else set()
    used, loose = _actions(job)
    return {
        "id": job.id, "line": job.line, "check": _check_name(job),
        "environment": _environment(job),
        "triggers": sorted(job.triggers()),
        "called_from": [],          # events of the jobs that call this job's workflow (see _resolve_calls)
        "secrets": sorted(n for n in names if not n.startswith("*")),
        "all_secrets": expr_mod.ALL in names,
        "calls": job.reusable,
        "passes": None if not job.reusable else {
            "inherit": isinstance(passed, str) and bool(passed.strip()),
            "names": sorted(n for n in handed if not n.startswith("*")),
            "all": expr_mod.ALL in handed},
        "permissions": _permissions(job),
        # Only the literal `true` counts: a job whose result GitHub always reports as a success.
        "advisory": job.raw.get("continue-on-error") is True,
        # github-hosted, self-hosted, or unknown (a label of the repository's own, an expression).
        "runner": None if job.reusable else job.runner_kind,
        "actions": used,
        "unpinned": loose,
    }


def _file(path: str, text: str) -> dict:
    workflow = wf_mod.parse(path, text)
    if workflow.error:
        return {"path": path, "error": wf_mod.one_line(workflow.error, 200), "problems": [], "triggers": {},
                "jobs": []}
    refused = _refused(workflow)
    if refused:
        # GitHub refuses the whole file, so none of its jobs runs: reading the others as if they did would
        # count checks that never report.
        return {"path": path, "error": wf_mod.one_line(f"{refused}, and GitHub refuses such a file", 200),
                "problems": [], "triggers": {}, "jobs": []}
    triggers = {event: _filters(config) for event, config in workflow.triggers.items()}
    return {"path": path, "error": None,
            "problems": [wf_mod.one_line(p, 200) for p in workflow.problems],
            "triggers": triggers, "jobs": [_job(job) for job in workflow.jobs.values()]}


# Filters that GitHub's workflow syntax says cannot be used together on one event.
EXCLUSIVE_FILTERS = (("branches", "branches-ignore"), ("tags", "tags-ignore"), ("paths", "paths-ignore"))


def _refused(workflow) -> str:
    """Why GitHub would refuse the file, for the ways this module knows of; empty when it knows none. It
    knows few: what it does not know is read as a file that runs."""
    raw_jobs = workflow.raw.get("jobs")
    if isinstance(raw_jobs, dict):
        for job_id, value in raw_jobs.items():
            if not isinstance(value, dict):
                return f"job {str(job_id)!r} is not a mapping"
            if "runs-on" not in value and "uses" not in value:
                return f"job {str(job_id)!r} has neither runs-on nor uses"
    for event, config in workflow.triggers.items():
        if isinstance(config, dict):
            for one, other in EXCLUSIVE_FILTERS:
                if one in config and other in config:
                    return f"the event {str(event)!r} has both {one} and {other}"
    return ""


def called_path(job: dict) -> str | None:
    """The path of the workflow file a job calls, when it is one in this repository."""
    target = job["calls"] or ""
    return target[2:] if target.startswith("./") else None


def _resolve_calls(files: list[dict]) -> None:
    """Join each job that calls a workflow in this repository to the jobs it calls.

    The called jobs learn which events reach them (a job in a reusable workflow runs for whatever started
    its caller), and the caller learns the names its checks are reported under. Calls can nest, so this is
    repeated until nothing changes. The events only grow, so they always settle, however long the chain.
    Names in a cycle of calls can keep changing: once the events have settled and MAX_PASSES have run,
    every caller's names are left unknown, which is the safe reading for names."""
    by_path = {file["path"]: file for file in files if not file["error"]}

    def events():
        return [[job["called_from"] for job in file["jobs"]] for file in by_path.values()]

    def names():
        return [[job["check"]["names"] for job in file["jobs"]] for file in by_path.values()]

    passes = 0
    while True:
        before = (events(), names())
        _resolve_once(by_path)
        passes += 1
        if (events(), names()) == before:
            return
        if passes >= MAX_PASSES and events() == before[0]:
            for file in by_path.values():
                for job in file["jobs"]:
                    if job["check"]["kind"] == "calls":
                        job["check"]["names"] = None
            return


MAX_PASSES = 200


def _resolve_once(by_path: dict) -> None:
    """One pass of _resolve_calls."""
    for file in by_path.values():
        for job in file["jobs"]:
            called = by_path.get(called_path(job) or "")
            if called is None:
                continue
            reach = sorted((set(job["triggers"]) | set(job["called_from"])) - {"workflow_call"})
            names: list[str] | None = []
            for inner in called["jobs"]:
                inner["called_from"] = sorted(set(inner["called_from"]) | set(reach))
                inner_names = inner["check"]["names"]
                prefixes = job["check"].get("prefixes")
                if names is None or inner_names is None or prefixes is None:
                    names = None
                else:
                    names += [f"{prefix} / {inner_name}" for prefix in prefixes for inner_name in inner_names]
            if job["check"]["kind"] == "calls":
                job["check"]["names"] = names if names is None or len(names) <= MAX_MATRIX_NAMES else None


def read(root: str | Path) -> dict:
    """Read the workflow files and the checker's configuration under ``root``."""
    root = Path(root)
    try:
        root, paths = wf_mod.locate(root)
    except OSError as exc:
        return not_read(f"the directory could not be read ({exc.strerror or type(exc).__name__})")
    if not (root / ".github" / "workflows").is_dir():
        return not_read("there is no .github/workflows directory there")
    files = []
    for path in paths:
        rel = path.relative_to(root).as_posix()
        try:
            with open(path, "rb") as handle:
                raw = handle.read(MAX_WORKFLOW_BYTES + 1)
            if len(raw) > MAX_WORKFLOW_BYTES:
                raise ValueError("it is larger than 2 MB")
            text = raw.decode("utf-8")
        except OSError as exc:
            files.append({"path": rel, "error": f"cannot be read ({exc.strerror or type(exc).__name__})",
                          "problems": [], "triggers": {}, "jobs": []})
            continue
        except ValueError as exc:
            reason = "it is not UTF-8 text" if isinstance(exc, UnicodeError) else str(exc)
            files.append({"path": rel, "error": f"cannot be read ({reason})", "problems": [], "triggers": {},
                          "jobs": []})
            continue
        try:
            files.append(_file(rel, text))
        except (RecursionError, TypeError, ValueError, KeyError, AttributeError, IndexError) as exc:
            # A file this module could not make sense of is recorded as unread, never skipped.
            files.append({"path": rel, "error": f"could not be read as a workflow ({type(exc).__name__})",
                          "problems": [], "triggers": {}, "jobs": []})
    _resolve_calls(files)
    usage = {"format": FORMAT, "read": True, "reason": "", "root": str(root), "files": files, "config": None,
             "config_error": ""}
    from obaaf import checker  # imported here: the checker is large, and --help should not load it

    try:
        config = checker.Config.load(root)
    except checker.ConfigError as exc:
        usage["config_error"] = wf_mod.one_line(str(exc), 300)
    except Exception as exc:  # noqa: BLE001 - a configuration nobody could read protects nothing, and says so
        usage["config_error"] = f"it could not be read ({type(exc).__name__})"
    else:
        if config.path:
            usage["config"] = {"path": Path(config.path).relative_to(root).as_posix(),
                               "protected_secrets": dict(sorted(config.protected_secrets.items()))}
    return usage
