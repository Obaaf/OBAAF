"""What a repository's workflow files use and assume, for the settings rules.

A settings rule compares a setting with something a workflow depends on: the environment a job names, the
events that start a workflow, the name a job reports as a check, the secrets a job reads. This module reads
those from the workflow files in a clone, with the parser `obaaf check` uses, and returns them as plain
data. It reads files and nothing else: no network, and no setting.

Nothing here judges. What could not be read is recorded as such (a file that does not parse, a job whose
check name is computed), so that a rule can answer "cannot tell" where the workflows did not say.
"""

from __future__ import annotations

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
            "tags": "tags" in config or "tags-ignore" in config}


def _check_name(job: wf_mod.Job) -> dict:
    """The name the job reports as a check. GitHub uses the job's `name`, or its id; a matrix adds the
    values in brackets, and a job that calls a reusable workflow reports `name / job in that workflow`."""
    name = job.name
    if "${{" in name:
        return {"kind": "computed", "name": None}
    strategy = job.raw.get("strategy")
    if job.reusable:
        return {"kind": "calls", "name": name}
    if isinstance(strategy, dict) and strategy.get("matrix") is not None or isinstance(strategy, str):
        return {"kind": "matrix", "name": name}
    return {"kind": "static", "name": name}


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
    found = job.permissions
    if found is None:
        return {"declared": False, "pull_requests_write": None}
    return {"declared": True, "pull_requests_write": found.level("pull-requests") == "write"}


def _unpinned(job: wf_mod.Job) -> list[str]:
    """Actions the job's steps use that are not pinned to a full commit. Local actions and container
    images are left out; what GitHub's own pinning requirement makes of those was not established."""
    out = []
    for step in job.steps:
        uses = step.uses
        if not uses or uses.startswith(("./", "docker://")):
            continue
        ref = uses.split("@", 1)[1] if "@" in uses else ""
        if not wf_mod.FULL_SHA_RE.match(ref):
            out.append(uses)
    return sorted(set(out))


def _job(job: wf_mod.Job) -> dict:
    names = job.secret_names()
    passed = job.raw.get("secrets") if job.reusable else None
    return {
        "id": job.id, "line": job.line, "check": _check_name(job),
        "environment": _environment(job),
        "triggers": sorted(job.triggers()),
        "secrets": sorted(n for n in names if not n.startswith("*")),
        "all_secrets": expr_mod.ALL in names,
        "calls": job.reusable,
        "passes": None if not job.reusable else {
            "inherit": isinstance(passed, str) and bool(passed.strip()),
            "names": sorted(n for n in wf_mod.secret_names(passed) if not n.startswith("*")),
            "all": expr_mod.ALL in wf_mod.secret_names(passed)},
        "permissions": _permissions(job),
        # Only the literal `true` counts: a job whose result GitHub always reports as a success.
        "advisory": job.raw.get("continue-on-error") is True,
        "self_hosted": job.self_hosted,
        "unpinned": _unpinned(job),
        "steps": len(job.steps),
    }


def _file(path: str, text: str) -> dict:
    workflow = wf_mod.parse(path, text)
    if workflow.error:
        return {"path": path, "error": wf_mod.one_line(workflow.error, 200), "problems": [], "triggers": {},
                "jobs": []}
    triggers = {event: _filters(config) for event, config in workflow.triggers.items()}
    return {"path": path, "error": None,
            "problems": [wf_mod.one_line(p, 200) for p in workflow.problems],
            "triggers": triggers, "jobs": [_job(job) for job in workflow.jobs.values()]}


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
    usage = {"format": FORMAT, "read": True, "reason": "", "root": str(root), "files": files, "config": None,
             "config_error": ""}
    from obaaf import checker  # imported here: the checker is large, and --help should not load it

    try:
        config = checker.Config.load(root)
    except (checker.ConfigError, OSError, ValueError) as exc:
        usage["config_error"] = wf_mod.one_line(str(exc), 300)
    else:
        if config.path:
            usage["config"] = {"path": Path(config.path).relative_to(root).as_posix(),
                               "protected_secrets": dict(sorted(config.protected_secrets.items()))}
    return usage
