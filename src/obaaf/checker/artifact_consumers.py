"""Match a visible artifact transfer to the step that could execute the downloaded files."""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from dataclasses import dataclass

from obaaf.checker.workflow import Job, Step, Workflow


@dataclass(frozen=True)
class Upload:
    workflow: str
    workflow_name: str
    job: str
    name: str
    path: str


def uploads(workflows):
    """Index literal artifact names once per check, also for workflow_run subscribers."""
    found = []
    for workflow in workflows:
        for job in workflow.jobs.values():
            if not job.in_lane("agent"):
                continue
            for step in job.steps:
                if step.clean_action != "actions/upload-artifact":
                    continue
                name = step.with_.get("name", "artifact")
                path = step.with_.get("path", "")
                if isinstance(name, str) and _local_path(name) == name and "/" not in name and isinstance(path, str):
                    found.append(Upload(workflow.path, workflow.raw.get("name", ""), job.id, name, path))
    return tuple(found)


def _source_matches(workflow: Workflow, job: Job, download: Step, source: Upload) -> bool:
    given = download.with_
    if "repository" in given or "artifact-ids" in given:
        return False
    if "run-id" in given:
        trigger = workflow.triggers.get("workflow_run")
        names = trigger.get("workflows") if isinstance(trigger, dict) else None
        return (re.fullmatch(r"\s*\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}\s*", str(given["run-id"]))
                is not None and isinstance(source.workflow_name, str)
                and source.workflow_name in ([names] if isinstance(names, str) else names if isinstance(names, list) else []))
    return source.workflow == workflow.path and source.job != job.id


def _local_path(value):
    if not isinstance(value, str) or not value or not re.fullmatch(r"[\w./ -]+", value):
        return None
    if value.startswith("/") or ".." in value.split("/"):
        return None
    return posixpath.normpath(value)


def _executed_paths(step: Step, job: Job, workflow: Workflow):
    """Read direct command and interpreter file operands. A printed or copied path is data."""
    if not step.run:
        return
    directory = "."
    for scope in (workflow.raw, job.raw):
        defaults = scope.get("defaults")
        run = defaults.get("run") if isinstance(defaults, dict) else None
        if isinstance(run, dict):
            directory = run.get("working-directory", directory)
    directory = _local_path(step.raw.get("working-directory", directory))
    if directory is None:
        return
    for line in step.run.splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        if not words:
            continue
        if words[0] == "cd" and len(words) >= 2:
            relative = _local_path(words[1])
            if relative is None:
                return
            directory = posixpath.normpath(posixpath.join(directory, relative))
            if len(words) == 2:
                continue
            if len(words) < 4 or words[2] != "&&":
                return
            words = words[3:]
        command = words[0]
        if command.startswith("./"):
            operand = command
        elif command in ("bash", "sh", "python", "python3", "node", "ruby", "pwsh") and len(words) > 1:
            operand = words[1]
            if operand.startswith("-"):
                continue
        elif command in ("npm", "pnpm", "yarn") and words[1:2] in (["test"], ["run"], ["start"]):
            operand = "package.json"
        elif words == ["make"]:
            operand = "Makefile"
        else:
            continue
        operand = _local_path(operand)
        if operand:
            yield posixpath.normpath(posixpath.join(directory, operand))


def consumers(workflow: Workflow, job: Job, sources):
    for index, download in enumerate(job.steps):
        if download.clean_action != "actions/download-artifact":
            continue
        given = download.with_
        target = _local_path(given.get("path", "."))
        if target is None:
            continue
        for source in sources:
            if not _source_matches(workflow, job, download, source):
                continue
            if "name" in given and given["name"] != source.name:
                continue
            pattern = given.get("pattern", "*")
            if not isinstance(pattern, str) or not fnmatch.fnmatchcase(source.name, pattern):
                continue
            root = target
            if "name" not in given and str(given.get("merge-multiple", False)).lower() != "true":
                root = posixpath.join(target, source.name)
            for step in job.steps[index + 1:]:
                for path in _executed_paths(step, job, workflow):
                    member = posixpath.relpath(path, root)
                    if member in (".", "..") or member.startswith("../"):
                        continue
                    # At the workspace root, unrelated repository files have the same prefix.
                    # Require a visible filename match there, or an explicitly uploaded directory.
                    if root == "." and not source.path.endswith("/"):
                        if posixpath.basename(source.path) != member:
                            continue
                    yield source, download, step, path
                    break
