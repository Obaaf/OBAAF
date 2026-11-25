"""Match a visible artifact transfer to the step that could execute the downloaded files."""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from collections import defaultdict
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
    found = defaultdict(list)
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
                    source = Upload(workflow.path, workflow.raw.get("name", ""), job.id, name, path)
                    found[workflow.path].append(source)
    return dict(found)


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
        elif command == "make" and all(re.fullmatch(r"[\w.-]+", arg) and not arg.startswith("-") for arg in words[1:]):
            operand = "Makefile"
        else:
            continue
        operand = _local_path(operand)
        if operand:
            yield posixpath.normpath(posixpath.join(directory, operand))


class _Members:
    """Earliest source per artifact name and member restriction, in upload order."""

    def __init__(self, uploads):
        self.members = defaultdict(dict)
        for rank, source in enumerate(uploads):
            filename = posixpath.basename(source.path)
            directory = source.path in (".", "./") or source.path.endswith("/") or re.fullmatch(
                r"\s*\$\{\{\s*steps\.[\w-]+\.outputs\.workspace\s*\}\}\s*", source.path
            )
            for workspace in (True, False):
                member = None if directory or (not workspace and "." not in filename) else filename
                self.members[workspace, member].setdefault(source.name, (rank, source))

    def first(self, workspace, member, name, pattern):
        best = None
        for restriction in (None, member):
            group = self.members.get((workspace, restriction))
            if not group:
                continue
            if name is not None:
                found = group.get(name)
            elif pattern == "*":
                found = next(iter(group.values()))
            else:
                found = next((entry for artifact, entry in group.items()
                              if fnmatch.fnmatchcase(artifact, pattern)), None)
            if found is not None and (best is None or found[0] < best[0]):
                best = found
        return best


def _trigger_sources(workflow, sources):
    trigger = workflow.triggers.get("workflow_run")
    names = trigger.get("workflows") if isinstance(trigger, dict) else None
    if isinstance(names, str):
        names = [names]
    if isinstance(names, list):
        for group in sources.values():
            if group[0].workflow_name in names:
                yield from group


class _Downloads:
    """Record each distinct destination and selector once. Sources are shared across downloads."""

    def __init__(self, workflow, job, sources):
        self.workflow = workflow
        self.job = job
        self.sources = sources
        self.by_scope = {}
        self.by_target = defaultdict(dict)
        self.depths = set()

    def add(self, index, step):
        given = step.with_
        target = _local_path(given.get("path", "."))
        pattern = given.get("pattern", "*")
        if target is None or not isinstance(pattern, str) or "repository" in given or "artifact-ids" in given:
            return
        name = given.get("name")
        if "name" in given:
            if not isinstance(name, str) or not fnmatch.fnmatchcase(name, pattern):
                return
            pattern = "*"
        triggering = "run-id" in given
        if triggering and not (given.get("github-token") and re.fullmatch(
            r"\s*\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}\s*", str(given["run-id"])
        )):
            return
        if triggering not in self.by_scope:
            if triggering:
                eligible = _trigger_sources(self.workflow, self.sources)
            else:
                eligible = (s for s in self.sources.get(self.workflow.path, ()) if s.job != self.job.id)
            self.by_scope[triggering] = _Members(eligible)
        split = name is None and str(given.get("merge-multiple", False)).lower() != "true"
        self.depths.add(0 if target == "." else target.count("/") + 1)
        self.by_target[target].setdefault((triggering, name, pattern, split), (index, step))

    def first(self, path):
        parts = path.split("/")
        best = None
        if path == ".":
            return None
        for depth in self.depths:
            if depth >= len(parts):
                continue
            target = "/".join(parts[:depth]) or "."
            selectors = self.by_target.get(target)
            if not selectors:
                continue
            member = "/".join(parts[depth:])
            for (triggering, name, pattern, split), (index, download) in selectors.items():
                if best is not None and index >= best[0]:
                    break
                sources = self.by_scope[triggering]
                if split:
                    # A literal artifact named "." shares the target folder. The old
                    # non-normalized root for that layout was never the workspace sentinel.
                    found = sources.first(False, member, ".", pattern) if fnmatch.fnmatchcase(".", pattern) else None
                    child, slash, rest = member.partition("/")
                    if slash and fnmatch.fnmatchcase(child, pattern):
                        other = sources.first(False, rest, child, pattern)
                        if other is not None and (found is None or other[0] < found[0]):
                            found = other
                else:
                    found = sources.first(target == ".", member, name, pattern)
                if found is not None:
                    rank, source = found
                    best = index, rank, source, download
        return best


def consumers(workflow: Workflow, job: Job, sources):
    if not sources:
        return
    downloads = _Downloads(workflow, job, sources)
    for index, step in enumerate(job.steps):
        best = None
        if downloads.by_target:
            for path in _executed_paths(step, job, workflow):
                hit = downloads.first(path)
                if hit is not None and (best is None or hit[:2] < best[:2]):
                    best = (*hit, path)
        if best is not None:
            _, _, source, download, path = best
            yield source, download, step, path
        if step.clean_action == "actions/download-artifact":
            downloads.add(index, step)
