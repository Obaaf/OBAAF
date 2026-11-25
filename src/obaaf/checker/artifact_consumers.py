"""Find a job that may run files from an agent job's artifact (OBAAF-GHA-027, plan decision F-359's second step).

The reading fails closed (review of #366, run `rosefinch`). After a download that may fetch an agent job's
artifact, every later step of the job that names the download's folder (in its script, working directory,
`env`, inputs or a local `uses`) is reported unless it is plainly read-only; when the folder is the
workspace, or a value the checker cannot read, every later step is, with the same exception. The layout
of the upload is not used to rule a file out: the agent writes what it uploads, so a path that looks like
one file may be a folder of anything.

Followed: `actions/upload-artifact`, `actions/upload-artifact/merge` and `actions/upload-pages-artifact`
in a job of the agent lane, and `actions/download-artifact` in another job of the same run (workflows of
this repository that call one another count as one run) or of a run started by `workflow_run` from the
producer's run, with `run-id: ${{ github.event.workflow_run.id }}`. Not followed (stated beside a cleared
egress control): downloads by other actions or in scripts, a computed artifact name, run ID or
repository, an artifact uploaded again by a job outside the agent lane, caches, job outputs, and code
from the repository that reads the download without naming its folder.
"""

from __future__ import annotations

import fnmatch
import posixpath
import re
import shlex
from dataclasses import dataclass

from obaaf.checker.workflow import Job, Step, Workflow

# Each upload action, with the artifact name it uses when `name` is not given.
UPLOAD_ACTIONS = {
    "actions/upload-artifact": "artifact",
    "actions/upload-artifact/merge": "merged-artifacts",
    "actions/upload-pages-artifact": "github-pages",
}
# Actions that only move or publish files: they run nothing they download.
READ_ONLY_ACTIONS = frozenset({*UPLOAD_ACTIONS, "actions/download-artifact"})
# Commands that read files and run none: a script of only these, with literal words, is read-only.
READ_ONLY_COMMANDS = frozenset({
    "cat", "echo", "printf", "ls", "jq", "grep", "egrep", "fgrep", "head", "tail", "wc", "diff", "cmp",
    "sha256sum", "sha1sum", "sha512sum", "md5sum", "stat", "file", "test", "[", "true", ":", "pwd", "du",
})
# Where a read-only command may write: nowhere a later step or job reads as settings or code.
_HARMLESS_TARGETS = frozenset({"/dev/null", "$GITHUB_STEP_SUMMARY", "${GITHUB_STEP_SUMMARY}"})
_SEPARATORS = frozenset({"|", "||", "&&", ";"})
_TRIGGERING_RUN = re.compile(r"\s*\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}\s*", re.IGNORECASE)
_CURRENT_RUN = re.compile(r"\s*\$\{\{\s*github\.run_id\s*\}\}\s*", re.IGNORECASE)
_WORKSPACE_PREFIX = re.compile(
    r"^(?:\$\{\{\s*github\.workspace\s*\}\}|\$GITHUB_WORKSPACE|\$\{GITHUB_WORKSPACE\})(?=/|$)", re.IGNORECASE)
_HOME_PREFIX = re.compile(r"^(?:\$HOME|\$\{HOME\})(?=/|$)")
_TOKEN = re.compile(r"""[^\s'"`;|&()<>=,]+""")

ANYWHERE = "a location the checker cannot read"     # a download whose folder is not a literal value
WORKSPACE = "."


@dataclass(frozen=True)
class Upload:
    workflow: str           # the file's path, as the checker names it
    run: str                # the run it belongs to: the files that call one another share one
    job: str
    name: str | None        # None: computed, so any name
    path: str


@dataclass(frozen=True)
class Sources:
    items: tuple
    run_of: dict            # workflow path -> run key
    names: dict             # run key -> the names a workflow_run trigger may give for it

    def __bool__(self) -> bool:
        return bool(self.items)


def _text(value) -> str | None:
    """A scalar input as GitHub hands it to an action; None for a mapping, a list or nothing."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (str, int, float)):
        return str(value)
    return None


def _runs(workflows) -> tuple[dict, dict]:
    """The workflows of this repository that call one another, read as one run (a called workflow's jobs
    are jobs of the caller's run, with its artifacts). Callers of the same file are joined too: wider."""
    parent: dict = {}

    def find(key):
        while parent.setdefault(key, key) != key:
            parent[key] = parent[parent[key]]
            key = parent[key]
        return key

    by_id = {id(workflow): workflow for workflow in workflows}
    for workflow in workflows:
        find(workflow.path)
        for job in workflow.jobs.values():
            for target in getattr(job, "called", None) or ():
                if id(target) in by_id:
                    a, b = find(workflow.path), find(target.path)
                    if a != b:
                        parent[max(a, b)] = min(a, b)
    run_of = {workflow.path: find(workflow.path) for workflow in workflows}
    names: dict = {}
    for workflow in workflows:
        given = _text(workflow.raw.get("name")) if isinstance(workflow.raw, dict) else None
        # An unnamed workflow is named by its path (wider: both are taken for a named one too).
        names.setdefault(run_of[workflow.path], set()).update(n.casefold() for n in (given, workflow.path) if n)
    return run_of, {key: frozenset(value) for key, value in names.items()}


def _name(step: Step, default: str) -> str | None:
    name = _text(step.with_.get("name", default))
    return None if name is None or "${{" in name else name


def uploads(workflows, expand=None) -> Sources:
    """Index the artifacts agent jobs upload, once per check. `expand(workflow, job)` gives the job with the
    steps of the local composite actions it uses, so an upload inside one counts. An
    `actions/upload-artifact/merge` step in any job of the run whose `pattern` may match an agent job's
    artifact makes a new one that holds its files, so it is indexed too, as the agent job's."""
    workflows = list(workflows)
    run_of, names = _runs(workflows)
    found = []
    merges = []
    for workflow in workflows:
        for job in workflow.jobs.values():
            view = expand(workflow, job) if expand is not None and job.local_steps else job
            agent = job.in_lane("agent") or view.in_lane("agent")
            for step in view.steps:
                default = UPLOAD_ACTIONS.get(step.clean_action)
                if default is None:
                    continue
                if agent:
                    path = _text(step.with_.get("path", "")) or ""
                    found.append(Upload(workflow.path, run_of[workflow.path], job.id, _name(step, default), path))
                elif step.clean_action == "actions/upload-artifact/merge":
                    merges.append((workflow, job, step))
    for workflow, job, step in merges:
        pattern = _text(step.with_.get("pattern"))
        run = run_of[workflow.path]
        if any(u.run == run and (u.name is None or pattern is None or "${{" in pattern
                                 or fnmatch.fnmatchcase(u.name, pattern)) for u in found):
            found.append(Upload(workflow.path, run, job.id, _name(step, "merged-artifacts"), ""))
    return Sources(tuple(found), run_of, names)


def _matched(workflow: Workflow, job: Job, download: Step, sources: Sources) -> list:
    """The uploads `download` may fetch. Computed values that decide which run or repository it reads
    from are a stated limit; a computed name or pattern is read as any."""
    given = download.with_
    if "repository" in given or "artifact-ids" in given:
        return []
    run = sources.run_of.get(workflow.path, workflow.path)
    if (given.get("run-id") is not None and given.get("github-token")
            and not _CURRENT_RUN.fullmatch(str(given["run-id"]))):
        if not _TRIGGERING_RUN.fullmatch(str(given["run-id"])):
            return []
        trigger = workflow.triggers.get("workflow_run") if isinstance(workflow.triggers, dict) else None
        listed = trigger.get("workflows") if isinstance(trigger, dict) else None
        if not isinstance(listed, list):
            listed = [listed]
        wanted = {text.casefold() for text in map(_text, listed) if text}
        candidates = [u for u in sources.items if sources.names.get(u.run, frozenset()) & wanted]
    else:
        candidates = [u for u in sources.items if u.run == run and not (u.workflow == workflow.path and u.job == job.id)]
    if "name" in given:
        name = _text(given["name"])
        if name is None or "${{" in name:
            return candidates
        # Matched in any letter case, the wider reading.
        return [u for u in candidates if u.name is None or u.name.casefold() == name.casefold()]
    pattern = _text(given.get("pattern"))
    if pattern is None or "${{" in pattern:
        return candidates
    return [u for u in candidates if u.name is None or fnmatch.fnmatchcase(u.name, pattern)]


def _normal(value: str) -> str | None:
    """A literal path as the steps after it would name it: relative to the workspace, absolute, or under
    `~`. None for a value the checker does not read (an expression, `..` above the workspace)."""
    value = value.strip()
    if not value or "${{" in value or "\n" in value:
        return None
    value = _WORKSPACE_PREFIX.sub(".", value)
    value = _HOME_PREFIX.sub("~", value)
    if value.startswith("~") and not (value == "~" or value.startswith("~/")):
        return None                         # ~user
    shown = posixpath.normpath(value)
    if shown == ".." or shown.startswith("../"):
        return None
    return shown


def _roots(download: Step, matched: list) -> list:
    """The folders the download writes. A download with no `name` and no `merge-multiple: true` writes each
    artifact into a folder of its name under `path`."""
    given = download.with_
    raw = given.get("path")
    base = WORKSPACE if raw is None else _normal(_text(raw) or "")
    if base is None:
        return [ANYWHERE]
    if "name" in given or str(given.get("merge-multiple", "")).strip().lower() == "true":
        return [base]
    roots = []
    for upload in matched:
        if upload.name is None:
            return [base]
        roots.append(posixpath.normpath(posixpath.join(base, upload.name)))
    return roots


def _working_directory(step: Step, job: Job, workflow: Workflow) -> str:
    directory = "."
    for scope in (workflow.raw, job.raw):
        defaults = scope.get("defaults") if isinstance(scope, dict) else None
        run = defaults.get("run") if isinstance(defaults, dict) else None
        if isinstance(run, dict) and run.get("working-directory") is not None:
            directory = _text(run.get("working-directory")) or "."
    if step.raw.get("working-directory") is not None:
        directory = _text(step.raw.get("working-directory")) or "."
    return directory


def _named(step: Step, job: Job, workflow: Workflow) -> frozenset:
    """Every folder and file a step names, with each of its leading folders: in its script, working
    directory, `env`, inputs and `uses`, and the job's and workflow's `env`. Relative names are taken both
    as written and from the step's working directory."""
    texts = [step.run, _working_directory(step, job, workflow), step.uses or ""]
    for scope in (step.raw, job.raw, workflow.raw):
        env = scope.get("env") if isinstance(scope, dict) else None
        if isinstance(env, dict):
            texts.extend(str(value) for value in env.values())
        elif env is not None:
            texts.append(str(env))
    raw_with = step.raw.get("with")
    if isinstance(raw_with, dict):
        texts.extend(str(value) for value in raw_with.values())
    elif raw_with is not None:
        texts.append(str(raw_with))
    directory = _normal(_working_directory(step, job, workflow))
    out: set = set()
    for text in texts:
        for token in _TOKEN.findall(text):
            for candidate in (token, posixpath.join(directory, token) if directory and directory != "." else None):
                shown = _normal(candidate) if candidate else None
                if shown is None:
                    continue
                parts = shown.split("/")
                for end in range(1, len(parts) + 1):
                    out.add("/".join(parts[:end]) or "/")
    if directory is None:
        out.add(ANYWHERE)
    return frozenset(out)


def _read_only(step: Step, job: Job, workflow: Workflow) -> bool:
    """A step that runs nothing it may have downloaded: one of `READ_ONLY_ACTIONS` with no `env` of its own,
    or a bash or sh script with no expression of whose lines each is commands of `READ_ONLY_COMMANDS` with
    literal words, joined by `|`, `||`, `&&` or `;`, writing at most to /dev/null or the step summary."""
    if step.uses is not None:
        return step.clean_action in READ_ONLY_ACTIONS and not step.raw.get("env")
    shell = step.raw.get("shell")
    for scope in (job.raw, workflow.raw):
        defaults = scope.get("defaults") if isinstance(scope, dict) else None
        run = defaults.get("run") if isinstance(defaults, dict) else None
        if shell is None and isinstance(run, dict):
            shell = run.get("shell")
    if shell not in (None, "bash", "sh") or "${{" in step.run:
        return False
    for line in step.run.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if any(mark in line for mark in ("`", "$(", "<(", ">(", "<<")) or line.endswith("\\"):
            return False
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = "#"
            words = list(lexer)
        except ValueError:
            return False
        if words == ["{"]:
            continue                        # a group's opening line; its `}` may redirect, below
        expect_command = True
        index = 0
        while index < len(words):
            word = words[index]
            if word == "}":
                expect_command = False      # the group's end: a redirection may follow
            elif expect_command:
                if word not in READ_ONLY_COMMANDS:
                    return False
                expect_command = False
            elif word in _SEPARATORS:
                expect_command = True
            elif word in (">", ">>"):
                index += 1
                if index >= len(words) or words[index] not in _HARMLESS_TARGETS:
                    return False
            elif word == ">&":
                index += 1
                if index >= len(words) or words[index] not in ("1", "2"):
                    return False
            elif set(word) <= set("();<>|&"):
                return False
            index += 1
        if expect_command:
            return False                    # a line ending in a separator
    return True


def _executed_paths(step: Step, job: Job, workflow: Workflow):
    """For the report only: a file a line of the script plainly runs (`./x`, an interpreter's file, a
    package's scripts, a Makefile). It no longer decides whether a step is reported."""
    if not step.run:
        return
    directory = _normal(_working_directory(step, job, workflow))
    if directory is None:
        return
    for line in step.run.splitlines():
        try:
            words = shlex.split(line, comments=True)
        except ValueError:
            continue
        if not words:
            continue
        command = words[0]
        if command.startswith(("./", "/")):
            operand = command
        elif command in ("bash", "sh", "python", "python3", "node", "ruby", "pwsh", "perl", "source", ".") \
                and len(words) > 1 and not words[1].startswith("-"):
            operand = words[1]
        elif command in ("npm", "pnpm", "yarn"):
            operand = "package.json"
        elif command == "make":
            operand = "Makefile"
        else:
            continue
        shown = _normal(posixpath.join(directory, operand) if not operand.startswith("/") else operand)
        if shown:
            yield shown


def consumers(workflow: Workflow, job: Job, sources: Sources):
    """Yield (uploads, download step, step, what it may run) for each step of `job` after a download of an
    agent job's artifact that may run files from it, at most once per step."""
    if not sources:
        return
    downloads = []
    for index, step in enumerate(job.steps):
        if step.clean_action != "actions/download-artifact":
            continue
        matched = _matched(workflow, job, step, sources)
        if matched:
            downloads.append((index, step, _roots(step, matched), matched))
    if not downloads:
        return
    first = downloads[0][0]
    for index, step in enumerate(job.steps):
        if index <= first or _read_only(step, job, workflow):
            continue
        named = None
        for start, download, roots, matched in downloads:
            if start >= index:
                break
            if not any(root in (WORKSPACE, ANYWHERE) for root in roots):
                if named is None:
                    named = _named(step, job, workflow)
                hit = [root for root in roots if root in named]
                if not hit and ANYWHERE not in named:
                    continue
                roots = hit or roots
            shown = next((path for path in _executed_paths(step, job, workflow)
                          if any(root in (WORKSPACE, ANYWHERE) or path == root or path.startswith(root + "/")
                                 for root in roots)), roots[0])
            yield matched, download, step, shown
            break
