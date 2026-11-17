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
import re
from pathlib import Path

from obaaf import yamlutil
from obaaf.checker import expr as expr_mod
from obaaf.checker import workflow as wf_mod

FORMAT = "obaaf-workflow-usage/v0.1"
MAX_WORKFLOW_BYTES = 2 * 1024 * 1024
# The events that put a check on a pull request's head commit. pull_request_target runs on the base branch's
# latest commit (GitHub's changelog of 2025-11-07), so its checks are not counted as the pull request's
# (flagship slice 2d.2g): PULL_REQUEST_EVENTS is still what starts a job for a pull request.
PULL_REQUEST_EVENTS = ("pull_request", "pull_request_target")
HEAD_COMMIT_EVENTS = ("pull_request",)
# A whole number as YAML 1.1 (this reader) and YAML 1.2 (GitHub's) both write it, with the same value.
PLAIN_INT_RE = re.compile(r"-?(?:0|[1-9][0-9]*)")


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


def _node(node, key):
    """The value of ``key`` in a composed YAML mapping, or None."""
    if isinstance(node, yamlutil.yaml.MappingNode):
        for k, v in node.value:
            if isinstance(k, yamlutil.yaml.ScalarNode) and k.value == key:
                return v
    return None


def _job_node(job: wf_mod.Job):
    """The job's composed mapping, or None when it cannot be found (a merge key, a key not written as text).
    The jobs' nodes are listed once per workflow, so asking for every job costs one walk of the file."""
    nodes = job.workflow.__dict__.get("_audit_job_nodes")
    if nodes is None:
        jobs = _node(job.workflow.composed(), "jobs")
        nodes = {}
        if isinstance(jobs, yamlutil.yaml.MappingNode):
            for k, v in jobs.value:
                if isinstance(k, yamlutil.yaml.ScalarNode):
                    nodes.setdefault(k.value, v)
        job.workflow.__dict__["_audit_job_nodes"] = nodes
    return nodes.get(job.id)


def _same_in_both(value, node) -> bool:
    """Whether a value reads the same to this checker's YAML reader (1.1) and to GitHub's (1.2), judged from
    its source (flagship slice 2d.2g): text that YAML 1.2 reads as a number, true, false or null (`08`,
    `0o10`), and a whole number written another way than plainly (`012` is 10 here and 12 to GitHub, `12:30`
    is 750 here and text to GitHub), are not. A value whose source was not found is not either."""
    if not isinstance(node, yamlutil.yaml.ScalarNode):
        return False
    if isinstance(value, str):
        return node.style is not None or not wf_mod._YAML12_SCALAR_RE.fullmatch(value)
    if isinstance(value, int) and not isinstance(value, bool):
        return node.style is None and bool(PLAIN_INT_RE.fullmatch(node.value))
    return False


def _matrix_values(strategy, matrix_node=None) -> list[str] | None:
    """The bracketed part of each check a matrix job reports ("3.13", "linux, 3.13"), when the matrix
    is written out: lists of text or whole numbers and nothing else, each written so that GitHub's YAML
    reader reads it as this one does. None when it is not, and then the names are not guessed: `include`,
    `exclude`, an expression, or a value GitHub prints in a way of its own (a decimal, true or false, a
    mapping)."""
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict) or not matrix or "include" in matrix or "exclude" in matrix:
        return None
    axes = []
    for key, values in matrix.items():
        if not isinstance(key, str) or not isinstance(values, list) or not values:
            return None
        if not all(isinstance(v, (str, int)) and not isinstance(v, bool) and "${{" not in str(v) for v in values):
            return None
        written = _node(matrix_node, key)
        if not isinstance(written, yamlutil.yaml.SequenceNode) or len(written.value) != len(values) or not all(
                _same_in_both(v, n) for v, n in zip(values, written.value)):
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
    written = job.raw.get("name")
    node = _job_node(job)
    if "${{" in name:
        return {"kind": "computed", "name": None, "matrix": has_matrix, "names": None}
    # A `name` that is not text (`name: 0` makes this reader fall back to the id), or text that GitHub's
    # YAML reader may read as something else, is not a name the audit can vouch for (slice 2d.2g).
    if written is not None and (not isinstance(written, str) or not _same_in_both(written, _node(node, "name"))):
        return {"kind": "computed", "name": None, "matrix": has_matrix, "names": None}
    values = _matrix_values(strategy, _node(_node(node, "strategy"), "matrix")) if has_matrix else None
    own = [name] if not has_matrix else None if values is None else [f"{name} ({v})" for v in values]
    if job.reusable:
        return {"kind": "calls", "name": name, "matrix": has_matrix, "names": None, "prefixes": own}
    return {"kind": "matrix" if has_matrix else "static", "name": name, "matrix": has_matrix, "names": own}


def _environment(job: wf_mod.Job):
    """None, {"name": ...} or {"computed": True}. A name GitHub would compute is not guessed, and neither is
    one written as a number or true or false, in either form (`environment: 010` or `environment: {name:
    010}`), whose text this reader and GitHub's may not agree on (flagship slice 2d.2g): the checker's own
    reading of the environment decides."""
    raw = job.raw.get("environment")
    if raw is None or raw == "" or raw == {}:
        return None
    kind, written = job.environment_reading
    return {"name": written} if kind == "literal" else {"computed": True}


def _permissions(job: wf_mod.Job) -> dict:
    """What the job's token may do, where the workflow says. Not declared means the repository's default
    applies, which is a setting; the two answers are then None."""
    found = job.permissions
    if found is None:
        return {"declared": False, "pull_requests_write": None, "writes_checks": None}
    return {"declared": True, "pull_requests_write": found.level("pull-requests") == "write",
            # A token that can write checks or statuses can report a check under any name.
            "writes_checks": "write" in (found.level("checks"), found.level("statuses"))}


def _actions(job: wf_mod.Job) -> tuple[int, list[str], list[str], list[str]]:
    """How many of the job's steps use an action from another repository, which of those are not pinned to
    a full commit, every such reference as written (for the list of selected actions, issue #182), and the
    local actions and container images its steps use, as written (slice 2b.7: their own steps, and whether
    the list covers an image, are not read). Local actions, container images and the reusable workflow a job
    calls are left out of the first two; what GitHub's own pinning requirement makes of those was not
    established."""
    used, loose, remote, other = 0, [], [], []
    for step in job.steps:
        uses = step.uses
        # `./path` and `$/path` are actions in this repository (flagship slice 2d.2g: `$/` was taken for a
        # remote action that is not pinned).
        if uses and (wf_mod.is_local_reference(uses) or uses.startswith("docker://")):
            other.append(uses)
        if not uses or wf_mod.is_local_reference(uses) or uses.startswith("docker://"):
            continue
        used += 1
        remote.append(uses)
        ref = uses.split("@", 1)[1] if "@" in uses else ""
        # A pin is 40 lower-case hex digits and nothing else, as the checker reads one (slice 2d.2f): a
        # 64-digit ref can only be a tag or a branch, and the old pattern's `$` took a trailing line break.
        if not wf_mod.COMMIT_SHA_RE.fullmatch(ref):
            loose.append(uses)
    return used, sorted(set(loose)), sorted(set(remote)), sorted(set(other))


def _runner(job: wf_mod.Job) -> str:
    kind = job.runner_kind
    if kind == "self-hosted":
        sets = job.runner_label_sets() or [job.runs_on]
        if not any(label.lower() == "self-hosted" for labels in sets for label in labels):
            return "unknown"
    return kind


def _job(job: wf_mod.Job) -> dict:
    names = job.secret_names()
    passed = job.raw.get("secrets") if job.reusable else None
    # A caller can also hand a secret over as an input, under `with:`.
    handed = (wf_mod.secret_names(passed) | wf_mod.secret_names(job.raw.get("with"))) if job.reusable else set()
    used, loose, remote, unread_actions = _actions(job)
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
        # Whether GitHub may read the job's file otherwise than this module does (set in read()): its
        # checks are then never counted as reported (flagship slice 2d.2g).
        "doubt": [],
        # github-hosted, self-hosted, or unknown (a label of the repository's own, an expression, a runner
        # group alone: a group can hold larger GitHub-hosted runners).
        "runner": None if job.reusable else _runner(job),
        "actions": used,
        "unpinned": loose,
        "remote_actions": remote,
        # Local actions and container images, whose steps or coverage by a list of allowed actions are not read.
        "unread_actions": unread_actions,
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
    problems = [wf_mod.one_line(p, 200) for p in workflow.problems]
    if workflow.has_merge_key and not any("merge key" in p for p in problems):
        problems.append("uses a YAML merge key (<<), which this reader merges and a YAML 1.2 reader does not")
    # Every problem but those about the names of a step's inputs makes the file one GitHub may read otherwise or
    # refuse (the second review of slice 2d.2g: a step that is text, or has neither run nor uses, a job whose
    # uses is not text, are refused by GitHub, and a list of words to include missed them).
    doubt = [p for p in problems if not HARMLESS_PROBLEM_RE.match(p)] + _odd_job_ids(workflow)
    return {"path": path, "error": None, "problems": problems, "doubt": doubt,
            "triggers": triggers, "jobs": [_job(job) for job in workflow.jobs.values()]}


# The checker's problems with a file that are about which input an action gets, not about whether GitHub runs
# the file or which jobs and names it has. Every other problem makes the file doubtful.
# Matched on the problem's whole shape, never on a phrase alone, because other problems quote what the author
# wrote (the third review of slice 2d.2g: `on: [pull_request, 'gives the same input twice']`). GitHub's job ids
# hold only letters, digits, `_` and `-`.
HARMLESS_PROBLEM_RE = re.compile(r"job '[A-Za-z0-9_-]+', step \d+ (?:has an input name with a letter outside ASCII "
                                 r"\(|gives the same input twice under two spellings \()")
# Filters that GitHub's workflow syntax says cannot be used together on one event.
EXCLUSIVE_FILTERS = (("branches", "branches-ignore"), ("tags", "tags-ignore"), ("paths", "paths-ignore"))
# A job id as GitHub's workflow syntax gives its form: it "must start with a letter or _ and contain only
# alphanumeric characters, -, or _" (issue #182; see _bad_job_id). Written from the reference as the author
# knew it on 2026-11-17; the page could not be read from the session that wrote this. Only ASCII is judged:
# whether GitHub's "alphanumeric" takes a letter or digit outside ASCII is not established (_odd_job_ids).
# GitHub's message for an id it refuses, as the author knew it, adds that an id "must be less than 100
# characters"; not read from a primary page this session, so a longer id is a doubt, not a refusal.
JOB_ID_DOUBTFUL_LENGTH = 100


def _bad_job_id(job_id: str) -> bool:
    """Whether a job id written as text breaks GitHub's form in a way that holds whatever "alphanumeric"
    means outside ASCII: an ASCII character other than a letter, a digit, `_` or `-` anywhere, or an ASCII
    digit or `-` first."""
    if not job_id:
        return True
    if job_id[0].isascii() and not (job_id[0].isalpha() or job_id[0] == "_"):
        return True
    return any(c.isascii() and not (c.isalnum() or c in "_-") for c in job_id)


def _odd_job_ids(workflow) -> list[str]:
    """Doubts about job ids GitHub may refuse, where its rule as known here does not settle it: a character
    outside ASCII, or an id of 100 characters or more."""
    raw_jobs = workflow.raw.get("jobs")
    doubts = []
    for job_id in raw_jobs if isinstance(raw_jobs, dict) else ():
        if not isinstance(job_id, str) or _bad_job_id(job_id):
            continue        # not text: the checker's own problem; a bad id: refused (_refused)
        shown = wf_mod.one_line(repr(job_id), 80)
        if not job_id.isascii():
            doubts.append(f"the job id {shown} has a character outside ASCII, and whether GitHub accepts such an "
                          "id is not established")
        elif len(job_id) >= JOB_ID_DOUBTFUL_LENGTH:
            doubts.append(f"the job id {shown} is {len(job_id)} characters long, and whether GitHub accepts an id "
                          f"of {JOB_ID_DOUBTFUL_LENGTH} or more is not established")
    return doubts


def _refused(workflow) -> str:
    """Why GitHub would refuse the file, for the ways this module knows of; empty when it knows none. It
    knows few: what it does not know is read as a file that runs."""
    raw_jobs = workflow.raw.get("jobs")
    if isinstance(raw_jobs, dict):
        for job_id in raw_jobs:
            # Checked for every job before anything else: an id outside GitHub's form is also how a problem's
            # text could imitate one HARMLESS_PROBLEM_RE lets through (issue #182), since the checker's
            # problems quote the id as written.
            if isinstance(job_id, str) and _bad_job_id(job_id):
                return (f"the job id {wf_mod.one_line(repr(job_id), 40)} is not in GitHub's form for one (a letter "
                        "or _, then letters, digits, _ or -)")
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
    """The path of the workflow file a job calls, when it is one in this repository: `./path`, or `$/path`,
    which the checker also reads as this repository (decision D-065; before issue #182 the audit took `$/` for
    another repository's workflow). `uses: ./` or `$/` alone gives "", the path of no file: a call to a file
    that was not read."""
    target = job["calls"] or ""
    return target[2:] if wf_mod.is_local_reference(target) else None


def self_repository_call(job: dict) -> bool:
    """Whether a job calls a workflow written with `$/`. GitHub's changelog of 2026-07-30 introduced `$/` for
    actions in the workflow's own repository; whether a job's `uses:` takes it for a reusable workflow was
    not established when this was written (issue #182), so such a call is never counted as one GitHub runs."""
    return (job["calls"] or "").startswith("$/")


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
        return [[(job["check"]["names"], job["doubt"]) for job in file["jobs"]] for file in by_path.values()]

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
            # A caller reports the names of the workflow it calls, so a doubt about that file is its doubt too.
            if called.get("doubt") or any(inner.get("doubt") for inner in called["jobs"]):
                note = f"it calls {called['path']}, which GitHub may read otherwise than the audit does"
                if note not in job["doubt"]:
                    job["doubt"] = job["doubt"] + [note]
            names: list[str] | None = []
            for inner in called["jobs"]:
                inner["called_from"] = sorted(set(inner["called_from"]) | set(reach))
                inner_names = inner["check"]["names"]
                prefixes = job["check"].get("prefixes")
                if names is None or inner_names is None or prefixes is None:
                    names = None
                elif len(names) + len(prefixes) * len(inner_names) > MAX_MATRIX_NAMES:
                    # Counted before the names are written out (flagship slice 2d.2g: 256 x 256 names per
                    # caller were built, then dropped).
                    names = None
                else:
                    names += [f"{prefix} / {inner_name}" for prefix in prefixes for inner_name in inner_names]
                    if inner["advisory"]:
                        advisory = job["check"].setdefault("advisory_names", [])
                        advisory += [f"{prefix} / {inner_name}" for prefix in prefixes for inner_name in inner_names
                                     if f"{prefix} / {inner_name}" not in advisory]
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
            continue
        if files[-1]["error"]:
            continue
        doubt = files[-1]["doubt"]
        if not (path.name.endswith((".yml", ".yaml")) and path.name not in (".yml", ".yaml")):
            doubt.append("its name is not NAME.yml or NAME.yaml in lower case, and whether GitHub runs such a file "
                         "is not established")
        if any(p.is_symlink() for p in (root / ".github", root / ".github" / "workflows", path)):
            doubt.append("it is, or is in, a symbolic link, and whether GitHub follows one is not established")
        for job in files[-1]["jobs"]:
            job["doubt"] = list(doubt)
    _resolve_calls(files)
    usage = {"format": FORMAT, "read": True, "reason": "", "root": str(root), "files": files, "config": None,
             "config_error": "",
             # GitHub's lockfile for actions (its changelog of 2026-10-28, as read by the review of slice
             # 2d.2g; not read here): a tag it locks may meet the pinning requirement.
             "actions_lock": (root / ".github" / "workflows" / "actions.lock").exists()}
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
