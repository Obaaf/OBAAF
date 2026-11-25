"""Preview and install a repository's first report-only GitHub Actions check."""

from __future__ import annotations

import difflib
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from stat import S_ISREG
from tempfile import NamedTemporaryFile

import yaml

from obaaf import agent_tools, checker, init_scanners
from obaaf.catalog import load
from obaaf.checker import CONFIG_LOCATIONS, repo
from obaaf.checker.egress import MODEL_KEYS
from obaaf.checker.workflow import one_line, parse, secret_names

WORKFLOW = ".github/workflows/obaaf-pipeline-check.yml"
PROVIDER_KEYS = frozenset(MODEL_KEYS) | {
    "META_API_KEY", "MODEL_API_KEY", "FIREWORKS_API_KEY", "BASETEN_API_KEY", "OPENROUTER_API_KEY",
    "MISTRAL_API_KEY", "COHERE_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY",
    "AZURE_OPENAI_API_KEY", "OPENAI_KEY", "CODEX_API_KEY",
    "ANTHROPIC_AUTH_TOKEN", "CLAUDE_API_KEY", "GEMINI_API_KEY", "COPILOT_PROVIDER_API_KEY",
}


def _read(path: Path) -> bytes | None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return None
    if not S_ISREG(mode):
        raise ValueError(f"{path} must be a regular file")
    return path.read_bytes()


def _read_workflows(root: Path) -> list:
    folder = root / ".github/workflows"
    read = []
    for path in sorted(folder.iterdir()) if folder.exists() else ():
        rel = path.relative_to(root).as_posix()
        if rel == WORKFLOW or not path.name.lower().endswith((".yaml", ".yml")):
            continue
        contents = _read(path)
        if contents is None:
            raise ValueError(f"{rel} disappeared during inspection")
        try:
            text = contents.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{rel} is not UTF-8 text (byte {error.start})") from None
        workflow = parse(rel, text)
        if workflow.error or workflow.problems:
            raise ValueError(f"{rel}: {workflow.error or workflow.problems[0]}")
        read.append((path, rel, workflow))
    return read


def _prepare(root: Path, read: list, catalog, config, unread: list) -> list:
    """The checker's own reading of `read` under `root`: callers, local actions and scripts."""
    actions = checker._agent_actions(catalog, config)
    commands = checker._script_commands(catalog, config)
    action_cache = {}
    step_state = {"agent": action_cache}
    # Give reusable workflows their caller context before checking scripts and local actions.
    checker._give_callers([(rel, workflow) for _, rel, workflow in read])
    declared = checker._LaneDeclarations(config, root, True, False, workflows_sought=True, jenkins_sought=False)
    return checker._prepare_workflows(read, root, root, config, declared, commands, actions,
                                      unread, action_cache, step_state)


def _agent_jobs(prepared: list, catalog, config) -> dict:
    """For each job the checker puts in the agent lane unaided, the job as classified."""
    found = {}
    for _, rel, workflow, errors in prepared:
        if errors:
            continue
        for job in workflow.jobs.values():
            classified = (checker.rules_mod.through_job(job, workflow, catalog.detection, config.agents)
                          if job.local_steps else job)
            if classified.in_lane("agent"):
                found[f"{rel}#{job.id}"] = classified
    return found


# A committed file larger than this is left out of the committed copy; a job the checker finds only
# through it is then declared.
_COMMITTED_LIMIT = 8 * 1024 * 1024


def _git_env() -> dict:
    # As `repo._run_git`: no GIT_* variable from the caller. A partial clone does not fetch the blobs
    # it lacks (git 2.44 and later read this); a missing blob is left out of the copy.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_NO_LAZY_FETCH"] = "1"
    return env


_GIT_OPTIONS = ["-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-c", "core.hooksPath=/dev/null"]


def _git(git: Path, root: Path, args: list, data: bytes = b"") -> bytes | None:
    """git's output for `args` at `root`, run as `repo._run_git` runs it, with `data` on its input."""
    try:
        done = subprocess.run([str(git), *_GIT_OPTIONS, *args], cwd=str(root), env=_git_env(), input=data,
                              capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _committed_copy(git: Path, root: Path, dest: Path) -> bool:
    """Write into `dest` the regular files of `root` as its last commit holds them, outside
    submodules: what a checkout of that commit writes, before any LFS or other filter. False when git
    cannot say.

    Review of #362: no link is written, so nothing written later can pass through one out of `dest`
    (a commit can list a link `l` and then a file `l/x`, and a case-insensitive file system reads `A`
    and `a/x` as one folder). A job the checker finds only through a link is then declared. Each file
    is created new, never followed or overwritten, and must stay inside `dest`."""
    listing = _git(git, root, ["ls-tree", "-r", "-z", "HEAD"])
    if listing is None:
        return False
    files = {}
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _, name = record.partition(b"\t")
        mode, kind, sha = meta.split(b" ")
        rel = Path(os.fsdecode(name))
        if rel.is_absolute() or ".." in rel.parts or not rel.parts:
            return False
        if kind == b"blob" and mode in (b"100644", b"100755"):
            files.setdefault(sha, []).append(rel)
    sizes = _git(git, root, ["cat-file", "--batch-check"], b"".join(sha + b"\n" for sha in files))
    if sizes is None:
        return False
    wanted = [fields[0] for fields in (line.split(b" ") for line in sizes.splitlines())
              if len(fields) == 3 and fields[1] == b"blob" and int(fields[2]) <= _COMMITTED_LIMIT]
    base = os.path.realpath(dest)
    with tempfile.TemporaryFile() as request:
        request.write(b"".join(sha + b"\n" for sha in wanted))
        request.seek(0)
        try:
            process = subprocess.Popen([str(git), *_GIT_OPTIONS, "cat-file", "--batch"], cwd=str(root),
                                       env=_git_env(), stdin=request, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL)
        except OSError:
            return False
        try:
            for _ in wanted:
                header = process.stdout.readline().split(b" ")
                if len(header) != 3 or header[1] != b"blob":
                    return False
                content = process.stdout.read(int(header[2]))
                process.stdout.read(1)
                for rel in files.get(header[0], ()):
                    target = dest / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    if os.path.commonpath([base, os.path.realpath(target.parent)]) != base:
                        return False
                    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
                    with os.fdopen(fd, "wb") as out:
                        out.write(content)
        finally:
            process.stdout.close()
            try:
                process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                return False
        return process.returncode == 0


def _committed_agent_jobs(root: Path, catalog, config) -> tuple[set, str] | None:
    """The jobs the checker puts in the agent lane from the files of the last commit, outside
    submodules, which is what the generated workflow checks once that commit is pushed, with the
    reason for any it could not read. None when `root` is in no Git work tree, where the folder is all
    there is.

    Review of #362: the folder can hold what that checkout will not: a script in a submodule, one Git
    ignores or does not track, an edit not yet committed, or a file an LFS filter turns from a pointer
    into its content. A job the checker finds only through such a file would get no declaration from
    init and no agent lane in CI."""
    if not any((folder / ".git").exists() for folder in (root, *root.parents)):
        return None
    git = repo.find_git(root)
    unread = "Git could not give the files of the last commit"
    if git is None:
        return set(), unread
    with tempfile.TemporaryDirectory() as tmp:
        copy = Path(tmp)
        try:
            if not _committed_copy(git, root, copy):
                return set(), unread
        except (ValueError, OSError):
            return set(), unread
        try:
            read = _read_workflows(copy)
        except (ValueError, OSError):
            return set(), "the checker could not read the workflows of the last commit"
        return set(_agent_jobs(_prepare(copy, read, catalog, config, []), catalog, config)), ""


def _proposal(root: Path, scanners: list[str]) -> tuple[dict[str, bytes], list[str]]:
    catalog = load()
    config = checker.Config()
    unread = []
    lanes = {}
    found_agent = False
    environments = defaultdict(set)
    notes = []
    unnamed_environments = set()
    untracked_evidence = []
    read = _read_workflows(root)
    prepared = _prepare(root, read, catalog, config, unread)
    for _, rel, workflow, errors in prepared:
        if errors:
            raise ValueError(errors[0])
    inferred_jobs = _agent_jobs(prepared, catalog, config)
    committed = _committed_agent_jobs(root, catalog, config) if inferred_jobs else None
    tracked_agents, unread_commit = committed if committed is not None else (None, "")
    for _, rel, workflow, errors in prepared:
        for job in workflow.jobs.values():
            key = f"{rel}#{job.id}"
            names = {name.upper() for name in job.secret_names()}
            steps = [*job.steps, *(step for inner in job.local_steps.values() for step in inner)]
            for inner in job.local_steps.values():
                for step in inner:
                    names.update(name.upper() for name in secret_names(step.raw))
            provider = names & PROVIDER_KEYS
            for env in [workflow.env, job.env, *(step.env for step in steps)]:
                if isinstance(env, dict):
                    provider.update(str(k) for k, v in env.items() if k in PROVIDER_KEYS and secret_names(v))
            tools = agent_tools.named_agents(job, catalog.detection)
            if not tools and job.agent_step_why:
                tools = sorted(set(job.agent_step_why.values()))
            classified = inferred_jobs.get(key)
            # Omitted only where the checker finds the agent in the last commit, too.
            inferred = classified is not None and (tracked_agents is None or key in tracked_agents)
            if classified is not None or tools or provider:
                found_agent = True
                if not inferred:
                    lanes[key] = "agent"
                if classified is not None and not inferred:
                    untracked_evidence.append(key)
                evidence = tools or ([classified.reason_for("agent")] if classified is not None else [])
                evidence += [f"references {name}" for name in sorted(provider)]
                notes.append(f"{key}: {', '.join(evidence)}")
            kind, value = job.environment_reading
            # A job that calls a reusable workflow cannot have an environment of its own, so an
            # environment written on it protects nothing (OBAAF-GHA-024 reports such a job).
            known = kind == "literal" and "workflow_call" not in workflow.triggers and not job.reusable
            environment = value if known else None
            for name in names:
                if name.startswith("*"):
                    notes.append(f"{key}: review access to unnamed or inherited secrets")
                    unnamed_environments.add(environment)
                else:
                    environments[name].add(environment)
    protected = {}
    for name, values in sorted(environments.items()):
        values = values | unnamed_environments
        # GitHub's secret names: letters, digits and underscores, not starting with a digit or
        # GITHUB_. Init also leaves names of fewer than three letters or digits to the team.
        valid_name = (re.fullmatch(r"[A-Z_][A-Z0-9_]*", name) and not name.startswith("GITHUB_")
                      and len(name.replace("_", "")) >= 3)
        if not valid_name:
            notes.append(f"Review {name}: init proposes rules only for secret names GitHub accepts "
                         "that have at least three letters or digits.")
        elif len(values) == 1 and None not in values:
            protected[name] = next(iter(values))
        else:
            notes.append(f"Review {name}: no single literal environment can be proposed.")
    notes.extend(checker._local_action_notes(unread))
    if untracked_evidence:
        why = (f"{unread_commit}, which is what the generated workflow checks" if unread_commit else
               "it does not find it in the files of the last commit outside submodules, which is what the "
               "generated workflow checks")
        notes.append("Declared as agent jobs although the checker finds their agent here, because "
                     + why + ": " + ", ".join(untracked_evidence))
    if not found_agent:
        notes.append("To create an agent workflow, start with GitHub Agentic Workflows: https://github.github.com/gh-aw/")
    config = yaml.safe_dump({"lanes": lanes, "protected_secrets": protected}, sort_keys=False)
    workflow_bytes = files("obaaf.data").joinpath("init-workflow.yaml").read_bytes()
    return {CONFIG_LOCATIONS[0]: config.encode("utf-8"), WORKFLOW: workflow_bytes + init_scanners.steps(scanners)}, notes


def _install(root: Path, missing: dict[str, bytes]) -> None:
    # Prepare complete files first, then link them into place without replacing an existing name.
    staged = {}
    linked = []
    umask = os.umask(0)
    os.umask(umask)
    try:
        for name, content in missing.items():
            dest = root / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile(dir=dest.parent, delete=False) as source:
                staged[dest] = Path(source.name)
                source.write(content)
            # A temporary file is private (0600); give the new file the mode any other new file gets.
            os.chmod(staged[dest], 0o666 & ~umask)
        for dest, source_path in staged.items():
            os.link(source_path, dest)
            linked.append(dest)
    except OSError:
        for dest in reversed(linked):
            if dest.exists() and dest.samefile(staged[dest]):
                dest.unlink()
        raise
    finally:
        for source_path in staged.values():
            source_path.unlink(missing_ok=True)


def _lines(text: str) -> list[str]:
    # Split at "\n" only, as diff does: str.splitlines also breaks at "\r", U+2028 and others.
    return re.findall(r"[^\n]*\n|[^\n]+\Z", text)


def _show_diff(old: bytes, proposed: bytes, old_name: str, new_name: str) -> None:
    before = _lines(old.decode("utf-8", "backslashreplace"))
    after = _lines(proposed.decode("utf-8"))
    for line in difflib.unified_diff(before, after, fromfile=old_name, tofile=new_name):
        print(one_line(line.removesuffix("\n")))
        if not line.endswith("\n"):
            print(r"\ No newline at end of file")


def _enclosing_work_tree(root: Path) -> Path | None:
    """The nearest folder above root that holds `.git`, when root itself holds none."""
    if os.path.lexists(root / ".git"):
        return None
    for parent in root.parents:
        if os.path.lexists(parent / ".git"):
            return parent
    return None


def _followup_command(prefix: str, command: str, path: str, root: Path) -> str:
    # init resolves links in the path it was given, as check does, but fix does not (#336 item 3):
    # through a link, `obaaf fix -- PATH` refuses the repository or reads another folder. Name the
    # folder init worked on instead (review-gpt #305).
    if Path(os.path.abspath(path)) != root:
        path = str(root)
    if path != one_line(path):
        return f"From inside the selected repository, run {command}"
    if path != ".":
        # zsh expands an unquoted =name before the CLI sees its option terminator.
        if path.startswith("="):
            path = "./" + path
        command += " -- " + shlex.quote(path)
    return prefix + command


def _handoff(root: Path, display_path: str, missing: dict[str, bytes], apply: bool) -> None:
    from obaaf.checker.report import to_summary
    from obaaf.fix_copy import PrivateCopyError, private_copy

    def summary(tree):
        result = checker.check(tree)
        result.checked = display_path
        return to_summary(result).rstrip()

    if missing and not apply:
        try:
            with private_copy(root) as tree:
                _install(tree, missing)
                text = summary(tree)
        except (PrivateCopyError, OSError) as exc:
            print("Could not simulate the proposed setup: " + one_line(exc))
            print("Current repository before applying either file:")
            text = summary(root)
        else:
            print("Proposed setup on a temporary copy:")
    else:
        text = summary(root)
        print("Current repository:")
    print(text)


def run(args) -> int:
    root = Path(args.path).resolve()
    try:
        if not root.is_dir():
            raise ValueError(f"{root} is not a repository directory")
        for folder in (root / ".github", root / ".github/workflows"):
            if folder.is_symlink() or (folder.exists() and not folder.is_dir()):
                raise ValueError(f"{folder} must be a directory inside the repository")
        proposal, notes = _proposal(root, args.with_scanner)
        if not args.with_scanner:
            print("Optional companion checks: run init with --with-scanner zizmor, --with-scanner actionlint "
                  "or --with-scanner poutine to preview their steps. Once the workflow exists, init reports "
                  "a conflict and shows the steps as a diff to copy into it.")
        top = _enclosing_work_tree(root)
        if top is not None:
            notes.insert(0, f"Note: {root} is inside the Git repository at {top}, and GitHub reads workflows "
                            f"only from a repository's top folder. To set up that repository, run obaaf init in {top}.")
        for note in notes:
            print(one_line(note))
        missing = {}
        conflict = False
        for alternate in CONFIG_LOCATIONS[1:]:
            existing = _read(root / alternate)
            if existing is None:
                continue
            conflict = True
            print(f"Conflict: existing checker configuration at {alternate}. "
                  f"Reconcile it with {CONFIG_LOCATIONS[0]} before applying.")
            if existing == proposal[CONFIG_LOCATIONS[0]]:
                print("The contents match. Creating another supported configuration would make the choice ambiguous.")
            else:
                _show_diff(existing, proposal[CONFIG_LOCATIONS[0]], alternate, CONFIG_LOCATIONS[0])
        for name, content in proposal.items():
            old = _read(root / name)
            if old == content:
                print(f"Already matches: {name}")
                continue
            if old is None:
                missing[name] = content
            else:
                print(f"Conflict: {name}")
                conflict = True
            _show_diff(old or b"", content, name if old is not None else "/dev/null", name)
        if conflict:
            print("Resolve the differences and preview again.", file=sys.stderr)
            return 1
        if args.apply:
            _install(root, missing)
            for name in missing:
                print(f"Wrote {name}")
        elif missing:
            print("Review both files, then run obaaf init with --apply to write them.")
        try:
            _handoff(root, args.path, missing, args.apply)
        except (OSError, ValueError) as exc:
            state = "Setup files installed." if missing and args.apply else "Setup review complete."
            print(f"{state} The follow-up summary was unavailable: {one_line(exc)}", file=sys.stderr)
            print(_followup_command("To check the current repository, run ", "obaaf check --summary", args.path, root))
        print(_followup_command("Preview available fixes with ", "obaaf fix", args.path, root))
        return 0
    except (OSError, ValueError) as error:
        print(f"error: {one_line(error)}", file=sys.stderr)
        return 2
