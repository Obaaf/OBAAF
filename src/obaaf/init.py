"""Preview and install a repository's first report-only GitHub Actions check."""

from __future__ import annotations

import difflib
import os
import re
import shlex
import sys
from collections import defaultdict
from importlib.resources import files
from pathlib import Path
from stat import S_ISREG
from tempfile import NamedTemporaryFile

import yaml

from obaaf import agent_tools, checker, init_scanners
from obaaf.catalog import load
from obaaf.checker import CONFIG_LOCATIONS
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


def _proposal(root: Path, scanners: list[str]) -> tuple[dict[str, bytes], list[str]]:
    folder = root / ".github/workflows"
    catalog = load()
    config = checker.Config()
    actions = checker._agent_actions(catalog, config)
    commands = checker._script_commands(catalog, config)
    action_cache = {}
    step_state = {"agent": action_cache}
    unread = []
    lanes = {}
    environments = defaultdict(set)
    notes = []
    unnamed_environments = set()
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
        errors = []
        checker._apply_local_action_detection(workflow, root, actions, commands, unread, errors, action_cache)
        checker._apply_local_action_steps(workflow, root, unread, errors, step_state)
        if errors:
            raise ValueError(errors[0])
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
            if tools or provider:
                lanes[key] = "agent"
                evidence = tools + [f"references {name}" for name in sorted(provider)]
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
    if not lanes:
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
