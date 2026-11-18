"""Agent tools as data (flagship slice 2d.5b, agent control R6).

``detection.yaml`` holds one entry per agent tool under ``agent_tools``: the actions that run it, the
command lines that run it, the packages and install scripts that install it, the inputs and options
that carry its prompt, and where each fact was read. The checker's older flat lists
(``agent_actions``, ``agent_commands``, ``agent_packages``, ``agent_installs`` and
``agent_install_urls``) are built from those entries when the catalogue is loaded, so the two can never
disagree. ``named_agents`` says which of the tools a job runs, for the agent rules' facts.

This module imports nothing from the checker, so the catalogue can load it.
"""

from __future__ import annotations

import datetime
import re

# Every key an entry may have, and the ones it must have.
FIELDS = ("id", "name", "read", "sources", "actions", "commands", "programs", "prompt_flags", "packages",
          "installs", "install_urls", "settings", "carried")
REQUIRED = ("id", "name", "read", "sources", "actions", "commands", "packages", "install_urls", "settings")
REGISTRIES = ("npm", "pypi")
ACTION_FIELDS = ("prompt_inputs",)
# The lists built from the entries. A detection file that still has one of them by hand is refused, so
# that a list and the entries cannot drift apart.
DERIVED = ("agent_actions", "agent_commands", "agent_packages", "agent_installs", "agent_install_urls")
_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,39}")
# An action as `uses:` names it, before the `@`: owner/repo, and a path in it.
_ACTION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*")


def tools(detection: dict) -> list:
    """The entries, as written (an empty list where there are none)."""
    value = detection.get("agent_tools")
    return value if isinstance(value, list) else []


def expand(detection: dict) -> dict:
    """The detection data with the flat lists built from `agent_tools`, in the entries' order and without
    repeats. A file with no `agent_tools` is returned as it is (a test may build its own)."""
    entries = tools(detection)
    if not entries or any(key in detection for key in DERIVED):
        return detection
    actions: list = []
    commands: list = []
    packages: list = []
    installs: dict = {}
    urls: list = []
    def listed(value) -> list:
        # A value of the wrong shape builds nothing here; `problems` names it, and `obaaf catalog` fails.
        return [str(v) for v in value] if isinstance(value, (list, dict)) else []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        actions += listed(entry.get("actions"))
        commands += listed(entry.get("commands"))
        given = entry.get("packages")
        for registry in REGISTRIES:
            packages += listed(given.get(registry)) if isinstance(given, dict) else []
        if isinstance(entry.get("installs"), dict):
            installs.update({str(k): str(v) for k, v in entry["installs"].items()})
        urls += listed(entry.get("install_urls"))
    out = dict(detection)
    out["agent_actions"] = list(dict.fromkeys(actions))
    out["agent_commands"] = list(dict.fromkeys(commands))
    out["agent_packages"] = list(dict.fromkeys(packages))
    out["agent_installs"] = installs
    out["agent_install_urls"] = list(dict.fromkeys(urls))
    return out


def problems(detection: dict) -> list[str]:
    """Every fault in the entries (empty when there is none): a missing or unknown key, an id that is not
    a short lower-case name or is given twice, an action, command, package or install script that two
    entries claim, a pattern Python cannot compile, an `installs` package the entry does not list, a
    source that is not an https address, and a flat list written by hand beside the entries."""
    out: list[str] = []
    entries = detection.get("agent_tools")
    if not isinstance(entries, list) or not entries:
        return ["detection: agent_tools must be a non-empty list"]
    for key in DERIVED:
        if key in detection:
            out.append(f"detection: {key} is built from agent_tools and must not be written by hand")
    owners: dict = {}

    def claim(kind: str, value: str, tool: str) -> None:
        key = (kind, value.lower() if kind == "action" else value)
        if key in owners and owners[key] != tool:
            out.append(f"agent tool {tool}: {kind} {value!r} is also {owners[key]}'s")
        owners.setdefault(key, tool)

    for number, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            out.append(f"agent_tools[{number}]: not a mapping")
            continue
        tool = str(entry.get("id", f"agent_tools[{number}]"))
        for key in REQUIRED:
            if key not in entry:
                out.append(f"agent tool {tool}: missing {key}")
        for key in entry:
            if key not in FIELDS:
                out.append(f"agent tool {tool}: unknown key {key!r}")
        if not isinstance(entry.get("id"), str) or not _ID_RE.fullmatch(entry["id"]):
            out.append(f"agent tool {tool}: id must be lower-case letters, digits and '-', at most 40")
        claim("id", tool, f"entry {number}")
        if not isinstance(entry.get("name"), str) or not entry.get("name", "").strip():
            out.append(f"agent tool {tool}: name must be text")
        read = entry.get("read")
        if not isinstance(read, datetime.date):
            out.append(f"agent tool {tool}: read must be a date (YYYY-MM-DD)")
        sources = entry.get("sources")
        if not isinstance(sources, list) or not all(isinstance(s, str) and s.startswith("https://") for s in sources):
            out.append(f"agent tool {tool}: sources must be a list of https addresses")
        actions = entry.get("actions")
        if not isinstance(actions, dict):
            out.append(f"agent tool {tool}: actions must be a mapping")
            actions = {}
        for action, spec in actions.items():
            if not isinstance(action, str) or not _ACTION_RE.fullmatch(action):
                out.append(f"agent tool {tool}: action {action!r} is not owner/repo or owner/repo/path")
                continue
            claim("action", action, tool)
            if not isinstance(spec, dict) or set(spec) - set(ACTION_FIELDS) or not isinstance(
                    spec.get("prompt_inputs", []), list) or not all(
                    isinstance(i, str) and i for i in spec.get("prompt_inputs", [])):
                out.append(f"agent tool {tool}: action {action}: expected {{prompt_inputs: [names]}}")
        for key in ("commands", "install_urls"):
            values = entry.get(key)
            if not isinstance(values, list):
                out.append(f"agent tool {tool}: {key} must be a list")
                continue
            for pattern in values:
                if not isinstance(pattern, str) or not pattern:
                    out.append(f"agent tool {tool}: {key}: {pattern!r} is not a pattern")
                    continue
                try:
                    re.compile(pattern)
                except re.error as exc:
                    out.append(f"agent tool {tool}: {key}: {pattern!r} does not compile: {exc}")
                claim(key[:-1], pattern, tool)
        for key in ("programs", "prompt_flags"):
            values = entry.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) and v and " " not in v for v in values):
                out.append(f"agent tool {tool}: {key} must be a list of words")
        packages = entry.get("packages")
        listed: set = set()
        if not isinstance(packages, dict) or set(packages) - set(REGISTRIES):
            out.append(f"agent tool {tool}: packages must map {' or '.join(REGISTRIES)} to lists of names")
        else:
            for registry, names in packages.items():
                if not isinstance(names, list) or not all(isinstance(n, str) and n and " " not in n for n in names):
                    out.append(f"agent tool {tool}: packages.{registry} must be a list of names")
                    continue
                for name in names:
                    claim("package", name, tool)
                    listed.add(name)
        installs = entry.get("installs", {})
        if not isinstance(installs, dict):
            out.append(f"agent tool {tool}: installs must be a mapping")
        else:
            for name, program in installs.items():
                if name not in listed:
                    out.append(f"agent tool {tool}: installs names {name!r}, which its packages do not list")
                if not isinstance(program, str) or program not in (entry.get("programs") or []):
                    out.append(f"agent tool {tool}: installs gives {name!r} the program {program!r}, "
                               "which its programs do not list")
        settings = entry.get("settings")
        if not isinstance(settings, list):
            out.append(f"agent tool {tool}: settings must be a list")
        carried = entry.get("carried", [])
        if not isinstance(carried, list) or not all(isinstance(c, str) and c.strip() for c in carried):
            out.append(f"agent tool {tool}: carried must be a list of text")
        if not actions and not entry.get("commands"):
            out.append(f"agent tool {tool}: has neither an action nor a command, so nothing finds it")
    return out


_COMPILED: dict = {}


def _compiled(detection: dict) -> list:
    """(id, action prefixes, compiled command patterns) for each entry, worked out once per data."""
    key = id(detection)
    cached = _COMPILED.get(key)
    if cached is not None and cached[0] is detection:
        return cached[1]
    out = []
    for entry in tools(detection):
        if isinstance(entry, dict) and isinstance(entry.get("id"), str):
            out.append((entry["id"], [str(a) for a in (entry.get("actions") or {})],
                        [re.compile(str(p), re.M) for p in (entry.get("commands") or [])]))
    if len(_COMPILED) >= 8:
        _COMPILED.clear()       # tests build their own data; the catalogue's is the one that matters
    _COMPILED[key] = (detection, out)
    return out


def named_agents(job, detection: dict, configured: dict | None = None) -> list[str]:
    """The agents a job runs that the checker can name, sorted: the `id` of each catalogue entry whose
    action a step uses or whose command a step's command lines match (`Step.agent_text`), in the job's
    own steps and in the steps of the local composite actions it uses (as `Job.local_steps` gives them,
    with the using step's inputs put in), in a reusable workflow the job calls by an agent action's name,
    and in the default shell `defaults.run.shell` gives its `run` steps; and, for a repository's own
    agents, `agents.actions: <prefix>` or `agents.commands: <pattern>` for each entry of the checker
    configuration that matches there. An agent found only in a repository script a step runs, or only by
    a lane declaration, is not named here (the `why` the agent rules give says how the job was found).
    A pattern matches anywhere in the text a step's command lines are read as, as the lanes are found, so
    a command written in an `echo` or a comment is read as run (the wider reading).

    The entries' patterns are compiled once for each detection mapping; a mapping changed after its first
    use keeps the patterns it had then."""
    configured = configured or {}
    entries = _compiled(detection)
    extra_actions = [str(a) for a in (configured.get("actions") or ())]
    extra_commands = [(str(p), re.compile(str(p), re.M)) for p in (configured.get("commands") or ())]
    every = [rx for _id, _a, rxs in entries for rx in rxs] + [rx for _p, rx in extra_commands]
    found: set = set()
    steps = list(job.steps)
    for inner in (getattr(job, "local_steps", None) or {}).values():
        steps.extend(inner)
    for step in steps:
        text = step.agent_text(every) if every else ""
        for tool, actions, rxs in entries:
            if any(step.uses_action(a) for a in actions) or (text and any(rx.search(text) for rx in rxs)):
                found.add(tool)
        found.update(f"agents.actions: {a}" for a in extra_actions if step.uses_action(a))
        found.update(f"agents.commands: {p}" for p, rx in extra_commands if text and rx.search(text))
    reusable = getattr(job, "reusable", None)
    if isinstance(reusable, str) and reusable:
        called = reusable.lower()
        for tool, actions, _rxs in entries:
            if any(called.startswith(a.lower()) for a in actions):
                found.add(tool)
        found.update(f"agents.actions: {a}" for a in extra_actions if called.startswith(a.lower()))
    for form in job.default_shell_forms():
        for tool, _actions, rxs in entries:
            if any(rx.match(form) for rx in rxs):
                found.add(tool)
        found.update(f"agents.commands: {p}" for p, rx in extra_commands if rx.match(form))
    return sorted(found)
