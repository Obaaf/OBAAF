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
          "installs", "install_urls", "settings", "flags", "carried")
REQUIRED = ("id", "name", "read", "sources", "actions", "commands", "packages", "install_urls", "settings")
REGISTRIES = ("npm", "pypi")
# `args_inputs`: the inputs an action hands to the tool's program as command-line options (flagship slice
# 2d.5c2a): `claude_args`, `codex-args`.
ACTION_FIELDS = ("prompt_inputs", "args_inputs")
# A setting the tool's own documentation warns about (flagship slice 2d.5c1, OBAAF-GHA-026): an input of
# one of the entry's actions, the values warned about (`equals`) or any value (`set: true`), and the words.
SETTING_FIELDS = ("id", "action", "input", "equals", "set", "severity", "read", "says", "source")
SETTING_REQUIRED = ("id", "action", "input", "severity", "read", "says", "source")
SEVERITIES = ("high", "medium", "low")
# A command-line option the tool's own files warn about (flagship slice 2d.5c2a, OBAAF-GHA-026): the option's
# spellings (`options`), the values warned about when it takes one (`equals`), and the words. It is read
# where the tool's program is run in a script and in the entry's actions' `args_inputs`.
FLAG_FIELDS = ("id", "options", "equals", "severity", "read", "says", "source")
FLAG_REQUIRED = ("id", "options", "severity", "read", "says", "source")
_OPTION_RE = re.compile(r"-[A-Za-z]|--[A-Za-z0-9][A-Za-z0-9-]*")
# A source is a file at a commit on GitHub, with the line or lines the words are on.
_SOURCE_RE = re.compile(r"https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/blob/[0-9a-f]{40}/[^#\s]+#L\d+(-L\d+)?")
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
            if not isinstance(spec, dict) or set(spec) - set(ACTION_FIELDS) or not all(
                    isinstance(spec.get(key, []), list) and all(isinstance(i, str) and i and i == i.strip()
                                                                for i in spec.get(key, []))
                    for key in ACTION_FIELDS):
                out.append(f"agent tool {tool}: action {action}: expected {{prompt_inputs: [names], "
                           "args_inputs: [names]}}")
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
        else:
            out.extend(_setting_problems(tool, settings, actions))
        flags = entry.get("flags", [])
        if not isinstance(flags, list):
            out.append(f"agent tool {tool}: flags must be a list")
        else:
            out.extend(_flag_problems(tool, flags, settings if isinstance(settings, list) else []))
            reads_args = any(isinstance(spec, dict) and spec.get("args_inputs") for spec in actions.values())
            if flags and not (entry.get("programs") or reads_args):
                out.append(f"agent tool {tool}: has flags but neither programs nor an action's args_inputs, "
                           "so nothing reads them")
        carried = entry.get("carried", [])
        if not isinstance(carried, list) or not all(isinstance(c, str) and c.strip() for c in carried):
            out.append(f"agent tool {tool}: carried must be a list of text")
        if not actions and not entry.get("commands"):
            out.append(f"agent tool {tool}: has neither an action nor a command, so nothing finds it")
    return out


def _setting_problems(tool: str, settings: list, actions: dict) -> list[str]:
    """The faults of one entry's `settings`: an unknown or missing key, an id that is not a short lower-case
    name or is given twice, an action the entry does not list, an input name that is not text, neither or
    both of `equals` and `set`, an `equals` that is not a list of text, an unknown severity, a date that
    is not one, words that are not text, and a source that is not a file at a commit with its lines."""
    out: list[str] = []
    seen: set = set()
    listed = {str(a).lower() for a in actions}
    for number, setting in enumerate(settings, start=1):
        name = f"agent tool {tool}: setting {number}"
        if not isinstance(setting, dict):
            out.append(f"{name}: not a mapping")
            continue
        sid = setting.get("id")
        if isinstance(sid, str):
            name = f"agent tool {tool}: setting {sid}"
        for key in SETTING_REQUIRED:
            if key not in setting:
                out.append(f"{name}: missing {key}")
        for key in setting:
            if key not in SETTING_FIELDS:
                out.append(f"{name}: unknown key {key!r}")
        if not isinstance(sid, str) or not _ID_RE.fullmatch(sid):
            out.append(f"{name}: id must be lower-case letters, digits and '-', at most 40")
        elif sid in seen:
            out.append(f"{name}: id is given twice")
        seen.add(sid)
        if str(setting.get("action", "")).lower() not in listed:
            out.append(f"{name}: action {setting.get('action')!r} is not one of the entry's actions")
        given = setting.get("input")
        if not isinstance(given, str) or not given.strip() or given != given.strip():
            out.append(f"{name}: input must be an input's name")
        has_equals, has_set = "equals" in setting, "set" in setting
        if has_equals == has_set:
            out.append(f"{name}: give either equals (the values warned about) or set: true")
        if has_equals and (not isinstance(setting["equals"], list) or not setting["equals"] or not all(
                isinstance(v, str) and v.strip() for v in setting["equals"])):
            out.append(f"{name}: equals must be a list of values written as text")
        if has_set and setting["set"] is not True:
            out.append(f"{name}: set must be true")
        if setting.get("severity") not in SEVERITIES:
            out.append(f"{name}: severity must be one of {', '.join(SEVERITIES)}")
        if not isinstance(setting.get("read"), datetime.date):
            out.append(f"{name}: read must be a date (YYYY-MM-DD)")
        if not isinstance(setting.get("says"), str) or not setting["says"].strip():
            out.append(f"{name}: says must be the documentation's words")
        if not isinstance(setting.get("source"), str) or not _SOURCE_RE.fullmatch(setting["source"]):
            out.append(f"{name}: source must be a file at a commit on GitHub, with its lines (#Ln or #Ln-Lm)")
    return out


def _flag_problems(tool: str, flags: list, settings: list) -> list[str]:
    """The faults of one entry's `flags`: an unknown or missing key, an id that is not a short lower-case
    name or is given twice (or is also a setting's), options that are not a list of option words or that
    another of the entry's flags also names, an `equals` that is not a list of text, an unknown severity, a
    date that is not one, words that are not text, and a source that is not a file at a commit with its lines."""
    out: list[str] = []
    seen = {s.get("id") for s in settings if isinstance(s, dict) and isinstance(s.get("id"), str)}
    named: dict = {}
    for number, flag in enumerate(flags, start=1):
        name = f"agent tool {tool}: flag {number}"
        if not isinstance(flag, dict):
            out.append(f"{name}: not a mapping")
            continue
        fid = flag.get("id")
        if isinstance(fid, str):
            name = f"agent tool {tool}: flag {fid}"
        for key in FLAG_REQUIRED:
            if key not in flag:
                out.append(f"{name}: missing {key}")
        for key in flag:
            if key not in FLAG_FIELDS:
                out.append(f"{name}: unknown key {key!r}")
        if not isinstance(fid, str) or not _ID_RE.fullmatch(fid):
            out.append(f"{name}: id must be lower-case letters, digits and '-', at most 40")
        elif fid in seen:
            out.append(f"{name}: id is given twice (a setting's and a flag's ids are one list)")
        seen.add(fid)
        options = flag.get("options")
        if not isinstance(options, list) or not options or not all(
                isinstance(o, str) and _OPTION_RE.fullmatch(o) for o in options):
            out.append(f"{name}: options must be a list of option words (-x or --name)")
        else:
            for option in options:
                key = option.lower()
                if key in named and named[key] != fid:
                    out.append(f"{name}: option {option} is also flag {named[key]}'s")
                named.setdefault(key, fid)
        if "equals" in flag and (not isinstance(flag["equals"], list) or not flag["equals"] or not all(
                isinstance(v, str) and v.strip() for v in flag["equals"])):
            out.append(f"{name}: equals must be a list of values written as text")
        if flag.get("severity") not in SEVERITIES:
            out.append(f"{name}: severity must be one of {', '.join(SEVERITIES)}")
        if not isinstance(flag.get("read"), datetime.date):
            out.append(f"{name}: read must be a date (YYYY-MM-DD)")
        if not isinstance(flag.get("says"), str) or not flag["says"].strip():
            out.append(f"{name}: says must be the documentation's words")
        if not isinstance(flag.get("source"), str) or not _SOURCE_RE.fullmatch(flag["source"]):
            out.append(f"{name}: source must be a file at a commit on GitHub, with its lines (#Ln or #Ln-Lm)")
    return out


def flag_readers(detection: dict) -> list:
    """For each well-formed entry with flags: (tool id, tool name, flags, programs, packages, args), where
    `args` maps each of the entry's actions that has `args_inputs` to those inputs. A fault is `problems`'
    to name; `obaaf catalog` fails on it."""
    out = []
    for entry in tools(detection):
        if not isinstance(entry, dict) or not isinstance(entry.get("flags"), list):
            continue
        flags = [f for f in entry["flags"] if isinstance(f, dict) and isinstance(f.get("id"), str) and isinstance(
            f.get("options"), list) and all(isinstance(o, str) for o in f["options"])]
        if not flags:
            continue
        programs = [str(p) for p in (entry.get("programs") or []) if isinstance(p, str)]
        given = entry.get("packages") if isinstance(entry.get("packages"), dict) else {}
        packages = [str(n) for names in given.values() if isinstance(names, list) for n in names]
        args = {str(a): [str(i) for i in spec.get("args_inputs", [])]
                for a, spec in (entry.get("actions") or {}).items()
                if isinstance(spec, dict) and isinstance(spec.get("args_inputs"), list) and spec["args_inputs"]}
        out.append((str(entry.get("id")), str(entry.get("name") or entry.get("id")), flags, programs, packages, args))
    return out


def settings(detection: dict) -> list:
    """Every entry's settings, in order, as (tool id, tool name, setting) for the entries and settings that
    are well formed (a fault is `problems`' to name; `obaaf catalog` fails on it)."""
    out = []
    for entry in tools(detection):
        if not isinstance(entry, dict) or not isinstance(entry.get("settings"), list):
            continue
        for setting in entry["settings"]:
            if isinstance(setting, dict) and isinstance(setting.get("action"), str) and isinstance(
                    setting.get("input"), str) and isinstance(setting.get("id"), str):
                out.append((str(entry.get("id")), str(entry.get("name") or entry.get("id")), setting))
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
    from obaaf.checker.workflow import matches_any     # the checker is loaded by now; the catalogue is not
    for step in steps:
        text = step.agent_text(every) if every else ""
        if text and not matches_any(every, text):
            text = ""       # no pattern matches anywhere: each tool's need not be tried (slice 2d.5b's cost)
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
