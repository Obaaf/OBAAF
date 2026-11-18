"""The OBAAF pipeline checker (`obaaf check`, FR12).

It reads GitHub Actions workflow files and repository settings that live in
files (CODEOWNERS, agent instruction files) and reports risky settings, each
with the profile requirement it threatens and the fix. It runs locally and
sends nothing over the network (NFR5).
"""

from __future__ import annotations

import fnmatch
import hashlib
import itertools
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path

from obaaf import yamlutil
from obaaf.catalog import Catalog, load
from obaaf.checker import acceptance as acceptance_mod
from obaaf.checker import egress as egress_mod
from obaaf.checker import expr as expr_mod
from obaaf.checker import jenkins as jenkins_mod
from obaaf.checker import repo as repo_checks
from obaaf.checker import rules as rules_mod
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import FIXED, Finding

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
CONFIG_LOCATIONS = (".github/obaaf.yml", ".github/obaaf.yaml", "obaaf.yml")
def _same_as_read(root: Path, rel: str) -> bool:
    """Whether a file is one the checker reads under another spelling, which a file system that ignores
    letter case gives for `.github/obaaf.yml` (`.github/OBAAF.yml` on macOS or Windows)."""
    for location in CONFIG_LOCATIONS:
        try:
            if (root / location).is_file() and os.path.samefile(root / location, root / rel):
                return True
        except OSError:
            continue
    return False


# Names a checker configuration may be given by mistake, in any letter case, at the root or in .github
# (flagship slice 2d.2f): the checker refuses to run beside one it would not read.
_CONFIG_LOOKALIKES = frozenset({"obaaf.yml", "obaaf.yaml", ".obaaf.yml", ".obaaf.yaml"})
# Words in a job id or name that suggest it runs an AI agent, used only to warn
# when such a job is not in the agent lane (never to classify it).
_AGENT_HINT = re.compile(r"agent|copilot|claude|gemini|codex|aider|opencode|cline|\bllm\b|\bai[-_ ]|autofix|auto[- ]fix",
                         re.I)


def parse_fail_on(spec: str) -> tuple[str | None, str]:
    """Parse a --fail-on value into (category, severity).

    Accepts 'never'; a bare severity ('high', 'medium' or 'low'); a category
    ('authority' or 'hygiene'), meaning that category at 'low' and above; or
    '<category>:<severity>'. Raises ValueError on anything else.
    """
    spec = str(spec).strip()
    if spec == "never":
        return (None, "never")
    if ":" in spec:
        cat, _, sev = spec.partition(":")
    elif spec in ("authority", "hygiene"):
        cat, sev = spec, "low"
    else:
        cat, sev = "", spec
    cat = cat or None
    if cat is not None and cat not in ("authority", "hygiene"):
        raise ValueError(f"--fail-on category must be 'authority' or 'hygiene', not {cat!r}")
    if sev not in ("high", "medium", "low"):
        raise ValueError(f"--fail-on must be high, medium, low, never, or <category>:<severity>, not {spec!r}")
    return (cat, sev)


_SCRIPT_REF = re.compile(r"(?<![\w./-])((?:\./)?[\w./-]+\.(?:sh|bash))\b")


def _script_targets(run_text: str) -> list[str]:
    """Script file paths a run step invokes (best-effort; paths with variables are skipped)."""
    out: list[str] = []
    for m in _SCRIPT_REF.finditer(run_text or ""):
        tok = m.group(1)
        if tok.startswith("./"):
            tok = tok[2:]
        if tok and tok not in out:
            out.append(tok)
    return out


def _copied_script_targets(run_text: str, root: Path) -> list[str]:
    """Map simple cp snapshots back to repository sources, without reading the destination.

    Variable names are symbolic: ${SNAPSHOT}/a and $SNAPSHOT/a name the same
    destination. No shell commands, substitutions or workflow expressions execute.
    Copy aliases are scoped to one run step; computed sources are not followed.
    """
    aliases: dict[str, Path] = {}
    targets: list[str] = []
    root = root.resolve()

    def normalize(value: str) -> str:
        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', r'$\1', value).rstrip('/')

    def source(value: str) -> Path | None:
        value = normalize(value)
        candidates = [path / value[len(alias):].lstrip('/') for alias, path in aliases.items()
                      if value == alias or value.startswith(alias + '/')]
        if '$' not in value:
            candidates.append(root / value)
        for path in candidates:
            try:
                path = path.resolve()
                if root in path.parents and path.exists():
                    return path
            except (OSError, RuntimeError):
                continue
        return None

    for line in run_text.splitlines():
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=';&|')
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            continue
        commands: list[list[str]] = [[]]
        for token in tokens:
            if token in (';', '&&', '||', '&', '|'):
                commands.append([])
            else:
                commands[-1].append(token)
        for command in commands:
            if not command:
                continue
            if command[0] == 'cp':
                args = [arg for arg in command[1:] if not arg.startswith('-')]
                if len(args) == 2:
                    original = source(args[0])
                    destination = normalize(args[1])
                    if original and destination:
                        aliases[destination] = original
                        # cp into an existing directory nests the source basename.
                        aliases[destination + '/' + original.name] = original
                continue
            if command[0] not in ('bash', 'sh', 'source', '.', 'exec', 'timeout', 'env') \
                    and not command[0].endswith(('.sh', '.bash')):
                continue
            for token in command:
                if token.endswith(('.sh', '.bash')):
                    original = source(token)
                    if original and original.is_file():
                        targets.append(original.relative_to(root).as_posix())
    return targets


def _agent_via_script(job, root: Path, commands: list) -> str | None:
    """A job whose run step calls a repository script that itself invokes an agent CLI is an agent
    job, whatever else it is (companion R1-R4). Only scripts readable under `root` are inspected, so this
    is best-effort; what it cannot read (fetched or generated scripts) is covered by the lane note.
    Every step found doing so is recorded on the job, for the egress control (OBAAF-GHA-020)."""
    if not commands:
        return None
    found = None
    for step in job.steps:
        run = step.run
        if step.confines and isinstance(step.with_.get("run"), str):
            run = step.with_["run"]     # the command OBAAF's egress action runs
        tok = _script_with_agent(root, run, commands)
        if tok:
            job.agent_script_steps.add(step.index)
            found = found or f"runs an agent in the script {tok}"
    return found


def _script_with_agent(root: Path, run: str, commands: list, memo: dict | None = None) -> str | None:
    """The first repository script a `run` text calls in which an agent CLI is found, by its path
    relative to `root`, or None. Only scripts readable under `root` are read; with `memo`, each script
    is searched once (local actions read many times call the same scripts)."""
    root_r = root.resolve()
    for tok in _script_targets(run) + _copied_script_targets(run, root_r):
        try:
            path = (root / tok).resolve()
            if path != root_r and root_r not in path.parents:
                continue
            if memo is not None and ("script", str(path)) in memo:
                if memo[("script", str(path))]:
                    return tok
                continue
            if not path.is_file():
                continue
            with path.open(encoding="utf-8", errors="replace") as script:
                text = script.read(200_000)
        except (OSError, RuntimeError):
            continue
        found = any(rx.search(text) for rx in commands)
        if memo is not None:
            memo[("script", str(path))] = found
        if found:
            return tok
    return None


# Flagship slice 2d.4a: how deep local actions are followed into each other. A chain deeper than this
# is named as not read rather than followed further.
LOCAL_ACTION_DEPTH = 10
# The largest action file read; a larger one is an error, as a workflow the checker cannot read is.
LOCAL_ACTION_BYTES = 1_000_000
# How much of local actions one check reads, in units: a reading of an action costs one, one for each
# of its steps and one for each 200 bytes of its files, and an action is read once for each set of
# values of the inputs its expressions read and of the environment it is given, and once more for each
# place a cycle or the depth cuts a reading short; the text a caller hands it costs one more for each
# 200 characters worked on. Beyond it the check stops reading them and fails with an error, so local
# actions that use each other many times over, with different inputs, cannot make the check run long
# or hide an agent in a job read after them.
LOCAL_ACTION_UNITS = 30_000
# And this many for each step of a job that uses a local action, spent only on what that step reads
# and not kept for another, so the bound grows with the repository (400 jobs that each give one action
# different inputs are not more than a check reads) and many cheap steps cannot buy a long reading for
# one heavy action. What that costs in time is measured in tests/test_local_composite_actions.py and
# stated in docs/checker-configuration.md.
LOCAL_ACTION_UNITS_PER_USE = 100
# The longest text a step of an action is read as once its inputs are put in; a longer one is read
# as written, and named as not read.
LOCAL_ACTION_TEXT = 200_000
# Where a composite action's own files are, as a step may write it: the expression in any letter case,
# with a dot or an index, and the runner's variable as the shell expands it.
_ACTION_PATH_EXPR_RE = re.compile(r"\$\{\{\s*github\s*(?:\.\s*action_path|\[\s*'action_path'\s*\])\s*\}\}", re.I)
_ACTION_PATH_VAR_RE = re.compile(r"\$\{GITHUB_ACTION_PATH(?:[^A-Za-z0-9_}][^}]*)?\}|\$GITHUB_ACTION_PATH(?![A-Za-z0-9_])")
_SHELL_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:[:]?[-=?+][^}]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
# The fields of a step `Step.agent_text` and the script reading read as command lines.
_COMMAND_FIELDS = ("run", "shell", "env", "with", "working-directory")


_READINGS = "readings"      # the counter's key in the cache, which no (folders, inputs, env) key can equal


_OWN = "own"                # what is left of the units of the step being read, which no other step may spend


def _charge(cache: dict, units: int) -> None:
    """Spend `units`: first from the step being read (`LOCAL_ACTION_UNITS_PER_USE`, which is not kept
    for another step), then from the check's shared `LOCAL_ACTION_UNITS`, past which reading stops."""
    own = cache.get(_OWN, 0)
    taken = min(own, units)
    cache[_OWN] = own - taken
    if units > taken:
        cache[_READINGS] = cache.get(_READINGS, 0) + units - taken
        if cache[_READINGS] > LOCAL_ACTION_UNITS:
            raise _ReadingsExceeded()


class _ReadingsExceeded(Exception):
    """More of local actions than one check reads (`LOCAL_ACTION_UNITS`)."""


@dataclass
class _ActionReading:
    """What reading a local action found: the agent, if one runs in it; what could not be read, as
    (the action as written, why) pairs; and whether the reading was cut short by the depth or by a
    cycle, in which case it is not kept for another use, where neither may apply."""
    agent: str | None = None
    unread: list = field(default_factory=list)
    cut: bool = False


def _is_local_like(uses) -> bool:
    """A `uses` that may name an action of the repository itself: `./`, `$/` or `.\\` at its start,
    after any space around it. `Step.is_local` takes only `./` and `$/` as written; how GitHub reads
    the other two forms is not established, so for an agent they are read as well."""
    return isinstance(uses, str) and uses.strip().startswith(("./", "$/", ".\\"))


def _local_action_folders(uses: str) -> tuple[list[str], str | None]:
    """The folders a local `uses` may name, relative to the repository, and why none can be read when
    there are none. Whether GitHub takes what follows an `@` as part of the path, and a backslash as a
    separator, is not established, so each reading is a candidate: the path as written, without what
    follows an `@`, and with backslashes as slashes."""
    path = uses.strip()[2:]
    if "${{" in path:
        return [], "its path holds an expression"
    candidates = [path]
    if "@" in path:
        candidates.append(path.split("@", 1)[0])
    candidates += [c.replace("\\", "/") for c in list(candidates) if "\\" in c]
    out = []
    for candidate in candidates:
        folder = posixpath.normpath(candidate.strip("/") or ".")
        if folder == ".." or folder.startswith("../"):
            return [], "its path leads outside the repository"
        if folder not in out:
            out.append(folder)
    return out, None


class _ActionFileError(ValueError):
    """An action file the checker cannot read as it reads a workflow: an error of the check."""


def _read_local_action(root: Path, folder: str) -> tuple[list, str | None]:
    """The metadata of the action in `folder` (both `action.yml` and `action.yaml` when both are there:
    which one GitHub takes is not established, so an agent in either counts), or ([], why) when there
    is none to read. An action file the checker cannot read as YAML it reads raises `_ActionFileError`,
    as a workflow it cannot read is an error."""
    root_r = root.resolve()
    prefix = "" if folder == "." else f"{folder}/"
    found = []
    for name in (f"{prefix}action.yml", f"{prefix}action.yaml"):
        try:
            real = (root / name).resolve()
            if real != root_r and root_r not in real.parents:
                return [], f"{name} leads outside the repository"
            if not real.is_file():
                continue
            with real.open("rb") as handle:
                data = handle.read(LOCAL_ACTION_BYTES + 1)
        except (OSError, RuntimeError) as exc:
            raise _ActionFileError(f"{name} cannot be read: {exc}") from None
        if len(data) > LOCAL_ACTION_BYTES:
            raise _ActionFileError(f"{name} is larger than the checker reads ({LOCAL_ACTION_BYTES} bytes)")
        text = data.decode("utf-8", errors="replace")
        for char, char_name in wf_mod._DISPUTED_BREAKS.items():
            if char in text:
                raise _ActionFileError(f"{name} contains the character {char_name}, which YAML readers do not "
                                       "agree is a line break")
        try:
            raw = yamlutil.load(text)
        except Exception as exc:       # YAML errors, duplicate keys
            raise _ActionFileError(f"{name}: cannot parse YAML: {wf_mod.one_line(str(exc), 200)}") from None
        if not isinstance(raw, dict):
            raise _ActionFileError(f"{name} is not an action (its top level is not a mapping)")
        try:
            odd = wf_mod._unreadable(raw)
        except RecursionError:
            odd = "nesting too deep to read"
        if odd:
            raise _ActionFileError(f"{name} contains a value the checker does not read ({odd})")
        found.append(raw)
    if not found:
        return [], "the repository has no action.yml or action.yaml there, so an earlier step may make it"
    return found, None


def _wraps(toks: list) -> bool:
    """Whether a pair of parentheses holds the whole of `toks`."""
    if len(toks) < 2 or toks[0] != ("op", "(") or toks[-1] != ("op", ")"):
        return False
    depth = 0
    for i, tok in enumerate(toks):
        if tok == ("op", "("):
            depth += 1
        elif tok == ("op", ")"):
            depth -= 1
            if depth == 0 and i != len(toks) - 1:
                return False
    return True


def _split_top(toks: list, by: str) -> list:
    """`toks` split where `||` or `&&` (`by="logic"`) or a comma (`by=","`) stands outside brackets."""
    parts: list = [[]]
    depth, i = 0, 0
    while i < len(toks):
        tok = toks[i]
        if tok in (("op", "("), ("op", "[")):
            depth += 1
        elif tok in (("op", ")"), ("op", "]")):
            depth -= 1
        if depth == 0 and by == "," and tok == ("op", ","):
            parts.append([])
            i += 1
            continue
        if depth == 0 and by == "logic" and tok in (("op", "|"), ("op", "&")) and i + 1 < len(toks) \
                and toks[i + 1] == tok:
            parts.append([])
            i += 2
            continue
        parts[-1].append(tok)
        i += 1
    return parts


_BOOLEAN_FUNCTIONS = frozenset({"contains", "startswith", "endswith", "success", "always", "failure", "cancelled"})
_COMPARISONS = frozenset({"=", "!", "<", ">"})
# How many pairs of parentheses around one operand are taken off; more is "not worked out".
_PAREN_LIMIT = 64


def _input_names(toks: list) -> list[str]:
    """The inputs a run of tokens reads (`inputs.name` or `inputs['name']`), by name in lower case;
    `["*"]` when it reads `inputs` some other way (`toJSON(inputs)`, a computed index)."""
    names, i = [], 0
    while i < len(toks):
        kind, text = toks[i]
        before = toks[i - 1] if i else None
        if kind == "id" and text.lower() == "inputs" and before != ("op", "."):
            if i + 2 < len(toks) and toks[i + 1] == ("op", ".") and toks[i + 2][0] == "id":
                names.append(wf_mod.input_name(toks[i + 2][1]))
            elif i + 3 < len(toks) and toks[i + 1] == ("op", "[") and toks[i + 2][0] == "str" \
                    and toks[i + 3] == ("op", "]"):
                names.append(wf_mod.input_name(toks[i + 2][1]))
            else:
                return ["*"]
        i += 1
    return names


_VALUE_LIMIT = 16      # values an expression is read as, and readings of one text; more is named in the note


def _capped(values: list, cut: list) -> list:
    """`values` without repeats, at most `_VALUE_LIMIT`; `cut` gets an entry when some are left out."""
    unique = list(dict.fromkeys(values))
    if len(unique) > _VALUE_LIMIT:
        cut.append(True)
    return unique[:_VALUE_LIMIT]


def _top_level_comparison(toks: list) -> bool:
    """Whether a comparison (`==`, `!=`, `<`, `>`, `!`) stands outside every bracket of `toks`."""
    depth = 0
    for kind, text in toks:
        if kind != "op":
            continue
        if text in "([":
            depth += 1
        elif text in ")]":
            depth -= 1
        elif depth == 0 and text in _COMPARISONS:
            return True
    return False


def _token_values(toks: list, inputs: dict, folder: str, depth: int = 0, env: dict | None = None,
                  cut: list | None = None) -> list[str] | None:
    """The texts an expression in a composite action's step can give, read the widest way, at most 16.
    An input, `github.action_path` and a literal are worked out; parentheses, `||` and `&&` (any operand
    can be the result) and `format()` are followed; a comparison or a function that gives true or false
    gives either; another reference to a context (`github.token`, `env.X`) gives nothing the checker
    knows, taken as empty; anything else that reads inputs gives each input it reads, and empty. None
    only when the expression is nested more deeply than the checker follows."""
    if depth > 8:
        return None
    lead = 0
    while lead < len(toks) and toks[lead] == ("op", "("):
        lead += 1
        if lead > _PAREN_LIMIT:
            return None
    while lead and _wraps(toks):
        toks = toks[1:-1]
        lead -= 1
    if not toks:
        return [""]
    parts = _split_top(toks, "logic")
    if len(parts) > 1:
        out: list = []
        for part in parts:
            values = _token_values(part, inputs, folder, depth + 1, env, cut)
            if values is None:
                return None
            out.extend(values)
        return _capped(out, cut if cut is not None else [])
    head = toks[0]
    if len(toks) == 1 and head[0] in ("str", "num"):
        return [head[1]]
    if len(toks) == 1 and head[0] == "id" and head[1].lower() in ("true", "false", "null"):
        return ["" if head[1].lower() == "null" else head[1].lower()]
    if head[0] == "id" and len(toks) in (3, 4):
        name = None
        if len(toks) == 3 and toks[1] == ("op", ".") and toks[2][0] == "id":
            name = toks[2][1]
        elif len(toks) == 4 and toks[1] == ("op", "[") and toks[2][0] == "str" and toks[3] == ("op", "]"):
            name = toks[2][1]
        if name is not None:
            if head[1].lower() == "inputs":
                return [inputs.get(wf_mod.input_name(name), "")]
            if head[1].lower() == "github" and name.lower() == "action_path":
                return [f"./{folder}"]
            if head[1].lower() == "env" and env:
                given = {str(k).upper(): v for k, v in env.items() if isinstance(v, (str, int, float, bool))}
                return [wf_mod.as_text(given.get(name.upper(), ""))]
            return [""]
    if head[0] == "id" and head[1].lower() == "format" and _wraps(toks[1:]):
        args = [_token_values(arg, inputs, folder, depth + 1, env, cut) for arg in _split_top(toks[2:-1], ",")]
        if args and all(values for values in args):
            out: list = []
            distinct: set = set()
            for count, choice in enumerate(itertools.product(*args)):
                if count >= 16 * _VALUE_LIMIT or len(distinct) > _VALUE_LIMIT:
                    # Combinations not made are values left out, whether or not the ones made repeat.
                    (cut if cut is not None else []).append(True)
                    break
                template = choice[0]
                for n, value in enumerate(choice[1:]):
                    template = template.replace("{" + str(n) + "}", value)
                out.append(template)
                distinct.add(template)
            return _capped(out, cut if cut is not None else [])
    if _top_level_comparison(toks) or (head[0] == "id" and head[1].lower() in _BOOLEAN_FUNCTIONS
                                       and _wraps(toks[1:])):
        return ["true", "false"]
    names = _input_names(toks)
    values = list(inputs.values()) if "*" in names else [inputs.get(name, "") for name in names]
    return _capped(values + [""], cut if cut is not None else [])


def _action_inputs(raw: dict, given: dict) -> dict:
    """An action's inputs as its steps see them: each `default` the action writes, replaced by what
    the step that uses it gives in `with:`, by name with A to Z in lower case (as `Step.with_` gives
    them). A default that is itself an expression is kept as written."""
    out: dict = {}
    declared = raw.get("inputs")
    for name, spec in (declared.items() if isinstance(declared, dict) else ()):
        default = spec.get("default") if isinstance(spec, dict) else None
        if isinstance(default, (str, int, float, bool)):
            out[wf_mod.input_name(name)] = wf_mod.as_text(default)
    for name, value in given.items():
        if isinstance(value, (str, int, float, bool)):
            out[wf_mod.input_name(name)] = wf_mod.as_text(value)
    return out


def _put_in(text: str, inputs: dict, folder: str, problems: list, env: dict | None = None) -> str:
    """`text` with what the checker can work out put in: each expression that reads the action's
    inputs (every value it can give, one reading per line, when there are several) and the action's
    own folder for `github.action_path`. An expression that reads an input in a way the checker does
    not work out is added to `problems`."""
    text = _ACTION_PATH_EXPR_RE.sub(lambda _m: f"./{folder}", text)
    if "${{" not in text:
        return text
    readings = [text]
    for body in dict.fromkeys(expr_mod.bodies(text)):
        whole = "${{" + body + "}}"
        if whole not in text or not re.search(r"\binputs\b|\benv\b|action_path", body, re.I):
            continue
        cut: list = []
        values = _token_values(expr_mod.tokens(body), inputs, folder, env=env, cut=cut)
        if values is None:
            problems.append(f"an expression that reads an input or the environment is nested more deeply than the "
                            f"checker works out ('{wf_mod.one_line(whole, 60)}')")
            continue
        readings = _capped([r.replace(whole, value) for r in readings for value in values], cut)
        if cut:
            problems.append(f"an expression that reads an input or the environment can give more than "
                            f"{_VALUE_LIMIT} texts, and the checker reads only {_VALUE_LIMIT} "
                            f"('{wf_mod.one_line(whole, 60)}')")
    out = "\n".join(dict.fromkeys(readings))
    if len(out) > LOCAL_ACTION_TEXT:
        problems.append("its inputs, put in, make a text longer than the checker reads")
        return text
    return out


def _put_inputs(value, inputs: dict, folder: str, problems: list, _done: dict | None = None, env: dict | None = None):
    """A step of a composite action with `_put_in` applied to every text it holds. A value YAML gives
    many times through an alias is worked on once (a file of a few kilobytes can name a million)."""
    done = {} if _done is None else _done
    if id(value) in done:
        return done[id(value)]
    if isinstance(value, str):
        out = _put_in(value, inputs, folder, problems, env)
    elif isinstance(value, dict):
        out = {}
        done[id(value)] = out
        for key, item in value.items():
            out[key] = _put_inputs(item, inputs, folder, problems, done, env)
    elif isinstance(value, list):
        out = []
        done[id(value)] = out
        out.extend(_put_inputs(item, inputs, folder, problems, done, env) for item in value)
    else:
        out = value
    done[id(value)] = out
    return out


def _with_env(step_raw: dict, env: dict) -> dict:
    """A composite step with the environment the step that uses the action gave (its `env`, which the
    action's steps inherit as the runner hands it on) under its own `env`, which wins."""
    if not env:
        return step_raw
    own = step_raw.get("env")
    merged = dict(env)
    if isinstance(own, dict):
        merged.update(own)
    return {**step_raw, "env": merged}


def _expand_variables(run: str, env: dict, problems: list) -> str:
    """`run` with each `$NAME` or `${NAME}` the step's `env` sets put in, for finding the scripts it
    runs (`P: ${{ github.action_path }}` and `bash "$P/agent.sh"`). A result longer than the checker
    reads is not used, and is added to `problems`."""
    values = {k: v for k, v in env.items() if isinstance(k, str) and isinstance(v, str)}
    if not values or "$" not in run:
        return run
    size = [len(run)]

    def put(match):
        value = values.get(match.group(1) or match.group(2), match.group(0))
        size[0] += len(value)
        if size[0] > LOCAL_ACTION_TEXT:
            raise OverflowError
        return value

    try:
        return _SHELL_VAR_RE.sub(put, run)
    except OverflowError:
        problems.append("its environment, put into a script, makes a text longer than the checker reads")
        return run


def _action_folder_script(root: Path, folder: str, run: str, workdir, commands: list,
                          memo: dict | None = None) -> str | None:
    """A script that `run` names relative to the action's own folder, or a folder under it, when the
    step's `working-directory` is there or its script changes to it (`cd "$GITHUB_ACTION_PATH"`, with
    `cd`'s options or `pushd`), in which an agent CLI is found."""
    if folder == ".":
        return None
    bases = []
    if isinstance(workdir, str):
        bases.append(workdir.strip().strip("\"'"))
    for match in re.finditer(r"(?:^|[;&|(\s])(?:cd|pushd)(?:\s+-\S*)*\s+[\"']?(\./" + re.escape(folder) +
                             r"(?:/[^\s\"';&|)]*)?)", run, re.M):
        bases.append(match.group(1))
    root_r = root.resolve()
    for base in dict.fromkeys(bases):
        where = posixpath.normpath(base.removeprefix("./") or ".")
        if where != folder and not where.startswith(folder + "/"):
            continue
        try:
            path = (root / where).resolve()
        except (OSError, RuntimeError):
            continue
        if root_r not in path.parents:
            continue
        tok = _script_with_agent(root / where, run, commands, memo)
        if tok:
            return f"{where}/{tok}"
    return None


def _agent_in_local_action(root: Path, uses: str, actions: list, commands: list, depth: int = 0,
                           seen: frozenset = frozenset(), cache: dict | None = None,
                           given: dict | None = None, given_env: dict | None = None) -> _ActionReading:
    """Whether the local action `uses` (`./path`, `$/path` or `.\\path`) runs an agent (flagship slice
    2d.4a). A composite action's steps are read for an agent as a job's steps are, with more put in: an
    agent action; an agent CLI in any command line `Step.agent_text` reads, with each expression that
    reads an input worked out from the `with:` of the step that uses the action (or else the action's
    `default`) and that step's `env` under the action step's own; a repository script a step runs,
    looked for from the repository's root and from the action's folder, with `github.action_path` and
    the step's `env` put in; and another local action, followed in turn. A JavaScript or Docker action,
    a missing file, a path that leads outside the repository, an input read in a way the checker does
    not work out, and a chain too deep or that comes back to itself are named as not read. A file the
    checker cannot read as YAML raises `_ActionFileError`, and too many readings `_ReadingsExceeded`.
    A `./` path is read in the repository as checked out; an action an earlier step writes or replaces
    there is not. A reading nothing cut short is kept in `cache` for every other use of the folder with
    the same inputs and environment."""
    out = _ActionReading()
    shown = wf_mod.one_line(uses, 120)
    folders, why = _local_action_folders(uses)
    if not folders:
        out.unread.append((shown, why))
        return out
    if depth >= LOCAL_ACTION_DEPTH:
        out.unread.append((shown, f"it is used through more than {LOCAL_ACTION_DEPTH} local actions"))
        out.cut = True
        return out
    if any(folder in seen for folder in folders):
        out.unread.append((shown, "it comes back to itself through the local actions it uses"))
        out.cut = True
        return out
    given = given or {}
    given_env = given_env or {}
    cache = {} if cache is None else cache
    files_key = ("files", tuple(folders))
    if files_key not in cache:
        raws: list = []
        missing = []
        for folder in folders:
            found, why = _read_local_action(root, folder)
            if found:
                raws.extend((folder, raw) for raw in found)
            else:
                missing.append(why)
        size = sum(_action_size(root, folder) for folder in folders)
        cache[files_key] = (raws, missing, _inputs_read(raw for _, raw in raws), size)
    raws, missing, read_names, size = cache[files_key]

    def fixed(mapping, names=None):
        return tuple(sorted((str(name), wf_mod.as_text(value)) for name, value in mapping.items()
                            if isinstance(value, (str, int, float, bool)) and (names is None or name in names)))

    # Only the inputs the action's own expressions read can change what is read of it, so a reading is
    # kept for every use that gives those the same values. The environment is kept whole: a further
    # local action may read any of it.
    key = (tuple(folders), fixed(given, None if "*" in read_names else read_names), fixed(given_env))
    context = (key, frozenset(seen), depth)
    for known in (key, context):
        if known in cache:
            return cache[known]
    cost = 1 + size // _BYTES_PER_UNIT + _UNITS_PER_STEP * sum(
        len(raw["runs"]["steps"]) if isinstance(raw.get("runs"), dict) and isinstance(raw["runs"].get("steps"), list)
        else 1 for _, raw in raws)
    _charge(cache, cost)
    if not raws:
        out.unread.append((shown, "; ".join(dict.fromkeys(missing))))
    for folder, raw in raws:
        runs = raw.get("runs")
        using = runs.get("using") if isinstance(runs, dict) else None
        kind = using.strip().lower() if isinstance(using, str) else None
        if kind != "composite":
            if kind and kind.startswith("node"):
                what = "a JavaScript action, whose code the checker does not read"
            elif kind == "docker":
                what = "a Docker action, whose container the checker does not read"
            else:
                what = "an action whose `runs.using` is not one the checker reads"
            out.unread.append((shown, f"it is {what}"))
            continue
        steps = runs.get("steps")
        if not isinstance(steps, list):
            out.unread.append((shown, "its `runs.steps` is not a list of steps"))
            continue
        inputs = _action_inputs(raw, given)
        for number, step_raw in enumerate(steps, start=1):
            if not isinstance(step_raw, dict):
                out.unread.append((shown, f"its step {number} is not a mapping"))
                continue
            problems: list = []
            put, done, ignored = {}, {}, {}
            merged = _with_env(step_raw, given_env)
            # The step's `env` first, with its inputs put in, so `${{ env.T }}` elsewhere reads what GitHub
            # gives it (`T: ${{ inputs.tool }}`).
            step_env = merged.get("env") if isinstance(merged.get("env"), dict) else {}
            if step_env:
                step_env = _put_inputs(step_env, inputs, folder, problems, {}, step_env)
            for key_name, value in merged.items():
                if key_name == "env":
                    put[key_name] = step_env
                elif key_name in _COMMAND_FIELDS:
                    put[key_name] = _put_inputs(value, inputs, folder, problems, done, step_env)
                else:
                    put[key_name] = _put_inputs(value, inputs, folder, [], ignored, step_env)
            step = wf_mod.Step(index=number - 1, raw=put, line=getattr(step_raw, "line", 0))
            # What a caller hands the action (the text its inputs add) is worked on again at each reading,
            # so it is paid for too; the action's own text is in the size of its files.
            added = (sum(_text_size(put.get(name)) for name in _COMMAND_FIELDS)
                     - sum(_text_size(merged.get(name)) for name in _COMMAND_FIELDS))
            _charge(cache, max(0, added) // _BYTES_PER_UNIT)
            out.unread.extend((shown, f"step {number}: {problem}") for problem in dict.fromkeys(problems))
            where = f"step '{wf_mod.one_line(step.name, 80)}' of the local action {shown}"
            if out.agent is None:
                prefix = next((p for p in actions if step.uses_action(p)), None)
                if prefix is not None:
                    out.agent = f"uses {step.action} in the local action {shown}"
            if out.agent is None:
                text = step.agent_text(commands)
                if text and any(rx.search(text) for rx in commands):
                    out.agent = f"runs an agent CLI in {where}"
            if out.agent is None and step.run:
                expand_problems: list = []
                run = _ACTION_PATH_VAR_RE.sub(f"./{folder}", _expand_variables(step.run, step.env, expand_problems))
                out.unread.extend((shown, f"step {number}: {problem}") for problem in expand_problems)
                tok = _script_with_agent(root, run, commands, cache) or _action_folder_script(
                    root, folder, run, step.raw.get("working-directory"), commands, cache)
                if tok:
                    out.agent = f"runs an agent in the script {tok}, from {where}"
            raw_uses = step_raw.get("uses")
            if _is_local_like(raw_uses) and "${{" in raw_uses:
                out.unread.append((wf_mod.one_line(raw_uses, 120), "its path holds an expression"))
            elif _is_local_like(step.uses):
                inner = _agent_in_local_action(root, step.uses, actions, commands, depth + 1,
                                               seen | set(folders), cache, step.with_, step.env)
                out.unread.extend(inner.unread)
                out.cut = out.cut or inner.cut
                out.agent = out.agent or inner.agent
    # A reading a cycle or the depth cut short is kept only for a use in the same place in a chain.
    cache[context if out.cut else key] = out
    return out


# A reading costs one unit, three for each step it reads (a step costs about three times as much to read
# as 200 bytes of text, measured by the review) and one for each this many bytes of its files.
_BYTES_PER_UNIT = 200
_UNITS_PER_STEP = 3


def _text_size(value) -> int:
    """The characters of the text a step's field holds: a string, or the strings of a mapping's values."""
    if isinstance(value, str):
        return len(value)
    if isinstance(value, dict):
        return sum(len(item) for item in value.values() if isinstance(item, str))
    return 0


def _action_size(root: Path, folder: str) -> int:
    """The bytes of the action files in `folder`, as `_read_local_action` read them."""
    prefix = "" if folder == "." else f"{folder}/"
    total = 0
    for name in (f"{prefix}action.yml", f"{prefix}action.yaml"):
        try:
            total += min((root / name).stat().st_size, LOCAL_ACTION_BYTES)
        except (OSError, RuntimeError):
            continue
    return total


def _inputs_read(raws) -> set:
    """The inputs the expressions in action files read, by name in lower case, with `*` when one reads
    `inputs` in another way (`toJSON(inputs)`, a computed index). Each value is visited once, however
    many times YAML names it through an alias."""
    names: set = set()
    seen: set = set()
    stack = list(raws)
    while stack:
        value = stack.pop()
        if isinstance(value, (dict, list)):
            if id(value) not in seen:
                seen.add(id(value))
                stack.extend(value.values() if isinstance(value, dict) else value)
        elif isinstance(value, str) and "${{" in value:
            for body in expr_mod.bodies(value):
                names.update(_input_names(expr_mod.tokens(body)))
    return names


def _apply_local_action_detection(workflow, root: Path | None, actions: list, commands: list,
                                  unread: list, errors: list, cache: dict | None = None) -> None:
    """Put a job whose agent runs inside a local action in the agent lane, and record the step for
    the egress control, as `_apply_script_detection` does for a script (flagship slice 2d.4a). With
    no `root` (a file checked on its own, whose repository the checker does not know), every local
    action is named as not read. What could not be read is added to `unread` as (file, job, action,
    why). An action file the checker cannot read as YAML, more readings than one check makes, and
    nesting too deep for Python are added to `errors`, which fail the check, as a workflow file the
    checker cannot read does: the action's author writes it as freely as the workflow's."""
    cache = {} if cache is None else cache
    for job in workflow.jobs.values():
        for step in job.steps:
            if not _is_local_like(step.uses):
                continue
            shown = wf_mod.one_line(step.uses, 120)
            if root is None:
                unread.append((workflow.path, job.id, shown,
                               "the file was checked on its own, so its repository's actions were not read"))
                continue
            where = f"{workflow.path}: job '{wf_mod.one_line(job.id, 60)}' uses the local action {shown}, and"
            cache[_OWN] = LOCAL_ACTION_UNITS_PER_USE
            try:
                reading = _agent_in_local_action(root, step.uses, actions, commands, cache=cache, given=step.with_,
                                                 given_env=step.env)
            except _ActionFileError as exc:
                errors.append(f"{where} {wf_mod.one_line(str(exc), 300)}, so the checker cannot tell whether an "
                              "agent runs in it")
                continue
            except _ReadingsExceeded:
                if not cache.get(_EXCEEDED):
                    cache[_EXCEEDED] = True
                    errors.append(f"{where} reading the check's local actions would cost more than the "
                                  f"units the check spends on them ({LOCAL_ACTION_UNITS} for the check, and "
                                  f"{LOCAL_ACTION_UNITS_PER_USE} for each step that uses one, for that step alone; a "
                                  "reading costs one, three "
                                  "for each step read and one for each 200 bytes of its files or of text its caller "
                                  "hands it, and an action is read once for each set of inputs and environment it is "
                                  "given), so the checker stopped reading them and cannot tell whether an agent runs "
                                  "in them")
                continue
            except (RecursionError, MemoryError):
                errors.append(f"{where} it is too deeply nested or too large to read, so the checker cannot tell "
                              "whether an agent runs in it")
                continue
            unread.extend((workflow.path, job.id, action, why) for action, why in reading.unread)
            if reading.agent:
                job.agent_script_steps.add(step.index)
                job.agent_step_why.setdefault(step.index, reading.agent)
                if not job.in_lane("agent"):
                    job.add_lane("agent", reading.agent)


_EXCEEDED = "exceeded"      # in the cache: the error for too many readings is given once per check


def _local_action_notes(unread: list) -> list[str]:
    """One advisory note naming the local actions that could not be read through, never a finding:
    whether such an action runs an agent is not known, and taking every one for an agent would report
    every job that uses one."""
    if not unread:
        return []
    unique = list(dict.fromkeys(unread))
    shown = "; ".join(f"{action} in {wf_mod.one_line(path, 120)} job '{wf_mod.one_line(job, 60)}' "
                      f"({wf_mod.one_line(why, 200)})"
                      for path, job, action, why in unique[:5])
    more = f"; and {len(unique) - 5} more" if len(unique) > 5 else ""
    return [f"Local actions were not read through in {len(unique)} place(s), so an agent run inside them does not "
            f"put the job in the agent lane: {shown}{more}. If one runs an AI agent, set OBAAF_LANE: agent on its job, "
            "or declare the agent's command in agents.commands in .github/obaaf.yml (docs/checker-configuration.md)."]


def _agent_actions(catalog: "Catalog", config: "Config") -> list:
    return list(catalog.detection.get("agent_actions", [])) + list(config.agents.get("actions", ()) or ())


def _script_commands(catalog: "Catalog", config: "Config") -> list:
    patterns = list(catalog.detection.get("agent_commands", [])) + list(config.agents.get("commands", ()) or ())
    return [re.compile(p, re.M) for p in patterns]


def _apply_script_detection(workflow, root: Path, commands: list) -> None:
    for job in workflow.jobs.values():
        reason = _agent_via_script(job, root, commands)
        if reason and not job.in_lane("agent"):
            job.add_lane("agent", reason)


class ConfigError(ValueError):
    pass


_SECRET_NAME = re.compile(r"^[A-Za-z_*?][A-Za-z0-9_*?]*$")
CONFIG_KEYS = frozenset({"lanes", "agents", "ignore", "jenkins", "protected_secrets"})


def parse_protected_secrets(value, path) -> dict:
    """protected_secrets: a list of secret names (any declared environment will do), or a mapping of
    secret name to the environment that must hold it. Names may use * and ? globs; secret names are
    case-insensitive in GitHub, so they are compared in upper case."""
    if value is None:
        return {}
    if isinstance(value, list):
        pairs = [(name, None) for name in value]
    elif isinstance(value, dict):
        pairs = list(value.items())
    else:
        raise ConfigError(f"{path}: protected_secrets must be a list of secret names or a mapping of secret "
                          "name to environment")
    out: dict = {}
    for name, env in pairs:
        if not isinstance(name, str) or not _SECRET_NAME.match(name):
            raise ConfigError(f"{path}: protected_secrets entry {name!r} is not a secret name (letters, digits, "
                              "underscores, and * or ? globs)")
        if len(re.sub(r"[*?_]", "", name)) < 3:
            raise ConfigError(f"{path}: protected_secrets entry {name!r} is too broad; name at least three letters "
                              "or digits (for example *_API_KEY)")
        if name.upper() == "GITHUB_TOKEN":
            raise ConfigError(f"{path}: GITHUB_TOKEN is not a stored secret; protected_secrets cannot list it")
        if env is not None and (not isinstance(env, str) or not env.strip() or "${{" in env):
            raise ConfigError(f"{path}: protected_secrets environment for {name!r} must be a literal "
                              "environment name")
        if name.upper() in out:
            # Secret names are one name to GitHub whatever their case, so two entries for one name
            # would be one entry here, and which environment applied would depend on their order.
            raise ConfigError(f"{path}: protected_secrets names {name!r} twice (secret names do not differ by "
                              "case); write it once, with the environment it needs")
        out[name.upper()] = env.strip() if isinstance(env, str) else None
    return out


@dataclass
class Config:
    lanes: dict = field(default_factory=dict)
    agents: dict = field(default_factory=dict)
    ignore: list = field(default_factory=list)
    path: str | None = None
    jenkins: dict = field(default_factory=dict)
    # Secret name (upper case, glob allowed) -> the environment that must hold it, or None for any
    # declared environment.
    protected_secrets: dict = field(default_factory=dict)
    lane_lines: dict = field(default_factory=dict)      # `lanes:` key -> the line it is written on

    @classmethod
    def load(cls, root: Path, explicit: str | None = None) -> "Config":
        candidates = [Path(explicit)] if explicit else [root / rel for rel in CONFIG_LOCATIONS]
        if not explicit:
            # Only the first would be read, and every lane, acceptance and protected secret in the others
            # would be dropped without a word (flagship slice 2d.2f; D-044 named it as unreported).
            present = [rel for rel in CONFIG_LOCATIONS if (root / rel).is_file()]
            if len(present) > 1:
                raise ConfigError(f"{root}: more than one checker configuration ({', '.join(present)}); the checker "
                                  f"reads one, so keep one of them")
            # A file named like a configuration where the checker does not look would be ignored without a
            # word, its lanes and protected secrets with it.
            for folder in ("", ".github"):
                try:
                    names = os.listdir(root / folder) if (root / folder).is_dir() else []
                except OSError:
                    names = []
                for name in names:
                    rel = f"{folder}/{name}" if folder else name
                    if name.lower() in _CONFIG_LOOKALIKES and rel not in CONFIG_LOCATIONS and (root / rel).is_file() \
                            and not _same_as_read(root, rel):
                        raise ConfigError(f"{root}: {rel} looks like a checker configuration, and the checker does not "
                                          f"read it (it reads {', '.join(CONFIG_LOCATIONS)}); rename or remove it")
        for path in candidates:
            if path.is_file():
                try:
                    data = yamlutil.load_file(path)
                except Exception as exc:    # YAML errors, duplicate keys, text that is not UTF-8
                    raise ConfigError(f"{path}: cannot be read as YAML: {exc}") from exc
                return cls.from_data(data or {}, path)
        if explicit:
            raise ConfigError(f"config file not found: {explicit}")
        return cls()

    @classmethod
    def from_data(cls, data, path) -> "Config":
        """A configuration from parsed YAML; `path` names it in error messages."""
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: expected a mapping")
        unknown = sorted(str(k) for k in data if k not in CONFIG_KEYS)
        if unknown:
            # A misspelt key (protected-secrets) would otherwise turn a control off without a word.
            raise ConfigError(f"{path}: unknown setting(s) {', '.join(unknown)}; the checker reads "
                              f"{', '.join(sorted(CONFIG_KEYS))}")
        ignore = data.get("ignore") or []
        for entry in ignore:
            if not isinstance(entry, dict):
                raise ConfigError(f"{path}: every ignore entry must be a mapping")
            for key in ("rule", "path", "reason", "until"):
                if not entry.get(key):
                    raise ConfigError(f"{path}: every ignore entry needs rule, path, reason and until; "
                                      f"missing {key!r} in {dict(entry)}")
            if not re.sub(r"[*?/\[\]!]", "", str(entry["path"])).strip("."):
                raise ConfigError(f"{path}: ignore path {entry['path']!r} matches everything; name the "
                                  "workflow file the finding is in")
            if entry["rule"] == IDLE_DECLARATION:
                # An ignore entry accepts a rule in a file, whatever the finding says. For this rule
                # that is every lane declaration in the file, including ones not written yet.
                raise ConfigError(f"{path}: an ignore entry cannot accept {IDLE_DECLARATION}. It would cover every "
                                  "lane declaration in the file it names, whatever each is later changed to. "
                                  "Correct the declaration, or accept that one declaration with a baseline entry "
                                  "(obaaf check --write-baseline FILE --owner OWNER --reason REASON --expires "
                                  "YYYY-MM-DD), which names its key and its value")
            if acceptance_mod.parse_date(entry["until"]) is None:
                # A date and nothing else: a time of day cannot be compared with today, and other
                # spellings of a date were read by some Python versions and not by others.
                raise ConfigError(f"{path}: ignore entry 'until' must be a date (YYYY-MM-DD), not "
                                  f"{str(entry['until'])[:40]!r}")
        jenkins = data.get("jenkins") or {}
        if not isinstance(jenkins, dict) or not isinstance(jenkins.get("files") or [], list) or \
                not isinstance(jenkins.get("exclude") or [], list):
            raise ConfigError(f"{path}: jenkins must be a mapping, and jenkins.files and jenkins.exclude "
                              "lists of globs")
        agents = data.get("agents") or {}
        if not isinstance(agents, dict) or not isinstance(agents.get("steps") or [], list):
            raise ConfigError(f"{path}: agents must be a mapping, and agents.steps a list of step names")
        lanes = data.get("lanes") or {}     # left empty, it declares nothing
        if not isinstance(lanes, dict):
            raise ConfigError(f"{path}: lanes must be a mapping of a workflow file, or 'file#job', to a lane")
        return cls(lanes=dict(lanes), agents=dict(agents), ignore=list(ignore),
                   path=str(path), jenkins=dict(jenkins),
                   protected_secrets=parse_protected_secrets(data.get("protected_secrets"), path),
                   lane_lines={key: wf_mod.key_line(lanes, key, 1) for key in lanes})


@dataclass
class CheckResult:
    findings: list[Finding]
    files: list[str]
    errors: list[str]
    config: Config
    notes: list[str] = field(default_factory=list)
    jenkins_files: list[str] = field(default_factory=list)   # the subset of files checked as Jenkinsfiles
    coverage: list[dict] = field(default_factory=list)       # per Jenkinsfile and rule: pass/fail/unknown/...
    jenkins: list[dict] = field(default_factory=list)        # per Jenkinsfile: kind, digest, file-wide unknowns
    baseline_used: bool = False                              # set by baseline.apply
    baseline_stale: list[dict] = field(default_factory=list) # baseline entries no finding matched
    baseline_format: str = ""                                # the format of the baseline that was applied
    baseline_path: str = ""
    checked: str = ""                                        # the path the command line asked to check
    options: list[str] = field(default_factory=list)         # --config and --platform as the command line gave them
    today: date | None = None                                # the day acceptances were judged against

    @property
    def workflow_files(self) -> list[str]:
        return [f for f in self.files if f not in set(self.jenkins_files)]

    def active(self) -> list[Finding]:
        """Findings that are neither ignored by configuration nor fixed by verified controls."""
        return [f for f in self.findings if not f.suppressed and f.state != FIXED]

    def cleared(self) -> list[Finding]:
        """Findings whose every control the checker verified. They are shown, and fail nothing."""
        return [f for f in self.findings if f.state == FIXED]

    def not_accepted(self) -> list[Finding]:
        """Findings that an ignore entry or a baseline entry names without accepting them: the entry
        lacks an owner, a reason or an expiry date, has expired, or expires too far ahead."""
        return [f for f in self.findings
                if f.state != FIXED and f.acceptance is not None and not f.acceptance.valid]

    def at_or_above(self, severity: str) -> list[Finding]:
        threshold = SEVERITY_ORDER[severity]
        return [f for f in self.active() if SEVERITY_ORDER[f.severity] >= threshold]

    def stale_gating(self, spec: str, catalog: Catalog) -> list[dict]:
        """Baseline entries no finding matched that make `--fail-on spec` fail: the same threshold and
        category as findings, so a vanished low finding does not fail `--fail-on high`."""
        category, severity = parse_fail_on(spec)
        if severity == "never":
            return []
        threshold = SEVERITY_ORDER[severity]
        out = []
        for entry in self.baseline_stale:
            if SEVERITY_ORDER.get(entry.get("severity"), 0) < max(threshold, 1):
                continue
            rule = catalog.rules.get(entry.get("rule"), {})
            if category is not None and (rule.get("category") or "authority") != category:
                continue
            out.append(entry)
        return out

    def gating(self, spec: str, catalog: Catalog, findings: list[Finding] | None = None) -> list[Finding]:
        """Active findings that make `--fail-on spec` fail (empty means it passes). With `findings`,
        those of them that would: what `--write-baseline` leaves out is judged so (slice 3.2b)."""
        category, severity = parse_fail_on(spec)
        if severity == "never":
            return []
        threshold = SEVERITY_ORDER[severity]
        out = []
        for f in (self.active() if findings is None else findings):
            if f.suppressed or f.state == FIXED:
                continue
            if f.baselined:
                continue
            if SEVERITY_ORDER[f.severity] < threshold:
                continue
            if category is not None and (catalog.rules[f.rule].get("category") or "authority") != category:
                continue
            out.append(f)
        return out


def _apply_ignores(findings: list[Finding], config: Config, today: date) -> None:
    """Apply the configuration's ignore entries. An entry is an acceptance, and only a valid one
    (owner, reason, an expiry date not passed and at most a year ahead) ignores a finding. An entry
    that matches and is not valid is attached to the finding, so the report can say what it lacks."""
    for finding in findings:
        if finding.rule == IDLE_DECLARATION:
            continue    # accepted by a baseline entry only, which names the one declaration (see Config.from_data)
        for entry in config.ignore:
            if entry["rule"] != finding.rule or not fnmatch.fnmatch(finding.path, str(entry["path"])):
                continue
            if entry.get("job") and entry["job"] != finding.job:
                continue
            until = acceptance_mod.parse_date(entry["until"])
            made = acceptance_mod.make(acceptance_mod.IGNORE, entry.get("owner"), entry["reason"], until, today)
            if not acceptance_mod.acceptable(finding):
                made.problems.append(acceptance_mod.UNACCEPTABLE_PROBLEM)
            if made.valid:
                finding.suppressed = f"{entry['reason']} (until {until.isoformat()})"
                finding.acceptance = made
                break
            if until < today:
                finding.message += f" (An ignore entry for this finding expired on {until.isoformat()}.)"
            if finding.acceptance is None:
                finding.acceptance = made


PLATFORMS = ("auto", "github", "jenkins")


def _resolve(target: Path, platform: str) -> tuple[Path, list[Path], list[Path], bool]:
    """(root, workflow files, Jenkinsfiles, is_repo) for a path given to `obaaf check`."""
    target = target.resolve()
    if target.is_file():
        # A single file: GitHub Actions workflows are YAML; a Jenkinsfile or a .groovy pipeline is Jenkins.
        is_jenkins = platform == "jenkins" or (platform == "auto" and (
            jenkins_mod.is_jenkinsfile(target) or target.suffix.lower() == ".groovy"))
        return target.parent, ([] if is_jenkins else [target]), ([target] if is_jenkins else []), False
    root, workflows = wf_mod.locate(target)
    if platform == "jenkins":
        workflows = []
    return root, workflows, [], True


def check(target: Path, files: list[Path] | None = None, config: Config | None = None,
          catalog: Catalog | None = None, today: date | None = None, platform: str = "auto",
          gate_files: list[Path] | None = None) -> CheckResult:
    """Check a repository root (workflows, Jenkinsfiles and repository files) or specific files.

    platform: auto (both kinds of CI definition), github (workflows only) or jenkins (Jenkinsfiles only).
    gate_files: other files that decide what the check accepts (a baseline, a configuration given by
    path), which OBAAF-REPO-001 then requires an owner for when they are in the repository.
    """
    if platform not in PLATFORMS:
        raise ValueError(f"platform must be one of {', '.join(PLATFORMS)}, not {platform!r}")
    catalog = catalog or load()
    target = target.resolve()
    jenkins_paths: list[Path] = []
    if files is None:
        root, files, jenkins_paths, is_repo = _resolve(target, platform)
        on_its_own = not is_repo
    else:
        root, is_repo, on_its_own = target, False, False
        if platform != "github":
            jenkins_paths = [f for f in files if platform == "jenkins" or jenkins_mod.is_jenkinsfile(f)
                             or f.suffix.lower() == ".groovy"]
            files = [f for f in files if f not in jenkins_paths]
    config = config or Config.load(root)
    # Jenkinsfiles are found from the repository root, not from .github/workflows.
    jenkins_sought = is_repo and platform != "github" and target == root
    errors: list[str] = []
    jenkins_notes: list[str] = []
    if jenkins_sought:
        jenkins_paths = jenkins_mod.discover(root, list(config.jenkins.get("files") or []),
                                             list(config.jenkins.get("exclude") or []),
                                             notes=jenkins_notes, errors=errors)
    script_cmds = _script_commands(catalog, config)
    agent_actions = _agent_actions(catalog, config)
    unread_actions: list = []
    action_cache: dict = {}
    findings: list[Finding] = []
    rels: list[str] = []
    # The CI definitions as a pull request changes them: a workflow that is a link by its own path,
    # and the target too when it is in the repository (slice 2d.2h).
    owned_paths: list[str] = []
    local_actions: set[str] = set()
    agent_lane_present = False
    suspect_jobs: list[tuple[str, str]] = []
    declared = _LaneDeclarations(config, root, is_repo, on_its_own, workflows_sought=platform != "jenkins",
                                 jenkins_sought=jenkins_sought)
    # The policy file of GitHub's native egress firewall is read from the repository, never for files
    # checked on their own, whose repository the checker does not know.
    firewall = egress_mod.read_firewall_policy(root) if is_repo else None
    for path in files:
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        rels.append(rel)
        owned_paths.extend(_as_found(path, root))
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # A file the checker could not read is an error, never a traceback or a pass.
            errors.append(f"{rel}: cannot be read: {exc}")
            declared.unreadable(rel, path)
            continue
        workflow = wf_mod.parse(rel, text)
        if workflow.error:
            errors.append(f"{rel}: {workflow.error}")
            declared.unreadable(rel, path)
            continue
        # The bytes, not the text: a byte that is not UTF-8 is replaced in the text, and two files
        # that differ only there must not be one file to an acceptance.
        workflow.digest = hashlib.sha256(path.read_bytes()).hexdigest()
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents,
                        aliases=declared.aliases(rel, path))
        _apply_script_detection(workflow, root, script_cmds)
        _apply_local_action_detection(workflow, None if on_its_own else root, agent_actions, script_cmds,
                                      unread_actions, errors, action_cache)
        declared.workflow(workflow, path)
        for job in workflow.jobs.values():
            if job.in_lane("agent"):
                agent_lane_present = True
            elif _AGENT_HINT.search(f"{job.id} {job.name}"):
                # Whatever other lane the job is in: a declaration must not be a way to silence this.
                suspect_jobs.append((rel, job.id))
        try:
            found = rules_mod.WorkflowRules(workflow, catalog, protected=config.protected_secrets,
                                            agents=config.agents, firewall=firewall).run()
        except expr_mod.TooComplex as exc:
            # A file the checker could not read is an error, never a pass.
            errors.append(f"{rel}: {exc}")
            continue
        except (RecursionError, MemoryError):
            errors.append(f"{rel}: too deeply nested or too large to read; the checker cannot tell what this "
                          "file does")
            continue
        findings.extend(found)
        errors.extend(f"{rel}: {problem}" for problem in workflow.problems)
        local_actions.update(_local_action_files(root, workflow))
    jenkins_results = []
    jenkins_rels: list[str] = []
    for path in jenkins_paths:
        # A Jenkinsfile that is a link is reported by its own path (flagship slice 2d.2i).
        try:
            rel = path.relative_to(root).as_posix()
        except ValueError:
            try:
                rel = path.resolve().relative_to(root).as_posix()
            except ValueError:
                rel = path.name
        rels.append(rel)
        jenkins_rels.append(rel)
        owned_paths.extend(_as_found(path, root))
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"{rel}: cannot be read: {exc}")
            continue
        result = jenkins_mod.analyze(rel, data, catalog, root, extra_agents=config.agents,
                                     lane_overrides=config.lanes)
        jenkins_results.append(result)
        if result.error:
            errors.append(f"{rel}: {result.error}")
            declared.unreadable(rel)
            continue
        declared.jenkinsfile(rel, result)
        findings.extend(result.findings)
        agent_lane_present = agent_lane_present or result.agent_present
        suspect_jobs.extend((rel, f"stage {s}") for s in result.suspect_stages)
    repo_notes: list[str] = []
    if is_repo:
        gates = [p for p in (_as_found(Path(g), root, strict=True) for g in (gate_files or [])) if p]
        findings.extend(rules_mod.repo_findings(root, sorted(set(owned_paths)), catalog, errors, repo_notes,
                                                local_actions=sorted(local_actions),
                                                gate_files=sorted({x for p in gates for x in p})))
    # A lane declaration that does nothing is a finding like any other: it can fail the check, be
    # fixed by correcting it, or be accepted by an ignore or baseline entry.
    findings.extend(declared.findings(catalog))
    today = today or date.today()
    _apply_ignores(findings, config, today)
    findings.sort(key=Finding.sort_key)
    notes = (jenkins_notes + repo_notes + _lane_notes(root, catalog, is_repo, agent_lane_present, suspect_jobs)
             + _local_action_notes(unread_actions))
    cov: list[dict] = []
    summaries: list[dict] = []
    for result in jenkins_results:
        cov.extend(jenkins_mod.coverage(result, findings))
        summaries.append(jenkins_mod.summary(result))
    return CheckResult(findings=findings, files=rels, errors=errors, config=config, notes=notes,
                       jenkins_files=jenkins_rels, coverage=cov, jenkins=summaries, today=today)


def _as_found(path: Path, root: Path, strict: bool = False) -> list[str]:
    """A file's path relative to the repository as found, without following links, and, when it is
    a link, the path of the file it leads to if that is in the repository. With `strict`, a file
    outside the repository gives nothing (a baseline kept elsewhere is not the repository's to own)."""
    out = []
    try:
        absolute = Path(os.path.abspath(path))
        out.append(absolute.relative_to(root).as_posix())
    except ValueError:
        # The path may reach the repository through a link (macOS's /tmp is /private/tmp): its folder,
        # with links resolved, is tried before it counts as outside.
        try:
            out.append((absolute.parent.resolve() / absolute.name).relative_to(root).as_posix())
        except (ValueError, OSError, RuntimeError):
            if strict:
                return []
            out.append(path.as_posix())
    try:
        real = path.resolve().relative_to(root).as_posix()
        if real not in out:
            out.append(real)
    except (ValueError, OSError, RuntimeError):
        pass
    return out


def _local_action_files(root: Path, workflow) -> set[str]:
    """The action files a workflow's steps use from this repository (`uses: ./path` or `$/path`): the
    path's action.yml, or action.yaml, or where action.yml would be when there is neither."""
    out: set[str] = set()
    for job in workflow.jobs.values():
        for step in job.steps:
            uses = step.uses
            if not wf_mod.is_local_reference(uses):
                continue
            folder = posixpath.normpath(uses[2:].split("@", 1)[0].strip("/") or ".")
            if folder == ".." or folder.startswith("../"):
                continue        # outside the repository: nothing here to own
            prefix = "" if folder == "." else f"{folder}/"
            names = [f"{prefix}action.yml", f"{prefix}action.yaml"]
            try:
                present = [n for n in names if (root / n).is_file() or (root / n).is_symlink()]
            except OSError:
                present = []         # a path the file system refuses (too long): taken as absent
            for name in present or names[:1]:
                out.update(_as_found(root / name, root))
    return out


def _lane_notes(root: Path, catalog: Catalog, is_repo: bool, agent_lane_present: bool,
                suspect_jobs: list[tuple[str, str]]) -> list[str]:
    """Advisory notes (never findings, never affect the exit code): surface agents the lane
    inference may have missed, so the agent controls are not silently skipped."""
    notes: list[str] = []
    if agent_lane_present:
        return notes
    if is_repo:
        instruction_files = repo_checks.find_instruction_files(root, catalog.detection.get("instruction_files", []),
                                                               errors=[])
        if instruction_files:
            shown = ", ".join(instruction_files[:3]) + (", ..." if len(instruction_files) > 3 else "")
            notes.append(
                f"{len(instruction_files)} agent instruction file(s) are present ({shown}) but no workflow job was "
                "classified into the agent lane, so the agent controls did not run on any job. If an agent runs "
                "indirectly, for example through a wrapper script like 'bash run-agent.sh', declare its command in "
                "agents.commands in .github/obaaf.yml, or set OBAAF_LANE: agent on the job (in a Jenkinsfile, "
                "OBAAF_LANE = 'agent' in the stage's environment). See docs/checker-configuration.md.")
    if suspect_jobs:
        shown = "; ".join(f"{w} {j}" if j.startswith("stage ") else f"{w} job '{j}'" for w, j in suspect_jobs[:5])
        more = f", and {len(suspect_jobs) - 5} more" if len(suspect_jobs) > 5 else ""
        notes.append(
            f"{len(suspect_jobs)} job(s) have a name that suggests agent work but are not in the agent lane "
            f"({shown}{more}). If any runs an AI agent, declare it with agents.commands or OBAAF_LANE so the agent "
            "controls apply.")
    return notes


IDLE_DECLARATION = "OBAAF-CFG-001"
_NOT_A_LANE = f"which is not a lane ({', '.join(wf_mod.LANES)}), so the declaration changes nothing"
_NOT_READ = ("where it is not read (it is read in the job's env and in the workflow's env), so the declaration "
             "changes nothing")
# One template for each case of OBAAF-CFG-001. The case is the finding's `kind`.
_IDLE_TEMPLATES = {
    "job-not-a-lane": f"Job '{{job}}' sets OBAAF_LANE to {{value}}, {_NOT_A_LANE}.",
    "workflow-not-a-lane": f"The workflow's env sets OBAAF_LANE to {{value}}, {_NOT_A_LANE}.",
    "job-misnamed": "Job '{job}' sets {name} to {value}. The variable that declares a lane is OBAAF_LANE, spelled "
                    "exactly so, so the declaration changes nothing.",
    "workflow-misnamed": "The workflow's env sets {name} to {value}. The variable that declares a lane is "
                         "OBAAF_LANE, spelled exactly so, so the declaration changes nothing.",
    "jenkins-not-a-lane": f"For the steps in {{stages}}, OBAAF_LANE is set to {{value}}, {_NOT_A_LANE}.",
    "jenkins-computed": "For the steps in {stages}, OBAAF_LANE is set to a value computed when the build runs, "
                        "which the checker cannot read as a lane, so the declaration changes nothing.",
    "jenkins-misnamed": "{name} is set to {value} (written in {stages}). The variable that declares a lane is "
                        "OBAAF_LANE, spelled exactly so, so the declaration changes nothing.",
    "jenkins-scripted": "A script assigns {value} to the environment variable {name} (written in {stages}), which "
                        "the checker does not read as a lane declaration (it reads OBAAF_LANE in an environment "
                        "block or a withEnv), so the declaration changes nothing.",
    "step-env": f"Job '{{job}}' sets OBAAF_LANE to {{value}} in the env of step '{{step}}', {_NOT_READ}.",
    "container-env": f"Job '{{job}}' sets OBAAF_LANE to {{value}} in container.env, {_NOT_READ}.",
    "service-env": f"Job '{{job}}' sets OBAAF_LANE to {{value}} in services.{{service}}.env, {_NOT_READ}.",
    "elsewhere": "Job '{job}' sets {name} to {value} in {where}, where the checker does not read a lane "
                 "declaration (it reads OBAAF_LANE, spelled exactly so, in the job's env and the workflow's env), "
                 "so the declaration changes nothing.",
    "workflow-elsewhere": "The workflow sets {name} to {value} in {where}, where the checker does not read a lane "
                          "declaration (it reads OBAAF_LANE, spelled exactly so, in the job's env and the workflow's "
                          "env), so the declaration changes nothing.",
    "entry-not-a-lane": f"lanes: '{{entry}}' is set to {{value}}, {_NOT_A_LANE}.",
    "entry-no-job": "lanes: '{entry}' (set to {value}) names a job that {file} does not have, so the declaration "
                    "changes nothing.",
    "entry-no-stage": "lanes: '{entry}' (set to {value}) names a stage that {file} does not have, so the "
                      "declaration changes nothing.",
    "entry-no-file": "lanes: '{entry}' (set to {value}) names a file the checker did not read, so the declaration "
                     "changes nothing.",
}


class _LaneDeclarations:
    """Lane declarations that did nothing, each reported as a finding (OBAAF-CFG-001): a value that
    is not a lane, OBAAF_LANE where it is not read, or a configured lane for a job, stage or file
    the checker did not find. A declaration can only add rules, so one that silently does nothing
    leaves a job with fewer rules than its author meant it to have."""

    def __init__(self, config: "Config", root: Path, is_repo: bool, on_its_own: bool, workflows_sought: bool,
                 jenkins_sought: bool) -> None:
        self.config, self.root, self.is_repo, self.on_its_own = config, root, is_repo, on_its_own
        self.workflows_sought, self.jenkins_sought = workflows_sought, jenkins_sought
        self.problems: list = []                       # IdleDeclaration: written in a workflow or a Jenkinsfile
        try:
            self.resolved_root: Path | None = root.resolve()
        except (OSError, RuntimeError):
            self.resolved_root = None
        self.known: dict[str, tuple[str, set]] = {}    # path -> ("job" or "stage", the names it has)
        self.unread: set[str] = set()

    def aliases(self, rel: str, path: Path) -> tuple:
        """Other paths the configuration may know a workflow by. A workflow checked on its own is
        `ci.yml` to the checker and `.github/workflows/ci.yml` in the repository's configuration.
        Only for a file given on its own: in a repository, or in a list of files, a file has one path."""
        parent = path.resolve().parent
        if not self.on_its_own or parent.name != "workflows" or parent.parent.name != ".github":
            return ()
        alias = f".github/workflows/{path.name}"
        return () if alias == rel else (alias,)

    def unreadable(self, rel: str, path: Path | None = None) -> None:
        """A file already reported as an error: say nothing more about its declarations."""
        self.unread.update((rel, *(self.aliases(rel, path) if path else ())))

    def workflow(self, workflow, path: Path) -> None:
        """Take a classified workflow's declarations. Call it once every lane the job is in is
        known, script detection included: a declaration written where it is not read loses nothing
        when the job is in the lane it names anyway."""
        for found in workflow.lane_problems:
            job = workflow.jobs.get(found.job) if found.job else None
            if job is not None and found.lane in wf_mod.LANE_ORDER and job.in_lane(found.lane):
                found = replace(found, redundant=True)
            self.problems.append(found)
        jobs = workflow.raw.get("jobs")
        # Every job the file names, including one the checker could not read and reported as an error.
        names = {str(name) for name in jobs} if isinstance(jobs, dict) else set(workflow.jobs)
        for known_as in (workflow.path, *self.aliases(workflow.path, path)):
            self.known[known_as] = ("job", names | self.known.get(known_as, ("job", set()))[1])

    def jenkinsfile(self, rel: str, result) -> None:
        self.problems.extend(result.lane_problems)
        self.known[rel] = ("stage", set(result.stage_keys))

    def _unsought(self, path: str) -> bool:
        """Whether `path` is a file that exists and is of a kind this run did not look for at all
        (a Jenkinsfile when only workflows were checked, or the other way round)."""
        sought = self.workflows_sought if path.endswith((".yml", ".yaml")) else self.jenkins_sought
        if sought or self.resolved_root is None:
            return False
        try:
            target = self.resolved_root / path
            # One look at the file system for a path that is not a file, which is nearly every one tried.
            return target.is_file() and target.resolve().is_relative_to(self.resolved_root)
        except (OSError, ValueError, RuntimeError):
            return False

    def _out_of_scope(self, key: str) -> bool:
        """Whether a `lanes:` key names a file outside this run: one that exists and is of a kind
        the run did not look for. An entry for a file that does not exist is never out of scope: it
        is a mistake whatever was checked. The file is the key, or the part of it before one of its
        `#`, because a file's own name may hold one. A path is short and has few of them, so only
        the first 4,096 characters and 64 cuts are tried."""
        cuts = [len(key)] if len(key) <= 4096 else []
        cut = -1
        while len(cuts) < 64 and (cut := key.find("#", cut + 1)) != -1 and cut <= 4096:
            cuts.append(cut)
        return any(self._unsought(key[:cut]) for cut in cuts)

    def config_path(self) -> str:
        """The checker configuration as a finding names it: from the directory every other path in
        the report is given from. A configuration that was not read from a file is named as the
        file such a declaration would be written in."""
        if not self.config.path:
            return CONFIG_LOCATIONS[0]
        given = Path(self.config.path)
        try:
            resolved, root = given.resolve(), self.root.resolve()
            if resolved.is_relative_to(root):
                return resolved.relative_to(root).as_posix()
            return Path(os.path.relpath(resolved, root)).as_posix()
        except (OSError, ValueError):
            return given.as_posix()

    def _finding(self, catalog: Catalog, kind: str, path: str, line: int, nothing_lost: bool,
                 job: str | None = None, step: str | None = None, **values) -> Finding:
        # A declaration that would have added no rule had it worked (it names `trusted`, or a lane
        # the job is in anyway) is hardening. Any other leaves a job without rules its author meant
        # it to have, and is reported at the rule's own severity.
        severity = "low" if nothing_lost else catalog.rules[IDLE_DECLARATION]["severity"]
        message, facts = rules_mod.compose(IDLE_DECLARATION, kind, _IDLE_TEMPLATES[kind], job, step, values)
        return Finding(IDLE_DECLARATION, severity, path, line or 1, message, job=job, step=step, kind=kind,
                       facts=facts)

    def _entries(self, catalog: Catalog) -> list[Finding]:
        """The `lanes:` entries of the checker configuration that do nothing."""
        out: list[Finding] = []
        where = self.config_path()
        for key, value in self.config.lanes.items():
            # A key that is not text is shown as YAML writes it, not as Python does.
            text = {True: "true", False: "false", None: "null"}.get(key, None) if isinstance(key, (bool, type(None))) \
                else wf_mod.as_text(key)
            named: list = []
            # A key that is not text (`5:`, `true:`) is never looked up, so it names nothing.
            if isinstance(key, str):
                # The files this run read or refused that the key names, whole or before a `#`. A file's
                # own name may hold a `#`, so the key is matched against the files, not cut at its first.
                named = [(path, text[len(path) + 1:]) for path in (*self.known, *self.unread)
                         if text == path or text.startswith(path + "#")]
                if any(path in self.unread for path, _ in named):
                    continue
                named = [(path, part) for path, part in named if path in self.known]
                if not named and (not self.is_repo or self._out_of_scope(text)):
                    continue    # the configuration covers more than the files this run was given
            lane = wf_mod.declared_lane(value)
            shared = {"path": where, "line": self.config.lane_lines.get(key, 1),
                      "entry": rules_mod.Fact(wf_mod.bounded(text), wf_mod.one_line(text, 120)),
                      "value": rules_mod.Fact(wf_mod.value_identity(value), wf_mod.shown_value(value))}
            if lane is None:
                out.append(self._finding(catalog, "entry-not-a-lane", nothing_lost=False, **shared))
            if not named:
                out.append(self._finding(catalog, "entry-no-file", nothing_lost=lane == "trusted", **shared))
            elif not any(text == path or part in self.known[path][1] for path, part in named):
                path = named[0][0]
                kind = self.known[path][0]
                # On a Jenkins stage only `agent` and `release` change what is checked (docs/jenkins.md).
                harmless = ("trusted",) if kind == "job" else ("trusted", "untrusted", "effect")
                out.append(self._finding(catalog, f"entry-no-{kind}", nothing_lost=lane in harmless, **shared,
                                         file=rules_mod.Note(wf_mod.one_line(path, 120))))
        return out

    def findings(self, catalog: Catalog) -> list[Finding]:
        """One finding for each declaration that did nothing."""
        out: list[Finding] = []
        for found in dict.fromkeys(self.problems):
            values: dict = {}
            if found.kind != "jenkins-computed":
                values["value"] = rules_mod.Fact(found.value, found.shown)
            if found.kind == "service-env":
                values["service"] = rules_mod.Fact(found.service, wf_mod.one_line(found.service, 60))
            if found.name:
                values["name"] = rules_mod.Fact(found.name, f"'{found.name_shown}'")
            if found.kind in ("elsewhere", "workflow-elsewhere"):
                values["where"] = rules_mod.Fact(found.where, f"'{wf_mod.one_line(found.where, 80)}'")
            if found.kind.startswith("jenkins-"):
                # The labels are the checker's own, as `--lanes` prints them: a stage by its name, a
                # stage in a stage as `Outer > Inner`, a method as `name()`, a post block as `post always`.
                values["stages"] = rules_mod.Fact(list(found.stages), ", ".join(
                    f"'{wf_mod.one_line(stage, 80)}'" if stage else "the pipeline outside any stage"
                    for stage in found.stages))
            out.append(self._finding(catalog, found.kind, found.path, found.line,
                                     found.lane == "trusted" or found.redundant, found.job, found.step, **values))
        return out + self._entries(catalog)

    def notes(self, catalog: Catalog) -> list[str]:
        """The same declarations as lines for `--lanes`, which lists lanes and reports no findings.
        Each is one line whatever a job or a step is called."""
        return [f"Lane declaration ignored: {wf_mod.one_line(f.path, 120)}, line {f.line}: "
                f"{wf_mod.one_line(f.message)} (`obaaf check` reports it as {f.rule}, {f.severity}.)"
                for f in sorted(self.findings(catalog), key=Finding.sort_key)]


def lanes(target: Path, config: Config | None = None, platform: str = "auto",
          notes: list | None = None, errors: list | None = None,
          seen: list | None = None) -> list[tuple[str, str, str, str]]:
    """(file, job or stage, lane, reason) for every workflow job and Jenkins stage, to show how the
    checker classified them. Lane declarations that did nothing, which `check` reports as findings,
    are added to `notes` as lines of text when it is given. Whatever `check` would report as an error
    for a file (it could not be read or parsed, an input is given twice, the rules could not read an
    expression) is added to `errors` as `check` words it, and a Jenkinsfile part of whose pipeline was
    not analyzed is added to `notes` (slice 3.2a); every file looked at, read or not, is added to `seen`."""
    errors = [] if errors is None else errors
    seen = [] if seen is None else seen
    notes = [] if notes is None else notes
    root, files, jenkins_paths, is_repo = _resolve(target, platform)
    firewall = egress_mod.read_firewall_policy(root) if is_repo else None
    config = config or Config.load(root)
    jenkins_sought = is_repo and platform != "github" and target.resolve() == root
    declared = _LaneDeclarations(config, root, is_repo, not is_repo, workflows_sought=platform != "jenkins",
                                 jenkins_sought=jenkins_sought)
    if jenkins_sought:
        jenkins_paths = jenkins_mod.discover(root, list(config.jenkins.get("files") or []),
                                             list(config.jenkins.get("exclude") or []), notes=notes, errors=errors)
    catalog = load()
    script_cmds = _script_commands(catalog, config)
    agent_actions = _agent_actions(catalog, config)
    unread_actions: list = []
    action_cache: dict = {}
    out = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        seen.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{rel}: cannot be read: {exc}")
            declared.unreadable(rel, path)
            continue
        workflow = wf_mod.parse(rel, text)
        if workflow.error:
            errors.append(f"{rel}: {workflow.error}")
            declared.unreadable(rel, path)
            continue
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents,
                        aliases=declared.aliases(rel, path))
        _apply_script_detection(workflow, root, script_cmds)
        _apply_local_action_detection(workflow, root if is_repo else None, agent_actions, script_cmds,
                                      unread_actions, errors, action_cache)
        declared.workflow(workflow, path)
        # What `check` reports as an error for the file (an input given twice under two spellings, an
        # expression too deep for the rules to read) means the file was not fully read, so `--lanes`
        # must not pass it either. The rules are run only to find those errors.
        try:
            rules_mod.WorkflowRules(workflow, catalog, protected=config.protected_secrets,
                                    agents=config.agents, firewall=firewall).run()
        except expr_mod.TooComplex as exc:
            errors.append(f"{rel}: {exc}")
        except (RecursionError, MemoryError):
            errors.append(f"{rel}: too deeply nested or too large to read; the checker cannot tell what this "
                          "file does")
        errors.extend(f"{rel}: {problem}" for problem in workflow.problems)
        out += [(rel, job.id, job.lane, job.lane_reason) for job in workflow.jobs.values()]
    for path in jenkins_paths:
        rel = path.relative_to(root).as_posix()
        seen.append(rel)
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"{rel}: cannot be read: {exc}")
            declared.unreadable(rel)
            continue
        result = jenkins_mod.analyze(rel, data, catalog, root, extra_agents=config.agents,
                                     lane_overrides=config.lanes)
        if result.error:
            errors.append(f"{rel}: {result.error}")
            declared.unreadable(rel)
        else:
            declared.jenkinsfile(rel, result)
            # `check` says no rule can pass such a file and still ends 0 (the Jenkins analyser is
            # advisory); the listing says the same, so a stage in the part not analyzed is not missing
            # in silence.
            general = list(dict.fromkeys(f"line {u.line}: {u.reason}" for u in result.unknowns
                                         if u.rule == jenkins_mod.ALL))
            if general:
                notes.append(f"{wf_mod.one_line(rel, 120)}: part of the pipeline was not analyzed, so a stage in "
                             f"it may be missing from this list ({wf_mod.one_line('; '.join(general))})")
        out += [(rel, f"stage {stage}", lane, reason) for stage, lane, reason in result.lanes]
    if is_repo:
        # A CODEOWNERS or instruction file `check` could not read is an error there, so it is here too
        # (slice 2d.8); the repository rules are run only to find it.
        rules_mod.repo_findings(root, [], catalog, errors, notes)
    notes.extend(declared.notes(catalog))
    notes.extend(_local_action_notes(unread_actions))
    return out
