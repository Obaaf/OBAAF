"""Environment variables in PowerShell and cmd command lines (flagship slice 2d.25, #411).

GitHub hands a `run` step's script to its shell with the `env` the step runs with (its own over its job's over its
workflow's) as the process's environment. bash reads a variable as `$NAME` or `${NAME}`, and both readers put those
in (the lanes' `Step.env_put_in`, OBAAF-GHA-026's `agent_flags._substitute`; D-137 to D-139). PowerShell reads one as
`$env:NAME` or `${env:NAME}`, and cmd as `%NAME%`. Before this slice neither reader put those in, so a job whose agent
was named only through `env` in a pwsh or cmd step (`& $env:AGENT --dangerously-skip-permissions -p x` with
`AGENT: claude`) was in no agent lane and got no agent rule, OBAAF-GHA-026 included.

What this module gives both readers:

- `run_shell` and `run_language`: the shell a `run` step's script is given to and the language it is read as, the
  one reading for both (they were `WorkflowRules._step_shell` and `_step_language`).
- `family`: `pwsh`, `cmd` or None for a shell's or language's name.
- `Lookup`: the values `env` gives by name, compared as the runner compares names: as written on a known
  GitHub-hosted Linux or macOS runner, without regard to case on a known GitHub-hosted Windows runner (the nearest
  scope's value winning), both where the runner is not known (`env_expr.env_case`). cmd runs only on Windows, so its
  names are always compared without regard to case.
- `lane_pattern`: what the lanes put in, the widest way (in any quotes, as their `$NAME` put-in does in bash).
- `put_in`: what OBAAF-GHA-026 puts in, only where the shell expands the reference: in PowerShell outside a
  single-quoted string, a single-quoted here-string and a comment, not after a backtick, and not where `.`, `[`, `:`
  or `?` follows (a member, an index, or a longer name); in cmd every `%NAME%` (cmd expands them before it reads
  quotes), with `%%`, `%0` to `%9`, `%*` and `%~...` left as written.
- `script_sets`: the names a script may set itself, which OBAAF-GHA-026 does not take from `env`.
"""

from __future__ import annotations

import re

from obaaf.checker import env_expr

PWSH_SHELLS = frozenset({"pwsh", "powershell"})
CMD_SHELLS = frozenset({"cmd"})
# The values OBAAF-GHA-026 puts in: `agent_flags._PLAIN_VALUE_RE`'s and a backslash, which neither PowerShell nor cmd
# reads as an escape (a Windows path, `C:\tools\claude.exe`). `_safe` refuses what each place cannot hold.
PLAIN_VALUE_RE = re.compile(r"[A-Za-z0-9 _.,:/\\@%+=-]*")


# ------------------------------------------------------------------------------------------ the shell
def run_shell(step_raw, holders, runs_on) -> str:
    """The shell a `run` step's script is given to: its `shell`, else the job's and then the workflow's
    `defaults.run.shell` (`holders`: the job's and the workflow's mappings, nearest first), else bash (pwsh on a
    runner one of whose labels holds "windows"). The shell's first word, after its last `/`, in lower case."""
    shell = step_raw.get("shell") if isinstance(step_raw, dict) else None
    if not isinstance(shell, str):
        for holder in holders:
            defaults = holder.get("defaults") if isinstance(holder, dict) else None
            run = defaults.get("run") if isinstance(defaults, dict) else None
            if isinstance(run, dict) and isinstance(run.get("shell"), str):
                shell = run["shell"]
                break
    if not isinstance(shell, str):
        windows = any("windows" in str(label).lower() for label in runs_on)
        return "pwsh" if windows else "bash"
    first = shell.split()[0] if shell.split() else ""
    return first.rsplit("/", 1)[-1].lower()


def run_language(step_raw, shell_name: str) -> str:
    """The language a `run` step's script is read as: the step's own `shell`'s program, after `env` and its options
    (`/usr/bin/env python3 {0}`), and python for `uv run --script {0}`; else `shell_name`."""
    shell = step_raw.get("shell") if isinstance(step_raw, dict) else None
    if not isinstance(shell, str):
        return shell_name
    words = [w.rsplit("/", 1)[-1].lower() for w in shell.split() if w != "{0}"]
    while words and (words[0] == "env" or words[0].startswith("-")):
        words = words[1:]
    if words and words[0] in ("uv", "uvx") and ("--script" in words or "run" in words):
        return "python"
    return words[0] if words else shell_name


def family(name: str | None) -> str | None:
    """`pwsh` for PowerShell, `cmd` for cmd, None for any other shell or language, read from a shell's or an
    interpreter's name as `agent_code.family_of` reads it (`pwsh.exe`, `C:\\...\\powershell.exe`, `cmd.exe`)."""
    if not name:
        return None
    base = re.sub(r"[0-9.]*(\.exe)?$", "", name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower())
    if base in PWSH_SHELLS:
        return "pwsh"
    if base in CMD_SHELLS:
        return "cmd"
    return None


# ------------------------------------------------------------------------------------------ the values
def _text(value, numbers: bool):
    """A YAML value as the text the process's environment holds: text as it is; with `numbers`, a boolean or a
    number as `agent_flags.known_variables` writes it; None for anything else."""
    if isinstance(value, str):
        return value
    if not numbers:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        try:
            return str(value)
        except ValueError:          # a number too long for Python to print
            return None
    return None


class Lookup:
    """The values the `env` mappings give, nearest first (`scopes`: the step's, the job's, the workflow's), by name.

    A name takes its value from the nearest scope that sets it; a scope that sets it to a value that is not text
    (with `numbers`, a boolean or a number is text) gives None, though an outer scope sets it to text, as D-139's
    `Step.run_env` has it. `trusted` (one for each scope, all by default) False for a scope makes each name it gives
    None (an earlier step may write `GITHUB_ENV`); `plain`, a compiled pattern, makes a value that does not match it
    None. `folded` compares names as a Windows runner does (`env_expr.fold`); two names of one scope that fold to the
    same name with different values give None, since which one the runner keeps is not established. A scope that is
    not a mapping (written as one expression) gives nothing, as in D-139."""

    def __init__(self, scopes: list, trusted: list | None = None, plain: re.Pattern | None = None,
                 numbers: bool = False) -> None:
        self.exact: dict = {}
        self.folded: dict = {}
        self.kept: list = []
        for number, scope in enumerate(scopes):
            if not isinstance(scope, dict):
                continue
            ok_scope = trusted is None or (number < len(trusted) and trusted[number])
            here: dict = {}
            for name, value in scope.items():
                if not isinstance(name, str):
                    continue
                text = _text(value, numbers)
                if text is not None and (not ok_scope or (plain is not None and not plain.fullmatch(text))):
                    text = None
                if text is not None:
                    self.kept.append(text)
                self.exact.setdefault(name, text)
                key = env_expr.fold(name)
                if key in here and here[key] != text:
                    here[key] = None
                else:
                    here[key] = text
            for key, text in here.items():
                self.folded.setdefault(key, text)

    def get(self, name: str, mode: str) -> str | None:
        """The value of `name` (None for none the checker knows): `mode` `exact` as written, `folded` without regard to
        case, `both` the value only where both give the same. A name outside ASCII is compared both ways on Windows
        (.NET's mapping is not copied; `env_expr.Env.lookup`)."""
        if mode == "folded" and not name.isascii():
            mode = "both"
        exact = self.exact.get(name)
        if mode == "exact":
            return exact
        folded = self.folded.get(env_expr.fold(name))
        if mode == "folded":
            return folded
        return exact if exact == folded else None


def case_of(family_name: str, job) -> str:
    """How the runner of `job` compares the names a `family_name` script reads: always without regard to case for
    cmd, which runs only on Windows; for PowerShell as `env_expr.env_case` has the runner (`exact`, `folded`,
    `both`)."""
    if family_name == "cmd":
        return "folded"
    return env_expr.env_case(job)


# ------------------------------------------------------------------------------------------ the lanes
# The lanes read the widest way: a reference is put in wherever it stands, in quotes too, as their `$NAME` put-in
# does in bash; bash's `$NAME` and `${NAME}` are put in too, as before. The groups: `pwsh` (or `cmd`) the name of a
# reference of that shell, `bash` a bash one; a match with neither (cmd's `%%`, `%1`, `%*`, `%~dp0`) is kept.
_BASH_REF = r"\$\{?(?P<bash>[A-Za-z_][A-Za-z0-9_]*)\}?"
_LANE_PATTERNS = {
    "pwsh": re.compile(r"\$\{(?i:env):(?P<pwsh>\w+)\}|\$(?i:env):(?P<pwsh2>\w+)|" + _BASH_REF),
    "cmd": re.compile(r"%%|%~[A-Za-z]*[0-9]|%[0-9*]|%(?P<cmd>[^%\r\n]+)%|" + _BASH_REF),
}


def lane_pattern(family_name: str) -> re.Pattern:
    return _LANE_PATTERNS[family_name]


def lane_reference(match: re.Match) -> tuple:
    """(kind, name) of a match of `lane_pattern`: kind `bash`, `shell` or None (a cmd match kept as written)."""
    groups = match.groupdict()
    if groups.get("bash"):
        return "bash", groups["bash"]
    for key in ("pwsh", "pwsh2", "cmd"):
        if groups.get(key):
            return "shell", groups[key]
    return None, None


# ------------------------------------------------------------------------------------------ OBAAF-GHA-026
_PS_SINGLE = frozenset("'\u2018\u2019\u201a\u201b")
_PS_DOUBLE = frozenset('"\u201c\u201d\u201e')
_PS_REF_RE = re.compile(r"\$(?:\{(?i:env):(\w+)\}|(?i:env):(\w+))")
# What after a reference makes it more than the value: a member (`.Length`), an index (`[0]`), a longer name or a
# drive-qualified path (`:`), `?` (a name PowerShell 7 reads on). Such a reference is left as written.
_PS_AFTER = frozenset(".[:?")
_CMD_ARG_RE = re.compile(r"%~[A-Za-z]*[0-9]|%[0-9*]")


def _here_end(text: str, eol: int, closers: frozenset) -> int:
    """Where a here-string that starts after the line break at `eol` ends: after the `'@` or `"@` that starts a later
    line; the text's end when none does."""
    j = eol
    while j != -1:
        if text[j + 1:j + 2] in closers and text[j + 2:j + 3] == "@":
            return j + 3
        j = text.find("\n", j + 1)
    return len(text)


def _ps_references(text: str) -> list:
    """(start, end, name, in_string, plain) for each `$env:NAME` and `${env:NAME}` PowerShell expands in `text`: in
    code and in a double-quoted string or here-string, not in a single-quoted one, a comment, or after a backtick.
    `plain` is False where, in code, `.`, `[`, `:` or `?` follows (a member, an index, a longer name), which is more
    than the value. One pass, so linear in the text."""
    out: list = []
    i, n = 0, len(text)
    state = "code"          # "code", "double" (a "..." string), "here" (a @"..."@ here-string)
    while i < n:
        ch = text[i]
        if state == "code":
            if ch == "`":
                i += 2
                continue
            if ch == "#" and (i == 0 or text[i - 1].isspace() or text[i - 1] in ";|&({}"):
                end = text.find("\n", i)
                i = n if end == -1 else end
                continue
            if text.startswith("<#", i):
                end = text.find("#>", i + 2)
                i = n if end == -1 else end + 2
                continue
            if ch == "@" and i + 1 < n and (text[i + 1] in _PS_SINGLE or text[i + 1] in _PS_DOUBLE):
                eol = text.find("\n", i + 2)
                if eol != -1 and not text[i + 2:eol].strip():
                    if text[i + 1] in _PS_SINGLE:
                        i = _here_end(text, eol, _PS_SINGLE)
                    else:
                        state = "here"
                        i = eol
                    continue
            if ch in _PS_SINGLE:
                j = i + 1
                while j < n:
                    if text[j] in _PS_SINGLE:
                        if j + 1 < n and text[j + 1] in _PS_SINGLE:
                            j += 2
                            continue
                        break
                    j += 1
                i = j + 1
                continue
            if ch in _PS_DOUBLE:
                state = "double"
                i += 1
                continue
        elif state == "double":
            if ch == "`":
                i += 2
                continue
            if ch in _PS_DOUBLE:
                if i + 1 < n and text[i + 1] in _PS_DOUBLE:
                    i += 2
                    continue
                state = "code"
                i += 1
                continue
        else:   # a double-quoted here-string, which ends at a line that starts with its closing quote and `@`
            if ch == "`":
                i += 2
                continue
            if ch == "\n" and text[i + 1:i + 2] in _PS_DOUBLE and text[i + 2:i + 3] == "@":
                state = "code"
                i += 3
                continue
        if ch == "$":
            m = _PS_REF_RE.match(text, i)
            if m:
                plain = state != "code" or text[m.end():m.end() + 1] not in _PS_AFTER
                out.append((m.start(), m.end(), m.group(1) or m.group(2), state != "code", plain))
                i = m.end()
                continue
        i += 1
    return out


def _cmd_references(text: str) -> list:
    """(start, end, name, False, plain) for each `%NAME%` cmd expands in a batch file: `%%` is a `%`, `%0` to `%9`,
    `%*` and `%~...` are the script's arguments, and a `%` with no `%` after it on its line is left as written.
    `plain` is False for a name with `:` (a substring or a replacement, `%X:~1%`) or another character no plain name
    has, whose name is then the part before the `:`."""
    out: list = []
    i, n = 0, len(text)
    while i < n:
        at = text.find("%", i)
        if at == -1:
            break
        if text.startswith("%%", at):
            i = at + 2
            continue
        arg = _CMD_ARG_RE.match(text, at)
        if arg:
            i = arg.end()
            continue
        close = text.find("%", at + 1)
        eol = text.find("\n", at + 1)
        if close == -1 or (eol != -1 and eol < close):
            i = at + 1
            continue
        name = text[at + 1:close]
        plain = bool(_CMD_NAME_RE.fullmatch(name))
        out.append((at, close + 1, name if plain else name.split(":", 1)[0], False, plain))
        i = close + 1
    return out


# The plain names cmd's `%NAME%` reads: one with `:` is a substring or a replacement (`%X:~1%`, `%X:a=b%`), which is
# not put in, and one with `=` cannot be set.
_CMD_NAME_RE = re.compile(r"[^\s%:=!^&|<>\"]+")


def references(text: str, family_name: str) -> list:
    """(start, end, name, in_string, plain) for each reference to an environment variable the shell expands in
    `text`; only a `plain` one is put in."""
    return _ps_references(text) if family_name == "pwsh" else _cmd_references(text)


# Every name a script may read from its environment, read the widest way, in any quotes: PowerShell's `$env:NAME`,
# `${env:NAME}`, a provider path (`env:NAME`, `Env:\NAME`) and `GetEnvironmentVariable('NAME')`; cmd's `%NAME%`,
# `%NAME:...%` and `!NAME!` (delayed expansion).
_PS_ANY_NAME_RE = re.compile(r"(?i:env):\\?(\w+)|GetEnvironmentVariable\s*\(\s*['\"\u2018\u2019\u201c\u201d]?(\w+)", re.I)
_CMD_ANY_NAME_RE = re.compile(r"%([^%\s:]+)(?::[^%\n]*)?%|!([^!\s:]+)(?::[^!\n]*)?!")


def names_read(text: str, family_name: str) -> list:
    """Every name `text` may read from its environment (`_PS_ANY_NAME_RE`, `_CMD_ANY_NAME_RE`), in order, once each:
    what OBAAF-GHA-026 reads for the tool's name where it does not put a value in."""
    pattern = _PS_ANY_NAME_RE if family_name == "pwsh" else _CMD_ANY_NAME_RE
    return list(dict.fromkeys(next(g for g in m.groups() if g) for m in pattern.finditer(text)))


def _safe(value: str, family_name: str, in_string: bool) -> bool:
    """Whether `value`, put in as `put_in` puts it, is read as the variable is: in PowerShell code it holds no
    single quote, in a PowerShell string no double quote, backtick or `$`, in cmd no `%`, `!`, `^`, `&`, `|`, `<`, `>`
    or `"` (a plain value holds none of them)."""
    if family_name == "cmd":
        return not any(ch in value for ch in '%!^&|<>"\n\r')
    if in_string:
        return not any(ch in _PS_DOUBLE or ch in "`$" for ch in value)
    return not any(ch in _PS_SINGLE for ch in value) and "\n" not in value


def put_in(text: str, family_name: str, lookup, budget=None) -> tuple | None:
    """(text, size, names) for `text` with each plain reference the shell expands (`references`) whose value
    `lookup(name)` gives put in, the characters put in and the names put in; None when the step's `PutInBudget` runs out or the workflow's ledger refuses
    (the budget's `ledger`, settled as `agent_flags._substitute` settles, by the step's number, the text and the
    values put in). In PowerShell code a value is put in as a single-quoted string, one word as the variable is (a
    plain value holds no quote); in a string as it is. In cmd a value is put in as it is, as cmd puts it in before it
    reads the line; a name with a `:` or `=` is not put in."""
    found = references(text, family_name)
    if not found:
        return text, 0, frozenset()
    pieces: list = []
    at = 0
    size = 0
    named: dict = {}
    for start, end, name, in_string, plain in found:
        if not plain:
            continue
        value = lookup(name)
        if value is None or not _safe(value, family_name, in_string):
            continue
        if budget is not None and not budget.take(value):
            return None
        size += len(value)
        named[name] = value
        pieces.append(text[at:start])
        pieces.append(value if in_string or family_name == "cmd" else f"'{value}'")
        at = end
    if not named:
        return text, 0, frozenset()
    if budget is not None and budget.ledger is not None:
        reading = (family_name, text, frozenset(named.items()))
        times = budget.made[reading] = budget.made.get(reading, 0) + 1
        if not budget.ledger.settle((budget.place, times, reading), size):
            return None
    pieces.append(text[at:])
    return "".join(pieces), size, frozenset(named)


# What can set an environment variable in a script, read the widest way. PowerShell: an assignment to `$env:NAME` or
# `${env:NAME}` (`=`, `+=`, `??=` and the like) sets that name; any other `env:` (`Set-Item env:X`, `Remove-Item
# Env:\X`, `cd env:`), `SetEnvironmentVariable`, `Invoke-Expression`, dot-sourcing, a `.ps1` run in the same process,
# `Import-Module` and `Invoke-Command` may set any. cmd: `set NAME=...` (with `/a` or `/p`, quoted or not) sets that
# name; a `set` whose name holds a variable (`set %N%=x`), and `call` of anything but a label, may set any.
_PS_ASSIGN_RE = re.compile(r"\$\{?(?i:env):(\w+)\}?\s*(?:[-+*/%]|\?\?)?=(?!=)")
_PS_ENV_ANY_RE = re.compile(r"env:", re.I)
_PS_DYNAMIC_RE = re.compile(r"SetEnvironmentVariable|Invoke-Expression|\biex\b|Import-Module|\bipmo\b|Invoke-Command"
                            r"|\bicm\b|\.ps1\b|\.psm1\b|Environment::|(?:^|[;|&({}\s])\.\s+\S", re.I | re.M)
_CMD_SET_RE = re.compile(r"\bset\s+(?:/[ap]\s+)?\"?\s*([^=\"\n]*?)\s*=", re.I)
_CMD_DYNAMIC_RE = re.compile(r"\bcall\s+(?!:)\S", re.I)


def script_sets(text: str, family_name: str) -> tuple:
    """(names, any): the names, folded, the script may set itself, and whether it may set any name."""
    names: set = set()
    if family_name == "pwsh":
        if _PS_DYNAMIC_RE.search(text):
            return frozenset(), True
        for m in _PS_ASSIGN_RE.finditer(text):
            names.add(env_expr.fold(m.group(1)))
        # Every `env:` that is not in a `$env:NAME` or `${env:NAME}` (read, or assigned to above), wherever it stands,
        # may set any name (`Set-Item env:X`, `"env:$n"`).
        covered = {m.start() + (2 if m.group(0).startswith("${") else 1) for m in _PS_REF_RE.finditer(text)}
        if any(m.start() not in covered for m in _PS_ENV_ANY_RE.finditer(text)):
            return frozenset(), True
        return frozenset(names), False
    if _CMD_DYNAMIC_RE.search(text):
        return frozenset(), True
    for m in _CMD_SET_RE.finditer(text):
        name = m.group(1)
        if "%" in name or "!" in name:
            return frozenset(), True
        names.add(env_expr.fold(name))
    return frozenset(names), False


# ------------------------------------------------------------------------------------------ launchers
# The words before a program that PowerShell and cmd run it through, for the lanes' reading of a text made with
# values put in, which reads command by command from a command's first word (D-139): `Start-Process` (and its aliases
# `saps` and `start`) with `-FilePath` and `-ArgumentList`, `Invoke-Expression` (`iex`) given the command line as
# text, and `&` and `.` in PowerShell; `@`, `call`, `start` (with its title and options) and `cmd /c` in cmd. The
# agent's own reader, `agent_code.read_shell_lines`, reads them the same way.
_PS_START = frozenset({"start-process", "saps", "start"})
_PS_START_SWITCHES = ("-wait", "-nonewwindow", "-passthru", "-usenewenvironment", "-loaduserprofile", "-whatif",
                      "-confirm")
_PS_EXPRESSION = frozenset({"iex", "invoke-expression"})


def _parameter(word: str, name: str, least: int = 2) -> bool:
    """Whether `word` names PowerShell's parameter `name` (`-FilePath`), which may be shortened to any start of at
    least `least` characters after the hyphen."""
    low = word.lower()
    return low.startswith("-") and len(low) > least and name.startswith(low)


def command_forms(segment: str, family_name: str | None) -> list:
    """The command lines a PowerShell or cmd command `segment` runs through a launcher (`Start-Process -FilePath
    claude -ArgumentList '-p', 'x'` runs `claude -p x`; `call claude -p x` runs `claude -p x`), as plain words;
    nothing for another command or another shell."""
    words = segment.split()
    if not words or family_name not in ("pwsh", "cmd"):
        return []
    out: list = []
    if family_name == "pwsh":
        stripped = False
        while words and words[0] in ("&", "."):
            words, stripped = words[1:], True
        if not words:
            return []
        first = words[0].lower()
        if first in _PS_START:
            file_path, arguments, positional = None, [], []
            j = 1
            while j < len(words):
                word = words[j]
                if any(_parameter(word, switch) for switch in _PS_START_SWITCHES):
                    j += 1
                    continue
                if _parameter(word, "-filepath", 1):
                    file_path = words[j + 1] if j + 1 < len(words) else None
                    j += 2
                    continue
                if _parameter(word, "-argumentlist") or word.lower() in ("-args", "-arguments"):
                    arguments = words[j + 1:]
                    break
                if word.startswith("-") and j + 1 < len(words) and file_path is not None:
                    j += 2
                    continue
                positional.append(word)
                j += 1
            if file_path is None and positional:
                file_path, positional = positional[0], positional[1:]
            if not arguments:
                arguments = positional
            if file_path:
                out.append(" ".join([file_path] + [w.strip(",") for w in arguments for w in w.split(",") if w]))
        elif first in _PS_EXPRESSION:
            rest = words[1:]
            if rest and _parameter(rest[0], "-command"):
                rest = rest[1:]
            if rest:
                out.append(" ".join(rest))
        elif stripped:
            out.append(" ".join(words))
        return out
    stripped = words[0].startswith("@") and len(words[0]) > 1
    if stripped:
        words = [words[0][1:]] + words[1:]
    first = words[0].lower()
    if first == "call" and len(words) > 1 and not words[1].startswith(":"):
        out.append(" ".join(words[1:]))
    elif first == "start" and len(words) > 1:
        # `start "title" program ...`: with its quotes taken out the title is a word like any other, so the program
        # may be either of the first two words after the options.
        j = 1
        while j < len(words) and words[j].startswith("/"):
            j += 1
        out.extend(" ".join(words[k:]) for k in (j, j + 1) if k < len(words))
    elif first in ("cmd", "cmd.exe") and len(words) > 2 and words[1].lower() in ("/c", "/k", "/s/c"):
        out.append(" ".join(words[2:]))
    elif stripped:
        out.append(" ".join(words))
    return out
