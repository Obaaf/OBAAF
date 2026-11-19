"""Command-line options an agent tool's own files warn about (flagship slice 2d.5c2a, OBAAF-GHA-026).

An agent tool's entry in the detection data may list `flags`: an option's spellings (`--yolo`, `-y`),
the values warned about when it takes one (`--permission-mode bypassPermissions`), and the documentation's
words. This module finds them in two places:

- a script that runs the tool's program (`claude`, `codex`, `gemini`, or its package through `npx` and the
  like): `read_script`;
- an input that an action of the entry hands to the program as options (`claude_args`, `codex-args`):
  `read_args`.

Both are read the wider way. A script is read twice and the two readings are added together: once as a
shell splits it into words (quotes and backslashes taken out, `$'...'` decoded, a variable the step's,
job's or workflow's `env` gives a plain value put in, `bash -c` and `eval` read again), and once with
quotes and backslashes simply removed and the text cut where a shell starts a command, as the agent
lane is found (so an option written inside a prompt's text is read as given). An option is matched in
any letter case, `--name=value` as well as `--name value`, and a one-letter option inside a group of
letters (`-yd`).

What the first reading cannot read is "cannot tell": a word of the program's command with a variable or
a substitution that is not inside quotes (the shell splits its value into words, any of which may be an
option), any `${{ }}` expression in the command (GitHub puts its text in before the shell reads the
line), the program run by `xargs` (its words come from the input), and an option that takes a value
given a value the checker cannot read. A word in double quotes is one word: one that starts with an
expansion is not read as an option (its value is not known), and one whose written start is the start
of a warned option (`"--dangerously-$X"`) is "cannot tell".
"""

from __future__ import annotations

import codecs
import json
import re
from dataclasses import dataclass, field

from obaaf.checker.workflow import (_SHELLS, _command_positions, _readings, _script_tokens, _sub_expressions,
                                    command_segments)

_EXPRESSION = "\x02OBAAFEXPR\x02"
_SEPARATORS = frozenset({";", "&&", "||", "&", ";;", "|", "|&", "(", ")", "\n"})
_VARIABLE_RE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
_ASSIGNED_RE = re.compile(
    r"(?:^|[\s;&|({`])(?:(?:export|local|readonly|typeset|declare|let)\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\[[^\]]*\])?\+?=|\b(?:read|mapfile|readarray)\s+(?:-\w+\s+(?:[^\s-]\S*\s+)?)*([A-Za-z_][A-Za-z0-9_]*)"
    r"|\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b|\bgetopts\s+\S+\s+([A-Za-z_][A-Za-z0-9_]*)")
# A plain value: no quote, backslash, expansion, backquote or character a shell treats specially.
_PLAIN_VALUE_RE = re.compile(r"[A-Za-z0-9 _.,:/@%+=-]*")
_ANSI_C_RE = re.compile(r"\$'((?:[^'\\]|\\.)*)'", re.S)
_EVAL = frozenset({"eval"})
_SPLITS_QUOTED_RE = re.compile(r"\$\{?[@*]|\$\{[A-Za-z_][A-Za-z0-9_]*\[[@*]\]|\$\{![A-Za-z_]")
_QUOTING_RE = re.compile(r"[\"'\\]")
_MAX_DEPTH = 3


@dataclass
class Reading:
    """What was found for one tool in one place: each warned flag matched (flag id -> (flag, the option as
    written, its value or None)), and the words that make the rest "cannot tell" (flag id -> words)."""
    hits: dict = field(default_factory=dict)
    unknown: dict = field(default_factory=dict)

    def hit(self, flag: dict, option: str, value: str | None) -> None:
        self.hits.setdefault(flag["id"], (flag, option, value))

    def cannot_tell(self, flag: dict, word: str) -> None:
        words = self.unknown.setdefault(flag["id"], [])
        if word not in words:
            words.append(word)

    def merge(self, other: "Reading") -> None:
        for fid, hit in other.hits.items():
            self.hits.setdefault(fid, hit)
        for fid, words in other.unknown.items():
            for word in words:
                if word not in self.unknown.setdefault(fid, []):
                    self.unknown[fid].append(word)


def _base(word: str) -> str:
    return word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1].casefold()


def _runs(word: str, programs: list, packages: list) -> bool:
    """Whether a word names the tool's program (`claude`, `/usr/local/bin/claude`, `CLAUDE` in any case) or
    its package, with or without a version (`@anthropic-ai/claude-code@2.1.0`)."""
    word = word.strip()
    if _base(word) in programs:
        return True
    low = word.casefold()
    for package in packages:
        if low == package or (low.startswith(package + "@") and len(low) > len(package) + 1):
            return True
    return False


def _equals(value: str, flag: dict) -> bool:
    folded = value.strip().strip("\"'").strip().casefold()
    return any(folded == str(v).strip().casefold() for v in flag.get("equals", []))


def _match(words: list, flags: list, reading: Reading) -> None:
    """Match the words of one command after its program. Each word is (text, kind): kind is None for a
    word whose text is known, "splits" for one with an expansion outside quotes, "expression" for one with
    a `${{ }}` expression, and "quoted" for one in quotes with an expansion (`prefix` is its known start)."""
    for flag in flags:
        takes = "equals" in flag
        for option in flag["options"]:
            o = option.casefold()
            short = len(o) == 2 and o[0] == "-" and o[1] != "-"
            for i, (word, kind, prefix) in enumerate(words):
                if kind in ("splits", "expression"):
                    reading.cannot_tell(flag, word)
                    continue
                low = (prefix if kind == "quoted" else word).casefold()
                if kind == "quoted":
                    # One word whose end is not known: "cannot tell" when what is written could start the
                    # option (`"--dangerously-$X"`, `"--permission-mode=$M"`); a word that starts with the
                    # expansion is not read as an option.
                    if low and (o.startswith(low) or low.startswith(o)):
                        reading.cannot_tell(flag, word)
                    continue
                if takes:
                    if low == o:
                        if i + 1 < len(words):
                            value, vkind, _vprefix = words[i + 1]
                            if vkind:
                                reading.cannot_tell(flag, f"{word} {value}")
                            elif _equals(value, flag):
                                reading.hit(flag, word, value)
                    elif low.startswith(o + "="):
                        if _equals(word[len(o) + 1:], flag):
                            reading.hit(flag, word[:len(o)], word[len(o) + 1:])
                    elif short and re.fullmatch(r"-[a-z]{2,}", low) and low.endswith(o[1]) and i + 1 < len(words):
                        value, vkind, _vprefix = words[i + 1]
                        if vkind:
                            reading.cannot_tell(flag, f"{word} {value}")
                        elif _equals(value, flag):
                            reading.hit(flag, word, value)
                else:
                    if low == o or low.startswith(o + "="):
                        reading.hit(flag, word, None)
                    elif short and re.fullmatch(r"-[a-z]{2,}", low) and o[1] in low[1:]:
                        reading.hit(flag, word, None)


def _decode_ansi_c(text: str) -> str:
    """`$'...'` strings, which bash decodes (`$'\\x2d-yolo'` is `--yolo`), written as single-quoted text."""
    def decode(m: re.Match) -> str:
        body = m.group(1)
        try:
            value = codecs.decode(body.replace("\\'", "'").encode("latin-1", "backslashreplace"), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            value = body
        return "'" + value.replace("'", "'\\''") + "'"
    return _ANSI_C_RE.sub(decode, text)


def _lines_as_commands(text: str) -> str:
    """The script with each line break outside quotes made a `;` (a quoted line break stays), a line ended
    by a backslash joined to the next, and each `#` comment taken out, so that it can be split as one text."""
    out, quote, escaped, previous = [], "", False, " "
    i = 0
    while i < len(text):
        ch = text[i]
        if escaped:
            escaped = False
            if ch == "\n":
                out[-1] = " "           # a backslash before a line break joins the lines
            else:
                out.append(ch)
            previous = ch
            i += 1
            continue
        if ch == "\\" and quote != "'":
            escaped = True
            out.append(ch)
            previous = ch
            i += 1
            continue
        if quote:
            if ch == quote:
                quote = ""
            out.append(ch)
        elif ch in "'\"":
            quote = ch
            out.append(ch)
        elif ch == "#" and (previous.isspace() or previous in ";&|("):
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
            continue
        elif ch == "\n":
            out.append(" ; ")
        else:
            out.append(ch)
        previous = ch
        i += 1
    return "".join(out)


def plain_variables(scopes: list, script: str) -> dict:
    """The variables whose value the checker can put into a script: each `env` value (the step's first,
    then the job's, then the workflow's) that is a plain value with no expression, and that the script
    does not set itself (a variable it sets is not known; `read`, `for` and `getopts` set one too)."""
    assigned = {next(g for g in m.groups() if g) for m in _ASSIGNED_RE.finditer(script)}
    out: dict = {}
    for scope in scopes:
        if not isinstance(scope, dict):
            continue
        for name, value in scope.items():
            if not isinstance(name, str) or name in out or name in assigned:
                continue
            if isinstance(value, bool):
                value = "true" if value else "false"
            if isinstance(value, (int, float)):
                value = str(value)
            if isinstance(value, str) and _PLAIN_VALUE_RE.fullmatch(value):
                out[name] = value
    for name in list(out):
        if name in assigned:
            del out[name]
    return out


def _put_in(text: str, variables: dict) -> str:
    if not variables or "$" not in text:
        return text
    return _VARIABLE_RE.sub(lambda m: variables.get(m.group(1) or m.group(2), m.group(0)), text)


def _word_kind(text: str, quoted: bool) -> tuple[str | None, str]:
    """(kind, known start) of a word: see `_match`."""
    if _EXPRESSION in text:
        return "expression", ""
    at = text.find("$")
    at_tick = text.find("`")
    if at_tick >= 0 and (at < 0 or at_tick < at):
        at = at_tick
    if at < 0:
        return None, text
    if not quoted or _SPLITS_QUOTED_RE.search(text):
        # Outside quotes the value is split into words; so is `"$@"` and `"${NAME[@]}"` inside them.
        return "splits", text[:at]
    return "quoted", text[:at]


def _commands(tokens: list) -> list:
    out, current = [], []
    for text, quoted in tokens:
        if not quoted and text in _SEPARATORS:
            if current:
                out.append(current)
            current = []
        else:
            current.append((text, quoted))
    if current:
        out.append(current)
    return out


def _read_tokens(text: str, programs: list, packages: list, flags: list, reading: Reading, depth: int) -> bool:
    """The first reading: the script split as a shell splits it. False when it cannot be split (an
    unclosed quote), which the second reading still covers."""
    tokens = _script_tokens(_lines_as_commands(_decode_ansi_c(text)))
    if tokens is None:
        return False
    for command in _commands(tokens):
        words = [t for t, _q in command]
        positions = _command_positions(words)
        for i, (word, quoted) in enumerate(command):
            if depth < _MAX_DEPTH:
                if _base(word) in _SHELLS:
                    flag_at = next((n for n in range(i + 1, min(i + 4, len(command)))
                                    if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", command[n][0])), None)
                    if flag_at is not None and flag_at + 1 < len(command):
                        _read_tokens(command[flag_at + 1][0], programs, packages, flags, reading, depth + 1)
                if _base(word) in _EVAL and i in positions:
                    _read_tokens(" ".join(t for t, _q in command[i + 1:]), programs, packages, flags, reading,
                                 depth + 1)
            if not _runs(word, programs, packages):
                continue
            rest = []
            for text_, quoted_ in command[i + 1:]:
                kind, prefix = _word_kind(text_, quoted_)
                rest.append((text_, kind, prefix))
            _match(rest, flags, reading)
            # `xargs ... claude`: the words xargs adds come from its input, which the checker does not read.
            if any(_base(w) == "xargs" and n in positions for n, w in enumerate(words[:i])):
                for flag in flags:
                    reading.cannot_tell(flag, "xargs")
    return True


def _read_segments(text: str, programs: list, packages: list, flags: list, reading: Reading) -> None:
    """The second reading: each reading of the text (as written, lines joined, quotes taken out,
    backslashes taken out) cut where a shell starts a command, wrappers taken off; a command that starts
    with the program has its words matched as known text."""
    for variant in _readings(text):
        for segment in command_segments(variant):
            words = segment.split()
            if not words or not _runs(words[0].strip("\"'"), programs, packages):
                continue
            _match([(w.strip("\"'"), None, w) for w in words[1:]], flags, reading)


def read_script(text: str, programs: list, packages: list, flags: list, variables: dict | None = None) -> Reading:
    """Each warned flag a script gives the tool's program, and what the checker cannot read there."""
    reading = Reading()
    if not text or not flags:
        return reading
    low = _QUOTING_RE.sub("", text).casefold()
    names = [p.casefold() for p in programs] + [p.casefold() for p in packages]
    if not any(name in low for name in names):
        return reading          # the program is not in the text at all (the common case, kept cheap)
    put = _put_in(text, variables or {})
    written: list = []

    def hold(expression: str) -> str:
        written.append(expression)
        return f"{_EXPRESSION}{len(written) - 1}{_EXPRESSION}"

    programs = [p.casefold() for p in programs]
    packages = [p.casefold() for p in packages]
    _read_tokens(_sub_expressions(put, hold), programs, packages, flags, reading, 0)
    if written:
        # Each held expression is shown as it was written.
        back = re.compile(re.escape(_EXPRESSION) + r"(\d+)" + re.escape(_EXPRESSION))
        reading.unknown = {fid: list(dict.fromkeys(back.sub(lambda m: written[int(m.group(1))], w) for w in words))
                           for fid, words in reading.unknown.items()}
    _read_segments(put, programs, packages, flags, reading)
    return reading


def read_args(value: str, flags: list, json_array: bool = False) -> Reading:
    """Each warned flag in an input an action hands to the program as options. `json_array`: the action
    reads a value that starts with `[` as a JSON array of words (codex-action's `codex-args`). Lines that
    start with `#` are taken out, as claude-code-action takes them out; a `#` later in a line is not."""
    reading = Reading()
    text = "\n".join(line for line in value.split("\n") if not line.strip().startswith("#"))
    words: list = []
    if json_array and text.strip().startswith("["):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            words = [(str(w), None, str(w)) for w in parsed]
    if not words:
        tokens = _script_tokens(_decode_ansi_c(text).replace("\n", " "))
        if tokens is not None:
            words = [(t, None, t) for t, _q in tokens]
    _match(words, flags, reading)
    unquoted = re.sub(r"[\\\"']", "", text)
    _match([(w, None, w) for w in unquoted.split()], flags, reading)
    return reading
