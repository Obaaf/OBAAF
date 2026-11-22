"""Command-line options an agent tool's own files warn about (flagship slice 2d.5c2a, OBAAF-GHA-026).

An agent tool's entry in the detection data may list `flags`: an option's spellings (`--yolo`, `-y`), the
values warned about when it takes one (`--permission-mode bypassPermissions`), and the documentation's
words. This module finds them in two places:

- a script that runs the tool's program (`claude`, `codex`, `gemini`, a path to one, or its package through
  `npx` and the like): `read_script`;
- an input that an action of the entry hands to the program as options (`claude_args`, `codex-args`):
  `read_args`.

A bash or sh script is read twice and the two readings are added together.

The first reading splits it as bash does (`_lex`): quotes, backslashes, `$'...'` and `$"..."` as bash
reads them; heredocs as data, unless a shell reads them; a variable put in where its value is known (an
`env` value with a plain value, or one plain assignment in the script itself); command substitutions,
`bash -c`, `sh -c`, `eval`, `env -S`, `su -c`, `script -c`, `flock -c`, `watch`, `npx -c`, aliases, and the
text a shell reads from a pipe, a heredoc or a here-string read again as scripts. The program counts only
where a command is started (after `sudo`, `env`, `timeout`, `xargs`, `find -exec`, `npx` and the like).
Whatever this reading cannot read, in a step that names the tool, is "cannot tell":

- a word of the program's command with a variable or substitution outside quotes, `"$@"` or
  `"${NAME[@]}"`, an unquoted glob or brace, or a `${{ }}` expression (GitHub puts its text in before the
  shell reads the line);
- a quoted word that could start a warned option (`"--dangerously-$X"`, `"$EMPTY"--yolo`,
  `"${F:---yolo}"`), and a warned option that takes a value given one the checker cannot read;
- the program run by `xargs` or `parallel`, whose words come from their input;
- a command the checker cannot name (`$C`, `"$(command -v claude)"`, `{claude,}`), a new name made for a
  program (`alias`, `hash`, `ln`, `cp`), `IFS` set, `eval` or a shell given text the checker cannot read,
  a script file written in the step and run, and text it cannot split (an unclosed quote) or nesting
  deeper than it reads.

The second reading is the widest: the text with comments and data heredocs taken out, quotes, backslashes,
brackets and commas removed, cut where a shell starts a command (`workflow.command_segments`); a command
that starts with the program has its words matched as known text. So an option written in a prompt's
text, or in a JavaScript or Python argument list, is read as given.

An option is matched in any letter case, as `--name=value` and `--name value`, and a one-letter option
inside a group of letters (`-yp`). Nothing after a word `--` is an option. `--name=false` (or `0`, `no`,
`off`) for an option that takes no value is not a match.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field

from obaaf.checker.workflow import _SHELLS, _command_positions, _sub_expressions, command_segments

_EXPR = "\x02"           # a `${{ }}` expression is held as \x02<n>\x02 while a script is read
_HOLE = "\x03"           # an expansion whose value is not known is marked \x03...\x03 in a word's text
_HOLE_RE = re.compile("\x03[^\x03]*\x03")


def _known_part(text: str) -> str:
    """A word's text with every expansion whose value is not known, and every expression, taken out."""
    return re.sub("\x02\\d*\x02", "", _HOLE_RE.sub("", text))
_MAX_DEPTH = 4
_DELIMITER_RE = re.compile(r"[ \t]*((?:[^\s;&|<>()'\"\\]|'[^']*'|\"[^\"]*\"|\\.)+)")
_PLAIN_RUN_RE = re.compile(r"[^\s;&|()<>'\"\\$`\x02*?\[{#]+")
_DOUBLE_RUN_RE = re.compile(r"[^\"\\$`\x02]+")
_SEPARATORS = frozenset({";", "&", "&&", "||", "|", "|&", ";;", ";&", ";;&", "(", ")", "\n"})
_REDIRECTS = frozenset({"<", ">", ">>", "<>", ">|", "&>", "&>>", ">&", "<&", "<<<"})
_PLAIN_VALUE_RE = re.compile(r"[A-Za-z0-9 _.,:/@%+=-]*")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_WINDOWS_SUFFIX_RE = re.compile(r"\.(exe|cmd|bat|ps1|com)$", re.I)
# What JavaScript's `\s` and `trim()` take for white space (the actions split and trim their inputs in
# JavaScript): Python's own white space and U+FEFF.
JS_SPACE = "".join(ch for ch in map(chr, range(0x3001)) if ch.isspace()) + "\ufeff"
_JS_SPACE = JS_SPACE
_JS_SPACE_RE = re.compile("[" + re.escape(_JS_SPACE) + "]")
_FALSE_VALUES = frozenset({"false", "0", "no", "off"})
# Commands that run the command or program named among their arguments.
_RUNS_ARGUMENTS = frozenset({
    "sudo", "doas", "env", "timeout", "nice", "ionice", "nohup", "stdbuf", "time", "command", "builtin", "exec",
    "chronic", "unbuffer", "runuser", "setsid", "flock", "retry", "xargs", "parallel", "find", "docker", "podman",
    "nerdctl", "kubectl", "nsenter", "chroot", "unshare", "firejail", "bwrap", "systemd-run", "strace", "ltrace",
    "valgrind", "gdb", "chrt", "taskset", "faketime", "proot", "toolbox", "distrobox", "flatpak-spawn", "wsl",
    "devbox", "poetry", "uv", "pipx", "mise", "asdf", "direnv", "dotenv",
    "op", "doppler", "infisical", "aws-vault", "with-contenv", "tini", "dumb-init", "catchsegv", "script", "su",
    "watch", "caffeinate", "npx", "bunx", "deno", "node", "nodejs", "ssh"})
# After a package runner (`uvx`, `uv ... run`, `pipx run`) a program may carry its version (`openhands@1.2`).
_VERSION_SUFFIX_RE = re.compile(r"(@|==|===|~=|!=|>=|<=|>|<|\[).*$", re.S)
# Commands whose arguments make another name for a program.
_RENAMES = frozenset({"alias", "hash", "ln", "cp", "install", "mv", "rsync", "link", "update-alternatives"})
# Option words of a shell that take the next word as their value.
_SHELL_VALUE_OPTIONS = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})
# Interpreters and the options that give them code to run.
_CODE_OPTIONS = {"perl": ("-e", "-E"), "python": ("-c",), "python3": ("-c",), "python2": ("-c",), "ruby": ("-e",),
                 "pypy": ("-c",), "pypy3": ("-c",),
                 "node": ("-e", "--eval", "-p", "--print"), "nodejs": ("-e", "--eval"), "php": ("-r",),
                 "pwsh": ("-c", "-command", "-Command", "-CommandWithArgs"),
                 "powershell": ("-c", "-command", "-Command"), "cmd": ("/c", "/C", "/k", "/K"),
                 "osascript": ("-e",), "lua": ("-e",), "tclsh": ("-c",), "awk": (), "gawk": (), "mawk": (),
                 "deno": ("eval",),
                 "bun": ("-e", "--eval", "-p", "--print")}
_RUNNER_STRING_OPTIONS = {"su": ("-c", "--command"), "runuser": ("-c", "--command"), "script": ("-c", "--command"),
                          "flock": ("-c", "--command"), "npx": ("-c", "--call"), "npm": ("-c", "--call"),
                          "sg": ("-c", "--command"), "expect": ("-c", "--command")}


@dataclass
class Reading:
    """What was found for one tool in one place: each warned flag matched (flag id -> (flag, the option as
    written, its value or None)), and the words that make the rest "cannot tell" (flag id -> words)."""
    hits: dict = field(default_factory=dict)
    unknown: dict = field(default_factory=dict)

    def hit(self, flag: dict, option: str, value: str | None) -> None:
        self.hits.setdefault(flag["id"], (flag, option, value))

    def cannot_tell(self, flag: dict, word: str) -> None:
        self.unknown.setdefault(flag["id"], {})[word] = None

    def merge(self, other: "Reading") -> None:
        for fid, hit in other.hits.items():
            self.hits.setdefault(fid, hit)
        for fid, words in other.unknown.items():
            self.unknown.setdefault(fid, {}).update(words)


# ------------------------------------------------------------------------------------------- matching
_TABLES: dict = {}


def _table(flags: list) -> tuple:
    """(long or two-letter option -> [flag], one letter -> [flag]) for a list of flags, worked out once."""
    key = id(flags)
    cached = _TABLES.get(key)
    if cached is not None and cached[0] is flags:
        return cached[1]
    options: dict = {}
    letters: dict = {}
    for flag in flags:
        for option in flag["options"]:
            o = option.casefold()
            options.setdefault(o, []).append(flag)
            if len(o) == 2 and o[0] == "-" and o[1] != "-":
                letters.setdefault(o[1], []).append(flag)
        if flag.get("prefixes") is True:
            # The tool's parser takes any beginning of a long option that no other option shares (argparse);
            # the checker does not know the tool's other options, so every beginning is read as the option,
            # the wider reading (one the tool finds ambiguous it refuses, and nothing runs).
            for option in flag["options"]:
                o = option.casefold()
                if o.startswith("--") and len(o) > 3:
                    for end in range(3, len(o)):
                        bucket = options.setdefault(o[:end], [])
                        if flag not in bucket:
                            bucket.append(flag)
    if len(_TABLES) >= 16:
        _TABLES.clear()
    _TABLES[key] = (flags, (options, letters))
    return options, letters


def _equals(value: str, flag: dict) -> bool:
    folded = value.strip(_JS_SPACE).strip("\"'").strip(_JS_SPACE).casefold()
    return any(folded == str(v).strip().casefold() for v in flag.get("equals", []))


def _takes_value(flag: dict) -> bool:
    return "equals" in flag or "unless" in flag


def _unless(value: str, flag: dict) -> bool:
    """Whether a value is one of those that make an `unless` option not a match (Cline's `false`)."""
    folded = value.strip(_JS_SPACE).strip("\"'").strip(_JS_SPACE).casefold()
    return any(folded == str(v).strip().casefold() for v in flag.get("unless", []))


def _match_known(words: list, flags: list, reading: Reading) -> None:
    """Match a command's words after its program, each known text. Stops at a word `--`."""
    options, letters = _table(flags)
    for i, word in enumerate(words):
        low = word.casefold()
        if low == "--" and not (i and words[i - 1].startswith("-") and words[i - 1] != "--"):
            return                  # options end (a `--` right after an option may be that option's value)
        if not low.startswith("-"):
            continue
        name, eq, after = low.partition("=")
        for flag in options.get(name, ()):
            if "unless" in flag:
                # An option that is on unless it is given one of these values (`cline --auto-approve "fix"`
                # is `--auto-approve true`, found by 2d.5c2b's second review); a value not known is read below.
                value = word[len(name) + 1:] if eq else (words[i + 1] if i + 1 < len(words) else None)
                if value is not None and any(c in value for c in ("\x00", "\x02", "$", "`")):
                    continue        # a value the checker cannot read: "cannot tell", below and in the reader
                if eq:
                    if not _unless(word[len(name) + 1:], flag):
                        reading.hit(flag, word[:len(name)], word[len(name) + 1:])
                elif i + 1 >= len(words) or not _unless(words[i + 1], flag):
                    shown = words[i + 1] if i + 1 < len(words) and words[i + 1].strip().casefold() == "true" else None
                    reading.hit(flag, word, shown)
                continue
            if _takes_value(flag):
                if eq:
                    if _equals(word[len(name) + 1:], flag):
                        reading.hit(flag, word[:len(name)], word[len(name) + 1:])
                elif i + 1 < len(words) and _equals(words[i + 1], flag):
                    reading.hit(flag, word, words[i + 1])
            elif not eq or after.strip() not in _FALSE_VALUES:
                reading.hit(flag, word, None)
        group = name if eq else low
        if len(group) > 2 and group[1] != "-" and group[1:].isalpha() and not (eq and len(group) == 2):
            # A group of one-letter options (`-yp`); with `=`, the last letter takes the value (`-dy=true`, as
            # yargs reads it, found by 2d.5c2b's review).
            for letter in dict.fromkeys(group[1:]):
                for flag in letters.get(letter, ()):
                    if _takes_value(flag):
                        if letter == group[-1]:
                            if eq and _equals(after, flag):
                                reading.hit(flag, word, after)
                            elif not eq and i + 1 < len(words) and _equals(words[i + 1], flag):
                                reading.hit(flag, word, words[i + 1])
                    elif not (eq and letter == group[-1] and after.strip() in _FALSE_VALUES):
                        reading.hit(flag, word, None)


def _could_start(text: str, flags: list) -> list:
    """The flags one of whose options a word could be or begin with, given the text it is known to start
    with (`--dangerously-` could become `--dangerously-skip-permissions`); none for an empty start."""
    low = text.casefold()
    if not low:
        return []
    out = []
    for flag in flags:
        for option in flag["options"]:
            o = option.casefold()
            if o.startswith(low) or low.startswith(o) or (len(o) == 2 and o[0] == "-" and o[1] != "-"
                                                          and low.startswith("-") and not low.startswith("--")):
                out.append(flag)
                break
    return out


# --------------------------------------------------------------------------------------------- the lexer
@dataclass
class Word:
    text: str = ""              # the word as bash reads it, with an unknown expansion left as written
    shown: str = ""             # the word as written in the script
    unquoted: bool = False      # an unknown expansion outside quotes (its value is split into words)
    quoted: bool = False        # an unknown expansion inside double quotes (one word)
    splits: bool = False        # `"$@"` or `"${NAME[@]}"`: one word for each value
    glob: bool = False          # an unquoted `*`, `?` or `[`
    brace: bool = False         # an unquoted `{a,b}` or `{a..b}`
    expr: bool = False          # a `${{ }}` expression
    redirect: bool = False      # the target of a redirection, not an argument
    redirect_op: str = ""        # that redirection's operator (`>>`, `<>`, ...), for a target
    candidates: list = field(default_factory=list)   # what the word could start with or be, where unknown
    inner: list = field(default_factory=list)        # the scripts of its command substitutions

    @property
    def computed(self) -> bool:
        return self.unquoted or self.quoted or self.splits or self.glob or self.brace or self.expr


@dataclass
class Command:
    words: list = field(default_factory=list)
    stdin: list = field(default_factory=list)        # (kind, text, literal): heredocs and here-strings
    piped: bool = False                              # its input is the output of the command before it
    before: "Command | None" = None                  # that command
    ended_by: str = ""                               # the operator after it


_ANSI_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b",
                 "E": "\x1b", "\\": "\\", "'": "'", '"': '"', "?": "?"}


def _ansi_c(body: str) -> str:
    out, i = [], 0
    while i < len(body):
        ch = body[i]
        if ch != "\\" or i + 1 >= len(body):
            out.append(ch)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in _ANSI_ESCAPES:
            out.append(_ANSI_ESCAPES[nxt])
            i += 2
        elif nxt in "01234567":
            m = re.match(r"[0-7]{1,3}", body[i + 1:])
            out.append(chr(int(m.group(0), 8) & 0xFF))
            i += 1 + len(m.group(0))
        elif nxt in "xuU":
            size = {"x": 2, "u": 4, "U": 8}[nxt]
            m = re.match(r"[0-9A-Fa-f]{1,%d}" % size, body[i + 2:])
            if m:
                try:
                    out.append(chr(int(m.group(0), 16)))
                except (ValueError, OverflowError):
                    pass
                i += 2 + len(m.group(0))
            else:
                out.append("\\" + nxt)
                i += 2
        elif nxt == "c" and i + 2 < len(body):
            out.append(chr(ord(body[i + 2]) & 0x1F))
            i += 3
        else:
            out.append("\\" + nxt)
            i += 2
    return "".join(out)


def _balanced(text: str, i: int, open_: str, close: str) -> int:
    """The index just after the `close` that ends what opens at `text[i]`, skipping quoted text, the
    bodies of heredocs, and, inside `$( )`, the `)` that ends a `case` pattern; len(text) when it does
    not end."""
    depth, quote = 0, ""
    cases: list = []                # the depths at which a `case` is open
    heredocs: list = []
    while i < len(text):
        ch = text[i]
        if not quote and open_ == "(":
            if ch == "\n" and heredocs:
                for delim, tabs in heredocs:
                    while i < len(text):
                        end = text.find("\n", i + 1)
                        line = text[i + 1:] if end < 0 else text[i + 1:end]
                        i = len(text) if end < 0 else end
                        if (line.lstrip("\t") if tabs else line) == delim:
                            break
                heredocs = []
                i += 1
                continue
            if ch == "<" and text.startswith("<<", i) and not text.startswith("<<<", i):
                m = _DELIMITER_RE.match(text, i + (3 if text.startswith("<<-", i) else 2))
                if m:
                    raw = m.group(1)
                    delim = re.sub(r"\\(.)", r"\1", re.sub(r"'([^']*)'|\"([^\"]*)\"",
                                                            lambda q: q.group(1) or q.group(2) or "", raw))
                    heredocs.append((delim, text.startswith("<<-", i)))
                    i = m.end()
                    continue
            if text.startswith("case", i) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")) and (
                    i + 4 >= len(text) or text[i + 4] in " \t\n"):
                cases.append(depth)
            elif text.startswith("esac", i) and cases and (i == 0 or not text[i - 1].isalnum()) and (
                    i + 4 >= len(text) or not (text[i + 4].isalnum() or text[i + 4] == "_")):
                cases.pop()
            elif ch == ")" and cases and depth == cases[-1] + 1 and depth > 1:
                i += 1              # a `case` pattern's `)`
                continue
        if quote:
            if ch == "\\" and quote == '"':
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch == "\\":
            i += 2
            continue
        elif ch in "'\"":
            quote = ch
        elif ch == open_:
            depth += 1
        elif ch == close:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(text)


class _Lexer:
    """Bash's reading of a script, as far as this rule needs it: words, operators, redirections, heredocs
    and here-strings, with quotes and expansions marked. `problem` is set where it cannot read the text."""

    def __init__(self, text: str, variables: dict) -> None:
        self.text = text
        self.variables = variables
        self.problem = ""

    def commands(self) -> list:
        tokens = self._tokens()
        out: list = []
        current = Command()
        for token in tokens:
            if isinstance(token, Word):
                current.words.append(token)
            elif isinstance(token, tuple):
                current.stdin.append(token)
            elif token in _SEPARATORS:
                had = bool(current.words or current.stdin)
                current.ended_by = token
                if had:
                    out.append(current)
                current = Command(piped=token in ("|", "|&"), before=current if had else None)
        if current.words or current.stdin:
            out.append(current)
        return out

    # The tokens: Word, an operator (str), or (kind, text, literal) for a heredoc or here-string.
    def _tokens(self) -> list:
        text, n = self.text, len(self.text)
        tokens: list = []
        pending: list = []          # heredocs waiting for the end of the line: [index in tokens, delim, tabs, quoted]
        i = 0
        word: Word | None = None
        start = 0
        redirect_next = False
        redirect_op = ""
        here_string_next = False

        def finish(end: int) -> None:
            nonlocal word, redirect_next, redirect_op, here_string_next
            if word is not None:
                word.shown = text[start:end]
                if here_string_next:
                    tokens.append(("herestring", word.text, not word.computed))
                    here_string_next = False
                    redirect_next = False
                else:
                    word.redirect = redirect_next
                    word.redirect_op = redirect_op if redirect_next else ""
                    redirect_next = False
                    tokens.append(word)
            word = None

        def begin(at: int) -> Word:
            nonlocal word, start
            if word is None:
                word = Word()
                start = at
            return word

        while i < n:
            ch = text[i]
            if ch == "\n":
                finish(i)
                tokens.append("\n")
                i += 1
                if pending:
                    i = self._heredoc_bodies(i, pending, tokens)
                    pending = []
                continue
            if ch in " \t":
                finish(i)
                i += 1
                continue
            if ch == "#" and word is None:
                end = text.find("\n", i)
                i = n if end < 0 else end
                continue
            if ch == "\\":
                if i + 1 < n and text[i + 1] == "\n":
                    i += 2
                    continue
                w = begin(i)
                if i + 1 < n:
                    w.text += text[i + 1]
                i += 2
                continue
            if ch == "'":
                w = begin(i)
                end = text.find("'", i + 1)
                if end < 0:
                    self.problem = "an unclosed quote"
                    end = n
                w.text += text[i + 1:end]
                i = end + 1
                continue
            if ch == '"':
                w = begin(i)
                i = self._double(i + 1, w)
                continue
            if ch == "$" and i + 1 < n and text[i + 1] == "'":
                w = begin(i)
                m = re.compile(r"((?:[^'\\]|\\.)*)'", re.S).match(text, i + 2)
                if not m:
                    self.problem = "an unclosed quote"
                    w.text += text[i + 2:]
                    i = n
                else:
                    w.text += _ansi_c(m.group(1))
                    i = m.end()
                continue
            if ch == "$" and i + 1 < n and text[i + 1] == '"':
                w = begin(i)
                i = self._double(i + 2, w)
                continue
            if ch == "$" or ch == "`" or ch == _EXPR:
                w = begin(i)
                i = self._expansion(i, w, quoted=False)
                continue
            if ch in "<>" and i + 1 < n and text[i + 1] == "(":
                # Process substitution: one word (a /dev/fd path) whose text runs a script.
                w = begin(i)
                end = _balanced(text, i + 1, "(", ")")
                w.inner.append(text[i + 2:end - 1])
                w.text += text[i:end]
                w.unquoted = True
                w.candidates.append("")
                i = end
                continue
            if ch in ";&|()<>":
                if word is not None and ch in "<>" and word.text.isdigit() and not word.computed and \
                        text[start:i] == word.text:
                    word = None                     # `2>`: the number is part of the redirection
                else:
                    finish(i)
                op = self._operator(i)
                i += len(op)
                if op in ("<<", "<<-"):
                    m = _DELIMITER_RE.match(text, i)
                    if m:
                        raw = m.group(1)
                        delim = re.sub(r"\\(.)", r"\1", re.sub(r"'([^']*)'|\"([^\"]*)\"",
                                                                lambda q: q.group(1) or q.group(2) or "", raw))
                        pending.append((len(tokens), delim, op == "<<-", raw != delim))
                        i = m.end()
                    continue
                if op == "<<<":
                    here_string_next = True
                    continue
                if op in _REDIRECTS:
                    redirect_next = True
                    redirect_op = op
                    continue
                tokens.append(op)
                continue
            m = _PLAIN_RUN_RE.match(text, i)
            if m and m.end() > i + 1:
                begin(i).text += m.group(0)
                i = m.end()
                continue
            w = begin(i)
            if ch in "*?" or (ch == "[" and "]" in text[i + 1:i + 200].split()[0] if text[i + 1:i + 200].split()
                              else False):
                w.glob = True           # `[` only with a `]` after it in the word (`[[` and `[` are tests)
            if ch == "{" and re.match(r"\{[^{}\s]*(,|\.\.)[^{}\s]*\}", text[i:]):
                w.brace = True
            w.text += ch
            i += 1
        finish(n)
        if pending:
            self.problem = "a heredoc with no end"
        return tokens

    def _operator(self, i: int) -> str:
        for op in ("<<<", "<<-", ";;&", "&>>", "&&", "||", ";;", ";&", "|&", ">>", "<<", ">&", "<&", "&>", "<>",
                   ">|", ";", "&", "|", "(", ")", "<", ">"):
            if self.text.startswith(op, i):
                return op
        return self.text[i]

    def _heredoc_bodies(self, i: int, pending: list, tokens: list) -> int:
        text = self.text
        for offset, (index, delim, tabs, quoted) in enumerate(pending):
            index += offset
            body: list = []
            while True:
                if i >= len(text):
                    self.problem = "a heredoc with no end"
                    break
                end = text.find("\n", i)
                line = text[i:] if end < 0 else text[i:end]
                i = len(text) if end < 0 else end + 1
                if (line.lstrip("\t") if tabs else line) == delim:
                    break
                body.append(line.lstrip("\t") if tabs else line)
            tokens.insert(index, ("heredoc", "\n".join(body), quoted))
        return i

    def _double(self, i: int, w: Word) -> int:
        """Read a double-quoted part from `i` (just after the quote) into `w`; the index after it."""
        text, n = self.text, len(self.text)
        while i < n:
            m = _DOUBLE_RUN_RE.match(text, i)
            if m and m.end() > i:
                w.text += m.group(0)
                i = m.end()
                continue
            ch = text[i]
            if ch == '"':
                return i + 1
            if ch == "\\" and i + 1 < n:
                nxt = text[i + 1]
                if nxt in '$`"\\':
                    w.text += nxt
                elif nxt != "\n":
                    w.text += "\\" + nxt
                i += 2
                continue
            if ch in "$`" + _EXPR:
                i = self._expansion(i, w, quoted=True)
                continue
            w.text += ch
            i += 1
        self.problem = "an unclosed quote"
        return n

    def _expansion(self, i: int, w: Word, quoted: bool) -> int:
        """Read the expansion at `i` into `w`; the index after it."""
        text, n = self.text, len(self.text)
        ch = text[i]

        def unknown(raw: str, defaults: list = ()) -> None:
            if quoted:
                w.quoted = True
            else:
                w.unquoted = True
            w.candidates.append(w.text)                 # what is known of the word before it
            w.candidates.extend(w.text + d for d in defaults)
            w.text += _HOLE + raw + _HOLE               # marked, so that it can be taken out again

        if ch == _EXPR:
            end = text.find(_EXPR, i + 1)
            end = n if end < 0 else end + 1
            w.expr = True
            w.text += text[i:end]
            return end
        if ch == "`":
            end = i + 1
            while end < n and text[end] != "`":
                end += 2 if text[end] == "\\" else 1
            w.inner.append(text[i + 1:end])
            unknown(text[i:end + 1])
            return end + 1
        # `$`
        if i + 1 >= n:
            w.text += "$"
            return i + 1
        nxt = text[i + 1]
        if text.startswith("$((", i):
            end = _balanced(text, i + 1, "(", ")")
            w.text += "0"                               # arithmetic gives a number, never an option
            return end
        if nxt == "(":
            end = _balanced(text, i + 1, "(", ")")
            w.inner.append(text[i + 2:end - 1])
            unknown(text[i:end])
            return end
        if nxt == "{":
            end = _balanced(text, i + 1, "{", "}")
            body = text[i + 2:end - 1]
            if re.fullmatch(r"@|\*|[A-Za-z_][A-Za-z0-9_]*\[[@*]\]|[@*]:.*|[A-Za-z_][A-Za-z0-9_]*\[[@*]\]:.*", body) \
                    or body.startswith("!"):
                w.splits = True
            defaults = []
            dm = re.match(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?(:?[-+=?])(.*)\Z", body, re.S)
            if dm:
                defaults.append(dm.group(2).strip("\"'"))
            unknown(text[i:end], defaults)
            return end
        m = _IDENT_RE.match(text, i + 1)
        if m:
            unknown("$" + m.group(0))
            return m.end()
        if nxt in "@*":
            w.splits = True
            unknown("$" + nxt)
            return i + 2
        if nxt in "#?$!-":
            w.text += "0"
            return i + 2
        if nxt.isdigit():
            unknown("$" + nxt)
            return i + 2
        w.text += "$"
        return i + 1


def _substitute(text: str, variables: dict) -> str:
    """The script with each `$NAME` and `${NAME}` whose value is known put in, outside single quotes (a plain
    value has no quote, expansion or backslash, so bash would read the result as it reads the variable:
    split into words outside double quotes, one word inside them)."""
    if not variables or "$" not in text:
        return text
    out, i, n, quote = [], 0, len(text), ""
    while i < n:
        ch = text[i]
        if quote == "'":
            out.append(ch)
            if ch == "'":
                quote = ""
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            out.append(text[i:i + 2])
            i += 2
            continue
        if ch == "'" and not quote:
            quote = "'"
            if i > 0 and text[i - 1] == "$":
                quote = "'"
            out.append(ch)
            i += 1
            continue
        if ch == '"':
            quote = "" if quote == '"' else '"'
            out.append(ch)
            i += 1
            continue
        if ch == "$":
            m = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))").match(text, i)
            if m:
                name = m.group(1) or m.group(2)
                if name in variables:
                    out.append(variables[name])
                    i = m.end()
                    continue
        out.append(ch)
        i += 1
    return "".join(out)


def _lex(text: str, variables: dict) -> tuple[list, str]:
    lexer = _Lexer(_substitute(text, variables), variables)
    commands = lexer.commands()
    return commands, lexer.problem


def lex(text: str) -> tuple[list, str]:
    """A bash script's commands as `Command`s of `Word`s, with nothing put in for its variables, and the
    problem that stopped the reading ("" when it read the whole text). An unknown expansion stays in a
    word's `text` between two `\\x03` marks; a redirection's target is a word with `redirect` set. Used
    by OBAAF-GHA-016's reading of writes to `GITHUB_ENV` (flagship slice 2d.13)."""
    return _lex(text, {})


# ------------------------------------------------------------------------------------- reading commands
def _base(word: str) -> str:
    return _WINDOWS_SUFFIX_RE.sub("", word.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]).casefold()


def _is_package(word: str, packages: list) -> bool:
    low = word.casefold()
    return any(low == p or (low.startswith(p + "@") and len(low) > len(p) + 1) for p in packages)


def _names_package_path(word: str, packages: list) -> bool:
    low = word.casefold().replace("\\", "/")
    return any(f"/{p}/" in low or low.startswith(p + "/") for p in packages)


@dataclass
class _Context:
    programs: list
    packages: list
    flags: list
    variables: dict
    mentioned: bool
    written: set                    # files the script writes (`> f`, `tee f`)
    reading: Reading
    depth: int = 0
    loose: bool = False             # the tool's name appears in the text at all, even inside a word
    prose: bool = False             # text that may be prose (another input, an `env` value, an argument)

    def cannot_tell(self, word: str) -> None:
        if self.mentioned:
            for flag in self.flags:
                self.reading.cannot_tell(flag, word)


def _arguments(words: list) -> list:
    return [w for w in words if not w.redirect]


def _read_program_args(words: list, ctx: _Context) -> None:
    """The words after the program: known ones are matched; what is not known is "cannot tell"."""
    known: list = []
    for n, w in enumerate(words):
        if w.text == "--" and not w.computed and not (n and words[n - 1].text.startswith("-")
                                                      and words[n - 1].text != "--"):
            break
        if w.expr or w.unquoted or w.splits or w.glob:
            for flag in ctx.flags:
                ctx.reading.cannot_tell(flag, w.shown)
            known.append("\x00")                        # a word whose text is not known
            continue
        if w.brace:
            expansions = _brace_expansions(w.text)
            if expansions is None:
                for flag in ctx.flags:
                    ctx.reading.cannot_tell(flag, w.shown)
                known.append("\x00")
            else:
                for expansion in expansions:
                    _match_known([expansion], ctx.flags, ctx.reading)
                known.append(expansions[0] if expansions else "")
            continue
        if w.quoted:
            stripped = _known_part(w.text)
            for candidate in [*(_known_part(c) for c in w.candidates), stripped]:
                for flag in _could_start(candidate, ctx.flags):
                    ctx.reading.cannot_tell(flag, w.shown)
            known.append("\x00")
            continue
        known.append(w.text)
    _match_known(known, ctx.flags, ctx.reading)
    # A warned option that takes a value, given a word that is not known.
    options, _letters = _table(ctx.flags)
    for i, text in enumerate(known[:-1]):
        flags = options.get(text.casefold(), ())
        if known[i + 1] == "\x00":
            for flag in flags:
                if _takes_value(flag):
                    ctx.reading.cannot_tell(flag, f"{text} {words[i + 1].shown if i + 1 < len(words) else ''}".strip())


def _brace_expansions(text: str) -> list | None:
    """The words one comma brace in a word expands to (`a{b,c}d` is `abd` and `acd`), or None for what is
    not one plain comma brace (a range, nesting, more than one brace)."""
    m = re.fullmatch(r"([^{}]*)\{([^{}]*,[^{}]*)\}([^{}]*)", text)
    if not m or ".." in m.group(2):
        return None
    return [m.group(1) + a + m.group(3) for a in m.group(2).split(",")]


def _read_text(text: str, ctx: _Context) -> None:
    """Read a script (or a part of one: `bash -c`, a substitution) with the first reading."""
    if ctx.depth > _MAX_DEPTH:
        ctx.cannot_tell("nesting deeper than the checker reads: " + _fact_text(text))
        return
    commands, problem = _lex(text, ctx.variables)
    if problem and not ctx.prose:
        ctx.cannot_tell(f"{problem}: " + _fact_text(text))
    case_depth, pattern_next = 0, False
    for command in commands:
        first = command.words[0].text if command.words and not command.words[0].computed else ""
        # `case WORD in PATTERN) ...;; PATTERN) ...;; esac`: a pattern is not a command.
        if first == "case":
            case_depth += 1
            texts = [w.text for w in command.words]
            after = command.words[texts.index("in") + 1:] if "in" in texts else []
            pattern_next = not (after and command.ended_by == ")")
            command.words = []
        elif first == "esac" and case_depth:
            case_depth -= 1
            command.words = command.words[1:]
            pattern_next = False
        elif case_depth and pattern_next and command.ended_by == ")":
            command.words = []
            pattern_next = False
        if case_depth and command.ended_by in (";;", ";&", ";;&"):
            pattern_next = True
        _read_command(command, ctx)
        for w in command.words:
            for inner in w.inner:
                _read_nested(inner, ctx)


def _fact_text(text: str) -> str:
    """A part of a script as a fact: the text itself up to 120 characters, else its start and a digest."""
    if len(text) <= 120:
        return text
    return text[:80] + " sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def _read_nested(text: str, ctx: _Context, prose: bool | None = None) -> None:
    ctx.depth += 1
    before = ctx.prose
    if prose is not None:
        ctx.prose = prose
    try:
        _read_text(text, ctx)
    finally:
        ctx.depth -= 1
        ctx.prose = before


def _pipeline(command: Command) -> str:
    """The pipeline that feeds a command, as written, for a fact (`curl ... | base64 -d | bash`)."""
    parts: list = []
    current = command
    while current is not None and len(parts) < 8:
        parts.append(" ".join(w.shown for w in current.words))
        current = current.before if current.piped else None
    return _fact_text(" | ".join(reversed(parts)))


def _literal_output(command: Command | None) -> str | None:
    """What `echo` or `printf` with known words writes, for a shell that reads it from a pipe."""
    if command is None or not command.words:
        return None
    name = _base(command.words[0].text)
    words = _arguments(command.words[1:])
    if name not in ("echo", "printf") or any(w.computed for w in words):
        return None
    words = [w.text for w in words]
    while name == "echo" and words and re.fullmatch(r"-[neE]+", words[0]):
        words = words[1:]
    return " ".join(words)


# Commands whose arguments are data: the program named among them is not run by them.
_DATA_COMMANDS = frozenset({
    "echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "git", "gh", "cat", "head", "tail", "less", "more",
    "sed", "tr", "cut", "sort", "uniq", "wc", "tee", "test", "[", "[[", "jq", "yq", "curl", "wget", "ls", "mkdir",
    "rm", "rmdir", "touch", "chmod", "chown", "cd", "pushd", "popd", "export", "declare", "local", "readonly",
    "typeset", "unset", "read", "mapfile", "readarray", "let", "shift", "set", "return", "exit", "true", "false",
    ":", "basename", "dirname", "realpath", "readlink", "which", "type", "whereis", "file", "stat", "du", "npm",
    "pnpm", "yarn", "pip", "pip3", "apt", "apt-get", "brew", "yum", "dnf", "apk", "conda", "mamba", "gem",
    "cargo", "go", "tar", "zip", "unzip", "gzip", "gunzip", "base64", "md5sum", "sha256sum", "shasum", "diff",
    "cmp", "date", "sleep", "kill", "pkill", "pgrep", "ps", "printenv", "find", "for", "select", "in", "do", "done",
    "then", "else", "elif", "fi", "while", "until", "if", "function", "}", "{", "!",
    "make", "cmake", "dotnet", "mvn", "gradle", "corepack", "volta-install", "poetry", "uv", "pipenv",
    "hatch", "pdm"})
_INTERPRETER_RE = re.compile(r"(python|python2|python3|pypy|pypy3|ruby|perl|node|nodejs|php|lua|bun|deno|osascript|tclsh|"
                             r"pwsh|powershell|cmd|awk|gawk|mawk)(?:[0-9.]*)(?:\.exe)?")


def _read_command(command: Command, ctx: _Context) -> None:
    words = [w for w in command.words if not w.redirect]
    if words and words[0].text == "coproc" and not words[0].computed:
        words = words[2:] if len(words) > 2 and words[2].text == "{" else words[1:]
    if not words:
        return
    texts = [w.text for w in words]
    bases = [_base(t) if not w.computed else "" for t, w in zip(texts, words)]
    # `GIT_CONFIG_VALUE_0='!cmd'` gives git a setting, which may be a command it runs.
    for t in texts:
        m = re.match(r"GIT_CONFIG_VALUE_\d+=(.*)", t, re.S)
        if m and mentions(m.group(1), ctx.programs, ctx.packages):
            value = m.group(1)
            _read_nested(value[1:] if value.startswith("!") else value, ctx)
    # `IFS=...` on its own changes how every later expansion is split (`IFS=, read` sets it for `read` only).
    if ctx.loose and all(re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=", t) for t in texts) and any(
            t.startswith(("IFS=", "IFS+=")) for t in texts):
        for flag in ctx.flags:
            ctx.reading.cannot_tell(flag, " ".join(w.shown for w in words)[:120])
    # `_command_positions` also takes a word that starts with `$(` or a backquote for a command; here such
    # a word counts only where a command starts (its own script is read anyway).
    positions = sorted(_command_positions([("x" if t.startswith(("$(", "`")) else t) for t in texts]))
    started = set(positions)
    for i, t in enumerate(texts):
        if t in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(texts):
            started.add(i + 1)
    runs_input = next((i for i in positions if bases[i] in ("xargs", "parallel")), None)
    for i in sorted(started):
        w = words[i]
        if w.computed and not re.match(r"[A-Za-z_][A-Za-z0-9_]*\+?=", w.text):
            # What is written of the name decides: `"$(npm prefix -g)/bin/claude"` is the program,
            # `"$GITHUB_WORKSPACE/scripts/post.sh"` is not, and `$C` or `"$(command -v claude)"` may be.
            literal = _known_part(w.text)
            base = _base(literal) if not literal.endswith("/") else ""
            if base in ctx.programs and not (w.glob or w.brace):
                _read_program_args(_arguments(words[i + 1:]), ctx)
                return
            if (not base or w.glob or w.brace or base in ctx.programs) and not ctx.prose and (
                    ctx.mentioned or appears(w.shown, ctx.programs, ctx.packages)):
                for flag in ctx.flags:
                    ctx.reading.cannot_tell(flag, w.shown)
            continue
        if not w.computed and i in positions and _written(texts[i], ctx):
            ctx.cannot_tell(f"{texts[i]}, a file written in the step")
            return
        if _start(words, bases, i, ctx, command, runs_input):
            return
    first = max(positions) if positions else 0          # the command itself, after `sudo`, `env` and the like
    name0 = bases[first]
    if name0 in _RENAMES:
        if any(bases[j] in ctx.programs or _is_package(texts[j], ctx.packages) or (
                words[j].computed and mentions(words[j].shown, ctx.programs, ctx.packages))
               for j in range(first + 1, len(words))):
            ctx.cannot_tell(" ".join(w.shown for w in words[first:])[:120])
        return
    if name0 == "git":
        # A git setting whose value names the tool can be a command git runs (`alias.r=!cmd`, `diff.external`,
        # `core.sshCommand`, `credential.helper`): given with `-c` or `git config`, it is read as a command line.
        for j in range(first + 1, len(words)):
            m = re.match(r"[A-Za-z][\w-]*(?:\.[^=\s]+)+(?:=|$)", texts[j])
            if m and (j > first + 1 and texts[j - 1] in ("-c", "config", "--global", "--local", "--system",
                                                          "--add", "--replace-all") or "=" in texts[j]):
                value = texts[j][m.end():] if "=" in texts[j] else (texts[j + 1] if j + 1 < len(texts) else "")
                if mentions(value, ctx.programs, ctx.packages):
                    _read_nested(value[1:] if value.startswith("!") else value, ctx)
        return
    sub = texts[first + 1] if first + 1 < len(words) else ""
    if name0 in ("docker", "podman", "nerdctl", "kubectl"):
        # Data only where a subcommand that does not run a command is among the next words and none that does
        # (`docker build -t claude`, `kubectl get pods -l app=claude`); a global option, with or without a
        # value, is skipped by looking for either kind (fails closed: neither found, the words are read).
        runs = ("run", "exec", "compose", "container", "debug", "attach")
        data = ("build", "buildx", "pull", "push", "tag", "images", "image", "ps", "logs", "login", "logout",
                "inspect", "rm", "rmi", "stop", "kill", "save", "load", "network", "volume", "get", "describe",
                "apply", "create", "delete", "label", "annotate", "rollout", "scale", "config", "version")
        leading = texts[first + 1:first + 12]
        # A run-type word anywhere among them is read (an option's value spelled `build` decides nothing).
        if not any(t in runs for t in leading) and any(t in data for t in leading):
            return
    # uv takes its global options before and between its subcommand's words (`uv -q tool run`), so a `run`
    # among its next words is enough (found by 2d.5c2b's second review).
    uv_runs = name0 == "uv" and "run" in texts[first + 1:first + 12]
    if name0 in _DATA_COMMANDS and sub not in ("run", "exec", "x", "dlx") and not uv_runs:
        return                      # `conda run`, `poetry run`, `uv run`, `uv tool run`, `npm exec` run what follows
    # A package runner that runs what it is given: `uvx`, `uv ... run`, `pipx run` (not `pipx install`).
    runner = name0 == "uvx" or uv_runs or (name0 == "pipx" and "run" in texts[first + 1:first + 4])
    # Any other command (`cross-env`, `tmux`, `docker run`, `ssh`, `trap`): a word among its arguments may
    # start the program, a shell or another runner, or be a command line of its own.
    for j in range(first + 1, len(words)):
        w = words[j]
        if runner and w.glob and not (w.expr or w.unquoted or w.quoted or w.splits or w.brace) and (
                _VERSION_SUFFIX_RE.sub("", _base(w.text)) in ctx.programs):
            # `uvx openhands[all]`: bash passes a glob that matches nothing through as written.
            name = _VERSION_SUFFIX_RE.sub("", _base(w.text))
            bases = bases[:j] + [name] + bases[j + 1:]
            if _start(words, bases, j, ctx, command, runs_input):
                return
            continue
        if w.computed:
            # A quoted command line with an expansion, given to another command (`tmux new -d "claude $F"`):
            # read as written inside its quotes, where the expansion is what it is.
            if w.shown[:1] in "\"'" and w.shown[-1:] == w.shown[:1] and len(w.shown) > 1 and (
                    " " in w.shown) and mentions(w.shown, ctx.programs, ctx.packages):
                inner = w.shown[1:-1]
                if w.shown[0] == "'":
                    _read_nested(inner, ctx)
                else:
                    _read_nested(inner.replace('\\"', '"'), ctx)
            continue
        name = bases[j]
        if runner and name not in ctx.programs:
            # `uvx openhands@latest`, `uv tool run openhands==1.2`, `pipx run aider-chat>=0.80`: the package
            # runner runs the program named before its version (found by 2d.5c2b's review).
            bare = _VERSION_SUFFIX_RE.sub("", name)
            if bare != name and bare in ctx.programs:
                name = bare
                bases = bases[:j] + [bare] + bases[j + 1:]      # rare: only for a runner's versioned program
        if (name in ctx.programs or _is_package(w.text, ctx.packages) or name in _SHELLS or name in (
                "npx", "bunx", "pnpx", "env") or _INTERPRETER_RE.fullmatch(name) or _names_package_path(
                w.text, ctx.packages)) and _start(words, bases, j, ctx, command, runs_input):
            return
        if (" " in w.text or "\n" in w.text) and mentions(w.text, ctx.programs, ctx.packages):
            _read_nested(w.text, ctx, prose=True)


def _written(name: str, ctx: _Context) -> bool:
    base = name.rsplit("/", 1)[-1]
    return bool(base) and any(f.rsplit("/", 1)[-1] == base for f in ctx.written)


def _mentions(text: str, ctx: _Context) -> bool:
    return mentions(text, ctx.programs, ctx.packages)


def _start(words: list, bases: list, i: int, ctx: _Context, command: Command, runs_input: int | None = None) -> bool:
    """Read the command started at word `i`. True when it is the program (or a runner of a script) and the
    rest of the command has been read. Cheap for a word that names none of these."""
    w = words[i]
    name = bases[i]
    interpreter = _INTERPRETER_RE.fullmatch(name)
    family = interpreter.group(1) if interpreter else ""
    if not (name in ctx.programs or _is_package(w.text, ctx.packages) or family or name in _SHELLS or name in (
            "npx", "bunx", "pnpx", "pnpm", "yarn", "npm", "eval", "source", ".", "env", "watch", "alias", "trap")
            or name in _RUNNER_STRING_OPTIONS):
        return False
    if name == "env":
        # Only env's own options are read here, word by word (a chain `env env ...` stays linear).
        j = i + 1
        while j < len(words) and words[j].text.startswith("-"):
            x = words[j]
            if x.text in ("-S", "--split-string") and j + 1 < len(words):
                _string_script(words[j + 1], ctx)
                return True
            for prefix in ("--split-string=", "-S"):
                if x.text.startswith(prefix) and len(x.text) > len(prefix):
                    _read_nested(x.text[len(prefix):], ctx)
                    return True
            j += 1
        return False
    if name in _RUNNER_STRING_OPTIONS and not (name in ("npx", "npm")):
        short, long_ = _RUNNER_STRING_OPTIONS[name]
        j = i + 1
        while j < len(words) and j < i + 12:
            t = words[j].text
            if t in (short, long_) or re.fullmatch(r"-[A-Za-z]*" + re.escape(short[1:]), t):
                if j + 1 < len(words):
                    _string_script(words[j + 1], ctx)
                return True
            if t.startswith(long_ + "="):
                _read_nested(t[len(long_) + 1:], ctx)
                return True
            j += 1
        return False
    if name in ("npx", "bunx", "pnpx", "pnpm", "yarn", "npm", "bun", "node", "nodejs", "deno") or family:
        # A runner's own options and target are near it: read the next words only, so that a chain of them
        # stays linear; the program's words are taken in full once it is found.
        rest = _arguments(words[i + 1:i + 40])
        if len(words) > i + 40:
            rest = _LazyRest(words, i, rest)
    else:
        rest = _arguments(words[i + 1:])
    if name in ctx.programs or _is_package(w.text, ctx.packages):
        if runs_input is not None and runs_input < i:
            ctx.cannot_tell(f"{bases[runs_input]}: " + _pipeline(command))
        _read_program_args(rest, ctx)
        return True
    if family in ("node", "nodejs", "bun", "deno"):
        for n, x in enumerate(rest):
            if x.text.startswith("-"):
                continue
            if _names_package_path(x.text, ctx.packages) or (family == "deno" and x.text == "run" and n + 1 < len(
                    rest) and False):
                _read_program_args(rest[n + 1:], ctx)
                return True
            if family == "deno" and x.text in ("run", "x") :
                continue
            if family == "deno" and x.text.casefold().startswith("npm:") and _is_package(x.text[4:], ctx.packages):
                _read_program_args(rest[n + 1:], ctx)
                return True
            break
    if name in ("npx", "bunx", "pnpx") or (name in ("pnpm", "yarn", "npm", "bun") and rest and rest[0].text in (
            "dlx", "exec", "x")):
        args = rest if name in ("npx", "bunx", "pnpx") else rest[1:]
        n = 0
        while n < len(args):
            t = args[n].text
            if t in ("-c", "--call") and n + 1 < len(args):
                _string_script(args[n + 1], ctx)
                return True
            if t.startswith("--call="):
                _read_nested(t[len("--call="):], ctx)
                return True
            if t in ("-p", "--package") and n + 1 < len(args):
                n += 2
                continue
            if t == "--" or (t.startswith("-") and not args[n].computed):
                n += 1
                continue
            break
        if n < len(args):
            target = args[n]
            if target.computed:
                ctx.cannot_tell(target.shown)
                return True
            if _base(target.text) in ctx.programs or _is_package(target.text, ctx.packages):
                after = args[n + 1:]
                if after and after[0].text == "--" and not after[0].computed:
                    after = after[1:]           # passed on to the package (the wider reading)
                _read_program_args(after, ctx)
                return True
            if _base(target.text) not in _DATA_COMMANDS:
                # `npx cross-env ... claude`, `npx concurrently "claude ..."`: read on as any other command.
                return False
        return False
    if name in ("yarn", "pnpm") and rest:
        # `yarn claude ...`, `pnpm claude ...`, `yarn run claude ...`: a package's program.
        args = rest[1:] if rest[0].text == "run" and len(rest) > 1 else rest
        if not args[0].computed and _base(args[0].text) in ctx.programs:
            _read_program_args(args[1:], ctx)
            return True
        return False
    if family:
        return _interpreter(family, rest, ctx, command)
    if name in _SHELLS:
        if runs_input is not None and runs_input < i:
            ctx.cannot_tell(f"{bases[runs_input]}: " + _pipeline(command))
        _shell(rest, ctx, command)
        return True
    if name == "eval":
        if any(x.computed for x in rest):
            ctx.cannot_tell("eval " + " ".join(x.shown for x in rest)[:120])
        else:
            _read_nested(" ".join(x.text for x in rest), ctx)
        return True
    if name == "trap":
        if rest and rest[0].text != "--" and not rest[0].text.startswith("-"):
            _string_script(rest[0], ctx)
        return True
    if name in ("source", "."):
        if rest:
            target = rest[0]
            if target.inner and target.text.startswith("<("):
                inner_commands, _p = _lex(target.inner[0], ctx.variables)
                literal = _literal_output(inner_commands[-1]) if len(inner_commands) == 1 else None
                if literal is None:
                    ctx.cannot_tell(target.shown)
                else:
                    _read_nested(literal, ctx)
            elif target.text in ("/dev/stdin", "-"):
                _stdin(command, ctx)
            elif target.computed or _written(target.text, ctx):
                ctx.cannot_tell(target.shown)
        return True
    if name == "watch":
        args = [x for x in rest]
        n = 0
        while n < len(args) and args[n].text.startswith("-"):
            n += 2 if args[n].text in ("-n", "--interval", "-d") and n + 1 < len(args) else 1
        if any(x.computed for x in args[n:]):
            ctx.cannot_tell("watch " + " ".join(x.shown for x in args[n:])[:120])
        elif args[n:]:
            _read_nested(" ".join(x.text for x in args[n:]), ctx)
        return True
    if name == "alias":
        for x in rest:
            head, eq, value = x.text.partition("=")
            if not eq:
                continue
            if x.computed:
                ctx.cannot_tell(x.shown)
                continue
            _read_nested(value, ctx)
            if appears(value, ctx.programs, ctx.packages):
                ctx.programs.append(head.casefold())
        return True
    return False


class _LazyRest(list):
    """The first words after a runner, which gives every word after it when sliced from a point on."""

    def __init__(self, words: list, at: int, head: list) -> None:
        super().__init__(head)
        self._words, self._at = words, at

    def __getitem__(self, key):
        if isinstance(key, slice) and key.stop is None and (key.step in (None, 1)):
            start = key.start or 0
            if start < 0:
                start += len(self)
            # The words from that point to the end of the command, redirections left out.
            head = list.__getitem__(self, slice(0, start))
            if not head:
                return _arguments(self._words[self._at + 1:])
            last = head[-1]
            index = next(n for n in range(self._at + 1, len(self._words)) if self._words[n] is last)
            return _arguments(self._words[index + 1:])
        return list.__getitem__(self, key)


def _interpreter(family: str, rest: list, ctx: _Context, command: Command) -> bool:
    """An interpreter given code (`perl -e`, `python3 -Ic`, `node -pe`, `pwsh -Command`, `awk '...'`) or a
    heredoc: the code is read the widest way, and "cannot tell" where it names the tool and nothing is
    found there. A file written in the step and run by it is "cannot tell"."""
    options = _CODE_OPTIONS.get(family, ())
    code = None
    skip = False
    group = family[:-1] if family in ("gawk", "mawk") else family
    takes_value = _VALUE_OPTIONS.get(group, frozenset())
    switches = _SWITCHES.get(group, "")
    for n, x in enumerate(rest):
        t = x.text
        if skip:
            skip = False
            continue
        if t == "-m" and group in ("python", "python2", "python3", "pypy"):
            return False                # a module is run (`python -m pkg`): not read, as a repository script is not
        if t == "-f" and group in ("awk", "gaw", "maw"):
            if n + 1 < len(rest) and rest[n + 1].text in ("/dev/stdin", "-"):
                break                   # the program from the heredoc (`awk -f /dev/stdin <<'EOF'`)
            return False                # an awk program from a file: not read, as a repository script is not
        if t in options:
            code = rest[n + 1] if n + 1 < len(rest) else None
            break
        if t.startswith("-") and not t.startswith("--") and len(t) > 2 and any(
                len(o) == 2 and o[0] == "-" and t.endswith(o[1]) for o in options) and all(
                ch in switches for ch in t[1:-1]):
            code = rest[n + 1] if n + 1 < len(rest) else None     # `perl -le`, `python3 -Ic`, `node -pe`
            break
        if t in takes_value:
            skip = True                 # an option with its value in the next word (`-W error`, `awk -v x=1`)
            continue
        if t.startswith("-"):
            continue                    # a switch, or an option with its value attached (`-Mautodie`, `-F,`)
        if family in ("awk", "gawk", "mawk"):
            code = x
            break
        if _written(t, ctx):
            ctx.cannot_tell(f"{x.shown}, a file written in the step")
            return True
        if x.computed and mentions(x.shown, ctx.programs, ctx.packages):
            ctx.cannot_tell(x.shown)
            return True
        break
    # An unquoted heredoc's body is expanded by bash before the interpreter reads it: each expansion is a
    # value pasted into the code (flagship slice 2d.5c2c, found by its review).
    texts = [code.text] if code is not None else [body if literal else _paste_expansions(body)
                                                  for _k, body, literal in command.stdin]
    if code is None and not texts and command.piped:
        # Code read from a pipe (`echo '...' | python3`, `cat <<'EOF' | python3`): what `echo`, `printf` or
        # `cat` of a heredoc writes, else "cannot tell" where the pipeline names the tool.
        literal = _literal_output(command.before)
        before = command.before
        if literal is None and before is not None and before.words and _base(before.words[0].text) == "cat" and (
                len(_arguments(before.words)) == 1) and before.stdin:
            texts = [body if lit else _paste_expansions(body) for _k, body, lit in before.stdin]
        elif literal is not None:
            texts = [literal]
        elif mentions(_pipeline(command), ctx.programs, ctx.packages):
            ctx.cannot_tell(f"{family} reading its code from a pipe: " + _pipeline(command))
            return True
    if not texts:
        return False
    if code is not None:
        # The program named among the code's own arguments (`node -e '...spawnSync(argv[1], ...)' claude "$@"`):
        # the code may run it with the words after it (found by slice 2d.5c2c's second review).
        after = rest[rest.index(code) + 1:] if code in rest else []
        at = next((n for n, w in enumerate(after) if not w.computed and (
            _base(w.text) in ctx.programs or _is_package(w.text, ctx.packages))), None)
        if at is not None:
            _read_program_args(_arguments(after[at + 1:]), ctx)
    for text in texts:
        probe = Reading()
        _read_widest(text, ctx.programs, ctx.packages, ctx.flags, probe, anywhere=True)
        ctx.reading.merge(probe)
        # "Cannot tell" where the code names the tool and holds the start of a warned option it does not
        # complete; code given as a variable is not read at all.
        if code is not None and code.computed and mentions(code.shown, ctx.programs, ctx.packages):
            for flag in ctx.flags:
                ctx.reading.cannot_tell(flag, f"{family}: {code.shown}")
        else:
            if mentions(text, ctx.programs, ctx.packages):
                _fragments(text, ctx.flags, ctx.reading, family)
            if appears(text, ctx.programs, ctx.packages):
                # The code read by its tokens: argument lists, command lines in strings, options in pieces
                # (flagship slice 2d.5c2c); `appears`, because a string's prefix (`f"claude ..."`) is
                # glued to the name once quotes are taken out.
                from obaaf.checker import agent_code
                agent_code.read_code(text, family, ctx)
    return True


# Options of an interpreter that take the next word as their value, and the one-letter switches that may
# come before a code option in one group (`perl -lne`, `python3 -Ic`).
_VALUE_OPTIONS = {
    "python": frozenset({"-W", "-X", "--check-hash-based-pycs"}),
    "pypy": frozenset({"-W", "-X"}),
    "node": frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader", "--env-file", "-C",
                       "--conditions", "--input-type", "--title"}),
    "nodejs": frozenset({"-r", "--require", "--import", "--loader", "--env-file", "-C", "--input-type"}),
    "perl": frozenset({"-I", "-M", "-m", "-x"}),
    "ruby": frozenset({"-r", "-I", "-C", "-E", "-F", "-K", "--encoding"}),
    "php": frozenset({"-d", "-c", "-z"}),
    "awk": frozenset({"-v", "-F", "--assign", "--field-separator"}),
    "gaw": frozenset({"-v", "-F", "--assign", "--field-separator"}),
    "maw": frozenset({"-v", "-F"}),
    "bun": frozenset({"-r", "--preload", "--env-file", "--cwd"}),
    "deno": frozenset({"--config", "--import-map"}),
}
_SWITCHES = {"python": "bBdEhiIOPqsSuvVxR", "python2": "bBdEhiIOPqsSuvVxR", "python3": "bBdEhiIOPqsSuvVxR",
             "pypy": "bBdEhiIOPqsSuvVxR",
             "perl": "lnpawsTtWXUcC0123456789", "ruby": "nplawsdvUcy", "node": "p", "nodejs": "p", "bun": "p"}
_BASH_EXPANSION_RE = re.compile(r"\\[\\$`]|\$\{[^}]*\}|\$\([^)]*\)|`[^`]*`|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]")


def _paste_expansions(body: str) -> str:
    """An unquoted heredoc's body with each expansion bash makes in it written as a pasted value
    (`${{ ... }}`), and its backslash escapes undone."""
    def one(m):
        text = m.group(0)
        if text.startswith("\\"):
            return text[1]
        return "${{ " + text.replace("}}", "} }") + " }}"
    return _BASH_EXPANSION_RE.sub(one, body)


def _string_script(word: Word, ctx: _Context) -> None:
    if word.computed:
        ctx.cannot_tell(word.shown)
    else:
        _read_nested(word.text, ctx)


def _stdin(command: Command, ctx: _Context) -> None:
    """A shell (or `source /dev/stdin`) reading its script from its input: a heredoc, a here-string, or
    the output of the command before it in a pipeline."""
    if command.stdin:
        for _kind, body, _literal in command.stdin:
            _read_nested(body, ctx)
        return
    if command.piped:
        literal = _literal_output(command.before)
        if literal is None:
            ctx.cannot_tell("a shell reading its script from a pipe: " + _pipeline(command))
        else:
            _read_nested(literal, ctx)


def _shell(rest: list, ctx: _Context, command: Command) -> None:
    n = 0
    while n < len(rest):
        x = rest[n]
        t = x.text
        if x.computed:
            ctx.cannot_tell(x.shown)
            return
        if t == "--":
            n += 1
            break
        if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", t):
            m = n + 1
            while m < len(rest) and rest[m].text == "--" and not rest[m].computed:
                m += 1
            if m < len(rest):
                _string_script(rest[m], ctx)
            return
        if t in _SHELL_VALUE_OPTIONS or re.fullmatch(r"[-+][A-Za-z]*[oO]", t):
            n += 2
            continue
        if t.startswith(("-", "+")):
            if "s" in t[1:] and not t.startswith("--"):
                _stdin(command, ctx)
                return
            n += 1
            continue
        break
    if n < len(rest):
        target = rest[n]
        if target.computed or _written(target.text, ctx):
            ctx.cannot_tell(target.shown)
        return
    _stdin(command, ctx)


# ---------------------------------------------------------------------------------------- variables
_ASSIGNED_RE = re.compile(
    r"(?:^|[\s;&|({`])(?:(?:export|local|readonly|typeset|declare|let)\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\[[^\]]*\])?\+?=|\b(?:read|mapfile|readarray)\s+(?:-\w+\s+(?:[^\s-]\S*\s+)?)*([A-Za-z_][A-Za-z0-9_]*)"
    r"|\bfor\s+([A-Za-z_][A-Za-z0-9_]*)\s+in\b|\bgetopts\s+\S+\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"|\bprintf\s+-v\s*([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*):?=")
# Commands that can set a variable whose name the checker cannot read: `eval` and `source` (or `.`) of any
# text, a nameref, and `declare`, `export`, `printf -v`, `read` and the like given a quoted or computed name.
# Matched where a command starts, so a prompt's "read the diff" is not one (found by 2d.5c2a's review).
_START = r"(?:^|[;&|({`]|\b(?:then|do|else|elif|if|while|until)\b|\$\()\s*"
_DYNAMIC_ASSIGN_RE = re.compile(
    _START + r"(?:(?:eval|source|let|unset|compgen)(?![\w-])|\.\s+\S"
    r"|(?:declare|typeset|local|readonly|export)\s+(?:-\w+\s+)*(?:-\w*n\w*\s|[\"'$`])"
    r"|printf\s+-v\s*[\"'$`]|(?:read|mapfile|readarray)(?:\s+-[a-zA-Z]+(?:\s+[^\s-]\S*)?)*\s+[\"'$`])", re.M)
_NAME_EQUALS_RE = re.compile(r"(?<![A-Za-z0-9_])([A-Za-z_][A-Za-z0-9_]*)\+?=")
_LITERAL_ASSIGN_RE = re.compile(
    r"(?:^|[\s;&|(])(?:(?:export|local|readonly|typeset|declare)\s+(?:-\w+\s+)*)?([A-Za-z_][A-Za-z0-9_]*)="
    r"(\"[^\"$`\\]*\"|'[^']*'|[A-Za-z0-9_.,:/@%+=-]*)(?=$|[\s;&|)])")


def known_variables(scopes: list, script: str, trust_env: bool = True) -> tuple[dict, dict]:
    """(known, unread): the variables whose value the checker can put into a script, and the `env` values
    it cannot read (name -> value as written), for the facts. An `env` name takes its value from the first
    scope that sets it (the step's, then the job's, then the workflow's), and is known only when that value
    is plain and the script does not set the name. A name the script sets is known only when it is set
    once, to a plain value (`FLAGS="--model x"`). `trust_env` False (an earlier step may write `GITHUB_ENV`)
    leaves every `env` name unknown."""
    if _DYNAMIC_ASSIGN_RE.search(script):
        # `eval`, `source`, `declare -n`, `printf -v`, `read`, a quoted `export NAME=...` and the like can set
        # any variable: none is known, from the script or from `env`.
        trust_env, dynamic = [False] * len(scopes), True
    else:
        dynamic = False
    counts: dict = {}
    for m in _ASSIGNED_RE.finditer(script):
        name = next(g for g in m.groups() if g)
        counts[name] = counts.get(name, 0) + 1
    known: dict = {}
    unread: dict = {}
    seen: set = set()
    trusted = list(trust_env) if isinstance(trust_env, (list, tuple)) else [trust_env] * len(scopes)
    for number, scope in enumerate(scopes):
        if not isinstance(scope, dict):
            continue
        trust_env = trusted[number] if number < len(trusted) else False
        for name, value in scope.items():
            if not isinstance(name, str) or name in seen:
                continue
            seen.add(name)
            if isinstance(value, bool):
                value = "true" if value else "false"
            elif isinstance(value, (int, float)):
                try:
                    value = str(value)
                except ValueError:          # a number too long for Python to print: not known
                    value = None
            if name in counts:
                continue
            if trust_env and isinstance(value, str) and _PLAIN_VALUE_RE.fullmatch(value):
                known[name] = value
            else:
                unread[name] = value if isinstance(value, str) else type(value).__name__
    literal: dict = {}
    for m in _LITERAL_ASSIGN_RE.finditer(script):
        literal.setdefault(m.group(1), []).append(m.group(2).strip("\"'") if m.group(2)[:1] in "\"'" else m.group(2))
    anywhere: dict = {}
    for m in _NAME_EQUALS_RE.finditer(script):
        anywhere[m.group(1)] = anywhere.get(m.group(1), 0) + 1
    for name, values in literal.items():
        if dynamic:
            break
        if counts.get(name) == 1 and len(values) == 1 and _PLAIN_VALUE_RE.fullmatch(values[0]) and anywhere.get(
                name) == 1:
            known[name] = values[0]
    return known, unread


# ------------------------------------------------------------------------------------------ the readings
def _hold_expressions(text: str) -> tuple[str, list]:
    held: list = []

    def hold(expression: str) -> str:
        held.append(expression)
        return f"{_EXPR}{len(held) - 1}{_EXPR}"
    return _sub_expressions(text, hold), held


def _show(word: str, held: list) -> str:
    return re.sub(re.escape(_EXPR) + r"(\d+)" + re.escape(_EXPR), lambda m: held[int(m.group(1))], word)


def _strip_data(text: str) -> str:
    """The text with comments and the bodies of heredocs no shell reads taken out, for the widest reading."""
    out_lines: list = []
    lines = text.split("\n")
    i = 0
    looking = True
    while i < len(lines):
        line = lines[i]
        out_lines.append(line)
        m = re.search(r"<<-?(?!<)", line) if looking else None
        d = _DELIMITER_RE.match(line, m.end()) if m else None
        if d and not re.search(r"(^|[\s;&|(])(ba|z|da|k|a)?sh\b[^|;&]*<<", line):
            delim = re.sub(r"\\(.)", r"\1", re.sub(r"'([^']*)'|\"([^\"]*)\"",
                                                    lambda q: q.group(1) or q.group(2) or "", d.group(1)))
            j = i + 1
            while j < len(lines) and lines[j].strip("\t") != delim:
                j += 1
            if j < len(lines):
                i = j
            else:
                looking = False     # no end: the rest is read as text, and no later line is searched again
        i += 1
    joined = "\n".join(out_lines)
    return "\n".join(_strip_comment_line(line) for line in re.sub(r"\\\r?\n", " ", joined).split("\n"))


def _strip_comment_line(line: str) -> str:
    quote, previous = "", " "
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (previous in " \t" or previous in ";&|("):
            return line[:i]
        previous = ch
    return line


def _read_widest(text: str, programs: list, packages: list, flags: list, reading: Reading,
                  anywhere: bool = False) -> None:
    """The second reading: quotes, backslashes, brackets and commas taken out, cut where a shell starts a
    command; a command that starts with the program has its words matched as known text."""
    plain = re.sub(r"[\[\],]", " ", re.sub(r"[\"'\\]", "", _strip_data(text).replace("$'", "'")))
    for segment in command_segments(plain):
        words = segment.split()
        if not words:
            continue
        first = words[0]
        if anywhere:
            # Code in another language: the program anywhere in it (`system "claude ..."`, `%x(claude ...)`).
            at = next((n for n, w in enumerate(words) if _base(w) in programs or _is_package(w, packages)), None)
            if at is not None:
                _match_known(words[at + 1:], flags, reading)
                continue
        if _base(first) in programs or _is_package(first, packages):
            _match_known(words[1:], flags, reading)
        elif _base(first) in ("node", "nodejs", "bun", "deno") and len(words) > 1 and _names_package_path(
                words[1], packages):
            _match_known(words[2:], flags, reading)


def read_script(text: str, programs: list, packages: list, flags: list, variables: dict | None = None,
                mentioned: bool | None = None, bash: bool = True, unread: dict | None = None,
                written_files: set | None = None, loose: bool | None = None, prose: bool = False,
                language: str = "") -> Reading:
    """Each warned flag a script gives the tool's program, and what the checker cannot read there.
    `mentioned`: whether the step names the tool anywhere (its script, its `env` values or the job's and
    workflow's); "cannot tell" about a command the checker cannot name is given only then. `bash` False:
    the script is in another shell or language, which is read only the widest way, and "cannot tell" where
    it names the tool and nothing is found; `language` (a shell's or an interpreter's name, or
    `github-script`) says how `agent_code` reads it by its tokens as well. `unread`: `env` values the checker
    cannot read, shown with a word that uses them."""
    reading = Reading()
    if not text or not flags:
        return reading
    programs = [p.casefold() for p in programs]
    packages = [p.casefold() for p in packages]
    if mentioned is None:
        mentioned = mentions(text, programs, packages)
    if loose is None:
        loose = mentioned or appears(text, programs, packages)
    if not mentioned and not loose:
        return reading          # the tool is not named at all (the common case, kept cheap)
    held_text, held = _hold_expressions(text)
    if bash:
        written = set(written_files or ()) | {m.group(1) for m in re.finditer(
            r"(?:>>?|\btee(?:\s+-a)?)\s*['\"]?([^\s'\";&|<>]+)", held_text)}
        ctx = _Context(list(programs), packages, flags, dict(variables or {}), mentioned, written, reading,
                       loose=loose, prose=prose)
        _read_text(held_text, ctx)
        if held or unread:
            shown: dict = {}
            for fid, words in reading.unknown.items():
                out: dict = {}
                for word in words:
                    word = _show(word, held)
                    for name, value in (unread or {}).items():
                        if re.search(r"\$\{?" + re.escape(name) + r"(?![A-Za-z0-9_])", word):
                            word = f"{word} ({name}: {value})"
                    out[word] = None
                shown[fid] = out
            reading.unknown = shown
    _read_widest(text, programs, packages, flags, reading, anywhere=not bash)
    if not bash and mentioned:
        _fragments(text, flags, reading, "a script the checker does not read as bash")
    if not bash and loose:
        if language:
            from obaaf.checker import agent_code
            ctx = _Context(list(programs), packages, flags, {}, True, set(), reading, loose=True)
            agent_code.read_language(text, language, ctx)
    return reading


_FRAGMENT_RE = re.compile(r"(?<![\w-])(--?[A-Za-z][A-Za-z0-9-]*)")


def _fragments(text: str, flags: list, reading: Reading, where: str) -> None:
    """In code the checker reads only the widest way: each warned option of which the code holds a start
    it does not complete (`"--dangerously-" . "skip-permissions"`, `--dangerously-#{x}-permissions`) is
    "cannot tell". An option held whole in a variable is not read, as in bash (#254)."""
    plain = re.sub(r"[\"'\\]", "", text)
    for m in _FRAGMENT_RE.finditer(plain):
        word = m.group(1)
        end = plain[m.end():m.end() + 1]
        low = word.casefold()
        for flag in flags:
            if flag["id"] in reading.hits:
                continue
            for option in flag["options"]:
                o = option.casefold()
                if len(low) >= 4 and o.startswith(low) and o != low and (end == "" or not end.isalnum()):
                    reading.cannot_tell(flag, f"{where}: {_fact_text(word + plain[m.end():m.end() + 40])}")
                    break


def put_in_cheaply(text: str, scopes: list) -> str:
    """A script with each plain assignment it makes and each plain `env` value put in for `$NAME` and
    `${NAME}`, by a regular expression: only to decide whether the step names the tool."""
    values: dict = {}
    for scope in reversed(scopes):
        if isinstance(scope, dict):
            values.update({k: v for k, v in scope.items() if isinstance(k, str) and isinstance(v, str)
                           and _PLAIN_VALUE_RE.fullmatch(v)})
    for m in _LITERAL_ASSIGN_RE.finditer(text):
        value = m.group(2)
        values[m.group(1)] = value[1:-1] if value[:1] in "\"'" else value
    if not values:
        return text
    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: values.get(m.group(1), m.group(0)), text)


def appears(text: str, programs: list, packages: list) -> bool:
    """Whether the tool's name is anywhere in a text, even inside a word, once quotes, backslashes and
    `$'...'` are read: the check that decides whether a step is read at all."""
    names = [n.casefold() for n in programs + packages]
    low = re.sub(r"[\"'\\]", "", text).casefold()
    if any(n in low for n in names):
        return True
    if "$'" in text:
        decoded = re.sub(r"[\"'\\]", "", re.sub(r"\$'((?:[^'\\]|\\.)*)'", lambda m: _ansi_c(m.group(1)),
                                                  text)).casefold()
        return any(n in decoded for n in names)
    return False


def mentions(text: str, programs: list, packages: list) -> bool:
    """Whether a text names the tool: its program as a word (not after `@` or a letter), or its package,
    once quotes, backslashes and `$'...'` are read."""
    low = re.sub(r"[\"'\\]", "", text).casefold()
    if any(p in low for p in packages):
        return True
    for program in programs:
        if re.search(r"(?<![\w@-])" + re.escape(program) + r"(?![\w-])", low):
            return True
    if "$'" in text:
        decoded = re.sub(r"\$'((?:[^'\\]|\\.)*)'", lambda m: _ansi_c(m.group(1)), text).casefold()
        decoded = re.sub(r"[\"'\\]", "", decoded)
        return any(p in decoded for p in packages) or any(
            re.search(r"(?<![\w@-])" + re.escape(p) + r"(?![\w-])", decoded) for p in programs)
    return False


def starts_program(text: str, programs: list, packages: list) -> bool:
    """Whether a text, read the widest way, holds a command that starts with the program."""
    programs = [p.casefold() for p in programs]
    packages = [p.casefold() for p in packages]
    if not mentions(text, programs, packages):
        return False
    plain = re.sub(r"[\"'\\]", "", _strip_data(text))
    for segment in command_segments(plain):
        words = segment.split()
        if words and (_base(words[0]) in programs or _is_package(words[0], packages)):
            return True
    return False


_EXPANSION_RE = re.compile(r"\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\$\([^)]*\)|`[^`]*`|\$[0-9@*#?$!-]")


def read_args(value: str, flags: list, json_array: bool = False, comments: bool = False,
              expands: bool = False) -> tuple[Reading, list]:
    """Each warned flag in an input an action hands to the program as options, and the words that make the
    rest "cannot tell". `json_array`: the action reads a value that starts with `[` as a JSON array of words
    (codex-action's `codex-args`, after trimming as `core.getInput` trims). `comments`: lines that start
    with `#` are left out, as claude-code-action leaves them out. `expands`: the action's tokenizer puts in a
    `$NAME` it has no value for as nothing (shell-quote, claude-code-action), so a word that would be a
    warned option without its expansions is "cannot tell". White space is what JavaScript takes for it,
    U+FEFF included."""
    reading = Reading()
    unknown: list = []
    text = value
    if comments:
        text = "\n".join(line for line in text.split("\n") if not line.strip(_JS_SPACE).startswith("#"))
    words: list = []
    trimmed = text.strip(_JS_SPACE)
    parsed = None
    if json_array and trimmed.startswith("["):
        try:
            parsed = json.loads(trimmed)
        except ValueError:
            parsed = None
        if isinstance(parsed, list):
            words = [str(w) for w in parsed]
    spaced = _JS_SPACE_RE.sub(" ", text)
    if not isinstance(parsed, list):
        commands, _problem = _lex(spaced, {})
        for command in commands:
            for w in command.words:
                if expands and (w.unquoted or w.quoted or w.splits):
                    stripped = _known_part(w.text)
                    probe = Reading()
                    _match_known(([words[-1]] if words else []) + [stripped], flags, probe)
                    if probe.hits or _could_start(stripped, flags):
                        unknown.append(w.shown)
                words.append(_HOLE_RE.sub(lambda m: m.group(0)[1:-1], w.text))
            words.extend(body for _kind, body, _literal in command.stdin)
    _match_known(words, flags, reading)
    if not isinstance(parsed, list):
        _match_known(re.sub(r"[\[\],]", " ", re.sub(r"[\\\"']", "", spaced)).split(), flags, reading)
    return reading, unknown
