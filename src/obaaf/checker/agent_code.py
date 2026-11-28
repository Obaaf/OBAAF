"""Code in another language that runs an agent tool's program (flagship slice 2d.5c2c, OBAAF-GHA-026).

`agent_flags` reads a bash or sh script as bash reads it. Code given to another interpreter (`python3 -c`,
`node -e`, a heredoc fed to `ruby`, `perl -e`, `php -r`, an awk program), a github-script script and a
step whose shell is pwsh, cmd, python or another language are read there the widest way. This module
reads such code a second time, by its tokens (PowerShell and cmd by their words), for what the widest
reading cannot see:

- **An argument list that holds what the checker cannot read.** A splat or spread (`*flags`, `...flags`,
  Perl's `@flags`, PHP's `...$flags`), a list joined with another (`["claude"] + flags`), a list held in a
  variable that the code changes or spreads (`cmd.append(f)`, `cmd += f`, `push @cmd, $f`), or the argument
  list given whole as a value to a call (`exec.exec('claude', flags)`, `spawn('claude', args)`,
  `os.execvp('claude', args)`): "cannot tell".
- **A command line held in a string that is joined with, or puts in, a value the checker cannot read**
  (`os.system("claude " + os.environ["F"])`, `f"claude {flags}"`, `` `claude ${flags}` ``, `"claude #{f}"`,
  `"claude $f"`, `"claude %s" % f`, `"claude {}".format(f)`). The string is read as bash with each such
  value as an expansion whose value is not known, so a value outside the command line's own quotes is
  "cannot tell" and one inside them is one word, as in bash.
- **An option written in pieces.** Literal pieces are joined (`"--" + "yolo"` is `--yolo`, then matched),
  and a joined value with a piece the checker cannot read that is, or could start, a warned option
  (`"--" + x`, `"-" + "y"` held in a variable) is "cannot tell".

A literal argument list (`subprocess.run(["claude", "--version"])`) is matched word by word. One value in
one place of a list (`["claude", "-p", prompt]`), or a value given as one argument where the language gives
it as one (Python and Ruby call arguments, a Perl scalar), is one word whose text is not known, as a quoted
variable is in bash (#254): it is "cannot tell" only as the value of a warned option that takes one, or
where its known start could begin a warned option.

A name given a literal program (`p = "claude"`) is followed: where it is used, it is the program. A program
name built at run time otherwise is not read, as the agent lane does not see it. Neither is code run from
a file, a module (`python -m`), or code a program builds and evaluates (`eval`, Python's `exec`) beyond
what the widest reading finds in its text.

Every string the tokenizer cannot close, in code that names the tool, is "cannot tell", as text bash
cannot split is.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from dataclasses import dataclass, field

from obaaf.checker import agent_flags as af

# The language each interpreter or shell is read as.
_FAMILIES = {
    "python": "python", "python2": "python", "python3": "python", "py": "python", "pypy": "python",
    "pypy3": "python",
    "node": "js", "nodejs": "js", "bun": "js", "deno": "js", "js": "js", "github-script": "js",
    "ruby": "ruby", "perl": "perl", "php": "php", "lua": "lua",
    "pwsh": "pwsh", "powershell": "pwsh", "cmd": "cmd", "cmd.exe": "cmd",
    "awk": "awk", "gawk": "awk", "mawk": "awk", "nawk": "awk",
}

# Calls whose arguments are output, never run (`print("claude", v)`, `console.log('claude', v)`).
_OUTPUT_CALLS = frozenset({
    "print", "println", "puts", "pp", "log", "info", "debug", "notice", "warn", "warning", "error", "trace",
    "setfailed", "startgroup", "say", "die", "echo", "write", "writeln", "write-host", "write-verbose",
    "write-debug", "write-information", "write-warning", "write-error", "includes", "startswith", "endswith",
    "indexof", "index", "find", "match", "test", "search", "replace", "contains", "count", "which",
    "exists", "isfile", "assert", "assertequal", "addheading", "addraw", "addcodeblock", "setoutput"})
# Calls that run a command line given as one string (beyond a string that starts with the program).
_RUNNER_CALLS = frozenset({
    "system", "exec", "spawn", "execsync", "spawnsync", "popen", "popen2", "popen3", "popen4", "run", "call",
    "check_call", "check_output", "getoutput", "getstatusoutput", "shell_exec", "passthru", "proc_open",
    "capture2", "capture2e", "capture3", "pipeline", "invoke-expression", "iex", "start-process", "execa",
    "execasync", "execcommand", "getexecoutput", "create_subprocess_shell", "readpipe", "qx", "execute",
    "spawnasync", "execfile", "execfilesync", "fork", "create_subprocess_exec", "subprocess", "posix_spawn",
    "posix_spawnp", "pcntl_exec", "open2", "open3", "capture", "capturex", "systemx", "run3", "command",
    "execasync", "execanode", "execasync", "spawnp", "execv", "execvp", "execvpe", "execl", "execlp", "spawnv",
    "spawnvp", "spawnl", "spawnlp"})
_SHELL_NAMES = frozenset({"bash", "sh", "zsh", "dash", "ksh", "ash", "fish", "cmd", "cmd.exe", "pwsh", "powershell",
                          "pwsh.exe", "powershell.exe", "ssh"})
# Calls whose argument after the program is the argument list itself (Python's `os.execv*`, `os.spawnv*`,
# `os.posix_spawn*`): a value there is a list.
_PY_LIST_CALL_RE = re.compile(r"(exec|spawn)v|posix_spawn")
# Ops that join two strings, per language.
_CONCAT = {"python": {"+"}, "js": {"+"}, "ruby": {"+", "<<"}, "perl": {"."}, "php": {"."}, "pwsh": {"+"},
           "lua": {".."}, "awk": set(), "other": {"+", ".", ".."}}
# Ops after a list, or after a name that holds one, that change or extend it.
_EXTENDS_AFTER = frozenset({"+", "+=", ".", "<<", "<<=", "*", "|", "|=", "[", "->", ".=", "..."})
_EXTENDS_BEFORE = frozenset({"*", "**", "...", "+", "push", "unshift", "splice", "extend", "concat",
                             "array_push", "array_unshift", "array_merge", "array_splice"})
_MULTI_OPS = ("...", "**=", "<<=", ">>=", "===", "!==", "**", "<<", ">>", "+=", "-=", ".=", "*=", "/=", "==",
              "!=", "<=", ">=", "&&", "||", "=>", "->", "::", "..", ":=", "=~", "!~", "?.", "??", "|=")
_VALUE_KEYWORDS = frozenset({"return", "typeof", "case", "do", "else", "in", "of", "and", "or", "not", "if",
                             "unless", "while", "until", "split", "grep", "when", "yield", "await", "void",
                             "delete", "throw", "new", "print", "puts", "join", "map", "sort", "x", "lt", "gt",
                             "le", "ge", "eq", "ne", "cmp"})
_SITE_LIMIT = 200           # places a program is named in one piece of code, beyond which it is "cannot tell"
_HOLE_NAME = "__OBAAF_HOLE_"
# A value pasted into the code's text before it runs: a `${{ }}` expression (GitHub puts its text in), one
# the bash reader holds as \x02<n>\x02, or a shell expansion in an unquoted heredoc. It can end the string
# it is in, so it is marked 2 (not True) among a string's parts and read as words the checker cannot read.
PASTED = 2
_PASTED_RE = re.compile(r"\$\{\{.*?\}\}|\x02\d*\x02", re.S)
_SUBSCRIPT_LIMIT = 1000     # characters a Perl or PHP subscript in a string is looked for in
_PASTE_LIMIT = 100_000      # characters of names' values put into strings in one piece of code


@dataclass
class Tok:
    kind: str                   # "str", "name", "num", "op", "nl"
    text: str                   # a name without its sigil, an op, a number; for a string, its known text
    start: int = 0
    end: int = 0
    parts: list = field(default_factory=list)   # for a string: (is a value the checker cannot read, text)
    sigil: str = ""             # `$`, `@`, `%`, `&` before a name (Perl, PHP, PowerShell, Ruby)
    command: bool = False       # a string the language runs as a command line (backticks, `%x`, `qx`)


def family_of(name: str) -> str:
    """The language an interpreter's name, or a step's shell, is read as."""
    base = re.sub(r"[0-9.]*(\.exe)?$", "", (name or "").rsplit("/", 1)[-1].rsplit("\\", 1)[-1].lower())
    return _FAMILIES.get(base, _FAMILIES.get((name or "").lower(), "other"))


# ------------------------------------------------------------------------------------------ tokenizing
_NAME_RE = re.compile(r"[^\W\d]\w*")
_PS_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUM_RE = re.compile(r"[0-9][A-Za-z0-9_.]*")
_PY_PREFIX_RE = re.compile(r"([rRbBuUfF]{1,2})(?=['\"])")
_OPEN = {"(": ")", "[": "]", "{": "}", "<": ">"}
_PS_QUOTES = {"'": "'", "\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'",
              '"': '"', "\u201c": '"', "\u201d": '"', "\u201e": '"'}


class _Tokenizer:
    def __init__(self, text: str, family: str) -> None:
        self.text = text
        self.family = family
        self.toks: list = []
        self.problem = ""
        self.pending_heredocs: list = []        # (tok, delimiter, interpolates, squiggly) waiting for a line end
        self.depth: list = []                   # the brackets open at this point; a line end inside ( or [
                                                # does not end a statement

    # -- helpers
    def _value_position(self) -> bool:
        prev = next((t for t in reversed(self.toks) if t.kind != "nl"), None) if self.toks else None
        if prev is None or (self.toks and self.toks[-1].kind == "nl"):
            return True
        if prev.kind == "op":
            return prev.text not in (")", "]", "}")
        return prev.kind == "name" and prev.text.lower() in _VALUE_KEYWORDS and (
            self.family == "perl" or prev.text.lower() not in ("x", "lt", "gt", "le", "ge", "eq", "ne", "cmp"))

    def _argument_position(self, i: int) -> bool:
        """A value may start at `i`: where `_value_position` says so, or after a name with a space before
        `i` and none after it (`system %(...)`, `system <<~CMD`, `puts ?x`), as Ruby and Perl read it."""
        text = self.text
        if text.startswith("%=", i) and self.toks and self.toks[-1].kind == "name":
            return False                # `x %= 3`
        if self._value_position():
            return True
        prev = self.toks[-1] if self.toks else None
        if text[i + 1:i + 2] == "=" or (text.startswith("<<", i) and not (
                prev is not None and prev.text.lower() in _RUNNER_CALLS | _OUTPUT_CALLS | {"p", "puts", "print"})):
            return False                # `x %= 3`; `args <<FLAGS` appends, `system <<~CMD` is a heredoc
        return (prev is not None and prev.kind == "name" and i > 0 and text[i - 1] in " \t"
                and i + 1 < len(text) and not text[i + 1].isspace())

    def _regex_end(self, i: int) -> int:
        """The index after a regular expression literal that starts with `/` at `i` (classes `[...]` and
        backslashes read), and its flags; -1 if it does not end on its line."""
        text = self.text
        n = min(len(text), i + 1000)    # a regular expression literal longer than this: -2
        j = i + 1
        in_class = False
        while j < n:
            c = text[j]
            if c == "\n":
                return -1
            if c == "\\":
                j += 2
                continue
            if in_class:
                if c == "]":
                    in_class = False
            elif c == "[":
                in_class = True
            elif c == "/":
                m = re.compile(r"[A-Za-z]*").match(text, j + 1)
                return m.end()
            j += 1
        return -2 if n < len(text) and "\n" not in text[i:n] else -1

    def _skip_balanced(self, i: int, open_: str, close: str, limit: int | None = None) -> int:
        """The index after the `close` that ends a group opened just before `i`, skipping strings; -1 if
        it is not found (before `limit`)."""
        depth, text = 1, self.text
        n = len(text) if limit is None else min(limit, len(text))
        while i < n:
            c = text[i]
            if c == "\\":
                i += 2
                continue
            if c in "'\"`" and open_ != c:
                j = i + 1
                while j < n and text[j] != c and text[j] != "\n":
                    j += 2 if text[j] == "\\" else 1
                i = j + 1
                continue
            if c == open_ and open_ != close:
                depth += 1
            elif c == close:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return -1

    def _escape(self, style: str, i: int) -> tuple[str, int]:
        """The text an escape at `i` (just after its backslash, or backquote in PowerShell) stands for."""
        text = self.text
        c = text[i] if i < len(text) else ""
        simple = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b",
                  "0": "\0", "s": " "}
        if c == "\n":
            return "", i + 1
        if c in "xX" and style != "ps":
            m = re.compile(r"\{([0-9A-Fa-f]{1,8})\}|([0-9A-Fa-f]{1,2})").match(text, i + 1)
            if m:
                return _chr(int(m.group(1) or m.group(2), 16)), m.end()
        if c == "u" and style == "rb":
            m = re.compile(r"\{([0-9A-Fa-f \t]{1,64})\}").match(text, i + 1)
            if m:
                return "".join(_chr(int(x, 16)) for x in m.group(1).split()), m.end()
        if c == "u" and (style in ("py", "js", "rb", "php", "ps")):
            m = re.compile(r"\{([0-9A-Fa-f]{1,8})\}|([0-9A-Fa-f]{4})").match(text, i + 1)
            if m:
                return _chr(int(m.group(1) or m.group(2), 16)), m.end()
        if c == "U" and style == "py":
            m = re.compile(r"[0-9A-Fa-f]{8}").match(text, i + 1)
            if m:
                return _chr(int(m.group(0), 16)), m.end()
        if c == "N" and style in ("py", "pl"):
            m = re.compile(r"\{([^}]*)\}").match(text, i + 1)
            if m:
                name = m.group(1)
                if name.upper().startswith("U+"):
                    try:
                        return _chr(int(name[2:], 16)), m.end()
                    except ValueError:
                        return "\x00", m.end()
                try:
                    return unicodedata.lookup(name), m.end()
                except KeyError:
                    return "\x00", m.end()
        if c.isdigit() and c in "01234567" and style in ("py", "rb", "pl", "php", "awk", "js"):
            m = re.compile(r"[0-7]{1,3}").match(text, i)
            return _chr(int(m.group(0), 8)), m.end()
        if c == "o" and style == "pl":
            m = re.compile(r"\{([0-7]+)\}").match(text, i + 1)
            if m:
                return _chr(int(m.group(1), 8)), m.end()
        if c == "c" and style in ("pl", "rb") and i + 1 < len(text):
            return _chr(ord(text[i + 1].upper()) ^ 64), i + 2
        if style == "pl" and c in "ULulQEF":
            return "", i + 1            # case and quoting modifiers: options are matched in any case
        if c in simple:
            return simple[c], i + 1
        if style in ("py", "php", "awk") and c not in "\\'\"`$/":
            return "\\" + c, i + 1      # an escape these languages do not know keeps its backslash
        return c, i + 1

    def _scan(self, i: int, close: str, style: str, interp: str, nest: str = "") -> tuple[list, int]:
        """A string's parts from `i` up to its `close`; (parts, index after close) or ([], -1) if open."""
        text, n = self.text, len(self.text)
        parts: list = []
        buf: list = []
        depth = 0

        def hole(expression: str) -> None:
            if buf:
                parts.append((False, "".join(buf)))
                buf.clear()
            parts.append((True, expression))

        while i < n:
            if text[i] in "$\x02":
                m = _PASTED_RE.match(text, i)
                if m:
                    if buf:
                        parts.append((False, "".join(buf)))
                        buf.clear()
                    parts.append((PASTED, m.group(0)))
                    i = m.end()
                    continue
            if text[i] == "\n" and close in ("'", '"') and style in ("py", "js", "raw") and self.family in (
                    "python", "js"):
                return [], -1           # a one-line string in Python or JavaScript ends at its line's end
            if text.startswith(close, i) and depth == 0:
                if close in ("'", '"') and style in ("ps",) and text.startswith(close * 2, i):
                    buf.append(close)   # PowerShell doubles a quote to write one
                    i += 2
                    continue
                if buf:
                    parts.append((False, "".join(buf)))
                return parts, i + len(close)
            c = text[i]
            if nest and c == nest:
                depth += 1
            elif nest and c == close and depth:
                depth -= 1
            esc = "`" if style == "ps" else "\\"
            if c == esc and style != "raw":
                if style == "single":
                    nxt = text[i + 1] if i + 1 < n else ""
                    if nxt in ("\\", close[:1]) or (nest and nxt == nest):
                        buf.append(nxt)
                        i += 2
                    else:
                        buf.append(c)
                        i += 1
                    continue
                piece, i = self._escape(style, i + 1)
                buf.append(piece)
                continue
            if c == "\\" and style == "raw":
                # A raw string keeps the backslash, and a backslash still stops a quote ending the string.
                buf.append(text[i:i + 2])
                i += 2
                continue
            if interp:
                got = self._interpolation(i, interp)
                if got is not None:
                    expression, i = got
                    hole(expression)
                    continue
            buf.append(c)
            i += 1
        return [], -1

    def _interpolation(self, i: int, interp: str):
        """(the expression, index after it) for an interpolation at `i`, or None."""
        text = self.text
        c = text[i]
        two = text[i:i + 2]
        if interp == "py-f":
            if two in ("{{", "}}"):
                return None
            if c == "{":
                end = self._skip_balanced(i + 1, "{", "}")
                return (text[i + 1:end - 1], end) if end > 0 else (text[i + 1:], len(text))
            return None
        if interp == "js" and two == "${":
            end = self._skip_balanced(i + 2, "{", "}")
            return (text[i + 2:end - 1], end) if end > 0 else (text[i + 2:], len(text))
        if interp == "rb":
            if two == "#{":
                end = self._skip_balanced(i + 2, "{", "}")
                return (text[i + 2:end - 1], end) if end > 0 else (text[i + 2:], len(text))
            m = re.compile(r"#(?:@@?[A-Za-z_]\w*|\$(?:[A-Za-z_]\w*|\d+|[~!@&`'+*$?:\"<>,./\\;]))").match(text, i)
            return (m.group(0)[1:], m.end()) if m else None
        if interp in ("pl", "php", "ps"):
            if interp == "php" and two == "{$":
                end = self._skip_balanced(i + 1, "{", "}")
                return (text[i + 1:end - 1], end) if end > 0 else (text[i + 1:], len(text))
            if c not in "$@" or (c == "@" and interp != "pl"):
                return None
            if text[i + 1:i + 2] == "{":
                end = self._skip_balanced(i + 2, "{", "}")
                return (text[i:end], end) if end > 0 else (text[i:], len(text))
            if interp == "ps" and text[i + 1:i + 2] == "(":
                end = self._skip_balanced(i + 2, "(", ")")
                return (text[i:end], end) if end > 0 else (text[i:], len(text))
            name_re = r"[A-Za-z_][\w]*(?::[A-Za-z_][\w]*)?" if interp == "ps" else r"[A-Za-z_]\w*(?:::\w+)*"
            m = re.compile(name_re).match(text, i + 1)
            if not m:
                if interp == "pl" and c == "$" and text[i + 1:i + 2] and (
                        text[i + 1].isdigit() or text[i + 1] in "&_$!@.;,0"):
                    return text[i:i + 2], i + 2
                return None
            end = m.end()
            if interp in ("pl", "php"):
                # Subscripts and arrows read as part of the value: `$h{x}`, `$a[0]`, `$o->{x}`, `$o->name`.
                limit = end + _SUBSCRIPT_LIMIT
                while end < len(text) and end < limit:
                    if text[end] == "[":
                        close = self._skip_balanced(end + 1, "[", "]", limit)
                    elif text[end] == "{" and interp == "pl":
                        close = self._skip_balanced(end + 1, "{", "}", limit)
                    elif text.startswith("->", end):
                        m2 = re.compile(r"->(?:\w+|\[|\{)").match(text, end)
                        if not m2:
                            break
                        if m2.group(0).endswith(("[", "{")):
                            opener = m2.group(0)[-1]
                            close = self._skip_balanced(m2.end(), opener, _OPEN[opener], limit)
                        else:
                            close = m2.end()
                    else:
                        break
                    if close < 0:
                        break
                    end = close
            return text[i:end], end
        return None

    def _string_at(self, i: int):
        """(Tok, end) for a string that starts at `i`, or None; (None, -1) for one that does not end."""
        text, fam = self.text, self.family
        c = text[i]
        if fam == "python":
            m = _PY_PREFIX_RE.match(text, i)
            prefix = ""
            if m and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
                prefix = m.group(1).lower()
                if not set(prefix) <= set("rbuf") or len(set(prefix)) != len(prefix) or (
                        "u" in prefix and len(prefix) > 1) or ("b" in prefix and "f" in prefix):
                    return None
                i += len(prefix)
                c = text[i]
            elif c not in "'\"":
                return None
            quote = text[i:i + 3] if text[i:i + 3] in ("'''", '"""') else c
            style = "raw" if "r" in prefix else "py"
            interp = "py-f" if "f" in prefix else ""
            return self._finish(i + len(quote), quote, style, interp, start=i - len(prefix))
        if fam == "js":
            if c in "'\"":
                return self._finish(i + 1, c, "js", "", start=i)
            if c == "`":
                return self._finish(i + 1, "`", "js", "js", start=i)
            return None
        if fam == "ruby":
            if c == "'":
                return self._finish(i + 1, "'", "single", "", start=i)
            if c == '"':
                return self._finish(i + 1, '"', "rb", "rb", start=i)
            if c == "`":
                return self._finish(i + 1, "`", "rb", "rb", start=i, command=True)
            if c == "?" and self._value_position() and i + 1 < len(text) and not text[i + 1].isspace() and (
                    i + 2 >= len(text) or not (text[i + 2].isalnum() or text[i + 2] == "_")):
                return self._tok([(False, text[i + 1])], i, i + 2), i + 2      # a character literal (`?"`)
            if c == "%" and self._argument_position(i):
                m = re.compile(r"%([qQwWiIxrs]?)([^\w\s])").match(text, i)
                if m:
                    kind, opener = m.group(1), m.group(2)
                    close = _OPEN.get(opener, opener)
                    nest = opener if opener in _OPEN else ""
                    single = kind in ("q", "w", "i", "s")
                    return self._finish(m.end(), close, "single" if single else "rb", "" if single else "rb",
                                        start=i, nest=nest, command=kind == "x", words=kind in ("w", "W"))
            if text.startswith("<<", i) and self._argument_position(i):
                m = re.compile(r"<<([~-]?)(['\"`]?)([A-Za-z_]\w*)\2").match(text, i)
                if m:
                    return self._heredoc(i, m, interpolates=m.group(2) != "'", squiggly=m.group(1) == "~")
            return None
        if fam == "perl":
            if c == "'":
                return self._finish(i + 1, "'", "single", "", start=i)
            if c == '"':
                return self._finish(i + 1, '"', "pl", "pl", start=i)
            if c == "`":
                return self._finish(i + 1, "`", "pl", "pl", start=i, command=True)
            if c in "qmsty" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$@%&-")):
                m = re.compile(r"(qq|qw|qx|qr|q|m|s|tr|y)\s*([^\w\s=,;)\]}>])").match(text, i)
                if m:
                    kind, opener = m.group(1), m.group(2)
                    close = _OPEN.get(opener, opener)
                    nest = opener if opener in _OPEN else ""
                    if kind in ("m", "qr", "s", "tr", "y"):
                        return self._regex_like(i, m.end(), close, nest, two=kind in ("s", "tr", "y"))
                    single = kind in ("q", "qw") or opener == "'"      # `qq'...'` does not put values in
                    return self._finish(m.end(), close, "single" if single else "pl", "" if single else "pl",
                                        start=i, nest=nest, command=kind == "qx", words=kind == "qw")
            if text.startswith("<<", i) and self._argument_position(i):
                m = re.compile(r"<<(~?)(?:[ \t]*(['\"`])([A-Za-z_]\w*)\2|([A-Za-z_]\w*))").match(text, i)
                if m:
                    return self._heredoc(i, m, interpolates=m.group(2) != "'", squiggly=m.group(1) == "~",
                                         delimiter=m.group(3) or m.group(4))
            return None
        if fam == "php":
            if c == "'":
                return self._finish(i + 1, "'", "single", "", start=i)
            if c == '"':
                return self._finish(i + 1, '"', "php", "php", start=i)
            if c == "`":
                return self._finish(i + 1, "`", "php", "php", start=i, command=True)
            if text.startswith("<<<", i):
                m = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1").match(text, i)
                if m:
                    return self._heredoc(i, m, interpolates=m.group(1) != "'", squiggly=True,
                                         delimiter=m.group(2))
            return None
        if fam == "pwsh":
            if c == "@" and text[i + 1:i + 2] in _PS_QUOTES:
                quote = _PS_QUOTES[text[i + 1]]
                close_re = re.compile(r"\n[ \t]*[" + ("'\u2018\u2019\u201a\u201b" if quote == "'" else
                                                     '"\u201c\u201d\u201e') + r"]@")
                m = close_re.search(text, i + 2)
                if not m:
                    return None, -1
                body_start = text.find("\n", i + 2)
                body = text[body_start + 1 if body_start >= 0 else i + 2:m.start()]
                tok = self._sub_tokenize_string(body, "ps" if quote == '"' else "single",
                                                "ps" if quote == '"' else "")
                tok.start, tok.end = i, m.end()
                return tok, m.end()
            if c in _PS_QUOTES:
                quote = _PS_QUOTES[c]
                return self._finish_ps(i + 1, quote, start=i)
            return None
        if fam == "lua":
            if c in "'\"":
                return self._finish(i + 1, c, "js", "", start=i)
            m = re.compile(r"\[(=*)\[").match(text, i)
            if m:
                return self._finish(m.end(), "]" + m.group(1) + "]", "raw", "", start=i)
            return None
        if fam == "awk":
            if c == '"':
                return self._finish(i + 1, '"', "awk", "", start=i)
            return None
        if c in "'\"":
            return self._finish(i + 1, c, "js", "", start=i)
        return None

    def _finish_ps(self, i: int, quote: str, start: int):
        """A PowerShell string: any of its quote characters (straight or curly) closes it, doubled is one."""
        text, n = self.text, len(self.text)
        closers = [q for q, kind in _PS_QUOTES.items() if kind == quote]
        parts: list = []
        buf: list = []
        while i < n:
            c = text[i]
            if c in closers:
                if i + 1 < n and text[i + 1] in closers:
                    buf.append(c)
                    i += 2
                    continue
                if buf:
                    parts.append((False, "".join(buf)))
                return self._tok(parts, start, i + 1), i + 1
            if quote == '"':
                if c == "`" and i + 1 < n:
                    piece, i = self._escape("ps", i + 1)
                    buf.append(piece)
                    continue
                got = self._interpolation(i, "ps")
                if got is not None:
                    if buf:
                        parts.append((False, "".join(buf)))
                        buf = []
                    parts.append((True, got[0]))
                    i = got[1]
                    continue
            buf.append(c)
            i += 1
        return None, -1

    def _sub_tokenize_string(self, body: str, style: str, interp: str) -> Tok:
        sub = _Tokenizer(body + "\x01", self.family)
        parts, _end = sub._scan(0, "\x01", style, interp)
        return self._tok(parts, 0, 0)

    def _tok(self, parts: list, start: int, end: int, command: bool = False) -> Tok:
        known = "".join("\x00" if is_hole else t for is_hole, t in parts)
        return Tok("str", known, start, end, parts, command=command)

    def _finish(self, i: int, close: str, style: str, interp: str, start: int, nest: str = "",
                command: bool = False, words: bool = False):
        parts, end = self._scan(i, close, style, interp, nest)
        if end < 0:
            return None, -1
        tok = self._tok(parts, start, end, command)
        if words:
            # A word list (`%w[a b]`, `qw(a b)`) is a list of strings: `[` the words `]`.
            return ("words", tok), end
        return tok, end

    def _regex_like(self, start: int, i: int, close: str, nest: str, two: bool):
        parts, end = self._scan(i, close, "raw", "", nest)
        if end < 0:
            return None, -1
        if two:
            if nest:
                m = re.compile(r"\s*([^\w\s])").match(self.text, end)
                if not m:
                    return None, -1
                close2 = _OPEN.get(m.group(1), m.group(1))
                _parts, end = self._scan(m.end(), close2, "raw", "", m.group(1) if m.group(1) in _OPEN else "")
            else:
                _parts, end = self._scan(end, close, "raw", "", "")
            if end < 0:
                return None, -1
        m = re.compile(r"[a-z]*").match(self.text, end)
        return ("skip", None), m.end()

    def _heredoc(self, i: int, m, interpolates: bool, squiggly: bool, delimiter: str | None = None):
        delimiter = delimiter or m.group(3)
        tok = Tok("str", "", i, m.end())
        self.pending_heredocs.append((tok, delimiter, interpolates, squiggly))
        return tok, m.end()

    def _read_heredocs(self, i: int) -> int:
        """At a line end with heredocs pending: read their bodies, which follow the line, in order."""
        text = self.text
        for tok, delimiter, interpolates, squiggly in self.pending_heredocs:
            j = i
            lines: list = []
            found = False
            while j <= len(text):
                k = text.find("\n", j)
                line = text[j:k if k >= 0 else len(text)]
                if line.strip() == delimiter:
                    found = True
                    j = (k + 1) if k >= 0 else len(text)
                    break
                closer = re.match(r"[ \t]*" + re.escape(delimiter) + r"(?!\w)", line) if self.family == "php" else None
                if closer:
                    # PHP 7.3 on: the closing name may be followed by code on its line (`EOT);`).
                    found = True
                    j = j + closer.end()
                    break
                lines.append(line)
                if k < 0:
                    j = len(text) + 1
                    break
                j = k + 1
            if not found:
                self.problem = self.problem or f"a heredoc with no line `{delimiter}`"
            body = "\n".join(line.lstrip() if squiggly else line for line in lines)
            style = {"ruby": "rb", "perl": "pl", "php": "php"}.get(self.family, "js")
            sub = self._sub_tokenize_string(body, style if interpolates else "raw",
                                            style if interpolates else "")
            tok.parts, tok.text = sub.parts, sub.text
            i = min(j, len(text))
        self.pending_heredocs = []
        return i

    # -- the loop
    def run(self) -> tuple[list, str]:
        text, fam = self.text, self.family
        n = len(text)
        i = 0
        if fam == "php":
            m = re.compile(r"\s*<\?(php)?").match(text)
            if m:
                i = m.end()
        line_start = True
        while i < n:
            c = text[i]
            if c == "\n":
                if not self.depth or self.depth[-1] == "{":
                    self.toks.append(Tok("nl", "\n", i, i + 1))
                i += 1
                if self.pending_heredocs:
                    i = self._read_heredocs(i)
                line_start = True
                continue
            if c.isspace() or c == "\ufeff":
                i += 1
                continue
            at_line_start, line_start = line_start, False
            if c == "\\" and text[i + 1:i + 2] == "\n" and fam != "pwsh":
                i += 2
                continue
            if fam == "pwsh" and c == "`" and text[i + 1:i + 2] in ("\n", "\r"):
                i += 2
                continue
            # Comments.
            if fam == "perl" and at_line_start and c == "=" and re.compile(r"=[A-Za-z]").match(text, i):
                m = re.compile(r"^=cut\b.*$", re.M).search(text, i)
                i = m.end() if m else n
                continue
            if fam == "ruby" and at_line_start and text.startswith("=begin", i):
                m = re.compile(r"^=end\b.*$", re.M).search(text, i)
                i = m.end() if m else n
                continue
            if fam == "pwsh" and text.startswith("<#", i):
                j = text.find("#>", i + 2)
                i = j + 2 if j >= 0 else n
                continue
            if fam == "js" and (text.startswith("<!--", i) or (at_line_start and text.startswith("-->", i))):
                j = text.find("\n", i)
                i = j if j >= 0 else n          # HTML-like comments, which JavaScript reads as line comments
                continue
            if fam == "php" and text.startswith("?>", i):
                m = re.compile(r"<\?(?:php|=)?").search(text, i + 2)
                i = m.end() if m else n         # inline HTML up to the next `<?php`
                continue
            if fam in ("js", "php", "other") and text.startswith("/*", i):
                j = text.find("*/", i + 2)
                i = j + 2 if j >= 0 else n
                continue
            if fam == "lua" and text.startswith("--", i):
                m = re.compile(r"--\[(=*)\[").match(text, i)
                if m:
                    j = text.find("]" + m.group(1) + "]", m.end())
                    i = j + len(m.group(1)) + 2 if j >= 0 else n
                else:
                    j = text.find("\n", i)
                    i = j if j >= 0 else n
                continue
            if (c == "#" and fam in ("python", "ruby", "perl", "pwsh", "awk", "php", "other")
                    and not (fam == "php" and text[i + 1:i + 2] == "[")) or (
                    text.startswith("//", i) and fam in ("js", "php", "other")):
                if not (fam == "perl" and self.toks and self.toks[-1].kind == "op" and self.toks[-1].text == "$"
                        and self.toks[-1].end == i):
                    j = text.find("\n", i)
                    i = j if j >= 0 else n
                    continue
            # A value pasted into the text before the code runs.
            if c in "$\x02":
                m = _PASTED_RE.match(text, i)
                if m:
                    self.toks.append(Tok("name", m.group(0), i, m.end(), sigil="pasted"))
                    i = m.end()
                    continue
            # Perl's punctuation variables (`$'`, `$"`, `` $` ``, `$&`, `$;`): not the start of a string.
            if fam == "perl" and c == "$" and text[i + 1:i + 2] and text[i + 1] in "'\"`&;,./\\!@$0123456789+^":
                self.toks.append(Tok("name", text[i + 1], i, i + 2, sigil="$"))
                i += 2
                continue
            # Strings.
            got = self._string_at(i)
            if got is not None:
                tok, end = got
                if end < 0:
                    self.problem = self.problem or "a string that does not end"
                    break
                if isinstance(tok, tuple):
                    kind, inner = tok
                    if kind == "words":
                        self.toks.append(Tok("op", "[", i, i, sigil="words"))
                        # `%W[a #{b}]` keeps its values: a word with one is a value the checker cannot read.
                        pieces = "".join("\x01" if h else t for h, t in inner.parts).split()
                        for word in pieces:
                            parts = [(False, word)] if "\x01" not in word else [(True, word.replace("\x01", "#{}"))]
                            self.toks.append(Tok("str", word.replace("\x01", "\x00"), i, end, parts))
                            self.toks.append(Tok("op", ",", i, i))
                        self.toks.append(Tok("op", "]", end, end))
                    i = end
                    continue
                if tok.end == 0:
                    tok.end = end
                self.toks.append(tok)
                i = end
                continue
            # A regular expression, where a value may start.
            if c == "/" and fam in ("js", "awk", "ruby", "perl") and self._value_position():
                end = self._regex_end(i)
                if end > 0:
                    i = end
                    continue
                if end == -2:
                    self.problem = self.problem or "a regular expression longer than the checker reads"
                    break
            # Names, with a sigil where the language has one.
            if c in "$@%&" and fam in ("perl", "php", "pwsh", "ruby"):
                m = (_PS_NAME_RE if fam == "pwsh" else _NAME_RE).match(text, i + 1)
                if fam == "pwsh" and m and text[m.end():m.end() + 1] == ":" :
                    m2 = _PS_NAME_RE.match(text, m.end() + 1)
                    if m2:
                        m = m2
                if fam == "perl" and text.startswith("$#", i):
                    m = _NAME_RE.match(text, i + 2)
                if m and (c != "%" or fam == "perl") and (c != "&" or fam == "perl"):
                    sigil = c if fam != "ruby" else ""
                    if fam == "ruby" and c == "@" and text[i + 1:i + 2] == "@":
                        m = _NAME_RE.match(text, i + 2) or m
                    self.toks.append(Tok("name", m.group(0), i, m.end(), sigil=sigil))
                    i = m.end()
                    continue
            m = (_PS_NAME_RE if fam == "pwsh" else _NAME_RE).match(text, i)
            if m:
                self.toks.append(Tok("name", m.group(0), i, m.end()))
                i = m.end()
                continue
            m = _NUM_RE.match(text, i)
            if m:
                self.toks.append(Tok("num", m.group(0), i, m.end()))
                i = m.end()
                continue
            op = next((o for o in _MULTI_OPS if text.startswith(o, i)), c)
            self.toks.append(Tok("op", op, i, i + len(op)))
            if op in ("(", "[", "{"):
                self.depth.append(op)
            elif op in (")", "]", "}") and self.depth:
                self.depth.pop()
            i += len(op)
        if self.pending_heredocs:
            self._read_heredocs(n)
        return self.toks, self.problem


def _chr(code: int) -> str:
    try:
        return chr(code)
    except (ValueError, OverflowError):
        return "\x00"


def tokens(text: str, family: str) -> tuple[list, str]:
    return _Tokenizer(text, family).run()


# ---------------------------------------------------------------------------------------- the structure
def _brackets(toks: list) -> tuple[list, list]:
    """For each token, the index of the bracket that encloses it (-1 at the top), and for each opening
    bracket the index of its closing one (-1 for none)."""
    parent = [-1] * len(toks)
    close = [-1] * len(toks)
    stack: list = []
    for k, t in enumerate(toks):
        parent[k] = stack[-1] if stack else -1
        if t.kind == "op" and t.text in ("(", "[", "{"):
            stack.append(k)
        elif t.kind == "op" and t.text in (")", "]", "}"):
            want = {")": "(", "]": "[", "}": "{"}[t.text]
            while stack and toks[stack[-1]].text != want:
                stack.pop()
            if stack:
                close[stack.pop()] = k
            parent[k] = stack[-1] if stack else -1
    return parent, close


@dataclass
class Expr:
    first: int                  # its first and last token
    last: int
    parts: list                 # (is a value the checker cannot read, text): literal pieces joined
    pieces: int                 # how many operands were joined
    command: bool = False       # a string the language runs as a command line
    shown: str = ""


class _Code:
    """One piece of code and what is read from it."""

    def __init__(self, text: str, family: str, ctx: af._Context) -> None:
        self.text = text
        self.family = family
        self.ctx = ctx
        self.toks, self.problem = tokens(text, family)
        self.parent, self.close = _brackets(self.toks)
        self.exprs: list = []
        self.expr_at: dict = {}             # token index -> the expression that starts there
        self.held: list = []                # (name, token of the name) for lists that hold the program
        self.names: dict | None = None      # name -> the tokens that name it, worked out once
        self.budget = 400_000               # tokens the argument readers may visit, beyond which: cannot tell
        self.values: dict = {}              # name -> the values it is given (`_values`)
        self.paste = [_PASTE_LIMIT]         # characters of names' values that may still be put into strings
        self.sites = 0

    def site(self) -> bool:
        """Count one place the program is read; beyond `_SITE_LIMIT`, "cannot tell"."""
        self.sites += 1
        if self.sites == _SITE_LIMIT + 1:
            self.cannot_tell(f"the program read in more than {_SITE_LIMIT} places")
        return self.sites <= _SITE_LIMIT

    def spend(self, amount: int) -> bool:
        self.budget -= max(amount, 1)
        if self.budget < 0:
            self.cannot_tell("code larger than the checker reads")
            return False
        return True

    def cannot_tell(self, shown: str) -> None:
        for flag in self.ctx.flags:
            if flag["id"] not in self.ctx.reading.hits:
                self.ctx.reading.cannot_tell(flag, f"{self.family}: {af._fact_text(shown)}")

    def src(self, first: int, last: int) -> str:
        if first > last or first >= len(self.toks):
            return ""
        return " ".join(self.text[self.toks[first].start:self.toks[min(last, len(self.toks) - 1)].end].split())

    # -- operands and the strings they join into
    def _operand_end(self, k: int) -> int:
        """The last token of the value that starts at `k` (a name with its `.x`, `[...]`, `(...)`, a group,
        a number, a string), or -1 if none starts there."""
        toks = self.toks
        if k >= len(toks):
            return -1
        t = toks[k]
        if t.kind == "op" and t.text == "$" and self.family == "awk" and k + 1 < len(toks) and toks[k + 1].kind in (
                "num", "name"):
            return k + 1                    # an awk field (`$1`, `$NF`)
        if t.kind == "op" and t.text in ("(", "[", "{") and self.close[k] > 0:
            end = self.close[k]
        elif t.kind in ("name", "num", "str"):
            end = k
        elif t.kind == "op" and t.text in ("-", "!", "~", "+") and k + 1 < len(toks):
            j = k
            while j < len(toks) and toks[j].kind == "op" and toks[j].text in ("-", "!", "~", "+"):
                j += 1
            return self._operand_end(j) if j < len(toks) and not (toks[j].kind == "op" and toks[j].text in (
                "-", "!", "~", "+")) else -1
        else:
            return -1
        if t.kind == "str":
            # `'-' * 2`, `'-' x 2`: repeated, a value the checker does not work out; `.format(...)` and
            # `.concat(...)` are read where the string is joined.
            if end + 2 < len(toks) and ((toks[end + 1].kind == "op" and toks[end + 1].text == "*") or (
                    toks[end + 1].kind == "name" and toks[end + 1].text == "x" and self.family == "perl")) and \
                    toks[end + 2].kind in ("num", "name"):
                return end + 2
            if end + 3 < len(toks) and toks[end + 1].text == "." and toks[end + 2].text in ("repeat", "lower", "upper",
                    "toLowerCase", "toUpperCase", "swapcase", "casefold", "downcase", "upcase", "reverse") and \
                    toks[end + 3].text == "(" and self.close[end + 3] > 0:
                return self.close[end + 3]
            if end + 1 < len(toks) and toks[end + 1].text == "[" and self.close[end + 1] > 0:
                return self.close[end + 1]          # `'...'[::-1]`
            return end
        if t.kind == "num" and end + 2 < len(toks) and toks[end + 1].text == "*" and toks[end + 2].kind == "str":
            return end + 2                          # `2 * '-'`
        while end + 1 < len(toks):
            nxt = toks[end + 1]
            if nxt.kind == "op" and nxt.text in ("(", "[") and self.close[end + 1] > 0:
                end = self.close[end + 1]
            elif nxt.kind == "op" and nxt.text in (".", "->", "::", "?.") and end + 2 < len(toks) and toks[
                    end + 2].kind == "name" and not (self.family in ("perl", "php") and nxt.text == "."):
                end += 2
            elif nxt.kind == "op" and nxt.text == "{" and self.family == "perl" and toks[end].sigil and \
                    self.close[end + 1] > 0:
                end = self.close[end + 1]
            else:
                break
        return end

    def _string_value(self, first: int, last: int) -> list | None:
        """The parts of a value that is one string literal, or None."""
        if first == last and self.toks[first].kind == "str":
            return list(self.toks[first].parts)
        return None

    def _top_level(self, a: int, b: int) -> list:
        """The tokens a..b with every bracket group's inside left out (its brackets kept)."""
        out: list = []
        k = a
        while k <= b:
            out.append(k)
            if self.toks[k].kind == "op" and self.toks[k].text in ("(", "[", "{") and a <= self.close[k] <= b \
                    and self.close[k] > k:
                k = self.close[k]
                out.append(k)
            k += 1
        return out

    def build(self) -> None:
        toks, fam = self.toks, self.family
        concat = _CONCAT.get(fam, _CONCAT["other"])
        covered = bytearray(len(toks))
        k = 0
        while k < len(toks):
            if covered[k]:
                k += 1
                continue
            end = self._operand_end(k)
            if end < 0:
                k += 1
                continue
            operands = [(k, end)]
            j = end
            while True:
                nxt = toks[j + 1] if j + 1 < len(toks) else None
                if nxt is None or nxt.kind == "nl":
                    break
                if nxt.kind == "op" and nxt.text in concat:
                    e2 = self._operand_end(j + 2)
                    if e2 < 0:
                        break
                    operands.append((j + 2, e2))
                    j = e2
                    continue
                if (fam == "awk" or (fam in ("python", "ruby") and toks[j].kind == "str" and nxt.kind == "str")) \
                        and nxt.kind in ("str", "name", "num") or (fam == "awk" and nxt.kind == "op" and nxt.text in (
                            "(", "$")):
                    e2 = self._operand_end(j + 1)
                    if e2 < 0 or (fam == "awk" and toks[j + 1].kind == "name" and toks[j + 1].text in (
                            "in", "getline", "if", "else", "while", "for", "do", "print", "printf")):
                        break
                    operands.append((j + 1, e2))
                    j = e2
                    continue
                if nxt.kind == "op" and nxt.text == "." and fam == "js" and j + 2 < len(toks) and toks[
                        j + 2].text == "concat" and j + 3 < len(toks) and toks[j + 3].text == "(":
                    # `"claude ".concat(x)`: each argument is a piece.
                    close = self.close[j + 3]
                    if close < 0:
                        break
                    operands.append((j + 3, close))
                    j = close
                    continue
                break
            strings = [o for o in operands if self._string_value(*o) is not None]
            if strings:
                parts: list = []
                for a, b in operands:
                    sv = self._string_value(a, b)
                    if sv is None:
                        pasted = any(toks[x].sigil == "pasted" for x in range(a, b + 1))
                        parts.append((PASTED if pasted else True, self.src(a, b)))
                    else:
                        parts.extend(sv)
                self._format(parts, operands, j)
                command = any(toks[a].command for a, b in operands if a == b)
                expr = Expr(k, j, _merge(parts), len(operands), command, self.src(k, j))
                self.exprs.append(expr)
                self.expr_at[k] = expr
            # Each token outside a bracket group starts at most one value; a group's inside is read on its own.
            for x in self._top_level(k, j):
                covered[x] = 1
            k += 1

    def _format(self, parts: list, operands: list, last: int) -> None:
        """`%` specifiers made values where the string is formatted (`"claude %s" % x`, `sprintf(...)`), and
        `{...}` where `.format` or `-f` follows: each becomes a value the checker cannot read."""
        toks = self.toks
        nxt = toks[last + 1] if last + 1 < len(toks) else None
        after = toks[last + 2] if last + 2 < len(toks) else None
        first = operands[0][0]
        parent = self.parent[first]
        callee = self.callee(parent) if parent >= 0 and toks[parent].text == "(" else ""
        percent = (nxt is not None and nxt.kind == "op" and nxt.text == "%") or callee in (
            "sprintf", "printf", "format", "fmt", "sprintf!", "string.format")
        braces = (nxt is not None and nxt.kind == "op" and nxt.text == "." and after is not None and
                  after.text == "format") or (nxt is not None and nxt.text == "-" and after is not None and
                                              after.text.lower() == "f") or callee.endswith("format")
        if not (percent or braces):
            return
        pattern = re.compile(r"%(?:\([^)]*\))?[-#0 +]*(?:\*|\d+)?(?:\.(?:\*|\d+))?[hlLqjzt]*[a-zA-Z%]" if percent
                             else r"\{[^{}]*\}")
        out: list = []
        for is_hole, text in parts:
            if is_hole:
                out.append((is_hole, text))
                continue
            pos = 0
            for m in pattern.finditer(text):
                if m.group(0) in ("%%",):
                    continue
                out.append((False, text[pos:m.start()]))
                out.append((True, m.group(0)))
                pos = m.end()
            out.append((False, text[pos:]))
        parts[:] = out

    def callee(self, open_index: int) -> str:
        """The name of what is called with the bracket at `open_index`, lower case, its last part
        (`exec.exec` -> `exec`), or "" if no name is before it."""
        k = open_index - 1
        if k < 0 or self.toks[k].kind != "name":
            return ""
        return self.toks[k].text.lower()



def _merge(parts: list) -> list:
    out: list = []
    for is_hole, text in parts:
        if not is_hole and out and not out[-1][0]:
            out[-1] = (False, out[-1][1] + text)
        elif is_hole or text:
            out.append((is_hole, text))
    return out


def _literal(parts: list) -> str | None:
    if any(is_hole for is_hole, _t in parts):
        return None
    return "".join(t for _h, t in parts)


def _is_program(text: str, ctx: af._Context) -> bool:
    stripped = text.strip()
    return bool(stripped) and (af._base(stripped) in ctx.programs or af._is_package(stripped, ctx.packages))


# ------------------------------------------------------------------------------------------- reading
_TRANSPARENT_CALLS = frozenset({"split", "join", "implode", "str", "string", "format", "quote", "strip", "trim",
                                "tostring", "concat", "list", "tuple", "from", "of", "sprintf", "fmt", "shlex",
                                "encode", "decode", "lower", "upper", "rstrip", "lstrip", ""})
_JOINS = frozenset({"join", "implode"})
_SPLITS = frozenset({"split", "shellwords", "shlex_split"})
_ARG_KEYS = frozenset({"args", "argv", "arguments", "argumentlist", "cmd", "command"})
_LIST_WRAPPERS = frozenset({"list", "tuple", "from", "of", "array", "freeze"})


def read_code(text: str, family: str, ctx: af._Context) -> None:
    """Read code in another language that names the tool (see the module's text)."""
    fam = family_of(family)
    if fam == "cmd":
        read_cmd(text, ctx)
        return
    code = _Code(text, fam, ctx)
    if code.problem and (ctx.mentioned or af.names(text, ctx.programs, ctx.packages)):
        # Code the tokenizer cannot split (a string that does not end) is "cannot tell", as in bash, where it
        # names the tool: not where the name's letters are only inside another word (`print('acne')`; flagship
        # slice 2d.23, #388).
        code.cannot_tell(f"{code.problem}: {text[:80]}")
    # Only code that names the tool in one of its strings or names is read further.
    if not any(t.kind in ("str", "name") and af.mentions(t.text, ctx.programs, ctx.packages) for t in code.toks):
        return
    code.build()
    code.values = _values(code)
    aliases = _aliases(code)
    # A value that is a name given a string that names the program (`f"{p} --yolo"`, `p + " --yolo"`,
    # `f"{c}"` where `c = "claude " + f`) is that string's parts; at most `_PASTE_LIMIT` characters are put in
    # for a piece of code, beyond which the rest is "cannot tell".
    budget = code.paste

    def put_in(expr: Expr) -> list:
        out: list = []
        for h, t in expr.parts:
            name = _bare(t) if h is True else ""
            value = _value_at(code, name, expr.first) if name else None
            sub = code.expr_at.get(value[0]) if value else None
            if sub is not None and sub.last == value[1] and sub is not expr and af.mentions(
                    "".join("" if hh else tt for hh, tt in sub.parts), ctx.programs, ctx.packages):
                size = sum(len(tt) for _hh, tt in sub.parts)
                budget[0] -= size
                if budget[0] < 0:
                    if budget[0] + size >= 0:
                        code.cannot_tell("names put into strings beyond what the checker reads")
                    out.append((h, t))
                    continue
                out.extend(sub.parts)
            else:
                out.append((h, t))
        return _merge(out)
    if code.values:
        for expr in code.exprs:
            if any(h is True and _bare(t) for h, t in expr.parts):
                expr.parts = put_in(expr)
    for expr in code.exprs:
        literal = _literal(expr.parts)
        joined = "".join("" if h else t for h, t in expr.parts)
        if not af.mentions(joined, ctx.programs, ctx.packages):
            continue
        if literal is not None and _is_program(literal, ctx):
            if code.site():
                _argv(code, expr.first, expr.last)
            continue
        _command_line(code, expr)
    for name, (_literal_text, alone, uses) in aliases.items():
        for k in uses:
            if alone and code.site():
                _argv(code, k, k)
    _held_lists(code)


# -- names and their values
def _statement_end(code: _Code, k: int) -> bool:
    toks = code.toks
    return k >= len(toks) or toks[k].kind == "nl" or (toks[k].kind == "op" and toks[k].text in (";", ")", "}", ","))


def _values(code: _Code) -> dict:
    """Each name given a value (`NAME = ...`, `NAME: type = ...`, `my $NAME = ...`): name -> [(the token of
    the name, the value's first token, its last token)], in the order written."""
    out: dict = {}
    toks = code.toks
    for k, t in enumerate(toks):
        if t.kind != "name" or k + 1 >= len(toks):
            continue
        j = k + 1
        if code.family == "python" and toks[j].kind == "op" and toks[j].text == ":":
            # An annotation: `cmd: list[str] = [...]`.
            j += 1
            while j < len(toks) and toks[j].kind != "nl" and not (toks[j].kind == "op" and toks[j].text == "="):
                if toks[j].kind == "op" and toks[j].text in ("(", "[", "{") and code.close[j] > 0:
                    j = code.close[j]
                j += 1
            if j >= len(toks) or toks[j].kind == "nl":
                continue
        if not (toks[j].kind == "op" and toks[j].text in ("=", ":=")):
            continue
        a = j + 1
        if a >= len(toks):
            continue
        b = code._operand_end(a)
        expr = code.expr_at.get(a)
        if expr is not None:
            b = expr.last
        if b < 0 or not _statement_end(code, b + 1):
            continue
        out.setdefault(t.text, []).append((k, a, b))
    return out


def _value_at(code: _Code, name: str, use: int):
    """The value a name was last given before token `use`: (first, last) tokens, or None."""
    assignments = code.values.get(name)
    if not assignments:
        return None
    n = bisect.bisect_left([k for k, _a, _b in assignments] if len(assignments) < 8 else _starts(code, name), use)
    while n > 0:
        _k, a, b = assignments[n - 1]
        if not (a <= use <= b):
            return (a, b)
        n -= 1
    return None


def _starts(code: _Code, name: str) -> list:
    cache = code.__dict__.setdefault("_starts_cache", {})
    if name not in cache:
        cache[name] = [k for k, _a, _b in code.values.get(name, ())]
    return cache[name]


def _next_assignment(code: _Code, name: str, after: int) -> int:
    starts = _starts(code, name)
    n = bisect.bisect_right(starts, after)
    return starts[n] if n < len(starts) else len(code.toks)


def _aliases(code: _Code) -> dict:
    """Names given a literal string that names the program (`p = "claude"`, `my $p = 'claude';`,
    `cmd = "claude -p x"`): name -> (the literal, whether it is the program alone, the tokens where the name
    is used as a value before it is given another). Where a name given the program alone is used, it is
    read as the program; a string changed in place there (`cmd += flags`) is "cannot tell"."""
    out: dict = {}
    toks = code.toks
    for name, assignments in code.values.items():
        uses = None
        for k, a, b in assignments:
            expr = code.expr_at.get(a)
            if expr is None or expr.last != b:
                continue
            literal = _literal(expr.parts)
            if literal is None or expr.pieces != 1 or not af.mentions(literal, code.ctx.programs, code.ctx.packages):
                continue
            stop = _next_assignment(code, name, k)
            entry = out.setdefault(name, (literal, _is_program(literal, code.ctx), []))
            if uses is None:
                uses = _uses(code, name, k)
            for u in uses[bisect.bisect_right(uses, k):bisect.bisect_left(uses, stop)]:
                if a <= u <= b:
                    continue
                if u + 1 < len(toks) and toks[u + 1].kind == "op" and toks[u + 1].text in ("+=", ".=", "<<", "<<="):
                    code.cannot_tell(code.src(u, min(u + 3, len(toks) - 1)))
                    continue
                entry[2].append(u)
    return out


def _bare(expression: str) -> str:
    """A value's text as a plain name, if it is one (`$p`, `${p}`, `@p`, ` p `), else ""."""
    m = re.fullmatch(r"\s*[$@]?\{?\s*([^\W\d]\w*)\s*\}?\s*", expression)
    return m.group(1) if m else ""


# -- command lines in strings
def _call_start(code: _Code, open_index: int) -> int:
    """The first token of the callee chain before the bracket at `open_index` (`shlex.split(` -> `shlex`)."""
    k = open_index - 1
    while k >= 2 and code.toks[k - 1].kind == "op" and code.toks[k - 1].text in (".", "->", "::", "?.") and \
            code.toks[k - 2].kind in ("name", "str"):
        k -= 2
    return k


def _first_or_after_shell(code: _Code, k: int, p: int) -> bool:
    """Whether token `k`, inside the bracket at `p`, is its first argument or element, or comes after a
    shell's name there (`["bash", "-c", "..."]`, `system("sh", "-c", "...")`): otherwise it is one argument
    of an argument list, not a command line."""
    shell = False
    for index, (a, b) in enumerate(_split_args(code, p + 1, code.close[p] - 1)):
        if a <= k <= b:
            return index == 0 or shell
        lit = code.expr_at.get(a)
        if lit is not None and lit.last == b and af._base((_literal(lit.parts) or "").strip()) in _SHELL_NAMES:
            shell = True
    return False


def _reaches_runner(code: _Code, k: int, hops: int = 0, end: int | None = None) -> bool:
    """Whether the value that starts at token `k` is given to a call that runs a command line: directly, or
    through calls that only change its form (`shlex.split`, `join`, `str`), a list after a shell's name,
    or a name that is (worked out once for each place)."""
    memo = code.__dict__.setdefault("_runner_memo", {})
    key = (k, hops, end)
    if key not in memo:
        memo[key] = False
        memo[key] = _reaches_runner_uncached(code, k, hops, end)
    return memo[key]


def _reaches_runner_uncached(code: _Code, k: int, hops: int, end: int | None) -> bool:
    toks = code.toks
    runners = _RUNNER_CALLS | ({"open"} if code.family in ("perl", "ruby") else frozenset())
    before = toks[k - 1] if k >= 1 else None
    if before is not None and before.kind == "name" and before.text.lower() in runners:
        return True                                     # a call without brackets (`system "..."`)
    if before is not None and before.kind == "op" and before.text == "$" and code.family == "js":
        return True                                     # zx's `` $`...` ``
    if code.family == "awk":
        # awk runs a command line it prints into or reads from: `print ... | cmd`, `cmd | getline`.
        end = code._operand_end(k) if end is None else end
        after = toks[end + 1] if 0 <= end < len(toks) - 1 else None
        group = code.parent[k]
        if group >= 1 and toks[group].text == "(" and not code.callee(group) and toks[group - 1].text == "|":
            return True                                 # `print ... | ("claude " x)`
        if (before is not None and before.kind == "op" and before.text == "|") or (
                after is not None and after.text == "|" and end + 2 < len(toks) and toks[end + 2].text == "getline"):
            return True
    p = code.parent[k]
    levels = 0
    inner = k
    while p >= 0 and levels < 6:
        if toks[p].text == "(":
            callee = code.callee(p)
            if callee in runners or _is_runner(code, p):
                # Perl's and Ruby's `open` take the command line among later arguments (`open($fh, '-|', ...)`).
                return callee == "open" or _first_or_after_shell(code, inner, p)
            if callee not in _TRANSPARENT_CALLS:
                return False
        elif toks[p].text == "[":
            holder = code.parent[p]
            if not _first_or_after_shell(code, inner, p) and not (
                    holder >= 0 and toks[holder].text == "(" and _is_runner(code, holder) and _first_or_after_shell(
                        code, p, holder) and _split_args(code, holder + 1, code.close[holder] - 1)[0][0] != p):
                return False                            # one argument of an argument list
        elif toks[p].text == "{":
            break                                       # a block or an object: the name it is given decides
        inner = p
        p = code.parent[p]
        levels += 1
    if hops < 2:
        top = k
        while code.parent[top] >= 0 and toks[code.parent[top]].text == "(":
            p = code.parent[top]
            if code.callee(p) in _TRANSPARENT_CALLS - {""}:
                top = _call_start(code, p)
            elif not code.callee(p) and code.close[p] > 0 and (end is None or code.close[p] == (end or 0) + 1):
                top = p                         # brackets round the value: `c = ('claude ' + f)`
            else:
                break
        name = _assigned_name(code, top)
        if name is not None:
            stop = _next_assignment(code, name, top - 2)
            uses = [u for u in _uses(code, name, top - 2) if top < u < stop]
            if len(uses) > _SITE_LIMIT:
                return True                     # too many places to follow: read it as a command line
            return any(_reaches_runner(code, u, hops + 1) for u in uses)
    return False


def _split_into_list(code: _Code, expr: Expr) -> int | None:
    """Where a command line string is split into a list (`shlex.split("...")`, `"...".split()`), the token
    the list is given to by name, or None."""
    toks = code.toks
    p = code.parent[expr.first]
    if p >= 0 and toks[p].text == "(" and code.callee(p) in _SPLITS:
        return _call_start(code, p)
    nxt = expr.last + 1
    if nxt + 1 < len(toks) and toks[nxt].text == "." and toks[nxt + 1].text.lower() in _SPLITS:
        return expr.first
    return None


def _command_line(code: _Code, expr: Expr) -> None:
    """A string that names the program and is given to a call that runs a command line (or is one): read as
    bash, with each value the checker cannot read put in as text whose value is not known, outside any
    quotes (text put into a string can end them). A name whose value is a literal is that literal."""
    ctx = code.ctx
    split_at = _split_into_list(code, expr)
    if split_at is not None:
        name = _assigned_name(code, split_at)
        if name is not None:
            code.held.append((name, split_at - 2))
    if not (expr.command or split_at is not None or _reaches_runner(code, expr.first, end=expr.last)):
        return
    if not code.site():
        return
    p = code.parent[expr.first]
    if p >= 0 and code.toks[p].text == "(" and expr.last + 1 < len(code.toks) and code.toks[expr.last + 1].text == ",":
        # A command line and then its arguments (`exec.exec('claude -p x', flags)`, `spawn('claude --print',
        # args)`): the arguments come after the line's own words.
        literal = _literal(expr.parts)
        line_words = literal.split() if literal is not None else []
        at = next((n for n, w in enumerate(line_words) if af._base(w) in ctx.programs or af._is_package(
            w, ctx.packages)), None)
        if at is not None:
            words: list = [af.Word(text=w, shown=w) for w in line_words[at + 1:]]
            joined = any(_shell_option(code, a, b) for a, b in _split_args(code, expr.last + 2, code.close[p] - 1))
            for a, b in _split_args(code, expr.last + 2, code.close[p] - 1):
                words.extend(_word(code, a, b, False, code.callee(p), joined=joined))
            _read_words(code, words)
    holes: list = []
    shell: list = []
    quote = ""
    raw = "".join(t for _h, t in expr.parts)
    prefix = _HOLE_NAME
    while prefix in raw:
        prefix += "X"
    for is_hole, text in expr.parts:
        if is_hole:
            value = _value_at(code, _bare(text), expr.first) if is_hole is True and _bare(text) else None
            sub = code.expr_at.get(value[0]) if value else None
            literal = _literal(sub.parts) if sub is not None and sub.last == value[1] else None
            if literal is not None and len(literal) <= code.paste[0]:
                code.paste[0] -= len(literal)
                text = literal                      # a name given a literal string: its text
            else:
                name = f"{prefix}{len(holes)}"
                holes.append(text)
                if quote != "'" and shell and shell[-1].endswith("\\") and (
                        len(shell[-1]) - len(shell[-1].rstrip("\\"))) % 2:
                    shell[-1] = shell[-1][:-1]      # a backslash before it escapes only its first character
                shell.append({"'": f"'${{{name}}}'", '"': f'"${{{name}}}"'}.get(quote, f"${{{name}}}"))
                continue
        shell.append(text)
        escaped = False
        for ch in text:
            if escaped:
                escaped = False
            elif ch == "\\" and quote != "'":
                escaped = True
            elif quote:
                if ch == quote:
                    quote = ""
            elif ch in "'\"":
                quote = ch
    probe = af.Reading()
    sub_ctx = af._Context(list(ctx.programs), ctx.packages, ctx.flags, {}, True, set(), probe,
                          depth=ctx.depth + 1, loose=True, prose=False)
    af._read_text("".join(shell), sub_ctx)
    for fid in probe.unknown:
        probe.unknown[fid] = {f"{code.family}: {af._fact_text(expr.shown)}": None}
    ctx.reading.merge(probe)


# -- argument lists
def _split_args(code: _Code, first: int, last: int) -> list:
    """The comma-separated parts of tokens first..last at one bracket depth: [(a, b)]."""
    out: list = []
    toks = code.toks
    if not code.spend(last - first + 1):
        return []
    k = first
    start = first
    while k <= last:
        t = toks[k]
        if t.kind == "op" and t.text in ("(", "[", "{") and code.close[k] > 0:
            k = code.close[k] + 1
            continue
        if t.kind == "op" and t.text == ",":
            if start <= k - 1:
                out.append((start, k - 1))
            start = k + 1
        k += 1
    if start <= last:
        out.append((start, last))
    return [(a, b) for a, b in out if not all(toks[x].kind == "nl" for x in range(a, b + 1))]


def _strip_nl(code: _Code, a: int, b: int) -> tuple[int, int]:
    while a <= b and code.toks[a].kind == "nl":
        a += 1
    while b >= a and code.toks[b].kind == "nl":
        b -= 1
    return a, b


def _inside(code: _Code, a: int, b: int) -> list:
    """The warned options a value the checker does not work out holds a literal of, whole, reversed or in any
    case (`os.environ.get('F', '--yolo')`, `'--YOLO'.lower()`, `cond && '--yolo'`): each is a start the value
    could have."""
    out: list = []
    texts = [code.toks[x].text.casefold() for x in range(a, b + 1) if code.toks[x].kind == "str"]
    if not texts:
        return out
    for flag in code.ctx.flags:
        for option in flag["options"]:
            o = option.casefold()
            if len(o) > 2 and any(o in t or o[::-1] in t for t in texts):
                out.append(option)
                break
    return out


def _unknown(shown: str, many: bool, prefix: str = "", code: _Code | None = None, a: int = 0, b: int = -1) -> object:
    if many:
        return af.Word(text="\x00", shown=shown, splits=True)
    candidates = [prefix] + (_inside(code, a, b) if code is not None else [])
    return af.Word(text="\x03v\x03", shown=shown, quoted=True, candidates=candidates)


def _ends(code: _Code, suffix: str) -> list:
    """The warned options a value could be, given the literal text it is known to end with (four
    characters or more: `x + '-skip-permissions'`)."""
    low = suffix.casefold()
    if not low:
        return []
    return [option for flag in code.ctx.flags for option in flag["options"] if option.casefold().endswith(low) and (
        len(low) >= 4 or option.casefold().lstrip("-") == low)]


def _expr_words(code: _Code, expr: Expr, shown: str, joined: bool) -> list:
    literal = _literal(expr.parts)
    if literal is not None:
        return [af.Word(text=w, shown=w) for w in literal.split()] if joined else [af.Word(text=literal, shown=shown)]
    if any(h == PASTED for h, _t in expr.parts) or joined:
        return [_unknown(shown, True)]
    known = "".join("\x03h\x03" if h else txt for h, txt in expr.parts)
    prefix = ""
    for h, txt in expr.parts:
        if h:
            break
        prefix += txt
    suffix = expr.parts[-1][1] if not expr.parts[-1][0] else ""
    return [af.Word(text=known, shown=shown, quoted=True,
                    candidates=[prefix] + _ends(code, suffix.split()[-1] if suffix.split() else "")
                    + _inside(code, expr.first, expr.last))]


def _word(code: _Code, a: int, b: int, in_list: bool, callee: str, depth: int = 0, joined: bool = False,
          listy: bool = False) -> list:
    """The words one argument stands for: a list of `agent_flags.Word`; one whose text is not known is
    marked `quoted` (one word) or `splits` (any number of words). `joined`: the list is joined into one
    string that a shell or a splitter reads, so a value there can be several words."""
    toks = code.toks
    a, b = _strip_nl(code, a, b)
    if a > b:
        return []
    t = toks[a]
    shown = code.src(a, b)
    fam = code.family
    if depth > 20:
        return [_unknown(shown, True)]
    words: list = []
    # A keyword argument, an option object, a hash pair: not the program's words, unless it names them.
    if a + 1 <= b and t.kind == "name" and toks[a + 1].kind == "op" and toks[a + 1].text in ("=", ":") and not (
            a + 2 <= b and toks[a + 2].text in ("=", ":")) and not in_list:
        if t.text.lower() in _ARG_KEYS:
            return _word(code, a + 2, b, False, callee, depth + 1, joined)
        return []
    if t.kind == "op" and t.text == "{" and code.close[a] == b:
        # An options object: its `args` (`new Deno.Command('claude', {args: flags})`) are the words.
        for x, y in _split_args(code, a + 1, b - 1):
            x, y = _strip_nl(code, x, y)
            key = toks[x] if x <= y else None
            if key is not None and x + 1 <= y and toks[x + 1].text in (":", "=>", "=") and (
                    key.text.lower().strip("'\"") in _ARG_KEYS):
                words.extend(_word(code, x + 2, y, False, callee, depth + 1, joined))
        return words
    if any(toks[x].kind == "op" and toks[x].text == "=>" for x in range(a, b + 1)) and fam in ("ruby", "php"):
        return []
    # A value pasted into the code's text, a splat or a spread.
    if any(toks[x].sigil == "pasted" for x in range(a, b + 1)):
        return [_unknown(shown, True)]
    if t.kind == "op" and t.text in ("*", "...") and a + 1 == b and toks[b].kind == "name":
        value = _value_at(code, toks[b].text, b)
        if value is not None and toks[value[0]].text == "[" and code.close[value[0]] == value[1]:
            return _word(code, b, b, False, callee, depth + 1, joined, listy=True)     # `[...common]`, `*c`
    if t.kind == "op" and t.text in ("*", "**", "...", "&"):
        return [_unknown(shown, True)]
    if t.kind == "name" and t.sigil in ("@", "%") and fam in ("perl", "pwsh"):
        return [_unknown(shown, True)]
    if t.kind == "op" and t.text == "@" and fam in ("perl", "pwsh") and not (fam == "pwsh" and a + 1 <= b and toks[
            a + 1].text == "("):
        return [_unknown(shown, True)]
    # A list given here: its elements.
    opener = a + 1 if (fam == "pwsh" and t.text == "@" and a + 1 <= b and toks[a + 1].text == "(") else a
    if toks[opener].kind == "op" and toks[opener].text in ("[", "(") and code.close[opener] > 0 and (
            toks[opener].text == "[" or fam in ("perl", "pwsh") or opener != a):
        close = code.close[opener]
        if any(toks[x].kind == "name" and toks[x].text == "for" and code.parent[x] == opener
               for x in range(opener + 1, close)):
            return [_unknown(shown, True)]          # a comprehension: its words are not known
        for x, y in _split_args(code, opener + 1, close - 1):
            words.extend(_word(code, x, y, True, callee, depth + 1, joined))
        if close < b and not (toks[close + 1].text == "." and close + 2 <= b and toks[close + 2].text.lower() in (
                "filter", "slice", "copy", "freeze")):
            words.append(_unknown(shown, True))     # `[...] + flags`, `[...].concat(x)`
        return words
    expr = code.expr_at.get(a)
    if expr is not None and expr.last == b:
        return _expr_words(code, expr, shown, joined)
    if t.kind == "op" and t.text == "(" and code.close[a] == b:
        return _word(code, a + 1, b - 1, in_list, callee, depth + 1, joined)     # brackets round a value
    if t.kind == "num" and a == b:
        return [af.Word(text=t.text, shown=shown)]
    # A name: what it was last given, where that is a string or a list the code does not change.
    if a == b and t.kind == "name":
        value = _value_at(code, t.text, a)
        if value is not None:
            va, vb = value
            sub = code.expr_at.get(va)
            if sub is not None and sub.last == vb:
                return _expr_words(code, sub, shown, joined)
            vo = va + 1 if (fam == "pwsh" and toks[va].text == "@") else va
            if toks[vo].kind == "op" and toks[vo].text in ("[", "(") and code.close[vo] == vb and (
                    toks[vo].text == "[" or fam in ("perl", "pwsh")):
                words = _word(code, va, vb, False, callee, depth + 1, joined)
                if not _changed(code, t.text, va - 2, a):
                    return words
                # Changed: read where each change adds words it can read (`args.push('--verbose')`).
                for u in _uses(code, t.text, va - 2):
                    if va - 2 < u < a and _changes(code, u):
                        added = _change_words(code, u, va - 2)
                        if added is None:
                            return [_unknown(shown, True)]
                        words = words + added
                return words
    # Another value: one word or a list, as the language gives it here (`listy`: a place that takes a list).
    many = joined or listy
    if not in_list:
        if fam in ("js", "php", "other", "lua"):
            many = True
        elif fam == "python":
            many = many or bool(_PY_LIST_CALL_RE.search(callee))
        elif fam == "perl":
            many = many or not (t.kind == "name" and t.sigil == "$")
    elif fam == "perl":
        many = many or not (t.kind == "name" and t.sigil == "$" and a == b)
    return [_unknown(shown, many, "", code, a, b)]


def _argv(code: _Code, first: int, last: int) -> None:
    """The program named at tokens first..last as an element of an argument list or a call's argument:
    the words after it are read as its words."""
    toks = code.toks
    parent = code.parent[first]
    if parent >= 0 and toks[parent].text in ("(", "["):
        close = code.close[parent]
        if close < 0:
            code.cannot_tell(code.src(first, len(toks) - 1))
            return
        callee = code.callee(parent)
        words_list = toks[parent].sigil == "words"
        is_list = toks[parent].text == "[" or (code.family in ("perl", "python") and not callee and not (
            parent >= 1 and toks[parent - 1].kind in ("name", "str") or (parent >= 1 and toks[parent - 1].text in (
                ")", "]")))) or (
            callee in ("array", "list", "tuple", "qw")) or (
            code.family == "pwsh" and parent >= 1 and toks[parent - 1].text == "@")
        if toks[parent].text == "[" and not words_list and parent >= 1 and toks[parent - 1].kind == "name" and toks[
                parent - 1].text.lower() not in _VALUE_KEYWORDS and toks[parent - 1].text.lower() not in _RUNNER_CALLS \
                and code.family != "perl":
            return          # an index (`argv["claude"]`), not a list
        if callee in _OUTPUT_CALLS and not is_list:
            return
        args = _split_args(code, last + 1, close - 1)
        if is_list:
            holder0 = code.parent[parent]
            earlier = _split_args(code, parent + 1, first - 1) + (
                _split_args(code, holder0 + 1, parent - 1) if holder0 >= 0 and toks[holder0].text == "(" else [])
            for a, b in earlier:
                lit = code.expr_at.get(a)
                if lit is not None and lit.last == b and af._base((_literal(lit.parts) or "").strip()) in (
                        "echo", "printf", "which", "type", "grep", "test", "command"):
                    return              # `['echo', 'claude', *flags]`: the program's name is data there
        # The program's own argument must end where a comma or the bracket does.
        if args and args[0][0] == last + 1:
            if not (toks[last + 1].kind == "op" and toks[last + 1].text == ","):
                return
        # Joined into one string (`" ".join([...])`, `[...].join(" ")`, `join(" ", ...)`, `implode`): a shell
        # or a splitter reads it, so a value there can be several words.
        joined = callee in _JOINS or (close + 2 < len(toks) and toks[close + 1].text == "." and toks[
            close + 2].text.lower() in _JOINS)
        holder = code.parent[parent] if is_list else -1
        if is_list and holder >= 0 and toks[holder].text == "(" and code.callee(holder) in _JOINS:
            joined = True
        if joined:
            # A joined list is a command line only where it is given to a call that runs one.
            start = _call_start(code, holder) if (is_list and holder >= 0 and code.callee(holder) in _JOINS) else (
                _call_start(code, parent) if callee in _JOINS else parent)
            if not _reaches_runner(code, start):
                return
        # Node's `{shell: true}` joins the program and its arguments into one shell command line.
        if not is_list and any(_shell_option(code, a, b) for a, b in args):
            joined = True
        words: list = []
        for a, b in args:
            words.extend(_word(code, a, b, is_list, callee, joined=joined))
        if not is_list and not _is_runner(code, parent) and code.family in ("js", "php", "lua", "other"):
            # The program as an argument of a call that does not run one (`core.group('claude', fn)`,
            # `path.resolve(dir, 'claude', name)`): only literal options are read there.
            words = [w for w in words if not w.computed]
        if is_list:
            after = toks[close + 1] if close + 1 < len(toks) else None
            before = toks[parent - 1] if parent >= 1 else None
            if after is not None and after.kind == "op" and after.text == "+" and close + 2 < len(toks) and toks[
                    close + 2].text == "[" and code.close[close + 2] > 0:
                # `[...] + ['--output-format', 'json']`: the other list's words.
                other = code.close[close + 2]
                words.extend(_word(code, close + 2, other, False, callee, joined=joined))
                if other + 1 < len(toks) and toks[other + 1].kind == "op" and toks[other + 1].text in _EXTENDS_AFTER:
                    words.append(af.Word(text="\x00", shown=code.src(parent, other + 2), splits=True))
            elif after is not None and after.kind == "op" and after.text in _EXTENDS_AFTER and not (
                    after.text == "[" or (after.text == "." and close + 2 < len(toks) and toks[close + 2].text.lower() in (
                        "join", "filter", "slice", "copy", "freeze"))):
                words.append(af.Word(text="\x00", shown=code.src(parent, close + 2), splits=True))
            if before is not None and ((before.kind == "op" and before.text == "+") or (
                    before.kind == "name" and before.text.lower() in _EXTENDS_BEFORE)):
                words.append(af.Word(text="\x00", shown=code.src(parent - 1, close), splits=True))
            if holder >= 0 and toks[holder].text == "(" and code.callee(holder) in _MUTATORS | _EXTENDS_BEFORE:
                words.append(af.Word(text="\x00", shown=code.src(holder - 1, code.close[holder]), splits=True))
            if code.family in ("perl", "ruby") and holder >= 0 and toks[holder].text == "(" and not (
                    code.callee(holder) in _JOINS):
                # Perl and Ruby flatten a list given among a call's arguments (`system(qw(claude -p), @ARGV)`).
                for a, b in _split_args(code, close + 1, code.close[holder] - 1):
                    words.extend(_word(code, a, b, False, code.callee(holder)))
            _note_list(code, parent - 1 if (code.family == "pwsh" and toks[parent - 1].text == "@") else parent)
        _read_words(code, words)
        return
    # A call without brackets (`system "claude", *args`, `exec 'claude', @flags`): the words after a comma,
    # to the end of the statement.
    before = toks[first - 1] if first >= 1 else None
    after = toks[last + 1] if last + 1 < len(toks) else None
    if before is None or before.kind != "name" or after is None or after.text != ",":
        return
    callee = before.text.lower()
    if callee in _OUTPUT_CALLS:
        return
    end = last + 1
    while end + 1 < len(toks):
        nxt = toks[end + 1]
        if code.parent[end + 1] != parent and not (nxt.kind == "op" and nxt.text in ("(", "[", "{")):
            end += 1
            continue
        if nxt.kind == "nl" or (nxt.kind == "op" and nxt.text in (";", "}", ")", "]")) or (
                nxt.kind == "name" and nxt.text in ("if", "unless", "or", "and", "do")):
            break
        end += 1
    words = []
    for a, b in _split_args(code, last + 2, end):
        words.extend(_word(code, a, b, False, callee, joined=callee in _JOINS))
    _read_words(code, words)


def _is_runner(code: _Code, open_index: int) -> bool:
    """Whether the call at `open_index` runs a command: by its name, or by a name given one
    (`const run = cp.spawnSync; run(...)`)."""
    callee = code.callee(open_index)
    if callee in _RUNNER_CALLS:
        return True
    value = _value_at(code, code.toks[open_index - 1].text, open_index) if callee else None
    if value is not None:
        last = code.toks[value[1]]
        return last.kind == "name" and last.text.lower() in _RUNNER_CALLS
    return False


def _shell_option(code: _Code, a: int, b: int) -> bool:
    """Whether an argument is an options object with `shell` set to anything but `false`."""
    toks = code.toks
    a, b = _strip_nl(code, a, b)
    if not (a <= b and toks[a].text == "{" and code.close[a] == b):
        return False
    for x, y in _split_args(code, a + 1, b - 1):
        x, y = _strip_nl(code, x, y)
        if x <= y and toks[x].text.strip("'\"") == "shell" and (x == y or not (
                x + 2 <= y and toks[x + 2].text in ("false", "undefined", "null"))):
            return True
    return False


def _read_words(code: _Code, words: list) -> None:
    words = [w if isinstance(w, af.Word) else af.Word(text=w, shown=w) for w in words]
    probe = af.Reading()
    sub = af._Context(list(code.ctx.programs), code.ctx.packages, code.ctx.flags, {}, True, set(), probe,
                      depth=code.ctx.depth + 1, loose=True)
    af._read_program_args(words, sub)
    for fid, ws in probe.unknown.items():
        probe.unknown[fid] = {f"{code.family}: {af._fact_text(w)}": None for w in ws}
    code.ctx.reading.merge(probe)


# -- names that hold a list with the program in it
def _assigned_name(code: _Code, k: int) -> str | None:
    """The name a value that starts at token `k` is given (`cmd = [`, `my @cmd = (`, `$cmd = [`,
    `const cmd = [`, `cmd: list[str] = [`, `cmd = list([`), or None."""
    toks = code.toks
    if k >= 2 and toks[k - 1].kind == "op" and toks[k - 1].text in ("=", ":="):
        if toks[k - 2].kind == "name":
            return toks[k - 2].text
        # An annotation: walk back over `: type` to the name.
        j = k - 2
        while j >= 0 and toks[j].kind != "nl":
            if toks[j].kind == "op" and toks[j].text in (")", "]", "}"):
                j = next((o for o in range(j - 1, -1, -1) if code.close[o] == j), j) - 1
                continue
            if toks[j].kind == "op" and toks[j].text == ":" and j >= 1 and toks[j - 1].kind == "name":
                return toks[j - 1].text
            j -= 1
        return None
    p = code.parent[k]
    if p >= 0 and toks[p].text == "(" and code.callee(p) in _LIST_WRAPPERS and k == p + 1:
        return _assigned_name(code, _call_start(code, p))
    return None


def _uses(code: _Code, name: str, skip: int) -> list:
    """The tokens that name `name` as a value (not a key, not the assignment at `skip`); an attribute
    (`self.cmd`) counts where the name was given as one."""
    if code.names is None:
        code.names = {}
        for k, t in enumerate(code.toks):
            if t.kind == "name":
                code.names.setdefault(t.text, []).append(k)
    cache = code.__dict__.setdefault("_uses_cache", {})
    if (name, skip) in cache:
        return cache[(name, skip)]
    out: list = []
    toks = code.toks
    attribute = skip >= 1 and toks[skip - 1].kind == "op" and toks[skip - 1].text in (".", "->", "::", "?.")
    for k in code.names.get(name, ()):
        if k == skip:
            continue
        if not attribute and k >= 1 and toks[k - 1].kind == "op" and toks[k - 1].text in (".", "->", "::", "?.") and not (
                code.family in ("perl", "php") and toks[k - 1].text == "." and toks[k].sigil):
            continue
        if k + 1 < len(toks) and toks[k + 1].kind == "op" and toks[k + 1].text == ":" and code.family in (
                "js", "ruby", "php") and not (k >= 1 and toks[k - 1].text == "?"):
            continue        # a key in an object literal or a keyword argument
        out.append(k)
    cache[(name, skip)] = out
    return out


def _note_list(code: _Code, open_index: int) -> None:
    """A list that holds the program, given a name: where the code changes, joins or spreads that name, the
    words it adds are not known."""
    name = _assigned_name(code, open_index)
    if name is not None:
        at = next((k for k, a, _b in code.values.get(name, ()) if a <= open_index), None)
        entry = (name, at if at is not None else open_index - 2)
        if entry not in code.held:
            code.held.append(entry)


# Methods and functions that change a list in place, or give one joined with more.
_MUTATORS = frozenset({"append", "extend", "insert", "push", "unshift", "concat", "splice", "add", "prepend",
                       "__iadd__", "__add__", "update", "fill", "replace", "sub", "gsub", "format", "apply",
                       "array_push", "array_unshift", "array_splice", "array_merge", "setdefault"})


def _changes(code: _Code, k: int) -> bool:
    """Whether the list held by the name at token `k` is changed, joined or spread there."""
    toks = code.toks
    before = toks[k - 1] if k >= 1 else None
    after = toks[k + 1] if k + 1 < len(toks) else None
    p = code.parent[k]
    if p >= 0 and toks[p].text == "(" and code.callee(p) in _OUTPUT_CALLS:
        return False                        # logged: `console.log(...args)`, `print(*cmd)`
    if before is not None and before.kind == "op" and before.text in ("*", "...") and p >= 0 and toks[
            p].text in ("(", "[") and (_is_runner(code, p) if toks[p].text == "(" else False) and after is not None and (
                after.text in (")", ",")):
        return False                        # the list given whole to the runner (`system(*c)`): read there
    if after is not None and after.kind == "op":
        if after.text in (".", "->", "?."):
            method = toks[k + 2] if k + 2 < len(toks) else None
            return method is not None and method.kind == "name" and method.text.lower() in _MUTATORS
        if after.text == "[":
            # An index read (`cmd[0]`) changes nothing; an assignment to one (`cmd[1:1] = flags`) does.
            close = code.close[k + 1]
            nxt = toks[close + 1] if close > 0 and close + 1 < len(toks) else None
            return nxt is not None and nxt.kind == "op" and nxt.text in ("=", "+=", ".=")
        if after.text in _EXTENDS_AFTER:
            return True
    if before is not None:
        if before.kind == "op" and before.text in ("*", "**", "...", "+", "@", "."):
            return not (before.text == "." and code.family not in ("perl", "php"))
        if before.kind == "name" and before.text.lower() in _EXTENDS_BEFORE:
            return True
    p = code.parent[k]
    if p >= 0 and toks[p].text == "(" and code.callee(p) in _OUTPUT_CALLS:
        return False                        # logged: `console.log(...args)`, `print(*cmd)`
    if p >= 0 and toks[p].text == "(" and code.callee(p) in _MUTATORS | _EXTENDS_BEFORE and (
            k == p + 1 or (k == p + 2 and toks[p + 1].text == "\\")):
        return True                         # `push(@c, ...)`, `array_push($a, ...)`, `splice(@c, ...)`
    return False


def _changed(code: _Code, name: str, at: int, until: int) -> bool:
    """Whether the list a name was given at `at` is changed before `until` (the changes worked out once)."""
    cache = code.__dict__.setdefault("_changes_cache", {})
    if (name, at) not in cache:
        cache[(name, at)] = [u for u in _uses(code, name, at) if u > at and _changes(code, u)]
    changes = cache[(name, at)]
    n = bisect.bisect_right(changes, at)
    return n < len(changes) and changes[n] < until


def _change_words(code: _Code, k: int, at: int = -1) -> list | None:
    """The words a change at token `k` adds to a held list, where it adds literal ones or values in a list's
    places (`cmd.append('--verbose')`, `args.push('--model', m)`, `cmd += ['--model', m]`); None where they
    are not known."""
    toks = code.toks
    after = toks[k + 1] if k + 1 < len(toks) else None
    if after is None or after.kind != "op":
        return None
    if after.text in (".", "->") and k + 3 < len(toks) and toks[k + 2].text.lower() in (
            "append", "push", "extend", "concat", "insert", "unshift") and toks[k + 3].text == "(":
        close = code.close[k + 3]
        args = _split_args(code, k + 4, close - 1) if close > 0 else None
        if args is None:
            return None
        if toks[k + 2].text.lower() == "insert" and args:
            args = args[1:]                     # `cmd.insert(1, x)`: the index is not a word
        whole = toks[k + 2].text.lower() in ("extend", "concat")
        return _loop_guard(code, k, at, [_strip_nl(code, a, b) for a, b in args], not whole, whole)
    if after.text == "+" and k + 2 < len(toks) and toks[k + 2].text == "[" and code.close[k + 2] > 0 and not (
            code.close[k + 2] + 1 < len(toks) and toks[code.close[k + 2] + 1].kind == "op" and toks[
                code.close[k + 2] + 1].text in _EXTENDS_AFTER):
        return _word(code, k + 2, code.close[k + 2], False, "")       # `cmd + ['--output-format', 'json']`
    if after.text in ("+=", "<<") and k + 2 < len(toks):
        end = code._operand_end(k + 2)
        modifier = end >= 0 and end + 1 < len(toks) and code.family == "ruby" and toks[end + 1].kind == "name" and \
            toks[end + 1].text in ("if", "unless")         # `args << '--verbose' if v`
        if end < 0 or not (_statement_end(code, end + 1) or modifier):
            return None
        if after.text == "+=" and toks[k + 2].text == "[" and code.close[k + 2] == end:
            # `cmd += ['--allowedTools', t]`: the list's own places.
            return _loop_guard(code, k, at, _split_args(code, k + 3, end - 1), True, False)
        return _loop_guard(code, k, at, [(k + 2, end)], after.text == "<<", after.text == "+=")
    return None


def _loop_guard(code: _Code, k: int, at: int, pieces: list, in_list: bool, listy: bool) -> list | None:
    """The words a change at token `k` adds, one piece at a time; None where a piece is a value of a loop
    over what the checker cannot read (`for f in extra: cmd.append(f)`, `extra[i]`), added on its own rather
    than as the value of an option the same change adds before it (`cmd += ['--allowedTools', t]`): such a
    value, added once for each turn, is any number of words."""
    toks = code.toks
    loops = _loop_names(code)
    # A loop over literal strings: the change adds its words once for each string, in turn (`for m in ['plan',
    # 'bypassPermissions']: cmd += ['--permission-mode', m]`).
    literal = next((toks[a].text for a, b in pieces if a == b and toks[a].kind == "name" and loops.get(
        toks[a].text) is not None), None)
    if literal is not None:
        turns: list = []
        for value in loops[literal][:_SITE_LIMIT]:
            for a, b in pieces:
                if a == b and toks[a].kind == "name" and toks[a].text == literal:
                    turns.append(af.Word(text=value, shown=value))
                else:
                    turns.extend(_word(code, a, b, in_list, "", listy=listy))
        return turns
    loop = _in_loop(code, k)
    repeated = loop is not None and (at < 0 or _in_loop(code, at) != loop)
    words: list = []
    for a, b in pieces:
        names = [toks[x].text for x in range(a, b + 1) if toks[x].kind == "name" and toks[x].text in loops]
        unknown_loop = any(loops[n] is None for n in names)
        if repeated and a <= b and toks[a].kind == "name" and toks[a].text not in loops and toks[a].text not in (
                code.values):
            unknown_loop = True                 # a name the code never gives a value, in a repeated change: a
                                                # callback's parameter (`extra.forEach(f => args.push(f))`)
        if unknown_loop and (repeated or loop is None):
            after_option = bool(words) and not words[-1].computed and words[-1].text.startswith("-")
            if not after_option:
                return None
        words.extend(_word(code, a, b, in_list, "", listy=listy))
    return words


_LOOP_CALLS = frozenset({"foreach", "each", "map", "flatmap", "flat_map", "times", "each_with_index", "upto",
                         "downto", "for_each", "reduce", "filter", "every", "some", "array_map", "array_walk"})


def _in_loop(code: _Code, k: int):
    """The loop token `k` is inside, or None: a callback given to `forEach`, `each`, `map` and the like (its
    bracket), a block after `for (...)` or `while (...)` (its brace), or, in Python and Ruby, the `for`,
    `while` or `... do` line it is indented under (that line's first token)."""
    toks = code.toks
    p = code.parent[k]
    while p >= 0:
        if toks[p].text == "(" and code.callee(p) in _LOOP_CALLS:
            return ("bracket", p)
        if toks[p].text == "{" and p >= 1 and toks[p - 1].text == ")":
            opener = next((o for o in range(p - 2, -1, -1) if code.close[o] == p - 1), -1)
            if opener >= 1 and toks[opener - 1].kind == "name" and toks[opener - 1].text in ("for", "while", "foreach"):
                return ("bracket", p)
        if toks[p].text == "{" and p >= 1 and toks[p - 1].kind == "name" and code.callee(p) in _LOOP_CALLS:
            return ("bracket", p)                 # Ruby's `extra.each { |f| ... }`
        p = code.parent[p]
    if code.family in ("python", "ruby"):
        lines = _loop_lines(code)
        n = bisect.bisect_right(lines[0], k) - 1
        loop = lines[1][n] if n >= 0 else None
        return ("line", loop) if loop is not None else None
    return None


def _loop_lines(code: _Code) -> tuple:
    """For Python and Ruby, worked out once: the first token of each logical line (after a line end the
    tokenizer keeps, so not inside a string or brackets), and the loop line each is indented under."""
    if "_loop_lines" in code.__dict__:
        return code.__dict__["_loop_lines"]
    toks, text = code.toks, code.text
    starts = [0] + [k + 1 for k, t in enumerate(toks) if t.kind == "nl" and k + 1 < len(toks)]
    loops: list = []
    stack: list = []            # (indent, the first token of a loop line or None)
    for k in starts:
        if k >= len(toks) or toks[k].kind == "nl":
            loops.append(stack[-1][1] if stack and stack[-1][1] is not None else _nearest(stack))
            continue
        line_start = text.rfind("\n", 0, toks[k].start) + 1
        indent = toks[k].start - line_start
        while stack and stack[-1][0] >= indent:
            stack.pop()
        loops.append(_nearest(stack))
        line = text[toks[k].start:text.find("\n", toks[k].start) if "\n" in text[toks[k].start:] else len(text)]
        is_loop = bool(re.match(r"(for|while|until)\b", line) or re.search(r"\b(each|times|map)\b.*\bdo\b", line))
        stack.append((indent, k if is_loop else None))
    code.__dict__["_loop_lines"] = (starts, loops)
    return code.__dict__["_loop_lines"]


def _nearest(stack: list):
    for _indent, loop in reversed(stack):
        if loop is not None:
            return loop
    return None


def _loop_names(code: _Code) -> dict:
    """The names a loop gives its values to (`for a in ...`, `for (const a of ...)`, `|a|`, `foreach $a`):
    name -> the strings every loop that names it goes over, where each goes over a list of literal strings
    (`for t in ['Read', 'Edit']`), else None."""
    if "_loops" not in code.__dict__:
        names: dict = {}
        toks = code.toks

        def literal_list(j: int) -> list | None:
            """The strings of a list of literal strings that starts at token `j`, or None."""
            if j < len(toks) and toks[j].text in ("[", "(") and code.close[j] > j:
                parts = [_strip_nl(code, x, y) for x, y in _split_args(code, j + 1, code.close[j] - 1)]
                if parts and all(a == b and toks[a].kind == "str" and _literal(toks[a].parts) is not None
                                 for a, b in parts):
                    return [_literal(toks[a].parts) for a, _b in parts]
            return None

        def record(name: str, values: list | None) -> None:
            if name in names and (names[name] is None or values is None):
                names[name] = None
            else:
                names[name] = (names.get(name) or []) + values if values is not None else None
        for k, t in enumerate(toks):
            if t.kind == "name" and t.text in ("for", "foreach", "each", "map") and k + 1 < len(toks):
                for j in range(k + 1, min(k + 6, len(toks))):
                    if toks[j].kind == "name" and toks[j].text not in ("const", "let", "var", "my", "our", "local",
                                                                          "each", "do"):
                        over = j + 2 if j + 1 < len(toks) and toks[j + 1].text in ("in", "of") else -1
                        record(toks[j].text, literal_list(over) if over > 0 else None)
                        break
            if t.kind == "op" and t.text == "|" and k + 2 < len(toks) and toks[k + 1].kind == "name" and toks[
                    k + 2].text in ("|", ","):
                # A Ruby block's `|a|`, over a literal list where `[...].each do |a|` or `%w[...].each { |a|`.
                opener = k - 1 if k >= 1 and toks[k - 1].text in ("{", "do") else -1
                known = None
                if opener >= 3 and toks[opener - 1].text == "each" and toks[opener - 2].text == "." and toks[
                        opener - 3].text == "]":
                    start = next((o for o in range(opener - 4, -1, -1) if code.close[o] == opener - 3), -1)
                    known = literal_list(start) if start >= 0 else None
                record(toks[k + 1].text, known)
        code.__dict__["_loops"] = names
    return code.__dict__["_loops"]


def _held_lists(code: _Code) -> None:
    toks = code.toks
    seen: set = set()
    queue = list(code.held)
    while queue:
        name, at = queue.pop(0)
        if (name, at) in seen or len(seen) > _SITE_LIMIT:
            continue
        seen.add((name, at))
        stop = _next_assignment(code, name, at)
        # The list's own words after the program, to read each literal change with (an option added in one
        # change and its value in the next: `cmd.append('--permission-mode'); cmd.append(mode)`).
        own: list = []
        value = next(((a, b) for kk, a, b in code.values.get(name, ()) if kk == at), None)
        if value is not None and toks[value[0]].text == "[":
            listed = _word(code, value[0], value[1], False, "")
            start = next((n for n, w in enumerate(listed) if not w.computed and (
                af._base(w.text) in code.ctx.programs or af._is_package(w.text, code.ctx.packages))), None)
            own = listed[start + 1:] if start is not None else []
        added_all: list = []
        for k in _uses(code, name, at):
            if not (at < k < stop):
                continue
            p = code.parent[k]
            if p >= 0 and toks[p].text == "(" and code.callee(p) in _OUTPUT_CALLS:
                continue                        # logged (`print('+', *cmd)`, `console.log(...cmd)`)
            if code.family in ("perl", "ruby") and k >= 1 and toks[k - 1].kind == "name" and toks[
                    k - 1].text.lower() in _RUNNER_CALLS and k + 1 < len(toks) and toks[k + 1].text == ",":
                words = []
                stop_at = k + 1
                while stop_at + 1 < len(toks) and not _statement_end(code, stop_at + 1):
                    stop_at += 1
                for a, b in _split_args(code, k + 2, stop_at):
                    words.extend(_word(code, a, b, False, toks[k - 1].text.lower()))
                _read_words(code, words)            # `exec @c, @ARGV;`
                continue
            if p >= 0 and toks[p].text == "(" and _is_runner(code, p) and k + 1 < len(toks) and toks[
                    k + 1].text == "," and code.family in ("perl", "ruby"):
                # Perl and Ruby flatten a list given among a runner's arguments (`system(@c, @ARGV)`).
                words: list = []
                for a, b in _split_args(code, k + 2, code.close[p] - 1):
                    words.extend(_word(code, a, b, False, code.callee(p)))
                _read_words(code, words)
                continue
            if (p >= 0 and toks[p].text == "(" and code.callee(p) in _JOINS) or (
                    k + 2 < len(toks) and toks[k + 1].text == "." and toks[k + 2].text.lower() in _JOINS):
                # Joined into a command line (`os.system(" ".join(cmd))`): its values are words.
                start = _call_start(code, p) if (p >= 0 and code.callee(p) in _JOINS) else k
                value = _value_at(code, name, k)
                if value is not None and _reaches_runner(code, start):
                    if any(w.computed for w in _word(code, value[0], value[1], False, "", joined=True)):
                        code.cannot_tell(code.src(max(k - 1, 0), min(k + 3, len(toks) - 1)))
                        return
                continue
            if _changes(code, k):
                added = _change_words(code, k, at)
                if added is not None:
                    added_all.extend(added)
                    continue
                code.cannot_tell(code.src(max(k - 1, 0), min(k + 3, len(toks) - 1)))
                return
            # A copy (`full = cmd`, `full = cmd[:]`, `full = cmd.copy()`, `full = list(cmd)`) is held too.
            start = k
            if code.parent[k] >= 0 and toks[code.parent[k]].text == "(" and code.callee(code.parent[k]) in _LIST_WRAPPERS:
                start = _call_start(code, code.parent[k])
            other = _assigned_name(code, start)
            if other is not None and other != name:
                queue.append((other, start - 2))
        if added_all:
            _read_words(code, own + added_all)


# ------------------------------------------------------------------------------------- pwsh and cmd
_CMD_VARIABLE_RE = re.compile(r"%[^%\s]+%|%[*~0-9]|%%\w|![^!\s]+!")


def _ps_words(line: str, family: str, stop: list | None = None) -> list:
    """A PowerShell or cmd line split into words: (text as the shell reads it, how it was written: "plain",
    "single", "double", "group", "op"). Quotes (straight and, in PowerShell, curly), PowerShell's backtick
    escapes, and groups `(...)`, `@(...)`, `$(...)`, `{...}` are one word; `;`, `|`, `&&`, `||`, a lone `&`
    in cmd, and redirections are operators."""
    out: list = []
    i, n = 0, len(line)
    ps = family == "pwsh"
    while i < n:
        c = line[i]
        if c.isspace():
            i += 1
            continue
        if c in ";|" or line.startswith(("&&", "||"), i) or (not ps and c in "&()") or (ps and c in "{}"):
            op = line[i:i + 2] if line.startswith(("&&", "||"), i) else c
            out.append((op, "op"))
            i += len(op)
            continue
        if ps and line.startswith("<#", i):
            # A comment block, `<# ... #>`, ends at its `#>`; one that does not end on the line ends it (2d.27a, from
            # its review: `claude <# note #> -p x` was cut at the `#`).
            close = line.find("#>", i + 2)
            if close < 0:
                if stop is not None:
                    stop.append(i)      # where the line's code ends (`_logical_lines`)
                break
            i = close + 2
            continue
        if ps and c == "#" and (i == 0 or line[i - 1].isspace()):
            if stop is not None:
                stop.append(i)
            break
        if ps and (c == "(" or line.startswith(("@(", "$(", "@{"), i)):
            j = i + (2 if c in "@$" else 1)
            opener = line[j - 1]
            depth = 1
            while j < n and depth:
                if line[j] == opener:
                    depth += 1
                elif line[j] == _OPEN[opener]:
                    depth -= 1
                j += 1
            out.append((line[i:j], "group"))
            i = j
            continue
        m = re.compile(r"[0-9*]?>>?(?:&[0-9])?|<").match(line, i)
        if m and (i == 0 or line[i - 1].isspace() or not ps):
            out.append((m.group(0), "redirect"))
            i = m.end()
            continue
        # A word: runs of plain text and quoted text joined. Its kind says where a variable is: outside quotes
        # ("plain"), inside double quotes ("double"), or nowhere it is read ("single").
        text, kind = [], "plain"
        unquoted, in_double = [], []
        while i < n and not line[i].isspace() and not (line[i] in ";|" or (not ps and line[i] in "&<>()") or (
                ps and line[i] in "{}")):
            ch = line[i]
            quote = _PS_QUOTES.get(ch) if ps else ('"' if ch == '"' else None)
            if quote:
                closers = [q for q, k in _PS_QUOTES.items() if k == quote] if ps else ['"']
                j = i + 1
                buf = []
                while j < n and line[j] not in closers:
                    if ps and quote == '"' and line[j] == "`" and j + 1 < n:
                        buf.append(line[j + 1])
                        j += 2
                        continue
                    buf.append(line[j])
                    j += 1
                text.append("".join(buf))
                if quote == '"':
                    in_double.append("".join(buf))
                i = j + 1
                continue
            if ps and ch == "`" and i + 1 < n:
                text.append(line[i + 1])
                i += 2
                continue
            if ps and line.startswith("${", i):
                found = line.find("}}", i + 3) if line.startswith("${{", i) else line.find("}", i + 2)
                end = n if found < 0 else found + (2 if line.startswith("${{", i) else 1)
                text.append(line[i:end])
                unquoted.append(line[i:end])        # `${env:F}`, a `${{ }}` expression
                i = end
                continue
            text.append(ch)
            unquoted.append(ch)
            i += 1
        var_re = _CMD_VARIABLE_RE if not ps else re.compile(r"\$[\w{(:]|@\w")
        if var_re.search("".join(unquoted)) or "${{" in "".join(unquoted):
            kind = "plain"
        elif any(var_re.search(d) or "${{" in d for d in in_double):
            kind = "double"
        elif unquoted:
            kind = "plain"
        else:
            kind = "single"
        out.append(("".join(text), kind))
    return out


def _logical_lines(text: str, family: str) -> list:
    """Lines with their continuations joined: a backtick at the end in PowerShell, a caret in cmd; and in PowerShell a
    line that ends with a `,` or a `|`, which PowerShell continues on the next (2d.27a, from its review)."""
    mark = "`" if family == "pwsh" else "^"
    lines = re.sub(re.escape(mark) + r"[ \t]*\r?\n", " ", text).split("\n")
    if family != "pwsh":
        return lines
    # Only where the `,` or `|` is the line's last word, outside a comment and a string: a comment ends its line
    # and carries nothing on (the second review: `# install it,` joined the next line into the comment). Each line is
    # split into words once, so this stays linear.
    # A carried line's comment is left out, so that the next line is joined to its code, not into the comment (the third
    # review: `Get-Content p | # feed it` lost the next line); the pieces are joined once, so this stays linear.
    out: list = []
    pieces: list | None = None
    for line in lines:
        stop: list = []
        words = _ps_words(line, family, stop)
        carry = bool(words) and (words[-1] == ("|", "op") or words[-1][1] == "plain" and words[-1][0].endswith(","))
        code = line[:stop[0]] if stop and carry else line
        if pieces is None and not carry:
            out.append(line)
            continue
        if pieces is None:
            pieces = []
        pieces.append(code)
        if not carry:
            out.append(" ".join(pieces))
            pieces = None
    if pieces is not None:
        out.append(" ".join(pieces))
    return out


def _shell_words(raw: str, kind: str, family: str) -> af.Word:
    """A PowerShell or cmd word as an `agent_flags.Word`: a variable or group outside quotes is any number
    of words (an array is passed as several in PowerShell; cmd splits); one inside double quotes is one."""
    if "${{" in raw or re.search("\x02\\d*\x02", raw):
        return [af.Word(text="\x00", shown=raw, splits=True)]      # pasted in before the script runs
    variable = (_CMD_VARIABLE_RE.search(raw) if family == "cmd" else re.search(r"\$[\w{(:]|@\w", raw))
    if kind == "group":
        literal = re.fullmatch(r"@?\(\s*((?:'[^']*'\s*,?\s*)+)\)", raw)
        if literal and family == "pwsh":
            items = re.findall(r"'([^']*)'", literal.group(1))
            return [af.Word(text=x, shown=raw) for x in items]
        return [af.Word(text="\x00", shown=raw, splits=True)]
    if kind == "single" or not variable:
        return [af.Word(text=raw, shown=raw)]
    if family == "cmd":
        return [af.Word(text="\x00", shown=raw, splits=True)]      # expanded as text before quotes are read
    if kind == "plain" and re.fullmatch(r"\$env:\w+|\$\{env:\w+\}", raw, re.I):
        return [af.Word(text="\x03v\x03", shown=raw, quoted=True, candidates=[""])]   # always one string
    if kind == "double":
        return [af.Word(text="\x03v\x03", shown=raw, quoted=True, candidates=[raw[:variable.start()]])]
    return [af.Word(text="\x00", shown=raw, splits=True)]


def read_shell_lines(text: str, ctx: af._Context, family: str) -> None:
    """PowerShell or cmd: each command that runs the program, read word by word. A variable or group among
    its words outside quotes (`claude @flags`, `claude $flags`, `claude (Get-Content f)`, `claude %F%`) is
    "cannot tell", as an unquoted variable is in bash; one inside double quotes is one word. The program
    counts where a command starts (after `&`, `.`, `call`, an assignment `$x =`), as `Start-Process`'s
    `-FilePath` or first word, and as a name given it (`$exe = 'claude'`, `set C=claude`); a command the
    checker cannot name (`& $exe`, `%C%`) in a script that names the tool is "cannot tell"."""
    # Each name given the program's name (`$exe = 'claude'`, `set C=claude`), with the program's name as `af._base`
    # reads it: the lanes take the command `& $exe ...` runs from it (flagship slice 2d.27a).
    aliases: dict = {}
    # A name given a value that holds the tool's letters anywhere (`$t = 'xcodex'.Substring(1)`,
    # `set X=!CODEXBIN!`): a command the checker cannot name that uses it may be the program (flagship slice
    # 2d.23, from its second review).
    maybe: set = set()
    lines = _logical_lines(text, family)
    for line in lines:
        m = re.match(r"\s*\$([\w:]+)\s*=\s*['\"‘’“”]?([^'\"\s‘’“”]+)", line) \
            if family == "pwsh" else re.match(r'\s*set\s+"?(\w+)=([^"\s&]+)', line, re.I)
        if m and af._base(m.group(2)) in ctx.programs:
            aliases[m.group(1).lower()] = af._base(m.group(2))
        elif m and af.appears(m.group(2), ctx.programs, ctx.packages):
            maybe.add(m.group(1).lower())
        # A loop's variable over values that hold the letters (`for /f %%i in ('where codexcli') do %%i ...`,
        # `foreach ($p in (Get-Command codexcli)) { & $p ... }`).
        # Each is anchored at `for` and reads no bracket inside the list, so it stays linear (the third review: a
        # lazy `.*?` before the variable took cubic time on a line of many `for ... in ( )`).
        loop = re.search(r"\bforeach\s*\(\s*\$(\w+)\s+in\s+(.*)", line, re.I) if family == "pwsh" else re.search(
            r"\bfor(?:\s+/\w+(?:\s+\"[^\"\n]*\")?)*\s+%%?(\w)\s+in\s*\(([^()]*)\)\s*do\b", line, re.I)
        if loop and af.appears(loop.group(2), ctx.programs, ctx.packages):
            maybe.add(loop.group(1).lower())
    # Only a script that names the tool (`names`) makes a command the checker cannot name "cannot tell" (flagship
    # slice 2d.23, #388): the caller's `ctx.mentioned` was `True` wherever the name's letters stood in any word,
    # so `'acne'` and a bracket left open at a line's end (`$x = (`) were "cannot tell" for Continue's `cn`.
    mentioned = ctx.mentioned or af.names(text, ctx.programs, ctx.packages)
    runs = ctx.runs
    for line in lines:
        if family == "cmd" and re.match(r"\s*@?\s*(?::|rem(?:$|[\s.:/\\]))", line, re.I):
            # A label (`:name`, `::`) or a `rem` line runs nothing, `&` and what follows included (2d.27a, from its
            # review).
            continue
        words = _ps_words(line, family)
        segment: list = []
        # In cmd, a bracket inside a command (`echo (claude ...)`, `for %%a in (...)`) is text, not a block; only one
        # where a command starts or after `if`'s condition opens a block. What such a bracket holds is still read, as
        # before, but not given to the lanes (`ctx.runs`; 2d.27a, from its review).
        literal = 0
        for w in words + [(";", "op")]:
            if w[1] == "op":
                _shell_command(segment, ctx, family, aliases, mentioned, maybe)
                head = [x for x in segment if x[0] != "@"]
                if family == "cmd" and w[0] == "(" and (literal or head and head[0][0].lstrip("@").lower() != "if"):
                    literal += 1
                    ctx.runs = None
                elif family == "cmd" and w[0] == ")" and literal:
                    literal -= 1
                    ctx.runs = runs if not literal else None
                elif family == "cmd" and w[0] in ("&", "&&", "||", "|") and literal:
                    # A bracket inside a command's text does not hold the next command (`echo :-( & claude ...`;
                    # the second review).
                    literal = 0
                    ctx.runs = runs
                segment = []
            elif family == "cmd" and w[1] == "plain" and w[0].lower() in ("do", "else"):
                if segment:
                    _shell_command(segment, ctx, family, aliases, mentioned, maybe)    # `for ... do claude %%a`
                segment = []
            else:
                segment.append(w)
        ctx.runs = runs


# PowerShell's own programs, and the options they take a value with, before `-Command` (2d.27a).
_PS_PROGRAMS = frozenset({"pwsh", "pwsh.exe", "powershell", "powershell.exe"})
_PS_VALUE_OPTIONS = ("-executionpolicy", "-ep", "-ex", "-windowstyle", "-w", "-workingdirectory", "-wd",
                     "-configurationname", "-custompipename", "-settingsfile", "-inputformat", "-outputformat",
                     "-version", "-psconsolefile")
_PS_EXPRESSIONS = frozenset({"iex", "invoke-expression"})


def _cmd_command_at(words: list, j: int) -> int | None:
    """Where the command line of `cmd [options] /c ...` or `/k` begins, after any number of options (`/d /s /c`,
    `/e:on /c`, `/s/c`; GitHub's own `shell: cmd` runs `cmd /D /E:ON /V:OFF /S /C`); None when no `/c` or `/k` comes
    before a word that is not an option (2d.27a, from its review)."""
    while j < len(words) and words[j][1] == "plain" and words[j][0].startswith("/"):
        if re.search(r"/[ck]$", words[j][0], re.I):
            return j + 1 if j + 1 < len(words) else None
        j += 1
    return None


def _ps_command_at(words: list, i: int) -> int | None:
    """Where the command PowerShell is given begins: after `pwsh` or `powershell` and their options up to `-Command`
    (any start of it, `-c`), or after `iex` or `Invoke-Expression` given one string; None for anything else, a
    `-File` among the options included (a script file, which is not read)."""
    low = words[i][0].lower()
    if low in _PS_EXPRESSIONS:
        rest = words[i + 1:]
        if len(rest) == 1 and rest[0][1] in ("single", "double") and not re.search(r"\$[\w{(]", rest[0][0]):
            return i + 1
        return None
    if af._base(words[i][0]) not in ("pwsh", "powershell") and low not in _PS_PROGRAMS:
        return None
    j = i + 1
    while j < len(words) and words[j][1] == "plain" and words[j][0].startswith("-"):
        option = words[j][0].lower()
        if "-command".startswith(option) and len(option) > 1:
            return j + 1 if j + 1 < len(words) else None
        if "-file".startswith(option) and len(option) > 2 or option == "-f":
            return None
        j += 2 if any(o.startswith(option) and len(option) > 2 or o == option for o in _PS_VALUE_OPTIONS) else 1
    return None


def _used_names(raw: str, ps: bool) -> set:
    """The variables a PowerShell or cmd word puts in (`$t`, `${env:X}`, `%C:~1%`, `!X!`), in lower case."""
    found = re.findall(r"\$\{?([\w:]+)", raw) if ps else (
        re.findall(r"[%!](\w+)(?::[^%!]*)?[%!]", raw) + re.findall(r"%%?~?\w*?(\w)(?![\w%])", raw))
    return {name.lower() for name in found}


def _shell_command(words: list, ctx: af._Context, family: str, aliases: dict, mentioned: bool,
                   maybe: set = frozenset()) -> None:
    ps = family == "pwsh"
    i = 0
    if ps and len(words) >= 2 and words[0][0].startswith("$") and words[1][0] in ("=", "+=") and words[0][1] == "plain":
        i = 2                               # `$out = claude -p x`
    while i < len(words) and words[i][1] == "plain" and words[i][0].lower() in (("&", ".") if ps else ("@", "call")):
        i += 1
    while not ps and i < len(words) and words[i][0].lower() == "if":
        # `if [not] [/i] (exist X | defined X | errorlevel N | A==B | A op B) command`, any number of times
        # (`if a==a if b==b claude ...`; flagship slice 2d.27a, from its review)
        i += 1
        while i < len(words) and words[i][0].lower() in ("not", "/i"):
            i += 1
        if i < len(words) and words[i][0].lower() in ("exist", "defined", "errorlevel", "cmdextversion"):
            i += 2
        elif i < len(words) and "==" in words[i][0]:
            i += 1
        else:
            i += 3
    if not ps and i < len(words) and words[i][0].startswith("@") and words[i][1] == "plain":
        words = words[:i] + [(words[i][0][1:], "plain")] + words[i + 1:]
    if i < len(words) and words[i][1] == "plain":
        low = words[i][0].lower()
        if not ps and low == "start":
            # `start [/wait] ["title"] program ...`; `/d`, `/node` and `/affinity` take the next word as their value
            # when it is not joined to them (`start /d C:\w claude ...`; 2d.27a, from its review).
            i += 1
            while i < len(words) and (words[i][0].startswith("/") or words[i][1] in ("double", "single") and (
                    i + 1 < len(words))):
                if words[i][1] in ("double", "single") and af._base(words[i][0]) in ctx.programs:
                    break
                i += 2 if words[i][0].lower() in ("/d", "/node", "/affinity") else 1
        elif low in ("cmd", "cmd.exe") and _cmd_command_at(words, i + 1) is not None:
            rest = words[_cmd_command_at(words, i + 1):]
            if ctx.depth > af._MAX_DEPTH:
                ctx.cannot_tell("nesting deeper than the checker reads: " + af._fact_text(" ".join(w[0] for w in rest)))
                return
            ctx.depth += 1
            try:
                if len(rest) == 1 and rest[0][1] in ("double", "single"):
                    read_shell_lines(rest[0][0], ctx, "cmd")
                else:
                    _shell_command(rest, ctx, "cmd", aliases, mentioned, maybe)
            finally:
                ctx.depth -= 1
            return
        elif _ps_command_at(words, i) is not None:
            # `pwsh -NoProfile -Command "claude ..."`, `powershell -c ...`, and PowerShell's `iex 'claude ...'` or
            # `Invoke-Expression "claude ..."` given the command line as one string: read as PowerShell, in the same
            # reading (2d.27a, from its review: the lanes and this reader did not enter them).
            rest = words[_ps_command_at(words, i):]
            if ctx.depth > af._MAX_DEPTH:
                ctx.cannot_tell("nesting deeper than the checker reads: " + af._fact_text(" ".join(w[0] for w in rest)))
                return
            ctx.depth += 1
            try:
                if len(rest) == 1 and rest[0][1] in ("double", "single"):
                    read_shell_lines(rest[0][0], ctx, "pwsh")
                elif rest and all(k != "group" for _w, k in rest):
                    _shell_command(rest, ctx, "pwsh", aliases, mentioned, maybe)
            finally:
                ctx.depth -= 1
            if not ps or low not in _PS_EXPRESSIONS:
                return
        elif low in ("bash", "sh") and i + 2 < len(words) and words[i + 1][0] == "-c":
            # The script's own `mentioned`, not `True` (2d.23): `bash -c '$X --y'` is "cannot tell" only in a
            # script that names the tool; bash's own readers still test a command word and `IFS=` for the letters.
            probe = af._Context(list(ctx.programs), ctx.packages, ctx.flags, {}, mentioned, set(), ctx.reading,
                                depth=ctx.depth + 1, loose=True)
            af._read_text(words[i + 2][0], probe)
            return
        elif low in ("npx", "bunx", "pnpx", "pnpm", "yarn"):
            j = i + 1
            while j < len(words) and words[j][0].startswith("-"):
                j += 2 if words[j][0] in ("-p", "--package") else 1
            if j < len(words) and (af._is_package(words[j][0], ctx.packages) or af._base(words[j][0]) in ctx.programs):
                i = j
    if i >= len(words):
        return
    raw, kind = words[i]
    name = raw.lower()
    program = af._base(raw) in ctx.programs or af._is_package(raw, ctx.packages)
    # The program's name as the lanes are given it (flagship slice 2d.27a): a package as written, a program as
    # `af._base` reads it (no folder, no `.exe`, in lower case), and a name's program for a name given one.
    runs = (raw.casefold() if af._is_package(raw, ctx.packages) else af._base(raw)) if program else None
    if ps and kind in ("single", "double") and not (i > 0 and words[i - 1][0] in ("&", ".")):
        # A quoted word that no `&` or `.` calls is a string to PowerShell, not a command (`$a = 'claude'`,
        # `'claude' + ' -p x'`): the lanes are not given it (2d.27a). OBAAF-GHA-026's own reading is unchanged.
        runs = None
    if ps and kind == "plain" and raw.startswith("$") and raw[1:].lower() in aliases:
        program = True
        # A variable PowerShell calls only after `&` or `.` (`& $exe ...`); in a command's place without them it is a
        # value (`$y = $x + ' -p x'`), which the lanes are not given (2d.27a, from its review).
        if i > 0 and words[i - 1][0] in ("&", "."):
            runs = runs or aliases[raw[1:].lower()]
    if not ps and kind == "plain" and re.fullmatch(r"%(\w+)%|!(\w+)!", raw):
        var = re.fullmatch(r"%(\w+)%|!(\w+)!", raw)
        if (var.group(1) or var.group(2)).lower() in aliases:
            program = True
            runs = runs or aliases[(var.group(1) or var.group(2)).lower()]
    rest = words[i + 1:]
    if not program:
        # A command the checker cannot name is "cannot tell" in a script that names the tool, where its own word
        # holds the tool's letters, as the bash reader has it (`& $claudeExe`, `%CLAUDEEXE%`,
        # `& ('xclaude'.Substring(1))`), or where it uses a name given such a value (`maybe`; flagship slice 2d.23,
        # from its reviews).
        held = mentioned or af.appears(raw, ctx.programs, ctx.packages) or bool(_used_names(raw, ps) & maybe)
        if name in ("start-process", "saps", "start") and ps:
            _start_process(rest, ctx, held or af.appears(" ".join(w[0] for w in rest), ctx.programs, ctx.packages)
                           or any(_used_names(w[0], ps) & maybe for w in rest))
        elif held and (
                kind == "group" or (ps and raw.startswith("$") and i > 0 and words[i - 1][0] in ("&", "."))
                or (not ps and _CMD_VARIABLE_RE.search(raw) and kind == "plain")):
            for flag in ctx.flags:
                if flag["id"] not in ctx.reading.hits:
                    ctx.reading.cannot_tell(flag, af._fact_text(" ".join(w[0] for w in words)))
        return
    args: list = []
    skip = False
    stop_parsing = False
    for raw2, kind2 in rest:
        if skip:
            skip = False
            continue
        if kind2 == "redirect":
            # The next word is the target, unless the redirection holds it (`2>&1`, `*>&1`, `3>&1`; 2d.27a, from its
            # review: the word after `2>&1` was dropped, an option with it).
            skip = not re.search(r"&[0-9]$", raw2)
            continue
        if ps and raw2 == "--%" and kind2 == "plain":
            stop_parsing = True             # the rest as written, with `%VAR%` put in as cmd does
            continue
        if stop_parsing:
            args.append(af.Word(text="\x00", shown=raw2, splits=True) if _CMD_VARIABLE_RE.search(raw2) else
                        af.Word(text=raw2, shown=raw2))
            continue
        args.extend(_shell_words(raw2, kind2, family))
    _ran(ctx, runs, args)
    _read_shell_args(args, ctx, family, words)


def _start_process(rest: list, ctx: af._Context, mentioned: bool) -> None:
    """`Start-Process claude -ArgumentList ...`, `Start-Process -FilePath claude -ArgumentList $a`."""
    file_path, arguments, positional = None, None, []
    switches = ("-wait", "-nonewwindow", "-passthru", "-usenewenvironment", "-loaduserprofile", "-whatif",
                "-confirm")
    # A parameter given its value after a colon (`-FilePath:claude`, `-ArgumentList:'-p'`) is read as one given it
    # after a space (flagship slice 2d.25, from its review).
    split: list = []
    for raw, kind in rest:
        head, colon, tail = raw.partition(":")
        if kind == "plain" and colon and head.startswith("-") and len(head) > 1 and tail and (
                "-filepath".startswith(head.lower()) or "-argumentlist".startswith(head.lower())
                or head.lower() in ("-args", "-arguments")):
            split += [(head, "plain"), (tail, "single")]
        else:
            split.append((raw, kind))
    rest = split
    j = 0
    while j < len(rest):
        raw, kind = rest[j]
        low = raw.lower()
        if kind == "plain" and low.startswith("-") and any(sw.startswith(low) and len(low) > 2 for sw in switches):
            j += 1
            continue
        if kind == "plain" and low.startswith("-") and j + 1 < len(rest):
            # `-Path` and `-PSPath` are `-FilePath`'s aliases, and `-A` is the only start of a parameter's name that is
            # `-ArgumentList`'s alone (2d.27a, from its review).
            if "-filepath".startswith(low) and len(low) > 1 or low in ("-path", "-pspath"):
                file_path = rest[j + 1]
                j += 2
                continue
            if low in ("-argumentlist", "-args", "-arguments") or "-argumentlist".startswith(low) and len(low) > 1:
                # A list written with commas (`-ArgumentList '-p', $p`, `'-p' , 'x'`) runs over several words, a comma
                # standing alone or at either end of one.
                items = [rest[j + 1]]
                j += 2
                while j < len(rest) and (items[-1][0].endswith(",") or rest[j][0].startswith(",")):
                    if rest[j][0] != ",":
                        items.append((rest[j][0].lstrip(","), rest[j][1]) if rest[j][1] == "plain" else rest[j])
                    elif j + 1 < len(rest):
                        items.append(rest[j + 1])
                        j += 1
                    j += 1
                arguments = [item for item in items if item[0] not in ("", ",")]
                continue
            j += 2
            continue
        if kind == "plain" and raw.startswith("@") and mentioned:
            for flag in ctx.flags:
                if flag["id"] not in ctx.reading.hits:
                    ctx.reading.cannot_tell(flag, "Start-Process " + raw)      # a splatted table of parameters
        positional.append(rest[j])
        j += 1
    if file_path is None and positional:
        file_path, positional = positional[0], positional[1:]
    if arguments is None and positional:
        arguments = [positional[0]]
    if file_path is None or not (af._base(file_path[0]) in ctx.programs or af._is_package(file_path[0], ctx.packages)):
        return
    if arguments is None:
        return
    # Start-Process joins its arguments into one command line: a variable anywhere in them is any words.
    words: list = []
    for raw, kind in arguments:
        raw = raw.rstrip(",")
        if kind != "single" and re.search(r"\$[\w{(]|@\w", raw) or kind == "group":
            words.append(af.Word(text="\x00", shown=raw, splits=True))
        else:
            words.extend(af.Word(text=w, shown=w) for part in raw.split(",") for w in part.split())
    program = file_path[0]
    _ran(ctx, program.casefold() if af._is_package(program, ctx.packages) else af._base(program), words)
    _read_shell_args(words, ctx, "pwsh", [file_path] + list(arguments))


def _ran(ctx: af._Context, program: str | None, args: list) -> None:
    """Note, for `program_lines`, the command line a command runs where the reader has named its program: the
    program's name, then each argument as the shell gives it (a word the checker cannot read as it was written)."""
    if program is not None and ctx.runs is not None:
        # A `;`, `&`, `|` or line break inside one argument (`--allowedTools "Bash(npm test)|Read"`) is that argument's
        # text, not a separator: it is written `_` here, so that the agent patterns read past it (2d.27a, its review).
        words = [w.shown if "\x00" in w.text or "\x03" in w.text else w.text for w in args if not w.redirect]
        ctx.runs.append(" ".join([program] + [re.sub(r"[;&|\r\n]", "_", w) for w in words]))


def cmd_carets_out(text: str) -> str:
    """A cmd script as its programs see it: a caret at a line's end continues the line, and any other is taken out
    (`claude ^--yolo`; slice 2d.5c2c and its review)."""
    return re.sub(r"\^[ \t]*\r?\n", " ", text).replace("^", "")


def program_lines(text: str, family: str, programs: list, packages: list) -> list:
    """The command lines a PowerShell or cmd script runs one of `programs` or `packages` with, where OBAAF-GHA-026's
    reader of those shells (`read_shell_lines`) names the program (flagship slice 2d.27a, #420): the program's name
    (no folder, no `.exe`, in lower case; a package as written), then its arguments as the shell gives them. The
    lanes match the catalogue's agent patterns against these, so that a job is an agent job wherever this reader
    finds the program run: `& “claude” ...`, `claude.exe ...`, `C:\\tools\\claude.exe ...`, cmd's `^claude ...`,
    `Start-Process -WorkingDirectory C:\\w claude ...`, `$a = 'claude'; & $a ...`, `set BIN=claude` and `%BIN% ...`.
    What the reader cannot name (a group, a subexpression, a method's result, a splat, a loop's variable) gives
    nothing here; OBAAF-GHA-026 makes it "cannot tell". Nothing where the script does not hold the letters of one of
    them (`af.appears`), the common case, kept cheap."""
    if not text or family not in ("pwsh", "cmd"):
        return []
    programs = [p.casefold() for p in programs]
    packages = [p.casefold() for p in packages]
    if family == "cmd":
        # A caret before an operator makes it text (`echo a ^& claude ...` echoes), so the operator is kept out of
        # the reading; every other caret is taken out (2d.27a, from its review).
        text = re.sub(r"\^[ \t]*\r?\n", " ", text).replace("^^", "\ue001")
        text = re.sub(r"\^[&|<>()]", "\ue000", text).replace("^", "").replace("\ue001", "^")
    if not af.appears(text, programs, packages):
        return []
    ctx = af._Context(programs, packages, [], {}, False, set(), af.Reading(), loose=True, runs=[])
    read_shell_lines(text, ctx, family)
    return ctx.runs


def _read_shell_args(args: list, ctx: af._Context, family: str, words: list) -> None:
    probe = af.Reading()
    sub = af._Context(list(ctx.programs), ctx.packages, ctx.flags, {}, True, set(), probe, depth=ctx.depth + 1,
                      loose=True)
    af._read_program_args(args, sub)
    line = " ".join(w[0] for w in words)
    for fid in probe.unknown:
        probe.unknown[fid] = {af._fact_text(line): None}
    ctx.reading.merge(probe)


def read_cmd(text: str, ctx: af._Context) -> None:
    read_shell_lines(text, ctx, "cmd")


def read_language(text: str, language: str, ctx: af._Context) -> None:
    """A script in another language or shell (a step's `shell`, `github-script`): code by its tokens,
    and in PowerShell, cmd and shells the checker does not know, each line that runs the program with a
    variable after it."""
    fam = family_of(language)
    if fam in ("python", "js", "ruby", "perl", "php", "awk", "lua"):
        read_code(text, fam, ctx)
    elif fam == "pwsh":
        read_code(text, fam, ctx)
        read_shell_lines(text, ctx, fam)
    elif fam == "cmd":
        read_shell_lines(text, ctx, fam)
    else:
        _other_shell(text, ctx)


def _other_shell(text: str, ctx: af._Context) -> None:
    """A shell the checker does not know (`zsh`, `fish`): a line that starts with the program and has a
    variable or splat outside quotes among its words is "cannot tell", as in 2d.5c2a."""
    for line in text.split("\n"):
        words = line.strip().split()
        first = words[0].strip("&'\"") if words else ""
        if af._base(first) in ctx.programs and re.search(r"(?<!\S)(?:[@$%]\w|\$\{|\$\()|%\w+%", line):
            for flag in ctx.flags:
                if flag["id"] not in ctx.reading.hits:
                    ctx.reading.cannot_tell(flag, af._fact_text(line.strip()))
