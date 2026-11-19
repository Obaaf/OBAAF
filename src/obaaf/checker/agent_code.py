"""Code in another language that runs an agent tool's program (flagship slice 2d.5c2c, OBAAF-GHA-026).

`agent_flags` reads a bash or sh script as bash reads it. Code given to another interpreter (`python3 -c`,
`node -e`, a heredoc fed to `ruby`, `perl -e`, `php -r`, an awk program), a github-script script and a
step whose shell is pwsh, cmd, python or another language are read there only the widest way. This module
reads such code a second time, by its tokens, for what the widest reading cannot see:

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

import re
import unicodedata
from dataclasses import dataclass, field

from obaaf.checker import agent_flags as af

# The language each interpreter or shell is read as.
_FAMILIES = {
    "python": "python", "python2": "python", "python3": "python", "py": "python",
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
    "execasync", "execcommand", "getexecoutput", "create_subprocess_shell", "readpipe", "qx"})
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

    # -- helpers
    def _value_position(self) -> bool:
        prev = next((t for t in reversed(self.toks) if t.kind != "nl"), None) if self.toks else None
        if prev is None or (self.toks and self.toks[-1].kind == "nl"):
            return True
        if prev.kind == "op":
            return prev.text not in (")", "]", "}")
        return prev.kind == "name" and prev.text.lower() in _VALUE_KEYWORDS

    def _skip_balanced(self, i: int, open_: str, close: str) -> int:
        """The index after the `close` that ends a group opened just before `i`, skipping strings."""
        depth, n, text = 1, len(self.text), self.text
        while i < n:
            c = text[i]
            if c == "\\":
                i += 2
                continue
            if c in "'\"`" and open_ != c:
                j = i + 1
                while j < n and text[j] != c:
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
            m = re.compile(r"#(@@?|\$)[A-Za-z_]\w*").match(text, i)
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
                while end < len(text):
                    if text[end] == "[":
                        close = self._skip_balanced(end + 1, "[", "]")
                    elif text[end] == "{" and interp == "pl":
                        close = self._skip_balanced(end + 1, "{", "}")
                    elif text.startswith("->", end):
                        m2 = re.compile(r"->(?:\w+|\[|\{)").match(text, end)
                        if not m2:
                            break
                        if m2.group(0).endswith(("[", "{")):
                            opener = m2.group(0)[-1]
                            close = self._skip_balanced(m2.end(), opener, _OPEN[opener])
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
            if c == "%" and self._value_position():
                m = re.compile(r"%([qQwWiIxrs]?)([^\w\s])").match(text, i)
                if m:
                    kind, opener = m.group(1), m.group(2)
                    close = _OPEN.get(opener, opener)
                    nest = opener if opener in _OPEN else ""
                    single = kind in ("q", "w", "i", "s")
                    return self._finish(m.end(), close, "single" if single else "rb", "" if single else "rb",
                                        start=i, nest=nest, command=kind == "x", words=kind in ("w", "W"))
            if text.startswith("<<", i) and self._value_position():
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
            if c in "qmsty" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] in "_$@%&")):
                m = re.compile(r"(qq|qw|qx|qr|q|m|s|tr|y)\s*([^\w\s=,;)])").match(text, i)
                if m:
                    kind, opener = m.group(1), m.group(2)
                    close = _OPEN.get(opener, opener)
                    nest = opener if opener in _OPEN else ""
                    if kind in ("m", "qr", "s", "tr", "y"):
                        return self._regex_like(i, m.end(), close, nest, two=kind in ("s", "tr", "y"))
                    single = kind in ("q", "qw")
                    return self._finish(m.end(), close, "single" if single else "pl", "" if single else "pl",
                                        start=i, nest=nest, command=kind == "qx", words=kind == "qw")
            if text.startswith("<<", i) and self._value_position():
                m = re.compile(r"<<(~?)(?:(['\"`])([A-Za-z_]\w*)\2|([A-Za-z_]\w*))").match(text, i)
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
                if line.strip() == delimiter or (line.strip().rstrip(";") == delimiter and self.family == "php"):
                    found = True
                    j = (k + 1) if k >= 0 else len(text)
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
                        self.toks.append(Tok("op", "[", i, i))
                        for word in inner.text.split():
                            self.toks.append(Tok("str", word, i, end, [(False, word)]))
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
                parts, end = self._scan(i + 1, "/", "raw", "")
                if end > 0 and "\n" not in text[i:end]:
                    m = re.compile(r"[A-Za-z]*").match(text, end)
                    i = m.end()
                    continue
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
        self.budget = 4_000_000             # tokens the argument readers may visit, beyond which: cannot tell

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
        if t.kind == "op" and t.text in ("(", "[", "{") and self.close[k] > 0:
            end = self.close[k]
        elif t.kind in ("name", "num", "str"):
            end = k
        elif t.kind == "op" and t.text in ("-", "!", "~") and k + 1 < len(toks):
            return self._operand_end(k + 1)
        else:
            return -1
        if t.kind == "str":
            return end          # `"...".format(...)` and `.concat(...)` are read where the string is joined
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
                        and nxt.kind in ("str", "name", "num") or (fam == "awk" and nxt.kind == "op" and nxt.text == "("):
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
                        parts.append((True, self.src(a, b)))
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

    def callee_full(self, open_index: int) -> str:
        k = open_index - 1
        names: list = []
        while k >= 0 and self.toks[k].kind == "name":
            names.append(self.toks[k].text.lower())
            if k >= 1 and self.toks[k - 1].kind == "op" and self.toks[k - 1].text in (".", "->", "::", "?."):
                k -= 2
                continue
            break
        return ".".join(reversed(names))


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
def read_code(text: str, family: str, ctx: af._Context) -> None:
    """Read code in another language that names the tool (see the module's text)."""
    fam = family_of(family)
    if fam == "cmd":
        read_cmd(text, ctx)
        return
    code = _Code(text, fam, ctx)
    if code.problem:
        # Code the tokenizer cannot split (a string that does not end) is "cannot tell", as in bash.
        code.cannot_tell(f"{code.problem}: {text[:80]}")
    # Only code that names the tool in one of its strings or names is read further.
    if not any(t.kind in ("str", "name") and af.mentions(t.text, ctx.programs, ctx.packages) for t in code.toks):
        return
    code.build()
    sites = 0
    aliases = _aliases(code)
    if aliases:
        # A value that is a name given the program (`f"{p} --yolo"`, `p + " --yolo"`) is the program's name.
        for expr in code.exprs:
            expr.parts = _merge([(False, aliases[_bare(t)][0]) if h and _bare(t) in aliases else (h, t)
                                 for h, t in expr.parts])
    for expr in code.exprs:
        literal = _literal(expr.parts)
        joined = "".join("" if h else t for h, t in expr.parts)
        if not af.mentions(joined, ctx.programs, ctx.packages):
            _pieces(code, expr)
            continue
        sites += 1
        if sites > _SITE_LIMIT:
            code.cannot_tell(f"the program named more than {_SITE_LIMIT} times")
            return
        if literal is not None and _is_program(literal, ctx) and expr.pieces == 1:
            _argv(code, expr.first, expr.last)
            continue
        _command_line(code, expr)
    for name, (_literal_text, alone, uses) in aliases.items():
        for k in uses:
            sites += 1
            if sites > _SITE_LIMIT:
                code.cannot_tell(f"the program named more than {_SITE_LIMIT} times")
                return
            if _changes(code, k):
                code.cannot_tell(code.src(max(k - 1, 0), min(k + 3, len(code.toks) - 1)))
            elif alone:
                _argv(code, k, k)
    _held_lists(code)


def _pieces(code: _Code, expr: Expr) -> None:
    """A value joined from pieces that is, or could start, a warned option (`"--" + "yolo"`, `"-" + x`,
    `f"--{x}"`): "cannot tell" for that option where the program's words are not found with it (found with
    them, a literal one is matched there)."""
    if expr.pieces < 2 and not any(h for h, _t in expr.parts):
        return
    known = ""
    for is_hole, text in expr.parts:
        if is_hole:
            break
        known += text
    words = known.split()
    head = words[0] if words else ""
    if not head.startswith("-"):
        return
    has_hole = any(h for h, _t in expr.parts)
    probe = af.Reading()
    af._match_known(words, code.ctx.flags, probe)
    flags = [hit[0] for hit in probe.hits.values()]
    if has_hole and len(words) == 1 and not known[-1:].isspace():
        flags += af._could_start(head, code.ctx.flags)
    for flag in flags:
        if flag["id"] not in code.ctx.reading.hits:
            code.ctx.reading.cannot_tell(flag, f"{code.family}: {af._fact_text(expr.shown)}")


def _command_line(code: _Code, expr: Expr) -> None:
    """A string that names the program and is, or may be, a command line: read as bash, with each value
    the checker cannot read put in as an expansion whose value is not known."""
    ctx = code.ctx
    parent = code.parent[expr.first]
    callee = code.callee(parent) if parent >= 0 and code.toks[parent].text == "(" else ""
    if not callee and expr.first > 0 and code.toks[expr.first - 1].kind == "name":
        callee = code.toks[expr.first - 1].text.lower()         # a call without brackets (`system "..."`)
    holes: list = []
    shell: list = []
    quote = ""
    for is_hole, text in expr.parts:
        if is_hole:
            name = f"{_HOLE_NAME}{len(holes)}"
            holes.append(text)
            shell.append(f"'\"${{{name}}}\"'" if quote == "'" else f"${{{name}}}")
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
    line = "".join(shell)
    plain = re.sub(r"\$\{" + _HOLE_NAME + r"\d+\}", "x", line)
    runs = expr.command or callee in _RUNNER_CALLS or af.starts_program(plain, ctx.programs, ctx.packages)
    if not runs or (callee in _OUTPUT_CALLS and not expr.command):
        return
    probe = af.Reading()
    sub = af._Context(list(ctx.programs), ctx.packages, ctx.flags, {}, True, set(), probe, depth=ctx.depth + 1,
                      loose=True, prose=False)
    af._read_text(line, sub)

    def shown(word: str) -> str:
        return re.sub(r"\$\{" + _HOLE_NAME + r"(\d+)\}", lambda m: "{" + holes[int(m.group(1))] + "}", word)
    for fid, words in probe.unknown.items():
        probe.unknown[fid] = {f"{code.family}: {af._fact_text(shown(w))}": None for w in words}
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


def _word(code: _Code, a: int, b: int, in_list: bool, callee: str, depth: int = 0) -> list:
    """The words one argument stands for: a list of `agent_flags.Word`; one whose text is not known is
    marked `quoted` (one word) or `splits` (any number of words)."""
    toks = code.toks
    a, b = _strip_nl(code, a, b)
    if a > b:
        return []
    t = toks[a]
    shown = code.src(a, b)
    fam = code.family
    if depth > 20:
        return [af.Word(text="\x00", shown=shown, splits=True)]
    # A keyword argument, an option object, a hash pair: not the program's words.
    if a + 1 <= b and t.kind == "name" and toks[a + 1].kind == "op" and toks[a + 1].text in ("=", ":") and not (
            a + 2 <= b and toks[a + 2].text in ("=", ":")) and not in_list:
        return []
    if t.kind == "op" and t.text == "{" and code.close[a] == b:
        return []
    if any(toks[x].kind == "op" and toks[x].text == "=>" for x in range(a, b + 1)) and fam in ("perl", "ruby",
                                                                                                "php"):
        if fam != "perl":
            return []
    # A splat or spread.
    if t.kind == "op" and t.text in ("*", "**", "...", "&"):
        return [af.Word(text="\x00", shown=shown, splits=True)]
    if t.kind == "name" and t.sigil in ("@", "%") and fam in ("perl", "pwsh"):
        return [af.Word(text="\x00", shown=shown, splits=True)]
    if t.kind == "op" and t.text == "@" and fam == "perl":
        return [af.Word(text="\x00", shown=shown, splits=True)]
    # A list given here: its elements.
    if t.kind == "op" and t.text == "[" and code.close[a] > 0:
        close = code.close[a]
        words: list = []
        for x, y in _split_args(code, a + 1, close - 1):
            words.extend(_word(code, x, y, True, callee, depth + 1))
        if close < b:
            words.append(af.Word(text="\x00", shown=shown, splits=True))     # `[...] + flags`, `[...].concat(x)`
        return words
    if fam == "perl" and t.kind == "op" and t.text == "(" and code.close[a] == b:
        words = []
        for x, y in _split_args(code, a + 1, b - 1):
            words.extend(_word(code, x, y, True, callee, depth + 1))
        return words
    expr = code.expr_at.get(a)
    if expr is not None and expr.last == b:
        literal = _literal(expr.parts)
        if literal is not None:
            return [af.Word(text=literal, shown=shown)]
        known = "".join("\x03h\x03" if h else txt for h, txt in expr.parts)
        prefix = ""
        for h, txt in expr.parts:
            if h:
                break
            prefix += txt
        return [af.Word(text=known, shown=shown, quoted=True, candidates=[prefix])]
    if t.kind == "num" and a == b:
        return [af.Word(text=t.text, shown=shown)]
    # Another value: one word or a list, as the language gives it here.
    many = False
    if not in_list:
        if fam in ("js", "php", "other", "lua"):
            many = True
        elif fam == "python":
            many = bool(_PY_LIST_CALL_RE.search(callee))
        elif fam == "perl":
            many = not (t.kind == "name" and t.sigil == "$")
    elif fam == "perl":
        many = not (t.kind == "name" and t.sigil == "$")
    if many:
        return [af.Word(text="\x00", shown=shown, splits=True)]
    return [af.Word(text="\x03v\x03", shown=shown, quoted=True, candidates=[""])]


def _argv(code: _Code, first: int, last: int) -> None:
    """The program named at tokens first..last as an element of an argument list or a call's argument:
    the words after it are read as its words."""
    toks = code.toks
    parent = code.parent[first]
    ctx = code.ctx
    if parent >= 0 and toks[parent].text in ("(", "["):
        close = code.close[parent]
        if close < 0:
            code.cannot_tell(code.src(first, len(toks) - 1))
            return
        is_list = toks[parent].text == "[" or (code.family == "perl" and not code.callee(parent)) or (
            code.callee(parent) in ("array", "list", "tuple", "qw")) or (
            code.family == "pwsh" and parent >= 1 and toks[parent - 1].text == "@")
        callee = code.callee(parent)
        if toks[parent].text == "[" and parent >= 1 and toks[parent - 1].kind == "name" and toks[
                parent - 1].text not in _VALUE_KEYWORDS and code.family != "perl":
            return          # an index (`argv["claude"]`), not a list
        if callee in _OUTPUT_CALLS and not is_list:
            return
        args = _split_args(code, last + 1, close - 1)
        # The program's own argument must end where a comma or the bracket does.
        if args and args[0][0] == last + 1:
            if not (toks[last + 1].kind == "op" and toks[last + 1].text == ","):
                return
        words: list = []
        for a, b in args:
            words.extend(_word(code, a, b, is_list, callee))
        if is_list:
            after = toks[close + 1] if close + 1 < len(toks) else None
            before = toks[parent - 1] if parent >= 1 else None
            if after is not None and after.kind == "op" and after.text in _EXTENDS_AFTER and not (
                    after.text == "[" or (after.text == "." and close + 2 < len(toks) and toks[close + 2].text in (
                        "join",))):
                words.append(af.Word(text="\x00", shown=code.src(parent, close + 2), splits=True))
            if before is not None and ((before.kind == "op" and before.text in ("+", "*", "...")) or (
                    before.kind == "name" and before.text.lower() in _EXTENDS_BEFORE)):
                words.append(af.Word(text="\x00", shown=code.src(parent - 1, close), splits=True))
            if toks[parent].text == "[" or code.family == "perl":
                _note_list(code, parent, close)
            elif code.family == "pwsh" and parent >= 1 and toks[parent - 1].text == "@":
                _note_list(code, parent - 1, close)
        _read_words(code, words)
        return
    # A call without brackets (`system "claude", *args`, `exec 'claude', @flags`) or a list without them
    # (Perl `my @c = "claude", ...` is not one): the words after a comma, to the end of the statement.
    before = toks[first - 1] if first >= 1 else None
    after = toks[last + 1] if last + 1 < len(toks) else None
    if before is None or before.kind != "name" or after is None or after.text != ",":
        return
    callee = before.text.lower()
    if callee in _OUTPUT_CALLS:
        return
    end = last + 1
    depth_parent = parent
    while end + 1 < len(toks):
        nxt = toks[end + 1]
        if code.parent[end + 1] != depth_parent and not (nxt.kind == "op" and nxt.text in ("(", "[", "{")):
            end += 1
            continue
        if nxt.kind == "nl" or (nxt.kind == "op" and nxt.text in (";", "}", ")", "]")) or (
                nxt.kind == "name" and nxt.text in ("if", "unless", "or", "and", "do")):
            break
        end += 1
    words = []
    for a, b in _split_args(code, last + 2, end):
        words.extend(_word(code, a, b, False, callee))
    _read_words(code, words)


def _read_words(code: _Code, words: list) -> None:
    probe = af.Reading()
    sub = af._Context(list(code.ctx.programs), code.ctx.packages, code.ctx.flags, {}, True, set(), probe,
                      depth=code.ctx.depth + 1, loose=True)
    af._read_program_args(words, sub)
    for fid, ws in probe.unknown.items():
        probe.unknown[fid] = {f"{code.family}: {af._fact_text(w)}": None for w in ws}
    code.ctx.reading.merge(probe)


# -- names that hold a list or the program
def _assigned_name(code: _Code, k: int) -> str | None:
    """The name a value that starts at token `k` is given (`cmd = [`, `my @cmd = (`, `$cmd = [`,
    `const cmd = [`), or None."""
    toks = code.toks
    if k >= 2 and toks[k - 1].kind == "op" and toks[k - 1].text in ("=", ":=") and toks[k - 2].kind == "name":
        return toks[k - 2].text
    return None


def _uses(code: _Code, name: str, skip: int) -> list:
    """The tokens that name `name` as a value (not an attribute, not the assignment at `skip`)."""
    if code.names is None:
        code.names = {}
        for k, t in enumerate(code.toks):
            if t.kind == "name":
                code.names.setdefault(t.text, []).append(k)
    out: list = []
    toks = code.toks
    for k in code.names.get(name, ()):
        t = toks[k]
        if k == skip:
            continue
        if k >= 1 and toks[k - 1].kind == "op" and toks[k - 1].text in (".", "->", "::", "?.") and not (
                code.family in ("perl", "php") and toks[k - 1].text == "." and t.sigil):
            continue
        if k + 1 < len(toks) and toks[k + 1].kind == "op" and toks[k + 1].text in (":",) and code.family in (
                "js", "python", "ruby", "php"):
            continue        # a key in an object literal or a keyword argument
        out.append(k)
    return out


def _note_list(code: _Code, open_index: int, close: int) -> None:
    """A list that holds the program, given a name: where the code changes, joins or spreads that name, the
    words it adds are not known."""
    name = _assigned_name(code, open_index)
    if name is not None and (name, open_index - 2) not in code.held:
        code.held.append((name, open_index - 2))


# Methods that change a list or a string in place, or give one joined with more.
_MUTATORS = frozenset({"append", "extend", "insert", "push", "unshift", "concat", "splice", "add", "prepend",
                       "__iadd__", "__add__", "update", "fill", "replace", "sub", "gsub", "format", "join"})


def _changes(code: _Code, k: int) -> bool:
    """Whether the name at token `k` is changed, joined or spread there."""
    toks = code.toks
    before = toks[k - 1] if k >= 1 else None
    after = toks[k + 1] if k + 1 < len(toks) else None
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
    return False


def _held_lists(code: _Code) -> None:
    toks = code.toks
    for name, at in code.held:
        for k in _uses(code, name, at):
            if _changes(code, k):
                code.cannot_tell(code.src(max(k - 1, 0), min(k + 3, len(toks) - 1)))
                return


def _bare(expression: str) -> str:
    """A value's text as a plain name, if it is one (`$p`, `${p}`, `@p`, ` p `), else ""."""
    m = re.fullmatch(r"\s*[$@]?\{?\s*([^\W\d]\w*)\s*\}?\s*", expression)
    return m.group(1) if m else ""


def _aliases(code: _Code) -> dict:
    """Names given a literal string that names the program (`p = "claude"`, `my $p = 'claude';`,
    `cmd = "claude -p x"`): name -> (the literal, whether it is the program alone, the tokens where the name
    is used as a value). Where it is used, a value that is the name alone is that literal; a name given the
    program alone is read as the program there. A name given another value elsewhere is still read so."""
    out: dict = {}
    toks = code.toks
    for expr in code.exprs:
        literal = _literal(expr.parts)
        if literal is None or expr.pieces != 1 or not af.mentions(literal, code.ctx.programs, code.ctx.packages):
            continue
        name = _assigned_name(code, expr.first)
        if name is None:
            continue
        nxt = toks[expr.last + 1] if expr.last + 1 < len(toks) else None
        if nxt is not None and nxt.kind not in ("nl",) and not (nxt.kind == "op" and nxt.text in (";", ",", ")")):
            continue
        uses = []
        for k in _uses(code, name, expr.first - 2):
            if k + 1 < len(toks) and toks[k + 1].kind == "op" and toks[k + 1].text == "=":
                continue
            uses.append(k)
        entry = out.setdefault(name, (literal, _is_program(literal, code.ctx), []))
        entry[2].extend(uses)
    return out


# ------------------------------------------------------------------------------------------------ cmd
_CMD_VARIABLE_RE = re.compile(r"%[^%\s]+%|%[*~0-9]|%%\w|![^!\s]+!")
_PS_VARIABLE_RE = re.compile(r"(?<![\S])[@$]\w|(?<![\S])\$\{|(?<![\S])\$\(")


def read_cmd(text: str, ctx: af._Context) -> None:
    """cmd: a line that runs the program with a variable among its words after it (`%F%`, `!F!`, `%*`,
    `%1`) is "cannot tell"."""
    for line in text.split("\n"):
        low = line.casefold()
        at = _program_position(low, ctx)
        if at is not None and _CMD_VARIABLE_RE.search(line, at):
            for flag in ctx.flags:
                if flag["id"] not in ctx.reading.hits:
                    ctx.reading.cannot_tell(flag, "cmd: " + af._fact_text(line.strip()))


def read_shell_line_variables(text: str, ctx: af._Context, family: str) -> None:
    """In PowerShell or cmd, a line that names the program as a word with a variable or splat outside quotes
    after it (`claude @flags`, `& claude $flags`, `Start-Process claude -ArgumentList $a`, `claude %F%`)
    is "cannot tell", as an unquoted variable is in bash."""
    if family == "cmd":
        read_cmd(text, ctx)
        return
    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        low = line.casefold()
        at = _program_position(low, ctx)
        if at is None:
            continue
        first = stripped.split()[0].casefold().strip("&.'\"")
        if first in ("write-host", "write-output", "write-verbose", "write-debug", "write-information",
                     "echo", "write-warning", "write-error"):
            continue
        rest = line[at:]
        if _PS_VARIABLE_RE.search(rest) or _CMD_VARIABLE_RE.search(rest):
            for flag in ctx.flags:
                if flag["id"] not in ctx.reading.hits:
                    ctx.reading.cannot_tell(flag, af._fact_text(stripped))


def _program_position(low: str, ctx: af._Context) -> int | None:
    """Where, in a line in lower case, the program is named as a word (or its package), or None."""
    best = None
    for name in list(ctx.programs) + list(ctx.packages):
        for m in re.finditer(r"(?<![\w@-])" + re.escape(name) + r"(?:\.exe|\.cmd|\.bat|\.ps1)?(?![\w-])", low):
            if best is None or m.end() < best:
                best = m.end()
            break
    return best


def read_language(text: str, language: str, ctx: af._Context) -> None:
    """A script in another language or shell (a step's `shell`, `github-script`): code by its tokens,
    and in PowerShell, cmd and shells the checker does not know, each line that runs the program with a
    variable after it."""
    fam = family_of(language)
    if fam in ("python", "js", "ruby", "perl", "php", "awk", "lua"):
        read_code(text, fam, ctx)
    elif fam == "pwsh":
        read_code(text, fam, ctx)
        read_shell_line_variables(text, ctx, fam)
    else:
        read_shell_line_variables(text, ctx, fam)
