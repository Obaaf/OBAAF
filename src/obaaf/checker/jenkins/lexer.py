"""Tokenizer for the Groovy subset that Jenkins pipelines use.

It reads text only. Nothing is compiled, evaluated or loaded: Groovy compilation can
run code (AST transforms, static initializers, Grab), so OBAAF never hands a Jenkinsfile
to Groovy to analyze it (Jenkins design, section 5). Strings keep their interpolated
expressions as text, which is what the rules need to see what reaches a shell.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

MAX_BYTES = 1_048_576       # 1 MiB per file (design, section 5)
MAX_TOKENS = 400_000
DEADLINE_SECONDS = 10.0     # per file, lexing and parsing together


class LexError(ValueError):
    def __init__(self, message: str, line: int, col: int):
        super().__init__(f"line {line}: {message}")
        self.line, self.col = line, col


class LimitExceeded(LexError):
    """A resource ceiling was reached: the file is reported as not analyzed, never as clean."""


@dataclass(frozen=True)
class Tok:
    kind: str                   # ident, num, str, op, nl, eof
    value: str
    line: int
    col: int
    quote: str = ""             # for strings: ' " ''' """ / $/
    parts: tuple = ()           # for strings: (("lit", text) | ("expr", text), ...)

    @property
    def interpolated(self) -> bool:
        return any(kind == "expr" for kind, _ in self.parts)

    def literal(self) -> str:
        """The string's text with interpolations shown as ${...}."""
        return "".join(text if kind == "lit" else "${" + text + "}" for kind, text in self.parts)


OPERATORS = sorted("""
>>>= <<= >>= **= ..< ... ?. *. .& .@ === !== == != <= >= <=> && || ++ -- += -= *= /= %= &= |= ^= -> ?: << >> >>> ** ==~ =~ !=~ .. ::
{ } ( ) [ ] , ; : . ? + - * / % < > = ! & | ^ ~ @
""".split(), key=len, reverse=True)
_OPS_BY_FIRST: dict = {}
for _op in OPERATORS:
    _OPS_BY_FIRST.setdefault(_op[0], []).append(_op)     # longest first, as in OPERATORS

# After these tokens a '/' starts a slashy string (a regular expression); otherwise it divides.
_SLASHY_AFTER_OPS = {"(", "[", ",", "=", "==", "!=", "=~", "==~", "~", ":", "?", "&&", "||", "!", "{", ";",
                     "+", "-", "*", "<<", "->", "?:", "+=", "-=", "in"}
_SLASHY_AFTER_WORDS = {"return", "in", "case", "assert", "else"}
_IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_$")
_IDENT_PART = _IDENT_START | set("0123456789")
_IDENT_RUN = re.compile(r"[A-Za-z0-9_$]*")
_STRING_SPECIAL = set("\\$\n")
_ORDINARY_RUN = re.compile(r"[^\\$\n]*")


class Lexer:
    def __init__(self, text: str, deadline: float | None = None):
        if len(text.encode("utf-8", errors="replace")) > MAX_BYTES:
            raise LimitExceeded(f"file exceeds {MAX_BYTES} bytes", 1, 1)
        self.src = text
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: list[Tok] = []
        self.brackets: list[str] = []
        self.deadline = deadline or (time.monotonic() + DEADLINE_SECONDS)

    # -- helpers -------------------------------------------------------------------
    def _peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        return self.src[i] if i < len(self.src) else ""

    def _advance(self, n: int = 1) -> str:
        out = self.src[self.pos:self.pos + n]
        newlines = out.count("\n")
        if newlines:
            self.line += newlines
            self.col = len(out) - out.rfind("\n")
        else:
            self.col += len(out)
        self.pos += n
        return out

    def _emit(self, kind: str, value: str, line: int, col: int, **extra) -> None:
        if len(self.tokens) >= MAX_TOKENS:
            raise LimitExceeded(f"file exceeds {MAX_TOKENS} tokens", line, col)
        self.tokens.append(Tok(kind, value, line, col, **extra))

    def _last(self) -> Tok | None:
        return self.tokens[-1] if self.tokens else None

    def _slashy_allowed(self) -> bool:
        prev = self._last()
        if prev is None or prev.kind == "nl":
            return True
        if prev.kind == "op":
            return prev.value in _SLASHY_AFTER_OPS
        if prev.kind == "ident":
            return prev.value in _SLASHY_AFTER_WORDS
        return False

    # -- main loop -------------------------------------------------------------------
    def run(self) -> list[Tok]:
        src = self.src
        if src.startswith("#!"):
            while self.pos < len(src) and src[self.pos] != "\n":
                self._advance()
        checks = 0
        while self.pos < len(src):
            checks += 1
            if checks % 2048 == 0 and time.monotonic() > self.deadline:
                raise LimitExceeded(f"analysis exceeded {DEADLINE_SECONDS:.0f} seconds", self.line, self.col)
            ch = src[self.pos]
            if ch == "\n":
                # Consume the whole run of blank space at once, so input made of many blank
                # lines stays linear, then decide whether the statement continues.
                line, col = self.line, self.col
                end = self.pos
                while end < len(src) and src[end] in " \t\r\n\f":
                    end += 1
                self._advance(end - self.pos)
                if self.brackets and self.brackets[-1] in "([":
                    continue
                if self._continues_on_next_line():
                    continue
                last = self._last()
                if last is not None and last.kind != "nl":
                    self._emit("nl", "\n", line, col)
                continue
            if ch in " \t\r\f﻿":
                self._advance()
                continue
            if ch == "\\" and self._peek(1) == "\n":
                self._advance(2)
                continue
            if src.startswith("//", self.pos):
                while self.pos < len(src) and src[self.pos] != "\n":
                    self._advance()
                continue
            if src.startswith("/*", self.pos):
                line, col = self.line, self.col
                end = src.find("*/", self.pos + 2)
                if end < 0:
                    raise LexError("unterminated comment", line, col)
                self._advance(end + 2 - self.pos)
                continue
            if src.startswith("'''", self.pos) or src.startswith('"""', self.pos):
                self._triple(src[self.pos:self.pos + 3])
                continue
            if ch in "'\"":
                self._quoted(ch)
                continue
            if src.startswith("$/", self.pos):
                self._dollar_slashy()
                continue
            if ch == "/" and self._slashy_allowed() and self._peek(1) not in ("", " ", "=", "/", "*"):
                self._slashy()
                continue
            if ch in _IDENT_START:
                line, col = self.line, self.col
                start = self.pos
                end = _IDENT_RUN.match(src, start).end()
                self._advance(end - start)
                self._emit("ident", src[start:self.pos], line, col)
                continue
            if ch.isdigit():
                self._number()
                continue
            for op in _OPS_BY_FIRST.get(ch, ()):
                if src.startswith(op, self.pos):
                    line, col = self.line, self.col
                    self._advance(len(op))
                    if op in "([{":
                        self.brackets.append(op)
                    elif op in ")]}":
                        if self.brackets:
                            self.brackets.pop()
                    self._emit("op", op, line, col)
                    break
            else:
                # Characters Groovy does not use outside strings (for example a stray backtick).
                line, col = self.line, self.col
                self._advance()
                self._emit("op", ch, line, col)
        self._emit("eof", "", self.line, self.col)
        return self.tokens

    def _continues_on_next_line(self) -> bool:
        """A line starting with `.method` or `?.method` continues the previous expression."""
        j = self.pos
        src = self.src
        while j < len(src) and src[j] in " \t\r\n":
            j += 1
        if src.startswith("?.", j):
            return True
        return j < len(src) and src[j] == "." and not src.startswith("..", j)

    def _number(self) -> None:
        line, col = self.line, self.col
        start = self.pos
        src = self.src
        if src.startswith(("0x", "0X"), self.pos):
            self._advance(2)
            while self.pos < len(src) and (src[self.pos].isalnum() or src[self.pos] == "_"):
                self._advance()
        else:
            while self.pos < len(src) and (src[self.pos].isdigit() or src[self.pos] == "_"):
                self._advance()
            if self._peek() == "." and self._peek(1).isdigit():
                self._advance()
                while self.pos < len(src) and src[self.pos].isdigit():
                    self._advance()
            if self._peek() in ("e", "E") and (self._peek(1).isdigit() or self._peek(1) in "+-"):
                self._advance(2)
                while self.pos < len(src) and src[self.pos].isdigit():
                    self._advance()
            if self._peek() in tuple("gGlLiIdDfF"):
                self._advance()
        self._emit("num", src[start:self.pos], line, col)

    # -- strings -------------------------------------------------------------------------
    def _quoted(self, quote: str) -> None:
        line, col = self.line, self.col
        self._advance()
        parts = self._string_body(quote, interpolate=(quote == '"'), single_line=True, line=line, col=col)
        self._emit("str", "", line, col, quote=quote, parts=parts)

    def _triple(self, quote: str) -> None:
        line, col = self.line, self.col
        self._advance(3)
        parts = self._string_body(quote, interpolate=(quote == '"""'), single_line=False, line=line, col=col)
        self._emit("str", "", line, col, quote=quote, parts=parts)

    def _slashy(self) -> None:
        line, col = self.line, self.col
        self._advance()
        parts = self._string_body("/", interpolate=True, single_line=False, line=line, col=col, slashy=True)
        self._emit("str", "", line, col, quote="/", parts=parts)

    def _dollar_slashy(self) -> None:
        line, col = self.line, self.col
        self._advance(2)
        buf: list[str] = []
        parts: list[tuple[str, str]] = []
        src = self.src
        while True:
            if self.pos >= len(src):
                raise LexError("unterminated dollar-slashy string", line, col)
            if src.startswith("/$", self.pos):
                self._advance(2)
                break
            if src.startswith("$$", self.pos) or src.startswith("$/", self.pos):
                buf.append(self._advance(2)[1])
                continue
            if src[self.pos] == "$" and self._interpolation_starts():
                if buf:
                    parts.append(("lit", "".join(buf)))
                    buf = []
                parts.append(("expr", self._interpolation()))
                continue
            buf.append(self._advance())
        if buf or not parts:
            parts.append(("lit", "".join(buf)))
        self._emit("str", "", line, col, quote="$/", parts=tuple(parts))

    def _interpolation_starts(self) -> bool:
        nxt = self._peek(1)
        return nxt == "{" or (nxt != "" and nxt in _IDENT_START and nxt != "$")

    def _interpolation(self) -> str:
        """Read `${...}` or `$name.path` at the current `$`; return the expression text."""
        src = self.src
        start_line, start_col = self.line, self.col
        self._advance()  # $
        if self._peek() == "{":
            self._advance()
            begin = self.pos
            depth = 1
            while True:
                if self.pos >= len(src):
                    raise LexError("unterminated ${...} in a string", start_line, start_col)
                ch = src[self.pos]
                if src.startswith("'''", self.pos) or src.startswith('"""', self.pos):
                    q = src[self.pos:self.pos + 3]
                    self._advance(3)
                    self._string_body(q, interpolate=(q == '"""'), single_line=False, line=self.line, col=self.col)
                    continue
                if ch in "'\"":
                    self._advance()
                    self._string_body(ch, interpolate=(ch == '"'), single_line=True, line=self.line, col=self.col)
                    continue
                if ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth == 0:
                        text = src[begin:self.pos]
                        self._advance()
                        return text.strip()
                self._advance()
        begin = self.pos
        while self.pos < len(src) and src[self.pos] in _IDENT_PART:
            self._advance()
        while self._peek() == "." and self._peek(1) and self._peek(1) in _IDENT_START and self._peek(1) != "$":
            self._advance()
            while self.pos < len(src) and src[self.pos] in _IDENT_PART:
                self._advance()
        return src[begin:self.pos]

    def _string_body(self, quote: str, *, interpolate: bool, single_line: bool, line: int, col: int,
                     slashy: bool = False) -> tuple:
        src = self.src
        buf: list[str] = []
        parts: list[tuple[str, str]] = []
        while True:
            if time.monotonic() > self.deadline:
                raise LimitExceeded(f"analysis exceeded {DEADLINE_SECONDS:.0f} seconds", line, col)
            if self.pos >= len(src):
                raise LexError("unterminated string", line, col)
            if src.startswith(quote, self.pos):
                self._advance(len(quote))
                break
            ch = src[self.pos]
            if ch not in _STRING_SPECIAL and ch != quote[0]:
                # Copy the run of ordinary characters at once.
                run_end = _ORDINARY_RUN.match(src, self.pos).end()
                stop = src.find(quote[0], self.pos, run_end)
                run_end = run_end if stop == -1 else stop
                buf.append(self._advance(max(run_end - self.pos, 1)))
                continue
            if ch == "\n" and single_line:
                raise LexError("unterminated string", line, col)
            if ch == "\\":
                if slashy:
                    if self._peek(1) == "/":
                        buf.append("/")
                        self._advance(2)
                    else:
                        buf.append(self._advance())
                    continue
                nxt = self._peek(1)
                self._advance(2)
                buf.append({"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f"}.get(nxt, nxt))
                continue
            if interpolate and ch == "$" and self._interpolation_starts():
                if buf:
                    parts.append(("lit", "".join(buf)))
                    buf = []
                parts.append(("expr", self._interpolation()))
                continue
            buf.append(self._advance())
        if buf or not parts:
            parts.append(("lit", "".join(buf)))
        return tuple(parts)


def tokenize(text: str, deadline: float | None = None) -> list[Tok]:
    return Lexer(text, deadline).run()
