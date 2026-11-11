"""Reading GitHub Actions expressions (the text inside `${{ }}`).

The rules ask two things of an expression: which secrets it can read, and whether it expands text
an outsider wrote. Both used to be answered by matching patterns against the expression's text,
and a spelling the patterns did not expect was a way past the rule. Here the expression is split
into tokens and the context references are read from them. Whatever the reader cannot pin down
counts as the worst case: a reference to `secrets` that is not one literal name is every secret,
and a wildcard or computed index matches any field.

Nothing is evaluated.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

OPEN, CLOSE = "${{", "}}"
_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUMBER = re.compile(r"[0-9][0-9A-Za-z_.]*")

# Kinds of path segment.
NAME, STAR, COMPUTED = "name", "star", "computed"


class TooComplex(ValueError):
    """A text with so many overlapping expression starts that reading it would take too long."""


_QUOTE_OR_CLOSE = re.compile(r"'|\}\}")


def bodies(text: str) -> list[str]:
    """The body of every `${{ }}` expression in a string.

    GitHub's runner ends an expression at the first `}}` that is not inside a single-quoted string,
    so `${{ format('}}{0}', secrets.KEY) }}` is one expression. A reader that stops at the first
    `}}` sees only `format('` and misses the secret. Both readings are returned (the second only
    where it differs), so a reference is found whichever one applies, and an expression with no
    end is read to the end of the text.
    """
    out: list[str] = []
    budget = 8 * len(text) + 65536       # an ordinary text needs about its own length
    start = text.find(OPEN)
    while start != -1:
        begin = start + len(OPEN)
        naive = text.find(CLOSE, begin)
        pos, in_string, end = begin, False, -1
        while True:
            match = _QUOTE_OR_CLOSE.search(text, pos)
            budget -= (match.end() if match else len(text)) - pos
            if match is None:
                break
            if match.group(0) == "'":
                in_string = not in_string      # '' inside a string toggles twice, as the runner does
                pos = match.end()
            elif in_string:
                pos = match.start() + 1
            else:
                end = match.start()
                break
        if budget < 0:
            raise TooComplex("too many unfinished ${{ expressions to read; the checker cannot tell what "
                             "this text expands")
        out.append(text[begin:end] if end != -1 else text[begin:])
        if naive != -1 and naive != end:
            out.append(text[begin:naive])
        # Continue after the shorter reading, so an expression that starts inside what the longer
        # reading took for a string is still read.
        nearest = min(p for p in (naive, end, len(text)) if p != -1)
        start = text.find(OPEN, max(nearest, begin))
    return out


def tokens(expr: str) -> list[tuple[str, str]]:
    """(kind, text) pairs: 'str', 'id', 'num' or 'op'. Whitespace is dropped. A string keeps its
    value without the quotes; a string with no closing quote runs to the end."""
    out: list[tuple[str, str]] = []
    i, n = 0, len(expr)
    while i < n:
        ch = expr[i]
        if ch.isspace():
            i += 1
        elif ch == "'":
            # Strings are single-quoted, with '' for a quote. A double quote is not valid in an
            # expression and is left as an operator, so `secrets["NAME"]` reads as a computed index.
            j, value = i + 1, []
            while j < n:
                if expr[j] == "'":
                    if j + 1 < n and expr[j + 1] == "'":
                        value.append("'")
                        j += 2
                        continue
                    break
                value.append(expr[j])
                j += 1
            out.append(("str", "".join(value)))
            i = j + 1
        elif (m := _ID.match(expr, i)):
            out.append(("id", m.group(0)))
            i = m.end()
        elif (m := _NUMBER.match(expr, i)):
            out.append(("num", m.group(0)))
            i = m.end()
        else:
            out.append(("op", ch))
            i += 1
    return out


@dataclass(frozen=True)
class Segment:
    kind: str            # NAME, STAR or COMPUTED
    value: str = ""      # the name as written, for NAME

    def shown(self) -> str:
        return self.value.lower() if self.kind == NAME else "*" if self.kind == STAR else "[...]"


def _matching_bracket(toks: list[tuple[str, str]], start: int) -> int:
    """Index of the `]` that closes the `[` at `start`, or len(toks) when there is none."""
    depth = 0
    for k in range(start, len(toks)):
        if toks[k] == ("op", "["):
            depth += 1
        elif toks[k] == ("op", "]"):
            depth -= 1
            if depth == 0:
                return k
    return len(toks)


def _paths(toks: list[tuple[str, str]]) -> list[tuple[Segment, ...]]:
    out: list[tuple[Segment, ...]] = []
    i, n = 0, len(toks)
    while i < n:
        kind, text = toks[i]
        if kind != "id" or (i > 0 and toks[i - 1] == ("op", ".")) or (i + 1 < n and toks[i + 1] == ("op", "(")):
            # Not the start of a context reference: an operator, a literal, a function name, or a
            # property of a function's result (fromJSON(x).name), whose object is read on its own.
            i += 1
            continue
        segments = [Segment(NAME, text)]
        j = i + 1
        while j < n:
            if toks[j] == ("op", ".") and j + 1 < n and toks[j + 1][0] == "id":
                segments.append(Segment(NAME, toks[j + 1][1]))
                j += 2
            elif toks[j] == ("op", ".") and j + 1 < n and toks[j + 1] == ("op", "*"):
                segments.append(Segment(STAR))
                j += 2
            elif toks[j] == ("op", "["):
                close = _matching_bracket(toks, j)
                inner = toks[j + 1:close]
                if len(inner) == 1 and inner[0][0] == "str":
                    segments.append(Segment(NAME, inner[0][1]))
                else:
                    segments.append(Segment(COMPUTED))
                    out.extend(_paths(inner))      # what the index itself reads
                j = close + 1
            else:
                break
        out.append(tuple(segments))
        i = j
    return out


def paths(expr: str) -> list[tuple[Segment, ...]]:
    """Every context reference in an expression, as a tuple of segments: `github.event.issue.title`,
    `github['event'].issue.title` and `GITHUB.EVENT.ISSUE.TITLE` all give the same four names;
    `secrets.*` ends in a STAR and `secrets[format(...)]` in a COMPUTED segment."""
    return _paths(tokens(expr))


def dotted(path: tuple[Segment, ...]) -> str:
    return ".".join(s.shown() for s in path)


ALL = "*"


def secret_refs(expr: str) -> set[str]:
    """Names of the secrets an expression reads, as written; ALL when it can read any of them.

    Only `secrets.NAME` and `secrets['NAME']` name one secret. Everything else that touches the
    `secrets` context (`toJSON(secrets)`, `secrets.*`, `secrets[matrix.key]`, `secrets` passed to a
    function) can reach every secret, and is reported as that.
    """
    names: set[str] = set()
    for path in paths(expr):
        if path[0].value.lower() != "secrets":
            continue
        if len(path) == 1 or path[1].kind != NAME or not path[1].value.strip():
            names.add(ALL)
        else:
            names.add(path[1].value)
    return names


# What a pattern segment accepts: a set of names, or None for anything (an array index).
Pattern = tuple


def reaches(path: tuple[Segment, ...], pattern: Pattern) -> bool:
    """Whether a context reference can read the field a pattern names.

    A STAR or COMPUTED segment in the reference matches any name. A reference at least as long as
    the pattern reads the field (or something inside it). A shorter reference reads an object that
    contains the field; it counts only when it has a STAR or COMPUTED segment, because that is what
    turns the object into its values (`github.event.issue.*`, `github.event[inputs.kind]`).
    """
    open_ended = any(s.kind != NAME for s in path)
    if len(path) < len(pattern) and not open_ended:
        return False
    for segment, accepted in zip(path, pattern):
        if segment.kind != NAME or accepted is None:
            continue
        if segment.value.lower() not in accepted:
            return False
    return True
