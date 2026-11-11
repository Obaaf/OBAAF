"""Reading GitHub Actions expressions (the text inside `${{ }}`).

The rules ask two things of an expression: which secrets it can read, and whether it expands text
an outsider wrote. Matching patterns against the expression's text answers neither reliably: a
spelling the patterns did not expect is a way past the rule. Here the expression is split into
tokens and its context references are read from them. Where the reader cannot pin a reference
down it takes the wider reading: a reference to `secrets` that is not one literal name is every
secret, a wildcard or computed index matches any field, and an argument of a function is treated
as something the function may turn into text.

Nothing is evaluated, and nothing here has been checked against a run on GitHub. What the rules
built on this reader do not follow is listed in each rule's description (data/rules.yaml).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

OPEN, CLOSE = "${{", "}}"
_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_NUMBER = re.compile(r"[0-9][0-9A-Za-z_.]*")

# Kinds of path segment.
NAME, STAR, COMPUTED = "name", "star", "computed"


class TooComplex(ValueError):
    """Text the reader refuses rather than read slowly or wrongly: too many unfinished expression
    starts, or brackets and parentheses nested too deeply."""


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


@dataclass(frozen=True)
class Ref:
    """One context reference in an expression."""

    path: tuple            # of Segment
    extracted: bool = False   # an argument of a function call, which may turn an object into its text


# Deeper nesting of ( and [ than this is refused. Real expressions nest a handful of levels.
MAX_DEPTH = 64
# Segments kept per reference. The longest field the rules look for has six, and a reference longer
# than the field it is compared with never matches, so the rest can be dropped. Without the limit
# `(a || a || ...).b.b.b...` costs memory in proportion to its length squared.
MAX_SEGMENTS = 16


def _closers(toks: list) -> list[int]:
    """For each `(` or `[`, the index of the token that closes it, or len(toks) when nothing does."""
    close = [len(toks)] * len(toks)
    stack: list[int] = []
    for k, (kind, text) in enumerate(toks):
        if kind != "op":
            continue
        if text in "([":
            stack.append(k)
        elif text in ")]" and stack and toks[stack[-1]][1] == ("(" if text == ")" else "["):
            close[stack.pop()] = k
    return close


def _accessors(toks: list, close: list, j: int, hi: int, in_call: bool, depth: int, out: list,
               segments: list | None) -> int:
    """Read `.name`, `.*` and `[...]` from position j, adding them to `segments` (when given), and
    return the position after them. What a computed index itself reads is added to `out`."""
    while j < hi:
        if toks[j] == ("op", ".") and j + 1 < hi and toks[j + 1][0] == "id":
            segment = Segment(NAME, toks[j + 1][1])
            j += 2
        elif toks[j] == ("op", ".") and j + 1 < hi and toks[j + 1] == ("op", "*"):
            segment = Segment(STAR)
            j += 2
        elif toks[j] == ("op", "["):
            end = min(close[j], hi)
            if end - j == 2 and toks[j + 1][0] == "str":
                segment = Segment(NAME, toks[j + 1][1])
            else:
                segment = Segment(COMPUTED)
                _read(toks, close, j + 1, end, in_call, depth + 1, out)
            j = end + 1
        else:
            break
        if segments is not None and len(segments) < MAX_SEGMENTS:
            segments.append(segment)
    return j


def _read(toks: list, close: list, lo: int, hi: int, in_call: bool, depth: int, out: list) -> None:
    if depth > MAX_DEPTH:
        raise TooComplex("an expression is nested too deeply to read; the checker cannot tell what it expands")
    i = lo
    while i < hi:
        kind, text = toks[i]
        if kind == "id" and i + 1 < hi and toks[i + 1] == ("op", "("):
            # A function call. Its arguments are read as extracted: toJSON, join, format or a
            # function added later can turn an object into text. What follows the call (`.name`,
            # `[...]`) applies to the function's result, not to a context.
            end = min(close[i + 1], hi)
            _read(toks, close, i + 2, end, True, depth + 1, out)
            i = _accessors(toks, close, end + 1, hi, in_call, depth, out, None)
        elif (kind, text) == ("op", "("):
            # A group. `(github.event.issue).title` reads the same field as the plain spelling, and
            # `(a || b).title` reads it from either side, so what follows the group is added to each
            # reference inside it.
            end = min(close[i], hi)
            inner: list = []
            _read(toks, close, i + 1, end, in_call, depth + 1, inner)
            suffix: list = []
            i = _accessors(toks, close, end + 1, hi, in_call, depth, out, suffix)
            if suffix:
                added = tuple(suffix)
                inner = [r if r.extracted else Ref((r.path + added)[:MAX_SEGMENTS], False) for r in inner]
            out.extend(inner)
        elif kind == "id" and not (i > 0 and toks[i - 1] == ("op", ".")):
            segments = [Segment(NAME, text)]
            i = _accessors(toks, close, i + 1, hi, in_call, depth, out, segments)
            out.append(Ref(tuple(segments), in_call))
        else:
            i += 1


@lru_cache(maxsize=4096)
def refs(expr: str) -> tuple:
    """Every context reference in an expression. `github.event.issue.title`,
    `github['event'].issue.title`, `GITHUB.EVENT.ISSUE.TITLE` and `(github.event.issue).title` all
    give the same four names; `secrets.*` ends in a STAR and `secrets[format(...)]` in a COMPUTED
    segment. Raises TooComplex for an expression nested too deeply to read."""
    toks = tokens(expr)
    out: list = []
    _read(toks, _closers(toks), 0, len(toks), False, 0, out)
    return tuple(out)


def paths(expr: str) -> list[tuple]:
    return [ref.path for ref in refs(expr)]


def dotted(path: tuple) -> str:
    return ".".join(s.shown() for s in path)


ALL = "*"
_SECRET_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")


def secret_refs(expr: str) -> set[str]:
    """Names of the secrets an expression reads, as written; ALL when it can read any of them.

    Only `secrets.NAME` and `secrets['NAME']` name one secret. Everything else that touches the
    `secrets` context (`toJSON(secrets)`, `secrets.*`, `secrets[matrix.key]`, `secrets` passed to a
    function, an index that is not a name) can reach every secret, and is reported as that.
    """
    names: set[str] = set()
    for path in paths(expr):
        if path[0].value.lower() != "secrets":
            continue
        if len(path) == 1 or path[1].kind != NAME or not _SECRET_NAME.match(path[1].value):
            names.add(ALL)
        else:
            names.add(path[1].value)
    return names


def reaches(path: tuple, pattern: tuple, extracted: bool = False) -> bool:
    """Whether a context reference can read the field a pattern names.

    A pattern is one accepted set of names per segment, or None where the data has an array index
    (which a wildcard, a computed index or a string that is not a name can stand for).
    A STAR or COMPUTED segment in the reference matches anything. A reference as long as the pattern
    reads the field. A shorter one reads an object that contains the field; it counts when
    something can turn that object into text: a STAR or COMPUTED segment (`github.event.issue.*`,
    `github.event[inputs.kind]`), or being an argument of a function (`extracted`). A longer one
    reads inside a text field, which holds nothing.
    """
    if len(path) > len(pattern):
        return False
    if len(path) < len(pattern) and not (extracted or any(s.kind != NAME for s in path)):
        return False
    for segment, accepted in zip(path, pattern):
        if segment.kind != NAME:
            continue
        if accepted is None:
            # An array index. A name such as `number` is not one; anything else written as a
            # string ('0', '', ' 0', '0x0') may be converted to one.
            if _SECRET_NAME.match(segment.value):
                return False
        elif segment.value.lower() not in accepted:
            return False
    return True
