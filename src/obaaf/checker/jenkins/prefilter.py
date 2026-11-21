"""A cheaper `search` for the long scripts the Jenkins rules read, with the same answers.

Most command patterns in `detection.yaml` begin `(^|[\\s;&|(])`, so the regular expression engine tries a match
at every space of a script; on a 900 KB script each such search takes about 12 ms, and the rules run some
eighty of them. Every one of those patterns also names its command in plain letters (`mvn`, `publish`,
`claude`). A match must contain those letters, so where the script does not, the pattern cannot match and
the search is skipped (flagship unblock run `gannet`, 2026-11-21: CI failed on `PERF_20k_line_script`).

`needles(rx)` reads the pattern's parse and returns strings one of which every match of `rx` contains, or
None when the parse does not show any (case-insensitive parts, optional parts, lookarounds, character classes
and anything it does not know give nothing, never a guess). `search` and `finditer` run the pattern only when
the text holds one of them, so they return exactly what `rx.search` and `rx.finditer` return.
"""

from __future__ import annotations

import functools
import re

try:                                    # Python 3.11 and later
    from re import _parser as _sre_parse    # type: ignore[attr-defined]
except ImportError:                     # pragma: no cover - Python 3.10
    import sre_parse as _sre_parse      # type: ignore[no-redef]

_REPEATS = {"MAX_REPEAT", "MIN_REPEAT", "POSSESSIVE_REPEAT"}


def _name(op) -> str:
    return getattr(op, "name", str(op))


def _smallest(found: set[str]) -> frozenset[str]:
    """The same condition with fewer strings: a string that contains another one in the set adds nothing."""
    return frozenset(s for s in found if not any(t != s and t in s for t in found))


def _best(candidates: list[frozenset[str]]) -> frozenset[str] | None:
    """The candidate whose shortest string is longest (the least likely to be in an unrelated text)."""
    if not candidates:
        return None
    return max(candidates, key=lambda c: (min(map(len, c)), -len(c)))


def _of_sequence(items, flags: int) -> frozenset[str] | None:
    """Strings one of which every match of this sequence of parsed items contains, or None.

    Consecutive literal characters match consecutive characters of the text, so they make one string; any
    other item breaks the run (conservative: a zero-width item between two literals would not)."""
    candidates: list[frozenset[str]] = []
    run: list[str] = []
    for op, av in items:
        name = _name(op)
        if name == "LITERAL" and not flags & re.IGNORECASE:
            run.append(chr(av))
            continue
        if run:
            candidates.append(frozenset({"".join(run)}))
            run = []
        found = _of_item(name, av, flags)
        if found:
            candidates.append(found)
    if run:
        candidates.append(frozenset({"".join(run)}))
    return _best(candidates)


def _of_item(name: str, av, flags: int) -> frozenset[str] | None:
    if name == "SUBPATTERN":
        # Under IGNORECASE no literal or class gives a string (see below), but a `(?-i:...)` inside can.
        _group, add_flags, del_flags, body = av
        return _of_sequence(body, (flags | add_flags) & ~del_flags)
    if name == "ATOMIC_GROUP":
        return _of_sequence(av, flags)
    if name in _REPEATS:
        low, _high, body = av
        return _of_sequence(body, flags) if low >= 1 else None
    if name == "BRANCH":
        _none, alternatives = av
        union: set[str] = set()
        for alternative in alternatives:
            found = _of_sequence(alternative, flags)
            if not found:
                return None
            union |= found
        return _smallest(union) if union else None
    if name == "IN" and not flags & re.IGNORECASE:
        chars = set()
        for op, value in av:
            if _name(op) != "LITERAL":
                return None
            chars.add(chr(value))
        return frozenset(chars) if chars else None
    # LITERAL under IGNORECASE, NOT_LITERAL, ANY, AT, CATEGORY, ASSERT, ASSERT_NOT, GROUPREF, GROUPREF_EXISTS,
    # and anything a later Python adds: no string is required.
    return None


@functools.lru_cache(maxsize=4096)
def _needles(pattern: str, flags: int) -> frozenset[str] | None:
    try:
        parsed = _sre_parse.parse(pattern, flags)
    except Exception:       # never let the shortcut change an answer: no needles, the pattern runs
        return None
    state = getattr(parsed, "state", None)
    flags |= getattr(state, "flags", 0)
    if flags & re.IGNORECASE:
        return None
    return _of_sequence(list(parsed), flags)


def needles(rx: re.Pattern) -> frozenset[str] | None:
    """Strings one of which every match of `rx` contains, or None when its parse does not show any."""
    if not isinstance(rx.pattern, str):
        return None
    return _needles(rx.pattern, rx.flags)


def possible(rx: re.Pattern, text: str) -> bool:
    """False only when `rx` cannot match anywhere in `text`."""
    found = needles(rx)
    return found is None or any(s in text for s in found)


def search(rx: re.Pattern, text: str):
    """`rx.search(text)`, without running the pattern over a text that cannot hold a match."""
    return rx.search(text) if possible(rx, text) else None


def finditer(rx: re.Pattern, text: str):
    """`rx.finditer(text)`, without running the pattern over a text that cannot hold a match."""
    return rx.finditer(text) if possible(rx, text) else iter(())
