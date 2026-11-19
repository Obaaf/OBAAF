"""Generators for the property tests in test_properties.py (slice 2d.3).

Each generator takes a workflow's text and a seeded `random.Random` and returns the same workflow
written another way. "The same" is checked, not assumed: `yaml_data` of the result must equal
`yaml_data` of the input for the YAML respellings, and the expression respellings only make the
changes the expression reader's own documentation (obaaf.checker.expr) calls equivalent. None of
these spellings has been run on GitHub; what is claimed is that the checker reads them as it reads
the original, not that GitHub accepts every one.

Nothing here imports anything outside the standard library, PyYAML and obaaf, so the tests run in
CI with the dependencies CI already installs.
"""

from __future__ import annotations

import re

import yaml

import helpers  # noqa: F401 - puts src/ on the path when the tests are run from a checkout

from obaaf import yamlutil

STR = "tag:yaml.org,2002:str"


def compose(text: str):
    return yaml.compose(text, Loader=yamlutil._Loader)


def yaml_data(text: str):
    """The data a workflow's text holds, as the checker's loader reads it."""
    return yamlutil.load(text)


def _nodes(root) -> list:
    """Every node once, parents before children."""
    seen: set = set()
    out: list = []
    todo = [root]
    while todo:
        node = todo.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))
        out.append(node)
        if isinstance(node, yaml.MappingNode):
            for key, value in reversed(node.value):
                todo.extend((value, key))
        elif isinstance(node, yaml.SequenceNode):
            todo.extend(reversed(node.value))
    return out


def _shape(node, memo: dict) -> tuple:
    """A key that two nodes share when they hold the same data."""
    found = memo.get(id(node))
    if found is not None:
        return found
    if isinstance(node, yaml.ScalarNode):
        found = ("s", node.tag, node.value)
    elif isinstance(node, yaml.SequenceNode):
        found = ("q", node.tag, tuple(_shape(child, memo) for child in node.value))
    else:
        found = ("m", node.tag, tuple((_shape(k, memo), _shape(v, memo)) for k, v in node.value))
    memo[id(node)] = found
    return found


def _share(root, rng) -> None:
    """Write some values that occur more than once once, under an anchor, and reach the others
    through aliases. Mapping keys are never aliased, and a merge key (`<<`) is never written: GitHub
    does not read merge keys, and the checker refuses them (slice 2d.2f)."""
    memo: dict = {}
    first: dict = {}
    for node in _nodes(root):
        children = (node.value if isinstance(node, yaml.SequenceNode)
                    else [v for _, v in node.value] if isinstance(node, yaml.MappingNode) else [])
        for index, child in enumerate(children):
            if isinstance(child, yaml.ScalarNode) and len(child.value) < 6:
                continue
            shape = _shape(child, memo)
            earlier = first.setdefault(shape, child)
            if earlier is child or rng.random() < 0.1:
                continue
            if isinstance(node, yaml.SequenceNode):
                node.value[index] = earlier
            else:
                node.value[index] = (node.value[index][0], earlier)


def _comment(text: str, rng) -> str:
    """Comment lines before some lines that begin a mapping key or a sequence entry."""
    starts: set = set()
    try:
        for token in yaml.scan(text, Loader=yamlutil._Loader):
            if isinstance(token, (yaml.KeyToken, yaml.BlockEntryToken)):
                mark = token.start_mark
                starts.add((mark.line, mark.column))
    except yaml.YAMLError:
        return text
    lines = text.split("\n")
    out: list = []
    for number, line in enumerate(lines):
        indent = len(line) - len(line.lstrip(" "))
        if (number, indent) in starts and line.strip() and rng.random() < 0.4:
            out.append(" " * indent + "# " + rng.choice(["note", "}} ${{ secrets.X }}", "'", '"', "- not: a key"]))
        out.append(line)
    return "\n".join(out)


def respell_yaml(text: str, rng, root=None) -> str:
    """The same data in other YAML: block or flow collections, plain, quoted, literal or folded
    text, keys in another order, values shared through anchors and aliases, other indentation and
    line widths, a document start marker, and comment lines."""
    root = compose(text) if root is None else root
    flow = rng.choice([0.0, 0.1, 0.4, 1.0])
    for node in _nodes(root):
        if isinstance(node, yaml.ScalarNode):
            # Only text is restyled: a quoted 10 is the text "10", not the number. PyYAML's emitter
            # does not write folded text faithfully when a line begins or ends with a space, so `>`
            # is used only where none does.
            styles = [None, None, "'", '"', "|"]
            if not re.search(r"(^|\n)[ \t]|[ \t](\n|$)", node.value):
                styles.append(">")
            node.style = rng.choice(styles) if node.tag == STR else None
        elif isinstance(node, yaml.MappingNode):
            node.flow_style = rng.random() < flow
            if rng.random() < 0.5:
                rng.shuffle(node.value)
        elif isinstance(node, yaml.SequenceNode):
            node.flow_style = rng.random() < flow
    if rng.random() < 0.8:
        _share(root, rng)
    out = yaml.serialize(root, Dumper=yaml.SafeDumper, indent=rng.randint(2, 8),
                         width=rng.choice([60, 80, 120, 4096]), explicit_start=rng.random() < 0.3,
                         allow_unicode=rng.random() < 0.5)
    if rng.random() < 0.5:
        out = _comment(out, rng)
    return out


# ---------------------------------------------------------------- expressions
_TOKEN = re.compile(r"(?P<ws>\s+)|(?P<str>'(?:[^']|'')*')|(?P<num>[0-9][0-9A-Za-z_.]*)"
                    r"|(?P<id>[A-Za-z_][A-Za-z0-9_-]*)|(?P<op>==|!=|<=|>=|&&|\|\||.)", re.S)
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*\Z")
_LITERALS = {"true", "false", "null", "nan", "infinity"}


def spans(text: str) -> list[tuple[int, int]]:
    """(start, end) of the body of each `${{ }}` that GitHub's runner and a reader that stops at
    the first `}}` both end in the same place. Only these are respelled, so no change moves the
    end of an expression."""
    out = []
    start = text.find("${{")
    while start != -1:
        begin = start + 3
        pos, in_string, end = begin, False, -1
        while pos < len(text):
            if text[pos] == "'":
                in_string = not in_string
                pos += 1
            elif not in_string and text.startswith("}}", pos):
                end = pos
                break
            else:
                pos += 1
        if end == -1:
            break
        if text.find("}}", begin) == end:
            out.append((begin, end))
        start = text.find("${{", end + 2)
    return out


def _tokens(body: str) -> list[tuple[str, str]] | None:
    out = []
    for match in _TOKEN.finditer(body):
        kind = match.lastgroup
        out.append((kind, match.group(0)))
    if "".join(t for _, t in out) != body:
        return None
    if any(kind == "op" and text == "'" for kind, text in out):     # an unended string
        return None
    return out


def _case(word: str, rng) -> str:
    return rng.choice([word, word.lower(), word.upper(), word.title(),
                       "".join(rng.choice((c.lower(), c.upper())) for c in word)])


def _significant(toks: list, index: int, step: int):
    index += step
    while 0 <= index < len(toks) and toks[index][0] == "ws":
        index += step
    return (index, toks[index]) if 0 <= index < len(toks) else (index, ("", ""))


def respell_body(body: str, rng) -> str:
    """The body of one expression, respelled the ways obaaf.checker.expr documents as reading the
    same: other letter cases in context and property names, `.name` and `['name']` for each other,
    other spaces where spaces may go, and parentheses round the whole and round a reference's
    first names."""
    toks = _tokens(body)
    if toks is None:
        return body
    out: list[str] = []
    i = 0
    while i < len(toks):
        kind, text = toks[i]
        _, before = _significant(toks, i, -1)
        after_at, after = _significant(toks, i, 1)
        if kind == "id" and text.lower() not in _LITERALS and after != ("op", "("):
            if before == ("op", ".") and out and out[-1] == "." and rng.random() < 0.3:
                out[-1] = ""
                out.append("['" + text + "']")
            else:
                out.append(_case(text, rng))
        elif (kind, text) == ("op", "[") and after[0] == "str" and _NAME.match(after[1][1:-1].replace("''", "'")):
            close_at, close = _significant(toks, after_at, 1)
            if close == ("op", "]") and rng.random() < 0.3:
                out.append("." + _case(after[1][1:-1], rng))
                i = close_at + 1
                continue
            out.append(text)
        elif kind == "ws":
            out.append(" " * rng.randint(1, 3))
        elif kind == "op" and text in ("(", ","):
            out.append(text + " " * rng.randint(0, 2))
        elif kind == "op" and text in (")",):
            out.append(" " * rng.randint(0, 2) + text)
        elif kind == "op" and text in ("==", "!=", "<=", ">=", "&&", "||"):
            out.append(" " * rng.randint(0, 2) + text + " " * rng.randint(0, 2))
        else:
            out.append(text)
        i += 1
    result = "".join(out)
    result = _group_first_names(result, rng)
    if rng.random() < 0.3:
        result = "(" + result + ")"
    return " " * rng.randint(0, 3) + result.strip() + " " * rng.randint(0, 3)


_CHAIN = re.compile(r"(?<![\w.'\]-])([A-Za-z_][\w-]*(?:\s*\.\s*[A-Za-z_][\w-]*){2,})")


def _group_first_names(body: str, rng) -> str:
    """`a.b.c` as `(a.b).c`, which the reader reads as the same reference, outside strings."""
    if rng.random() >= 0.3:
        return body
    pieces = re.split(r"('(?:[^']|'')*')", body)
    for k in range(0, len(pieces), 2):
        def group(match):
            names = re.split(r"\s*\.\s*", match.group(1))
            if names[0].lower() in _LITERALS:
                return match.group(1)
            cut = rng.randint(1, len(names) - 1)
            return "(" + ".".join(names[:cut]) + ")." + ".".join(names[cut:])
        pieces[k] = _CHAIN.sub(lambda m: group(m) if rng.random() < 0.5 and not _call_follows(body, m) else m.group(1),
                               pieces[k])
    return "".join(pieces)


def _call_follows(body: str, match) -> bool:
    rest = match.string[match.end():].lstrip()
    return rest.startswith("(")


def respell_expressions(text: str, rng) -> str:
    """Every expression in every text value of the workflow, respelled; then the YAML written
    again. Keys are left as they are."""
    root = compose(text)
    for node in _nodes(root):
        if isinstance(node, yaml.MappingNode):
            values = [v for _, v in node.value]
        elif isinstance(node, yaml.SequenceNode):
            values = list(node.value)
        else:
            continue
        for value in values:
            if isinstance(value, yaml.ScalarNode) and value.tag == STR and "${{" in value.value:
                value.value = respell_text(value.value, rng)
    return yaml.serialize(root, Dumper=yaml.SafeDumper, width=4096, allow_unicode=True)


def respell_text(text: str, rng) -> str:
    out, last = [], 0
    for begin, end in spans(text):
        out.append(text[last:begin])
        out.append(respell_body(text[begin:end], rng))
        last = end
    out.append(text[last:])
    return "".join(out)


# ---------------------------------------------------------------- the workflow's own forms
_USES = re.compile(r"(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?P<rest>(/[^@]*)?@.*)\Z", re.S)


def _respell_uses(value, rng):
    """`owner/repo` in another letter case (GitHub names are compared without regard to case; a
    folder inside the repository, and the ref, are left as written)."""
    if not isinstance(value, str) or value.startswith(("./", "docker://")):
        return value
    match = _USES.match(value)
    if not match:
        return value
    return _case(match.group("repo"), rng) + match.group("rest")


def _respell_if(value, rng):
    """An `if` with `${{ }}` round all of it and one without, which GitHub documents as the same."""
    if isinstance(value, bool):
        return value
    if not isinstance(value, str):
        return value
    found = spans(value)
    stripped = value.strip()
    if len(found) == 1 and stripped.startswith("${{") and stripped.endswith("}}") \
            and value[found[0][1]:].strip() == "}}" and value[:found[0][0]].strip() == "${{":
        inner = value[found[0][0]:found[0][1]].strip()
        if inner and not inner.startswith(("!", "*", "&", "[", "{", "'", '"', "|", ">", "%", "@", "`", "#")):
            return inner
        return value
    if "${{" not in value and value.strip():
        return "${{ " + value.strip() + " }}"
    return value


def respell_forms(text: str, rng) -> str | None:
    """The same workflow in other forms GitHub documents as meaning the same: one label, job or
    event as a list of one, an event as a mapping with no settings, the workflow's `env` written
    into each job that has steps instead, an `if` with and without `${{ }}`, and an action's or a
    called workflow's `owner/repo` in another letter case. None when nothing was changed."""
    data = yaml_data(text)
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        return None
    changed = False
    for job in data["jobs"].values():
        if not isinstance(job, dict):
            continue
        places = [job] + [step for step in (job.get("steps") or []) if isinstance(step, dict)]
        for place in places:
            for key, respell in (("uses", _respell_uses), ("if", _respell_if)):
                if key in place and rng.random() < 0.5:
                    new = respell(place[key], rng)
                    if new != place[key]:
                        place[key] = new
                        changed = True
    on = data.get("on")
    if isinstance(on, str) and rng.random() < 0.7:
        data["on"] = [on] if rng.random() < 0.5 else {on: rng.choice([None, {}])}
        changed = True
    elif isinstance(on, list) and all(isinstance(e, str) for e in on) and rng.random() < 0.7:
        data["on"] = {e: rng.choice([None, {}]) for e in on}
        changed = True
    for job in data["jobs"].values():
        if not isinstance(job, dict):
            continue
        for key in ("runs-on", "needs"):
            if isinstance(job.get(key), str) and rng.random() < 0.7:
                job[key] = [job[key]]
                changed = True
    env = data.get("env")
    jobs = list(data["jobs"].values())
    if (isinstance(env, dict) and env and rng.random() < 0.7
            and all(isinstance(j, dict) and "steps" in j and "uses" not in j for j in jobs)
            and all(not isinstance(j.get("env"), str) for j in jobs)):
        for job in jobs:
            merged = dict(env)
            merged.update(job.get("env") or {})
            job["env"] = merged
        del data["env"]
        changed = True
    if not changed:
        return None
    return yaml.safe_dump(_plain(data), sort_keys=False, allow_unicode=True, width=4096)


def _plain(value):
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


# ---------------------------------------------------------------- corruption
_NOISE = ["{", "}", "[", "]", ":", "'", '"', "&a", "*a", "!", "|", ">", "#", "%", "@", "`", "\\", "-", "?", ",",
          "${{", "}}", "\t", "\n", "\r", "\x00", "﻿", " ", "\u0085", " ", "é", "😀", "<<: *a", "~"]


def corrupt(text: str, rng) -> str:
    """The text with a few random edits: characters deleted, inserted or repeated, a line
    duplicated, moved or cut short, or the end cut off."""
    for _ in range(rng.randint(1, 4)):
        choice = rng.random()
        lines = text.split("\n")
        if not text:
            text = rng.choice(_NOISE)
        elif choice < 0.25:
            at = rng.randrange(len(text))
            text = text[:at] + text[at + rng.randint(1, 8):]
        elif choice < 0.5:
            at = rng.randrange(len(text) + 1)
            text = text[:at] + rng.choice(_NOISE) + text[at:]
        elif choice < 0.65:
            at = rng.randrange(len(lines))
            lines.insert(rng.randrange(len(lines) + 1), lines[at])
            text = "\n".join(lines)
        elif choice < 0.8:
            at = rng.randrange(len(lines))
            line = lines.pop(at)
            lines.insert(rng.randrange(len(lines) + 1), line[: rng.randrange(len(line) + 1)])
            text = "\n".join(lines)
        elif choice < 0.9:
            text = text[: rng.randrange(len(text) + 1)]
        else:
            at = rng.randrange(len(text))
            text = text[:at] + text[at] * rng.randint(2, 50) + text[at:]
    return text
