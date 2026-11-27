"""Working out the `${{ }}` expressions in a step's command lines that read `env` (flagship slice 2d.19, #382).

GitHub works out every `${{ }}` in a step's `run` (and in the inputs it hands an action) before the shell starts,
with the `env` context: the workflow's, the job's and the step's own `env`, the nearest winning. So
`run: ${{ env.AGENT }} -p review` with `AGENT: claude` in the job's `env` runs `claude`. The lanes read a step's
command lines for an agent (`Step.agent_text`); before this slice they read such an expression as written, so the
job was in no agent lane and no agent rule applied.

`put_in(text, env)` (that is, `plan` and then `build`) gives the text with each expression that reads `env` worked out,
for the `Env` of the step's scopes and its runner (`env_case`), read the widest way:

- **Only `env` at the head of a reference counts** (`env.X`, `ENV.X`, `env['X']`, `(env).X`, `env[...]`);
  `matrix.env`, `inputs.env` and the string `'env'` do not. An expression that does not read `env` is left as
  written, as before.
- **Letter case follows the runner** (#387, the lead's decision on F-405): on a known GitHub-hosted Linux or macOS
  runner a name is looked up as written (`exact`); on a known GitHub-hosted Windows runner without regard to case,
  letter by letter (`fold`), the step's value over the job's over the workflow's (`folded`), and a name outside
  ASCII may be any name outside ASCII; anywhere else (`both`) each reading is kept where the two differ.
- **A reference not pinned to one name gives every value**: `env[matrix.key]`, the `env` object made into text
  (`toJSON(env)`, `format('{0}', env)`, `env.*`, `join(env.*, sep)`) give each value `env` holds, one reading each,
  as the local-action reader gives every input for `inputs[*]` (`join` gives the values joined in the order the
  workflow writes them too, and `toJSON` the JSON). A function the checker does not know given what
  an expression reads from `env`, or a form it does not read, make the step an error of its file (`Unread`).
- **Each expression is read on its own**; readings are made line by line, never multiplied across a step: a line
  (with the lines a backslash continues or an expression spans) holding several expressions with several values
  each is read in every combination, at most `LINE_READINGS` of them (`SINGLE_READINGS` where only one expression
  there has several values); past that the step is an error of its file. What the readings make (the values in
  every reading and the lines copied for readings past the first) is worked out before anything is made (`plan`),
  against the room the caller has left for the whole workflow.
- A value the checker does not know (another context: `matrix`, `inputs`, `github`, a step's output) makes no
  reading where the expression has values the checker knows (the lines as written are read anyway); where it is
  one operand of `||`, `&&`, `format()` or `join()`, the other readings are made, with it as an empty text where
  it is a piece of the text; an expression with no value the checker knows is left as written.

- **A scope written as one expression** (flagship slice 2d.19d: `env: ${{ fromJSON(vars.E) }}`, `env: ${{ matrix.env
  }}`) may give any name any text: a name that no mapping nearer the step sets, under the runner's comparison of
  names, and the whole `env` give `FROM_SCOPE`. It makes no reading, as a value of another context does, but the
  plan names each expression whose text may hold it (`Plan.scoped`), and the lanes make the step an error of its
  file where one stands where a command's program goes (`workflow._scope_at_program`). Before, such a scope gave a
  value of another context, so `run: ${{ env.AGENT }} -p x` under it was in no agent lane, with no error.

Nothing here is checked against a run on GitHub beyond what #387 asserts (letter case in the `env` context on
GitHub-hosted runners). What an earlier step writes to `GITHUB_ENV` is not read.
"""

from __future__ import annotations

import itertools
import json
import math
import re

from obaaf.checker import expr as expr_mod

# Readings of one line where two or more of its expressions give several values (their combinations), and where
# only one does (its values: `echo "${{ toJSON(env) }}"` with a large `env` is ordinary).
LINE_READINGS = 1024
SINGLE_READINGS = 4096
# Values one expression may give; more is an error of the file.
EXPRESSION_VALUES = 4096
# Characters the readings of a step's lines may add to the lines as written (the copies of lines, not the values
# put in, which the workflow's ledger counts).
COPIES_TEXT = 2_000_000
MAX_DEPTH = 64
# Characters `fromJSON` may parse for one step, each text once.
PARSE_TEXT = 4_000_000

# A quick test: a text that cannot hold an expression reading `env` is not read at all.
_MAY_READ_ENV = re.compile(r"\benv\b", re.I)


class Unread(Exception):
    """An expression reading `env` that the checker does not work out; `str()` says which and why."""


class NoRoom(Exception):
    """The readings of a step would make more text than the workflow's ledger has room for (`plan`'s `room`)."""


class _Unknown:
    """A value of another context, which the checker does not know: put in as the expression is written."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "UNKNOWN"


UNKNOWN = _Unknown()


class _EnvObject:
    """The `env` context itself, not yet indexed."""

    __slots__ = ()


ENV_OBJECT = _EnvObject()


class _AllValues:
    """`env.*`: every value `env` holds, as an array."""

    __slots__ = ()


ALL_VALUES = _AllValues()


class _FromScope:
    """What an `env` written as one expression the checker does not read may give (flagship slice 2d.19d): any
    text, or nothing. An expression whose text may hold it is named in its plan (`Plan.scoped`)."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "FROM_SCOPE"


FROM_SCOPE = _FromScope()


def env_case(job) -> str:
    """How the runner of `job` compares the names of the `env` context (#387, F-405): `exact` on a known
    GitHub-hosted Linux or macOS runner, `folded` on a known GitHub-hosted Windows runner, `both` where the runner
    is not resolved, not GitHub-hosted, or may be either."""
    if job is None:
        return "both"
    try:
        if job.self_hosted:
            return "both"
        sets = job.runner_label_sets()
    except Exception:       # a `runs-on` the reader refuses: the runner is not known
        return "both"
    if not sets:
        return "both"
    from obaaf.checker.workflow import is_hosted_label
    kinds = set()
    for labels in sets:
        low = {str(label).lower() for label in labels}
        if len(low) != 1:
            return "both"
        label = next(iter(low))
        if not is_hosted_label(label):
            return "both"
        kinds.add("folded" if label.startswith("windows-") else "exact")
    return kinds.pop() if len(kinds) == 1 else "both"


class Env:
    """The `env` context a step's expressions see, by letter-case mode: `exact` looks a name up as written,
    `folded` without regard to case (the nearest scope's value), `both` gives each where they differ. Each table
    is built once per reading of a step (the review of 2d.18 found it rebuilt for every reference).

    A scope that is not a mapping is written as one expression the checker does not read (flagship slice 2d.19d):
    the tables hold only the mappings nearer the step than the nearest such scope, and a name they do not settle,
    and the whole `env`, may then be anything (`FROM_SCOPE`)."""

    def __init__(self, scopes: list, case: str, labels: list | None = None) -> None:
        # `scopes`: the `env` mappings, outermost first (the workflow's, the job's, the step's).
        self.case = case
        if labels is None:
            labels = ["the workflow's", "the job's", "the step's own"] if len(scopes) == 3 else \
                ["the step's own"] * len(scopes)
        last = max((i for i, scope in enumerate(scopes) if scope is not None and not isinstance(scope, dict)),
                   default=-1)
        # The nearest scope the checker does not read, which decides what a name it does not settle may be.
        self.unread = last >= 0
        self.where = labels[last] if self.unread else None
        exact: dict = {}
        folded: dict = {}
        # Values under a name the checker may not spell as GitHub does: a key YAML gives as a number, a boolean
        # or null (GitHub names it by its text, not checked here), or a text key that YAML 1.2, which GitHub reads,
        # may read as one (`0o7`, `yes` is text to both). Every lookup may give them (found by the review of 2d.19).
        self.odd: list = []
        # Such text keys settle no name (found by the review of 2d.19d: GitHub names `0o7` `7`, so `env['0o7']`
        # comes from an outer scope).
        odd_names: set = set()
        for scope in scopes[last + 1:]:
            if not isinstance(scope, dict):
                continue
            for name, value in scope.items():
                text = _scalar_text(value)
                if not isinstance(name, str) or _YAML12_SCALAR.fullmatch(name):
                    if text is not None:
                        self.odd.append(text)
                    if not isinstance(name, str):
                        continue
                    odd_names.add(name)
                if text is None:
                    # Not text (a mapping, a list): GitHub refuses it, or gives what the checker does not know.
                    exact.pop(name, None)
                    folded.pop(fold(name), None)
                    continue
                exact[name] = text
                folded[fold(name)] = text
        self.exact, self.folded = exact, folded
        self.odd_folded = {fold(name) for name in odd_names}
        self.odd_names = odd_names
        # On Windows a name outside ASCII is compared by .NET's own mapping, which the checker does not copy (the
        # second review: U+1FB3 and U+1FBC are one name there), so such a lookup may give any such name's value.
        self.outside_ascii = [value for name, value in exact.items() if not name.isascii()]
        self.parsed: dict = {}
        self.parse_room = PARSE_TEXT
        self.fields: dict = {}
        self.kept: list = []
        self.every_texts = None

    def lookup(self, name: str) -> list:
        """The values `env.NAME` can give (None for a name `env` does not hold)."""
        out = []
        # A name outside ASCII may fold otherwise on Windows than here (.NET's ordinal comparison maps letter by
        # letter: `ß` is not `SS`), so there both tables are read.
        case = "both" if self.case == "folded" and not name.isascii() else self.case
        settled = True
        if case in ("exact", "both"):
            out.append(self.exact.get(name))
            settled = name in self.exact and name not in self.odd_names
        if case in ("folded", "both"):
            key = fold(name)
            out.append(self.folded.get(key))
            if not name.isascii():
                out.extend(self.outside_ascii)
            settled = settled and name.isascii() and key in self.folded and key not in self.odd_folded
        out.extend(self.odd)
        if self.unread and not settled:
            out.append(FROM_SCOPE)
        return _unique(out)

    def every(self) -> list:
        """Every value `env` can give, and nothing (a name it does not hold)."""
        values: list = []
        if self.case in ("exact", "both"):
            values.extend(self.exact.values())
        if self.case in ("folded", "both"):
            values.extend(self.folded.values())
        values.extend(self.odd)
        values.append(None)
        if self.unread:
            values.append(FROM_SCOPE)
        return _unique(values)

    def joined(self, sep: str) -> list:
        """`join(env.*, sep)`: the values in the order the workflow writes them, in each table."""
        if self.unread:
            return [FROM_SCOPE]
        out = []
        tables = []
        if self.case in ("exact", "both"):
            tables.append(list(self.exact.values()))
        if self.case in ("folded", "both"):
            tables.append(list(self.folded.values()))
        for values in tables:
            out.append(sep.join(values))
            if self.odd:
                # Where a name YAML may read otherwise stands among them is not known: first and last.
                out.append(sep.join(self.odd + values))
                out.append(sep.join(values + self.odd))
        return out

    def as_dict(self) -> list:
        """The object(s) `toJSON(env)` serialises (none where a scope is not read: `every` gives `FROM_SCOPE`)."""
        if self.unread:
            return []
        out = []
        if self.case in ("exact", "both"):
            out.append(dict(self.exact))
        if self.case in ("folded", "both") and (self.case == "folded" or set(self.folded) != {
                k.upper() for k in self.exact}):
            out.append(dict(self.folded))
        return out


_YAML12_SCALAR = re.compile(r"~|null|Null|NULL|true|True|TRUE|false|False|FALSE"
                            r"|[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+"
                            r"|[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
                            r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN)")


def fold(name: str) -> str:
    """A name as a Windows runner compares it: each letter by its own upper case where that is one letter (.NET's
    ordinal comparison without regard to case maps letter by letter), so `ß` stays `ß`."""
    if name.isascii():
        return name.upper()
    out = []
    for ch in name:
        up = ch.upper()
        out.append(up if len(up) == 1 else ch)
    return "".join(out)


def _scalar_text(value) -> str | None:
    """A YAML value as the text GitHub's `env` holds, None for a mapping or a list."""
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number_text(value)
    return None


def _number_text(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    if value == int(value) and abs(value) < 1e15:
        return str(int(value))
    return repr(value)


def _key(value):
    if value is UNKNOWN or value is ENV_OBJECT or value is ALL_VALUES or value is FROM_SCOPE:
        return ("special", id(value))
    if isinstance(value, (dict, list)):
        return ("id", id(value))
    return (type(value).__name__, value)


def _unique(values: list) -> list:
    seen: dict = {}
    for value in values:
        seen.setdefault(_key(value), value)
    out = list(seen.values())
    if len(out) > EXPRESSION_VALUES:
        raise Unread(f"can give more than {EXPRESSION_VALUES:,} values")
    return out


def _truthy(value):
    """True, False, or None where the checker cannot tell."""
    if value is UNKNOWN or value is FROM_SCOPE:
        return None
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return not (value == 0 or (isinstance(value, float) and math.isnan(value)))
    if isinstance(value, str):
        return value != ""
    return True     # an object or an array


def text_of(value, env: Env) -> list:
    """The texts a value gives where GitHub puts it into a string (`${{ }}` in `run`, an argument of `format`).
    An object made into text gives every value `env` holds (the checker reads it the widest way). What a scope the
    checker does not read may give stays `FROM_SCOPE` (flagship slice 2d.19d)."""
    if value is UNKNOWN or value is FROM_SCOPE:
        return [value]
    if value is None:
        return [""]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, (int, float)):
        return [_number_text(value)]
    if isinstance(value, str):
        return [value]
    if value is ENV_OBJECT or value is ALL_VALUES:
        # Made once for each reading of a step (found by the second review: 30 `${{ env }}` over 4,000 values in
        # each of 150 steps).
        if env.every_texts is None:
            env.every_texts = _unique([text_of(v, env)[0] for v in env.every()])
        return env.every_texts
    if isinstance(value, (dict, list)):
        # An object or array from `fromJSON`: its JSON and each text in it.
        leaves: list = []
        _leaves(value, leaves, 0)
        return _unique([json.dumps(value, ensure_ascii=False), *leaves])
    return [UNKNOWN]


def _leaves(value, out: list, depth: int) -> None:
    if depth > MAX_DEPTH or len(out) > EXPRESSION_VALUES:
        raise Unread("holds JSON nested too deeply to read")
    if isinstance(value, dict):
        for item in value.values():
            _leaves(item, out, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _leaves(item, out, depth + 1)
    else:
        out.append(text_of(value, None)[0] if not isinstance(value, (dict, list)) else "")


# --------------------------------------------------------------------------------- the reader
_COMPARE = ("==", "!=", "<=", ">=", "<", ">")
_KNOWN_FUNCTIONS = frozenset({"format", "join", "tojson", "fromjson", "contains", "startswith", "endswith",
                              "hashfiles", "success", "always", "failure", "cancelled"})


class _Reader:
    """A recursive-descent reader of one expression's tokens (`expr.tokens`), giving the values it can have."""

    def __init__(self, toks: list, env: Env) -> None:
        self.toks, self.env, self.pos = toks, env, 0

    def peek(self, k: int = 0):
        i = self.pos + k
        return self.toks[i] if i < len(self.toks) else None

    def op(self, text: str) -> bool:
        """Whether the operator `text` (one or two characters) is next; it is taken if so."""
        for k, ch in enumerate(text):
            if self.peek(k) != ("op", ch):
                return False
        if text in ("<", ">", "!") and self.peek(1) == ("op", "="):
            return False
        if text == "=" or text == "|" or text == "&":
            return False
        self.pos += len(text)
        return True

    def read(self) -> list:
        values = self.or_(0)
        if self.pos != len(self.toks):
            raise Unread("is written in a form the checker does not read")
        return values

    def or_(self, depth: int) -> list:
        left = self.and_(depth)
        while self.op("||"):
            right = self.and_(depth)
            out: list = []
            for value in left:
                truth = _truthy(value)
                if truth is None:
                    out.append(value)
                    out.extend(right)
                elif truth:
                    out.append(value)
                else:
                    out.extend(right)
            left = _unique(out)
        return left

    def and_(self, depth: int) -> list:
        left = self.compare(depth)
        while self.op("&&"):
            right = self.compare(depth)
            out: list = []
            for value in left:
                truth = _truthy(value)
                if value is FROM_SCOPE:
                    # Falsy, what a scope gives is an empty text, or false, 0 or null through `fromJSON` (found by
                    # the review of 2d.19d: `${{ env.DEBUG && 'V=1' || '' }}` can only be `V=1` or empty).
                    out.extend(["", False, 0])
                    out.extend(right)
                elif truth is None:
                    out.append(value)
                    out.extend(right)
                elif truth:
                    out.extend(right)
                else:
                    out.append(value)
            left = _unique(out)
        return left

    def compare(self, depth: int) -> list:
        left = self.unary(depth)
        while True:
            found = next((op for op in _COMPARE if self.op(op)), None)
            if found is None:
                return left
            right = self.unary(depth)
            left = _compared(found, left, right)

    def unary(self, depth: int) -> list:
        if depth > MAX_DEPTH:
            raise Unread("is nested too deeply to read")
        if self.peek() == ("op", "-") and self.peek(1) is not None and self.peek(1)[0] == "num":
            self.pos += 2
            number = _number(self.toks[self.pos - 1][1])
            return [UNKNOWN if number is UNKNOWN else -number]
        if self.op("!"):
            values = self.unary(depth + 1)
            out = []
            for value in values:
                truth = _truthy(value)
                out.extend([True, False] if truth is None else [not truth])
            return _unique(out)
        return self.postfix(depth)

    def postfix(self, depth: int) -> list:
        values = self.primary(depth)
        while True:
            if self.peek() == ("op", ".") and self.peek(1) is not None and self.peek(1)[0] == "id":
                name = self.peek(1)[1]
                self.pos += 2
                values = _unique([v for value in values for v in self.member(value, [name])])
            elif self.peek() == ("op", ".") and self.peek(1) == ("op", "*"):
                self.pos += 2
                values = _unique([ALL_VALUES if value is ENV_OBJECT else value if value is UNKNOWN
                                  or value is FROM_SCOPE else self._star(value) for value in values])
            elif self.op("["):
                keys = self.or_(depth + 1)
                if not self.op("]"):
                    raise Unread("has an index the checker does not read")
                values = _unique([v for value in values for v in self.member(value, keys)])
            else:
                return values

    def _star(self, value):
        if isinstance(value, dict):
            return list(value.values())
        if isinstance(value, list):
            return value
        return None

    def member(self, value, keys: list) -> list:
        """What `value.KEY` or `value[KEY]` gives for each key the index can be."""
        if value is UNKNOWN or value is FROM_SCOPE:
            return [value]
        if len(keys) > EXPRESSION_VALUES:
            raise Unread(f"has an index that can give more than {EXPRESSION_VALUES:,} values")
        if value is ENV_OBJECT:
            out: list = []
            every = False
            for key in keys:
                if isinstance(key, str):
                    out.extend(self.env.lookup(key))
                elif isinstance(key, (int, float)):
                    out.extend(self.env.lookup(_number_text(key)))
                elif key is None:
                    out.append(None)        # `env[null]`, as `env[env.UNSET]`: no name, no value
                else:
                    # A key the checker does not know (another context, an object): any name, once however many
                    # such keys there are (found by the review: 4,000 of them built 16,000,000 values).
                    every = True
                if len(out) > 4 * EXPRESSION_VALUES:
                    out = _unique(out)
            if every:
                out.extend(self.env.every())
            return out
        if value is ALL_VALUES:
            # `env.*[0]`: some value, in an order the checker does not know.
            return self.env.every()
        if isinstance(value, dict):
            out = []
            every = False
            # The fields by their names in upper case, made once for each object (found by the review: 5,000
            # fields read from one object of 5,000 compared every name each time).
            index = self.env.fields.get(id(value))
            if index is None:
                index = {}
                for k, v in value.items():
                    if isinstance(k, str):
                        index.setdefault(k.upper() if k.isascii() else k, []).append(v)
                self.env.fields[id(value)] = index
                self.env.kept.append(value)
            for key in keys:
                if isinstance(key, str) and key.isascii():
                    out.extend(index.get(key.upper()) or [None])
                else:
                    every = True        # a key outside ASCII, or one the checker does not know: any field
            if every:
                out.extend(list(value.values()) + [None])
            return out
        if isinstance(value, list):
            out = []
            every = False
            for key in keys:
                if isinstance(key, (int, float)) and not isinstance(key, bool) and not math.isnan(key) \
                        and not math.isinf(key):
                    # GitHub takes the whole part of a number given as an index (`[1.9]` is `[1]`).
                    n = math.floor(key)
                    out.append(value[n] if 0 <= n < len(value) else None)
                else:
                    every = True
            if every:
                out.extend(list(value) + [None])
            return out
        return [None]       # a field of text, a number, true or null is null

    def primary(self, depth: int) -> list:
        tok = self.peek()
        if tok is None:
            raise Unread("ends where the checker expects a value")
        kind, text = tok
        if kind == "str":
            self.pos += 1
            return [text]
        if kind == "num":
            self.pos += 1
            return [_number(text)]
        if kind == "op" and text == "(":
            self.pos += 1
            values = self.or_(depth + 1)
            if not self.op(")"):
                raise Unread("has a bracket the checker does not see closed")
            return values
        if kind == "id":
            low = text.lower()
            if self.peek(1) == ("op", "("):
                self.pos += 2
                start = self.pos
                args: list = []
                if not self.op(")"):
                    while True:
                        args.append(self.or_(depth + 1))
                        if self.op(")"):
                            break
                        if not self.op(","):
                            raise Unread("has a function call the checker does not read")
                return self.call(low, args, head_reads_env(self.toks[start:self.pos]))
            self.pos += 1
            if low == "env":
                return [ENV_OBJECT]
            if low == "true":
                return [True]
            if low == "false":
                return [False]
            if low == "null":
                return [None]
            if low in ("nan",):
                return [float("nan")]
            if low in ("infinity",):
                return [float("inf")]
            return [UNKNOWN]        # another context: github, inputs, matrix, steps, needs, vars, secrets, ...
        raise Unread("is written in a form the checker does not read")

    def call(self, name: str, args: list, reads_env: bool = False) -> list:
        env = self.env
        if name not in _KNOWN_FUNCTIONS:
            # GitHub's functions are a fixed list; one the checker does not know may make any text of its
            # arguments, so where they read `env` the step is an error of its file.
            if reads_env:
                raise Unread(f"passes what it reads from `env` to a function the checker does not know ({name})")
            return [UNKNOWN]
        if name in ("success", "always", "failure", "cancelled"):
            return [True, False]
        if name == "hashfiles":
            return [UNKNOWN]
        if name in ("contains", "startswith", "endswith"):
            return [True, False]
        if name == "tojson":
            if len(args) != 1:
                return [UNKNOWN]
            out: list = []
            for value in args[0]:
                if value is UNKNOWN or value is FROM_SCOPE:
                    out.append(value)
                elif value is ENV_OBJECT:
                    for table in env.as_dict():
                        out.append(json.dumps(table, ensure_ascii=False, indent=2))
                    out.extend(text_of(ENV_OBJECT, env))
                elif value is ALL_VALUES:
                    out.extend(text_of(ALL_VALUES, env))
                else:
                    try:
                        out.append(json.dumps(value, ensure_ascii=False, indent=2))
                    except (TypeError, ValueError):
                        out.append(UNKNOWN)
            return _unique(out)
        if name == "fromjson":
            if len(args) != 1:
                return [UNKNOWN]
            out = []
            for value in args[0]:
                if isinstance(value, str):
                    # One parse of each text for the whole step, the characters parsed counted (found by the
                    # review: 5,000 references to one 380 KB value parsed it 5,000 times).
                    memo = self.env.parsed
                    if value not in memo:
                        self.env.parse_room -= len(value)
                        if self.env.parse_room < 0:
                            raise Unread(f"gives fromJSON more than {PARSE_TEXT:,} characters to read")
                        try:
                            memo[value] = json.loads(value)
                        except (ValueError, RecursionError):
                            memo[value] = None      # GitHub fails the step: nothing runs
                    out.append(memo[value])
                elif value is ENV_OBJECT or value is ALL_VALUES:
                    raise Unread("passes the whole `env` to fromJSON")
                else:
                    out.append(UNKNOWN if value is UNKNOWN else value)
            return _unique(out)
        if name == "join":
            if not args:
                return [UNKNOWN]
            seps = [s for v in (args[1] if len(args) > 1 else [","]) for s in text_of(v, env)]
            if any(sep is FROM_SCOPE for sep in seps):
                return [FROM_SCOPE]
            out = []
            for value in args[0]:
                if value is ENV_OBJECT or value is ALL_VALUES:
                    # The values joined in the order the workflow writes them, as GitHub keeps them (not checked
                    # on GitHub), and each value on its own.
                    for sep in seps:
                        out.extend(env.joined("" if sep is UNKNOWN else sep))
                    out.extend(text_of(ALL_VALUES, env))
                    continue
                if value is FROM_SCOPE:
                    out.append(FROM_SCOPE)
                    continue
                if isinstance(value, list):
                    pieces = []
                    for item in value:
                        texts = text_of(item, env)
                        if len(texts) != 1:
                            raise Unread("joins values the checker reads more than one way")
                        pieces.append(texts[0])
                    for sep in seps:
                        if UNKNOWN in pieces or sep is UNKNOWN:
                            out.append(UNKNOWN)
                        out.append("".join("" if p is UNKNOWN else p for p in
                                           _interleave(pieces, "" if sep is UNKNOWN else sep)))
                elif value is UNKNOWN:
                    out.extend([UNKNOWN, ""])
                else:
                    out.extend(text_of(value, env))     # join of one value is that value as text
            return _unique(out)
        if name == "format":
            if not args:
                return [UNKNOWN]
            pieces = [[t for v in values for t in text_of(v, env)] for values in args]
            if any(t is FROM_SCOPE for piece in pieces for t in piece):
                # Any text, in the template or an argument: the result may be any text (flagship slice 2d.19d).
                return [FROM_SCOPE]
            count = 1
            for p in pieces:
                count *= len(p)
                if count > EXPRESSION_VALUES:
                    raise Unread(f"can give more than {EXPRESSION_VALUES:,} values")
            out = []
            if UNKNOWN in pieces[0]:
                # A template the checker does not know may give any argument, or all of them together.
                for arg in pieces[1:]:
                    out.extend(arg)
                if all(len(arg) == 1 for arg in pieces[1:]):
                    out.append("".join("" if a[0] is UNKNOWN else a[0] for a in pieces[1:]))
            for choice in _product(pieces):
                if any(p is UNKNOWN for p in choice):
                    out.append(UNKNOWN)
                text = _format("" if choice[0] is UNKNOWN else choice[0],
                               ["" if p is UNKNOWN else p for p in choice[1:]])
                if text is not None:
                    out.append(text)
            return _unique(out or [None])
        return [UNKNOWN]


def _interleave(pieces: list, sep: str) -> list:
    out: list = []
    for n, piece in enumerate(pieces):
        if n:
            out.append(sep)
        out.append(piece)
    return out


def _product(lists: list):
    return itertools.product(*lists)


_FORMAT_RE = re.compile(r"\{\{|\}\}|\{(\d+)\}")


def _format(template: str, args: list) -> str | None:
    """GitHub's `format`: `{N}` is argument N, `{{` and `}}` are braces. None where GitHub fails the step (an
    index with no argument)."""
    out: list = []
    pos = 0
    for match in _FORMAT_RE.finditer(template):
        out.append(template[pos:match.start()])
        token = match.group(0)
        if token == "{{":
            out.append("{")
        elif token == "}}":
            out.append("}")
        else:
            n = int(match.group(1))
            if n >= len(args):
                return None
            out.append(args[n])
        pos = match.end()
    out.append(template[pos:])
    return "".join(out)


def _number(text: str):
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        if text.lower().startswith("0o"):
            return int(text[2:], 8)
        value = float(text)
        return int(value) if value.is_integer() and "." not in text and "e" not in text.lower() else value
    except ValueError:
        return UNKNOWN


def _reads_env(value) -> bool:
    return value is ENV_OBJECT or value is ALL_VALUES


def _compared(op: str, left: list, right: list) -> list:
    """A comparison gives true or false; where both sides are one known text or number it is worked out, as
    GitHub compares them (texts without regard to case), and otherwise it may be either."""
    if len(left) == 1 and len(right) == 1:
        a, b = left[0], right[0]
        if isinstance(a, str) and isinstance(b, str) and op in ("==", "!=") and a.isascii() and b.isascii():
            # GitHub compares texts without regard to case, letter by letter (.NET's ordinal comparison); outside
            # ASCII Python's mapping differs from it (`ß` and `SS`), so there the answer may be either (found by
            # the review of 2d.19).
            same = a.upper() == b.upper()
            return [same if op == "==" else not same]
        if (isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool)
                and not isinstance(b, bool)):
            if any(isinstance(x, float) and math.isnan(x) for x in (a, b)):
                return [op == "!="]
            return [{"==": a == b, "!=": a != b, "<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]]
    return [True, False]


# --------------------------------------------------------------------------------- the text
def head_reads_env(toks: list) -> bool:
    """Whether an expression's tokens hold `env` at the head of a reference (not `matrix.env`, not the text
    'env', not a function's name)."""
    for i, (kind, text) in enumerate(toks):
        if kind == "id" and text.lower() == "env":
            if i and toks[i - 1] == ("op", "."):
                continue
            return True
    return False


def spans(text: str) -> list:
    """(start, end, body) of each `${{ }}` in `text`, ended where GitHub's runner ends it: at the first `}}` that
    is not inside a single-quoted string (`expr.bodies`). An expression with no end is left out (GitHub refuses
    the workflow). Raises `expr.TooComplex` as `expr.bodies` does."""
    out: list = []
    budget = 8 * len(text) + 65536
    start = text.find(expr_mod.OPEN)
    quote_or_close = re.compile(r"'|\}\}")
    while start != -1:
        begin = start + len(expr_mod.OPEN)
        pos, in_string, end = begin, False, -1
        while True:
            match = quote_or_close.search(text, pos)
            budget -= (match.end() if match else len(text)) - pos
            if match is None:
                break
            if match.group(0) == "'":
                in_string = not in_string
                pos = match.end()
            elif in_string:
                pos = match.start() + 1
            else:
                end = match.start()
                break
        if budget < 0:
            raise expr_mod.TooComplex("too many unfinished ${{ expressions to read")
        if end == -1:
            break
        out.append((start, end + 2, text[begin:end]))
        start = text.find(expr_mod.OPEN, end + 2)
    return out


def names_read(text: str):
    """The names the `${{ }}` expressions of `text` read from `env` with `env.NAME` or `env['NAME']`, or None where
    one reads it any other way (`env[x]`, `(env).X`, `toJSON(env)`) or the text cannot be read. Used to keep the
    key of a reading small (found by the third review: a key of the whole `env` for each of 2,000 steps took
    1 GB)."""
    try:
        found = spans(text)
    except expr_mod.TooComplex:
        return None
    names: set = set()
    for _start, _end, body in found:
        toks = expr_mod.tokens(body)
        for i, (kind, word) in enumerate(toks):
            if kind != "id" or word.lower() != "env" or (i and toks[i - 1] == ("op", ".")):
                continue
            nxt = toks[i + 1:i + 4]
            if len(nxt) >= 2 and nxt[0] == ("op", ".") and nxt[1][0] == "id":
                names.add(nxt[1][1])
            elif len(nxt) == 3 and nxt[0] == ("op", "[") and nxt[1][0] == "str" and nxt[2] == ("op", "]"):
                names.add(nxt[1][1])
            else:
                return None
    return names


def relevant(name, names, case: str) -> bool:
    """Whether a scope's entry `name` can give a value to the expressions that read `names` (`names_read`)."""
    if names is None or not isinstance(name, str) or _YAML12_SCALAR.fullmatch(name):
        return True
    if name in names:
        return True
    if case == "exact":
        return False
    return not name.isascii() or any(fold(name) == fold(n) for n in names if isinstance(n, str))


def may_read_env(text: str) -> bool:
    return expr_mod.OPEN in text and _MAY_READ_ENV.search(text) is not None


class Plan:
    """What `put_in` will make of a text, worked out before any of it is made (found by the review of 2d.19:
    readings made first, and counted after, kept 1.2 GB for 600 steps past the workflow's bound): the units of the
    text with the values of their expressions, the characters of values put in in every reading (`size`, which
    the lanes ledger counts as D-138 counts `$NAME`), the characters the text made comes to past the text as
    written (`copies`: the first reading's values, and for each reading past the first its line again with its
    values), the most readings of one line (`readings`), and (start, end) of each expression whose text may hold
    what a scope written as one expression gives (`scoped`, flagship slice 2d.19d)."""

    __slots__ = ("units", "size", "copies", "readings", "scoped")

    def __init__(self, units, size, copies, readings, scoped=()) -> None:
        self.units, self.size, self.copies, self.readings = units, size, copies, readings
        self.scoped = tuple(scoped)


def plan(text: str, env: Env, room: int | None = None) -> Plan:
    """`_plan`, and where it refuses the text (`Unread`), the characters its work came to before it stopped, as the
    refusal's `spent`, so the caller can count them for the workflow too (found by the second review: 300 steps,
    each refused at its own bound, each worked to that bound)."""
    state = [0]
    try:
        return _plan(text, env, room, state)
    except (Unread, NoRoom) as error:
        error.spent = state[0]
        raise


def _plan(text: str, env: Env, room: int | None, state: list) -> Plan:
    """The `Plan` for `text`. Raises `Unread` (its text says why) where the checker does not work an expression
    out, or the readings would pass what it reads for one step; `NoRoom` where the text they make (the copies and
    the values in every reading) would pass `room`, the room left on the workflow's ledger, which is checked as
    the work goes, so a step past it costs little (found by the second review)."""
    room = COPIES_TEXT * 1000 if room is None else room
    whole_room = room
    scoped: list = []
    try:
        found = spans(text)
    except expr_mod.TooComplex as error:
        raise Unread(f"has {error}") from None
    work: list = []
    for start, end, body in found:
        try:
            toks = expr_mod.tokens(body)
        except RecursionError:
            raise Unread("is nested too deeply to read") from None
        if not head_reads_env(toks):
            continue
        try:
            values = _Reader(toks, env).read()
        except Unread as error:
            raise Unread(f"('{_short(text[start:end])}') {error}") from None
        except RecursionError:
            raise Unread(f"('{_short(text[start:end])}') is nested too deeply to read") from None
        texts: list = []
        for value in values:
            texts.extend(text_of(value, env))
        if any(t is FROM_SCOPE for t in texts):
            # GitHub puts in what that scope gives, which the checker does not read: like a value of another
            # context it makes no reading, and the lanes make the step an error where it stands where a command's
            # program goes (flagship slice 2d.19d; before, nothing was said, so `${{ env.AGENT }} -p x` was in no
            # agent lane, with no error).
            scoped.append((start, end))
        known = _unique([t for t in texts if t is not UNKNOWN and t is not FROM_SCOPE])
        # Each value is in at least one reading: what they come to is a floor of what the readings make.
        room -= sum(len(t) for t in known)
        state[0] = whole_room - room
        if room < 0:
            raise NoRoom
        # A value the checker does not know is the expression as written, which the lanes read anyway in the
        # lines as written; where the expression also has values it knows, only those are made into readings, so
        # the default idiom `${{ inputs.k || env.K }}` gives one reading, not two (found by the review: nine of
        # them in one `helm` command were an error).
        work.append((start, end, known or [text[start:end]]))
    if not work:
        return Plan([], 0, 0, 1, scoped)
    units_ = _units(text, [(start, end) for start, end, _texts in work])
    planned: list = []
    size = copies = firsts = 0
    most = 1
    w = 0
    for u_start, u_end in units_:
        here = []
        while w < len(work) and work[w][0] < u_end:
            here.append(work[w])
            w += 1
        if not here:
            continue
        several = [item for item in here if len(item[2]) > 1]
        count = 1
        for item in several:
            count *= len(item[2])
        limit = SINGLE_READINGS if len(several) <= 1 else LINE_READINGS
        if count > limit:
            raise Unread(f"holds expressions that read `env` which together give more than {limit:,} readings of "
                         "one line")
        most = max(most, count)
        # The readings' length, worked out without making them: each holds the line's text outside its
        # expressions, and each value of an expression is in count / (its number of values) of them.
        outside = (u_end - u_start) - sum(end - start for start, end, _texts in here)
        values = first = 0
        for _start, _end, texts in here:
            values += sum(len(t) for t in texts) * (count // len(texts))
            first += len(texts[0])
        size += values
        firsts += first
        # The copies are what the readings past the first make: the line's text outside its expressions again for
        # each, and the values in them (found by the second review: counting only the text outside let 100 lines
        # of five expressions with 1,000-character values make 768 MB). One reading's values are what GitHub puts
        # in, bounded for the workflow like any value (D-138).
        copies += (count - 1) * (outside + 1) + (values - first)
        state[0] = copies + firsts
        if copies > COPIES_TEXT:
            raise Unread(f"holds expressions that read `env` whose readings come to more than {COPIES_TEXT:,} "
                         "characters")
        # What the text made comes to: the first reading's values and the copies (found by the third review:
        # counting every reading's values again gave false errors earlier than D-138 gives them for `$NAME`).
        if copies + firsts > whole_room:
            raise NoRoom
        planned.append((u_start, u_end, here))
    return Plan(planned, size, copies + firsts, most, scoped)


def build(text: str, made: Plan) -> str:
    """The text a `Plan` says: each unit replaced by its readings, one per line."""
    out: list = []
    pos = 0
    for u_start, u_end, here in made.units:
        out.append(text[pos:u_start])
        pos = u_end
        readings = []
        for choice in _product([item[2] for item in here]):
            pieces = []
            at = u_start
            for (start, end, _texts), value in zip(here, choice):
                pieces.append(text[at:start])
                pieces.append(value)
                at = end
            pieces.append(text[at:u_end])
            readings.append("".join(pieces))
        out.append("\n".join(readings))
    out.append(text[pos:])
    return "".join(out)


def put_in(text: str, env: Env) -> tuple:
    """(text, size, readings): `text` with each expression that reads `env` worked out, line by line, the
    characters of values put in, and the most readings made of one line (`plan` and `build`)."""
    made = plan(text, env)
    if not made.units:
        return text, 0, 1
    return build(text, made), made.size, made.readings


def _units(text: str, spans_: list) -> list:
    """(start, end) of each line of `text` that holds a span, joined with the lines a backslash continues and the
    lines a span reaches into, in order; lines with no span are left out."""
    lines: list = []
    pos = 0
    for line in text.split("\n"):
        lines.append([pos, pos + len(line)])
        pos += len(line) + 1
    # Join a line ending in a backslash with the next.
    merged: list = []
    for start, end in lines:
        if merged and text[merged[-1][0]:merged[-1][1]].endswith("\\"):
            merged[-1][1] = end
        else:
            merged.append([start, end])
    out: list = []
    i = 0
    for start, end in spans_:
        while i < len(merged) and merged[i][1] < start:
            i += 1
        if i >= len(merged):
            break
        unit = [merged[i][0], merged[i][1]]
        j = i
        while unit[1] < end and j + 1 < len(merged):
            j += 1
            unit[1] = merged[j][1]
        if out and out[-1][1] >= unit[0]:
            out[-1][1] = max(out[-1][1], unit[1])
        else:
            out.append(unit)
        i = j
    return [tuple(u) for u in out]


def _short(text: str) -> str:
    one = " ".join(text.split())
    return one if len(one) <= 60 else one[:57] + "..."
