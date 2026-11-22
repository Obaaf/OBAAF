"""What text a Groovy value can carry into a command (OBAAF-JEN-009; flagship slice 2d.2).

`judge(node, pipeline)` reads an expression's structure, not its text, and returns the most dangerous untrusted
source the value can carry, as `(shown, severity, root)`, or None when it carries none. `severity` is high, medium
or low (UNTRUSTED in model.py says who controls which value) or `unknown` ("cannot tell": the value comes from
outside the file, such as a caller of a method nothing here calls). Before this slice the rule searched the
interpolation's text for names: a dot before the name (`e.CHANGE_TITLE` after `def e = env`), `env?.X`, a
closure's parameter or a method's return value hid the source, and a ternary choosing literals, `.length()` or
`.toInteger()` were reported. What the reader does not follow it reads the old way, by the names in its text, so
nothing it used to find is lost.
"""

from __future__ import annotations

import re
import time

from obaaf.checker.jenkins.lexer import tokenize
from obaaf.checker.jenkins.parser import (
    Assign, Binary, Block, Call, Closure, Decl, ExprStmt, If, Index, ListLit, Loop, MapLit, MethodDef, Name, Num, Opaque,
    Parser, Prop, Return, Str, Switch, Ternary, Try, Unary, path_of,
)

RANK = {"unknown": 0.5, "low": 1, "medium": 2, "high": 3}

# Methods whose result is a number, a boolean or a digest, whatever text they are called on: the value that reaches
# the command is not the text (`${env.CHANGE_TITLE.length()}`, `${params.COUNT.toInteger()}`).
SAFE_METHODS = {
    "length", "size", "toInteger", "toLong", "toShort", "toBigInteger", "toBigDecimal", "toDouble", "toFloat",
    "isInteger", "isLong", "isShort", "isNumber", "isDouble", "isFloat", "isBigInteger", "isBigDecimal", "isEmpty",
    "isBlank", "isAllWhitespace", "contains", "startsWith", "endsWith", "equals", "equalsIgnoreCase", "matches",
    "hashCode", "compareTo", "compareToIgnoreCase", "indexOf", "lastIndexOf", "count", "asBoolean", "toBoolean",
    "booleanValue", "intValue", "longValue", "any", "every", "isCase", "encodeBase64", "encodeBase64Url",
    "encodeHex", "digest", "md5", "sha256", "containsKey", "containsValue", "keySet",
}
SAFE_CASTS = {"int", "Integer", "long", "Long", "short", "Short", "byte", "Byte", "boolean", "Boolean", "double",
              "Double", "float", "Float", "BigInteger", "BigDecimal", "Number", "java.lang.Integer",
              "java.lang.Long", "java.lang.Boolean", "java.math.BigInteger", "java.math.BigDecimal"}
# Operators whose result is a boolean or a number compared, never the operands' text.
SAFE_OPS = {"==", "!=", "===", "!==", "<", ">", "<=", ">=", "<=>", "&&", "||", "==~", "in", "!in", "instanceof",
            "!instanceof"}
# Iteration methods: a closure given to one of these is called with the receiver's elements (or the receiver).
ITERATORS = {"each", "eachWithIndex", "collect", "collectEntries", "collectMany", "find", "findAll", "findResult",
             "findResults", "any", "every", "with", "tap", "eachLine", "inject", "sum", "groupBy", "sort",
             "unique", "reverseEach", "flatten", "takeWhile", "dropWhile", "split", "eachMatch", "withIndex",
             "indexed", "min", "max", "join", "toSorted", "countBy", "collectNested"}
# pipeline-github's `pullRequest`: fields that are numbers, states or links are not text the change's author wrote;
# the base branch is the repository's own.
PR_SAFE = {"number", "id", "state", "url", "link", "mergeable", "merged", "mergeableState", "draft", "locked",
           "created", "createdAt", "updated", "updatedAt", "closed", "closedAt", "commitCount", "additions",
           "deletions", "changedFiles", "isDraft"}
PR_LOW = {"base", "baseRef"}
# A whitelist regular expression whose replacement leaves only these characters cannot carry shell syntax.
_SAFE_CLASS = re.compile(r"\[\^((?:A-Z|a-z|0-9|\\w|\\d|[A-Za-z0-9._@:+,/]|\\[.\-_/])+-?)\]([+*]?)")
_SAFE_REPLACEMENT = re.compile(r"[A-Za-z0-9._\-@:+,/]*")

_EXPR_CACHE: dict = {}


def worst(*results):
    best = None
    for r in results:
        if r is not None and (best is None or RANK[r[1]] > RANK[best[1]]):
            best = r
    return best


def parse_expr(text: str):
    """The node of an interpolation's text, or None when the parser cannot read it."""
    if text in _EXPR_CACHE:
        return _EXPR_CACHE[text]
    node = None
    body = text.strip()
    if body.startswith("->"):          # ${-> value}: a closure Groovy calls when it builds the string
        body = body[2:]
    try:
        deadline = time.monotonic() + 1.0
        parser = Parser(tokenize(body, deadline), deadline)
        parser.skip_nl()
        node = parser.expr()
        parser.skip_nl()
        if not parser.at("eof"):
            node = None
    except Exception:              # noqa: BLE001 -- any failure falls back to reading the names in the text
        node = None
    if len(_EXPR_CACHE) > 20000:
        _EXPR_CACHE.clear()
    _EXPR_CACHE[text] = node
    return node


def _shown(name: str, root: str) -> str:
    return name if name == root else f"{name} (from {root})"


def _tainted(p, name: str, shown: str | None = None):
    hit = p.tainted.get(name)
    if hit is None:
        return None
    root, severity = hit
    return (_shown(shown or name, root), severity, root)


class Judge:
    """One judgement of a value, with a budget: past it, the rest is read by the names in its text."""

    def __init__(self, p, budget: int = 4000, function_params: set | None = None):
        self.p = p
        self.budget = budget
        self.stack: list = []
        # The parameters of the uncalled method a step is in: only those come from outside the file. None while the
        # pipeline is walked, when any parameter of an uncalled method counts.
        self.function_params = function_params
        self.depth = 0
        self.cut = False          # some part was read by the names in its text, past a limit
        self.recursed = False     # a method's result was cut where it called itself

    # ---------------------------------------------------------------- entry points
    def value(self, node, scope: dict | None = None):
        # Deeply nested values (a chain of 2,000 calls) are read by the names in their text, which is iterative: the
        # structural reading must not exhaust the stack (the first review of slice 2d.2).
        if self.depth > 150:
            from obaaf.checker.jenkins import model as m
            self.cut = True
            return self.by_text(m.source_texts(node)) if node is not None else None
        self.depth += 1
        try:
            return self._value(node, scope)
        finally:
            self.depth -= 1

    def _value(self, node, scope: dict | None = None):
        from obaaf.checker.jenkins import model as m
        self.budget -= 1
        self.p.judge_budget -= 1
        if node is None:
            return None
        if self.budget <= 0 or self.p.judge_budget <= 0 or len(self.stack) > 40:
            # Past the reader's budget for this value or this file, the rest is read by the names in its text and
            # is at least "cannot tell", never a pass (the second review of slice 2d.2).
            self.cut = True
            return worst(self.by_text(m.source_texts(node)),
                         ("a value larger than the checker reads", "unknown",
                          "a value or file larger than the checker reads value by value"))
        cast = getattr(node, "cast_type", None)
        if cast in SAFE_CASTS:
            return None
        scope = scope or {}
        if isinstance(node, Str):
            return worst(*(self.text(e, scope) for e in node.exprs))
        if isinstance(node, (Num,)):
            return None
        if isinstance(node, Name):
            return self.name(node.name, scope)
        if isinstance(node, Prop):
            return self.prop(node, scope)
        if isinstance(node, Index):
            return self.index(node, scope)
        if isinstance(node, Call):
            return self.call(node, scope)
        if isinstance(node, Binary):
            if node.op in SAFE_OPS:
                return None
            if node.op == "as":
                if getattr(node.right, "type_name", None) in SAFE_CASTS:
                    return None
                return self.value(node.left, scope)
            # A long chain (`a + b + ... + z`) is read iteratively, so it cannot exhaust the stack.
            leaves, todo = [], [node]
            while todo:
                n = todo.pop()
                if isinstance(n, Binary) and n.op not in SAFE_OPS and n.op != "as" and \
                        getattr(n, "cast_type", None) is None:
                    todo += [n.right, n.left]
                else:
                    leaves.append(n)
            return worst(*(self.value(x, scope) for x in leaves))
        if isinstance(node, Ternary):
            return worst(self.value(node.then, scope), self.value(node.otherwise, scope))
        if isinstance(node, Unary):
            if node.op == "!":
                return None
            return self.value(node.operand, scope)
        if isinstance(node, ListLit):
            return worst(*(self.value(x, scope) for x in node.items))
        if isinstance(node, MapLit):
            return worst(*(self.value(v, scope) for _, v in node.entries),
                         *(self.value(k, scope) for k, _ in node.entries if not isinstance(k, str)))
        if isinstance(node, Closure):
            return self.block_result(node.body, scope)
        if isinstance(node, Opaque):
            return None
        return self.by_text(m.source_texts(node))

    def text(self, expr_text: str, scope: dict):
        if not expr_text.strip():
            return None                                  # "${}" is null
        node = parse_expr(expr_text)
        if node is None:
            # An interpolation the parser cannot read (a comment holding a brace, Groovy it does not know): read by
            # the names in its text, and "cannot tell" when that finds none (flagship slice 2d.2).
            return self.by_text([expr_text]) or (
                "an interpolation the checker cannot read", "unknown",
                f"an interpolation the checker cannot read (${{{expr_text[:60]}}})")
        cut, self.cut = self.cut, False
        found = self.value(node, scope)
        if self.cut:
            # Past a limit the structure was not read to the end: the interpolation's whole text is read the old way
            # as well, so nothing found before is lost.
            found = worst(found, self.by_text([expr_text]))
        self.cut = self.cut or cut
        return found

    def by_text(self, texts: list):
        from obaaf.checker.jenkins import model as m
        found = m.untrusted_source([t for t in texts if t], self.p)
        if found is None:
            return None
        return (found[0], found[1], found[0])

    # ---------------------------------------------------------------- names and paths
    def name(self, name: str, scope: dict):
        from obaaf.checker.jenkins import model as m
        p = self.p
        if name in scope:
            return scope[name]
        if name in ("true", "false", "null", "this"):
            return None
        if name in m.UNTRUSTED:
            return (name, m.UNTRUSTED[name], name)
        hit = _tainted(p, name)
        if hit is not None:
            return hit
        if name in p.caller_values:
            return (name, "unknown", p.caller_values[name])
        if name in p.string_params and name not in p.safe_params:
            return (f"parameter {name}", "medium", f"parameter {name}")
        if name in p.method_params and (self.function_params is None or name in self.function_params):
            return (name, "unknown", "a value passed in by a method's caller outside this file")
        if name == "params" or name in p.param_aliases:
            return ("params", "medium", "params")
        return None

    def env_key(self, key: str):
        from obaaf.checker.jenkins import model as m
        hit = m.UNTRUSTED_FOLDED.get(key.lower())
        if hit is not None:
            return (hit[0], hit[1], hit[0])
        hit = _tainted(self.p, key)
        if hit is not None:
            return hit
        if key in self.p.string_params and key not in self.p.safe_params:
            return (f"parameter {key}", "medium", f"parameter {key}")     # a parameter is an environment variable
        if key in self.p.caller_values:
            return (f"env.{key}", "unknown", self.p.caller_values[key])
        if self.p.env_any is not None:
            return (f"env.{key}", self.p.env_any[1], self.p.env_any[0])
        return None

    def param_key(self, key: str):
        if key in self.p.safe_params:
            return None
        return (f"params.{key}", "medium", f"params.{key}")

    def root_kind(self, node) -> str | None:
        """env, params or None: what a receiver is, through aliases and `getEnvironment()`."""
        p = self.p
        if isinstance(node, Name):
            # A method's own parameter or variable named env or params is not the build's (2d.2).
            if node.name == "env" or node.name in p.env_aliases:
                return "env"
            if node.name == "params" or node.name in p.param_aliases:
                return "params"
            return None
        if isinstance(node, Prop) and isinstance(node.target, Name) and (
                node.target.name in ("this", "binding", "script", "steps") or node.target.name in p.script_vars):
            return "env" if node.name == "env" else "params" if node.name == "params" else None
        if isinstance(node, Prop) and path_of(node) == "currentBuild.buildVariables":
            return "params"
        if isinstance(node, Call) and isinstance(node.callee, Prop):
            if node.callee.name in ("getEnvironment", "getOverriddenEnvironment") and not node.args and \
                    self.root_kind(node.callee.target) == "env":
                return "env"
            if node.callee.name == "getenv" and not node.args and path_of(node.callee.target) in (
                    "System", "java.lang.System"):
                return "env"
        if isinstance(node, Prop) and node.name in ("environment", "overriddenEnvironment") and \
                self.root_kind(node.target) == "env":
            return "env"
        return None

    def key_of(self, node, scope: dict):
        """A key given as a literal or a variable that only ever holds one literal; "" when computed."""
        from obaaf.checker.jenkins import model as m
        lit = m.literal(node)
        if lit is not None:
            return lit
        if isinstance(node, Name) and node.name not in scope:
            seen = self.p.literal_values.get(node.name)
            if seen and len(seen) == 1 and node.name not in self.p.nonliteral_names:
                return next(iter(seen))
            if node.name in self.p.key_lists:
                return self.p.key_lists[node.name]
        return ""

    def keyed(self, kind: str, key, where: str):
        if isinstance(key, list):                     # a loop over a literal list of names
            return worst(*(self.keyed(kind, k, where) for k in key))
        if not key:
            return (f"a computed name in {where}", "unknown",
                    f"a value read from {kind} under a name the file computes")
        return self.env_key(key) if kind == "env" else self.param_key(key)

    def prop(self, node: Prop, scope: dict):
        p = self.p
        kind = self.root_kind(node.target)
        if kind is not None:
            name = node.name
            if "${" in name:                           # env."${n}"
                inner = parse_expr(name[2:-1]) if name.startswith("${") and name.endswith("}") else None
                return self.keyed(kind, self.key_of(inner, scope) if inner is not None else "", f"{kind}.\"...\"")
            return self.env_key(name) if kind == "env" else self.param_key(name)
        whole = self.root_kind(node)
        if whole is not None:
            return self.whole(whole)
        path = path_of(node)
        if path:
            parts = path.split(".")
            root = parts[0]
            if root in ("this", "binding") and len(parts) == 2:
                return self.name(parts[1], scope)
            if root == "pullRequest" and "pullRequest" not in p.local_names and len(parts) > 1:
                field_ = parts[1]
                if field_ in PR_SAFE:
                    return None
                severity = "low" if field_ in PR_LOW else "high"
                return (f"pullRequest.{field_}", severity, f"pullRequest.{field_}")
            if root == "currentBuild" and "currentBuild" not in p.local_names and len(parts) > 1:
                if parts[1] in ("changeSets", "rawBuild", "buildCauses", "upstreamBuilds"):
                    shown = "commit text (currentBuild.changeSets)" if parts[1] == "changeSets" else \
                        f"build cause text (currentBuild.{parts[1]})"
                    return (shown, "high", shown)
            for i in range(len(parts), 0, -1):         # m.title = x; "${m.title}", and "${m.anything}" for m
                hit = _tainted(p, ".".join(parts[:i]))
                if hit is not None:
                    return hit
            if root in scope:
                return scope[root]
            hit = self.name(root, scope) if len(parts) > 1 else None
            if hit is not None:
                return hit
            return None
        return self.value(node.target, scope)

    def index(self, node: Index, scope: dict):
        kind = self.root_kind(node.target)
        if kind is not None:
            return self.keyed(kind, self.key_of(node.index, scope), f"{kind}[...]")
        return worst(self.value(node.target, scope), self.value(node.index, scope)
                     if not isinstance(node.index, (Num, Str)) else None)

    # ---------------------------------------------------------------- calls
    def whole(self, kind: str):
        """Every build parameter, or every environment variable (`env.getEnvironment()`, `System.getenv()`)."""
        if kind == "params":
            return ("params", "medium", "params")
        return ("every environment variable", "high", "every environment variable")

    def call(self, node: Call, scope: dict):
        from obaaf.checker.jenkins import model as m
        p = self.p
        callee = node.callee
        whole = self.root_kind(node)
        if whole is not None:
            return self.whole(whole)
        if isinstance(callee, Prop) and isinstance(callee.target, Name) and callee.target.name in (
                "this", "steps") and callee.name in p.method_defs:
            return self.method_result(callee.name, node, scope)     # this.length(x): the file's own method
        if isinstance(callee, Prop):
            method = callee.name
            if method in SAFE_METHODS:
                return None
            target_kind = self.root_kind(callee.target)
            if target_kind is not None and method in ("get", "getProperty", "getAt", "getOrDefault") and node.args:
                found = self.keyed(target_kind, self.key_of(node.args[0], scope), f"{target_kind}.{method}(...)")
                return worst(found, *(self.value(a, scope) for a in node.args[1:]))
            if method == "getenv" and node.args and path_of(callee.target) in ("System", "java.lang.System"):
                return self.keyed("env", self.key_of(node.args[0], scope), "System.getenv(...)")
            if method == "replaceAll" and len(node.args) == 2 and self.whitelist(node.args):
                return None
            if path_of(callee.target) in ("URLEncoder", "java.net.URLEncoder") and method == "encode":
                return None
            if path_of(callee) in ("currentBuild.getBuildCauses", "currentBuild.rawBuild.getCauses",
                                   "currentBuild.rawBuild.getCause", "currentBuild.getRawBuild"):
                shown = "build cause text (currentBuild.getBuildCauses())"
                return (shown, "high", shown)
            if path_of(callee) in ("currentBuild.getChangeSets",):
                return ("commit text (currentBuild.changeSets)", "high", "commit text (currentBuild.changeSets)")
            if isinstance(callee.target, Name) and callee.target.name in ("this", "steps") and \
                    callee.name in p.method_defs:
                return self.method_result(callee.name, node, scope)
        name = m.callee_name(node) or ""
        bare = name.removeprefix("steps.").removeprefix("this.")
        if bare in ("getProperty", "binding.getVariable", "binding.getProperty", "getVariable") and node.args:
            key = self.key_of(node.args[0], scope)       # getProperty('CHANGE_TITLE') on the script
            keys = key if isinstance(key, list) else [key]
            if not all(keys):
                return ("a computed name in getProperty(...)", "unknown", "a value read under a name the file computes")
            return worst(*(worst(self.name(k, scope), self.env_key(k) if k.lower() in m.UNTRUSTED_FOLDED else None)
                           for k in keys))
        if bare in m.SHELL_STEPS:
            return self.shell_output(node)
        if bare == "input":
            asks = m.named_arg(node, "parameters") is not None or m.named_arg(node, "submitterParameter") is not None
            return ("an input step's answer", "medium", "an input step's answer") if asks else None
        if isinstance(callee, Name) and callee.name in p.method_defs and callee.name not in scope:
            return self.method_result(callee.name, node, scope)
        parts = []
        if isinstance(callee, Prop):
            parts.append(self.value(callee.target, scope))
        elif not isinstance(callee, Name):
            parts.append(self.value(callee, scope))
        elif callee.name in scope or callee.name in p.tainted:   # a closure variable called: what it returns
            parts.append(self.name(callee.name, scope))
        parts += [self.value(a, scope) for a in node.args]
        parts += [self.value(v, scope) for _, v in node.named]
        if node.closure is not None:
            inner = dict(scope)
            given = self.value(callee.target, scope) if isinstance(callee, Prop) else None
            for param in (node.closure.params or ["it"]):
                if isinstance(param, str):
                    inner[param] = given
            parts.append(self.block_result(node.closure, inner))
        return worst(*parts)

    def whitelist(self, args) -> bool:
        from obaaf.checker.jenkins import model as m
        pattern = args[0]
        text = pattern.text() if isinstance(pattern, Str) and not pattern.interpolated else None
        repl = m.literal(args[1])
        if text is None or repl is None:
            return False
        return bool(_SAFE_CLASS.fullmatch(text)) and bool(_SAFE_REPLACEMENT.fullmatch(repl))

    def shell_output(self, node: Call):
        from obaaf.checker.jenkins import model as m
        if not m._truthy_node(m.named_arg(node, "returnStdout")):
            return None
        script = m.shell_script(node)
        if isinstance(script, Str):
            return m.git_output(script.text())
        texts = m.source_texts(script) if script is not None else []
        if any("git" in t for t in texts):
            return ("output of a git command the checker cannot read", "unknown", "git output")
        return None

    def method_result(self, name: str, call: Call, scope: dict):
        """What a method of this file returns, with its parameters given what the call passes."""
        if name in self.stack:
            self.recursed = True                         # a method calling itself: the cycle adds nothing new
            return None
        if len(self.stack) > 12:
            from obaaf.checker.jenkins import model as m
            # Past twelve methods deep the result is not followed: the names in the call's text, else cannot tell.
            return self.by_text(m.source_texts(call)) or (
                f"the result of {name}()", "unknown", "a chain of methods deeper than the checker follows")
        defs = self.p.method_defs.get(name) or []
        if not defs:
            return None
        mdef = next((d for d in defs if len(d.params) == len(call.args)), defs[0])
        args = [self.value(a, scope) for a in call.args]
        named = worst(*(self.value(v, scope) for _, v in call.named))
        # A method's result depends on what it is given and on the state of the names its body (and the methods it
        # calls) can read: worked out once for each (the first two reviews of slice 2d.2: helpers that each call the
        # next twice took seconds). A result computed under a cut (recursion, a budget) is not kept.
        memo_key = (name, tuple(args), named, frozenset(self.function_params or ()), self.state_of(name))
        hit = self.p.judge_cache.get(memo_key)
        if hit is not None:
            return hit[0]
        inner: dict = {}
        params = [x for x in mdef.params if isinstance(x, str)]
        for i, param in enumerate(params):
            if i == 0 and call.named and not call.args:
                inner[param] = named
            elif i == len(params) - 1 and len(args) > len(params):
                inner[param] = worst(*args[i:])       # varargs: the rest
            else:
                inner[param] = args[i] if i < len(args) else None
        cut_before, recursed_before = self.cut, self.recursed
        self.cut = self.recursed = False
        self.stack.append(name)
        try:
            result = self.block_result(mdef.body, inner)
        finally:
            self.stack.pop()
        clean = not (self.cut or self.recursed)
        self.cut, self.recursed = self.cut or cut_before, self.recursed or recursed_before
        if clean:
            if len(self.p.judge_cache) > 50000:
                self.p.judge_cache.clear()
            self.p.judge_cache[memo_key] = (result,)
        return result

    def state_of(self, name: str) -> tuple:
        """The state a method's result can depend on: what is recorded for every word its body and the methods it
        calls contain, and the sizes of the pipeline's other records."""
        p = self.p
        words = _method_words(p, name)
        state = []
        for w in words:
            entry = (p.tainted.get(w), p.caller_values.get(w), w in p.env_aliases, w in p.param_aliases,
                     w in p.script_vars, w in p.string_params, w in p.safe_params, w in p.method_params,
                     w in p.nonliteral_names, tuple(sorted(p.literal_values.get(w, ()))),
                     tuple(p.key_lists.get(w, ())))
            if any(entry):
                state.append((w, entry))
        return tuple(sorted(state, key=lambda x: x[0])), p.env_any

    def block_result(self, block: Block | None, scope: dict):
        """Every value a block can return: `return` statements and the last expression."""
        if block is None:
            return None
        results = []
        local = dict(scope)
        for value in _returned(block, local):
            results.append(self.value(value, local))
        return worst(*results)


def _method_words(p, name: str) -> frozenset:
    """Every identifier, property name and literal in a method of the file and in the methods it calls, transitively:
    the names whose recorded taint its result can depend on."""
    cache = p.judge_words
    if name in cache:
        return cache[name]
    cache[name] = frozenset()                     # a cycle reads as what is found so far
    words: set = set()
    todo, seen = [name], set()
    while todo:
        n = todo.pop()
        if n in seen:
            continue
        seen.add(n)
        for d in p.method_defs.get(n, []):
            for node in _walk(d.body):
                if isinstance(node, Name):
                    words.add(node.name)
                    if node.name in p.method_defs:
                        todo.append(node.name)
                elif isinstance(node, Prop):
                    words.add(node.name)
                    if node.name in p.method_defs:
                        todo.append(node.name)
                elif isinstance(node, Str):
                    words.add(node.text())
                    for e in node.exprs:
                        words.update(re.findall(r"[A-Za-z_]\w*", e))
    result = frozenset(words)
    cache[name] = result
    return result


def _walk(node, limit: int = 200_000):
    from obaaf.checker.jenkins.model import find_nodes
    return find_nodes(node, lambda n: isinstance(n, (Name, Prop, Str)), limit=limit)


def _returned(block: Block, local: dict, depth: int = 0) -> list:
    """The values a block returns, not looking into closures or methods it defines. Local declarations are
    left to the pipeline's own record of variables."""
    out: list = []
    if depth > 20 or block is None:
        return out
    stmts = block.stmts
    for i, stmt in enumerate(stmts):
        last = i == len(stmts) - 1
        if isinstance(stmt, Return) and not stmt.throw and stmt.value is not None:
            out.append(stmt.value)
        elif isinstance(stmt, ExprStmt) and last:
            out.append(stmt.expr)
        elif isinstance(stmt, If):
            out += _returned(stmt.then, local, depth + 1)
            if stmt.otherwise is not None:
                out += _returned(stmt.otherwise, local, depth + 1)
        elif isinstance(stmt, (Loop,)):
            out += _returned(stmt.body, local, depth + 1)
        elif isinstance(stmt, Try):
            out += _returned(stmt.body, local, depth + 1)
            for h in stmt.handlers:
                out += _returned(h, local, depth + 1)
        elif isinstance(stmt, Switch):
            for case in stmt.cases:
                out += _returned(case, local, depth + 1)
        elif isinstance(stmt, (Decl, Assign)) and last and stmt.value is not None:
            out.append(stmt.value)                     # a method whose last statement assigns returns the value
        elif isinstance(stmt, MethodDef):
            continue
    return out


def judge(node, p, scope: dict | None = None):
    return Judge(p).value(node, scope)
