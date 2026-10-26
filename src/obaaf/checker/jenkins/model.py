"""A pipeline model built from the syntax tree: stages, steps and the context of each step.

For every step it records the stage it belongs to, the credentials bound around it,
the agent it runs on, the post condition it runs under, and whether the stage can run
for a change request (a pull request in a multibranch or organization-folder job).
That last question comes from `when` conditions in Declarative Pipeline, and from simple
`if (env.CHANGE_ID)` and `BRANCH_NAME` tests in Scripted Pipeline. Anything the model
cannot settle is recorded as unknown, never as safe (Jenkins design, section 5).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace

from obaaf.checker.jenkins.parser import (
    Annotated, Assign, Binary, Block, Call, Closure, Decl, ExprStmt, If, Index, ListLit, Loop, MapLit,
    MethodDef, ClassDef, Name, Opaque, Prop, Return, Str, Switch, Ternary, Try, Unary, callee_name, path_of,
)

# Change-request reachability of a stage.
CR_YES = "yes"            # the stage runs only, or also, for change requests
CR_POSSIBLE = "possible"  # nothing keeps change requests out (they run it if the job builds them)
CR_NO = "no"              # a condition keeps change requests out
CR_UNKNOWN = "unknown"    # a condition the model cannot evaluate

SHELL_STEPS = {"sh", "bat", "powershell", "pwsh"}
CONTROLLER_LABELS = {"master", "built-in"}
_SECTIONS = {"agent", "environment", "options", "parameters", "triggers", "tools", "libraries", "stages",
             "post", "when", "input", "steps", "parallel", "matrix", "axes", "axis", "excludes", "exclude",
             "failFast"}


@dataclass(frozen=True)
class Binding:
    """Credentials made available to the steps inside a scope."""
    ids: tuple            # literal credential ids ("?" when computed)
    variables: tuple      # variable names that hold the secret
    how: str              # withCredentials, environment, sshagent, ...
    line: int
    origin: str           # pipeline, stage '<name>', or a wrapper
    paths: tuple = ()     # variables that hold the path of a file with the secret, not the secret itself


@dataclass
class Agent:
    kind: str             # any, none, label, docker, dockerfile, kubernetes, node, unknown
    label: str | None = None
    image: str | None = None
    image_dynamic: bool = False
    args: str = ""
    yaml: str | None = None
    yaml_file: str | None = None
    inherit: str | None = None
    images: list = field(default_factory=list)   # (image, line) from pod templates
    line: int = 0
    yaml_ref: str | None = None    # a variable or call that holds the pod spec ("" when not a name)
    from_step: bool = False        # docker.image(...).inside or withDockerContainer: the image is a step argument


@dataclass(frozen=True)
class Ctx:
    stage: tuple = ()
    creds: tuple = ()
    cr: str = CR_POSSIBLE
    cr_line: int = 0              # the condition that made `cr` unknown, for the report
    post: str | None = None       # post condition, or "catch/finally" for a Scripted failure handler
    in_script: bool = False
    agent: Agent | None = None
    lane: str | None = None
    lane_line: int = 0
    in_function: str | None = None
    swallowed: str | None = None  # catchError, warnError or a catch block: its failure does not stop the build
    branch: tuple = ()            # ((parallel line, branch name), ...): steps in sibling branches run concurrently
    guards: tuple = ()            # conditions (as text) that must hold for the step to run


@dataclass
class StepUse:
    name: str
    call: Call
    ctx: Ctx
    line: int


@dataclass
class Library:
    name: str
    version: str | None
    dynamic: bool
    how: str
    line: int
    exprs: tuple = ()


@dataclass
class Approval:
    submitter: str | None
    line: int
    ctx: Ctx


@dataclass
class Trigger:
    name: str             # GenericTrigger, ghprbTrigger, gitlab, ...
    line: int
    change_requests: bool  # starts the pipeline for pull or merge requests
    token: str | None = None  # a literal webhook token written in the file


@dataclass
class Pipeline:
    kind: str = "scripted"
    steps: list = field(default_factory=list)
    agents: list = field(default_factory=list)          # (Agent, Ctx)
    libraries: list = field(default_factory=list)
    approvals: list = field(default_factory=list)
    env_values: dict = field(default_factory=dict)      # name -> Str node (literal environment values)
    tainted: dict = field(default_factory=dict)         # variable -> (source, severity)
    string_params: set = field(default_factory=set)
    docker_vars: set = field(default_factory=set)
    local_names: set = field(default_factory=set)       # variables, methods and classes the file defines
    method_params: set = field(default_factory=set)     # parameters of methods: their values come from callers
    opaque: list = field(default_factory=list)          # (line, what)
    triggers: list = field(default_factory=list)        # Trigger: SCM and webhook triggers named in the file
    literals: dict = field(default_factory=dict)        # variable -> Str assigned to it (last assignment)


# ----------------------------------------------------------------------- helpers
def chain_name(node) -> str | None:
    """`docker.image.inside` for docker.image('x').inside(...): a call chain with the calls removed."""
    parts = []
    while True:
        if isinstance(node, Name):
            parts.append(node.name)
            break
        if isinstance(node, Prop):
            parts.append(node.name)
            node = node.target
        elif isinstance(node, Call):
            node = node.callee
        elif isinstance(node, Index):
            node = node.target
        else:
            break
    return ".".join(reversed(parts)) if parts else None


def children(node) -> list:
    """The direct child nodes of any syntax node, for generic walks."""
    if isinstance(node, Call):
        out = [node.callee] + list(node.args) + [v for _, v in node.named]
        return out + ([node.closure] if node.closure is not None else [])
    if isinstance(node, Block):
        return list(node.stmts)
    if isinstance(node, ExprStmt):
        return [node.expr]
    if isinstance(node, (Decl, Return)):
        return [node.value] if node.value is not None else []
    if isinstance(node, Assign):
        return [node.target, node.value]
    if isinstance(node, ListLit):
        return list(node.items)
    if isinstance(node, MapLit):
        return [k for k, _ in node.entries if not isinstance(k, str)] + [v for _, v in node.entries]
    if isinstance(node, Closure):
        return [node.body]
    if isinstance(node, If):
        return [node.cond, node.then] + ([node.otherwise] if node.otherwise is not None else [])
    if isinstance(node, Loop):
        return list(node.header) + [node.body]
    if isinstance(node, Try):
        return [node.body] + list(node.handlers)
    if isinstance(node, Switch):
        return [node.subject] + list(node.cases)
    if isinstance(node, (MethodDef, ClassDef)):
        return [node.body]
    if isinstance(node, Annotated):
        return list(node.args) + [v for _, v in node.named] + ([node.target] if node.target is not None else [])
    if isinstance(node, Binary):
        return [node.left, node.right]
    if isinstance(node, Unary):
        return [node.operand]
    if isinstance(node, Ternary):
        return [node.cond, node.then, node.otherwise]
    if isinstance(node, Prop):
        return [node.target]
    if isinstance(node, Index):
        return [node.target, node.index]
    return []


def find_nodes(node, match, limit: int = 2_000_000):
    """Every node under `node` for which match(node) is true, depth first. Iterative and bounded."""
    stack = [node]
    seen = 0
    while stack and seen < limit:
        n = stack.pop()
        seen += 1
        if n is None:
            continue
        if match(n):
            yield n
        stack += reversed(children(n))


def named_arg(call: Call, key: str):
    for name, value in call.named:
        if name == key:
            return value
    return None


def literal(node) -> str | None:
    """The text of a string literal without interpolation, else None."""
    if isinstance(node, Str) and not node.interpolated:
        return node.text()
    return None


def text_of(node) -> str | None:
    """A string's text with interpolations shown as ${...}; None when not a string."""
    if isinstance(node, Str):
        return node.text()
    return None


def first_arg(call: Call):
    return call.args[0] if call.args else None


def iter_closure_bodies(node):
    """Closures passed as arguments, list items or map values (parallel(a: {...}))."""
    if isinstance(node, Closure):
        yield node.body
    elif isinstance(node, ListLit):
        for item in node.items:
            yield from iter_closure_bodies(item)
    elif isinstance(node, MapLit):
        for _, value in node.entries:
            yield from iter_closure_bodies(value)


def shell_script(call: Call):
    """The script node of an sh/bat/powershell step: `sh 'x'`, `sh(script: "x")`."""
    node = named_arg(call, "script")
    if node is None:
        node = first_arg(call)
        if isinstance(node, MapLit):
            for key, value in node.entries:
                if key == "script":
                    return value
            return None
    return node


def all_strings(node):
    """Every string literal inside an expression."""
    if isinstance(node, Str):
        yield node
    elif isinstance(node, (ListLit,)):
        for item in node.items:
            yield from all_strings(item)
    elif isinstance(node, MapLit):
        for _, value in node.entries:
            yield from all_strings(value)
    elif isinstance(node, Call):
        for arg in node.args:
            yield from all_strings(arg)
        for _, value in node.named:
            yield from all_strings(value)
    elif isinstance(node, Binary):
        yield from all_strings(node.left)
        yield from all_strings(node.right)
    elif isinstance(node, Ternary):
        yield from all_strings(node.then)
        yield from all_strings(node.otherwise)


# ------------------------------------------------------------------ change requests
# A git command, allowing global options before the subcommand: git -C dir log, git --no-pager log.
_GIT_PREFIX = r"\bgit(?:\s+(?:-C\s+\S+|-c\s+\S+|--[\w-]+(?:=\S+)?|-[a-zA-Z]))*\s+"
_GIT_TEXT_CMD = re.compile(_GIT_PREFIX + r"(log|show|cat-file\s+commit|rev-list\s+--format)\b")
_GIT_FORMAT = re.compile(r"--(?:format|pretty)[= ](?:(['\"])(.*?)\1|(\S+))")
# Placeholders whose output is a hash or a date, never text a person wrote.
_GIT_SAFE_PLACEHOLDERS = re.compile(r"%(H|h|T|t|P|p|ct|at|cd|ad|ci|ai|cI|aI|cs|as|n|%)")
GIT_PUSH = re.compile(r"(^|[\s;&|(])" + _GIT_PREFIX[2:] + r"push\b|(^|[\s;&|(])gh\s+pr\s+merge\b", re.M)


def git_text(script: str) -> bool:
    """Whether a git command in the script prints commit text (subject, body, author name)."""
    for line in script.splitlines():
        if not _GIT_TEXT_CMD.search(line):
            continue
        fmt = _GIT_FORMAT.search(line)
        if fmt is None:
            return True
        spec = fmt.group(2) if fmt.group(1) else fmt.group(3)
        spec = re.sub(r"^(t?format:)", "", spec)
        if spec in ("oneline", "short", "medium", "full", "fuller", "reference", "email", "raw") or \
                _GIT_SAFE_PLACEHOLDERS.sub("", spec).count("%"):
            return True
    return False


_CHANGE_VARS = re.compile(r"\b(?:env\.)?(?:CHANGE_(?:ID|TARGET|BRANCH|TITLE|AUTHOR\w*|URL|FORK)|gitlabMergeRequest\w*|"
                          r"gitlabActionType|ghprb\w+)\b")
_BRANCH_VAR = re.compile(r"\b(?:env\.)?(?:BRANCH_NAME|TAG_NAME|GIT_BRANCH)\b")
# BRANCH_NAME of a change request in a multibranch job.
_CR_BRANCH_SAMPLES = ("PR-1", "PR-42", "PR-9001")


def _combine_all(values: list[str]) -> str:
    if not values:
        return CR_POSSIBLE
    if CR_NO in values:
        return CR_NO
    if CR_YES in values:
        return CR_YES
    if CR_UNKNOWN in values:
        return CR_UNKNOWN
    return CR_POSSIBLE


def _combine_any(values: list[str]) -> str:
    if not values:
        return CR_POSSIBLE
    if CR_YES in values:
        return CR_YES
    if all(v == CR_NO for v in values):
        return CR_NO
    if CR_UNKNOWN in values:
        return CR_UNKNOWN
    return CR_POSSIBLE


# A condition evaluates to (reach, full): reach is one of the CR_* values; full is True when the
# condition holds for every change request, so that its negation keeps all of them out. A filtered
# test such as changeRequest(author: 'bot') is not full: `not` of it still lets other changes in.
def _all(parts: list) -> tuple:
    parts = [p for p in parts if p is not None]
    reach = _combine_all([r for r, _ in parts])
    full = reach == CR_YES and all(r == CR_YES and f for r, f in parts)
    return reach, full


def _any(parts: list) -> tuple:
    parts = [p for p in parts if p is not None]
    reach = _combine_any([r for r, _ in parts])
    return reach, reach == CR_YES and any(r == CR_YES and f for r, f in parts)


def _inv(cond: tuple) -> tuple:
    reach, full = cond
    if reach == CR_YES:
        return (CR_NO, True) if full else (CR_POSSIBLE, False)
    if reach == CR_UNKNOWN:
        return CR_UNKNOWN, False
    return CR_POSSIBLE, False


def _invert(value: str) -> str:
    return _inv((value, True))[0]


def _branch_match(pattern: str, comparator: str = "GLOB") -> tuple:
    """Whether a branch condition matches change requests, whose BRANCH_NAME is PR-<number>."""
    if "${" in pattern:
        return CR_UNKNOWN, False
    comparator = (comparator or "GLOB").upper()
    try:
        if comparator == "REGEXP":
            rx = re.compile(pattern)
            hits = [bool(rx.fullmatch(x)) for x in _CR_BRANCH_SAMPLES]
        elif comparator == "EQUALS":
            hits = [pattern == x for x in _CR_BRANCH_SAMPLES]
        else:
            import fnmatch
            hits = [fnmatch.fnmatchcase(x, pattern) for x in _CR_BRANCH_SAMPLES]
    except re.error:
        return CR_UNKNOWN, False
    if all(hits):
        return CR_YES, True
    if any(hits):
        return CR_YES, False
    return CR_NO, True


_MODIFIERS = ("beforeAgent", "beforeInput", "beforeOptions")


def when_eval(stmt, methods: dict | None = None, depth: int = 0) -> tuple | None:
    """(reach, full) for one condition inside `when {}`; None for modifiers such as beforeAgent."""
    expr = stmt.expr if isinstance(stmt, ExprStmt) else stmt
    if depth > 32:
        return CR_UNKNOWN, False
    if not isinstance(expr, Call):
        if isinstance(expr, Name) and expr.name in _MODIFIERS:
            return None
        return CR_UNKNOWN, False
    name = callee_name(expr)
    if name in _MODIFIERS:
        return None
    if name == "changeRequest":
        filtered = bool(expr.args or expr.named)
        return CR_YES, not filtered
    if name in ("buildingTag", "tag"):
        return CR_NO, True
    if name == "branch":
        pattern = literal(named_arg(expr, "pattern") or first_arg(expr))
        if pattern is None:
            return CR_UNKNOWN, False
        return _branch_match(pattern, literal(named_arg(expr, "comparator")) or "GLOB")
    if name == "environment":
        var = literal(named_arg(expr, "name")) or ""
        value = literal(named_arg(expr, "value"))
        if var.startswith("CHANGE_"):
            return CR_YES, False
        if var in ("BRANCH_NAME", "GIT_BRANCH", "TAG_NAME"):
            if value is None:
                return CR_UNKNOWN, False
            return _branch_match(value, literal(named_arg(expr, "comparator")) or "EQUALS") \
                if var == "BRANCH_NAME" else (CR_NO, True)
        return CR_POSSIBLE, False
    if name in ("not", "allOf", "anyOf") and expr.closure is not None:
        inner = [when_eval(s, methods, depth + 1) for s in expr.closure.stmts if not isinstance(s, Opaque)]
        if name == "not":
            return _inv(_all(inner))
        return _all(inner) if name == "allOf" else _any(inner)
    if name in ("triggeredBy", "changeset", "changelog", "equals", "isRestartedRun"):
        return CR_POSSIBLE, False
    if name == "expression" and expr.closure is not None and len(expr.closure.stmts) == 1:
        only = expr.closure.stmts[0]
        node = only.value if isinstance(only, Return) else only.expr if isinstance(only, ExprStmt) else None
        if node is not None:
            return if_eval(node, methods, depth + 1)
    return CR_UNKNOWN, False


def when_condition(stmt, methods: dict | None = None) -> str:
    result = when_eval(stmt, methods)
    return CR_POSSIBLE if result is None else result[0]


def when_block(block: Block, methods: dict | None = None) -> str:
    return _all([when_eval(s, methods) for s in block.stmts if not isinstance(s, Opaque)])[0]


_CHANGE_ID = re.compile(r"(env\.)?CHANGE_ID")
_BRANCH_NAME = re.compile(r"(env\.)?(BRANCH_NAME|GIT_BRANCH|TAG_NAME)")


def if_eval(cond, methods: dict | None = None, depth: int = 0) -> tuple:
    """(reach, full) for a Scripted `if` or an `expression {}`: simple tests of CHANGE_ID and
    BRANCH_NAME, combined with &&, || and !, and calls to methods of this file that return such a
    test. Anything else that mentions change requests or branches is unknown."""
    methods = methods or {}
    if depth > 32:
        return CR_UNKNOWN, False
    if isinstance(cond, Binary) and cond.op in ("&&", "||"):
        parts = [if_eval(cond.left, methods, depth + 1), if_eval(cond.right, methods, depth + 1)]
        return _all(parts) if cond.op == "&&" else _any(parts)
    if isinstance(cond, Unary) and cond.op == "!":
        return _inv(if_eval(cond.operand, methods, depth + 1))
    p = path_of(cond)
    if p and _CHANGE_ID.fullmatch(p):
        return CR_YES, True
    if isinstance(cond, Call):
        name = callee_name(cond)
        body = methods.get(name) if not cond.args and not cond.named else None
        if body is not None and len(body.stmts) == 1:
            only = body.stmts[0]
            node = only.value if isinstance(only, Return) else only.expr if isinstance(only, ExprStmt) else None
            if node is not None:
                return if_eval(node, methods, depth + 1)
        # env.BRANCH_NAME.startsWith('PR-'), .matches('PR-\\d+'), .endsWith(...)
        if isinstance(cond.callee, Prop) and cond.callee.name in ("startsWith", "endsWith", "matches") and \
                _BRANCH_NAME.fullmatch(path_of(cond.callee.target) or "") and len(cond.args) == 1:
            arg = literal(cond.args[0])
            var = path_of(cond.callee.target)
            if arg is not None and "BRANCH_NAME" in var:
                if cond.callee.name == "matches":
                    return _branch_match(arg, "REGEXP")
                pattern = arg + "*" if cond.callee.name == "startsWith" else "*" + arg
                return _branch_match(pattern.replace("[", "[[]"), "GLOB")
            if arg is not None:
                return CR_NO, True        # TAG_NAME and GIT_BRANCH are not PR-<n>
    if isinstance(cond, Binary) and cond.op in ("==", "!=", "==~"):
        sides = [cond.left, cond.right]
        var = next((path_of(x) for x in sides if path_of(x) and (
            _BRANCH_NAME.fullmatch(path_of(x)) or _CHANGE_ID.fullmatch(path_of(x)))), None)
        value = next((literal(x) for x in sides if literal(x) is not None), None)
        if var and value is not None and _BRANCH_NAME.fullmatch(var):
            if "BRANCH_NAME" not in var:
                match = (CR_NO, True)
            else:
                match = _branch_match(value, "REGEXP" if cond.op == "==~" else "EQUALS")
            return match if cond.op != "!=" else _inv(match)
        if var and _CHANGE_ID.fullmatch(var) and any(path_of(x) == "null" for x in sides):
            return (CR_NO, True) if cond.op == "==" else (CR_YES, True)
    text = _source_hint(cond)
    if _CHANGE_VARS.search(text) or _BRANCH_VAR.search(text) or "isPR" in text or "changeRequest" in text:
        return CR_UNKNOWN, False
    return CR_POSSIBLE, False


def if_condition(cond, methods: dict | None = None, depth: int = 0) -> str:
    return if_eval(cond, methods, depth)[0]


def _source_hint(node) -> str:
    """Names and strings in an expression, joined: enough to see what a condition tests."""
    out: list[str] = []
    stack = [node]
    while stack and len(out) < 200:
        n = stack.pop()
        p = path_of(n)
        if p:
            out.append(p)
        elif isinstance(n, Str):
            out.append(n.text())
        elif isinstance(n, Call):
            stack += list(reversed([v for _, v in n.named])) + list(reversed(n.args)) + [n.callee]
        elif isinstance(n, Binary):
            stack += [n.right, n.left]
        elif isinstance(n, Unary):
            out.append(n.op)
            stack.append(n.operand)
        elif isinstance(n, Prop):
            out.append(n.name)
            stack.append(n.target)
        elif isinstance(n, Ternary):
            stack += [n.otherwise, n.then, n.cond]
        elif isinstance(n, Index):
            stack += [n.index, n.target]
        elif isinstance(n, (ExprStmt,)):
            stack.append(n.expr)
        elif isinstance(n, Block):
            stack += list(reversed(n.stmts))
    return " ".join(out)


def narrow(current: str, condition: str) -> str:
    return _combine_all([current, condition])


def source_texts(node, limit: int = 400) -> list[str]:
    """Every value an expression reads, as text untrusted_source understands: interpolations in
    strings, variable and property paths (env.CHANGE_TITLE, through .trim() and other calls),
    env['X'] and env.getProperty('X'), and operands of +, ?:, ternaries, maps and lists. Iterative,
    so a long concatenation cannot exhaust the stack."""
    out: list[str] = []
    stack = [node]
    seen = 0
    while stack and seen < limit:
        n = stack.pop()
        seen += 1
        if n is None:
            continue
        if isinstance(n, Str):
            out += n.exprs
            continue
        p = path_of(n)
        if p:
            out.append(p)
            continue
        if isinstance(n, Index):
            base = path_of(n.target)
            key = literal(n.index)
            if base and key:
                out.append(f"{base}.{key}")
            stack += [n.target, n.index]
        elif isinstance(n, Call):
            callee = n.callee
            if isinstance(callee, Prop) and callee.name in ("getProperty", "get", "getAt") and n.args:
                base = path_of(callee.target)
                key = literal(n.args[0])
                if base and key:
                    out.append(f"{base}.{key}")
            if isinstance(callee, Prop):
                stack.append(callee.target)
            stack += list(n.args) + [v for _, v in n.named]
        elif isinstance(n, Binary):
            stack += [n.left, n.right]
        elif isinstance(n, (Unary,)):
            stack.append(n.operand)
        elif isinstance(n, Ternary):
            stack += [n.then, n.otherwise]
        elif isinstance(n, ListLit):
            stack += list(n.items)
        elif isinstance(n, MapLit):
            stack += [v for _, v in n.entries]
        elif isinstance(n, Prop):
            stack.append(n.target)
    return out


# ------------------------------------------------------------------- credentials
_CRED_KEYS = ("credentialsId", "credentials", "credentialId", "credentialsIds")


def _cred_ids(node) -> list[str]:
    out = []
    if node is None:
        return out
    if isinstance(node, ListLit):
        for item in node.items:
            out += _cred_ids(item)
        return out
    lit = literal(node)
    out.append(lit if lit is not None else "?")
    return out


def bindings_of(call: Call, how: str, ctx_origin: str) -> list[Binding]:
    """Credential bindings created by a wrapper step such as withCredentials or sshagent."""
    out: list[Binding] = []
    name = chain_name(call.callee) or ""

    def from_binding_call(b) -> Binding | None:
        if isinstance(b, Call):
            ids = []
            for key in _CRED_KEYS:
                ids += _cred_ids(named_arg(b, key))
            variables = [literal(v) for k, v in b.named if k.lower().endswith("variable") and literal(v)]
            kind = chain_name(b.callee) or ""
            # file and zip bindings, and the key file of an SSH key or certificate, hold a path.
            paths = [literal(v) for k, v in b.named if literal(v) and (
                (kind in ("file", "zip") and k == "variable") or k in ("keyFileVariable", "keystoreVariable"))]
            if ids or variables:
                return Binding(tuple(ids or ["?"]), tuple(variables), f"{how}:{kind}", b.line, ctx_origin,
                               tuple(paths))
        if isinstance(b, MapLit):
            ids, variables = [], []
            for k, v in b.entries:
                if k in _CRED_KEYS:
                    ids += _cred_ids(v)
                elif isinstance(k, str) and k.lower().endswith("variable") and literal(v):
                    variables.append(literal(v))
            if ids:
                return Binding(tuple(ids), tuple(variables), how, b.line, ctx_origin)
        return None

    if name == "withCredentials":
        items = []
        for arg in call.args:
            items += arg.items if isinstance(arg, ListLit) else [arg]
        for key, value in call.named:
            if key == "bindings" and isinstance(value, ListLit):
                items += value.items
        for item in items:
            b = from_binding_call(item)
            if b:
                out.append(b)
        if not out and items:
            out.append(Binding(("?",), (), how, call.line, ctx_origin))
        return out
    if name == "sshagent":
        ids = []
        for arg in call.args:
            ids += _cred_ids(arg)
        ids += _cred_ids(named_arg(call, "credentials"))
        return [Binding(tuple(ids or ["?"]), ("SSH_AUTH_SOCK",), how, call.line, ctx_origin)]
    if name in ("withSonarQubeEnv",):
        ident = literal(first_arg(call)) or "?"
        return [Binding((f"sonar:{ident}",), ("SONAR_AUTH_TOKEN",), how, call.line, ctx_origin)]
    if name in ("docker.withRegistry", "docker.withServer"):
        node = call.args[1] if len(call.args) > 1 else named_arg(call, "credentialsId")
        if node is None:
            return []
        return [Binding((literal(node) or "?",), (), how, call.line, ctx_origin)]
    if name in ("configFileProvider",):
        files = []
        for arg in call.args:
            for item in (arg.items if isinstance(arg, ListLit) else [arg]):
                if isinstance(item, Call):
                    fid = literal(named_arg(item, "fileId")) or "?"
                    var = literal(named_arg(item, "variable"))
                    files.append((fid, var))
        if files:
            names = tuple(v for _, v in files if v)
            return [Binding(tuple(f"config-file:{f}" for f, _ in files), names, how, call.line, ctx_origin, names)]
        return []
    # Any other wrapper that names a credential, at any depth of its arguments: withAWS(credentials: 'x'),
    # withKubeConfig([credentialsId: 'x']), withVault(configuration: [vaultCredentialId: 'x'], ...),
    # wrap([$class: 'VaultBuildWrapper', ...]).
    ids = _nested_credential_ids(call)
    if ids:
        return [Binding(tuple(ids), (), how, call.line, ctx_origin)]
    if name in CREDENTIAL_WRAPPERS:
        # These steps supply credentials by design (withAWS(role: ...) assumes a role, withVault reads
        # secrets), even when no credential ID is written in the file.
        return [Binding(("?",), (), how, call.line, ctx_origin)]
    if name == "wrap":
        cls = next((literal(v) for arg in call.args if isinstance(arg, MapLit) for k, v in arg.entries
                    if k == "$class"), None) or ""
        if re.search(r"Vault|Credential|Secret|Binding|SSHAgent|Keychain|Kubectl|Aws|Azure", cls, re.I):
            return [Binding(("?",), (), f"wrap {cls}", call.line, ctx_origin)]
    return out


# Wrapper steps that make credentials available to the steps inside them.
CREDENTIAL_WRAPPERS = {"withAWS", "withVault", "withKubeConfig", "withKubeCredentials", "withDockerRegistry",
                       "withDockerServer", "withAzureCLI", "withAzureVault", "withGCP", "withNPM",
                       "withSonarQubeEnv", "withGitHubToken", "withAnsible", "kubeconfig", "azureCLI"}


def _nested_credential_ids(call: Call, limit: int = 200) -> list[str]:
    ids: list[str] = []
    stack = [(k, v) for k, v in call.named] + [("", a) for a in call.args]
    seen = 0
    while stack and seen < limit:
        key, node = stack.pop()
        seen += 1
        if isinstance(key, str) and re.fullmatch(r"(?i)credentials?(Ids?)?|\w*CredentialsI[dD]s?|\w*CredentialI[dD]s?",
                                                 key):
            ids += _cred_ids(node)
            continue
        if isinstance(node, MapLit):
            stack += [(k, v) for k, v in node.entries]
        elif isinstance(node, ListLit):
            stack += [("", item) for item in node.items]
        elif isinstance(node, Call):
            stack += [(k, v) for k, v in node.named] + [("", a) for a in node.args]
    return ids


# --------------------------------------------------------------------------- agents
def agent_from_closure(block: Block) -> Agent:
    a = Agent(kind="unknown", line=block.line)
    for stmt in block.stmts:
        expr = stmt.expr if isinstance(stmt, ExprStmt) else None
        if not isinstance(expr, Call):
            continue
        name = callee_name(expr)
        arg = first_arg(expr)
        if name == "label":
            a.kind, a.label = "label", literal(arg) or ("${dynamic}" if arg is not None else None)
        elif name == "node":
            a.kind = "node"
            if expr.closure is not None:
                inner = agent_from_closure(expr.closure)
                a.label = inner.label
            else:
                a.label = literal(arg)
        elif name == "docker":
            a.kind = "docker"
            if expr.closure is not None:
                _docker_details(a, expr.closure)
            else:
                _set_image(a, arg)
                args = named_arg(expr, "args")
                a.args = _args_text(args)
        elif name == "dockerfile":
            a.kind = "dockerfile"
            if expr.closure is not None:
                _docker_details(a, expr.closure)
        elif name == "kubernetes":
            a.kind = "kubernetes"
            if expr.closure is not None:
                _k8s_details(a, expr.closure)
            for key, value in expr.named:
                _k8s_key(a, key, value)
        elif name in ("any", "none"):
            a.kind = name
    return a


def _args_text(node) -> str:
    """docker run options as text; a computed value is marked so the rules report it as unknown."""
    if node is None:
        return ""
    return text_of(node) or "${computed}"


def _set_image(a: Agent, node) -> None:
    lit = literal(node)
    if lit is not None:
        a.image = lit
    elif node is not None:
        a.image, a.image_dynamic = text_of(node), True


def _docker_details(a: Agent, block: Block) -> None:
    for stmt in block.stmts:
        expr = stmt.expr if isinstance(stmt, ExprStmt) else None
        if isinstance(expr, Call):
            name = callee_name(expr)
            if name == "image":
                _set_image(a, first_arg(expr))
            elif name == "args":
                a.args = _args_text(first_arg(expr))
            elif name == "label":
                a.label = literal(first_arg(expr))


def _k8s_key(a: Agent, key: str, value) -> None:
    if key == "yaml":
        a.yaml = text_of(value)
        if a.yaml is None and value is not None:
            # A variable (resolved later from the file's literals) or a call such as libraryResource().
            a.yaml_ref = path_of(value) or ""
    elif key == "yamlFile":
        a.yaml_file = literal(value) or ("?" if value is not None else None)
    elif key == "inheritFrom":
        a.inherit = literal(value) or ("?" if value is not None else None)
    elif key == "label":
        a.label = literal(value)
    elif key == "containers" and isinstance(value, ListLit):
        for item in value.items:
            if isinstance(item, Call) and callee_name(item) == "containerTemplate":
                img = named_arg(item, "image")
                a.images.append((literal(img) or text_of(img) or "?", item.line))


def _k8s_details(a: Agent, block: Block) -> None:
    for stmt in block.stmts:
        if isinstance(stmt, Assign) and path_of(stmt.target):
            _k8s_key(a, path_of(stmt.target), stmt.value)
            continue
        expr = stmt.expr if isinstance(stmt, ExprStmt) else None
        if isinstance(expr, Call):
            name = callee_name(expr)
            if name in ("yaml", "yamlFile", "inheritFrom", "label"):
                _k8s_key(a, name, first_arg(expr))
            elif name == "containerTemplate":
                img = named_arg(expr, "image")
                a.images.append((literal(img) or text_of(img) or "?", expr.line))


TRIGGER_STEPS = {"GenericTrigger", "ghprbTrigger", "GhprbTrigger", "githubPullRequests", "gitlab", "bitbucketPR",
                 "GitLabPushTrigger"}


def find_calls(node, names: set):
    """Every call to one of `names` anywhere under node."""
    return find_nodes(node, lambda n: isinstance(n, Call) and callee_name(n) in names)


def _trigger_nodes(tree):
    """Trigger declarations: GenericTrigger(...) calls, and the map form properties([pipelineTriggers(
    [[$class: 'GenericTrigger', ...]])]) uses."""
    def match(n):
        if isinstance(n, Call):
            return callee_name(n) in TRIGGER_STEPS
        if isinstance(n, MapLit):
            cls = next((literal(v) for k, v in n.entries if k == "$class"), None)
            return bool(cls) and cls.rsplit(".", 1)[-1] in TRIGGER_STEPS
        return False
    return find_nodes(tree, match)


def _split_sections(expr: Call) -> list | None:
    """Declarative sections written on one line (`when { ... } steps { ... }`) read as a command chain:
    the first section called with the next as its argument. Return them as separate sections, or None
    when the call is not a section."""
    if callee_name(expr) in _SECTIONS:
        return [expr]
    if isinstance(expr.callee, Call) and expr.command and callee_name(expr.callee) in _SECTIONS and expr.args \
            and all(isinstance(a, Call) for a in expr.args):
        rest = []
        for arg in expr.args:
            split = _split_sections(arg)
            if split is None:
                return None
            rest += split
        return [expr.callee] + rest
    return None


def _closure_branches(node, default_key):
    """(key, body) for each closure in a parallel argument: a closure, a map of closures or a list."""
    if isinstance(node, Closure):
        yield default_key, node.body
    elif isinstance(node, MapLit):
        for i, (k, v) in enumerate(node.entries):
            key = k if isinstance(k, str) else (literal(k) or f"{default_key}.{i}")
            if isinstance(v, Closure):
                yield key, v.body
    elif isinstance(node, ListLit):
        for i, item in enumerate(node.items):
            if isinstance(item, Closure):
                yield f"{default_key}.{i}", item.body


def _rethrows(block: Block) -> bool:
    """Whether a catch block throws again (throw, or the error step), so the failure still stops the build."""
    for n in find_nodes(block, lambda n: (isinstance(n, Return) and n.throw) or (
            isinstance(n, Call) and callee_name(n) == "error")):
        return True
    return False


def _list_items(node) -> list:
    return list(node.items) if isinstance(node, ListLit) else []


def _entry(node, key: str):
    """`key` of a map literal ([key: 'X', value: '$.a']) or a named argument of a call."""
    if isinstance(node, MapLit):
        for k, v in node.entries:
            if k == key:
                return v
    if isinstance(node, Call):
        return named_arg(node, key)
    return None


# --------------------------------------------------------------------------- walker
class Builder:
    INLINE_BUDGET = 5000      # calls to the file's own methods expanded per file
    INLINE_DEPTH = 16

    def __init__(self):
        self.p = Pipeline()
        self.methods: dict[str, Block] = {}        # parameterless methods, for conditions
        self.defs: dict[str, list] = {}            # every top-level method, by name
        self.called: set[str] = set()
        self.stack: list[str] = []
        self.budget = self.INLINE_BUDGET

    def build(self, tree: Block) -> Pipeline:
        # Methods may be defined below their first use; collect the top-level ones first. A method the
        # file calls is walked where it is called, with the caller's stage, credentials and conditions.
        for stmt in tree.stmts:
            target = stmt.target if isinstance(stmt, Annotated) else stmt
            if isinstance(target, MethodDef):
                self.defs.setdefault(target.name, []).append(target)
                if not target.params:
                    self.methods[target.name] = target.body
        if self.defs:
            self.called = {callee_name(c) for c in find_calls(tree, set(self.defs))}
        declarative = any(isinstance(s, ExprStmt) and isinstance(s.expr, Call) and callee_name(s.expr) == "pipeline"
                          for s in tree.stmts)
        self.p.kind = "declarative" if declarative else "scripted"
        # Triggers decide who can start the whole pipeline, wherever they are declared (a triggers {}
        # directive or properties([pipelineTriggers([...])])), so read them before walking.
        for node in _trigger_nodes(tree):
            self.trigger(node)
        start = Ctx(cr=CR_YES) if any(t.change_requests for t in self.p.triggers) else Ctx()
        self.block(tree, start, top=True)
        return self.p

    def trigger(self, node) -> None:
        def arg(key):
            return named_arg(node, key) if isinstance(node, Call) else _entry(node, key)
        if isinstance(node, Call):
            name = callee_name(node) or ""
        else:
            name = (next((literal(v) for k, v in node.entries if k == "$class"), "") or "").rsplit(".", 1)[-1]
        token = literal(arg("token"))
        change_requests = False
        if name == "GenericTrigger":
            text = " ".join(filter(None, (literal(arg("regexpFilterExpression")), literal(arg("regexpFilterText")),
                                          literal(arg("causeString")))))
            for key, source in (("genericVariables", "payload"), ("genericRequestVariables", "request parameter"),
                                ("genericHeaderVariables", "request header")):
                for item in _list_items(arg(key)):
                    var = literal(_entry(item, "key"))
                    path = literal(_entry(item, "value")) or ""
                    if not var:
                        continue
                    text += " " + path
                    words = re.search(r"title|description|body|message|comment|text|name|label|branch|ref|subject|"
                                      r"display", path, re.I)
                    severity = "high" if source == "payload" and words else "medium"
                    self.p.tainted[var] = (f"webhook {source} {path or var}".strip(), severity)
            change_requests = bool(re.search(r"pull|merge_request|mergeRequest|\bpr\b|pr:|changes", text, re.I))
        elif name in ("ghprbTrigger", "githubPullRequests", "GhprbTrigger", "bitbucketPR"):
            change_requests = True
        elif name in ("gitlab", "GitLabPushTrigger"):
            flag = arg("triggerOnMergeRequest")
            change_requests = flag is None or path_of(flag) != "false"
        self.p.triggers.append(Trigger(name, node.line, change_requests, token))

    # -- generic statements ------------------------------------------------------------
    def block(self, block: Block | None, ctx: Ctx, top: bool = False) -> None:
        if block is None:
            return
        for stmt in block.stmts:
            self.stmt(stmt, ctx)

    @staticmethod
    def narrowed(ctx: Ctx, condition: str, line: int, guard: str | None = None) -> Ctx:
        cr = narrow(ctx.cr, condition)
        guards = ctx.guards + (guard,) if guard else ctx.guards
        if cr == CR_UNKNOWN and ctx.cr != CR_UNKNOWN:
            return replace(ctx, cr=cr, cr_line=line, guards=guards)
        return replace(ctx, cr=cr, guards=guards)

    def stmt(self, stmt, ctx: Ctx) -> None:
        if isinstance(stmt, ExprStmt):
            self.expr(stmt.expr, ctx)
        elif isinstance(stmt, Decl):
            self.p.local_names.add(stmt.name)
            if stmt.value is not None:
                self.track_value(stmt.name, stmt.value)
                self.expr(stmt.value, ctx)
        elif isinstance(stmt, Assign):
            target = path_of(stmt.target) or path_of(getattr(stmt.target, "target", None))
            if target:
                self.p.local_names.add(target.split(".")[0])
                if path_of(stmt.target):
                    self.track_value(target.removeprefix("env."), stmt.value)
                else:
                    # x['key'] = value, x.y[0] = value: the container now holds the value.
                    self.track_value(target.split(".")[0], stmt.value, merge=True)
            self.expr(stmt.value, ctx)
        elif isinstance(stmt, If):
            cond = if_eval(stmt.cond, self.methods)
            hint = _source_hint(stmt.cond)
            self.expr(stmt.cond, ctx)
            self.block(stmt.then, self.narrowed(ctx, cond[0], stmt.line, f"if {hint}"))
            if stmt.otherwise is not None:
                self.block(stmt.otherwise, self.narrowed(ctx, _inv(cond)[0], stmt.line, f"if not {hint}"))
        elif isinstance(stmt, Loop):
            for h in stmt.header:
                if isinstance(h, Decl):
                    self.p.local_names.add(h.name)
                elif isinstance(h, Name):
                    self.p.local_names.add(h.name)
                elif isinstance(h, Binary) and h.op == "in" and isinstance(h.left, Name):
                    self.p.local_names.add(h.left.name)
                self.expr(h, ctx)
            # A loop body may run zero times: it is conditional.
            self.block(stmt.body, replace(ctx, guards=ctx.guards + (f"loop {stmt.line}",)))
        elif isinstance(stmt, Try):
            body_ctx = ctx
            catches = [h for h, kind in zip(stmt.handlers, stmt.kinds or ["catch"] * len(stmt.handlers))
                       if kind == "catch"]
            if catches and not all(_rethrows(h) for h in catches):
                # A failure in the body is caught and not thrown again, so it does not stop the build.
                body_ctx = replace(ctx, swallowed=f"try/catch at line {stmt.line} without rethrow")
            self.block(stmt.body, body_ctx)
            # catch and finally blocks run after the body failed or stopped part way.
            for h in stmt.handlers:
                self.block(h, replace(ctx, post="catch/finally"))
        elif isinstance(stmt, Switch):
            branchy = bool(_BRANCH_VAR.search(_source_hint(stmt.subject)) or _CHANGE_VARS.search(
                _source_hint(stmt.subject)))
            for case in stmt.cases:
                inner = self.narrowed(ctx, CR_UNKNOWN, stmt.line) if branchy else ctx
                self.block(case, replace(inner, guards=inner.guards + (f"switch {stmt.line}",)))
        elif isinstance(stmt, Return):
            if stmt.value is not None:
                self.expr(stmt.value, ctx)
        elif isinstance(stmt, MethodDef):
            self.p.local_names.add(stmt.name)
            self.p.local_names.update(p for p in stmt.params if isinstance(p, str))
            if stmt.name in self.called and any(stmt is d for d in self.defs.get(stmt.name, [])):
                return    # walked at each call, in the caller's context
            self.p.method_params.update(p for p in stmt.params if isinstance(p, str))
            # A method nothing in this file calls (a shared-library step, `call()` in vars/) can be
            # called from any stage, so whether change requests reach it is unknown.
            self.block(stmt.body, replace(ctx, in_function=stmt.name, cr=CR_UNKNOWN, cr_line=stmt.line,
                                          stage=ctx.stage + (f"{stmt.name}()",)))
        elif isinstance(stmt, ClassDef):
            self.p.local_names.add(stmt.name)
            self.p.opaque.append((stmt.line, f"class {stmt.name}"))
            self.block(stmt.body, replace(ctx, in_function=stmt.name, cr=CR_UNKNOWN, cr_line=stmt.line))
        elif isinstance(stmt, Annotated):
            if stmt.annotation in ("Library", "groovy.lang.Library"):
                self.annotation_libraries(stmt)
            elif stmt.annotation in ("Grab", "Grapes", "GrabResolver", "GrabConfig"):
                self.p.opaque.append((stmt.line, f"@{stmt.annotation}: dependencies fetched at compile time"))
            if stmt.target is not None:
                self.stmt(stmt.target, ctx)
        elif isinstance(stmt, Opaque):
            self.p.opaque.append((stmt.line, f"statement not analyzed ({stmt.reason})"))

    def track_value(self, name: str, value, merge: bool = False) -> None:
        """Remember values that matter later: docker images, literal strings, and text from untrusted
        sources, however the value is built (interpolation, +, ?:, .trim(), env['X'], maps, lists)."""
        if value is None:
            return
        if isinstance(value, Str) and not merge:
            self.p.literals[name] = value
        elif not merge:
            self.p.literals.pop(name, None)
        cname = chain_name(value) if isinstance(value, Call) else None
        if cname and (cname.startswith("docker.build") or cname.startswith("docker.image")):
            self.p.docker_vars.add(name)
        # def msg = sh(script: 'git log -1 --pretty=%B', returnStdout: true).trim(): the output is text
        # the commit's author wrote.
        base = value
        while isinstance(base, Call) and isinstance(base.callee, Prop) and isinstance(base.callee.target, Call):
            base = base.callee.target
        if isinstance(base, Call) and callee_name(base) in SHELL_STEPS:
            script = shell_script(base)
            text = script.text() if isinstance(script, Str) else ""
            if git_text(text):
                self.p.tainted[name] = ("git commit text", "high")
                return
        source = untrusted_source(source_texts(value), self.p)
        if source:
            current = self.p.tainted.get(name)
            if current is None or _RANK[source[1]] >= _RANK[current[1]]:
                self.p.tainted[name] = source

    def expr(self, node, ctx: Ctx) -> None:
        # Operator chains are walked iteratively: a long concatenation must not exhaust the stack.
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, Call):
                self.call(n, ctx)
            elif isinstance(n, Closure):
                self.p.local_names.update(p for p in n.params if isinstance(p, str))
                self.block(n.body, ctx)
            elif isinstance(n, ListLit):
                stack += reversed(n.items)
            elif isinstance(n, MapLit):
                stack += reversed([v for _, v in n.entries])
            elif isinstance(n, Binary):
                stack += [n.right, n.left]
            elif isinstance(n, Unary):
                stack.append(n.operand)
            elif isinstance(n, Ternary):
                stack += [n.otherwise, n.then, n.cond]
            elif isinstance(n, Prop):
                stack.append(n.target)
            elif isinstance(n, Index):
                stack += [n.index, n.target]

    # -- calls ---------------------------------------------------------------------------
    def call(self, call: Call, ctx: Ctx) -> None:
        name = chain_name(call.callee) or ""
        # Receivers in a chain are calls too: docker.image('x') in docker.image('x').inside { },
        # sh(script: 'x', returnStdout: true) in sh(...).trim().
        if isinstance(call.callee, Prop) and isinstance(call.callee.target, Call):
            self.call(call.callee.target, ctx)
        if name == "pipeline" and call.closure is not None:
            self.pipeline(call.closure, ctx)
            return
        if name == "stage":
            self.stage(call, ctx)
            return
        if name == "node" and call.closure is not None:
            label = literal(first_arg(call)) or literal(named_arg(call, "label"))
            dynamic = first_arg(call) is not None and label is None
            agent = Agent(kind="node" if (label or dynamic) else "any", label=label or (
                "${dynamic}" if dynamic else None), line=call.line)
            self.p.agents.append((agent, ctx))
            self.block(call.closure, replace(ctx, agent=agent))
            return
        if name in ("podTemplate",):
            agent = Agent(kind="kubernetes", line=call.line)
            for key, value in call.named:
                _k8s_key(agent, key, value)
            self.p.agents.append((agent, ctx))
            self.record_step(name, call, ctx)
            self.block(call.closure, replace(ctx, agent=agent))
            return
        if name.endswith(".inside") or name == "withDockerContainer":
            agent = Agent(kind="docker", line=call.line, from_step=True)
            if name == "withDockerContainer":
                _set_image(agent, named_arg(call, "image") or first_arg(call))
                agent.args = _args_text(named_arg(call, "args"))
            else:
                receiver = call.callee.target if isinstance(call.callee, Prop) else None
                if isinstance(receiver, Call) and (chain_name(receiver) or "").startswith("docker.image"):
                    _set_image(agent, first_arg(receiver))
                agent.args = _args_text(first_arg(call))
            self.p.agents.append((agent, ctx))
            self.record_step(name, call, ctx)
            self.block(call.closure, replace(ctx, agent=agent))
            return
        if name == "parallel":
            # Each branch runs concurrently with its siblings.
            def branch(key) -> Ctx:
                return replace(ctx, branch=ctx.branch + ((call.line, str(key)),))
            for index, arg in enumerate(call.args):
                found = False
                for key, body in _closure_branches(arg, index):
                    found = True
                    self.block(body, branch(key))
                if found:
                    continue
                p = path_of(arg)
                if p:
                    # Branches assigned in this file (branches[name] = { ... }) were walked where they were
                    # assigned; a map from anywhere else is code the checker never saw.
                    if p.split(".")[0] not in self.p.local_names:
                        self.p.opaque.append((call.line, f"parallel branches built elsewhere ({p})"))
                else:
                    # parallel(xs.collectEntries { ... }) or parallel(makeBranches()): walk the expression,
                    # so closures inside it are read and unknown steps are reported.
                    self.expr(arg, branch(f"computed {index}"))
            for key, value in call.named:
                for _, body in _closure_branches(value, key):
                    self.block(body, branch(key))
                if not isinstance(value, (Closure, MapLit, ListLit)):
                    self.expr(value, branch(key))
            if call.closure is not None:      # declarative parallel { stage ... }
                self.stage_list(call.closure, ctx, parallel=call.line)
            return
        if name in self.defs and "." not in name:
            self.inline(name, call, ctx)
            return
        if name == "script" and call.closure is not None:
            self.block(call.closure, replace(ctx, in_script=True))
            return
        if name == "library":
            self.library_step(call)
        if name in ("load", "evaluate"):
            self.p.opaque.append((call.line, f"{name}(): Groovy loaded at run time is not analyzed"))
        if name in ("input",):
            sub = named_arg(call, "submitter")
            self.p.approvals.append(Approval(None if sub is None else (literal(sub) or "?"), call.line, ctx))
        if name == "withEnv":
            for arg in call.args:
                for s in all_strings(arg):
                    var, eq, _ = s.text().partition("=")
                    if eq:
                        source = untrusted_source(s.exprs, self.p)
                        if source:
                            self.p.tainted[var.strip()] = source
        # A step. Record it, then walk any closure with the bindings it adds.
        self.record_step(name, call, ctx)
        for arg in call.args:
            if isinstance(arg, (Call, Closure, ListLit, MapLit)):
                self.expr(arg, ctx)
        for _, value in call.named:
            if isinstance(value, (Call, Closure, ListLit, MapLit)):
                self.expr(value, ctx)
        if call.closure is not None:
            inner = ctx
            new = bindings_of(call, name, ctx_origin=f"{name}()")
            if new:
                inner = replace(inner, creds=inner.creds + tuple(new))
            if name in ("catchError", "warnError"):
                inner = replace(inner, swallowed=f"{name} (line {call.line})")
            if name == "withEnv":
                for arg in call.args:
                    for s in all_strings(arg):
                        var, _, val = s.text().partition("=")
                        if var.strip() == "OBAAF_LANE" and val.strip():
                            inner = replace(inner, lane=val.strip().lower(), lane_line=s.line)
            self.block(call.closure, inner)

    def inline(self, name: str, call: Call, ctx: Ctx) -> None:
        """Walk a method of this file where it is called, so its steps get the caller's stage,
        credentials, post condition and conditions. Arguments flow into the parameters."""
        for arg in call.args:
            if isinstance(arg, (Call, Closure, ListLit, MapLit)):
                self.expr(arg, ctx)
        for _, value in call.named:
            if isinstance(value, (Call, Closure, ListLit, MapLit)):
                self.expr(value, ctx)
        if name in self.stack or len(self.stack) >= self.INLINE_DEPTH or self.budget <= 0:
            self.p.opaque.append((call.line, f"call to {name}() not expanded (recursion or too many calls)"))
            return
        self.budget -= 1
        candidates = self.defs[name]
        mdef = next((d for d in candidates if len(d.params) == len(call.args) + (1 if call.closure else 0)),
                    candidates[0])
        values = list(call.args) + ([Closure([], call.closure, line=call.line)] if call.closure is not None else [])
        for param, value in zip(mdef.params, values):
            self.track_value(param, value)
        self.stack.append(name)
        try:
            self.block(mdef.body, replace(ctx, in_function=name))
        finally:
            self.stack.pop()
        # A trailing closure passed to the method runs inside it (withRetry { ... }).
        if call.closure is not None:
            self.block(call.closure, ctx)

    def record_step(self, name: str, call: Call, ctx: Ctx) -> None:
        if name:
            self.p.steps.append(StepUse(name, call, ctx, call.line))

    # -- libraries -------------------------------------------------------------------------
    def annotation_libraries(self, stmt: Annotated) -> None:
        values = []
        for arg in stmt.args:
            values += arg.items if isinstance(arg, ListLit) else [arg]
        for key, value in stmt.named:
            if key == "value":
                values += value.items if isinstance(value, ListLit) else [value]
        for v in values:
            self._library(v, "@Library", stmt.line)

    def library_step(self, call: Call) -> None:
        node = named_arg(call, "identifier") or first_arg(call)
        self._library(node, "library step", call.line)

    def _library(self, node, how: str, line: int) -> None:
        if not isinstance(node, Str):
            self.p.libraries.append(Library("?", None, True, how, line))
            return
        text = node.text()
        name, _, version = text.partition("@")
        self.p.libraries.append(Library(name, version or None, node.interpolated, how, line, tuple(node.exprs)))

    # -- declarative ------------------------------------------------------------------------
    def sections(self, block: Block) -> dict:
        out: dict[str, list] = {}
        for stmt in block.stmts:
            expr = stmt.expr if isinstance(stmt, ExprStmt) else None
            parts = _split_sections(expr) if isinstance(expr, Call) else None
            if parts:
                for part in parts:
                    out.setdefault(callee_name(part), []).append(part)
                continue
            out.setdefault("_other", []).append(stmt)
        return out

    def pipeline(self, block: Block, ctx: Ctx) -> None:
        secs = self.sections(block)
        ctx = self.apply_common(secs, ctx, origin="pipeline")
        for lib in secs.get("libraries", []):
            for s in (lib.closure.stmts if lib.closure else []):
                e = s.expr if isinstance(s, ExprStmt) else None
                if isinstance(e, Call) and callee_name(e) == "lib":
                    self._library(first_arg(e), "libraries directive", e.line)
        for p in secs.get("parameters", []):
            for s in (p.closure.stmts if p.closure else []):
                e = s.expr if isinstance(s, ExprStmt) else None
                if isinstance(e, Call) and callee_name(e) in ("string", "text", "password", "choice"):
                    pname = literal(named_arg(e, "name"))
                    if pname and callee_name(e) in ("string", "text"):
                        self.p.string_params.add(pname)
        for st in secs.get("stages", []):
            self.stage_list(st.closure, ctx)
        for post in secs.get("post", []):
            self.post(post, ctx)
        for other in secs.get("_other", []):
            self.stmt(other, ctx)

    def apply_common(self, secs: dict, ctx: Ctx, origin: str) -> Ctx:
        """agent, environment and when, which shape the context of everything below them."""
        for env in secs.get("environment", []):
            ctx = self.environment(env, ctx, origin)
        for agent_call in secs.get("agent", []):
            agent = self.agent(agent_call)
            if agent is not None:
                self.p.agents.append((agent, ctx))
                ctx = replace(ctx, agent=agent)
        for w in secs.get("when", []):
            if w.closure is not None:
                ctx = self.narrowed(ctx, when_block(w.closure, self.methods), w.line,
                                    "when " + _source_hint(w.closure))
        for inp in secs.get("input", []):
            sub = None
            if inp.closure is not None:
                for s in inp.closure.stmts:
                    e = s.expr if isinstance(s, ExprStmt) else None
                    if isinstance(e, Call) and callee_name(e) == "submitter":
                        sub = literal(first_arg(e)) or "?"
            for key, value in inp.named:
                if key == "submitter":
                    sub = literal(value) or "?"
            self.p.approvals.append(Approval(sub, inp.line, ctx))
            self.record_step("input", inp, ctx)
        return ctx

    def agent(self, call: Call) -> Agent | None:
        if call.closure is not None:
            return agent_from_closure(call.closure)
        arg = first_arg(call)
        if isinstance(arg, Name) and arg.name in ("any", "none"):
            return Agent(kind=arg.name, line=call.line)
        if isinstance(arg, Name) and arg.name == "label":     # agent label 'x' (old form)
            return Agent(kind="label", line=call.line)
        return Agent(kind="unknown", line=call.line)

    def environment(self, env: Call, ctx: Ctx, origin: str) -> Ctx:
        if env.closure is None:
            return ctx
        new: list[Binding] = []
        lane, lane_line = ctx.lane, ctx.lane_line
        for stmt in env.closure.stmts:
            if not isinstance(stmt, Assign):
                continue
            var = path_of(stmt.target) or ""
            value = stmt.value
            if isinstance(value, Call) and callee_name(value) == "credentials":
                cid = literal(first_arg(value)) or "?"
                new.append(Binding((cid,), (var, f"{var}_USR", f"{var}_PSW"), "environment credentials()",
                                   stmt.line, origin))
                continue
            if var == "OBAAF_LANE":
                lane = (literal(value) or "").strip().lower() or lane
                lane_line = stmt.line
            if isinstance(value, Str):
                self.p.env_values[var] = value
            self.track_value(var, value)
        return replace(ctx, creds=ctx.creds + tuple(new), lane=lane, lane_line=lane_line)

    def stage_list(self, block: Block | None, ctx: Ctx, parallel: int | None = None) -> None:
        """Stages in order; with `parallel` (the line of a parallel block), each stage is a branch that
        runs concurrently with its siblings."""
        if block is None:
            return
        for index, stmt in enumerate(block.stmts):
            expr = stmt.expr if isinstance(stmt, ExprStmt) else None
            if isinstance(expr, Call) and callee_name(expr) == "stage":
                sctx = ctx if parallel is None else replace(ctx, branch=ctx.branch + ((parallel, str(index)),))
                self.stage(expr, sctx)
            elif isinstance(expr, Call) and callee_name(expr) == "parallel" and expr.closure is not None:
                self.stage_list(expr.closure, ctx, parallel=expr.line)
            else:
                self.stmt(stmt, ctx)

    def stage(self, call: Call, ctx: Ctx) -> None:
        arg = first_arg(call) or named_arg(call, "name")
        name = literal(arg) or (text_of(arg) if arg is not None else None) or "?"
        sctx = replace(ctx, stage=ctx.stage + (name,))
        if call.closure is None:
            return
        secs = self.sections(call.closure)
        is_declarative_stage = bool(secs.keys() & {"steps", "stages", "parallel", "matrix"}) and self.p.kind == \
            "declarative"
        if not is_declarative_stage:
            # Scripted stage('x') { ...steps... }
            self.block(call.closure, sctx)
            return
        sctx = self.apply_common(secs, sctx, origin=f"stage '{name}'")
        for steps in secs.get("steps", []):
            self.block(steps.closure, sctx)
        for st in secs.get("stages", []):
            self.stage_list(st.closure, sctx)
        for par in secs.get("parallel", []):
            self.stage_list(par.closure, sctx, parallel=par.line)
        for m in secs.get("matrix", []):
            msecs = self.sections(m.closure) if m.closure else {}
            mctx = self.apply_common(msecs, sctx, origin=f"stage '{name}' matrix")
            for st in msecs.get("stages", []):
                self.stage_list(st.closure, mctx)
            for post in msecs.get("post", []):
                self.post(post, mctx)
        for post in secs.get("post", []):
            self.post(post, sctx)

    def post(self, call: Call, ctx: Ctx) -> None:
        if call.closure is None:
            return
        for stmt in call.closure.stmts:
            expr = stmt.expr if isinstance(stmt, ExprStmt) else None
            if isinstance(expr, Call) and expr.closure is not None:
                cond = callee_name(expr) or "?"
                self.block(expr.closure, replace(ctx, post=cond, stage=ctx.stage + (f"post {cond}",)))


# ------------------------------------------------------------------ untrusted values
# Who controls each value, for a multibranch or organization-folder job. Free text a change's author
# writes is high. Build parameters are medium: anyone with Build permission sets them, and an upstream
# build, which runs as SYSTEM unless build authorization is configured, can pass anything. Names
# whose character set Git or the SCM restricts, or that only people with write access choose (branch
# and tag names of the repository itself; BRANCH_NAME is PR-<n> for a change request), are low.
UNTRUSTED = {
    "CHANGE_TITLE": "high", "CHANGE_BRANCH": "high", "CHANGE_AUTHOR_DISPLAY_NAME": "high",
    "CHANGE_AUTHOR_EMAIL": "medium",
    "CHANGE_AUTHOR": "low", "CHANGE_FORK": "low", "CHANGE_TARGET": "low",
    "BRANCH_NAME": "low", "TAG_NAME": "low", "GIT_BRANCH": "low", "GIT_LOCAL_BRANCH": "low",
    # GitLab plugin and GitHub Pull Request Builder (ghprb) variables.
    "gitlabMergeRequestTitle": "high", "gitlabMergeRequestDescription": "high", "gitlabSourceBranch": "high",
    "gitlabBranch": "high", "gitlabUserName": "high", "gitlabMergeRequestLastCommit": "low",
    "gitlabUserEmail": "medium", "gitlabTargetBranch": "low",
    "ghprbPullTitle": "high", "ghprbPullDescription": "high", "ghprbPullLongDescription": "high",
    "ghprbSourceBranch": "high", "ghprbCommentBody": "high", "ghprbActualCommitAuthor": "high",
    "ghprbTriggerAuthor": "high", "ghprbPullAuthorLoginMention": "low", "ghprbPullAuthorLogin": "low",
    "ghprbTargetBranch": "low",
}
_RANK = {"low": 1, "medium": 2, "high": 3}
_UNTRUSTED_RE = re.compile(r"(?<![\w.])(?:env\s*\.\s*|env\s*\[\s*['\"])?("
                           + "|".join(sorted(UNTRUSTED, key=len, reverse=True)) + r")\b")
_PARAM_RE = re.compile(r"\bparams\s*\.\s*([A-Za-z_]\w*)|\bparams\s*\[\s*['\"]([^'\"]+)['\"]")


def untrusted_source(exprs: list[str], pipeline: Pipeline | None) -> tuple[str, str] | None:
    """(source, severity) for the most dangerous untrusted value an interpolated expression reads:
    text change authors write, build parameters, branch names, or a variable assigned from one of
    them. None when it reads none of these."""
    found: list[tuple[str, str]] = []
    for text in exprs:
        for m in _UNTRUSTED_RE.finditer(text):
            found.append((m.group(1), UNTRUSTED[m.group(1)]))
        for m in _PARAM_RE.finditer(text):
            found.append((f"params.{m.group(1) or m.group(2)}", "medium"))
        if pipeline is not None:
            for word in re.findall(r"[A-Za-z_]\w*", text):
                if word in pipeline.tainted:
                    src, sev = pipeline.tainted[word]
                    found.append((src if src == word else f"{word} (from {src})", sev))
                elif word in pipeline.string_params:
                    found.append((f"parameter {word}", "medium"))
    if not found:
        return None
    return max(found, key=lambda item: _RANK[item[1]])


def build(tree: Block) -> Pipeline:
    return Builder().build(tree)
