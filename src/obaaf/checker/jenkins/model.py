"""A pipeline model built from the syntax tree: stages, steps and the context of each step.

For every step it records the stage it belongs to, the credentials bound around it,
the agent it runs on, the post condition it runs under, and whether the stage can run
for a change request (a pull request in a multibranch or organization-folder job).
That last question comes from `when` conditions in Declarative Pipeline, and from simple
`if (env.CHANGE_ID)` and `BRANCH_NAME` tests in Scripted Pipeline. Anything the model
cannot settle is recorded as unknown, never as safe (Jenkins design, section 5).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, fields, is_dataclass, replace

from obaaf.checker.workflow import is_lane_variable_spelling
from obaaf.checker.jenkins import steps as known
from obaaf.checker.jenkins.parser import (
    Annotated, Assign, Binary, Block, Call, Closure, Decl, ExprStmt, If, Import, Index, ListLit, Loop, MapLit,
    MethodDef, ClassDef, Name, Num, Opaque, Prop, Return, Str, Switch, Ternary, Try, Unary, callee_name, path_of,
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
    # Flagship slice 2d.2k: the Dockerfile a `dockerfile` agent builds ("?" when computed), and whether a
    # pod template's container list could not be read (a variable the file changes, a call).
    dockerfile: str | None = None
    images_unknown: bool = False
    build_args: str | None = None  # additionalBuildArgs, as text ("${computed}" when not a literal)
    # Flagship slice 2d.2j: `reuseNode` of a docker or dockerfile agent ("true", or "?" when computed; None when
    # absent or false), and a node's `customWorkspace` ("?" when computed).
    reuse: str | None = None
    custom_workspace: str | None = None
    # A Kubernetes agent's workspaceVolume when it outlives the pod (a claim, a host path or an NFS export; "?"
    # when the file does not fix which), None for the default emptyDir and the other per-pod volumes.
    pod_workspace: str | None = None
    # What podTemplate's own arguments give the pod that reaches the host (flagship slice 2d.2j): a privileged
    # containerTemplate, a hostPathVolume, hostNetwork.
    pod_settings: list = field(default_factory=list)
    label_ref: str | None = None   # the variable a podTemplate's `label:` names, when it is not a literal
    label_text: str | None = None  # its text, interpolations shown as ${...}


@dataclass
class Workspace:
    """One allocation of a workspace (flagship slice 2d.2j). Steps whose context carries the same id run in
    the same directory; `machine` is the allocation of the node it is on, so `ws()` inside a `node` is
    another directory on the same machine, written by the same user."""
    id: int
    machine: int
    kind: str             # label, node, any, docker, dockerfile, kubernetes, unknown, ws, context
    line: int
    label: str | None = None      # the literal label; "${dynamic}" when computed; None for any agent
    custom: str | None = None     # customWorkspace or the path given to ws() ("?" when computed)
    how: str = ""                 # what allocated it, for messages


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
    lanes: tuple = ()             # (value, line) of every OBAAF_LANE on the way to the step, outermost
                                  # first; the value is None when it is computed at run time
    in_function: str | None = None
    swallowed: str | None = None  # catchError, warnError or a catch block: its failure does not stop the build
    branch: tuple = ()            # ((parallel line, branch name), ...): steps in sibling branches run concurrently
    guards: tuple = ()            # conditions (as text) that must hold for the step to run
    dir: str = ""                 # the folder dir() moved into, relative to the workspace; "?" when computed
    ws: int = 0                   # the Workspace the step runs in (flagship slice 2d.2j); 0 when none is known
    repeats: tuple = ()           # retry and waitUntil blocks around the step, which may run it again (2d.2j)
    # Flagship slice 2d.2l: the step is read where a closure or a method nothing calls is written, not where it
    # runs (it may run later, elsewhere or never); the value says which closure or method.
    deferred: str | None = None
    # Flagship slice 2d.2l, from its review: the catching block (try/catch, catchError, warnError) the step is in, one
    # number per walk of the block, so an inlined method's block called twice is two blocks; and the call of an
    # inlined method the step is read in, with the method's parameter names.
    swallow_id: int = 0
    invocation: tuple = ()
    # Flagship slice 2d.2n: the stage path whose Declarative post block the step is in (() for the pipeline's own), or
    # None outside one. A Scripted stage may be named "post always", so the stage path alone does not say it.
    post_owner: tuple | None = None
    # The review of pull request #365 (#344): ((name, line), ...) for every variable a `withEnv` entry or an
    # `environment { }` block around the step sets, outermost first, as written (`PATH+OBAAF` included); the name
    # is "?" where the checker cannot read it (a computed entry, a list held in a variable). A check's shell may run
    # another `obaaf` when one of them is `PATH` or another name `steers` counts.
    env_names: tuple = ()


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
    ref: str | None = None          # the variable or property a library named by a value reads (env.LIB)
    # Flagship slice 2d.2k: where a `library` step's retriever takes the library from. "self" for
    # legacySCM(scm), the build's own checkout; "computed" for a retriever built from values the file
    # does not fix; None for a retriever written out, or none.
    retriever: str | None = None
    retriever_source: tuple | None = None   # (source, severity) when those values come from untrusted text


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
    token_node: object = None  # the token's expression when it is not a plain literal (flagship slice 2d.2i)
    token_key: str = "token"   # the argument that held it: token (Generic Webhook Trigger), secretToken (GitLab)


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
    tree: object = None                                 # the parsed file (flagship slice 2d.2m: OBAAF-JEN-010 looks
                                                        # for every place it names copyArtifacts)
    source: str = ""                                    # the file's text, as parsed (2d.2m: OBAAF-JEN-010 counts
                                                        # every place a variable's name appears)
    triggers: list = field(default_factory=list)        # Trigger: SCM and webhook triggers named in the file
    literals: dict = field(default_factory=dict)        # variable -> Str assigned to it (last assignment)
    lists: dict = field(default_factory=dict)           # variable -> ListLit assigned to it (last assignment)
    # variable -> the names its assigned values read, from every assignment, parameter and withEnv entry
    # in the file (flagship slice 2d.2i): a secret copied into another variable is still a secret.
    refs: dict = field(default_factory=dict)
    stages: list = field(default_factory=list)          # every stage with a block, as a tuple of names, steps or not
    # Lane declarations the checker does not read (flagship slice 2d.2f): (kind, name, value text or
    # None, line, stage). `jenkins-misnamed` is the variable under another spelling in an environment
    # block or a withEnv; `jenkins-scripted` is any spelling assigned to `env.` in a script.
    unread_lanes: list = field(default_factory=list)
    # Flagship slice 2d.2k: every call that runs Groovy the file does not hold, whatever the receiver:
    # (kind, name, call, ctx, certain), kind one of load, evaluate, jobDsl; certain is False when the receiver
    # may not be the script or a Groovy shell. Variables holding a GroovyShell, GroovyClassLoader,
    # GroovyScriptEngine or JSR-223 engine, whose parse, run or eval compiles text.
    code_loads: list = field(default_factory=list)
    groovy_shells: set = field(default_factory=set)
    # Names a code-loading call can hide behind: `def l = this.&load` (name -> load or evaluate), and
    # `import groovy.util.Eval as E` (alias -> class name).
    code_aliases: dict = field(default_factory=dict)
    import_aliases: dict = field(default_factory=dict)
    # Variables assigned anything but a literal without interpolation, somewhere in the file: a variable
    # counts as holding reviewed text only when every assignment to it is one (the review of 2d.2k).
    nonliteral_names: set = field(default_factory=set)
    workspace_vars: set = field(default_factory=set)    # assigned from readFile and other workspace reads
    self_scm_vars: set = field(default_factory=set)     # assigned legacySCM(scm)
    script_vars: set = field(default_factory=set)       # variables and parameters given `this` or `steps`
    literal_values: dict = field(default_factory=dict)  # name -> every literal assigned to it, environment included
    workspaces: dict = field(default_factory=dict)      # id -> Workspace (flagship slice 2d.2j)
    # Flagship slice 2d.2, OBAAF-JEN-009: parameters that cannot carry text (booleanParam, choice); names whose
    # value comes from outside the file (name -> why); names that stand for `env` or `params`; the methods the
    # file defines, so a call's result can be read; a value assigned to an environment variable whose name is
    # computed ((source, severity)); a closure parameter that takes each name of a literal list.
    safe_params: set = field(default_factory=set)
    caller_values: dict = field(default_factory=dict)
    env_aliases: set = field(default_factory=set)
    param_aliases: set = field(default_factory=set)
    method_defs: dict = field(default_factory=dict)
    env_any: tuple | None = None
    key_lists: dict = field(default_factory=dict)
    webhook_unread: int | None = None                   # line of a GenericTrigger whose variables are not read
    shell_aliases: dict = field(default_factory=dict)   # def run = this.&sh: run -> sh
    uncalled_methods: set = field(default_factory=set)  # methods of the file that nothing in it calls
    closure_params: dict = field(default_factory=dict)  # def run = { x -> ... }: run -> [x]
    # values.Judge's cache of method results and the total work it may do for one file (flagship slice 2d.2).
    judge_cache: dict = field(default_factory=dict)
    judge_words: dict = field(default_factory=dict)
    judge_budget: int = 300_000
    taint_version: int = 0
    # Names set in the environment by the file (env.X =, env['X'] =, withEnv, environment {}, webhook variables):
    # what bat's %NAME% expands (flagship slice 2d.2).
    env_set: set = field(default_factory=set)
    # The review of pull request #365 (#344): (name, line) for every variable a script sets in the build's
    # environment (`env.X =`, `env['X'] =`, `env.setProperty('X', ...)`, through an alias of `env` too), which holds
    # for every step after it wherever it is; the name is "?" where it is computed.
    env_scripted: list = field(default_factory=list)
    with_env_read: set = field(default_factory=set)     # ids of the callees of the withEnv calls the walker read
    # The implicit `it` of a closure an iteration method calls: what each closure body's `it` holds, by its id, and
    # what it held where each step was recorded (flagship slice 2d.2, from its first review).
    it_values: dict = field(default_factory=dict)
    step_it: dict = field(default_factory=dict)


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


def _holds_no_step(node) -> bool:
    """A name, a literal or a property of one (`env.A`): no step runs in it, so a condition on it changes
    nothing (flagship slice 2d.2l)."""
    while isinstance(node, Prop):
        node = node.target
    return isinstance(node, (Name, Num)) or (isinstance(node, Str) and not node.interpolated)

# Groovy methods that run their closure once per item, or not at all (flagship slice 2d.2l).
ITERATING = {"each", "eachWithIndex", "reverseEach", "times", "upto", "downto", "step", "forEach", "collect",
             "collectEntries", "collectMany", "findAll", "find", "findResult", "any", "every", "inject", "eachLine",
             "eachFile", "eachFileRecurse", "eachDir", "sum", "sort", "toSorted", "findIndexOf", "findLastIndexOf",
             "findIndexValues", "count", "countBy", "groupBy", "max", "min", "unique", "takeWhile", "dropWhile",
             "retainAll", "removeAll", "eachPermutation", "eachCombination", "split"}


def submitter_value(node) -> str | None:
    """What an input's `submitter` says, as the Pipeline: Input Step plugin reads it (flagship slice 2d.2l):
    None for no submitter, `null`, or blank text (its setter applies Util.fixEmptyAndTrim, so any user with
    Build permission can respond); "?" when the file does not fix it; otherwise the text."""
    if node is None or (isinstance(node, Name) and node.name == "null"):
        return None
    text = literal(node)
    if text is None:
        return "?"
    return text if text.strip(JAVA_TRIM) else None


# Java's String.trim(), which Util.fixEmptyAndTrim uses, removes the characters up to U+0020 and no others.
JAVA_TRIM = "".join(chr(c) for c in range(0x21))


def input_submitter(call: Call) -> str | None:
    """The submitter an `input` step is given. Groovy keeps the last of a repeated key, a spread map (`*: m`)
    may hold one, and a map given as the only argument is the named arguments (`input([submitter: 'x'])`)."""
    entries = list(call.named)
    if call.args:
        if len(call.args) == 1 and isinstance(call.args[0], MapLit) and not call.named:
            entries = [(k if isinstance(k, str) else literal(k), v) for k, v in call.args[0].entries]
        elif not all(isinstance(a, Str) for a in call.args):
            return "?"          # input(m): a map whose keys the file does not show here
    value, seen = None, False
    for key, node in entries:
        if key == "*":
            value, seen = "?", True       # a later key still overrides what the spread map holds
        elif key == "submitter":
            value, seen = submitter_value(node), True
    return value if seen else None


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


_EVAL_FUNCTIONS = {"me", "x", "xy", "xyz"}
# Steps that read a file in the workspace: what they return is the change's own for a change request.
WORKSPACE_READS = {"readFile", "readJSON", "readYaml", "readProperties", "readCSV", "readMavenPom", "findFiles"}


def code_loading(name: str, shells=()) -> str | None:
    """`load`, `evaluate` or `jobDsl` when a call runs Groovy the file does not hold, on any receiver
    (flagship slice 2d.2k: `s.load(...)` with `s` the script, `Eval.me(...)`, a GroovyShell's
    `evaluate` and `parse`, `parseClass`, and Job DSL got past OBAAF-JEN-004); None otherwise."""
    if not name:
        return None
    parts = name.split(".")
    last = parts[-1]
    if name == "jobDsl":
        return "jobDsl"
    if last == "load":
        return "load"
    if last == "evaluate" or last == "parseClass":
        return "evaluate"
    if len(parts) >= 2 and parts[-2] == "Eval" and last in _EVAL_FUNCTIONS:
        return "evaluate"
    if last in ("parse", "run", "eval") and len(parts) >= 2 and _shell_receiver(parts, shells):
        return "evaluate"
    if last == "eval" and any(x in ("getEngineByName", "getEngineByExtension") or "ScriptEngine" in x
                              for x in parts[:-1]):
        return "evaluate"       # JSR-223: new ScriptEngineManager().getEngineByName('groovy').eval(...)
    return None


def _shell_receiver(parts: list, shells) -> bool:
    return parts[0] in shells or any("GroovyShell" in x or "GroovyClassLoader" in x or "GroovyScriptEngine" in x
                                     or x == "classLoader" for x in parts[:-1])


_SCRIPT_RECEIVERS = {"this", "steps", "script", "pipeline", "delegate", "owner"}
_CODE_CLASSES = {"Eval", "GroovyShell", "GroovyClassLoader", "GroovyScriptEngine"}


def code_receiver(name: str, shells, script_vars) -> bool:
    """Whether a code-loading call is surely the pipeline's own `load`/`evaluate` or a Groovy shell: no
    receiver, the script (`this`, `steps`, or a variable or parameter given `this`), Eval or a GroovyShell.
    Any other receiver (`props.load(...)`, `xpath.evaluate(...)`, a library's global variable) may be
    something else, and is reported as unknown (the review of 2d.2k)."""
    parts = name.split(".")
    if len(parts) == 1 or parts[0] in _SCRIPT_RECEIVERS or parts[0] == "Eval" or parts[-1] == "parseClass":
        return True
    if _shell_receiver(parts, shells) or code_loading(name) == "evaluate" and parts[-1] == "eval":
        return True
    return len(parts) == 2 and parts[0] in script_vars


def code_text_arg(kind: str, name: str, call: Call):
    """The argument that holds the code a code-loading call runs: the path for load, the text for
    evaluate (the last argument of Eval.x, Eval.xy and Eval.xyz), scriptText for jobDsl."""
    if kind == "jobDsl":
        return named_arg(call, "scriptText")
    if name.split(".")[-2:-1] == ["Eval"] and call.args:
        return call.args[-1]
    return first_arg(call) if call.args else named_arg(call, "path") or named_arg(call, "text")


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


def with_env_names(call: Call) -> list:
    """(name, line) for each entry of `withEnv([...])`, as Jenkins reads an entry: the text before its first `=`, so
    `PATH+OBAAF` for `PATH+OBAAF=...` (the review of pull request #365). The name is "?" for an entry the checker
    cannot read: one not written as a string or as a string joined with `+`, one whose name holds an interpolation or
    has no `=`, or a list held in a variable or built by code."""
    out = []
    args = list(call.args) + [value for _key, value in call.named]
    for arg in args:
        if not isinstance(arg, ListLit):
            out.append(("?", getattr(arg, "line", 0) or call.line))
            continue
        for item in arg.items:
            line = getattr(item, "line", 0) or call.line
            head = item
            while isinstance(head, Binary) and head.op == "+":
                head = head.left
            if not isinstance(head, Str):
                out.append(("?", line))
                continue
            name, eq, _ = head.text().partition("=")
            out.append((name.strip() if eq and name.strip() and "${" not in name else "?", line))
    return out


def matrix_axis_names(axes: list) -> list:
    """(name, line) for each `axis { name 'X' ... }` of a Declarative matrix's `axes` blocks; "?" for one whose name is
    not a literal (the review of pull request #365)."""
    out = []
    for block in axes:
        for stmt in (block.closure.stmts if isinstance(block, Call) and block.closure is not None else ()):
            axis = stmt.expr if isinstance(stmt, ExprStmt) else None
            if not (isinstance(axis, Call) and callee_name(axis) == "axis" and axis.closure is not None):
                out.append(("?", getattr(stmt, "line", 0) or block.line))
                continue
            for inner in axis.closure.stmts:
                e = inner.expr if isinstance(inner, ExprStmt) else None
                if isinstance(e, Call) and callee_name(e) == "name":
                    out.append((literal(first_arg(e)) or "?", e.line))
    return out


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


# Flagship slice 2d.2 (OBAAF-JEN-009): what a git command run with `returnStdout: true` prints. Commit text and the
# names of changed files are written by a change's author; branch and tag names by people with write access.
_GIT_CMD = re.compile(_GIT_PREFIX + r"([\w-]+)")
_GIT_ANY_FORMAT = re.compile(r"--(?:format|pretty)(?:[= ](?:(['\"])(.*?)\1|(\S+)))?")
_GIT_REF_TEXT = re.compile(r"%\((?:subject|body|contents|trailers|(?:author|committer|tagger)(?:name|email))")
_GIT_SAFE_DATES = re.compile(r"%(?:cr|ar|cD|aD|cR|aR|ch|ah|cs|as|ct|at|cd|ad|ci|ai|cI|aI|H|h|T|t|P|p|n|%)")
_GIT_NAMES = re.compile(r"--name-only|--name-status|--stat\b|--numstat")
_GIT_BRANCH_CMDS = re.compile(r"rev-parse\s+(?:.*\s)?--abbrev-ref|rev-parse\s+(?:.*\s)?--symbolic-full-name|"
                              r"branch\s+(?:.*\s)?--show-current|describe\b|symbolic-ref\b|name-rev\b|"
                              r"tag\s+(?:.*\s)?(?:--points-at|--contains|-l|--list)|branch\s+(?:-r|-a|--remote)")


def _format_has_text(spec: str) -> bool:
    if "$" in spec:                      # a format held in a variable: what it prints is not fixed
        return True
    spec = re.sub(r"^(t?format:)", "", spec)
    if spec in ("oneline", "short", "medium", "full", "fuller", "reference", "email", "raw", "mboxrd"):
        return True
    return bool(_GIT_REF_TEXT.search(spec)) or _GIT_SAFE_DATES.sub("", spec).count("%") > 0


def _worst_result(a, b):
    from obaaf.checker.jenkins.values import worst
    return worst(a, b)


def git_output(script: str):
    """(shown, severity, root) for what a script's git commands print, or None for hashes, dates and counts.
    Every git command on every line is read (a `%%` is `%`, as a batch file writes it)."""
    found = []
    text = script.replace("%%", "%")
    for line in text.splitlines():
        for m in _GIT_CMD.finditer(line):
            cmd = m.group(1)
            rest = line[m.end():]
            nxt = re.search(r"(?:&&|\|\||[;|&])", rest)
            args = rest[:nxt.start()] if nxt else rest
            if nxt and nxt.group(0) == "|" and re.match(r"\s*(?:wc\b|grep\s+(?:-\w*[cq]\w*|--count|--quiet)\b)",
                                                        rest[nxt.end():]):
                continue                     # git status --porcelain | wc -l: a count, not the names
            formats = [f.group(2) if f.group(1) else (f.group(3) or "") for f in _GIT_ANY_FORMAT.finditer(args)]
            if cmd in ("log", "show", "whatchanged", "reflog") or (cmd == "cat-file" and re.search(
                    r"(?:^|\s)(?:-p|commit|tag)\b", args)):
                if _GIT_NAMES.search(args) or not formats or any(_format_has_text(f) for f in formats):
                    found.append(("git commit text", "high"))
            elif cmd == "rev-list" and formats and any(_format_has_text(f) for f in formats):
                found.append(("git commit text", "high"))
            elif cmd in ("for-each-ref", "branch", "tag") and formats and any(
                    _GIT_REF_TEXT.search(f) or "$" in f for f in formats):
                found.append(("git commit text", "high"))
            elif cmd in ("diff", "diff-tree", "diff-index", "ls-files", "ls-tree", "status") and (
                    _GIT_NAMES.search(args) or cmd in ("ls-files", "ls-tree", "status")):
                found.append(("names of changed files from git", "high"))
            elif _GIT_BRANCH_CMDS.match(cmd + " " + args.strip()) or (
                    cmd in ("for-each-ref", "branch", "tag") and not formats):
                found.append(("a branch or tag name from git", "low"))
    if not found:
        return None
    rank = {"low": 1, "medium": 2, "high": 3}
    best = max(found, key=lambda f: rank[f[1]])
    return (best[0], best[1], best[0])


def _truthy_node(node) -> bool:
    """Whether a step argument may be true: anything but a missing argument or a literal false (2d.2)."""
    if node is None:
        return False
    text = path_of(node) or (node.text().strip().lower() if isinstance(node, Str) and not node.interpolated
                             else None)
    return text not in ("false", "null", "")


_PARAM_KINDS = {"string", "text", "password", "booleanParam", "choice", "file", "stashedFile", "base64File", "run",
                "credentials"}


_CHANGE_VARS = re.compile(r"\b(?:env\.)?(?:CHANGE_(?:ID|TARGET|BRANCH|TITLE|AUTHOR\w*|URL|FORK)|gitlabMergeRequest\w*|"
                          r"gitlabActionType|ghprb\w+)\b")
_BRANCH_VAR = re.compile(r"\b(?:env\.)?(?:BRANCH_NAME|TAG_NAME|GIT_BRANCH)\b")
# BRANCH_NAME of a change request in a multibranch job: PR-<n> (GitHub, Bitbucket), PR-<n>-head and
# PR-<n>-merge (GitHub, when both discovery strategies are on), MR-<n> (GitLab). Flagship slice 2d.2i
# added the last three; the plugins' own pages were not read in the session.
_CR_BRANCH_SAMPLES = ("PR-1", "PR-42", "PR-9001", "PR-7-head", "PR-7-merge", "MR-1", "MR-42")


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
    if reach == CR_NO:
        # Keeps every change request out when one part does (flagship slice 2d.2i: the fullness of a
        # `no` was dropped, so `not { not { changeRequest() } }` came out as only possible).
        return reach, any(r == CR_NO and f for r, f in parts)
    full = reach == CR_YES and all(r == CR_YES and f for r, f in parts)
    return reach, full


def _any(parts: list) -> tuple:
    parts = [p for p in parts if p is not None]
    reach = _combine_any([r for r, _ in parts])
    if reach == CR_NO:
        return reach, bool(parts) and all(r == CR_NO and f for r, f in parts)
    return reach, reach == CR_YES and any(r == CR_YES and f for r, f in parts)


def _inv(cond: tuple) -> tuple:
    reach, full = cond
    if reach == CR_YES:
        return (CR_NO, True) if full else (CR_POSSIBLE, False)
    if reach == CR_UNKNOWN:
        return CR_UNKNOWN, False
    if reach == CR_NO and full:
        # not { not { changeRequest() } }: what kept every change request out lets every one in
        # (flagship slice 2d.2i).
        return CR_YES, True
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
                if var in ("BRANCH_NAME", "GIT_BRANCH") else (CR_NO, True)
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
            # GIT_BRANCH holds the branch head's name in a multibranch job too (flagship slice 2d.2i).
            if arg is not None and ("BRANCH_NAME" in var or "GIT_BRANCH" in var):
                if cond.callee.name == "matches":
                    return _branch_match(arg, "REGEXP")
                pattern = arg + "*" if cond.callee.name == "startsWith" else "*" + arg
                return _branch_match(pattern.replace("[", "[[]"), "GLOB")
            if arg is not None:
                return CR_NO, True        # TAG_NAME is not PR-<n>
    if isinstance(cond, Binary) and cond.op in ("==", "!=", "==~"):
        sides = [cond.left, cond.right]
        var = next((path_of(x) for x in sides if path_of(x) and (
            _BRANCH_NAME.fullmatch(path_of(x)) or _CHANGE_ID.fullmatch(path_of(x)))), None)
        value = next((literal(x) for x in sides if literal(x) is not None), None)
        if var and value is not None and _BRANCH_NAME.fullmatch(var):
            # GIT_BRANCH holds the change request's name in a multibranch job, as BRANCH_NAME does
            # (flagship slice 2d.2k: `env.GIT_BRANCH ==~ /PR-\d+/` was read as keeping them out).
            if "BRANCH_NAME" not in var and "GIT_BRANCH" not in var:
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


# A condition's label is its readable text, as reports show it, then KEY_SEP and what makes it the condition it
# is (flagship slice 2d.2l). Two steps are under the same condition only when the whole label is equal.
KEY_SEP = "\x00"


def shown(label: str) -> str:
    """The readable part of a condition's label."""
    return label.split(KEY_SEP, 1)[0]


def guard_key(label: str) -> str:
    """What two conditions are compared by: the hidden part of a label, or the whole label when it has none."""
    return label.split(KEY_SEP, 1)[1] if KEY_SEP in label else label


def condition_key(node, limit: int = 4000) -> str:
    """A condition's whole structure as text, so that two conditions share a key only when they are written the
    same way: operators, grouping, numbers, lists, closure bodies, `return` and every other part the parser keeps
    (flagship slice 2d.2l, from its review; `_source_hint` keeps only names and strings). Past `limit` characters
    the key is the condition's place in the file, so a long condition never matches another."""
    out: list[str] = []
    size = 0
    stack = [node]
    while stack:
        if size > limit:
            return f"<condition at {getattr(node, 'line', 0)}:{getattr(node, 'col', 0)}>"
        n = stack.pop()
        if isinstance(n, _Raw):
            piece = n.text
        elif isinstance(n, str):
            piece = repr(n)
        elif isinstance(n, Str):
            piece = "Str" + repr(tuple(n.tok.parts))
        elif is_dataclass(n) and not isinstance(n, type):
            piece = type(n).__name__ + "("
            stack.append(_Raw(")"))
            # `command` is only how a call is written: `branch 'main'` is `branch('main')`.
            for f in reversed([f for f in fields(n) if f.name not in ("line", "col", "command")]):
                stack += [_Raw(","), getattr(n, f.name), _Raw(f.name + "=")]
        elif isinstance(n, (list, tuple)):
            piece = "["
            stack.append(_Raw("]"))
            for item in reversed(n):
                stack += [_Raw(","), item]
        else:
            piece = repr(n)
        out.append(piece)
        size += len(piece)
    return "".join(out)


@dataclass(frozen=True)
class _Raw:
    text: str




def declared_names(tree, limit: int = 2_000_000) -> set:
    """Every name a file declares: method and closure parameters, `def` and typed variables, the first name of
    an assignment's target, loop variables (flagship slice 2d.2l)."""
    out: set = set()
    for n in find_nodes(tree, lambda n: isinstance(n, (MethodDef, Closure, Block, Decl, Assign, Loop)), limit=limit):
        if isinstance(n, (MethodDef, Closure, Block)):
            out.update(x for x in n.params if isinstance(x, str))
        elif isinstance(n, Decl):
            # `def (a, b) = ...` is one Decl named "a,b".
            out.update(x.strip() for x in n.name.split(",") if x.strip())
        elif isinstance(n, Assign):
            # `x = ...`, `this.x = ...` and `binding.x = ...` declare x; `env.VERSION = ...` or
            # `currentBuild.description = ...` declares nothing (the fifth review of 2d.2l).
            target = path_of(n.target) or ""
            parts = target.split(".")
            if len(parts) == 1 and parts[0]:
                out.add(parts[0])
            elif len(parts) == 2 and parts[0] in ("this", "binding"):
                out.add(parts[1])
        else:
            for h in n.header:
                if isinstance(h, Decl):
                    out.add(h.name)
                elif isinstance(h, Name):
                    out.add(h.name)
                elif isinstance(h, Binary) and h.op == "in" and isinstance(h.left, Name):
                    out.add(h.left.name)
    out -= _LITERAL_NAMES
    return out


def condition_names(node, limit: int = 2000) -> frozenset | None:
    """The names a condition reads, each as ("root", name) when it is read as `name.x` or `name[...]` and as
    ("bare", name) otherwise; None when it calls something, holds a closure or an interpolation, or is too large
    to read to the end (flagship slice 2d.2l)."""
    names, rooted, count = [], set(), 0
    for n in find_nodes(node, lambda n: True, limit=limit):
        count += 1
        if isinstance(n, (Call, Closure)):
            return None
        # `"${c}" == 'true'`, `env."${key}"`: the names inside an interpolation are text the walk does not see.
        if (isinstance(n, Str) and n.interpolated) or (isinstance(n, Prop) and "$" in n.name):
            return None
        if isinstance(n, (Prop, Index)) and isinstance(n.target, Name):
            rooted.add(id(n.target))
        if isinstance(n, Name):
            names.append(n)
    if count >= limit:
        return None
    return frozenset(("root" if id(n) in rooted else "bare", n.name) for n in names)


# What a condition may read and still mean the same wherever a method is called: a property of the build's own
# objects (`env.BRANCH_NAME`, `params.RELEASE`, `currentBuild.result`), and the literal names (2d.2l).
_BUILD_ROOTS = {"env", "params", "currentBuild"}
_LITERAL_NAMES = {"true", "false", "null"}


def reads_only_globals(names: frozenset | None, local: set) -> bool:
    """Whether a condition reading `names` means the same wherever a method is called: it reads only properties
    of env, params and currentBuild, none of which the file declares as a name of its own. A bare name, even
    `BRANCH_NAME`, may be a parameter or variable the reader does not see (a closure's `{ X -> }`, `def (X, y)`,
    `binding.setVariable('X', v)`), so it ties the condition to the call (the sixth review of 2d.2l)."""
    if names is None:
        return False
    for kind, name in names:
        if name in local:
            return False
        if not (name in _LITERAL_NAMES or (kind == "root" and name in _BUILD_ROOTS)):
            return False
    return True


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


# Variables a binding sets when the Jenkinsfile does not name them (flagship slice 2d.2i). The binding's
# own argument, when given, replaces the default. AWS: plugins.jenkins.io/aws-credentials; Azure: the
# credentials-binding steps page ("If empty, default value is AZURE_CLIENT_SECRET"); git: not verified.
_DEFAULT_VARIABLES = {
    "aws": {"accessKeyVariable": "AWS_ACCESS_KEY_ID", "secretKeyVariable": "AWS_SECRET_ACCESS_KEY"},
    "AmazonWebServicesCredentialsBinding": {"accessKeyVariable": "AWS_ACCESS_KEY_ID",
                                            "secretKeyVariable": "AWS_SECRET_ACCESS_KEY"},
    "azureServicePrincipal": {"subscriptionIdVariable": "AZURE_SUBSCRIPTION_ID", "clientIdVariable": "AZURE_CLIENT_ID",
                              "clientSecretVariable": "AZURE_CLIENT_SECRET", "tenantIdVariable": "AZURE_TENANT_ID"},
    "gitUsernamePassword": {"usernameVariable": "GIT_USERNAME", "passwordVariable": "GIT_PASSWORD"},
}
# Binding kinds whose `variable` holds the path of a file with the secret, not the secret.
_PATH_KINDS = {"file", "zip", "FileBinding", "ZipFileBinding"}
_PATH_KEYS = {"keyFileVariable", "keystoreVariable"}


COMPUTED_ENV = "<computed env>"


def _computed_env(node) -> bool:
    """The expression reads an environment variable whose name is computed: env[n], env."${n}",
    env.getProperty(n), env.getAt(n), System.getenv(n) (flagship slice 2d.2i)."""
    for n in find_nodes(node, lambda n: isinstance(n, (Index, Prop, Call)), limit=400):
        if isinstance(n, Index) and path_of(n.target) == "env" and literal(n.index) is None:
            return True
        if isinstance(n, Prop) and path_of(n.target) == "env" and "${" in n.name:
            return True
        if isinstance(n, Call) and (chain_name(n.callee) or "") in (
                "System.getenv", "env.getProperty", "env.getAt", "env.get", "getProperty", "binding.getVariable",
                "getVariable", "binding.getProperty") and \
                n.args and literal(n.args[0]) is None:
            return True
    return False


def named_entries(call: Call) -> list:
    """A call's named arguments, and the entries of a map given as an argument: Groovy passes
    `string(credentialsId: 'x')` and `string([credentialsId: 'x'])` the same map (flagship slice 2d.2i)."""
    out = list(call.named)
    for arg in call.args:
        if isinstance(arg, MapLit):
            out += [(k, v) for k, v in arg.entries if isinstance(k, str)]
    return out


def bindings_of(call: Call, how: str, ctx_origin: str) -> list[Binding]:
    """Credential bindings created by a wrapper step such as withCredentials or sshagent."""
    out: list[Binding] = []
    name = chain_name(call.callee) or ""

    def make(entries: list, kind: str, line: int, how_shown: str) -> Binding | None:
        ids: list = []
        variables: list = []
        paths: list = []
        given = {k for k, _ in entries}
        for k, v in entries:
            if k in _CRED_KEYS:
                ids += _cred_ids(v)
            elif isinstance(k, str) and k.lower().endswith("variable"):
                value = literal(v)
                if value:
                    variables.append(value)
                    if (kind in _PATH_KINDS and k == "variable") or k in _PATH_KEYS:
                        paths.append(value)
                elif v is not None:
                    variables.append("?")
        for key, default in _DEFAULT_VARIABLES.get(kind, {}).items():
            if key not in given:
                variables.append(default)
        if ids or variables:
            return Binding(tuple(ids or ["?"]), tuple(variables), how_shown, line, ctx_origin, tuple(paths))
        return None

    def from_binding_call(b) -> Binding | None:
        if isinstance(b, Call):
            kind = chain_name(b.callee) or ""
            return make(named_entries(b), kind, b.line, f"{how}:{kind}")
        if isinstance(b, MapLit):
            entries = [(k, v) for k, v in b.entries if isinstance(k, str)]
            kind = (next((literal(v) for k, v in entries if k == "$class"), "") or "").rsplit(".", 1)[-1]
            return make(entries, kind, b.line, f"{how}:{kind}" if kind else how)
        return None

    if name == "withCredentials":
        items = []
        for arg in call.args:
            items += _list_parts(arg)
        for key, value in call.named:
            if key == "bindings":
                items += _list_parts(value)
        for item in items:
            b = from_binding_call(item)
            if b:
                out.append(b)
            else:
                # A binding the checker cannot read (a variable it could not follow, a computed list, a
                # method that returns one): unknown credentials in unknown variables (flagship slice 2d.2i).
                out.append(Binding(("?",), ("?",), how, call.line, ctx_origin))
        if not out and items:
            out.append(Binding(("?",), (), how, call.line, ctx_origin))
        return out
    if name == "sshagent":
        ids = []
        for arg in call.args:
            ids += _cred_ids(arg)
        ids += _cred_ids(named_arg(call, "credentials"))
        # SSH_AUTH_SOCK is the path of the agent's socket, not the key (flagship slice 2d.2i).
        return [Binding(tuple(ids or ["?"]), ("SSH_AUTH_SOCK",), how, call.line, ctx_origin, ("SSH_AUTH_SOCK",))]
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
    variables = _nested_variables(call) + list(_WRAPPER_VARIABLES.get(name, ()))
    if ids:
        return [Binding(tuple(ids), tuple(variables), how, call.line, ctx_origin)]
    if name in CREDENTIAL_WRAPPERS:
        # These steps supply credentials by design (withAWS(role: ...) assumes a role, withVault reads
        # secrets), even when no credential ID is written in the file.
        return [Binding(("?",), tuple(variables), how, call.line, ctx_origin)]
    if name == "wrap":
        cls = next((literal(v) for arg in call.args if isinstance(arg, MapLit) for k, v in arg.entries
                    if k == "$class"), None) or ""
        if re.search(r"Vault|Credential|Secret|Binding|SSHAgent|Keychain|Kubectl|Aws|Azure", cls, re.I):
            return [Binding(("?",), (), f"wrap {cls}", call.line, ctx_origin)]
    return out


def _list_parts(node) -> list:
    """The items of a list literal, of `a + b` of lists, or the node itself (a binding or something the
    checker cannot read, which becomes a binding of unknown credentials)."""
    if isinstance(node, ListLit):
        return list(node.items)
    if isinstance(node, Binary) and node.op == "+":
        return _list_parts(node.left) + _list_parts(node.right)
    return [node]


# Wrapper steps that make credentials available to the steps inside them.
CREDENTIAL_WRAPPERS = {"withAWS", "withVault", "withKubeConfig", "withKubeCredentials", "withDockerRegistry",
                       "withDockerServer", "withAzureCLI", "withAzureVault", "withGCP", "withNPM",
                       "withSonarQubeEnv", "withGitHubToken", "withAnsible", "kubeconfig", "azureCLI"}


# Variables a wrapper sets in the environment of the steps inside it (not verified against each plugin's
# page): withAWS sets the AWS keys, withSonarQubeEnv the server's token.
_WRAPPER_VARIABLES = {"withAWS": ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"),
                      "withSonarQubeEnv": ("SONAR_AUTH_TOKEN",)}


def _nested_variables(call: Call, limit: int = 200) -> list[str]:
    """Literal values of `...Variable` and `envVar` keys at any depth of a wrapper's arguments:
    withVault(vaultSecrets: [[secretValues: [[envVar: 'TOKEN', vaultKey: 'x']]]]) (flagship slice 2d.2i)."""
    out: list[str] = []
    stack = [(k, v) for k, v in call.named] + [("", a) for a in call.args]
    seen = 0
    while stack and seen < limit:
        key, node = stack.pop()
        seen += 1
        if isinstance(key, str) and (key.lower().endswith("variable") or key == "envVar") and literal(node):
            out.append(literal(node))
            continue
        if isinstance(node, MapLit):
            stack += [(k, v) for k, v in node.entries]
        elif isinstance(node, ListLit):
            stack += [("", item) for item in node.items]
        elif isinstance(node, Call):
            stack += [(k, v) for k, v in node.named] + [("", a) for a in node.args]
    return out


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
                a.custom_workspace = inner.custom_workspace
            else:
                a.label = literal(arg)
        elif name == "customWorkspace":
            a.custom_workspace = literal(arg) or "?"
        elif name == "docker":
            a.kind = "docker"
            if expr.closure is not None:
                _docker_details(a, expr.closure)
            else:
                _set_image(a, arg)
                args = named_arg(expr, "args")
                a.args = _args_text(args)
                _reuse(a, named_arg(expr, "reuseNode"))
        elif name == "dockerfile":
            a.kind = "dockerfile"
            if expr.closure is not None:
                _docker_details(a, expr.closure)
            else:
                # `dockerfile true` builds ./Dockerfile; any other value is not read.
                a.dockerfile = "Dockerfile" if path_of(arg) == "true" else "?"
                _reuse(a, named_arg(expr, "reuseNode"))
        elif name == "kubernetes":
            a.kind = "kubernetes"
            if expr.closure is not None:
                _k8s_details(a, expr.closure)
            for key, value in expr.named:
                _k8s_key(a, key, value)
        elif name in ("any", "none"):
            a.kind = name
    return a


def _reuse(a: Agent, node) -> None:
    """reuseNode of a docker or dockerfile agent: "true", "?" when the file does not fix it, None for false
    (flagship slice 2d.2j)."""
    if node is None:
        return
    value = path_of(node) or literal(node)
    a.reuse = "true" if value == "true" else None if value == "false" else "?"


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
        # `image params.X`, `image IMG`: a value the rules resolve from the file's literals or report as
        # computed (flagship slice 2d.2k: such an image was dropped, and OBAAF-JEN-008 said nothing).
        text = text_of(node)
        if text is None:
            text = "${" + (path_of(node) or "computed") + "}"
        a.image, a.image_dynamic = text, True


def _docker_details(a: Agent, block: Block) -> None:
    filename = folder = None
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
            elif name == "reuseNode":
                _reuse(a, first_arg(expr))
            elif name == "customWorkspace":
                a.custom_workspace = literal(first_arg(expr)) or "?"
            elif name == "filename":
                filename = literal(first_arg(expr)) or "?"
            elif name == "dir":
                folder = literal(first_arg(expr)) or "?"
            elif name == "additionalBuildArgs":
                arg = first_arg(expr)
                a.build_args = literal(arg) if literal(arg) is not None else (text_of(arg) or "${computed}")
    if a.kind == "dockerfile":
        a.dockerfile = _dockerfile_path(folder, filename)


def _dockerfile_path(folder: str | None, filename: str | None) -> str:
    """The Dockerfile a `dockerfile` agent builds: `filename` inside `dir`, by default ./Dockerfile."""
    if folder == "?" or filename == "?":
        return "?"
    parts = [x.strip("/") for x in (folder, filename or "Dockerfile") if x and x.strip("/") not in ("", ".")]
    return "/".join(parts) or "Dockerfile"


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
        a.label_ref = path_of(value) if a.label is None else None
        a.label_text = text_of(value)
    elif key == "containers" and isinstance(value, ListLit):
        for item in value.items:
            if isinstance(item, Call) and callee_name(item) == "containerTemplate":
                _container_image(a, item)
            else:
                a.images_unknown = True
    elif key == "containers" and value is not None:
        a.images_unknown = True       # a list the file builds or changes elsewhere (flagship slice 2d.2k)
    elif key == "volumes" and isinstance(value, ListLit):
        for item in value.items:
            if isinstance(item, Call) and callee_name(item) == "hostPathVolume":
                path = literal(named_arg(item, "hostPath")) or "?"
                a.pod_settings.append("a mount of the Docker socket" if "docker.sock" in path else "a hostPath volume")
    elif key == "hostNetwork" and (path_of(value) == "true" or (literal(value) or "").lower() == "true"):
        a.pod_settings.append("host networking")
    elif key == "workspaceVolume" and value is not None:
        # The Kubernetes plugin's workspace volumes: emptyDir, a per-pod dynamic claim and a generic ephemeral
        # volume die with the pod; a named claim, a host path and an NFS export are kept (flagship slice 2d.2j).
        kind = callee_name(value) if isinstance(value, Call) else None
        if kind in ("emptyDirWorkspaceVolume", "dynamicPVC", "genericEphemeralVolume"):
            a.pod_workspace = None
        else:
            # "claim:NAME" and "nfs:PATH" are one directory wherever the pod runs; "host:PATH" is the node's.
            which = None
            for key, tag in (("claimName", "claim"), ("serverPath", "nfs"), ("hostPath", "host")):
                if isinstance(value, Call) and named_arg(value, key) is not None:
                    found = literal(named_arg(value, key))
                    if found is not None and tag != "claim":
                        found = re.sub(r"/+", "/", found).rstrip("/") or "/"
                    if found is not None and tag == "nfs":
                        server = (literal(named_arg(value, "serverAddress")) or "").lower() or None
                        found = f"{server}:{found}" if server is not None else None
                    which = f"{tag}:{found}" if found is not None else None
                    break
            a.pod_workspace = which or "?"
            if kind == "hostPathWorkspaceVolume":
                path = (which or "host:?")[5:]
                a.pod_settings.append("a mount of the host root file system" if path == "/" else "a hostPath volume")


def _container_image(a: Agent, item: Call) -> None:
    """The image of a containerTemplate: a named argument, or `image '...'` in its closure (flagship
    slice 2d.2k: the closure form was reported as "Image '?'"); and `privileged: true` (slice 2d.2j)."""
    if path_of(named_arg(item, "privileged")) == "true" or (literal(named_arg(item, "privileged")) or "").lower() == "true":
        a.pod_settings.append("a privileged container")
    img = named_arg(item, "image")
    if img is None and item.closure is not None:
        for stmt in item.closure.stmts:
            expr = stmt.expr if isinstance(stmt, ExprStmt) else None
            if isinstance(expr, Call) and callee_name(expr) == "image":
                img = first_arg(expr)
    if img is None:
        a.images_unknown = True
        return
    text = literal(img) or text_of(img) or ("${" + path_of(img) + "}" if path_of(img) else "${computed}")
    a.images.append((text, item.line))


def _k8s_details(a: Agent, block: Block) -> None:
    for stmt in block.stmts:
        if isinstance(stmt, Assign) and path_of(stmt.target):
            _k8s_key(a, path_of(stmt.target), stmt.value)
            continue
        expr = stmt.expr if isinstance(stmt, ExprStmt) else None
        if isinstance(expr, Call):
            name = callee_name(expr)
            if name in ("yaml", "yamlFile", "inheritFrom", "label", "workspaceVolume"):
                _k8s_key(a, name, first_arg(expr))
            elif name == "containerTemplate":
                _container_image(a, expr)


# Keys of a library retriever that do not choose which code is fetched.
_NOT_CODE_KEYS = {"$class", "credentialsId", "id", "changelog"}

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
    """Whether a catch block always throws again (throw, or the error step), so the failure still stops the
    build. A throw under a condition does not count (flagship slice 2d.2l: `if (user) { error(...) }` lets a
    timeout through)."""
    for stmt in block.stmts:
        if isinstance(stmt, Return) and stmt.throw:
            return True
        expr = stmt.expr if isinstance(stmt, ExprStmt) else None
        if isinstance(expr, Call) and (callee_name(expr) == "error" or chain_name(expr.callee) == "steps.error"):
            return True
        if isinstance(stmt, Block) and _rethrows(stmt):
            return True
        # stage('Notify') { throw e }: a step that runs its body once, and does not catch, throws on.
        if isinstance(expr, Call) and expr.closure is not None and callee_name(expr) in _RUNS_BODY_ONCE and \
                _rethrows(expr.closure):
            return True
    return False


_RUNS_BODY_ONCE = {"stage", "node", "dir", "ws", "timeout", "script", "withCredentials", "withEnv", "container",
                   "sshagent", "wrap", "lock", "timestamps", "ansiColor", "withDockerContainer", "withAWS",
                   "withVault", "configFileProvider", "withKubeConfig", "withDockerRegistry", "steps"}


def _list_items(node) -> list:
    return list(node.items) if isinstance(node, ListLit) else []


def _key(k) -> str | None:
    """A map key as text: `a:`, `'a':` or `$class:`."""
    if isinstance(k, str):
        return k
    return literal(k) or path_of(k)


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
        self.it_stack: list = []                   # the implicit `it` of the closure bodies being walked (2d.2)
        self.closure_bodies: dict = {}             # def g = f: g -> f's body, for OBAAF-JEN-009 only (2d.2)
        self.called: set[str] = set()
        self.stack: list[str] = []
        self.budget = self.INLINE_BUDGET
        self.seq = 0
        self.keys: dict = {}
        self.declared: set = set()
        # For each method being expanded, its closure parameter -> (the caller's closure, walked yet).
        self.closure_args: list[dict] = []
        # Closures and method pointers assigned to variables of this file (flagship slice 2d.2i):
        # name -> Block of the closure; name -> method name (def f = this.&build); name -> {key: Block}.
        self.closure_vars: dict[str, Block] = {}
        self.method_refs: dict[str, str] = {}
        self.closure_maps: dict[str, dict] = {}
        # Variables the file changes other than by assigning them (`b << x`, `b.add(x)`, `b += x`): a list
        # held in one is not taken for the list first assigned (the review of slice 2d.2i).
        self.changed_lists: set[str] = set()

    # -- workspaces (flagship slice 2d.2j) -------------------------------------------------
    def new_ws(self, kind: str, line: int, label: str | None = None, custom: str | None = None,
               machine: int | None = None, how: str = "") -> int:
        """A new workspace allocation. `machine` is the node it is on (a new one when None)."""
        wid = len(self.p.workspaces) + 1
        self.p.workspaces[wid] = Workspace(wid, machine if machine else wid, kind, line, label, custom, how)
        return wid

    def agent_ws(self, agent: Agent, ctx: Ctx) -> int:
        """The workspace the steps under a Declarative agent directive run in. The top-level agent holds one
        workspace for every stage without an agent of its own ("where the entire Pipeline ... will execute");
        `agent none` allocates nothing; a docker or dockerfile agent with `reuseNode true` runs "on the node
        specified at the top-level of the Pipeline, in the same workspace" (the Jenkins handbook, Pipeline
        Syntax). Any other agent allocates its own. A reuseNode the file does not fix is read as reused, the
        reading under which more steps share a workspace."""
        if agent.kind == "none":
            return ctx.ws
        if agent.kind in ("docker", "dockerfile") and agent.reuse and ctx.ws:
            return ctx.ws
        label = agent.label if agent.kind in ("label", "node", "docker", "dockerfile", "kubernetes") else None
        custom = agent.pod_workspace if agent.kind == "kubernetes" else agent.custom_workspace
        return self.new_ws(agent.kind, agent.line, label, custom, how=f"the agent directive at line {agent.line}")

    def context_ws(self, ctx: Ctx, line: int, how: str, kind: str = "context") -> Ctx:
        """Code whose workspace is the caller's and the caller is not in this file (a method nothing here calls,
        a closure where it is written, the body of a step whose code the checker does not have): one workspace
        of its own, shared by everything in it. Inside a known workspace it stays there."""
        if ctx.ws:
            return ctx
        return replace(ctx, ws=self.new_ws(kind, line, how=how))

    def build(self, tree: Block) -> Pipeline:
        # Methods may be defined below their first use; collect the top-level ones first. A method the
        # file calls is walked where it is called, with the caller's stage, credentials and conditions.
        for stmt in tree.stmts:
            target = stmt.target if isinstance(stmt, Annotated) else stmt
            if isinstance(target, MethodDef):
                self.defs.setdefault(target.name, []).append(target)
                if not target.params:
                    self.methods[target.name] = target.body
        self.p.method_defs = self.defs
        if self.defs:
            self.called = {callee_name(c) for c in find_calls(tree, set(self.defs))}
        self.p.uncalled_methods = {n for n in self.defs if n not in self.called}
        # Every name the file declares anywhere, before the walk: a method's or closure's parameter, a variable, an
        # assigned name, a loop variable (flagship slice 2d.2l, from its fourth review: names collected while
        # walking missed methods defined below their use and closure parameters).
        self.declared = declared_names(tree)
        # A list is followed into withCredentials only when its name is used nowhere else: passed to a method or
        # copied to another name, it can be changed there (the second review of slice 2d.2i).
        uses: dict[str, int] = {}
        for n in find_nodes(tree, lambda n: isinstance(n, Name)):
            uses[n.name] = uses.get(n.name, 0) + 1
        in_bindings: dict[str, int] = {}
        for c in find_nodes(tree, lambda n: isinstance(n, Call) and (chain_name(n.callee) or "").removeprefix(
                "steps.") == "withCredentials"):
            for a in list(c.args) + [v for k, v in c.named if k == "bindings"]:
                for part in _list_parts(a):
                    if isinstance(part, Name):
                        in_bindings[part.name] = in_bindings.get(part.name, 0) + 1
        self.changed_lists.update(name for name, count in uses.items() if count > in_bindings.get(name, 0))
        for n in find_nodes(tree, lambda n: isinstance(n, (Binary, Call, Assign))):
            if isinstance(n, Binary) and n.op == "<<" and path_of(n.left):
                self.changed_lists.add(path_of(n.left))
            elif isinstance(n, Call) and isinstance(n.callee, Prop) and path_of(n.callee.target) and \
                    n.callee.name in ("add", "addAll", "push", "leftShift", "plus", "putAt", "set", "remove", "clear",
                                      "removeAll", "retainAll", "putAll", "put"):
                self.changed_lists.add(path_of(n.callee.target))
            elif isinstance(n, Assign) and n.op != "=" and path_of(n.target):
                self.changed_lists.add(path_of(n.target))
            elif isinstance(n, Assign) and path_of(n.target) is None and path_of(getattr(n.target, "target", None)):
                self.changed_lists.add(path_of(n.target.target))
        declarative = any(isinstance(s, ExprStmt) and isinstance(s.expr, Call) and callee_name(s.expr) == "pipeline"
                          for s in tree.stmts)
        self.p.kind = "declarative" if declarative else "scripted"
        # Triggers decide who can start the whole pipeline, wherever they are declared (a triggers {}
        # directive or properties([pipelineTriggers([...])])), so read them before walking.
        # Build parameters, wherever declared (a parameters {} directive or properties([parameters([...])])):
        # string, text and password parameters carry text; a booleanParam or a choice cannot (flagship slice 2d.2).
        texty: set = set()
        safe: set = set()
        for c in find_nodes(tree, lambda n: isinstance(n, Call) and callee_name(n) == "parameters"):
            for d in find_nodes(c, lambda n: isinstance(n, Call) and callee_name(n) in _PARAM_KINDS):
                pname = literal(named_arg(d, "name"))
                if pname:
                    (safe if callee_name(d) in ("booleanParam", "choice") else texty).add(pname)
        self.p.string_params.update(texty)
        self.p.safe_params.update(safe - texty)
        self.list_decls = {}
        for n in find_nodes(tree, lambda n: isinstance(n, (Decl, Assign))):
            name = n.name if isinstance(n, Decl) else path_of(n.target)
            if name and isinstance(n.value, ListLit):
                self.list_decls.setdefault(name, []).append(n.value)
        for node in _trigger_nodes(tree):
            self.trigger(node)
        start = Ctx(cr=CR_YES) if any(t.change_requests for t in self.p.triggers) else Ctx()
        self.block(tree, start, top=True)
        # Each call inside a closure body whose implicit `it` holds a value, wherever the body was walked from
        # (flagship slice 2d.2): read by OBAAF-JEN-009 at each step.
        # Outer bodies first, so the innermost body with its own `it` decides (a literal loop inside a tainted one).
        bodies = []
        for block, found in list(self.p.it_values.values()):
            calls = list(find_nodes(block, lambda n: isinstance(n, Call), limit=200_000))
            bodies.append((len(calls), calls, found))
        for _size, calls, found in sorted(bodies, key=lambda b: -b[0]):
            for n in calls:
                if found is None:
                    self.p.step_it.pop(id(n), None)
                else:
                    self.p.step_it[id(n)] = (n, found)
        return self.p

    def trigger(self, node) -> None:
        def arg(key):
            if isinstance(node, Call):
                # GenericTrigger([token: 'x']) passes the same map as GenericTrigger(token: 'x').
                return next((v for k, v in named_entries(node) if k == key), None)
            return _entry(node, key)
        if isinstance(node, Call):
            name = callee_name(node) or ""
        else:
            name = (next((literal(v) for k, v in node.entries if k == "$class"), "") or "").rsplit(".", 1)[-1]
        # GitLab's webhook secret is `secretToken` (plugins.jenkins.io/gitlab-plugin); flagship slice 2d.2i.
        token_key = "secretToken" if name in ("gitlab", "GitLabPushTrigger") else "token"
        token_node = arg(token_key)
        token = literal(token_node)
        change_requests = False
        if name == "GenericTrigger":
            text = " ".join(filter(None, (literal(arg("regexpFilterExpression")), literal(arg("regexpFilterText")),
                                          literal(arg("causeString")))))
            for key, source in (("genericVariables", "payload"), ("genericRequestVariables", "request parameter"),
                                ("genericHeaderVariables", "request header")):
                given = arg(key)
                if isinstance(given, Name):
                    # The list held in a variable assigned once (flagship slice 2d.2); anything else is not read.
                    found = self.list_decls.get(given.name, [])
                    given = found[0] if len(found) == 1 else None
                    if given is None:
                        self.p.webhook_unread = node.line
                elif given is not None and not isinstance(given, ListLit):
                    self.p.webhook_unread = node.line
                for item in _list_items(given):
                    var = literal(_entry(item, "key"))
                    path = literal(_entry(item, "value")) or ""
                    if not var:
                        if isinstance(item, (MapLit, Call)):
                            self.p.webhook_unread = node.line
                        continue
                    text += " " + path
                    # A payload value is text anyone who can send the hook chose, unless the path ends in a field
                    # that is a number, a count or an identifier (flagship slice 2d.2: `$` and `$.pull_request`,
                    # which hold the title, were medium, and `$.pull_request.comments`, a count, was high).
                    last = re.split(r"[.\[\]]+", path.strip("$.[] "))[-1] if path.strip("$.[] ") else ""
                    numeric = re.search(r"(^|_)(id|number|count|size|sha|comments|commits|additions|deletions|"
                                        r"changed_files|review_comments|after|before|action|merged|draft|state|"
                                        r"private|fork|forced|created|deleted)$|_at$", last, re.I)
                    severity = "medium" if source != "payload" or numeric else "high"
                    shown = f"webhook {source} {path or var}".strip()
                    names = {var, var + "_0"}
                    if source == "request header":
                        # Header variables reach the build lower-cased (the plugin's page shows `headerwithnumber`
                        # for a header variable `headerWithNumber`); other characters as `_` is assumed.
                        folded = var.lower()
                        names |= {folded, folded + "_0", re.sub(r"[^a-z0-9_]", "_", folded),
                                  re.sub(r"[^a-z0-9_]", "_", folded) + "_0"}
                    for n in names:
                        self.p.env_set.add(n)
                        current = self.p.tainted.get(n)
                        if current is None or _RANK[severity] > _RANK[current[1]]:
                            self.p.tainted[n] = (shown, severity)
                            self.p.taint_version += 1
            change_requests = bool(re.search(r"pull|merge_request|mergeRequest|\bpr\b|pr:|changes", text, re.I))
        elif name in ("ghprbTrigger", "githubPullRequests", "GhprbTrigger", "bitbucketPR"):
            change_requests = True
        elif name in ("gitlab", "GitLabPushTrigger"):
            flag = arg("triggerOnMergeRequest")
            change_requests = flag is None or path_of(flag) != "false"
        self.p.triggers.append(Trigger(name, node.line, change_requests, token,
                                       token_node if token is None else None, token_key))

    # -- generic statements ------------------------------------------------------------
    def block(self, block: Block | None, ctx: Ctx, top: bool = False) -> None:
        if block is None:
            return
        params = [x for x in getattr(block, "params", ()) if isinstance(x, str)]
        if params:
            # A trailing closure's parameters take values from whoever calls it (the second review of 2d.2k).
            # They are not added to the names the file defines: a call through one stays unknown code.
            self.p.nonliteral_names.update(params)
        bound = self.p.it_values.get(id(block))
        if bound is not None and bound[0] is block:
            self.it_stack.append(bound[1])           # the implicit `it` of this closure body (2d.2)
        try:
            for stmt in block.stmts:
                self.stmt(stmt, ctx)
        finally:
            if bound is not None and bound[0] is block:
                self.it_stack.pop()

    def condition_tag(self, node, ctx: Ctx) -> str:
        """The hidden part of a condition's label: its structure's digest, cached per node, and, inside an
        inlined method, the call when the condition reads more than the build's own values (2d.2l)."""
        cached = self.keys.get(id(node))
        if cached is None or cached[0] is not node:
            digest = hashlib.sha256(condition_key(node).encode("utf-8", "surrogatepass")).hexdigest()[:16]
            cached = (node, digest, condition_names(node))
            self.keys[id(node)] = cached
        tag = cached[1]
        if ctx.invocation and not reads_only_globals(cached[2], ctx.invocation[1] | self.declared):
            tag += f" call {ctx.invocation[0]}"
        return tag

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    @staticmethod
    def site(ctx: Ctx, node) -> str:
        """Where a condition is written, and in which call of an inlined method (flagship slice 2d.2l)."""
        call = f"#{ctx.invocation[0]}" if ctx.invocation else ""
        return f"{node.line}:{getattr(node, 'col', 0)}{call}"

    @staticmethod
    def narrowed(ctx: Ctx, condition: str, line: int, guard: str | None = None) -> Ctx:
        cr = narrow(ctx.cr, condition)
        guards = ctx.guards + (guard,) if guard else ctx.guards
        if cr == CR_UNKNOWN and ctx.cr != CR_UNKNOWN:
            return replace(ctx, cr=cr, cr_line=line, guards=guards)
        return replace(ctx, cr=cr, guards=guards)

    def stmt(self, stmt, ctx: Ctx) -> None:
        if isinstance(stmt, Import):
            # import groovy.util.Eval as E: E.me(...) is Eval.me(...) (the review of 2d.2k).
            words = stmt.path.split()
            if "as" in words and words.index("as") + 1 < len(words):
                target = "".join(words[:words.index("as")]).split(".")[-1]
                self.p.import_aliases[words[words.index("as") + 1]] = target
            return
        if isinstance(stmt, ExprStmt):
            e = stmt.expr
            if isinstance(e, Binary) and e.op == "<<":
                # sb << value, and sb << 'a' << value: the leftmost holds every value shifted in (2d.2).
                rights, root = [], e
                while isinstance(root, Binary) and root.op == "<<":
                    rights.append(root.right)
                    root = root.left
                if path_of(root):
                    self.track_value(path_of(root), ListLit(rights, line=e.line), merge=True)
            self.expr(stmt.expr, ctx)
        elif isinstance(stmt, Decl):
            self.p.local_names.add(stmt.name)
            if stmt.value is not None:
                if "," in stmt.name:
                    # def (a, b) = [x, y]: each name takes its element, or any of them (flagship slice 2d.2).
                    names = [n.strip() for n in stmt.name.split(",")]
                    items = stmt.value.items if isinstance(stmt.value, ListLit) else []
                    for i, n in enumerate(names):
                        self.p.local_names.add(n)
                        self.track_value(n, items[i] if i < len(items) else stmt.value)
                self.track_value(stmt.name, stmt.value)
                self.expr(stmt.value, ctx)
        elif isinstance(stmt, Assign):
            target = path_of(stmt.target) or path_of(getattr(stmt.target, "target", None))
            if target and target.startswith("env.") and (target[4:] == "OBAAF_LANE"
                                                          or is_lane_variable_spelling(target[4:])):
                # `env.OBAAF_LANE = 'agent'` in a script sets the variable for later steps when the build
                # runs; the checker reads lanes from environment blocks and withEnv only (2d.2a left this).
                self.p.unread_lanes.append(("jenkins-scripted", target[4:], literal(stmt.value), stmt.line,
                                            " > ".join(ctx.stage)))
            if target and path_of(stmt.target):
                # The review of pull request #365: `env.PATH = ...` (also through `this.`, `script.` or an alias of
                # `env`) holds for every later step, wherever it is.
                scoped = target
                for prefix in ("this.", "script.", "binding.", "steps."):
                    scoped = scoped.removeprefix(prefix)
                base, _, rest = scoped.partition(".")
                if rest and (base == "env" or base in self.p.env_aliases):
                    self.p.env_scripted.append((rest if "${" not in rest and "." not in rest else "?", stmt.line))
            if target:
                self.p.local_names.add(target.split(".")[0])
                if path_of(stmt.target) and "." in target and not target.startswith("env.") and \
                        isinstance(stmt.value, Closure):
                    base, _, attr = target.partition(".")
                    if "." not in attr:
                        self.closure_maps.setdefault(base, {})[attr] = stmt.value.body
                if path_of(stmt.target):
                    plain = target
                    for prefix in ("this.", "binding.", "script."):
                        if plain.startswith(prefix) and "." not in plain[len(prefix):]:
                            plain = plain[len(prefix):]          # this.T = x: T holds it (2d.2)
                    if plain.startswith("env.") and "${" in plain:
                        self.taint_env_any(stmt.value)           # env."${n}" = x
                    else:
                        if plain.startswith("env."):
                            self.p.env_set.add(plain[4:])
                        self.track_value(plain.removeprefix("env."), stmt.value)
                    if target.endswith(".delegate") and target.split(".")[0] in (
                            self.p.method_params | set(self.p.caller_values)) and path_of(stmt.value):
                        # body.delegate = config; body(): the caller's closure fills config (a vars/ step).
                        self.p.caller_values.setdefault(path_of(stmt.value),
                                                        "a map the caller's closure fills, outside this file")
                    for prefix in ("this.", "binding."):
                        if target.startswith(prefix) and "." not in target[len(prefix):]:
                            self.p.nonliteral_names.add(target[len(prefix):])
                elif isinstance(stmt.target, Index) and path_of(stmt.target.target) in ("binding", "this") and \
                        literal(stmt.target.index) is not None:
                    self.p.nonliteral_names.add(literal(stmt.target.index))   # binding['code'] = ...
                elif isinstance(stmt.target, Index) and path_of(stmt.target.target) in {"env", "this.env"} | \
                        self.p.env_aliases:
                    key = literal(stmt.target.index)
                    if key is None and isinstance(stmt.target.index, Name):
                        seen = self.p.literal_values.get(stmt.target.index.name)
                        if seen and len(seen) == 1 and stmt.target.index.name not in self.p.nonliteral_names:
                            key = next(iter(seen))
                    self.p.env_scripted.append((key if key is not None else "?", stmt.line))   # review of #365
                    if key is not None:
                        # env['T'] = x (2d.2): T holds x for OBAAF-JEN-009; OBAAF-JEN-013 reads `env` as before.
                        self.p.env_set.add(key)
                        self.taint(key, self.judge(stmt.value))
                    else:
                        self.taint_env_any(stmt.value)
                    # As before 2d.2, `env` itself is recorded as holding the value, which OBAAF-JEN-013 reads; it is
                    # not tainted, so `env.Y` and the names read in a text are not reported for it.
                    self.track_value(target.split(".")[0], stmt.value, merge=True, no_taint=True)
                else:
                    # x['key'] = value, x.y[0] = value: the container now holds the value.
                    self.track_value(target.split(".")[0], stmt.value, merge=True)
                    # tasks['a'] = { ... }: a map of closures, for `parallel tasks` (flagship slice 2d.2i).
                    index = getattr(stmt.target, "index", None)
                    if isinstance(stmt.value, Closure) and path_of(stmt.target) is None and \
                            path_of(getattr(stmt.target, "target", None)) == target:
                        key = literal(index) if index is not None else None
                        self.closure_maps.setdefault(target, {})[key if key is not None else
                                                             f"computed {stmt.line}"] = stmt.value.body
            self.expr(stmt.value, ctx)
        elif isinstance(stmt, If):
            cond = if_eval(stmt.cond, self.methods)
            # The label shows the condition as before; its hidden part tells conditions written differently, and
            # calls of an inlined method, apart (flagship slice 2d.2l: `onlyIf(params.ASK) { input }` and
            # `onlyIf(true) { publish }`, also through a local copy or a closure given to another method).
            hint, tag = _source_hint(stmt.cond), self.condition_tag(stmt.cond, ctx)
            self.expr(stmt.cond, ctx)
            self.block(stmt.then, self.narrowed(ctx, cond[0], stmt.line, f"if {hint}{KEY_SEP}if {tag}"))
            if stmt.otherwise is not None:
                self.block(stmt.otherwise, self.narrowed(ctx, _inv(cond)[0], stmt.line,
                                                         f"if not {hint}{KEY_SEP}if not {tag}"))
        elif isinstance(stmt, Loop):
            for h in stmt.header:
                if isinstance(h, Decl):
                    self.p.local_names.add(h.name)
                    self.p.nonliteral_names.add(h.name)
                elif isinstance(h, Name):
                    self.p.local_names.add(h.name)
                    self.p.nonliteral_names.add(h.name)
                elif isinstance(h, Binary) and h.op == "in" and isinstance(h.left, Name):
                    self.p.local_names.add(h.left.name)
                    self.p.nonliteral_names.add(h.left.name)
                    self.bind_each([h.left.name], h.right)           # for (x in values) (2d.2)
                self.expr(h, ctx)
            # A loop body may run zero times: it is conditional.
            loop = f"loop {stmt.line}{KEY_SEP}loop {self.site(ctx, stmt)}"
            self.block(stmt.body, replace(ctx, guards=ctx.guards + (loop,)))
        elif isinstance(stmt, Try):
            body_ctx = ctx
            catches = [h for h, kind in zip(stmt.handlers, stmt.kinds or ["catch"] * len(stmt.handlers))
                       if kind == "catch"]
            if catches and not all(_rethrows(h) for h in catches):
                # A failure in the body is caught and not thrown again, so it does not stop the build.
                body_ctx = replace(ctx, swallowed=f"try/catch at line {stmt.line} without rethrow",
                                   swallow_id=self.next_seq())
            self.block(stmt.body, body_ctx)
            # catch and finally blocks run after the body failed or stopped part way.
            for h in stmt.handlers:
                self.block(h, replace(ctx, post="catch/finally", post_owner=None))
        elif isinstance(stmt, Switch):
            branchy = bool(_BRANCH_VAR.search(_source_hint(stmt.subject)) or _CHANGE_VARS.search(
                _source_hint(stmt.subject)))
            for number, case in enumerate(stmt.cases):
                inner = self.narrowed(ctx, CR_UNKNOWN, stmt.line) if branchy else ctx
                # Each case is its own condition: a step in one case does not run in another (2d.2l).
                self.block(case, replace(inner, guards=inner.guards + (
                    f"switch {stmt.line}{KEY_SEP}switch {self.site(ctx, stmt)} case {number}",)))
        elif isinstance(stmt, Return):
            if stmt.value is not None:
                self.expr(stmt.value, ctx)
        elif isinstance(stmt, MethodDef):
            self.p.local_names.add(stmt.name)
            self.p.local_names.update(p for p in stmt.params if isinstance(p, str))
            if stmt.name in self.called and any(stmt is d for d in self.defs.get(stmt.name, [])):
                return    # walked at each call, in the caller's context
            self.p.method_params.update(p for p in stmt.params if isinstance(p, str))
            self.p.nonliteral_names.update(p for p in stmt.params if isinstance(p, str))
            # A method nothing in this file calls (a shared-library step, `call()` in vars/) can be
            # called from any stage, so whether change requests reach it is unknown.
            self.block(stmt.body, replace(self.context_ws(ctx, stmt.line, f"method {stmt.name}() at line {stmt.line}, "
                                                          "which nothing in this file calls"),
                                          in_function=stmt.name, cr=CR_UNKNOWN, cr_line=stmt.line,
                                          stage=ctx.stage + (f"{stmt.name}()",),
                                          deferred=f"method {stmt.name}() at line {stmt.line}, which nothing in "
                                                   "this file calls"))
        elif isinstance(stmt, ClassDef):
            self.p.local_names.add(stmt.name)
            self.p.opaque.append((stmt.line, f"class {stmt.name}"))
            self.block(stmt.body, replace(self.context_ws(ctx, stmt.line, f"class {stmt.name} at line {stmt.line}"),
                                          in_function=stmt.name, cr=CR_UNKNOWN, cr_line=stmt.line,
                                          deferred=f"class {stmt.name} at line {stmt.line}"))
        elif isinstance(stmt, Annotated):
            if stmt.annotation in ("Library", "groovy.lang.Library"):
                self.annotation_libraries(stmt)
            elif stmt.annotation in ("Grab", "Grapes", "GrabResolver", "GrabConfig"):
                self.p.opaque.append((stmt.line, f"@{stmt.annotation}: dependencies fetched at compile time"))
            if stmt.target is not None:
                self.stmt(stmt.target, ctx)
        elif isinstance(stmt, Opaque):
            self.p.opaque.append((stmt.line, f"statement not analyzed ({stmt.reason})"))

    def track_value(self, name: str, value, merge: bool = False, no_taint: bool = False) -> None:
        """Remember values that matter later: docker images, literal strings, and text from untrusted
        sources, however the value is built (interpolation, +, ?:, .trim(), env['X'], maps, lists)."""
        if value is None:
            return
        if isinstance(value, Str) and not merge:
            self.p.literals[name] = value
        elif not merge:
            self.p.literals.pop(name, None)
        if not (isinstance(value, Str) and not value.interpolated):
            self.p.nonliteral_names.add(name)
        if isinstance(value, Name) and value.name in ("this", "steps"):
            self.p.script_vars.add(name)
        last = (path_of(value) or "").split(".")[-1]
        if isinstance(value, (Name, Prop)) and last in _CODE_CLASSES and path_of(value) not in self.p.literals:
            self.p.import_aliases[name] = last           # def E = Eval, def E = groovy.util.Eval (2d.2k)
        if isinstance(value, Name) and value.name in self.p.groovy_shells:
            self.p.groovy_shells.add(name)               # def alias = shell
        if isinstance(value, Name) and value.name in self.p.code_aliases:
            self.p.code_aliases[name] = self.p.code_aliases[value.name]   # def m = l
        pointed = self._pointer(value)
        if pointed is not None:
            self.p.code_aliases[name] = pointed if pointed != "evaluate" or value.name in ("load", "evaluate") \
                else "Eval." + value.name                # def l = s.&load, def ev = Eval.&me
        if isinstance(value, Str) and not value.interpolated and not merge:
            seen = self.p.literal_values.setdefault(name, set())
            seen.add(value.text())
            if len(seen) > 1:
                self.p.nonliteral_names.add(name)        # two different literals: which one is not fixed
        if next(find_nodes(value, lambda n: isinstance(n, Call) and callee_name(n) in WORKSPACE_READS,
                           limit=2000), None) is not None:
            self.p.workspace_vars.add(name)
        if isinstance(value, Call) and callee_name(value) == "legacySCM" and any(
                path_of(a) in ("scm", "this.scm") for a in list(value.args) + [v for _, v in value.named]):
            self.p.self_scm_vars.add(name)
        if isinstance(value, ListLit) and not merge:
            self.p.lists[name] = value
        elif not merge:
            self.p.lists.pop(name, None)
        if not merge:
            self.closure_vars.pop(name, None)
            self.method_refs.pop(name, None)
            self.closure_maps.pop(name, None)
            if isinstance(value, Closure):
                self.closure_vars[name] = value.body
                self.p.closure_params[name] = [x for x in value.params if isinstance(x, str)] or ["it"]
            elif isinstance(value, Prop) and isinstance(value.target, Name) and value.target.name == "this" and \
                    value.name in self.defs:
                self.method_refs[name] = value.name        # this.&build (the parser reads `.&` as `.`)
            elif isinstance(value, Name) and value.name in self.defs:
                pass
            elif isinstance(value, MapLit) and any(isinstance(v, Closure) for _, v in value.entries):
                self.closure_maps[name] = {str(k): v.body for k, v in value.entries if isinstance(v, Closure)}
        self.p.refs.setdefault(name, set()).update(
            w for t in source_texts(value) for w in re.findall(r"[A-Za-z_]\w*", t or ""))
        if _computed_env(value):
            # def v = env."${n}": the value of an environment variable whose name is computed.
            self.p.refs[name].add(COMPUTED_ENV)
        if isinstance(value, Closure):
            # def get = { TOKEN }: what the closure returns can be what it reads (the review of slice 2d.2i).
            for n in find_nodes(value.body, lambda n: isinstance(n, (Name, Str)), limit=2000):
                if isinstance(n, Name):
                    self.p.refs[name].add(n.name)
                else:
                    self.p.refs[name].update(w for e in n.exprs for w in re.findall(r"[A-Za-z_]\w*", e))
        cname = chain_name(value) if isinstance(value, Call) else None
        if cname and (cname.startswith("docker.build") or cname.startswith("docker.image")):
            self.p.docker_vars.add(name)
        if cname:
            first = cname.split(".")[0]
            # The class is the last capitalised part: new groovy.lang.GroovyShell(), GroovyShell.newInstance().
            named = next((x for x in reversed(cname.removeprefix("new ").split(".")) if x[:1].isupper()), "")
            cls = self.p.import_aliases.get(named, named)
            if cls in ("GroovyShell", "GroovyClassLoader", "GroovyScriptEngine") and (
                    first.startswith("new ") or cname.endswith(".newInstance")):
                self.p.groovy_shells.add(name)
            if cname.split(".")[-1] in ("getEngineByName", "getEngineByExtension", "getEngineByMimeType"):
                self.p.groovy_shells.add(name)          # a JSR-223 engine: engine.eval(...) compiles text
        # What text the value can carry, read from its structure (flagship slice 2d.2): a variable is tainted with
        # the root source, so a chain of copies reads `u (from CHANGE_TITLE)`. The output of a git command run with
        # returnStdout is commit text, file names or branch names (values.Judge.shell_output).
        from obaaf.checker.jenkins.values import Judge
        if no_taint:
            return
        if not merge:
            self.p.shell_aliases.pop(name, None)
            arms = [value.then, value.otherwise] if isinstance(value, Ternary) else [value]
            pointed = [a.name for a in arms if isinstance(a, Prop) and isinstance(a.target, Name) and
                       a.target.name in ("this", "steps") and a.name in SHELL_STEPS]
            if pointed and len(pointed) == len(arms):
                self.p.shell_aliases[name] = pointed[0]       # def run = this.&sh (the parser reads .& as .)
                self.p.shell_aliases[name + ".call"] = pointed[0]
        judge = Judge(self.p)
        scope = {"it": self.it_stack[-1]} if self.it_stack and self.it_stack[-1] is not None else None
        if not merge and isinstance(value, Name) and value.name in self.p.closure_params:
            self.p.closure_params[name] = self.p.closure_params[value.name]      # def g = f (a closure)
            body = self.closure_bodies.get(value.name) or self.closure_vars.get(value.name)
            if body is not None:
                self.closure_bodies[name] = body          # for OBAAF-JEN-009's `it` only; other rules unchanged
        if not merge and isinstance(value, MapLit):
            for k, v in value.entries:
                if isinstance(v, Closure) and isinstance(k, str):
                    self.p.closure_params[f"{name}.{k}"] = [x for x in v.params if isinstance(x, str)] or ["it"]
        kind = judge.root_kind(value)
        if kind == "env" and not merge:
            self.p.env_aliases.add(name)                 # def e = env; "${e.CHANGE_TITLE}"
        elif kind == "params" and not merge:
            self.p.param_aliases.add(name)               # def p = params
        if kind is not None:
            return
        self.taint(name, judge.value(value, scope))

    def judge(self, value):
        """values.Judge on a value where it stands in the walk: inside a closure body, with that body's `it`."""
        from obaaf.checker.jenkins.values import Judge
        scope = {"it": self.it_stack[-1]} if self.it_stack and self.it_stack[-1] is not None else None
        return Judge(self.p).value(value, scope)

    def taint(self, name: str, found) -> None:
        """Record that `name` can hold what `found` (a values.Judge result) says: a source and its severity, or a
        value from outside the file ("cannot tell")."""
        if not found or not name:
            return
        _shown, severity, root = found
        if severity == "unknown":
            if name not in self.p.tainted and name not in self.p.caller_values:
                self.p.caller_values[name] = root
                self.p.taint_version += 1
            return
        current = self.p.tainted.get(name)
        if current is None or _RANK[severity] > _RANK[current[1]] or (
                _RANK[severity] == _RANK[current[1]] and current[0] != root):
            self.p.tainted[name] = (root, severity)
            self.p.taint_version += 1

    def taint_env_any(self, value) -> None:
        """A value assigned to an environment variable whose name the file computes: any `env.X` may hold it."""
        from obaaf.checker.jenkins.values import worst
        found = self.judge(value)
        if found and found[1] != "unknown":
            current = (self.p.env_any[0], self.p.env_any[1], self.p.env_any[0]) if self.p.env_any else None
            best = worst(current, found)
            if self.p.env_any != (best[2], best[1]):
                self.p.env_any = (best[2], best[1])
                self.p.taint_version += 1

    def bind_each(self, names: list, receiver, block=None) -> None:
        """A closure given to an iteration method, or a for-in loop, gets the receiver's elements in its parameters
        (flagship slice 2d.2: `[env.CHANGE_TITLE].each { t -> sh "echo ${t}" }` was quiet)."""
        from obaaf.checker.jenkins.values import Judge
        kind = Judge(self.p).root_kind(receiver)
        if kind is not None:
            found = ("params", "medium", "params") if kind == "params" else (
                "every environment variable", "high", "every environment variable")
        else:
            found = self.judge(receiver)
        if isinstance(receiver, Name) and receiver.name in self.p.lists:
            receiver = self.p.lists[receiver.name]
        keys = None
        if isinstance(receiver, ListLit) and receiver.items and all(literal(x) is not None for x in receiver.items):
            keys = [literal(x) for x in receiver.items]
        for n in names:
            if not isinstance(n, str):
                continue
            if n == "it" and block is None:
                continue                         # an implicit `it` is never a name for the whole file
            if n == "it":
                # The implicit `it` holds the value only inside this closure's body: kept by the body, not by name
                # for the whole file (the first review of slice 2d.2: one loop over commit text made every `it` high).
                prev = self.p.it_values.get(id(block))
                best = found if prev is None or prev[0] is not block else _worst_result(prev[1], found)
                self.p.it_values[id(block)] = (block, best)
                continue
            if keys is not None:
                self.p.key_lists[n] = keys
            self.taint(n, found)

    def expr(self, node, ctx: Ctx) -> None:
        # Operator chains are walked iteratively: a long concatenation must not exhaust the stack.
        stack = [(node, ctx)]
        while stack:
            n, ctx = stack.pop()
            if isinstance(n, Call):
                self.call(n, ctx)
            elif isinstance(n, Closure):
                self.p.local_names.update(p for p in n.params if isinstance(p, str))
                self.p.nonliteral_names.update(p for p in n.params if isinstance(p, str))
                # Where a closure is written is not where it runs: outside a workspace it gets one of its own
                # (flagship slice 2d.2j); where it is called it is walked again in the caller's.
                self.block(n.body, replace(self.context_ws(ctx, n.line, f"the closure at line {n.line}", "closure"),
                                           deferred=ctx.deferred or f"the closure at line {n.line}"))
            elif isinstance(n, ListLit):
                stack += [(x, ctx) for x in reversed(n.items)]
            elif isinstance(n, MapLit):
                stack += [(v, ctx) for _, v in reversed(n.entries)]
            elif isinstance(n, Binary):
                # `a && b`, `a || b`, `a ?: b`: b may not be evaluated (flagship slice 2d.2l).
                right = replace(ctx, guards=ctx.guards + (f"{n.op} {self.site(ctx, n)}",)) \
                    if n.op in ("&&", "||", "?:") and not _holds_no_step(n.right) else ctx
                stack += [(n.right, right), (n.left, ctx)]
            elif isinstance(n, Unary):
                stack.append((n.operand, ctx))
            elif isinstance(n, Ternary):
                then = ctx if _holds_no_step(n.then) else \
                    replace(ctx, guards=ctx.guards + (f"?: then {self.site(ctx, n)}",))
                otherwise = ctx if _holds_no_step(n.otherwise) else \
                    replace(ctx, guards=ctx.guards + (f"?: else {self.site(ctx, n)}",))
                stack += [(n.otherwise, otherwise), (n.then, then), (n.cond, ctx)]
            elif isinstance(n, Prop):
                stack.append((n.target, ctx))
            elif isinstance(n, Index):
                stack += [(n.index, ctx), (n.target, ctx)]

    # -- calls ---------------------------------------------------------------------------
    def call(self, call: Call, ctx: Ctx) -> None:
        name = chain_name(call.callee) or ""
        # steps.sh, this.sh, this.build(): the same step or method as sh and build() (flagship slice 2d.2i).
        for prefix in ("steps.", "this."):
            if name.startswith(prefix) and "." not in name[len(prefix):]:
                name = name[len(prefix):]
                break
        # def s = this; s.sh "...": a variable holding the script is the script (flagship slice 2d.2).
        head, _, rest = name.partition(".")
        if rest in SHELL_STEPS and head in self.p.script_vars:
            name = rest
        if name in self.p.shell_aliases:
            name = self.p.shell_aliases[name]             # def run = this.&sh; run "..." (2d.2)
        self.values_flow(call)
        if name.startswith("this.") and name.endswith(".call") and name[5:-5] in self.defs:
            name = name[5:-5]             # this.&build.call(): the parser reads `.&` as `.`
        # Groovy the file does not hold, run through any receiver (flagship slice 2d.2k). Recorded here,
        # before any branch below can return, so no spelling of the call is lost.
        if name in ("binding.setVariable", "binding.setProperty", "setProperty", "this.setProperty",
                    "setVariable") and call.args and literal(call.args[0]) is not None:
            self.p.nonliteral_names.add(literal(call.args[0]))   # binding.setVariable('code', ...) (2d.2k)
        # A pointer to load or evaluate given as an argument (`list.each(this.&load)`) runs where it is called.
        for arg in call.args:
            pointed = self._pointer(arg)
            if pointed is None and isinstance(arg, Name) and arg.name in self.p.code_aliases:
                held = self.p.code_aliases[arg.name]       # def loader = this.&load; list.each(loader)
                pointed = "load" if held == "load" else "evaluate"
            if pointed is not None:
                self.p.code_loads.append((pointed, f"{path_of(arg)} (a pointer)", Call(Name(pointed, line=call.line),
                                          line=call.line), ctx, True))
                self.p.opaque.append((call.line, f"{path_of(arg)}: Groovy loaded at run time is not analyzed"))
        code_name = name[:-5] if name.endswith(".call") else name      # l.call(...), this.&load.call(...)
        code_name = self.p.code_aliases.get(code_name, code_name)
        if code_name in ("this.load", "this.evaluate", "steps.load", "steps.evaluate"):
            code_name = code_name.split(".", 1)[1]
        head = code_name.split(".")[0]
        bare = head[4:] if head.startswith("new ") else head
        if bare in self.p.import_aliases:
            code_name = ("new " if head.startswith("new ") else "") + self.p.import_aliases[bare] + code_name[len(head):]
        code_call = call
        if name == "step" and (call.named or (call.args and isinstance(call.args[0], MapLit))):
            # step([$class: 'ExecuteDslScripts', targets: ...]) and step $class: ..., targets: ...: Job DSL
            # in its older spelling.
            entries = [(_key(k), v) for k, v in call.args[0].entries] if call.args and isinstance(
                call.args[0], MapLit) else list(call.named)
            if any(k == "$class" and (literal(v) or "").split(".")[-1] == "ExecuteDslScripts" for k, v in entries):
                code_name = "jobDsl"
                code_call = Call(Name("jobDsl", line=call.line), named=[(k, v) for k, v in entries if k != "$class"],
                                 line=call.line)
        loading = code_loading(code_name, self.p.groovy_shells) if name not in self.defs else None
        if loading is not None:
            certain = code_receiver(code_name, self.p.groovy_shells, self.p.script_vars)
            self.p.code_loads.append((loading, code_name, code_call, ctx, certain))
            if certain:
                self.p.opaque.append((call.line, f"{code_name}(): Groovy loaded at run time is not analyzed"
                                      if loading != "jobDsl" else
                                      "jobDsl(): Job DSL scripts run on the controller and are not analyzed"))
        # A closure held in a variable, given as the last argument, is the step's body like a literal one;
        # so is a method pointer (this.&build, or a variable holding one), as a call of the method.
        if call.closure is None and call.args and name != "parallel":
            last = call.args[-1]
            lp = path_of(last)
            pointer = None
            if lp in self.closure_vars:
                call = replace(call, args=call.args[:-1], closure=self.closure_vars[lp])
            elif lp in self.method_refs:
                pointer = self.method_refs[lp]
            elif isinstance(last, Prop) and isinstance(last.target, Name) and last.target.name == "this" and \
                    last.name in self.defs:
                pointer = last.name
            if pointer is not None:
                body = Block([ExprStmt(Call(Name(pointer, line=call.line), line=call.line), line=call.line)],
                             line=call.line)
                call = replace(call, args=call.args[:-1], closure=body)
        # `f(a, { ... })` is `f(a) { ... }` in Groovy: the closure is the step's body, and the bindings of
        # withCredentials([...], { ... }) reach it (flagship slice 2d.2i). Not for parallel, whose closure
        # arguments are branches.
        if call.closure is None and call.args and isinstance(call.args[-1], Closure) and name != "parallel":
            self.p.local_names.update(p for p in call.args[-1].params if isinstance(p, str))
            self.p.nonliteral_names.update(p for p in call.args[-1].params if isinstance(p, str))
            call = replace(call, args=call.args[:-1], closure=call.args[-1].body)
        # A closure passed to a method of this file runs where the method calls it: `body()` inside
        # withCredentials in the method gets the method's bindings (flagship slice 2d.2i).
        target = name[:-len(".call")] if name.endswith(".call") else name
        for idx in range(len(self.closure_args) - 1, -1, -1):
            frame = self.closure_args[idx]
            if target in frame and "." not in target:
                body, walked, depth = frame[target]
                frame[target] = (body, True, depth)
                if self.budget <= 0:
                    self.p.opaque.append((call.line, f"call to {target}() not expanded (too many calls)"))
                    return
                self.budget -= 1
                # The closure runs with the frames and methods of the place it was written: a `body()`
                # inside it is the caller's, not this method's (the review of slice 2d.2i found two helpers
                # that both name their closure `body` recursing without end).
                saved_frames, saved_stack = self.closure_args, self.stack
                self.closure_args, self.stack = saved_frames[:idx], saved_stack[:depth]
                try:
                    self.block(body, ctx)
                finally:
                    self.closure_args, self.stack = saved_frames, saved_stack
                return
        # A closure, a method pointer or a map of closures assigned in this file, called here: walked here,
        # with the bindings and conditions of this place (flagship slice 2d.2i). The closure was also walked
        # where it was written.
        if "." not in target and target in self.closure_vars and target not in self.defs:
            if self.budget > 0 and target not in self.stack:
                self.budget -= 1
                self.stack.append(target)
                try:
                    self.block(self.closure_vars[target], ctx)
                finally:
                    self.stack.pop()
            else:
                self.p.opaque.append((call.line, f"call to {target}() not expanded (recursion or too many calls)"))
            return
        if "." not in target and target in self.method_refs:
            self.inline(self.method_refs[target], call, ctx)
            return
        if name.endswith(".put") and "." not in name[:-4] and call.args and literal(call.args[0]) is not None:
            # tasks.put('a', { ... }), whose closure the line above may have made the call's body.
            body = call.closure if len(call.args) == 1 and call.closure is not None else (
                call.args[1].body if len(call.args) == 2 and isinstance(call.args[1], Closure) else None)
            if body is not None:
                self.closure_maps.setdefault(name[:-4], {})[literal(call.args[0])] = body
        if isinstance(call.callee, Index) and path_of(call.callee.target) in self.closure_maps:
            key = literal(call.callee.index)
            bodies = self.closure_maps[path_of(call.callee.target)]
            chosen = [bodies[key]] if key in bodies else list(bodies.values())
            if self.budget > 0 and target not in self.stack:
                self.budget -= 1
                self.stack.append(target or "index call")
                try:
                    for body in chosen:
                        self.block(body, ctx)
                finally:
                    self.stack.pop()
            return
        head, _, key = target.partition(".")
        if key and "." not in key and head in self.closure_maps and key in self.closure_maps[head]:
            if self.budget > 0 and target not in self.stack:
                self.budget -= 1
                self.stack.append(target)
                try:
                    self.block(self.closure_maps[head][key], ctx)
                finally:
                    self.stack.pop()
            return
        if name == "withCredentials":
            # withCredentials(bindings) with a list assigned in this file, also under `bindings:` and in `a + b`.
            call = replace(call, args=[self._lists_in(a) for a in call.args],
                           named=[(k, self._lists_in(v) if k == "bindings" else v) for k, v in call.named])
        # Receivers in a chain are calls too: docker.image('x') in docker.image('x').inside { },
        # sh(script: 'x', returnStdout: true) in sh(...).trim().
        if isinstance(call.callee, Prop) and isinstance(call.callee.target, Call):
            self.call(call.callee.target, ctx)
        elif isinstance(call.callee, Prop):
            # library(...).org.ci.Steps.new(this): a call at the root of a chain of properties is walked
            # too (the review of 2d.2k: such a `library` step was never recorded).
            root = call.callee.target
            while isinstance(root, Prop):
                root = root.target
            if isinstance(root, Call):
                self.call(root, ctx)
        if name == "dir" and call.closure is not None and name not in self.defs:
            folder = literal(first_arg(call) if call.args else named_arg(call, "path"))
            here = "?" if folder is None or ctx.dir == "?" else "/".join(
                x for x in (ctx.dir, folder.strip("/")) if x and x != ".")
            self.record_step(name, call, ctx)
            for arg in list(call.args) + [v for _, v in call.named]:
                if isinstance(arg, (Call, Closure, ListLit, MapLit)):
                    self.expr(arg, ctx)
            self.block(call.closure, replace(ctx, dir=here))
            return
        if name == "pipeline" and call.closure is not None:
            self.pipeline(call.closure, ctx)
            return
        if name == "stage":
            self.stage(call, ctx)
            return
        if name == "node" and call.closure is not None:
            arg = first_arg(call) if call.args else named_arg(call, "label")
            label = literal(arg) if not (isinstance(arg, Str) and arg.interpolated) else None
            if label is None and isinstance(arg, Name) and arg.name in self.p.literals and \
                    arg.name not in self.p.nonliteral_names:
                label = self.p.literals[arg.name].text()     # def where = 'built-in'; node(where) (2d.2j)
            dynamic = arg is not None and label is None
            # node(POD_LABEL) inside podTemplate is the pod itself (flagship slice 2d.2j): its steps run in the
            # pod the template describes, so they stay under it, in a workspace of that pod.
            # Any label the file does not fix there is read as the pod's (`POD_LABEL`, "${POD_LABEL}", the
            # template's own label variable); a literal is the pod's only when it is the template's label.
            pod_label = path_of(arg) in ("POD_LABEL", "env.POD_LABEL") or (
                isinstance(arg, Str) and arg.interpolated and arg.text().strip() in (
                    "${POD_LABEL}", "${env.POD_LABEL}", "$POD_LABEL"))
            template = ctx.agent if ctx.agent is not None and ctx.agent.kind == "kubernetes" else None
            same = False
            if template is not None:
                # The template's label, as the file writes it: the same text ("ci-${env.BUILD_NUMBER}" in both),
                # the same variable, or the literal that variable holds (the fourth review of 2d.2j).
                held = (self.p.literals[template.label_ref].text() if template.label_ref in self.p.literals
                        and template.label_ref not in self.p.nonliteral_names else None)
                same = bool((label and label in (template.label, held)) or (
                    template.label_ref and path_of(arg) == template.label_ref) or (
                    template.label_text and text_of(arg) == template.label_text))
            pod = template if template is not None and (pod_label or same) else None
            if pod is not None:
                wid = self.new_ws("kubernetes", call.line, pod.label, pod.pod_workspace,
                                  how=f"node() at line {call.line}, in the pod of podTemplate at line {pod.line}")
                self.block(call.closure, replace(ctx, ws=wid))
                return
            agent = Agent(kind="node" if (label or dynamic) else "any", label=label or (
                "${dynamic}" if dynamic else None), line=call.line)
            self.p.agents.append((agent, ctx))
            wid = self.new_ws(agent.kind, call.line, agent.label, how=f"node() at line {call.line}")
            self.block(call.closure, replace(ctx, agent=agent, ws=wid))
            return
        if name == "ws" and call.closure is not None and name not in self.defs:
            # ws() is another directory on the node the step is on (flagship slice 2d.2j).
            path = first_arg(call) if call.args else named_arg(call, "dir")
            machine = self.p.workspaces[ctx.ws].machine if ctx.ws else None
            wid = self.new_ws("ws", call.line, custom=literal(path) or "?", machine=machine,
                              how=f"ws() at line {call.line}")
            self.record_step(name, call, ctx)
            for arg in list(call.args) + [v for _, v in call.named]:
                if isinstance(arg, (Call, Closure, ListLit, MapLit)):
                    self.expr(arg, ctx)
            self.block(call.closure, replace(ctx, ws=wid))
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
                if p and p in self.closure_maps:
                    # A map of closures assigned in this file: each branch runs here (flagship slice 2d.2i),
                    # once per walk, under the budget, and not inside itself.
                    marker = f"parallel {p}"
                    if marker in self.stack or self.budget <= 0:
                        self.p.opaque.append((call.line, f"parallel {p} not expanded (recursion or too many calls)"))
                        continue
                    self.stack.append(marker)
                    try:
                        for key, body in self.closure_maps[p].items():
                            self.budget -= 1
                            if self.budget <= 0:
                                self.p.opaque.append((call.line, f"parallel {p} not expanded (too many calls)"))
                                break
                            self.block(body, branch(key))
                    finally:
                        self.stack.pop()
                    continue
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
        if name in ("input",):
            self.p.approvals.append(Approval(input_submitter(call), call.line, ctx))
        if name == "withEnv":
            for arg in call.args:
                # withEnv(["T=" + value]): an entry built with + (flagship slice 2d.2).
                entries = arg.items if isinstance(arg, ListLit) else []
                for item in entries:
                    if isinstance(item, Binary) and item.op == "+":
                        leftmost = item
                        while isinstance(leftmost, Binary) and leftmost.op == "+":
                            leftmost = leftmost.left
                        head_text = leftmost.text() if isinstance(leftmost, Str) else ""
                        var, eq, _ = head_text.partition("=")
                        if eq and var.strip():
                            self.p.nonliteral_names.add(var.strip())
                            self.p.env_set.add(var.strip())
                            self.track_value(var.strip(), item)
                for s in all_strings(arg):
                    var, eq, _ = s.text().partition("=")
                    if eq:
                        self.p.nonliteral_names.add(var.strip())   # a value for part of the run only (2d.2k)
                        # withEnv(["T2=${TOKEN}"]): T2 holds what TOKEN holds (flagship slice 2d.2i).
                        self.p.refs.setdefault(var.strip(), set()).update(
                            w for e in s.exprs for w in re.findall(r"[A-Za-z_]\w*", e))
                        self.p.env_set.add(var.strip())
                        if s.interpolated:
                            self.track_value(var.strip(), s)
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
            if not ctx.ws and name not in known.KNOWN_STEPS and name.split(".")[0] not in known.KNOWN_OBJECTS:
                # A step whose code is not in this file may allocate a node for its body (flagship slice 2d.2j).
                inner = self.context_ws(inner, call.line, f"the body of {name or 'a call'}() at line {call.line}, "
                                        "whose code is not in this file")
            new = bindings_of(call, name, ctx_origin=f"{name}()")
            if new:
                inner = replace(inner, creds=inner.creds + tuple(new))
            if name in ("catchError", "warnError"):
                inner = replace(inner, swallowed=f"{name} (line {call.line})", swallow_id=self.next_seq())
            if isinstance(call.callee, Prop) and call.callee.name in ITERATING:
                # xs.each { }, n.times { }: a loop body may run zero times, as `for` (flagship slice 2d.2l).
                inner = replace(inner, guards=inner.guards + (f"loop {call.line}{KEY_SEP}loop {self.site(ctx, call)}",))
            if name in ("retry", "waitUntil"):
                inner = replace(inner, repeats=inner.repeats + (f"{name} {call.line}",))
            if name.rsplit(".", 1)[-1] == "withEnv":
                # The review of #365: `withEnv`, `this.withEnv`, `steps.withEnv` or any receiver's (`s.withEnv` with
                # `s = this`); the callee is recorded so that OBAAF-JEN-010 to 012 can tell any other place the file
                # names withEnv (a method pointer, a quoted name, `options { withEnv(...) }`), which is not read.
                self.p.with_env_read.add(id(call.callee))
                inner = replace(inner, env_names=inner.env_names + tuple(with_env_names(call)))
            if name == "withEnv":
                for arg in call.args:
                    for s in all_strings(arg):
                        var, sep, val = s.text().partition("=")
                        if var.strip() == "OBAAF_LANE" and sep:
                            inner = replace(inner, lane=val.strip().lower() or inner.lane, lane_line=s.line,
                                            lanes=inner.lanes + ((val.strip(), s.line),))
                        elif sep and is_lane_variable_spelling(var.strip()):
                            self.p.unread_lanes.append(("jenkins-misnamed", var.strip(), val.strip(), s.line,
                                                        " > ".join(ctx.stage)))
            self.block(call.closure, inner)

    def _pointer(self, node) -> str | None:
        """load or evaluate for a pointer to the script's own (`this.&load`, `s.&load` with `s` the script),
        or to Eval.me and the like; None otherwise. The parser reads `.&` as `.`."""
        if not isinstance(node, Prop) or not isinstance(node.target, Name):
            return None
        receiver = node.target.name
        if node.name in ("load", "evaluate") and (receiver in _SCRIPT_RECEIVERS or receiver in self.p.script_vars):
            return node.name
        if self.p.import_aliases.get(receiver, receiver) == "Eval" and node.name in _EVAL_FUNCTIONS:
            return "evaluate"
        return None

    def _lists_in(self, node, depth: int = 0):
        if depth > 50:
            return node
        p = path_of(node)
        if p and p in self.p.lists and p not in self.changed_lists:
            return self.p.lists[p]
        if isinstance(node, Binary) and node.op == "+":
            return replace(node, left=self._lists_in(node.left, depth + 1), right=self._lists_in(node.right, depth + 1))
        return node

    _MUTATORS = {"append", "add", "addAll", "put", "putAll", "push", "leftShift", "offer", "addFirst", "addLast",
                 "insert", "set", "putAt", "plus", "concat"}
    _SETTERS = {"binding.setVariable", "binding.setProperty", "setProperty", "this.setProperty", "setVariable",
                "env.setProperty", "env.put", "env.putAt", "this.binding.setVariable"}

    def values_flow(self, call: Call) -> None:
        """Where a call moves a value for OBAAF-JEN-009 (flagship slice 2d.2): an iteration method's closure gets
        the receiver's elements; `sb.append(x)`, `list.add(x)` and `map.put(k, x)` put x in the receiver;
        `env.setProperty('T', x)` and `binding.setVariable('T', x)` set T."""
        callee = call.callee
        closure_params = None
        closure_block = None
        if call.closure is not None:
            closure_params = list(call.closure.params) or ["it"]
            closure_block = call.closure
        elif call.args and isinstance(call.args[-1], Closure):
            closure_params = [p for p in call.args[-1].params if isinstance(p, str)] or ["it"]
            closure_block = call.args[-1].body
        full_path = path_of(callee) or ""
        if full_path in self.p.closure_params or (full_path.endswith(".call") and
                                                   full_path[:-5] in self.p.closure_params):
            # m.run(value), m.run.call(value), f.call(value): a closure held in a map or variable (2d.2).
            held = full_path if full_path in self.p.closure_params else full_path.removesuffix(".call")
            base, _, key = held.partition(".")
            body = self.closure_vars.get(held) or self.closure_bodies.get(held) or \
                self.closure_maps.get(base, {}).get(key)
            for i, n in enumerate(self.p.closure_params[held]):
                if i < len(call.args):
                    if n == "it" and body is not None:
                        self.bind_each(["it"], ListLit([call.args[i]], line=call.line), body)
                    else:
                        self.track_value(n, call.args[i])
            return
        if isinstance(callee, Prop):
            from obaaf.checker.jenkins.values import ITERATORS
            if closure_params is not None and callee.name in ITERATORS:
                self.bind_each(closure_params, callee.target, closure_block)
            if callee.name == "setDelegate" and call.args and path_of(callee.target) in (
                    self.p.method_params | set(self.p.caller_values)) and path_of(call.args[0]):
                # body.setDelegate(config); body(): the caller's closure fills config (a vars/ step).
                self.p.caller_values.setdefault(path_of(call.args[0]),
                                                "a map the caller's closure fills, outside this file")
            target = path_of(callee.target)
            root = callee.target
            while target is None and isinstance(root, Call) and isinstance(root.callee, Prop) and \
                    root.callee.name in self._MUTATORS:
                root = root.callee.target            # sb.append('a').append(value): sb holds it
                target = path_of(root)
            full = path_of(callee) or ""
            if full in self._SETTERS or (callee.name in ("setProperty", "put", "putAt") and target in
                                         self.p.env_aliases):
                if len(call.args) >= 2:
                    key = literal(call.args[0])
                    if full.startswith("env.") or target in self.p.env_aliases:
                        self.p.env_scripted.append((key if key is not None else "?", call.line))   # review of #365
                    if key is not None:
                        if full.startswith("env.") or target in self.p.env_aliases:
                            self.p.env_set.add(key)
                        self.track_value(key, call.args[1])
                    elif full.startswith("env.") or target in self.p.env_aliases:
                        self.taint_env_any(call.args[1])
                return
            if callee.name == "call" and target in self.p.closure_params:
                for i, n in enumerate(self.p.closure_params[target]):
                    if i < len(call.args):
                        self.track_value(n, call.args[i])
            if callee.name in self._MUTATORS and target and call.args and target not in ("env", "params"):
                self.track_value(target, ListLit(list(call.args), line=call.line), merge=True)
        elif isinstance(callee, Name) and callee.name in self.p.closure_params:
            # run(value) for def run = { x -> ... }: the closure's parameters take the arguments (2d.2).
            names = self.p.closure_params[callee.name]
            body = self.closure_vars.get(callee.name) or self.closure_bodies.get(callee.name)
            for i, n in enumerate(names):
                if i < len(call.args):
                    if n == "it" and body is not None:
                        self.bind_each(["it"], ListLit([call.args[i]], line=call.line), body)
                    else:
                        self.track_value(n, call.args[i])
        elif isinstance(callee, Name) and callee.name in ("setProperty", "setVariable") and len(call.args) >= 2:
            key = literal(call.args[0])
            if key is not None:
                self.track_value(key, call.args[1])

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
        # A trailing closure is the last argument, so it binds to the last parameter: a parameter before it with
        # a default value takes the default (flagship slice 2d.2l: `def withTimeout(int m = 60, Closure body)`).
        # notify(title: x): Groovy passes the named arguments as a map before the positional ones (2d.2).
        positional = ([MapLit([(k, v) for k, v in call.named], line=call.line)] if call.named else []) + list(call.args)
        pairs = list(zip(mdef.params, positional))
        if len(positional) > len(mdef.params) >= 1 and call.closure is None:
            # run('a', x): the last parameter of `def run(String... xs)` takes the rest (2d.2).
            rest = ListLit(positional[len(mdef.params) - 1:], line=call.line)
            pairs = list(zip(mdef.params[:-1], positional)) + [(mdef.params[-1], rest)]
        if call.closure is not None and mdef.params:
            closure = Closure([], call.closure, line=call.line)
            if len(positional) < len(mdef.params):
                pairs = list(zip(mdef.params[:-1], positional)) + [(mdef.params[-1], closure)]
            else:
                pairs = list(zip(mdef.params, positional + [closure]))
        for param, value in pairs:
            self.track_value(param, value)
        frame: dict = {}
        depth = len(self.stack)
        for param, value in pairs:
            # Each closure given to the method, in any position, runs where the method calls it.
            if isinstance(param, str) and isinstance(value, Closure):
                frame[param] = (value.body, False, depth)
            elif isinstance(param, str) and path_of(value) in self.closure_vars:
                frame[param] = (self.closure_vars[path_of(value)], False, depth)
        self.stack.append(name)
        self.closure_args.append(frame)
        try:
            self.block(mdef.body, replace(ctx, in_function=name, invocation=(
                self.next_seq(), frozenset(p for p in mdef.params if isinstance(p, str)))))
        finally:
            self.stack.pop()
            self.closure_args.pop()
        # A trailing closure passed to the method runs inside it (withRetry { ... }); where the method
        # calls it by its parameter, it was walked there, with the method's bindings and conditions.
        # (A closure given as another argument was walked at the call, before the method, by `expr`.)
        if call.closure is not None and not any(walked for body, walked, _ in frame.values() if body is call.closure):
            # The method was not seen to call it: it may run there, later or never (flagship slice 2d.2l).
            self.block(call.closure, replace(ctx, deferred=ctx.deferred or
                                             f"the closure given to {name}() at line {call.line}"))

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
        retriever = named_arg(call, "retriever")
        if retriever is None or not self.p.libraries:
            return
        lib = self.p.libraries[-1]
        # Flagship slice 2d.2k: where the library comes from. legacySCM(scm) is the build's own checkout,
        # which for a change request is the change; a retriever whose remote or settings are values the
        # file does not fix lets whoever sets them choose the library's code.
        if (isinstance(retriever, Call) and callee_name(retriever) == "legacySCM" and any(
                path_of(a) in ("scm", "this.scm") for a in list(retriever.args) + [v for _, v in retriever.named])) or \
                path_of(retriever) in self.p.self_scm_vars:
            lib.retriever = "self"
            return
        texts = [t for t in self._retriever_values(retriever) if t not in ("true", "false", "null")]
        if texts:
            lib.retriever, lib.retriever_source = "computed", untrusted_source(texts, self.p)

    def _retriever_values(self, node, depth: int = 0) -> list:
        """What a retriever reads that the file does not fix: values of every key but credentials and
        `$class`, after variables and environment values the file assigns a literal are put in."""
        if node is None or depth > 20:
            return [] if node is None else ["computed"]
        if isinstance(node, Str):
            return list(node.exprs)
        p = path_of(node)
        if p:
            base = p[4:] if p.startswith("env.") else p
            known = self.p.literals.get(base) or self.p.env_values.get(base)
            if isinstance(known, Str) and not known.interpolated and base not in self.p.nonliteral_names:
                return []
            return [p]
        if isinstance(node, Call):
            out = []
            for a in node.args:
                out += self._retriever_values(a, depth + 1)
            for k, v in node.named:
                if k not in _NOT_CODE_KEYS:
                    out += self._retriever_values(v, depth + 1)
            return out
        if isinstance(node, ListLit):
            return [t for item in node.items for t in self._retriever_values(item, depth + 1)]
        if isinstance(node, MapLit):
            return [t for k, v in node.entries if _key(k) not in _NOT_CODE_KEYS
                    for t in self._retriever_values(v, depth + 1)]
        return source_texts(node) or ["computed"]

    def _library(self, node, how: str, line: int) -> None:
        if not isinstance(node, Str):
            self.p.libraries.append(Library("?", None, True, how, line, ref=path_of(node) if node is not None
                                            else None))
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
                # `agent none` on a stage allocates nothing: its steps stay on the enclosing agent, in its
                # container and workspace (flagship slice 2d.2j; before, they lost the agent they run on).
                if agent.kind != "none" or ctx.agent is None:
                    ctx = replace(ctx, agent=agent)
                ctx = replace(ctx, ws=self.agent_ws(agent, ctx))
        pre_when_guards = ctx.guards
        before_input = False
        for w in secs.get("when", []):
            if w.closure is not None:
                # `beforeAgent`, `beforeInput` and `beforeOptions` say when the condition is evaluated, not what
                # it tests, so they are not part of the condition's text (flagship slice 2d.2l).
                options = [s for s in w.closure.stmts if isinstance(s, ExprStmt) and isinstance(s.expr, Call)
                           and callee_name(s.expr) in ("beforeAgent", "beforeInput", "beforeOptions")]
                tested = Block([s for s in w.closure.stmts if not any(s is o for o in options)], line=w.closure.line)
                ctx = self.narrowed(ctx, when_block(w.closure, self.methods), w.line,
                                    f"when {_source_hint(w.closure)}{KEY_SEP}when {self.condition_tag(tested, ctx)}")
                # beforeOptions is evaluated before options and input, and takes precedence over beforeInput.
                before_input = before_input or any(
                    callee_name(o.expr) in ("beforeInput", "beforeOptions") and path_of(first_arg(o.expr)) != "false"
                    for o in options)
        # A wrapper step in `options { }` wraps every step of the pipeline or stage: options { withAWS(...) }
        # binds its credentials for them (flagship slice 2d.2i).
        for opt in secs.get("options", []):
            for stmt in (opt.closure.stmts if opt.closure is not None else []):
                e = stmt.expr if isinstance(stmt, ExprStmt) else None
                if isinstance(e, Call):
                    oname = chain_name(e.callee) or ""
                    new = bindings_of(e, oname, ctx_origin=f"{origin} options")
                    if new:
                        ctx = replace(ctx, creds=ctx.creds + tuple(new))
                    if oname == "retry":       # options { retry(3) } runs the whole stage again (2d.2j)
                        ctx = replace(ctx, repeats=ctx.repeats + (f"retry {e.line}",))
        for inp in secs.get("input", []):
            sub = input_submitter(inp)
            if inp.closure is not None:
                for s in inp.closure.stmts:
                    e = s.expr if isinstance(s, ExprStmt) else None
                    if isinstance(e, Call) and callee_name(e) == "submitter":
                        # `submitter null` or `submitter ''` is no submitter; `submitter` alone is not read.
                        sub = submitter_value(first_arg(e)) if e.args else "?"
            # Without `beforeInput true` the stage asks for input before its `when` is evaluated, so the
            # question is asked whatever the condition says (flagship slice 2d.2l).
            asked = ctx if before_input else replace(ctx, guards=pre_when_guards)
            self.p.approvals.append(Approval(sub, inp.line, asked))
            self.record_step("input", inp, asked)
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
        lane, lane_line, lanes = ctx.lane, ctx.lane_line, ctx.lanes
        names: list = []
        for stmt in env.closure.stmts:
            if not isinstance(stmt, Assign):
                if not (isinstance(stmt, ExprStmt) and isinstance(stmt.expr, Str)):
                    names.append(("?", getattr(stmt, "line", env.line)))   # not an assignment the checker reads
                continue
            var = path_of(stmt.target) or ""
            names.append((var or "?", stmt.line))
            value = stmt.value
            if isinstance(value, Call) and callee_name(value) == "credentials":
                cid = literal(first_arg(value)) or "?"
                new.append(Binding((cid,), (var, f"{var}_USR", f"{var}_PSW"), "environment credentials()",
                                   stmt.line, origin))
                continue
            if var != "OBAAF_LANE" and is_lane_variable_spelling(var):
                self.p.unread_lanes.append(("jenkins-misnamed", var, literal(value), stmt.line, " > ".join(ctx.stage)))
            if var == "OBAAF_LANE":
                text = literal(value)
                lane = (text or "").strip().lower() or lane
                lane_line = stmt.line
                # Kept even when it names no lane, so that it can be reported and not dropped.
                lanes += ((None if text is None else text.strip(), stmt.line),)
            if isinstance(value, Str):
                self.p.env_values[var] = value
            self.p.env_set.add(var)
            self.track_value(var, value)
        return replace(ctx, creds=ctx.creds + tuple(new), lane=lane, lane_line=lane_line, lanes=lanes,
                       env_names=ctx.env_names + tuple(names))

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
            return      # `stage 'Build'` with no block: the steps after it are not in it
        self.p.stages.append(sctx.stage)
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
            # The review of #365: each axis sets its name in the environment of every cell, as `environment` does.
            mctx = replace(mctx, env_names=mctx.env_names + tuple(matrix_axis_names(msecs.get("axes", []))))
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
                self.block(expr.closure, replace(ctx, post=cond, stage=ctx.stage + (f"post {cond}",),
                                                 post_owner=ctx.stage))


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
    # Flagship slice 2d.2: the comment that triggered a GitLab build; ghprb's e-mail addresses; and the
    # Bitbucket Push and Pull Request plugin's variables, read from its README's table on 2026-11-22.
    "gitlabTriggerPhrase": "high", "ghprbPullAuthorEmail": "medium", "ghprbActualCommitAuthorEmail": "medium",
    "ghprbTriggerAuthorEmail": "medium", "ghprbTriggerAuthorLogin": "low", "ghprbTriggerAuthorLoginMention": "low",
    "BITBUCKET_PULL_REQUEST_TITLE": "high", "BITBUCKET_PULL_REQUEST_DESCRIPTION": "high",
    "BITBUCKET_SOURCE_BRANCH": "high", "BITBUCKET_PULL_REQUEST_COMMENT_TEXT": "high", "BITBUCKET_PAYLOAD": "high",
    "BITBUCKET_ACTOR": "low", "BITBUCKET_TARGET_BRANCH": "low",
}
# Jenkins reads environment variables without regard to case (hudson.EnvVars), so `env.change_title` is
# CHANGE_TITLE (flagship slice 2d.2). Bare names in Groovy keep their case.
UNTRUSTED_FOLDED = {k.lower(): (k, v) for k, v in UNTRUSTED.items()}
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
    pipeline = Builder().build(tree)
    pipeline.tree = tree
    return pipeline
