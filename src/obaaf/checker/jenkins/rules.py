"""Advisory rules for Jenkinsfiles (OBAAF-JEN-*). Metadata lives in data/rules.yaml.

The rules read only the Jenkinsfile and files it names in the repository. Jenkins decides much
of what matters on the controller: security realm and authorization, build authorization
(builds run as SYSTEM unless configured), which agents carry executors, library trust and
version overrides, Replay permission, script approval, credential scopes, and network policy.
None of that is in the file, so the rules report it as coverage unknowns rather than passing
it. A finding describes what the file shows; an unknown says what the file cannot show.
"""

from __future__ import annotations

import functools
import json
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from obaaf.catalog import Catalog
from obaaf.checker.jenkins import steps as known
from obaaf.checker.jenkins.model import (
    COMPUTED_ENV, CONTROLLER_LABELS, CR_NO, CR_POSSIBLE, CR_UNKNOWN, CR_YES, GIT_PUSH, SHELL_STEPS, Binding, Pipeline,
    StepUse,
    chain_name, code_text_arg, first_arg, literal, named_arg, shell_script, source_texts, untrusted_source,
)
from obaaf.checker.jenkins.parser import Binary, Call, ListLit, MapLit, Name, Prop, Str, path_of
from obaaf.checker.rules import Finding
from obaaf.checker.workflow import declared_lane

RULES = ("OBAAF-JEN-001", "OBAAF-JEN-002", "OBAAF-JEN-003", "OBAAF-JEN-004", "OBAAF-JEN-005", "OBAAF-JEN-006",
         "OBAAF-JEN-007", "OBAAF-JEN-008", "OBAAF-JEN-009", "OBAAF-JEN-010", "OBAAF-JEN-011", "OBAAF-JEN-012",
         "OBAAF-JEN-013", "OBAAF-JEN-014", "OBAAF-JEN-015")
ALL = "*"

# post conditions (and Scripted catch/finally blocks) that run when the build failed, was aborted, or
# is unstable: a publish there can run after a failed or skipped check.
FAILURE_PATHS = {"always", "changed", "regression", "aborted", "failure", "unstable", "unsuccessful", "cleanup",
                 "catch/finally"}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}\b")
CHECKSUM_VERIFY = re.compile(r"(^|[\s;&|(])(sha256sum|sha512sum|shasum)\b[^\n]*\s(-c|--check)\b"
                             r"|(^|[\s;&|(])cosign\s+verify|(^|[\s;&|(])obaaf\s+verify\b", re.M)
INSTALLER = re.compile(r"\b(npm|pnpm|yarn|bun|npx|bunx|pip3?|pipx|uv|uvx)\b")
# Commands that run code from the checkout: build tools, test runners, package scripts, and scripts
# by path. Best effort; anything else is treated as a fixed tool, one severity level lower.
REPO_CODE = re.compile(
    r"(^|[\s;&|(\"'}=])(\./|\.\\|bash\s+|sh\s+|source\s+|\.\s+|python3?\s+|node\s+|ruby\s+|perl\s+|"
    r"pwsh\s+|powershell(\.exe)?\s+(-File\s+)?)?[\w./\\-]+\.(sh|bash|py|js|mjs|rb|pl|ps1|bat|cmd|groovy)\b"
    r"|(^|[\s;&|(])(\./)?(mvn|mvnw|gradle|gradlew|ant|make|gmake|cmake|ninja|meson|npm|npx|yarn|pnpm|bun|node|"
    r"python3?|pip3?|pytest|tox|nox|poetry|uv|go|cargo|dotnet|msbuild|bazel|bazelisk|buck2?|sbt|lein|mix|rake|"
    r"bundle|composer|php|xcodebuild|swift|flutter|dart|tsc|jest|ctest|yetus|test-patch|docker\s+build|"
    r"docker\s+compose|docker-compose|buildah|kaniko|terraform|ansible-playbook|UnrealBuildTool|RunUAT|"
    r"Unity|godot)\b", re.M)
# Steps that read a file in the workspace: a value read from one is the change's own for a change request.
WORKSPACE_READ = re.compile(r"\b(readFile|readJSON|readYaml|readProperties|readCSV|readMavenPom|findFiles)\b")
MUTABLE_SELECTORS = {"lastSuccessful", "lastCompleted", "latestSavedBuild", "permalink", "lastWithArtifacts",
                     "workspace", "buildParameter"}

# Docker run options and pod settings that reach the host (JEN-006).
DOCKER_HOST_ARGS = [
    (re.compile(r"--privileged\b"), "--privileged"),
    (re.compile(r"(-v|--volume|--mount)[=\s][^\s]*docker\.sock"), "a mount of the Docker socket"),
    (re.compile(r"(-v|--volume)[=\s]/:"), "a mount of the host root file system"),
    (re.compile(r"--(net|network)[=\s]host\b"), "host networking"),
    (re.compile(r"--pid[=\s]host\b"), "the host PID namespace"),
    (re.compile(r"--ipc[=\s]host\b"), "the host IPC namespace"),
    (re.compile(r"--userns[=\s]host\b"), "the host user namespace"),
    (re.compile(r"--cap-add[=\s](ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|DAC_READ_SEARCH)\b", re.I), "extra capabilities"),
    (re.compile(r"--security-opt[=\s](seccomp|apparmor)[=:]unconfined"), "an unconfined security profile"),
]
POD_HOST_SETTINGS = [
    (re.compile(r"^[ \t]*privileged:[ \t]*true\b", re.M), "a privileged container"),
    (re.compile(r"^[ \t]*allowPrivilegeEscalation:[ \t]*true\b", re.M), "allowPrivilegeEscalation: true"),
    (re.compile(r"^[ \t]*hostNetwork:[ \t]*true\b", re.M), "host networking"),
    (re.compile(r"^[ \t]*hostPID:[ \t]*true\b", re.M), "the host PID namespace"),
    (re.compile(r"^[ \t]*hostIPC:[ \t]*true\b", re.M), "the host IPC namespace"),
    (re.compile(r"docker\.sock"), "a mount of the Docker socket"),
    (re.compile(r"^[ \t]*-?[ \t]*hostPath:", re.M), "a hostPath volume"),
    (re.compile(r"\b(SYS_ADMIN|SYS_PTRACE|NET_ADMIN)\b"), "extra capabilities"),
]


# OBAAF-JEN-008 (flagship slice 2d.2k).
PINNED_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
EXACT_NPM = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
EXACT_PIP = re.compile(r"^\d+(?:\.\d+)*(?:(?:a|b|rc|\.post|\.dev)\d+)*(?:\+[0-9A-Za-z.]+)?$")
_REF = re.compile(r"\$\{(?:env\.)?([A-Za-z_]\w*)\}|\$env\.([A-Za-z_]\w*)|\$([A-Za-z_]\w*)")
# Words between an installer and the package that make the command something other than an install.
_NOT_INSTALL = re.compile(r"(?<![\w-])(uninstall|remove|rm|un|unlink|ls|list|view|info|show|outdated|why|explain|"
                          r"search|audit|cache|config|help|download)(?![\w-])", re.I)
_UPDATE = re.compile(r"(?<![\w-])(update|upgrade|up)(?![\w-])", re.I)
_AGENT_SELF_UPDATE = re.compile(r"(?:^|[\s;&|(])claude[ \t]+(?:update|upgrade)\b")
_CONTAINER_CMD = re.compile(r"(?:^|[\s;&|(`])(docker|podman|nerdctl)[ \t]+(?:(?:container|image)[ \t]+)?"
                            r"(run|create|pull)(?=[ \t])", re.I)
_DOCKER_BOOL = {"--rm", "-d", "--detach", "-i", "--interactive", "-t", "--tty", "--privileged", "--init",
                "--read-only", "-P", "--publish-all", "-q", "--quiet", "--no-healthcheck", "--oom-kill-disable",
                "--sig-proxy", "--disable-content-trust", "-a", "--all-tags", "--help"}
_DOCKER_VALUE = {"--add-host", "--annotation", "--attach", "--blkio-weight", "--cap-add", "--cap-drop",
                 "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-period", "--cpu-quota", "--cpu-shares", "-c",
                 "--cpus", "--cpuset-cpus", "--cpuset-mems", "--device", "--device-cgroup-rule", "--dns",
                 "--dns-option", "--dns-search", "--domainname", "--entrypoint", "-e", "--env", "--env-file",
                 "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval", "--health-retries",
                 "--health-start-period", "--health-timeout", "-h", "--hostname", "--ip", "--ip6", "--ipc",
                 "--isolation", "--kernel-memory", "-l", "--label", "--label-file", "--link", "--log-driver",
                 "--log-opt", "--mac-address", "-m", "--memory", "--memory-reservation", "--memory-swap",
                 "--memory-swappiness", "--mount", "--name", "--network", "--net", "--network-alias", "--pid",
                 "--pids-limit", "--platform", "-p", "--publish", "--pull", "--restart", "--runtime",
                 "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl",
                 "--tmpfs", "--ulimit", "-u", "--user", "--userns", "--uts", "-v", "--volume", "--volume-driver",
                 "--volumes-from", "-w", "--workdir", "--detach-keys"}
_PIP_REQUIREMENTS = re.compile(r"(?<![\w-])(?:pip3?|uv[ \t]+pip)[ \t]+install\b[^\n;&|]*?(?:-r|--requirement)"
                               r"(?:[ \t]+|=)(['\"]?)([^\s'\";&|]+)\1")
_NPM_INSTALL = re.compile(r"(?<![\w-])(?:npm[ \t]+(?:install|i|ci|add)|pnpm[ \t]+(?:install|i|add)|"
                          r"yarn(?:[ \t]+install)?|bun[ \t]+(?:install|i))(?=$|[ \t;&|])", re.M)
LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock")
_DOWNLOAD = re.compile(r"(?<![\w-])(curl|wget|irm|iwr|Invoke-WebRequest|Invoke-RestMethod)(?![\w-])", re.I)
_TO_SHELL = re.compile(r"\|[ \t]*(?:sudo[ \t]+(?:-\S+[ \t]+)*)?(?:\S*/)?(?:ba|z|da|k)?sh\b|\|[ \t]*iex\b|"
                       r"(?:ba|z)?sh[ \t]+<\(|(?:ba|z)?sh[ \t]+-c[ \t]+[\"']?\$\(", re.I)


def _piped_install(line: str, agent_words) -> bool:
    """A download piped into a shell (or run by one) on a line that names an agent: linear checks, not one
    backtracking pattern (flagship slice 2d.2k: 8,000 words on one line took 7.5 seconds)."""
    return bool(_DOWNLOAD.search(line) and _TO_SHELL.search(line) and agent_words.search(line))


def _exact_version(ver: str) -> bool:
    """An exact version after a package name: `@1.2.3` (npm) or `==1.2.3`/`===x` (pip); not a range, a tag,
    a wildcard or a value set at run time."""
    if "$" in ver:
        return False
    if ver.startswith("@"):
        return bool(EXACT_NPM.match(ver[1:]))
    if ver.startswith("==="):
        return len(ver) > 3
    if ver.startswith("=="):
        return bool(EXACT_PIP.match(ver[2:]))
    return False


def _build_dockerfile(options: str) -> str:
    """The Dockerfile docker.build reads: `-f`/`--file`, else Dockerfile in the build context."""
    try:
        words = shlex.split(options)
    except ValueError:
        return "?"
    file, context, i = None, ".", 0
    while i < len(words):
        w = words[i]
        if w in ("-f", "--file") and i + 1 < len(words):
            file, i = words[i + 1], i + 2
            continue
        if w.startswith("--file="):
            file = w.split("=", 1)[1]
        elif w.startswith("-") and "=" not in w and w not in ("-q", "--quiet", "--no-cache", "--pull", "--rm"):
            i += 2
            continue
        elif not w.startswith("-"):
            context = w
        i += 1
    if file is None:
        file = context.rstrip("/") + "/Dockerfile" if context not in (".", "./") else "Dockerfile"
    if "$" in file:
        return "?"
    return file[2:] if file.startswith("./") else file


@dataclass
class Unknown:
    rule: str          # a rule ID, or ALL when nothing in the file can be decided
    line: int
    reason: str


@dataclass
class Info:
    """What one step does, as far as the file shows."""
    use: StepUse
    index: int
    shell: bool = False
    script: str = ""
    exprs: list = field(default_factory=list)
    dynamic: bool = False
    ai: str | None = None
    publish: str | None = None
    verify: str | None = None      # full | provenance
    swallowed: str | None = None   # why a failure of this step does not stop the build
    push: bool = False
    trigger: str | None = None
    unresolved: bool = False

    @property
    def ctx(self):
        return self.use.ctx

    @property
    def line(self) -> int:
        return self.use.line

    @property
    def runs_code(self) -> bool:
        return self.shell or bool(self.ai) or self.use.name.startswith("docker.build")


# Steps that copy files to another host. They are not counted as publishing on their own, because
# they mostly copy reports and logs; in a stage declared a release lane they are the upload.
TRANSFER_STEPS = ("sshPublisher", "ftpPublisher")


# Names in an interpolated expression, outside quoted text, that are not called (`f(`, `tool "x"`).
_QUOTED = re.compile(r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'")
_NAME_IN_EXPR = re.compile(r"(?<![.\w$])[A-Za-z_]\w*\b(?!\s*\(|\s+(?!(?:as|in|instanceof)\b)[\"'\w$])")


def _skip_quoted(expr: str, i: int, depth: int = 0) -> int:
    """The index just after the quoted text that starts at `i`, following `${...}` inside double quotes."""
    n = len(expr)
    triple = expr.startswith(expr[i] * 3, i)
    q = expr[i] * 3 if triple else expr[i]
    j = i + len(q)
    while j < n and not expr.startswith(q, j):
        if expr[j] == "\\":
            j += 2
        elif q[0] == '"' and expr.startswith("${", j) and depth < 50:
            j = _skip_braces(expr, j + 2, depth + 1)
        else:
            j += 1
    return min(j + len(q), n)


def _skip_braces(expr: str, k: int, depth: int = 0) -> int:
    """The index just after the `}` that closes a `${` whose body starts at `k`."""
    n, level = len(expr), 1
    while k < n and level:
        ch = expr[k]
        if ch == "\\":
            k += 2
            continue
        if ch in "\"'" and depth < 50:
            k = _skip_quoted(expr, k, depth + 1)
            continue
        level += 1 if ch == "{" else -1 if ch == "}" else 0
        k += 1
    return k


_DOLLAR_NAME = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*")


@functools.lru_cache(maxsize=4096)
def _unquoted(expr: str, depth: int = 0) -> str:
    """The expression with each quoted text replaced by what it interpolates (`"a-${v}"` and `"a-$v"` by `v`,
    each read the same way again), and text that interpolates nothing by a placeholder; quotes and `${...}` are
    followed together, so a quote inside `${...}` does not end the text (the third to fifth reviews of
    2d.2i). Past 50 levels the rest is left as it is, so its names are still read."""
    if depth > 50:
        return expr
    out: list[str] = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c == "'":
            # A placeholder that reads as an argument: `tool 'maven'` is a step called with one.
            i = _skip_quoted(expr, i, depth)
            out.append(" _q_ ")
            continue
        if c == '"':
            q = '"""' if expr.startswith('"""', i) else '"'
            j = i + len(q)
            parts: list[str] = []
            while j < n and not expr.startswith(q, j):
                if expr[j] == "\\":
                    j += 2
                elif expr.startswith("${", j):
                    k = _skip_braces(expr, j + 2, depth + 1)
                    body = expr[j + 2:k - 1] if k <= n and expr[k - 1:k] == "}" else expr[j + 2:k]
                    parts.append(_unquoted(body, depth + 1))
                    j = k
                elif expr[j] == "$" and j + 1 < n and (expr[j + 1].isalpha() or expr[j + 1] == "_"):
                    m = _DOLLAR_NAME.match(expr, j + 1)      # in place: no copy of the rest of the text
                    parts.append(m.group(0))
                    j = m.end()
                else:
                    j += 1
            i = min(j + len(q), n)
            # What it interpolates, ended by `;` so a name after it is not read as a step call; a text that
            # interpolates nothing reads as an argument, as above.
            out.append(" " + " ; ".join(parts) + " ; " if parts else " _q_ ")
            continue
        out.append(c)
        i += 1
    return "".join(out)
# Names a Jenkinsfile can read without defining them, which hold no secret of a binding.
_JENKINS_GLOBALS = {"env", "params", "currentBuild", "scm", "docker", "pipeline", "manager", "build", "true", "false",
                    "null", "this", "steps", "binding", "args", "out", "jenkins", "hudson", "Jenkins", "workspace",
                    "new", "in", "as", "instanceof", "def", "return"}


def stage_label(stage: tuple) -> str:
    return " > ".join(stage) if stage else "pipeline"


def script_parts(node) -> tuple[str, list, bool]:
    """(text, interpolated expressions, dynamic) of a script argument. Groovy concatenation
    (`"make " + env.X`) counts as interpolation, and so does any value a computed script reads
    (String.format('...', env.X)). dynamic: some text comes from a variable or call. Iterative."""
    if node is None:
        return "", [], True
    texts: list[str] = []
    exprs: list = []
    dynamic = False
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, Str):
            texts.append(n.text())
            exprs += n.exprs
        elif isinstance(n, Binary) and n.op == "+":
            stack += [n.right, n.left]
        elif isinstance(n, Call) and isinstance(n.callee, Prop) and not n.args and \
                n.callee.name in ("stripIndent", "trim", "stripMargin", "toString", "replaceAll", "denormalize"):
            stack.append(n.callee.target)        # """...""".stripIndent().trim()
        else:
            p = path_of(n)
            texts.append("${" + (p or "...") + "}")
            exprs += [p] if p else source_texts(n)
            dynamic = True
    return "".join(texts), exprs, dynamic


def step_arg(call: Call, key: str):
    """A step argument given by name, or inside a map passed as the only argument: sh([script: ..])."""
    value = named_arg(call, key)
    if value is None and call.args and isinstance(call.args[0], MapLit):
        for k, v in call.args[0].entries:
            if k == key:
                return v
    return value


def base_stage(stage: tuple) -> tuple:
    """A stage without its post blocks: ('Build', 'post success') -> ('Build',)."""
    out = list(stage)
    while out and out[-1].startswith("post "):
        out.pop()
    return tuple(out)


def concurrent(a, b) -> bool:
    """Whether two steps are in different branches of the same parallel block."""
    for x, y in zip(a.branch, b.branch):
        if x[0] == y[0] and x[1] != y[1]:
            return True
        if x != y:
            return False
    return False


def _last_command(script: str, start: int) -> bool:
    """Whether nothing but blank lines and comments follows position `start`'s line in the script."""
    end = script.find("\n", start)
    if end == -1:
        return True
    rest = [ln.strip() for ln in script[end + 1:].splitlines()]
    return all(not ln or ln.startswith(("#", "REM ", "::")) for ln in rest)


class JenkinsRules:
    def __init__(self, path: str, pipeline: Pipeline, catalog: Catalog, root: Path | None,
                 extra_agents: dict | None = None, lane_overrides: dict | None = None) -> None:
        self.path = path
        self.p = pipeline
        self.catalog = catalog
        self._script_texts: dict[int, tuple] = {}     # id(call) -> (call, the script as the shell reads it)
        self.detection = catalog.detection
        self.root = root
        extra_agents = extra_agents or {}
        self.agent_cmds = [re.compile(x, re.M) for x in
                           list(self.detection.get("agent_commands", [])) + list(extra_agents.get("commands") or [])]
        self.agent_steps = set(extra_agents.get("steps") or []) | set(self.detection.get("jenkins_agent_steps", []))
        self.upload_cmds = [re.compile(x, re.M) for x in list(self.detection.get("upload_commands", []))
                            + list(self.detection.get("jenkins_upload_commands", []))]
        self.upload_steps = set(self.detection.get("jenkins_upload_steps", []))
        self.verify_cmds = [re.compile(x, re.M) for x in self.detection.get("verify_commands", [])]
        self.release_verify = [re.compile(x) for x in self.detection.get("release_verify_commands", [])]
        # A package name, its extras (`aider-chat[playwright]`) and any version after it, in npm's form
        # (`@1.2.3`, `@^1`, `@latest`) or PEP 440's (`==`, `~=`, `>=`, ...): flagship slice 2d.2k.
        self.packages = [(pkg, re.compile(r"(?<![\w@/.-])" + re.escape(pkg) + r"(?:\[[^\]\s'\"]*\])?"
                                          r"(?P<ver>(?:@|===|==|~=|!=|>=|<=|>|<)[^\s;&|'\"]*)?"
                                          r"(?=[\s;&|'\",)]|$)"))
                         for pkg in self.detection.get("agent_packages", [])]
        self.agent_package_names = set(self.detection.get("agent_packages", []))
        self.install_urls = [re.compile(x, re.I) for x in self.detection.get("agent_install_urls", [])]
        self._agent_words = re.compile(r"(?<![\w-])(claude|gemini|codex|opencode|aider|copilot|qodo)(?![\w])", re.I)
        self.lane_overrides = lane_overrides or {}
        self.findings: list[Finding] = []
        self.unknowns: list[Unknown] = []
        self.applicable: set[str] = set()
        self.infos: list[Info] = []
        self._seen: set = set()
        self._files: dict = {}
        self.by_agent: dict[int, list[Info]] = {}
        self.by_stage: dict[tuple, list[Info]] = {}
        self.publishing_stages: set = set()

    # ------------------------------------------------------------------ plumbing
    def add(self, rule: str, line: int, message: str, stage: tuple | None = None, severity: str | None = None,
            step: str | None = None) -> None:
        key = (rule, line, message)
        if key in self._seen:      # a method of the file expanded at several calls
            return
        self._seen.add(key)
        self.findings.append(Finding(rule=rule, severity=severity or self.catalog.rules[rule]["severity"],
                                     path=self.path, line=line or 1, message=message,
                                     job=stage_label(stage) if stage is not None else None, step=step,
                                     scope="stage"))

    def unknown(self, rule: str, line: int, reason: str) -> None:
        key = (rule, line, reason)
        if key in self._seen:
            return
        self._seen.add(key)
        self.unknowns.append(Unknown(rule, line or 1, reason))

    def run(self) -> tuple[list[Finding], list[Unknown], set[str]]:
        self.classify()
        self.file_unknowns()
        self.credentials_exposed()        # JEN-001
        self.controller_and_placement()   # JEN-002
        self.agent_effects()              # JEN-003
        self.pipeline_code()              # JEN-004
        self.approvals()                  # JEN-005
        self.host_access()                # JEN-006
        self.agent_egress()               # JEN-007
        self.mutable_references()         # JEN-008
        self.injection()                  # JEN-009
        self.artifact_transfer()          # JEN-010
        self.failure_paths()              # JEN-011
        self.provenance_check()           # JEN-012
        self.secret_interpolation()       # JEN-013
        self.signing_keys()               # JEN-014
        self.webhook_tokens()             # JEN-015
        return self.findings, self.unknowns, self.applicable

    # ------------------------------------------------------------------ classification
    def classify(self) -> None:
        defined = self.p.local_names
        # A method of the file called many times records the same step once per call; what a step is
        # depends only on its call, so it is worked out once (flagship slice 2d.2i: a 2.9 KB file of
        # nested calls took 7.5 seconds).
        seen: dict[int, tuple] = {}
        for index, use in enumerate(self.p.steps):
            info = Info(use, index)
            call = use.call
            name = use.name
            if name in SHELL_STEPS:
                info.shell = True
                if _truthy(step_arg(call, "returnStatus")):
                    info.swallowed = "returnStatus: true"
            if use.ctx.swallowed:
                info.swallowed = use.ctx.swallowed
            hit = seen.get(id(call))
            if hit is not None and hit[0] is call and hit[1] == name:
                info.script, info.exprs, info.dynamic, info.ai, info.publish, info.verify, info.push = hit[2:]
            else:
                if info.shell:
                    info.script, info.exprs, info.dynamic = script_parts(shell_script(call))
                info.ai = self._ai(info)
                info.publish = self._publish(info)
                info.verify = self._verify(info)
                info.push = bool(info.shell and GIT_PUSH.search(info.script))
                seen[id(call)] = (call, name, info.script, info.exprs, info.dynamic, info.ai, info.publish,
                                  info.verify, info.push)
            if name == "build":
                job = named_arg(call, "job") or first_arg(call)
                info.trigger = literal(job) or "a computed job name"
            # A call the file does not define and the checker does not know: most likely a shared-library
            # step, whose code is not in this file. Method calls on a step's result (sh(...).trim()) and
            # on local variables are not steps.
            receiver_is_call = isinstance(call.callee, Prop) and isinstance(call.callee.target, Call)
            base = name.split(".")[0]
            if name and not receiver_is_call and not name.startswith("new ") and name not in known.KNOWN_STEPS \
                    and base not in defined and base not in known.KNOWN_OBJECTS and name not in self.agent_steps \
                    and name not in self.upload_steps and not base[:1].isupper():
                info.unresolved = True
            self.infos.append(info)
        # A stage declared as an agent lane (OBAAF_LANE or configuration) runs agents in every code step.
        for info in self.infos:
            lanes = self.lanes_of(info.ctx)
            # A shell step, or a step whose code is not in this file (most likely a shared-library
            # step): in a stage declared an agent or release lane, that is where the agent runs or
            # the upload happens. Not in a post block, where such a step is most often a notice.
            code = info.shell or (info.unresolved and info.ctx.post is None)
            if "agent" in lanes and code and not info.ai:
                info.ai = "the stage is declared an agent lane"
            if "release" in lanes and (code or info.use.name in TRANSFER_STEPS) and not info.publish:
                info.publish = "the stage is declared a release lane"
        # Indexes, so no rule compares every step with every agent or stage.
        for info in self.infos:
            if info.ctx.agent is not None:
                self.by_agent.setdefault(id(info.ctx.agent), []).append(info)
            self.by_stage.setdefault(info.ctx.stage, []).append(info)
            if info.publish:
                self.publishing_stages.add(info.ctx.stage)

    def lane_keys(self, stage: tuple) -> list[str]:
        """The `lanes:` keys that apply to a step in `stage`: the file, the stage by its full label or
        its own name, and every stage it is nested in."""
        keys = [self.path, f"{self.path}#{stage_label(stage)}"]
        for depth in range(1, len(stage) + 1):
            keys += [f"{self.path}#{stage_label(stage[:depth])}", f"{self.path}#{stage[depth - 1]}"]
        return list(dict.fromkeys(keys))

    def lanes_of(self, ctx) -> set:
        """Every lane declared for a step: in the configuration, and with OBAAF_LANE anywhere on the
        way to the step. A declaration adds a lane and none hides another, as in a workflow; a value
        that is not a lane adds nothing."""
        values = [self.lane_overrides.get(key) for key in self.lane_keys(ctx.stage)]
        values += [value for value, _ in ctx.lanes]
        return {lane for lane in map(declared_lane, values) if lane}

    def _ai(self, info: Info) -> str | None:
        if info.use.name in self.detection.get("jenkins_agent_steps", []):
            return f"the {info.use.name} step runs an agent"
        if info.use.name in self.agent_steps:
            return f"step {info.use.name} is declared an agent in the checker configuration"
        if not info.shell:
            return None
        # The script as the shell reads it: continued lines joined, literal variables of this file put in
        # (flagship slice 2d.2i: `sh cmd` and `claude \\` + `-p` on the next line were not recognised).
        script = self.script_text(info)
        for rx in self.agent_cmds:
            m = rx.search(script)
            if m:
                return f"runs an agent CLI ({m.group(0).strip()})"
        for rel in self._scripts(info.script):
            text = self._read(rel)
            if text and any(rx.search(text) for rx in self.agent_cmds):
                return f"runs an agent in the script {rel}"
        return None

    def _publish(self, info: Info) -> str | None:
        name = info.use.name
        if name in self.upload_steps:
            return f"{name} step"
        if name.endswith(".push"):
            base = name.rsplit(".", 1)[0]
            if base.startswith("docker.") or base.split(".")[0] in self.p.docker_vars:
                return "docker push"
        if info.shell:
            for rx in self.upload_cmds:
                m = rx.search(info.script)
                if m:
                    return m.group(0).strip()
        return None

    def _verify(self, info: Info) -> str | None:
        """'full' or 'provenance' for a verification step; info.swallowed says why one cannot stop the
        build: `|| ...`, a pipe without pipefail, `set +e`, or a later command when the script does not
        stop at the first failure (a #! line without -e, bat, powershell)."""
        if not info.shell or not info.script:
            return None
        text = info.script
        kind = None
        errexit = info.use.name == "sh" and not text.lstrip().startswith("#!")
        if info.use.name == "sh" and text.lstrip().startswith("#!"):
            first = text.lstrip().splitlines()[0]
            errexit = bool(re.search(r"\s-[a-z]*e", first))
        if re.search(r"(^|[\n;&])\s*set\s+(-[a-z]*e|-o\s+errexit)\b", text):
            errexit = True
        pipefail = bool(re.search(r"set\s+(-[a-z]*o\s+pipefail|-o\s+pipefail)", text))
        for pattern in self.verify_cmds:
            for m in pattern.finditer(text):
                end = text.find("\n", m.end())
                rest = text[m.end(): None if end == -1 else end]
                before = text[: m.start()]
                why = None
                if re.search(r"(^|[\n;&])\s*set\s+\+e\b", before):
                    why = "set +e before the command"
                elif "||" in rest or re.search(r"(?<![&])&\s*$", rest):
                    why = "|| or & after the command"
                elif re.search(r"(?<![|])\|(?![|])", rest) and not pipefail:
                    why = "a pipe without pipefail: the step's status is the last command's"
                elif not errexit and not _last_command(text, m.start()):
                    why = (f"the {info.use.name} script does not stop at a failed command, and more commands "
                           "follow it")
                if why:
                    info.swallowed = info.swallowed or why
                    kind = kind or "swallowed"
                    continue
                if any(r.match(text, m.start()) for r in self.release_verify):
                    return "full"
                kind = "provenance"
        return kind

    def _scripts(self, script: str) -> list[str]:
        if self.root is None:
            return []
        from obaaf.checker import _copied_script_targets, _script_targets   # shared with the workflow checker
        out = _script_targets(script)
        try:
            out += _copied_script_targets(script, self.root)
        except Exception:      # best-effort: never let a helper stop the check
            pass
        return out

    def _read(self, rel: str) -> str | None:
        if self.root is None:
            return None
        if rel in self._files:
            return self._files[rel]
        self._files[rel] = None
        try:
            root = self.root.resolve()
            path = (self.root / rel).resolve()
            if root not in path.parents or not path.is_file():
                return None
            with path.open(encoding="utf-8", errors="replace") as fh:
                self._files[rel] = fh.read(200_000)
        except (OSError, RuntimeError):
            return None
        return self._files[rel]

    # ------------------------------------------------------------------ helpers
    def stages(self) -> dict:
        return self.by_stage

    def stage_publishes(self, stage: tuple) -> bool:
        return stage in self.publishing_stages

    def under(self, agent) -> list:
        return self.by_agent.get(id(agent), [])

    def gates(self, check: Info, target: Info) -> bool:
        """Whether a check step can stop `target`: it runs before it, its failure stops the build, it
        is not in a failure path or a sibling parallel branch, and every condition that could skip the
        check also guards the target."""
        return (check.index < target.index and not check.swallowed and check.ctx.post not in FAILURE_PATHS
                and not concurrent(check.ctx, target.ctx) and set(check.ctx.guards) <= set(target.ctx.guards))

    def bindings(self) -> dict[Binding, list[Info]]:
        out: dict[Binding, list[Info]] = {}
        for info in self.infos:
            for b in info.ctx.creds:
                out.setdefault(b, []).append(info)
        return out

    @staticmethod
    def ids(b: Binding) -> str:
        shown = [i for i in b.ids if i != "?"]
        return ", ".join(f"'{i}'" for i in shown) if shown else "computed credential IDs"

    def file_unknowns(self) -> None:
        for line, what in self.p.opaque:
            self.unknown(ALL, line, what)
        unresolved = [i for i in self.infos if i.unresolved]
        if unresolved:
            names = sorted({i.use.name for i in unresolved})
            shown = ", ".join(names[:6]) + (f" and {len(names) - 6} more" if len(names) > 6 else "")
            self.unknown(ALL, unresolved[0].line,
                         f"calls {len(names)} step(s) that are not built into Jenkins or defined in this file "
                         f"({shown}); they are probably shared-library or plugin code the checker did not read")

    # ------------------------------------------------------------------ JEN-001
    def credentials_exposed(self) -> None:
        """One finding per binding, at its worst exposure. A step 'runs repository code' when it calls a
        build tool, test runner or script from the checkout; steps that only run fixed tools (curl, a
        vendor CLI) still expose the credential if a tool reads files from the checkout, so they are
        reported one level lower rather than dropped."""
        scopes = self.bindings()
        if scopes:
            self.applicable.add("OBAAF-JEN-001")
        # A step that runs an agent and takes a credential itself (aiAgent(apiCredentialsId: ...)).
        for info in self.infos:
            if not info.ai:
                continue
            for key in ("apiCredentialsId", "credentialsId"):
                cred = named_arg(info.use.call, key)
                if cred is None:
                    continue
                self.applicable.add("OBAAF-JEN-001")
                shown = f"'{literal(cred)}'" if literal(cred) else "a computed credential"
                yolo = path_of(named_arg(info.use.call, "yoloMode")) == "true"
                self.add("OBAAF-JEN-001", info.line,
                         f"The {info.use.name} step at line {info.line} gives the agent credential {shown} ({key})"
                         + (" and runs its tools without confirmation (yoloMode)" if yolo else "")
                         + ". Text the agent reads can make it use or disclose the credential.", info.ctx.stage,
                         severity="high")
        for b, infos in scopes.items():
            code = [i for i in infos if i.runs_code]
            where = f"bound by {b.how} (line {b.line}, {b.origin})"
            ai = [i for i in code if i.ai]
            if ai:
                first = ai[0]
                self.add("OBAAF-JEN-001", b.line,
                         f"Credential(s) {self.ids(b)} {where} are available to the AI agent at line {first.line} "
                         f"in stage '{stage_label(first.ctx.stage)}' ({first.ai}). Text the agent reads can make it "
                         "use or disclose them." + self._also(code, first), first.ctx.stage, severity="high")
                continue
            reached = [i for i in code if i.ctx.cr in (CR_YES, CR_POSSIBLE)]
            if reached:
                yes = any(i.ctx.cr == CR_YES for i in reached)
                repo = [i for i in reached if self.runs_repo_code(i)]
                first = (repo or reached)[0]
                levels = ["low", "medium", "high"]
                level = (2 if yes else 1) - (0 if repo else 1)
                when = ("run for change requests" if yes else
                        "nothing in the Jenkinsfile keeps away from change requests")
                how = ("It runs code from the checkout, which for a change request is the change's own code, so "
                       "its author can read the credential, even when Jenkins takes the Jenkinsfile from a trusted "
                       "branch." if repo else
                       "The steps seem to run fixed tools rather than code from the checkout; the credential is "
                       "still exposed if a tool reads configuration or scripts from the checkout.")
                cond = "" if yes else " This matters if the job builds pull requests."
                self.add("OBAAF-JEN-001", b.line,
                         f"Credential(s) {self.ids(b)} {where} are available to the step at line {first.line} in stage "
                         f"'{stage_label(first.ctx.stage)}', which {when}. {how}{cond}" + self._also(reached, first),
                         first.ctx.stage, severity=levels[max(level, 0)])
                continue
            unknown = [i for i in code if i.ctx.cr == CR_UNKNOWN]
            if unknown:
                self.unknown("OBAAF-JEN-001", unknown[0].ctx.cr_line or b.line,
                             f"credential(s) {self.ids(b)} (line {b.line}) reach steps whose stage condition the checker "
                             "cannot evaluate, so it cannot tell whether change requests reach them")
            hidden = [i for i in infos if i.unresolved and i.ctx.cr != CR_NO]
            if hidden:
                self.unknown("OBAAF-JEN-001", hidden[0].line,
                             f"credential(s) {self.ids(b)} (line {b.line}) are available to {hidden[0].use.name}, "
                             "whose code is not in this file")

    @staticmethod
    def _also(infos: list, first) -> str:
        others = sorted({stage_label(i.ctx.stage) for i in infos if i.ctx.stage != first.ctx.stage})
        if not others:
            return ""
        shown = ", ".join(f"'{o}'" for o in others[:3]) + (f" and {len(others) - 3} more" if len(others) > 3 else "")
        return f" The same binding also reaches stage(s) {shown}."

    def _reviewed_text(self, node) -> bool:
        """Code text the reviewed Jenkinsfile fixes: a string literal with no interpolation, a variable that
        holds one, or text read with readTrusted or libraryResource (whose pin is OBAAF-JEN-008's)."""
        if isinstance(node, Str):
            return not node.interpolated
        if isinstance(node, Name) and node.name in self.p.literals:
            return not self.p.literals[node.name].interpolated
        if isinstance(node, Call):
            name = chain_name(node.callee) or ""
            return name.split(".")[-1] in ("readTrusted", "libraryResource") and \
                not name.startswith(("new ", "Eval."))
        return False

    def runs_repo_code(self, info: Info) -> bool:
        if info.ai or info.use.name.startswith("docker.build") or info.unresolved:
            return True
        return bool(info.shell and (REPO_CODE.search(info.script) or info.dynamic))

    # ------------------------------------------------------------------ JEN-002
    def controller_and_placement(self) -> None:
        self.applicable.add("OBAAF-JEN-002")
        floating = []
        labels: dict[str, list] = {}
        for agent, ctx in self.p.agents:
            under = self.under(agent)
            label = (agent.label or "").strip().lower()
            if label in CONTROLLER_LABELS:
                risky = [i for i in under if i.ai or i.ctx.cr in (CR_YES, CR_POSSIBLE)]
                severity = "high" if risky or not under else "medium"
                why = ("steps that change requests or an AI agent can steer" if risky else
                       "steps from branches without change requests")
                self.add("OBAAF-JEN-002", agent.line,
                         f"Stage '{stage_label(ctx.stage)}' runs on the controller (label '{agent.label}'), with "
                         f"{why}. Code on the built-in node can read $JENKINS_HOME, including the keys that decrypt "
                         "every stored credential.", ctx.stage, severity=severity)
            elif agent.kind in ("any", "unknown") or (agent.kind in ("label", "node") and (
                    not agent.label or "${" in agent.label)):
                floating.append((agent, ctx))
            elif agent.kind in ("label", "node") and agent.label:
                labels.setdefault(agent.label, []).append((agent, ctx, under))
        exposed = sorted(label for label, uses in labels.items() if any(
            i.ai or (i.runs_code and i.ctx.cr in (CR_YES, CR_POSSIBLE)) for _, _, under in uses for i in under))
        if exposed:
            first = labels[exposed[0]][0][0]
            self.unknown("OBAAF-JEN-002", first.line,
                         f"agents labelled {', '.join(repr(x) for x in exposed)} run work that change requests or an "
                         "AI agent can steer; whether those agents are ephemeral, and whether other jobs run "
                         "privileged work on them, is controller configuration")
        if floating:
            agent, ctx = floating[0]
            self.unknown("OBAAF-JEN-002", agent.line,
                         f"{len(floating)} agent selection(s) (agent any, node without a label, or a computed label) "
                         "can place work on any agent, including the built-in node if it has executors; which agents "
                         "exist and who else uses them is controller configuration")
        # One persistent agent label shared by change-request work and privileged work.
        for label, uses in labels.items():
            untrusted = [(a, c) for a, c, under in uses if any(
                i.runs_code and i.ctx.cr in (CR_YES, CR_POSSIBLE) for i in under)]
            privileged = [(a, c) for a, c, under in uses if any(
                i.ctx.cr == CR_NO and (i.ctx.creds or i.publish) for i in under)]
            if untrusted and privileged:
                a, c = privileged[0]
                self.add("OBAAF-JEN-002", a.line,
                         f"Agents labelled '{label}' run both work that change requests reach (stage "
                         f"'{stage_label(untrusted[0][1].stage)}') and stage '{stage_label(c.stage)}', which holds "
                         "credentials or publishes. Code from a change request can leave files or processes on a "
                         "persistent agent that the privileged stage then uses.", c.stage, severity="medium")

    # ------------------------------------------------------------------ JEN-003
    def agent_effects(self) -> None:
        # A stage and its own post blocks share a workspace.
        groups: dict[tuple, list[Info]] = {}
        for info in self.infos:
            groups.setdefault(base_stage(info.ctx.stage), []).append(info)
        for stage, infos in groups.items():
            ai = [i for i in infos if i.ai]
            if not ai:
                continue
            self.applicable.add("OBAAF-JEN-003")
            for info in infos:
                if info.ai and not (info.push or info.trigger or info.publish):
                    continue
                effect = ("pushes to the repository" if info.push else
                          f"starts job {info.trigger} (as SYSTEM unless build authorization is configured)"
                          if info.trigger else f"publishes ({info.publish})" if info.publish else None)
                if effect:
                    self.add("OBAAF-JEN-003", info.line,
                             f"Stage '{stage_label(stage)}' runs an AI agent at line {ai[0].line} and the step at line "
                             f"{info.line} {effect}, in the same workspace. What the agent wrote or was told can reach "
                             "that effect without review.", stage, severity="high")

    # ------------------------------------------------------------------ JEN-004
    def pipeline_code(self) -> None:
        self.applicable.add("OBAAF-JEN-004")
        for lib in self.p.libraries:
            shown = lib.name + (f"@{lib.version}" if lib.version else "")
            if lib.retriever == "self":
                self.add("OBAAF-JEN-004", lib.line,
                         f"Library '{shown}' is loaded with legacySCM(scm), from the build's own checkout. For a "
                         "change request that is the change's own code, so its author chooses the library code that "
                         "runs.", None, severity="high")
            elif lib.retriever == "computed":
                source = lib.retriever_source
                self.add("OBAAF-JEN-004", lib.line,
                         f"Library '{shown}' is fetched by a retriever built from "
                         + (f"{source[0]}, so whoever sets that value chooses" if source else
                            "values computed at run time, so the reviewed Jenkinsfile does not fix")
                         + " where the library's code comes from.", None,
                         severity="high" if source else "medium")
            if lib.name == "?":
                self.unknown("OBAAF-JEN-004", lib.line, f"{lib.how} names a library computed at run time")
                continue
            if lib.dynamic:
                what = "a name" if "${" in lib.name else "a version"
                source = untrusted_source(list(lib.exprs), self.p)
                if source is None and any(WORKSPACE_READ.search(x) for x in lib.exprs):
                    # A file in the workspace is the change's own for a change request (flagship slice 2d.2k).
                    source = ("a file in the workspace", "high")
                if source:
                    self.add("OBAAF-JEN-004", lib.line,
                             f"Library '{shown}' is loaded with {what} taken from {source[0]}, so whoever sets that "
                             "value chooses the pipeline code that runs. A trusted global library runs outside the "
                             "Groovy sandbox.", None, severity="high")
                else:
                    self.add("OBAAF-JEN-004", lib.line,
                             f"Library '{shown}' is loaded with {what} computed at run time, so the reviewed "
                             "Jenkinsfile does not fix which code runs.", None, severity="medium")
        # Every call that runs Groovy the file does not hold, on any receiver (flagship slice 2d.2k).
        for kind, name, call, ctx in self.p.code_loads:
            arg = code_text_arg(kind, name, call)
            if kind == "jobDsl":
                if named_arg(call, "targets") is None and arg is not None and self._reviewed_text(arg):
                    continue
                what = ("runs Job DSL scripts from the workspace on the controller"
                        if named_arg(call, "targets") is not None or arg is None else
                        "runs Job DSL script text read at run time on the controller")
            elif kind == "evaluate":
                if arg is not None and self._reviewed_text(arg):
                    continue
                what = f"evaluates Groovy text read at run time ({name})"
            else:
                what = f"loads Groovy from the workspace ({literal(arg) or 'a computed path'})"
            cr = ctx.cr
            source = untrusted_source(source_texts(arg), self.p) if kind != "load" and arg is not None else None
            if source is not None:
                # Text built from a parameter or a change's text: whoever sets it writes the code, on any
                # branch (flagship slice 2d.2k: `evaluate("${params.GROOVY}")` was only "unknown").
                self.add("OBAAF-JEN-004", call.line,
                         f"Stage '{stage_label(ctx.stage)}' runs Groovy built from {source[0]} ({name}), so whoever "
                         "sets that value writes pipeline code.", ctx.stage,
                         severity="high" if source[1] == "high" else "medium")
                continue
            if cr in (CR_YES, CR_POSSIBLE):
                privileged = bool(ctx.creds) or self.stage_publishes(ctx.stage) or kind == "jobDsl"
                self.add("OBAAF-JEN-004", call.line,
                         f"Stage '{stage_label(ctx.stage)}' {what}. For a change request the workspace holds the "
                         "change's own files, so its author controls this pipeline code even when Jenkins takes the "
                         "Jenkinsfile from a trusted branch" + (", and the code runs where credentials are bound."
                                                               if ctx.creds or self.stage_publishes(ctx.stage) else
                                                               ", and Job DSL can create and change jobs."
                                                               if kind == "jobDsl" else "."),
                         ctx.stage, severity="high" if privileged or cr == CR_YES else "medium")
            elif cr == CR_UNKNOWN:
                self.unknown("OBAAF-JEN-004", call.line,
                             f"{name} at line {call.line} runs under a condition the checker cannot evaluate")
        if self.p.libraries:
            self.unknown("OBAAF-JEN-004", self.p.libraries[0].line,
                         "whether each library is trusted (global, outside the sandbox) or untrusted (folder), and "
                         "whether the Jenkinsfile may override its version, is controller configuration")
        if any(i.ctx.creds or i.publish for i in self.infos):
            self.unknown("OBAAF-JEN-004", 1,
                         "Replay lets users with Run/Replay permission run an edited Jenkinsfile with this job's "
                         "credentials; whether that permission is restricted is controller configuration")

    # ------------------------------------------------------------------ JEN-005
    def approvals(self) -> None:
        publishes = [i for i in self.infos if i.publish]
        if publishes or self.p.approvals:
            self.applicable.add("OBAAF-JEN-005")
        for approval in self.p.approvals:
            if approval.submitter is None:
                self.add("OBAAF-JEN-005", approval.line,
                         f"The input step at line {approval.line} sets no submitter, so any user with Build permission "
                         "on the job can approve it, including the person who started the build.",
                         approval.ctx.stage, severity="medium")
            elif approval.submitter == "?":
                self.unknown("OBAAF-JEN-005", approval.line, "the input step's submitter list is computed at run time")
        if publishes:
            first = publishes[0]
            gates = [i for i in self.infos if i.use.name == "input" and i.index < first.index]
            if not gates:
                self.add("OBAAF-JEN-005", first.line,
                         f"Stage '{stage_label(first.ctx.stage)}' publishes ({first.publish}) with no input step before "
                         "it, so no person approves the release in the pipeline.", first.ctx.stage,
                         severity="medium")
        if self.p.approvals:
            self.unknown("OBAAF-JEN-005", self.p.approvals[0].line,
                         "whether approvers are independent of the person who started or changed the build, and "
                         "whether the approval is bound to the exact artifacts, is not visible in the Jenkinsfile")

    # ------------------------------------------------------------------ JEN-006
    def host_access(self) -> None:
        for agent, ctx in self.p.agents:
            if agent.kind not in ("docker", "dockerfile", "kubernetes"):
                continue
            self.applicable.add("OBAAF-JEN-006")
            problems: list[str] = []
            if agent.args:
                problems += [label for rx, label in DOCKER_HOST_ARGS if rx.search(agent.args)]
                if "${" in agent.args:
                    self.unknown("OBAAF-JEN-006", agent.line, "docker run options are computed at run time")
            pod = self.pod_spec(agent, "OBAAF-JEN-006")
            under = self.under(agent)
            if pod:
                problems += [label for rx, label in POD_HOST_SETTINGS if rx.search(pod)]
                account = re.search(r"^\s*serviceAccount(?:Name)?:\s*['\"]?([\w.-]+)", pod, re.M)
                if account:
                    self.unknown("OBAAF-JEN-006", agent.line,
                                 f"the pod runs as service account '{account.group(1)}', whose permissions are cluster "
                                 "configuration")
                elif any(i.ai for i in under) and not re.search(r"automountServiceAccountToken:\s*false", pod):
                    problems.append("the namespace's service account token, mounted by default")
            if agent.inherit:
                shown = f"'{agent.inherit}'" if agent.inherit != "?" else "computed at run time"
                self.unknown("OBAAF-JEN-006", agent.line,
                             f"pod template {shown} is defined on the controller, not in the repository")
            if not problems:
                continue
            risky = [i for i in under if i.ai or i.ctx.cr in (CR_YES, CR_POSSIBLE)]
            unique = list(dict.fromkeys(problems))
            self.add("OBAAF-JEN-006", agent.line,
                     f"The {agent.kind} agent for stage '{stage_label(ctx.stage)}' uses {', '.join(unique)}. Code in "
                     "the container can then reach the host and other builds on it"
                     + (", and change requests or an AI agent can steer that code." if risky else "."),
                     ctx.stage, severity="high" if risky or not under else "medium")

    def pod_spec(self, agent, rule: str) -> str | None:
        """The pod YAML of a Kubernetes agent: inline, from a variable assigned a literal in this file, or
        from a file in the repository. Anything else is reported as unknown for `rule`."""
        if agent.yaml:
            return agent.yaml
        if agent.yaml_ref is not None:
            lit = self.p.literals.get(agent.yaml_ref) if agent.yaml_ref else None
            if lit is not None:
                return lit.text()
            self.unknown(rule, agent.line, "the pod spec is computed at run time"
                         + (f" ({agent.yaml_ref})" if agent.yaml_ref else " (for example libraryResource)"))
            return None
        if agent.yaml_file:
            text = self._read(agent.yaml_file) if agent.yaml_file != "?" else None
            if text is None:
                self.unknown(rule, agent.line, f"pod definition {agent.yaml_file if agent.yaml_file != '?' else ''}"
                             " is not in the repository checkout".replace("  ", " "))
            return text
        return None

    # ------------------------------------------------------------------ JEN-007
    def agent_egress(self) -> None:
        declared = "OBAAF_EGRESS" in self.p.env_values
        for stage, infos in self.stages().items():
            ai = [i for i in infos if i.ai]
            if not ai:
                continue
            self.applicable.add("OBAAF-JEN-007")
            note = (" OBAAF_EGRESS declares a policy, but a declaration is not enforcement." if declared else "")
            self.add("OBAAF-JEN-007", ai[0].line,
                     f"Nothing in the Jenkinsfile limits the network access of the AI agent in stage "
                     f"'{stage_label(stage)}'. Jenkins has no egress control of its own; a limit has to come from "
                     f"the agent's network (for example a Kubernetes NetworkPolicy).{note}", stage)

    # ------------------------------------------------------------------ JEN-008
    def _resolve(self, text: str) -> str:
        """`${NAME}`, `${env.NAME}`, `$env.NAME` and `$NAME` (as a shell reads it) replaced by this file's
        literal variables and literal environment values (flagship slice 2d.2k). What is left with a `$` is
        computed. Bounded: three passes, and no text longer than 100,000 characters."""
        def value(name: str):
            node = self.p.literals.get(name)
            if node is None:
                node = self.p.env_values.get(name)
            return node.text() if isinstance(node, Str) else None

        def sub(m):
            got = value(m.group(1) or m.group(2) or m.group(3))
            return got if got is not None else m.group(0)

        for _ in range(3):
            changed = _REF.sub(sub, text)
            if changed == text or len(changed) > 100_000:
                break
            text = changed
        return text

    def _image(self, ref: str, line: int, stage: tuple | None, where: str, severity: str) -> None:
        """One image reference: pinned to a digest, computed (unknown), or a finding."""
        self.applicable.add("OBAAF-JEN-008")
        if "$" in ref:
            ref = self._resolve(ref)
        if "$" in ref or not ref.strip() or ref == "?":
            self.unknown("OBAAF-JEN-008", line, f"image reference {ref or '(empty)'} {where} is computed at run time"
                         .replace("  ", " "))
        elif not PINNED_IMAGE.match(ref.strip()):
            self.add("OBAAF-JEN-008", line, f"Image '{ref}' {where} is not pinned to a sha256 digest.", stage,
                     severity=severity)

    def _pod_images(self, text: str) -> list | None:
        """Every `image` a pod spec names, read as YAML (flagship slice 2d.2k: a line pattern missed flow
        mappings, JSON, quoted keys and `image :`, and took a block scalar's `>-` for the image). None when
        the text is not YAML the checker can read; an image that is not text is None in the list."""
        try:
            docs = list(yaml.safe_load_all(text))
        except Exception:      # any parse failure is "cannot read", never "no images"
            return None
        out: list = []
        stack, seen, visits = list(docs), set(), 0
        while stack:
            node = stack.pop()
            visits += 1
            if visits > 50_000:
                return None
            if isinstance(node, (dict, list)):
                if id(node) in seen:       # an alias: the same object, read once
                    continue
                seen.add(id(node))
            if isinstance(node, dict):
                for key, item in node.items():
                    if key == "image":
                        out.append(item if isinstance(item, str) else None)
                    else:
                        stack.append(item)
            elif isinstance(node, list):
                stack.extend(node)
        return out

    def _dockerfile(self, rel: str, line: int, stage: tuple | None, severity: str) -> None:
        """The FROM lines and agent CLI installs of a Dockerfile in the repository (flagship slice 2d.2k:
        `dockerfile true` and docker.build were never read)."""
        self.applicable.add("OBAAF-JEN-008")
        text = self._read(rel) if rel != "?" else None
        if text is None:
            self.unknown("OBAAF-JEN-008", line, "the Dockerfile " + (f"{rel} is not in the repository checkout"
                                                                    if rel != "?" else "is named at run time"))
            return
        joined = re.sub(r"\\\r?\n", " ", text)
        aliases: set = set()
        args: dict = {}
        for raw in joined.splitlines():
            m = re.match(r"[ \t]*(FROM|RUN|ARG)[ \t]+(.*)", raw, re.I)
            if not m:
                continue
            word, rest = m.group(1).upper(), m.group(2).strip()
            if word == "ARG":
                name, eq, default = rest.partition("=")
                if eq:
                    args[name.strip()] = default.strip().strip("'\"")
                continue
            if word == "RUN":
                for message in self._install_problems(rest):
                    self.add("OBAAF-JEN-008", line, f"{message} (in {rel}).", stage, severity="high")
                continue
            tokens = [t for t in rest.split() if not t.startswith("--")]
            if not tokens:
                continue
            image = re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda a: args.get(a.group(1), a.group(0)), tokens[0])
            if len(tokens) >= 3 and tokens[1].lower() == "as":
                aliases.add(tokens[2].lower())
            if image.lower() == "scratch" or image.lower() in aliases:
                continue
            if "$" in image:
                self.unknown("OBAAF-JEN-008", line, f"the base image {image} in {rel} is computed at build time")
            elif not PINNED_IMAGE.match(image):
                self.add("OBAAF-JEN-008", line, f"Base image '{image}' in {rel} is not pinned to a sha256 digest.",
                         stage, severity=severity)

    def _shell_images(self, text: str) -> list:
        """(image or None, command) for each `docker`/`podman`/`nerdctl` run, create or pull in a script.
        None when an option the checker does not know stands before the image, so it cannot tell which
        word is the image (flagship slice 2d.2k: images in shell steps were never checked)."""
        out = []
        for m in _CONTAINER_CMD.finditer(text):
            command = m.group(2).lower()
            rest = re.split(r"(?<!\\)[;&|\n]", text[m.end():], maxsplit=1)[0]
            try:
                words = shlex.split(rest)
            except ValueError:
                out.append((None, command))
                continue
            image, i = None, 0
            while i < len(words):
                w = words[i]
                if w == "--":
                    image = words[i + 1] if i + 1 < len(words) else None
                    break
                if not w.startswith("-") or w == "-":
                    image = w
                    break
                flag = w.split("=", 1)[0]
                if "=" in w or flag in _DOCKER_BOOL:
                    i += 1
                elif flag in _DOCKER_VALUE:
                    i += 2
                elif re.fullmatch(r"-[ditPq]+", w):
                    i += 1
                else:
                    image = "?"
                    break
            out.append((None if image in (None, "?") else image, command))
        return out

    def _install_problems(self, text: str, where: str = "") -> list:
        """What in a script installs an agent CLI at a version that can move: a downloaded install script,
        a package without an exact version (a range, a tag, a version set at run time), or an update
        command (flagship slice 2d.2k)."""
        out: list = []
        text = re.sub(r"[\\^`]\r?\n[ \t]*", " ", text)
        if len(text) > 400_000:
            return ["An agent CLI may be installed in a script too long to read"] if self._agent_words.search(
                text) else []
        for line_text in text.splitlines():
            if not self._agent_words.search(line_text) and "install" not in line_text.lower():
                continue
            if _piped_install(line_text, self._agent_words):
                out.append("An agent CLI is installed by piping a downloaded script into a shell, which installs "
                           "whatever version the script fetches" + where)
            elif any(rx.search(line_text) for rx in self.install_urls):
                out.append("An agent CLI is installed by a downloaded install script, which installs whatever "
                           "version the script chooses" + where)
            for pkg, rx in self.packages:
                if pkg not in line_text:
                    continue
                for m in rx.finditer(line_text):
                    before = line_text[: m.start()]
                    installers = list(INSTALLER.finditer(before))
                    if not installers:
                        continue
                    between = before[installers[-1].end():]
                    if _NOT_INSTALL.search(between):
                        continue
                    ver = m.group("ver") or ""
                    if _UPDATE.search(between):
                        out.append(f"Agent CLI {pkg} is updated to the newest version" + where)
                        continue
                    if not _exact_version(ver):
                        shown = f" ({ver})" if ver else ""
                        reason = " at a version set at run time" if "$" in ver else " without a fixed version"
                        out.append(f"Agent CLI {pkg} is installed{reason}{shown}" + where)
            if _AGENT_SELF_UPDATE.search(line_text):
                out.append("An agent CLI updates itself to the newest version (claude update)" + where)
        return out

    def mutable_references(self) -> None:
        def severity_for(infos: list[Info]) -> str:
            if any(i.ai or i.publish for i in infos):
                return "high"
            if any(i.ctx.creds for i in infos):
                return "medium"
            return "low"

        for agent, ctx in self.p.agents:
            under = self.under(agent)
            severity = severity_for(under)
            where = f"for stage '{stage_label(ctx.stage)}'"
            if agent.image and not agent.from_step:      # step images are checked with the step below
                self._image(agent.image, agent.line, ctx.stage, where, severity)
            for img, line in agent.images:
                self._image(img, line, ctx.stage, where, severity)
            if agent.images_unknown:
                self.applicable.add("OBAAF-JEN-008")
                self.unknown("OBAAF-JEN-008", agent.line, "a pod template's containers are a list the checker "
                             "cannot read, so their images are not checked")
            if agent.kind == "dockerfile":
                self._dockerfile(agent.dockerfile or "Dockerfile", agent.line, ctx.stage, severity)
            pod = self.pod_spec(agent, "OBAAF-JEN-008") if agent.kind == "kubernetes" else None
            if pod:
                images = self._pod_images(pod)
                if images is None:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", agent.line, "the pod spec is not YAML the checker can read, so its "
                                 "images are not checked")
                else:
                    for img in images:
                        self._image(img if img is not None else "?", agent.line, ctx.stage, where, severity)
        for info in self.infos:
            name = info.use.name
            users = self.by_stage.get(info.ctx.stage, [])
            where = f"in stage '{stage_label(info.ctx.stage)}'"
            if name in ("docker.image", "withDockerContainer"):
                call = info.use.call
                node = first_arg(call) if name == "docker.image" else (named_arg(call, "image") or first_arg(call))
                if node is None:
                    continue
                ref = literal(node)
                if ref is None:
                    ref = node.text() if isinstance(node, Str) else (
                        "${" + path_of(node) + "}" if path_of(node) else "${computed}")
                self._image(ref, info.line, info.ctx.stage, where, severity_for(users))
            elif name == "docker.build":
                call = info.use.call
                options = call.args[1] if len(call.args) > 1 else None
                text = literal(options) if options is not None else "."
                if text is None:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", info.line, "docker.build's options are computed at run time, so "
                                 "the Dockerfile it builds is not checked")
                    continue
                self._dockerfile(_build_dockerfile(text), info.line, info.ctx.stage, severity_for(users))
        for lib in self.p.libraries:
            name, version = lib.name, lib.version
            if lib.name == "?" or lib.dynamic:
                # A library named by a value: put in what the file fixes (flagship slice 2d.2k).
                text = None
                if lib.name == "?" and lib.ref:
                    base = lib.ref[4:] if lib.ref.startswith("env.") else lib.ref
                    text = self._resolve("${" + base + "}")
                elif lib.dynamic:
                    text = self._resolve(lib.name + (f"@{lib.version}" if lib.version else ""))
                if text is None or "$" in text:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", lib.line, f"{lib.how} names a library or version computed at run "
                                 "time, so its pin is not checked")
                    continue
                name, _, version = text.partition("@")
                version = version or None
            self.applicable.add("OBAAF-JEN-008")
            # A library's code runs in every stage: high when any of them runs an agent or publishes.
            severity = "high" if any(i.ai or i.publish for i in self.infos) else "medium"
            if version is None:
                self.add("OBAAF-JEN-008", lib.line,
                         f"Library '{name}' is loaded at its default version, which an administrator can change "
                         "and which may follow a branch.", None, severity=severity)
            elif not FULL_SHA.match(version):
                self.add("OBAAF-JEN-008", lib.line,
                         f"Library '{name}' is loaded at '{version}', a branch or tag that can move.", None,
                         severity=severity)
        lockfiles = None
        scanned: set = set()
        for info in self.infos:
            # A method of the file expanded at many calls records its steps once per call; each step's
            # script is scanned once, as the signing scan is (flagship slice 2d.2i, B097).
            if not info.shell or id(info.use.call) in scanned:
                continue
            scanned.add(id(info.use.call))
            text = self._resolve(self.script_text(info))
            problems = self._install_problems(text)
            for rel in self._scripts(info.script):
                body = self._read(rel)
                if body:
                    problems += self._install_problems(body, f" (in the script {rel})")
            for m in _PIP_REQUIREMENTS.finditer(text):
                rel = m.group(2)
                body = self._read(rel) if "$" not in rel else None
                if body is None:
                    if self._agent_words.search(rel) or "$" in rel:
                        self.unknown("OBAAF-JEN-008", info.line, f"the requirements file {rel} is not read")
                    continue
                for req in body.splitlines():
                    problems += self._install_problems("pip install " + req.split("#", 1)[0],
                                                       f" (in the requirements file {rel})")
            if _NPM_INSTALL.search(text):
                if lockfiles is None:
                    lockfiles = any(self._read(x) is not None for x in LOCKFILES)
                if not lockfiles:
                    problems += self._package_json_problems()
            for image, command in self._shell_images(text):
                where = f"in a `{command}` command in stage '{stage_label(info.ctx.stage)}'"
                if image is None:
                    self.applicable.add("OBAAF-JEN-008")
                    self.unknown("OBAAF-JEN-008", info.line, f"a `{command}` command in stage "
                                 f"'{stage_label(info.ctx.stage)}' names its image in a way the checker cannot read")
                else:
                    self._image(image, info.line, info.ctx.stage, where,
                                severity_for(self.by_stage.get(info.ctx.stage, [])))
            for message in dict.fromkeys(problems):
                self.applicable.add("OBAAF-JEN-008")
                self.add("OBAAF-JEN-008", info.line, message + ".", info.ctx.stage, severity="high")

    def _package_json_problems(self) -> list:
        """Agent CLIs that package.json asks for at a version that can move, when no lockfile fixes them."""
        text = self._read("package.json")
        if text is None:
            return []
        try:
            data = json.loads(text)
        except ValueError:
            return ["An agent CLI may be installed from a package.json the checker cannot read"] \
                if self._agent_words.search(text) else []
        out = []
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(key) if isinstance(data, dict) else None
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                if pkg in self.agent_package_names and not (isinstance(ver, str) and EXACT_NPM.match(ver)):
                    out.append(f"Agent CLI {pkg} is installed from package.json at {ver!r}, a version that can move, "
                               "with no lockfile")
        return out

    # ------------------------------------------------------------------ JEN-009
    def injection(self) -> None:
        for info in self.infos:
            name = info.use.name
            if info.shell:
                self.applicable.add("OBAAF-JEN-009")
                source = untrusted_source(info.exprs, self.p)
                if source:
                    self.add("OBAAF-JEN-009", info.line,
                             f"The {name} step in stage '{stage_label(info.ctx.stage)}' builds its script with Groovy "
                             f"interpolation of {source[0]}. The value becomes part of the command before the shell "
                             "runs, so it can run commands of its own.", info.ctx.stage, severity=source[1])
                elif any(e.split(".")[0] in self.p.method_params for e in info.exprs if e):
                    # A method nothing in this file calls: its callers, and what they pass, are elsewhere.
                    self.unknown("OBAAF-JEN-009", info.line,
                                 f"the {name} step at line {info.line} uses a value passed in by a method's caller "
                                 "outside this file")
            elif name in ("load", "evaluate"):
                arg = first_arg(info.use.call)
                source = untrusted_source(source_texts(arg), self.p) if arg is not None else None
                if source:
                    self.add("OBAAF-JEN-009", info.line,
                             f"{name} at line {info.line} takes Groovy {('code' if name == 'evaluate' else 'from a path')} "
                             f"built from {source[0]}.", info.ctx.stage, severity="high")
            elif info.trigger:
                self.applicable.add("OBAAF-JEN-009")
                params = named_arg(info.use.call, "parameters")
                exprs = []
                for item in (params.items if isinstance(params, ListLit) else []):
                    # Booleans and choices cannot carry commands; string, text and run parameters can.
                    if isinstance(item, Call) and chain_name(item.callee) in ("booleanParam", "choice"):
                        continue
                    for st in _strings(item):
                        exprs += st.exprs
                    for node in _values(item):
                        p = path_of(node)
                        if p:
                            exprs.append(p)
                source = untrusted_source(exprs, self.p)
                if source and source[1] != "low":
                    job = f"Job '{info.trigger}'" if info.trigger != "a computed job name" else "A job with a computed name"
                    self.add("OBAAF-JEN-009", info.line,
                             f"{job} is started with a parameter taken from {source[0]}. Check that the job treats it "
                             "as data, never as part of a command.", info.ctx.stage, severity="medium")

    # ------------------------------------------------------------------ JEN-010
    def artifact_transfer(self) -> None:
        if not any(i.publish for i in self.infos):
            return
        for info in self.infos:
            if info.use.name != "copyArtifacts":
                continue
            self.applicable.add("OBAAF-JEN-010")
            call = info.use.call
            selector = named_arg(call, "selector")
            sel = chain_name(selector.callee) if isinstance(selector, Call) else None
            mutable = selector is None or sel in MUTABLE_SELECTORS
            if not mutable:
                if sel not in ("specific", "upstream"):
                    self.unknown("OBAAF-JEN-010", info.line, f"copyArtifacts selector {sel or 'computed'} not understood")
                continue
            later = [i for i in self.by_stage.get(info.ctx.stage, []) if i.index > info.index]
            if any(i.shell and CHECKSUM_VERIFY.search(i.script) for i in later):
                continue
            project = literal(named_arg(call, "projectName")) or "another job"
            same = self.stage_publishes(info.ctx.stage)
            self.add("OBAAF-JEN-010", info.line,
                     f"Stage '{stage_label(info.ctx.stage)}' copies artifacts from {project} by "
                     f"{'the default selector (last successful build)' if selector is None else sel + '()'}, "
                     "a reference that moves, and does not check their digests before "
                     + ("publishing them in the same stage." if same else "the pipeline publishes."),
                     info.ctx.stage, severity="high" if same else "medium")

    # ------------------------------------------------------------------ JEN-011
    def failure_paths(self) -> None:
        publishes = [i for i in self.infos if i.publish]
        if not publishes:
            return
        self.applicable.add("OBAAF-JEN-011")
        for info in publishes:
            if info.ctx.post in FAILURE_PATHS:
                where = "a catch or finally block" if info.ctx.post == "catch/finally" else \
                    f"post {{ {info.ctx.post} }}"
                self.add("OBAAF-JEN-011", info.line,
                         f"The step at line {info.line} publishes ({info.publish}) in {where}, which runs when the "
                         "build failed, was aborted or is unstable, so it can publish after a check failed or was "
                         "skipped.", info.ctx.stage, severity="high")
        checks = [i for i in self.infos if i.verify or (i.shell and CHECKSUM_VERIFY.search(i.script))]
        for check in checks:
            if check.ctx.post in FAILURE_PATHS:
                continue
            later = [p for p in publishes if p.index > check.index or concurrent(check.ctx, p.ctx)]
            target = next((p for p in later if not self.gates(check, p)), None)
            if target is None:
                continue
            if check.swallowed:
                why = f"its failure is ignored ({check.swallowed})"
            elif concurrent(check.ctx, target.ctx):
                why = "it runs in a parallel branch beside the publish, not before it"
            else:
                extra = [g for g in check.ctx.guards if g not in target.ctx.guards]
                why = (f"it runs only when a condition holds ({extra[0][:80]}) that does not also guard the publish, "
                       "so it can be skipped" if extra else "it does not run before the publish")
            self.add("OBAAF-JEN-011", check.line,
                     f"The check at line {check.line} cannot stop the publish at line {target.line}: {why}.",
                     check.ctx.stage, severity="high")

    # ------------------------------------------------------------------ JEN-012
    def provenance_check(self) -> None:
        publishes = [i for i in self.infos if i.publish]
        if not publishes:
            return
        self.applicable.add("OBAAF-JEN-012")
        checks = [i for i in self.infos if i.verify in ("full", "provenance")]
        unchecked = []
        for publish in publishes:
            found = {c.verify for c in checks if self.gates(c, publish)}
            if "full" not in found:
                unchecked.append((publish, found))
        if not unchecked:
            return
        # One finding for the file, on the worst step: a step that publishes with no check at all
        # before one that has a provenance check only. Taking the first in the file let an earlier,
        # better checked step stand in for a later one that nothing checks, at a lower severity.
        first, kinds = next((pair for pair in unchecked if "provenance" not in pair[1]), unchecked[0])
        if "provenance" in kinds:
            self.add("OBAAF-JEN-012", first.line,
                     f"The step at line {first.line} publishes after a provenance check only; approvals and agent "
                     "records are not checked (use obaaf verify release).", first.ctx.stage, severity="medium")
        else:
            self.add("OBAAF-JEN-012", first.line,
                     f"The step at line {first.line} publishes ({first.publish}) without an earlier check that stops "
                     "the build when verification fails.", first.ctx.stage)

    # ------------------------------------------------------------------ JEN-013
    def secret_names(self, variables: set) -> set:
        """The secret's variables and every variable of this file whose assigned values read one of them,
        transitively: `def t = TOKEN`, `def cmd = "curl ${TOKEN}"`, a method parameter given TOKEN,
        withEnv(["T2=${TOKEN}"]) (flagship slice 2d.2i)."""
        names = set(variables)
        changed = True
        while changed:
            changed = False
            for name, refs in self.p.refs.items():
                if name not in names and refs & names:
                    names.add(name)
                    changed = True
        return names

    def secret_interpolation(self) -> None:
        if any(info.ctx.creds for info in self.infos):
            self.applicable.add("OBAAF-JEN-013")
        for info in self.infos:
            if not info.ctx.creds:
                continue
            exprs = info.exprs
            if not info.shell:
                # The arguments of docker.image(...).inside/withRun/run and withDockerContainer become the
                # `docker run` command line (flagship slice 2d.2i).
                name = info.use.name
                if not (name.endswith((".inside", ".withRun", ".run")) and name.startswith("docker.") or
                        name == "withDockerContainer"):
                    continue
                exprs = [e for a in list(info.use.call.args) + [v for _, v in info.use.call.named]
                         for e in source_texts(a)]
            variables = {v for b in info.ctx.creds for v in b.variables if v not in b.paths and v != "?"}
            secrets = self.secret_names(variables)
            used = sorted({w for e in exprs for w in re.findall(r"[A-Za-z_]\w*", e) if w in secrets})
            envs = {"env"} | {n for n, refs in self.p.refs.items() if refs == {"env"}}
            computed_env = re.compile(
                r"\b(" + "|".join(sorted(map(re.escape, envs))) + r")\s*(\[\s*[^'\"\s\]]|\.\s*[\"']|"
                r"\.\s*(getProperty|getAt|get)\s*\(\s*[^'\"\s)])|\bSystem\s*\.\s*getenv\s*\(\s*[^'\"\s)]|"
                r"(^|[^.\w])(getProperty|getVariable)\s*\(\s*[^'\"\s)]|\bbinding\s*\.\s*(getVariable|getProperty)\s*\("
                r"\s*[^'\"\s)]")
            if not used and any(computed_env.search(e) for e in exprs):
                self.unknown("OBAAF-JEN-013", info.line,
                             f"the {info.use.name} step at line {info.line} interpolates an environment variable whose "
                             "name is computed, inside a credential binding; the checker cannot tell whether it is the "
                             "secret")
                continue
            # A name of this file whose value the checker never saw (a closure's parameter, `it`, a name a
            # destructuring assignment sets) may be the secret (the review of slice 2d.2i).
            # The first name of each path a step interpolates, when it starts with a lower-case letter (upper-case
            # names are environment variables), is not one of Jenkins's globals, and the file never gave it a
            # value the checker saw; and any name whose value reads an environment variable by a computed name.
            computed = self.secret_names({COMPUTED_ENV}) - {COMPUTED_ENV}
            unaccounted = sorted({w for e in exprs for w in _NAME_IN_EXPR.findall(_unquoted(e))
                                  if (w in computed) or (w[:1].islower() and w not in _JENKINS_GLOBALS
                                                         and w not in self.p.refs and w not in self.p.literals
                                                         and w not in self.p.lists)})
            if not used and unaccounted:
                self.unknown("OBAAF-JEN-013", info.line,
                             f"the {info.use.name} step at line {info.line} interpolates {', '.join(unaccounted[:3])} "
                             "inside a credential binding, and the checker cannot tell what it holds")
                continue
            if not used and any(b.variables == () or "?" in b.variables for b in info.ctx.creds) and exprs:
                self.unknown("OBAAF-JEN-013", info.line,
                             f"the {info.use.name} step at line {info.line} interpolates values inside a credential "
                             "binding whose variables the Jenkinsfile does not name; the checker cannot tell whether "
                             "one of them is the secret")
                continue
            if used:
                where = "script" if info.shell else "arguments"
                fix = ("Reference it as a shell variable inside single quotes." if info.shell else
                       "Pass it as `-e NAME` with no value, so docker takes it from the environment.")
                self.add("OBAAF-JEN-013", info.line,
                         f"The {info.use.name} step at line {info.line} puts secret variable(s) {', '.join(used)} into "
                         f"its {where} with Groovy interpolation, so the secret appears in the command line, where "
                         f"other processes on the agent can read it. {fix}",
                         info.ctx.stage)

    # ------------------------------------------------------------------ JEN-014
    def publishes_near(self, stage: tuple) -> bool:
        """The stage, or the stage a `post` block belongs to, publishes (flagship slice 2d.2i: a publish
        in `post { success { } }` did not make a signing finding high)."""
        base = base_stage(stage)
        return any(base_stage(s) == base and self.stage_publishes(s) for s in self.stages())

    def script_text(self, info: Info) -> str:
        """The script as the shell reads it: backslash-continued lines joined, and `${name}` placeholders
        for variables of this file that hold a literal replaced by it (flagship slice 2d.2i)."""
        cached = self._script_texts.get(id(info.use.call))
        if cached is not None and cached[0] is info.use.call:
            return cached[1]
        text = info.script
        for _ in range(3):
            changed = re.sub(r"\$\{([A-Za-z_]\w*)\}", lambda m: (
                self.p.literals[m.group(1)].text() if m.group(1) in self.p.literals else m.group(0)), text)
            if changed == text:
                break
            text = changed
        # A line continued with `\` (shell), `^` (cmd) or a backtick (PowerShell) is one line.
        text = re.sub(r"[\\^`]\r?\n[ \t]*", " ", text)
        self._script_texts[id(info.use.call)] = (info.use.call, text)
        return text

    def signing_keys(self) -> None:
        patterns = [re.compile(x, re.I) for x in self.detection.get("signing_secret_patterns", [])]
        commands = [re.compile(x, re.M) for x in self.detection.get("signing_commands", [])]
        scopes = self.bindings()
        if scopes or any(i.shell for i in self.infos):
            self.applicable.add("OBAAF-JEN-014")
        for b, infos in scopes.items():
            names = [n for n in list(b.ids) + list(b.variables) if n != "?"]
            hits = [n for n in names if any(p.search(re.sub(r"[-.]", "_", n)) for p in patterns)]
            # A certificate binding is a PKCS#12 keystore: signing material whatever it is called.
            if b.how.endswith((":certificate", ":CertificateMultiBinding")):
                hits.append(f"certificate binding {self.ids(b)}")
            if hits:
                stage = infos[0].ctx.stage if infos else ()
                severity = "high" if any(self.publishes_near(i.ctx.stage) for i in infos) else "medium"
                self.add("OBAAF-JEN-014", b.line,
                         f"Signing material ({', '.join(sorted(set(hits)))}) is bound by {b.how} for the steps of "
                         f"stage '{stage_label(stage)}', so any build step there can read the key.", stage,
                         severity=severity)
        loads: dict[int, tuple] = {}
        for info in self.infos:
            if not info.shell:
                continue
            hit = loads.get(id(info.use.call))
            if hit is None or hit[0] is not info.use.call:
                # Once per call, however many times the method holding it is expanded.
                hit = (info.use.call, any(rx.search(self.script_text(info)) for rx in commands))
                loads[id(info.use.call)] = hit
            if hit[1]:
                severity = "high" if self.publishes_near(info.ctx.stage) else "medium"
                self.add("OBAAF-JEN-014", info.line,
                         f"The step at line {info.line} loads a signing key into the build environment.",
                         info.ctx.stage, severity=severity)


    # ------------------------------------------------------------------ JEN-015
    def resolve_text(self, node, depth: int = 0) -> str | None:
        """The text of an expression built only from literals written in this file: a string, a variable
        whose last assignment is one, `+` of those, `.trim()` and similar; None otherwise."""
        if node is None or depth > 20:
            return None
        if isinstance(node, Str):
            if not node.interpolated:
                return node.text()
            parts = []
            for kind, value in node.tok.parts:
                if kind == "lit":
                    parts.append(value)
                else:
                    inner = self.p.literals.get(value.strip().removeprefix("env.")) if \
                        re.fullmatch(r"\s*(env\.)?[A-Za-z_]\w*\s*", value) else None
                    text = self.resolve_text(inner, depth + 1) if inner is not None else None
                    if text is None:
                        return None
                    parts.append(text)
            return "".join(parts)
        if isinstance(node, Binary) and node.op == "+":
            left, right = self.resolve_text(node.left, depth + 1), self.resolve_text(node.right, depth + 1)
            return None if left is None or right is None else left + right
        if isinstance(node, Call) and isinstance(node.callee, Prop) and not node.args and \
                node.callee.name in ("trim", "toString", "stripIndent"):
            text = self.resolve_text(node.callee.target, depth + 1)
            return text.strip() if text is not None and node.callee.name == "trim" else text
        p = path_of(node)
        if p:
            name = p.removeprefix("env.")
            value = self.p.literals.get(name)
            if value is None:
                env = self.p.env_values.get(name)
                value = env if env is not None else None
            return self.resolve_text(value, depth + 1) if value is not None else None
        return None

    def webhook_tokens(self) -> None:
        for trig in self.p.triggers:
            self.applicable.add("OBAAF-JEN-015")
            token = trig.token
            if not token and trig.token_node is not None:
                # A token built from literals in this file is written in the file (flagship slice 2d.2i).
                token = self.resolve_text(trig.token_node)
                if token is None:
                    self.unknown("OBAAF-JEN-015", trig.line,
                                 f"{trig.name}'s {trig.token_key} is computed; the checker cannot tell whether it is "
                                 "written in the repository")
                    continue
            if not token:
                continue
            privileged = any(i.ctx.creds or i.publish or i.ai for i in self.infos)
            hint = token[:3] + "..." if len(token) > 6 else "..."
            self.add("OBAAF-JEN-015", trig.line,
                     f"{trig.name} at line {trig.line} has its webhook token written in the Jenkinsfile ('{hint}'), "
                     "so anyone who can read the file can start the job and choose every webhook value it reads. "
                     "The Generic Webhook Trigger plugin runs token-started builds as SYSTEM."
                     + (" The pipeline holds credentials, publishes or runs an AI agent." if privileged else ""),
                     None, severity="high" if privileged else "medium")


def _truthy(node) -> bool:
    if node is None:
        return False
    p = path_of(node)
    return p == "true" or (isinstance(node, Str) and node.text().strip().lower() == "true")


def _strings(node):
    from obaaf.checker.jenkins.model import all_strings
    if node is None:
        return []
    return list(all_strings(node))


def _values(node):
    """Leaf argument values in a parameters list: string(name: 'x', value: env.CHANGE_TITLE)."""
    out = []
    if isinstance(node, ListLit):
        for item in node.items:
            out += _values(item)
    elif isinstance(node, Call):
        for _, value in node.named:
            out.append(value)
        out += list(node.args)
    return out
