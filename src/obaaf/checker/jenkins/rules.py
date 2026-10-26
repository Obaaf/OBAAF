"""Advisory rules for Jenkinsfiles (OBAAF-JEN-*). Metadata lives in data/rules.yaml.

The rules read only the Jenkinsfile and files it names in the repository. Jenkins decides much
of what matters on the controller: security realm and authorization, build authorization
(builds run as SYSTEM unless configured), which agents carry executors, library trust and
version overrides, Replay permission, script approval, credential scopes, and network policy.
None of that is in the file, so the rules report it as coverage unknowns rather than passing
it. A finding describes what the file shows; an unknown says what the file cannot show.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from obaaf.catalog import Catalog
from obaaf.checker.jenkins import steps as known
from obaaf.checker.jenkins.model import (
    CONTROLLER_LABELS, CR_NO, CR_POSSIBLE, CR_UNKNOWN, CR_YES, SHELL_STEPS, Binding, Pipeline, StepUse,
    chain_name, first_arg, literal, named_arg, shell_script, untrusted_source,
)
from obaaf.checker.jenkins.parser import Binary, Call, ListLit, Prop, Str, path_of
from obaaf.checker.rules import Finding

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
GIT_PUSH = re.compile(r"(^|[\s;&|(])git\s+push\b|(^|[\s;&|(])gh\s+pr\s+merge\b", re.M)
CHECKSUM_VERIFY = re.compile(r"(^|[\s;&|(])(sha256sum|sha512sum|shasum)\b[^\n]*\s(-c|--check)\b"
                             r"|(^|[\s;&|(])cosign\s+verify|(^|[\s;&|(])obaaf\s+verify\b", re.M)
INSTALLER = re.compile(r"\b(npm|pnpm|yarn|bun|npx|bunx|pip3?|pipx|uv|uvx)\b")
AGENT_INSTALL_SCRIPT = re.compile(r"\bcurl\b[^\n|]*\b(claude|gemini|codex|opencode|aider|copilot)\b[^\n|]*\|\s*(ba|z)?sh\b",
                                  re.I)
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
    (re.compile(r"^\s*privileged:\s*true\b", re.M), "a privileged container"),
    (re.compile(r"^\s*allowPrivilegeEscalation:\s*true\b", re.M), "allowPrivilegeEscalation: true"),
    (re.compile(r"^\s*hostNetwork:\s*true\b", re.M), "host networking"),
    (re.compile(r"^\s*hostPID:\s*true\b", re.M), "the host PID namespace"),
    (re.compile(r"^\s*hostIPC:\s*true\b", re.M), "the host IPC namespace"),
    (re.compile(r"docker\.sock"), "a mount of the Docker socket"),
    (re.compile(r"^\s*-?\s*hostPath:", re.M), "a hostPath volume"),
    (re.compile(r"\b(SYS_ADMIN|SYS_PTRACE|NET_ADMIN)\b"), "extra capabilities"),
]
POD_IMAGE = re.compile(r"^\s*-?\s*image:\s*['\"]?([^'\"\s#]+)", re.M)


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


def stage_label(stage: tuple) -> str:
    return " > ".join(stage) if stage else "pipeline"


def script_parts(node) -> tuple[str, list, bool]:
    """(text, interpolated expressions, dynamic) of a script argument. Groovy concatenation
    (`"make " + env.X`) counts as interpolation. dynamic: some text comes from a variable or call."""
    if node is None:
        return "", [], True
    if isinstance(node, Str):
        return node.text(), list(node.exprs), False
    if isinstance(node, Binary) and node.op == "+":
        a, b = script_parts(node.left), script_parts(node.right)
        return a[0] + b[0], a[1] + b[1], a[2] or b[2]
    if isinstance(node, Call) and isinstance(node.callee, Prop) and not node.args:
        return script_parts(node.callee.target)     # """...""".stripIndent().trim()
    p = path_of(node)
    if p:
        return "${" + p + "}", [p], True
    return "", [], True


class JenkinsRules:
    def __init__(self, path: str, pipeline: Pipeline, catalog: Catalog, root: Path | None,
                 extra_agents: dict | None = None, lane_overrides: dict | None = None) -> None:
        self.path = path
        self.p = pipeline
        self.catalog = catalog
        self.detection = catalog.detection
        self.root = root
        extra_agents = extra_agents or {}
        self.agent_cmds = [re.compile(x, re.M) for x in
                           list(self.detection.get("agent_commands", [])) + list(extra_agents.get("commands") or [])]
        self.agent_steps = set(extra_agents.get("steps") or []) | set(self.detection.get("jenkins_agent_steps", []))
        self.upload_cmds = [re.compile(x, re.M) for x in list(self.detection.get("upload_commands", []))
                            + list(self.detection.get("jenkins_upload_commands", []))]
        self.upload_steps = set(self.detection.get("jenkins_upload_steps", []))
        self.lane_overrides = lane_overrides or {}
        self.findings: list[Finding] = []
        self.unknowns: list[Unknown] = []
        self.applicable: set[str] = set()
        self.infos: list[Info] = []

    # ------------------------------------------------------------------ plumbing
    def add(self, rule: str, line: int, message: str, stage: tuple | None = None, severity: str | None = None,
            step: str | None = None) -> None:
        self.findings.append(Finding(rule=rule, severity=severity or self.catalog.rules[rule]["severity"],
                                     path=self.path, line=line or 1, message=message,
                                     job=stage_label(stage) if stage is not None else None, step=step,
                                     scope="stage"))

    def unknown(self, rule: str, line: int, reason: str) -> None:
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
        for index, use in enumerate(self.p.steps):
            info = Info(use, index)
            call = use.call
            name = use.name
            if name in SHELL_STEPS:
                info.shell = True
                info.script, info.exprs, info.dynamic = script_parts(shell_script(call))
                if _truthy(named_arg(call, "returnStatus")):
                    info.swallowed = "returnStatus: true"
            if use.ctx.swallowed:
                info.swallowed = use.ctx.swallowed
            info.ai = self._ai(info)
            info.publish = self._publish(info)
            info.verify = self._verify(info)
            info.push = bool(info.shell and GIT_PUSH.search(info.script))
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
            lane = self.lane_of(info.ctx)
            if lane == "agent" and info.shell and not info.ai:
                info.ai = "the stage is declared an agent lane"
            if lane == "release" and info.shell and not info.publish:
                info.publish = "the stage is declared a release lane"

    def lane_of(self, ctx) -> str | None:
        label = stage_label(ctx.stage)
        override = self.lane_overrides.get(f"{self.path}#{label}") or (
            self.lane_overrides.get(f"{self.path}#{ctx.stage[-1]}") if ctx.stage else None)
        return override or ctx.lane

    def _ai(self, info: Info) -> str | None:
        if info.use.name in self.detection.get("jenkins_agent_steps", []):
            return f"the {info.use.name} step runs an agent"
        if info.use.name in self.agent_steps:
            return f"step {info.use.name} is declared an agent in the checker configuration"
        if not info.shell:
            return None
        for rx in self.agent_cmds:
            m = rx.search(info.script)
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
        if not info.shell or not info.script:
            return None
        text = info.script
        if re.search(r"(^|[\n;&])\s*set\s+\+e\b", text):
            return None
        kind = None
        for pattern in self.detection.get("verify_commands", []):
            for m in re.finditer(pattern, text, re.M):
                end = text.find("\n", m.end())
                rest = text[m.end(): None if end == -1 else end]
                if "||" in rest or re.search(r"(?<![&])&\s*$", rest):
                    info.swallowed = info.swallowed or "|| after the command"
                    continue
                if any(re.match(r, text[m.start():]) for r in self.detection.get("release_verify_commands", [])):
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
        try:
            root = self.root.resolve()
            path = (self.root / rel).resolve()
            if root not in path.parents or not path.is_file():
                return None
            with path.open(encoding="utf-8", errors="replace") as fh:
                return fh.read(200_000)
        except (OSError, RuntimeError):
            return None

    # ------------------------------------------------------------------ helpers
    def stages(self) -> dict:
        out: dict[tuple, list[Info]] = {}
        for info in self.infos:
            out.setdefault(info.ctx.stage, []).append(info)
        return out

    def stage_publishes(self, stage: tuple) -> bool:
        return any(i.publish for i in self.infos if i.ctx.stage == stage)

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
            under = [i for i in self.infos if i.ctx.agent is agent]
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
        for stage, infos in self.stages().items():
            ai = [i for i in infos if i.ai]
            if not ai:
                continue
            self.applicable.add("OBAAF-JEN-003")
            for info in infos:
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
            if lib.name == "?":
                self.unknown("OBAAF-JEN-004", lib.line, f"{lib.how} names a library computed at run time")
                continue
            if lib.dynamic:
                what = "a name" if "${" in lib.name else "a version"
                source = untrusted_source(list(lib.exprs), self.p)
                shown = lib.name + (f"@{lib.version}" if lib.version else "")
                if source:
                    self.add("OBAAF-JEN-004", lib.line,
                             f"Library '{shown}' is loaded with {what} taken from {source[0]}, so whoever sets that "
                             "value chooses the pipeline code that runs. A trusted global library runs outside the "
                             "Groovy sandbox.", None, severity="high")
                else:
                    self.add("OBAAF-JEN-004", lib.line,
                             f"Library '{shown}' is loaded with {what} computed at run time, so the reviewed "
                             "Jenkinsfile does not fix which code runs.", None, severity="medium")
        for info in self.infos:
            if info.use.name not in ("load", "evaluate"):
                continue
            arg = first_arg(info.use.call)
            if info.use.name == "evaluate":
                inner = chain_name(arg.callee) if isinstance(arg, Call) else None
                if inner == "readTrusted" or isinstance(arg, Str):
                    continue
            cr = info.ctx.cr
            what = (f"loads Groovy from the workspace ({literal(arg) or 'a computed path'})"
                    if info.use.name == "load" else "evaluates Groovy text read at run time")
            if cr in (CR_YES, CR_POSSIBLE):
                privileged = bool(info.ctx.creds) or self.stage_publishes(info.ctx.stage)
                self.add("OBAAF-JEN-004", info.line,
                         f"Stage '{stage_label(info.ctx.stage)}' {what}. For a change request the workspace holds the "
                         "change's own files, so its author controls this pipeline code even when Jenkins takes the "
                         "Jenkinsfile from a trusted branch" + (", and the code runs where credentials are bound."
                                                               if privileged else "."),
                         info.ctx.stage, severity="high" if privileged or cr == CR_YES else "medium")
            elif cr == CR_UNKNOWN:
                self.unknown("OBAAF-JEN-004", info.line,
                             f"{info.use.name} at line {info.line} runs under a condition the checker cannot evaluate")
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
            pod = agent.yaml
            if agent.yaml_file:
                pod = self._read(agent.yaml_file)
                if pod is None:
                    self.unknown("OBAAF-JEN-006", agent.line,
                                 f"pod definition {agent.yaml_file} is not in the repository checkout")
            under = [i for i in self.infos if i.ctx.agent is agent]
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
                self.unknown("OBAAF-JEN-006", agent.line,
                             f"pod template '{agent.inherit}' is defined on the controller, not in the repository")
            if not problems:
                continue
            risky = [i for i in under if i.ai or i.ctx.cr in (CR_YES, CR_POSSIBLE)]
            unique = list(dict.fromkeys(problems))
            self.add("OBAAF-JEN-006", agent.line,
                     f"The {agent.kind} agent for stage '{stage_label(ctx.stage)}' uses {', '.join(unique)}. Code in "
                     "the container can then reach the host and other builds on it"
                     + (", and change requests or an AI agent can steer that code." if risky else "."),
                     ctx.stage, severity="high" if risky or not under else "medium")

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
    def mutable_references(self) -> None:
        def severity_for(infos: list[Info]) -> str:
            if any(i.ai or i.publish for i in infos):
                return "high"
            if any(i.ctx.creds for i in infos):
                return "medium"
            return "low"

        for agent, ctx in self.p.agents:
            under = [i for i in self.infos if i.ctx.agent is agent]
            refs = []
            if agent.image:
                refs.append((agent.image, agent.line, agent.image_dynamic))
            refs += [(img, line, "${" in img) for img, line in agent.images]
            if agent.yaml:
                refs += [(m.group(1), agent.line, "${" in m.group(1)) for m in POD_IMAGE.finditer(agent.yaml)]
            for ref, line, dynamic in refs:
                self.applicable.add("OBAAF-JEN-008")
                if dynamic:
                    self.unknown("OBAAF-JEN-008", line, f"image reference {ref} is computed at run time")
                elif not DIGEST.search(ref):
                    self.add("OBAAF-JEN-008", line,
                             f"Image '{ref}' for stage '{stage_label(ctx.stage)}' is not pinned to a sha256 digest.",
                             ctx.stage, severity=severity_for(under))
        for info in self.infos:
            if info.use.name.startswith("docker.image") or info.use.name == "withDockerContainer":
                call = info.use.call
                node = first_arg(call) if info.use.name.startswith("docker.image") else (
                    named_arg(call, "image") or first_arg(call))
                ref = literal(node)
                if node is None:
                    continue
                self.applicable.add("OBAAF-JEN-008")
                if ref is None:
                    self.unknown("OBAAF-JEN-008", info.line, "an image reference is computed at run time")
                elif not DIGEST.search(ref):
                    users = [i for i in self.infos if i.ctx.stage == info.ctx.stage]
                    self.add("OBAAF-JEN-008", info.line,
                             f"Image '{ref}' in stage '{stage_label(info.ctx.stage)}' is not pinned to a sha256 digest.",
                             info.ctx.stage, severity=severity_for(users))
        for lib in self.p.libraries:
            if lib.name == "?" or lib.dynamic:
                continue
            self.applicable.add("OBAAF-JEN-008")
            if lib.version is None:
                self.add("OBAAF-JEN-008", lib.line,
                         f"Library '{lib.name}' is loaded at its default version, which an administrator can change "
                         "and which may follow a branch.", None, severity="medium")
            elif not FULL_SHA.match(lib.version):
                self.add("OBAAF-JEN-008", lib.line,
                         f"Library '{lib.name}' is loaded at '{lib.version}', a branch or tag that can move.", None,
                         severity="medium")
        packages = list(self.detection.get("agent_packages", []))
        for info in self.infos:
            if not info.shell:
                continue
            for line_text in info.script.splitlines():
                if AGENT_INSTALL_SCRIPT.search(line_text):
                    self.applicable.add("OBAAF-JEN-008")
                    self.add("OBAAF-JEN-008", info.line,
                             "An agent CLI is installed by piping a downloaded script into a shell, which installs "
                             "whatever version the script fetches.", info.ctx.stage, severity="high")
                    continue
                for pkg in packages:
                    for m in re.finditer(r"(?<![\w@/-])" + re.escape(pkg) + r"(?P<ver>(@|==|===)[^\s;&|'\"]+)?"
                                         r"(?=[\s;&|'\"]|$)", line_text):
                        if not INSTALLER.search(line_text[: m.start()]):
                            continue
                        self.applicable.add("OBAAF-JEN-008")
                        ver = (m.group("ver") or "").lstrip("@=")
                        if not ver or ver in ("latest", "next", "stable"):
                            self.add("OBAAF-JEN-008", info.line,
                                     f"Agent CLI {pkg} is installed without a fixed version"
                                     + (f" ({m.group('ver')})" if ver else "") + ".", info.ctx.stage, severity="high")

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
                elif info.dynamic and any(e.split(".")[0] in self.p.method_params for e in info.exprs):
                    self.unknown("OBAAF-JEN-009", info.line,
                                 f"the {name} step at line {info.line} runs a script passed in by a method's caller")
            elif name in ("load", "evaluate"):
                arg = first_arg(info.use.call)
                source = untrusted_source(list(arg.exprs) if isinstance(arg, Str) else (
                    [path_of(arg)] if path_of(arg) else []), self.p)
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
            later = [i for i in self.infos if i.index > info.index and i.ctx.stage == info.ctx.stage]
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
        first = publishes[0]
        swallowed = [i for i in self.infos if i.index < first.index and i.swallowed and (
            i.verify or (i.shell and CHECKSUM_VERIFY.search(i.script)))]
        for info in swallowed:
            self.add("OBAAF-JEN-011", info.line,
                     f"The check at line {info.line} cannot stop the publish at line {first.line}: its failure is "
                     f"ignored ({info.swallowed}).", info.ctx.stage, severity="high")

    # ------------------------------------------------------------------ JEN-012
    def provenance_check(self) -> None:
        publishes = [i for i in self.infos if i.publish]
        if not publishes:
            return
        self.applicable.add("OBAAF-JEN-012")
        first = publishes[0]
        kinds = {i.verify for i in self.infos
                 if i.index < first.index and i.verify and not i.swallowed and i.ctx.post not in FAILURE_PATHS}
        if "full" in kinds:
            return
        if "provenance" in kinds:
            self.add("OBAAF-JEN-012", first.line,
                     f"The step at line {first.line} publishes after a provenance check only; approvals and agent "
                     "records are not checked (use obaaf verify release).", first.ctx.stage, severity="medium")
        else:
            self.add("OBAAF-JEN-012", first.line,
                     f"The step at line {first.line} publishes ({first.publish}) without an earlier check that stops "
                     "the build when verification fails.", first.ctx.stage)

    # ------------------------------------------------------------------ JEN-013
    def secret_interpolation(self) -> None:
        if any(info.ctx.creds for info in self.infos):
            self.applicable.add("OBAAF-JEN-013")
        for info in self.infos:
            if not info.shell or not info.ctx.creds:
                continue
            variables = {v for b in info.ctx.creds for v in b.variables if v not in b.paths}
            used = sorted({w for e in info.exprs for w in re.findall(r"[A-Za-z_]\w*", e) if w in variables})
            if used:
                self.add("OBAAF-JEN-013", info.line,
                         f"The {info.use.name} step at line {info.line} puts secret variable(s) {', '.join(used)} into "
                         "its script with Groovy interpolation, so the secret appears in the command line, where other "
                         "processes on the agent can read it. Reference it as a shell variable inside single quotes.",
                         info.ctx.stage)

    # ------------------------------------------------------------------ JEN-014
    def signing_keys(self) -> None:
        patterns = [re.compile(x, re.I) for x in self.detection.get("signing_secret_patterns", [])]
        commands = [re.compile(x, re.M) for x in self.detection.get("signing_commands", [])]
        scopes = self.bindings()
        if scopes or any(i.shell for i in self.infos):
            self.applicable.add("OBAAF-JEN-014")
        for b, infos in scopes.items():
            names = [n for n in list(b.ids) + list(b.variables) if n != "?"]
            hits = [n for n in names if any(p.search(re.sub(r"[-.]", "_", n)) for p in patterns)]
            if hits:
                stage = infos[0].ctx.stage if infos else ()
                severity = "high" if any(self.stage_publishes(i.ctx.stage) for i in infos) else "medium"
                self.add("OBAAF-JEN-014", b.line,
                         f"Signing material ({', '.join(sorted(set(hits)))}) is bound by {b.how} for the steps of "
                         f"stage '{stage_label(stage)}', so any build step there can read the key.", stage,
                         severity=severity)
        for info in self.infos:
            if info.shell and any(rx.search(info.script) for rx in commands):
                severity = "high" if self.stage_publishes(info.ctx.stage) else "medium"
                self.add("OBAAF-JEN-014", info.line,
                         f"The step at line {info.line} loads a signing key into the build environment.",
                         info.ctx.stage, severity=severity)


    # ------------------------------------------------------------------ JEN-015
    def webhook_tokens(self) -> None:
        for trig in self.p.triggers:
            self.applicable.add("OBAAF-JEN-015")
            if not trig.token:
                continue
            privileged = any(i.ctx.creds or i.publish or i.ai for i in self.infos)
            hint = trig.token[:3] + "..." if len(trig.token) > 6 else "..."
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
