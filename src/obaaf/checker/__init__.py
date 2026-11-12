"""The OBAAF pipeline checker (`obaaf check`, FR12).

It reads GitHub Actions workflow files and repository settings that live in
files (CODEOWNERS, agent instruction files) and reports risky settings, each
with the profile requirement it threatens and the fix. It runs locally and
sends nothing over the network (NFR5).
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from obaaf import yamlutil
from obaaf.catalog import Catalog, load
from obaaf.checker import expr as expr_mod
from obaaf.checker import jenkins as jenkins_mod
from obaaf.checker import repo as repo_checks
from obaaf.checker import rules as rules_mod
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import Finding

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
CONFIG_LOCATIONS = (".github/obaaf.yml", ".github/obaaf.yaml", "obaaf.yml")
# Words in a job id or name that suggest it runs an AI agent, used only to warn
# when such a job is not in the agent lane (never to classify it).
_AGENT_HINT = re.compile(r"agent|copilot|claude|gemini|codex|aider|opencode|cline|\bllm\b|\bai[-_ ]|autofix|auto[- ]fix",
                         re.I)


def parse_fail_on(spec: str) -> tuple[str | None, str]:
    """Parse a --fail-on value into (category, severity).

    Accepts 'never'; a bare severity ('high', 'medium' or 'low'); a category
    ('authority' or 'hygiene'), meaning that category at 'low' and above; or
    '<category>:<severity>'. Raises ValueError on anything else.
    """
    spec = str(spec).strip()
    if spec == "never":
        return (None, "never")
    if ":" in spec:
        cat, _, sev = spec.partition(":")
    elif spec in ("authority", "hygiene"):
        cat, sev = spec, "low"
    else:
        cat, sev = "", spec
    cat = cat or None
    if cat is not None and cat not in ("authority", "hygiene"):
        raise ValueError(f"--fail-on category must be 'authority' or 'hygiene', not {cat!r}")
    if sev not in ("high", "medium", "low"):
        raise ValueError(f"--fail-on must be high, medium, low, never, or <category>:<severity>, not {spec!r}")
    return (cat, sev)


_SCRIPT_REF = re.compile(r"(?<![\w./-])((?:\./)?[\w./-]+\.(?:sh|bash))\b")


def _script_targets(run_text: str) -> list[str]:
    """Script file paths a run step invokes (best-effort; paths with variables are skipped)."""
    out: list[str] = []
    for m in _SCRIPT_REF.finditer(run_text or ""):
        tok = m.group(1)
        if tok.startswith("./"):
            tok = tok[2:]
        if tok and tok not in out:
            out.append(tok)
    return out


def _copied_script_targets(run_text: str, root: Path) -> list[str]:
    """Map simple cp snapshots back to repository sources, without reading the destination.

    Variable names are symbolic: ${SNAPSHOT}/a and $SNAPSHOT/a name the same
    destination. No shell commands, substitutions or workflow expressions execute.
    Copy aliases are scoped to one run step; computed sources are not followed.
    """
    aliases: dict[str, Path] = {}
    targets: list[str] = []
    root = root.resolve()

    def normalize(value: str) -> str:
        return re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}', r'$\1', value).rstrip('/')

    def source(value: str) -> Path | None:
        value = normalize(value)
        candidates = [path / value[len(alias):].lstrip('/') for alias, path in aliases.items()
                      if value == alias or value.startswith(alias + '/')]
        if '$' not in value:
            candidates.append(root / value)
        for path in candidates:
            try:
                path = path.resolve()
                if root in path.parents and path.exists():
                    return path
            except (OSError, RuntimeError):
                continue
        return None

    for line in run_text.splitlines():
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=';&|')
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:
            continue
        commands: list[list[str]] = [[]]
        for token in tokens:
            if token in (';', '&&', '||', '&', '|'):
                commands.append([])
            else:
                commands[-1].append(token)
        for command in commands:
            if not command:
                continue
            if command[0] == 'cp':
                args = [arg for arg in command[1:] if not arg.startswith('-')]
                if len(args) == 2:
                    original = source(args[0])
                    destination = normalize(args[1])
                    if original and destination:
                        aliases[destination] = original
                        # cp into an existing directory nests the source basename.
                        aliases[destination + '/' + original.name] = original
                continue
            if command[0] not in ('bash', 'sh', 'source', '.', 'exec', 'timeout', 'env') \
                    and not command[0].endswith(('.sh', '.bash')):
                continue
            for token in command:
                if token.endswith(('.sh', '.bash')):
                    original = source(token)
                    if original and original.is_file():
                        targets.append(original.relative_to(root).as_posix())
    return targets


def _agent_via_script(job, root: Path, commands: list) -> str | None:
    """A job whose run step calls a repository script that itself invokes an agent CLI is an agent
    job, whatever else it is (companion R1-R4). Only scripts readable under `root` are inspected, so this
    is best-effort; what it cannot read (fetched or generated scripts) is covered by the lane note."""
    if not commands:
        return None
    root_r = root.resolve()
    for step in job.steps:
        for tok in _script_targets(step.run) + _copied_script_targets(step.run, root_r):
            try:
                path = (root / tok).resolve()
                if path != root_r and root_r not in path.parents:
                    continue
                if not path.is_file():
                    continue
                with path.open(encoding="utf-8", errors="replace") as script:
                    text = script.read(200_000)
            except (OSError, RuntimeError):
                continue
            if any(rx.search(text) for rx in commands):
                return f"runs an agent in the script {tok}"
    return None


def _script_commands(catalog: "Catalog", config: "Config") -> list:
    patterns = list(catalog.detection.get("agent_commands", [])) + list(config.agents.get("commands", ()) or ())
    return [re.compile(p, re.M) for p in patterns]


def _apply_script_detection(workflow, root: Path, commands: list) -> None:
    for job in workflow.jobs.values():
        if not job.in_lane("agent"):
            reason = _agent_via_script(job, root, commands)
            if reason:
                job.add_lane("agent", reason)


class ConfigError(ValueError):
    pass


_SECRET_NAME = re.compile(r"^[A-Za-z_*?][A-Za-z0-9_*?]*$")
CONFIG_KEYS = frozenset({"lanes", "agents", "ignore", "jenkins", "protected_secrets"})


def parse_protected_secrets(value, path) -> dict:
    """protected_secrets: a list of secret names (any declared environment will do), or a mapping of
    secret name to the environment that must hold it. Names may use * and ? globs; secret names are
    case-insensitive in GitHub, so they are compared in upper case."""
    if value is None:
        return {}
    if isinstance(value, list):
        pairs = [(name, None) for name in value]
    elif isinstance(value, dict):
        pairs = list(value.items())
    else:
        raise ConfigError(f"{path}: protected_secrets must be a list of secret names or a mapping of secret "
                          "name to environment")
    out: dict = {}
    for name, env in pairs:
        if not isinstance(name, str) or not _SECRET_NAME.match(name):
            raise ConfigError(f"{path}: protected_secrets entry {name!r} is not a secret name (letters, digits, "
                              "underscores, and * or ? globs)")
        if len(re.sub(r"[*?_]", "", name)) < 3:
            raise ConfigError(f"{path}: protected_secrets entry {name!r} is too broad; name at least three letters "
                              "or digits (for example *_API_KEY)")
        if name.upper() == "GITHUB_TOKEN":
            raise ConfigError(f"{path}: GITHUB_TOKEN is not a stored secret; protected_secrets cannot list it")
        if env is not None and (not isinstance(env, str) or not env.strip() or "${{" in env):
            raise ConfigError(f"{path}: protected_secrets environment for {name!r} must be a literal "
                              "environment name")
        out[name.upper()] = env.strip() if isinstance(env, str) else None
    return out


@dataclass
class Config:
    lanes: dict = field(default_factory=dict)
    agents: dict = field(default_factory=dict)
    ignore: list = field(default_factory=list)
    path: str | None = None
    jenkins: dict = field(default_factory=dict)
    # Secret name (upper case, glob allowed) -> the environment that must hold it, or None for any
    # declared environment.
    protected_secrets: dict = field(default_factory=dict)

    @classmethod
    def load(cls, root: Path, explicit: str | None = None) -> "Config":
        candidates = [Path(explicit)] if explicit else [root / rel for rel in CONFIG_LOCATIONS]
        for path in candidates:
            if path.is_file():
                return cls.from_data(yamlutil.load_file(path) or {}, path)
        if explicit:
            raise ConfigError(f"config file not found: {explicit}")
        return cls()

    @classmethod
    def from_data(cls, data, path) -> "Config":
        """A configuration from parsed YAML; `path` names it in error messages."""
        if not isinstance(data, dict):
            raise ConfigError(f"{path}: expected a mapping")
        unknown = sorted(str(k) for k in data if k not in CONFIG_KEYS)
        if unknown:
            # A misspelt key (protected-secrets) would otherwise turn a control off without a word.
            raise ConfigError(f"{path}: unknown setting(s) {', '.join(unknown)}; the checker reads "
                              f"{', '.join(sorted(CONFIG_KEYS))}")
        ignore = data.get("ignore") or []
        for entry in ignore:
            if not isinstance(entry, dict):
                raise ConfigError(f"{path}: every ignore entry must be a mapping")
            for key in ("rule", "path", "reason", "until"):
                if not entry.get(key):
                    raise ConfigError(f"{path}: every ignore entry needs rule, path, reason and until; "
                                      f"missing {key!r} in {dict(entry)}")
            if not re.sub(r"[*?/\[\]!]", "", str(entry["path"])).strip("."):
                raise ConfigError(f"{path}: ignore path {entry['path']!r} matches everything; name the "
                                  "workflow file the finding is in")
            try:
                until = entry["until"]
                until if isinstance(until, date) else date.fromisoformat(str(until))
            except ValueError as exc:
                raise ConfigError(f"{path}: ignore entry 'until' must be a date (YYYY-MM-DD): {exc}") from exc
        jenkins = data.get("jenkins") or {}
        if not isinstance(jenkins, dict) or not isinstance(jenkins.get("files") or [], list) or \
                not isinstance(jenkins.get("exclude") or [], list):
            raise ConfigError(f"{path}: jenkins must be a mapping, and jenkins.files and jenkins.exclude "
                              "lists of globs")
        agents = data.get("agents") or {}
        if not isinstance(agents, dict) or not isinstance(agents.get("steps") or [], list):
            raise ConfigError(f"{path}: agents must be a mapping, and agents.steps a list of step names")
        lanes = data.get("lanes") or {}     # left empty, it declares nothing
        if not isinstance(lanes, dict):
            raise ConfigError(f"{path}: lanes must be a mapping of a workflow file, or 'file#job', to a lane")
        return cls(lanes=dict(lanes), agents=dict(agents), ignore=list(ignore),
                   path=str(path), jenkins=dict(jenkins),
                   protected_secrets=parse_protected_secrets(data.get("protected_secrets"), path))


@dataclass
class CheckResult:
    findings: list[Finding]
    files: list[str]
    errors: list[str]
    config: Config
    notes: list[str] = field(default_factory=list)
    jenkins_files: list[str] = field(default_factory=list)   # the subset of files checked as Jenkinsfiles
    coverage: list[dict] = field(default_factory=list)       # per Jenkinsfile and rule: pass/fail/unknown/...
    jenkins: list[dict] = field(default_factory=list)        # per Jenkinsfile: kind, digest, file-wide unknowns
    baseline_used: bool = False                              # set by baseline.apply
    baseline_stale: list[dict] = field(default_factory=list) # baseline entries no finding matched

    @property
    def workflow_files(self) -> list[str]:
        return [f for f in self.files if f not in set(self.jenkins_files)]

    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def at_or_above(self, severity: str) -> list[Finding]:
        threshold = SEVERITY_ORDER[severity]
        return [f for f in self.active() if SEVERITY_ORDER[f.severity] >= threshold]

    def stale_gating(self, spec: str, catalog: Catalog) -> list[dict]:
        """Baseline entries no finding matched that make `--fail-on spec` fail: the same threshold and
        category as findings, so a vanished low finding does not fail `--fail-on high`."""
        category, severity = parse_fail_on(spec)
        if severity == "never":
            return []
        threshold = SEVERITY_ORDER[severity]
        out = []
        for entry in self.baseline_stale:
            if SEVERITY_ORDER.get(entry.get("severity"), 0) < max(threshold, 1):
                continue
            rule = catalog.rules.get(entry.get("rule"), {})
            if category is not None and (rule.get("category") or "authority") != category:
                continue
            out.append(entry)
        return out

    def gating(self, spec: str, catalog: Catalog) -> list[Finding]:
        """Active findings that make `--fail-on spec` fail (empty means it passes)."""
        category, severity = parse_fail_on(spec)
        if severity == "never":
            return []
        threshold = SEVERITY_ORDER[severity]
        out = []
        for f in self.active():
            if f.baselined:
                continue
            if SEVERITY_ORDER[f.severity] < threshold:
                continue
            if category is not None and (catalog.rules[f.rule].get("category") or "authority") != category:
                continue
            out.append(f)
        return out


def _apply_ignores(findings: list[Finding], config: Config, today: date) -> None:
    for finding in findings:
        for entry in config.ignore:
            if entry["rule"] != finding.rule or not fnmatch.fnmatch(finding.path, str(entry["path"])):
                continue
            if entry.get("job") and entry["job"] != finding.job:
                continue
            until = entry["until"]
            until = until if isinstance(until, date) else date.fromisoformat(str(until))
            if until < today:
                finding.message += f" (An ignore entry for this finding expired on {until.isoformat()}.)"
                continue
            finding.suppressed = f"{entry['reason']} (until {until.isoformat()})"
            break


PLATFORMS = ("auto", "github", "jenkins")


def _resolve(target: Path, platform: str) -> tuple[Path, list[Path], list[Path], bool]:
    """(root, workflow files, Jenkinsfiles, is_repo) for a path given to `obaaf check`."""
    target = target.resolve()
    if target.is_file():
        # A single file: GitHub Actions workflows are YAML; a Jenkinsfile or a .groovy pipeline is Jenkins.
        is_jenkins = platform == "jenkins" or (platform == "auto" and (
            jenkins_mod.is_jenkinsfile(target) or target.suffix.lower() == ".groovy"))
        return target.parent, ([] if is_jenkins else [target]), ([target] if is_jenkins else []), False
    root, workflows = wf_mod.locate(target)
    if platform == "jenkins":
        workflows = []
    return root, workflows, [], True


def check(target: Path, files: list[Path] | None = None, config: Config | None = None,
          catalog: Catalog | None = None, today: date | None = None, platform: str = "auto") -> CheckResult:
    """Check a repository root (workflows, Jenkinsfiles and repository files) or specific files.

    platform: auto (both kinds of CI definition), github (workflows only) or jenkins (Jenkinsfiles only).
    """
    if platform not in PLATFORMS:
        raise ValueError(f"platform must be one of {', '.join(PLATFORMS)}, not {platform!r}")
    catalog = catalog or load()
    target = target.resolve()
    jenkins_paths: list[Path] = []
    if files is None:
        root, files, jenkins_paths, is_repo = _resolve(target, platform)
        on_its_own = not is_repo
    else:
        root, is_repo, on_its_own = target, False, False
        if platform != "github":
            jenkins_paths = [f for f in files if platform == "jenkins" or jenkins_mod.is_jenkinsfile(f)
                             or f.suffix.lower() == ".groovy"]
            files = [f for f in files if f not in jenkins_paths]
    config = config or Config.load(root)
    # Jenkinsfiles are found from the repository root, not from .github/workflows.
    jenkins_sought = is_repo and platform != "github" and target == root
    if jenkins_sought:
        jenkins_paths = jenkins_mod.discover(root, list(config.jenkins.get("files") or []),
                                             list(config.jenkins.get("exclude") or []))
    script_cmds = _script_commands(catalog, config)
    findings: list[Finding] = []
    errors: list[str] = []
    rels: list[str] = []
    agent_lane_present = False
    suspect_jobs: list[tuple[str, str]] = []
    declared = _LaneDeclarations(config, is_repo, on_its_own, workflows_sought=platform != "jenkins",
                                 jenkins_sought=jenkins_sought)
    for path in files:
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        rels.append(rel)
        text = path.read_text(encoding="utf-8", errors="replace")
        workflow = wf_mod.parse(rel, text)
        if workflow.error:
            errors.append(f"{rel}: {workflow.error}")
            declared.unreadable(rel, path)
            continue
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents,
                        aliases=declared.aliases(rel, path))
        _apply_script_detection(workflow, root, script_cmds)
        declared.workflow(workflow, path)
        for job in workflow.jobs.values():
            if job.in_lane("agent"):
                agent_lane_present = True
            elif _AGENT_HINT.search(f"{job.id} {job.name}"):
                # Whatever other lane the job is in: a declaration must not be a way to silence this.
                suspect_jobs.append((rel, job.id))
        try:
            found = rules_mod.WorkflowRules(workflow, catalog, protected=config.protected_secrets).run()
        except expr_mod.TooComplex as exc:
            # A file the checker could not read is an error, never a pass.
            errors.append(f"{rel}: {exc}")
            continue
        except (RecursionError, MemoryError):
            errors.append(f"{rel}: too deeply nested or too large to read; the checker cannot tell what this "
                          "file does")
            continue
        findings.extend(found)
        errors.extend(f"{rel}: {problem}" for problem in workflow.problems)
    jenkins_results = []
    jenkins_rels: list[str] = []
    for path in jenkins_paths:
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.name
        rels.append(rel)
        jenkins_rels.append(rel)
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"{rel}: cannot be read: {exc}")
            continue
        result = jenkins_mod.analyze(rel, data, catalog, root, extra_agents=config.agents,
                                     lane_overrides=config.lanes)
        jenkins_results.append(result)
        if result.error:
            errors.append(f"{rel}: {result.error}")
            declared.unreadable(rel)
            continue
        declared.jenkinsfile(rel, result)
        findings.extend(result.findings)
        agent_lane_present = agent_lane_present or result.agent_present
        suspect_jobs.extend((rel, f"stage {s}") for s in result.suspect_stages)
    if is_repo:
        findings.extend(rules_mod.repo_findings(root, rels, catalog))
    _apply_ignores(findings, config, today or date.today())
    findings.sort(key=Finding.sort_key)
    notes = _lane_notes(root, catalog, is_repo, agent_lane_present, suspect_jobs)
    notes += declared.notes()
    cov: list[dict] = []
    summaries: list[dict] = []
    for result in jenkins_results:
        cov.extend(jenkins_mod.coverage(result, findings))
        summaries.append(jenkins_mod.summary(result))
    return CheckResult(findings=findings, files=rels, errors=errors, config=config, notes=notes,
                       jenkins_files=jenkins_rels, coverage=cov, jenkins=summaries)


def _lane_notes(root: Path, catalog: Catalog, is_repo: bool, agent_lane_present: bool,
                suspect_jobs: list[tuple[str, str]]) -> list[str]:
    """Advisory notes (never findings, never affect the exit code): surface agents the lane
    inference may have missed, so the agent controls are not silently skipped."""
    notes: list[str] = []
    if agent_lane_present:
        return notes
    if is_repo:
        instruction_files = repo_checks.find_instruction_files(root, catalog.detection.get("instruction_files", []))
        if instruction_files:
            shown = ", ".join(instruction_files[:3]) + (", ..." if len(instruction_files) > 3 else "")
            notes.append(
                f"{len(instruction_files)} agent instruction file(s) are present ({shown}) but no workflow job was "
                "classified into the agent lane, so the agent controls did not run on any job. If an agent runs "
                "indirectly, for example through a wrapper script like 'bash run-agent.sh', declare its command in "
                "agents.commands in .github/obaaf.yml, or set OBAAF_LANE: agent on the job (in a Jenkinsfile, "
                "OBAAF_LANE = 'agent' in the stage's environment). See docs/checker-configuration.md.")
    if suspect_jobs:
        shown = "; ".join(f"{w} {j}" if j.startswith("stage ") else f"{w} job '{j}'" for w, j in suspect_jobs[:5])
        more = f", and {len(suspect_jobs) - 5} more" if len(suspect_jobs) > 5 else ""
        notes.append(
            f"{len(suspect_jobs)} job(s) have a name that suggests agent work but are not in the agent lane "
            f"({shown}{more}). If any runs an AI agent, declare it with agents.commands or OBAAF_LANE so the agent "
            "controls apply.")
    return notes


class _LaneDeclarations:
    """Lane declarations that did nothing, for the notes: a value that is not a lane, OBAAF_LANE on
    a step, or a configured lane for a job, stage or file the checker did not find. A declaration can
    only add rules, so one that silently does nothing leaves a job with fewer rules than its author
    meant it to have."""

    def __init__(self, config: "Config", is_repo: bool, on_its_own: bool, workflows_sought: bool,
                 jenkins_sought: bool) -> None:
        self.config, self.is_repo, self.on_its_own = config, is_repo, on_its_own
        self.workflows_sought, self.jenkins_sought = workflows_sought, jenkins_sought
        self.problems: list[str] = []
        self.known: dict[str, tuple[str, set]] = {}    # path -> ("job" or "stage", the names it has)
        self.unread: set[str] = set()

    def aliases(self, rel: str, path: Path) -> tuple:
        """Other paths the configuration may know a workflow by. A workflow checked on its own is
        `ci.yml` to the checker and `.github/workflows/ci.yml` in the repository's configuration.
        Only for a file given on its own: in a repository, or in a list of files, a file has one path."""
        parent = path.resolve().parent
        if not self.on_its_own or parent.name != "workflows" or parent.parent.name != ".github":
            return ()
        alias = f".github/workflows/{path.name}"
        return () if alias == rel else (alias,)

    def unreadable(self, rel: str, path: Path | None = None) -> None:
        """A file already reported as an error: say nothing more about its declarations."""
        self.unread.update((rel, *(self.aliases(rel, path) if path else ())))

    def workflow(self, workflow, path: Path) -> None:
        self.problems.extend(workflow.lane_problems)
        jobs = workflow.raw.get("jobs")
        # Every job the file names, including one the checker could not read and reported as an error.
        names = {str(name) for name in jobs} if isinstance(jobs, dict) else set(workflow.jobs)
        for known_as in (workflow.path, *self.aliases(workflow.path, path)):
            self.known[known_as] = ("job", names | self.known.get(known_as, ("job", set()))[1])

    def jenkinsfile(self, rel: str, result) -> None:
        self.problems.extend(result.lane_problems)
        self.known[rel] = ("stage", set(result.stage_keys))

    def _looked_for(self, path: str) -> bool:
        """Whether this run looked for files of the kind `path` names at all."""
        return self.workflows_sought if path.endswith((".yml", ".yaml")) else self.jenkins_sought

    def notes(self) -> list[str]:
        found = list(self.problems)
        for key, value in self.config.lanes.items():
            path, sep, part = str(key).partition("#")
            shown = wf_mod.one_line(key, 120)
            if path in self.unread:
                continue
            read = path in self.known
            if not read and not (self.is_repo and self._looked_for(path)):
                continue    # the configuration covers more than the files this run was given
            if wf_mod.declared_lane(value) is None:
                found.append(wf_mod.not_a_lane(f"the checker configuration sets lanes: '{shown}'", value))
            if not read:
                found.append(f"lanes: '{shown}' in the checker configuration names a file the checker did not "
                             "read; the declaration changes nothing")
            elif sep and part not in self.known[path][1]:
                kind = self.known[path][0]
                found.append(f"lanes: '{shown}' in the checker configuration names a {kind} that "
                             f"{wf_mod.one_line(path, 120)} does not have; the declaration changes nothing")
        return [f"Lane declaration ignored: {problem}." for problem in dict.fromkeys(found)]


def lanes(target: Path, config: Config | None = None, platform: str = "auto",
          notes: list | None = None) -> list[tuple[str, str, str, str]]:
    """(file, job or stage, lane, reason) for every workflow job and Jenkins stage, to show how the
    checker classified them. Lane declarations that did nothing are added to `notes` when it is given."""
    root, files, jenkins_paths, is_repo = _resolve(target, platform)
    config = config or Config.load(root)
    jenkins_sought = is_repo and platform != "github" and target.resolve() == root
    declared = _LaneDeclarations(config, is_repo, not is_repo, workflows_sought=platform != "jenkins",
                                 jenkins_sought=jenkins_sought)
    if jenkins_sought:
        jenkins_paths = jenkins_mod.discover(root, list(config.jenkins.get("files") or []),
                                             list(config.jenkins.get("exclude") or []))
    script_cmds = _script_commands(load(), config)
    out = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        workflow = wf_mod.parse(rel, path.read_text(encoding="utf-8", errors="replace"))
        if workflow.error:
            declared.unreadable(rel, path)
            continue
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents,
                        aliases=declared.aliases(rel, path))
        _apply_script_detection(workflow, root, script_cmds)
        declared.workflow(workflow, path)
        out += [(rel, job.id, job.lane, job.lane_reason) for job in workflow.jobs.values()]
    catalog = load()
    for path in jenkins_paths:
        rel = path.relative_to(root).as_posix()
        result = jenkins_mod.analyze(rel, path.read_bytes(), catalog, root, extra_agents=config.agents,
                                     lane_overrides=config.lanes)
        if result.error:
            declared.unreadable(rel)
        else:
            declared.jenkinsfile(rel, result)
        out += [(rel, f"stage {stage}", lane, reason) for stage, lane, reason in result.lanes]
    if notes is not None:
        notes.extend(declared.notes())
    return out
