"""The OBAAF pipeline checker (`obaaf check`, FR12).

It reads GitHub Actions workflow files and repository settings that live in
files (CODEOWNERS, agent instruction files) and reports risky settings, each
with the profile requirement it threatens and the fix. It runs locally and
sends nothing over the network (NFR5).
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import shlex
from dataclasses import dataclass, field, replace
from datetime import date
from pathlib import Path

from obaaf import yamlutil
from obaaf.catalog import Catalog, load
from obaaf.checker import acceptance as acceptance_mod
from obaaf.checker import egress as egress_mod
from obaaf.checker import expr as expr_mod
from obaaf.checker import jenkins as jenkins_mod
from obaaf.checker import repo as repo_checks
from obaaf.checker import rules as rules_mod
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import FIXED, Finding

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
    is best-effort; what it cannot read (fetched or generated scripts) is covered by the lane note.
    Every step found doing so is recorded on the job, for the egress control (OBAAF-GHA-020)."""
    if not commands:
        return None
    root_r = root.resolve()
    found = None
    for step in job.steps:
        run = step.run
        if step.confines and isinstance(step.with_.get("run"), str):
            run = step.with_["run"]     # the command OBAAF's egress action runs
        for tok in _script_targets(run) + _copied_script_targets(run, root_r):
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
                job.agent_script_steps.add(step.index)
                found = found or f"runs an agent in the script {tok}"
                break
    return found


def _script_commands(catalog: "Catalog", config: "Config") -> list:
    patterns = list(catalog.detection.get("agent_commands", [])) + list(config.agents.get("commands", ()) or ())
    return [re.compile(p, re.M) for p in patterns]


def _apply_script_detection(workflow, root: Path, commands: list) -> None:
    for job in workflow.jobs.values():
        reason = _agent_via_script(job, root, commands)
        if reason and not job.in_lane("agent"):
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
    lane_lines: dict = field(default_factory=dict)      # `lanes:` key -> the line it is written on

    @classmethod
    def load(cls, root: Path, explicit: str | None = None) -> "Config":
        candidates = [Path(explicit)] if explicit else [root / rel for rel in CONFIG_LOCATIONS]
        for path in candidates:
            if path.is_file():
                try:
                    data = yamlutil.load_file(path)
                except Exception as exc:    # YAML errors, duplicate keys, text that is not UTF-8
                    raise ConfigError(f"{path}: cannot be read as YAML: {exc}") from exc
                return cls.from_data(data or {}, path)
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
            if entry["rule"] == IDLE_DECLARATION:
                # An ignore entry accepts a rule in a file, whatever the finding says. For this rule
                # that is every lane declaration in the file, including ones not written yet.
                raise ConfigError(f"{path}: an ignore entry cannot accept {IDLE_DECLARATION}. It would cover every "
                                  "lane declaration in the file it names, whatever each is later changed to. "
                                  "Correct the declaration, or accept that one declaration with a baseline entry "
                                  "(obaaf check --write-baseline FILE --owner OWNER --reason REASON --expires "
                                  "YYYY-MM-DD), which names its key and its value")
            if acceptance_mod.parse_date(entry["until"]) is None:
                # A date and nothing else: a time of day cannot be compared with today, and other
                # spellings of a date were read by some Python versions and not by others.
                raise ConfigError(f"{path}: ignore entry 'until' must be a date (YYYY-MM-DD), not "
                                  f"{str(entry['until'])[:40]!r}")
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
                   protected_secrets=parse_protected_secrets(data.get("protected_secrets"), path),
                   lane_lines={key: wf_mod.key_line(lanes, key, 1) for key in lanes})


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
    baseline_format: str = ""                                # the format of the baseline that was applied
    baseline_path: str = ""
    checked: str = ""                                        # the path the command line asked to check
    options: list[str] = field(default_factory=list)         # --config and --platform as the command line gave them
    today: date | None = None                                # the day acceptances were judged against

    @property
    def workflow_files(self) -> list[str]:
        return [f for f in self.files if f not in set(self.jenkins_files)]

    def active(self) -> list[Finding]:
        """Findings that are neither ignored by configuration nor fixed by verified controls."""
        return [f for f in self.findings if not f.suppressed and f.state != FIXED]

    def cleared(self) -> list[Finding]:
        """Findings whose every control the checker verified. They are shown, and fail nothing."""
        return [f for f in self.findings if f.state == FIXED]

    def not_accepted(self) -> list[Finding]:
        """Findings that an ignore entry or a baseline entry names without accepting them: the entry
        lacks an owner, a reason or an expiry date, has expired, or expires too far ahead."""
        return [f for f in self.findings
                if f.state != FIXED and f.acceptance is not None and not f.acceptance.valid]

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
    """Apply the configuration's ignore entries. An entry is an acceptance, and only a valid one
    (owner, reason, an expiry date not passed and at most a year ahead) ignores a finding. An entry
    that matches and is not valid is attached to the finding, so the report can say what it lacks."""
    for finding in findings:
        if finding.rule == IDLE_DECLARATION:
            continue    # accepted by a baseline entry only, which names the one declaration (see Config.from_data)
        for entry in config.ignore:
            if entry["rule"] != finding.rule or not fnmatch.fnmatch(finding.path, str(entry["path"])):
                continue
            if entry.get("job") and entry["job"] != finding.job:
                continue
            until = acceptance_mod.parse_date(entry["until"])
            made = acceptance_mod.make(acceptance_mod.IGNORE, entry.get("owner"), entry["reason"], until, today)
            if made.valid:
                finding.suppressed = f"{entry['reason']} (until {until.isoformat()})"
                finding.acceptance = made
                break
            if until < today:
                finding.message += f" (An ignore entry for this finding expired on {until.isoformat()}.)"
            if finding.acceptance is None:
                finding.acceptance = made


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
    declared = _LaneDeclarations(config, root, is_repo, on_its_own, workflows_sought=platform != "jenkins",
                                 jenkins_sought=jenkins_sought)
    # The policy file of GitHub's native egress firewall is read from the repository, never for files
    # checked on their own, whose repository the checker does not know.
    firewall = egress_mod.read_firewall_policy(root) if is_repo else None
    for path in files:
        try:
            rel = path.resolve().relative_to(root).as_posix()
        except ValueError:
            rel = path.as_posix()
        rels.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            # A file the checker could not read is an error, never a traceback or a pass.
            errors.append(f"{rel}: cannot be read: {exc}")
            declared.unreadable(rel, path)
            continue
        workflow = wf_mod.parse(rel, text)
        if workflow.error:
            errors.append(f"{rel}: {workflow.error}")
            declared.unreadable(rel, path)
            continue
        # The bytes, not the text: a byte that is not UTF-8 is replaced in the text, and two files
        # that differ only there must not be one file to an acceptance.
        workflow.digest = hashlib.sha256(path.read_bytes()).hexdigest()
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
            found = rules_mod.WorkflowRules(workflow, catalog, protected=config.protected_secrets,
                                            agents=config.agents, firewall=firewall).run()
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
    # A lane declaration that does nothing is a finding like any other: it can fail the check, be
    # fixed by correcting it, or be accepted by an ignore or baseline entry.
    findings.extend(declared.findings(catalog))
    today = today or date.today()
    _apply_ignores(findings, config, today)
    findings.sort(key=Finding.sort_key)
    notes = _lane_notes(root, catalog, is_repo, agent_lane_present, suspect_jobs)
    cov: list[dict] = []
    summaries: list[dict] = []
    for result in jenkins_results:
        cov.extend(jenkins_mod.coverage(result, findings))
        summaries.append(jenkins_mod.summary(result))
    return CheckResult(findings=findings, files=rels, errors=errors, config=config, notes=notes,
                       jenkins_files=jenkins_rels, coverage=cov, jenkins=summaries, today=today)


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


IDLE_DECLARATION = "OBAAF-CFG-001"
_NOT_A_LANE = f"which is not a lane ({', '.join(wf_mod.LANES)}), so the declaration changes nothing"
_NOT_READ = ("where it is not read (it is read in the job's env and in the workflow's env), so the declaration "
             "changes nothing")
# One template for each case of OBAAF-CFG-001. The case is the finding's `kind`.
_IDLE_TEMPLATES = {
    "job-not-a-lane": f"Job '{{job}}' sets OBAAF_LANE to {{value}}, {_NOT_A_LANE}.",
    "workflow-not-a-lane": f"The workflow's env sets OBAAF_LANE to {{value}}, {_NOT_A_LANE}.",
    "job-misnamed": "Job '{job}' sets {name} to {value}. The variable that declares a lane is OBAAF_LANE, spelled "
                    "exactly so, so the declaration changes nothing.",
    "workflow-misnamed": "The workflow's env sets {name} to {value}. The variable that declares a lane is "
                         "OBAAF_LANE, spelled exactly so, so the declaration changes nothing.",
    "jenkins-not-a-lane": f"For the steps in {{stages}}, OBAAF_LANE is set to {{value}}, {_NOT_A_LANE}.",
    "jenkins-computed": "For the steps in {stages}, OBAAF_LANE is set to a value computed when the build runs, "
                        "which the checker cannot read as a lane, so the declaration changes nothing.",
    "step-env": f"Job '{{job}}' sets OBAAF_LANE to {{value}} in the env of step '{{step}}', {_NOT_READ}.",
    "container-env": f"Job '{{job}}' sets OBAAF_LANE to {{value}} in container.env, {_NOT_READ}.",
    "service-env": f"Job '{{job}}' sets OBAAF_LANE to {{value}} in services.{{service}}.env, {_NOT_READ}.",
    "entry-not-a-lane": f"lanes: '{{entry}}' is set to {{value}}, {_NOT_A_LANE}.",
    "entry-no-job": "lanes: '{entry}' (set to {value}) names a job that {file} does not have, so the declaration "
                    "changes nothing.",
    "entry-no-stage": "lanes: '{entry}' (set to {value}) names a stage that {file} does not have, so the "
                      "declaration changes nothing.",
    "entry-no-file": "lanes: '{entry}' (set to {value}) names a file the checker did not read, so the declaration "
                     "changes nothing.",
}


class _LaneDeclarations:
    """Lane declarations that did nothing, each reported as a finding (OBAAF-CFG-001): a value that
    is not a lane, OBAAF_LANE where it is not read, or a configured lane for a job, stage or file
    the checker did not find. A declaration can only add rules, so one that silently does nothing
    leaves a job with fewer rules than its author meant it to have."""

    def __init__(self, config: "Config", root: Path, is_repo: bool, on_its_own: bool, workflows_sought: bool,
                 jenkins_sought: bool) -> None:
        self.config, self.root, self.is_repo, self.on_its_own = config, root, is_repo, on_its_own
        self.workflows_sought, self.jenkins_sought = workflows_sought, jenkins_sought
        self.problems: list = []                       # IdleDeclaration: written in a workflow or a Jenkinsfile
        try:
            self.resolved_root: Path | None = root.resolve()
        except (OSError, RuntimeError):
            self.resolved_root = None
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
        """Take a classified workflow's declarations. Call it once every lane the job is in is
        known, script detection included: a declaration written where it is not read loses nothing
        when the job is in the lane it names anyway."""
        for found in workflow.lane_problems:
            job = workflow.jobs.get(found.job) if found.job else None
            if job is not None and found.lane in wf_mod.LANE_ORDER and job.in_lane(found.lane):
                found = replace(found, redundant=True)
            self.problems.append(found)
        jobs = workflow.raw.get("jobs")
        # Every job the file names, including one the checker could not read and reported as an error.
        names = {str(name) for name in jobs} if isinstance(jobs, dict) else set(workflow.jobs)
        for known_as in (workflow.path, *self.aliases(workflow.path, path)):
            self.known[known_as] = ("job", names | self.known.get(known_as, ("job", set()))[1])

    def jenkinsfile(self, rel: str, result) -> None:
        self.problems.extend(result.lane_problems)
        self.known[rel] = ("stage", set(result.stage_keys))

    def _unsought(self, path: str) -> bool:
        """Whether `path` is a file that exists and is of a kind this run did not look for at all
        (a Jenkinsfile when only workflows were checked, or the other way round)."""
        sought = self.workflows_sought if path.endswith((".yml", ".yaml")) else self.jenkins_sought
        if sought or self.resolved_root is None:
            return False
        try:
            target = self.resolved_root / path
            # One look at the file system for a path that is not a file, which is nearly every one tried.
            return target.is_file() and target.resolve().is_relative_to(self.resolved_root)
        except (OSError, ValueError, RuntimeError):
            return False

    def _out_of_scope(self, key: str) -> bool:
        """Whether a `lanes:` key names a file outside this run: one that exists and is of a kind
        the run did not look for. An entry for a file that does not exist is never out of scope: it
        is a mistake whatever was checked. The file is the key, or the part of it before one of its
        `#`, because a file's own name may hold one. A path is short and has few of them, so only
        the first 4,096 characters and 64 cuts are tried."""
        cuts = [len(key)] if len(key) <= 4096 else []
        cut = -1
        while len(cuts) < 64 and (cut := key.find("#", cut + 1)) != -1 and cut <= 4096:
            cuts.append(cut)
        return any(self._unsought(key[:cut]) for cut in cuts)

    def config_path(self) -> str:
        """The checker configuration as a finding names it: from the directory every other path in
        the report is given from. A configuration that was not read from a file is named as the
        file such a declaration would be written in."""
        if not self.config.path:
            return CONFIG_LOCATIONS[0]
        given = Path(self.config.path)
        try:
            resolved, root = given.resolve(), self.root.resolve()
            if resolved.is_relative_to(root):
                return resolved.relative_to(root).as_posix()
            return Path(os.path.relpath(resolved, root)).as_posix()
        except (OSError, ValueError):
            return given.as_posix()

    def _finding(self, catalog: Catalog, kind: str, path: str, line: int, nothing_lost: bool,
                 job: str | None = None, step: str | None = None, **values) -> Finding:
        # A declaration that would have added no rule had it worked (it names `trusted`, or a lane
        # the job is in anyway) is hardening. Any other leaves a job without rules its author meant
        # it to have, and is reported at the rule's own severity.
        severity = "low" if nothing_lost else catalog.rules[IDLE_DECLARATION]["severity"]
        message, facts = rules_mod.compose(IDLE_DECLARATION, kind, _IDLE_TEMPLATES[kind], job, step, values)
        return Finding(IDLE_DECLARATION, severity, path, line or 1, message, job=job, step=step, kind=kind,
                       facts=facts)

    def _entries(self, catalog: Catalog) -> list[Finding]:
        """The `lanes:` entries of the checker configuration that do nothing."""
        out: list[Finding] = []
        where = self.config_path()
        for key, value in self.config.lanes.items():
            # A key that is not text is shown as YAML writes it, not as Python does.
            text = {True: "true", False: "false", None: "null"}.get(key, None) if isinstance(key, (bool, type(None))) \
                else wf_mod.as_text(key)
            named: list = []
            # A key that is not text (`5:`, `true:`) is never looked up, so it names nothing.
            if isinstance(key, str):
                # The files this run read or refused that the key names, whole or before a `#`. A file's
                # own name may hold a `#`, so the key is matched against the files, not cut at its first.
                named = [(path, text[len(path) + 1:]) for path in (*self.known, *self.unread)
                         if text == path or text.startswith(path + "#")]
                if any(path in self.unread for path, _ in named):
                    continue
                named = [(path, part) for path, part in named if path in self.known]
                if not named and (not self.is_repo or self._out_of_scope(text)):
                    continue    # the configuration covers more than the files this run was given
            lane = wf_mod.declared_lane(value)
            shared = {"path": where, "line": self.config.lane_lines.get(key, 1),
                      "entry": rules_mod.Fact(wf_mod.bounded(text), wf_mod.one_line(text, 120)),
                      "value": rules_mod.Fact(wf_mod.value_identity(value), wf_mod.shown_value(value))}
            if lane is None:
                out.append(self._finding(catalog, "entry-not-a-lane", nothing_lost=False, **shared))
            if not named:
                out.append(self._finding(catalog, "entry-no-file", nothing_lost=lane == "trusted", **shared))
            elif not any(text == path or part in self.known[path][1] for path, part in named):
                path = named[0][0]
                kind = self.known[path][0]
                # On a Jenkins stage only `agent` and `release` change what is checked (docs/jenkins.md).
                harmless = ("trusted",) if kind == "job" else ("trusted", "untrusted", "effect")
                out.append(self._finding(catalog, f"entry-no-{kind}", nothing_lost=lane in harmless, **shared,
                                         file=rules_mod.Note(wf_mod.one_line(path, 120))))
        return out

    def findings(self, catalog: Catalog) -> list[Finding]:
        """One finding for each declaration that did nothing."""
        out: list[Finding] = []
        for found in dict.fromkeys(self.problems):
            values: dict = {}
            if found.kind != "jenkins-computed":
                values["value"] = rules_mod.Fact(found.value, found.shown)
            if found.kind == "service-env":
                values["service"] = rules_mod.Fact(found.service, wf_mod.one_line(found.service, 60))
            if found.name:
                values["name"] = rules_mod.Fact(found.name, f"'{found.name_shown}'")
            if found.kind.startswith("jenkins-"):
                # The labels are the checker's own, as `--lanes` prints them: a stage by its name, a
                # stage in a stage as `Outer > Inner`, a method as `name()`, a post block as `post always`.
                values["stages"] = rules_mod.Fact(list(found.stages), ", ".join(
                    f"'{wf_mod.one_line(stage, 80)}'" if stage else "the pipeline outside any stage"
                    for stage in found.stages))
            out.append(self._finding(catalog, found.kind, found.path, found.line,
                                     found.lane == "trusted" or found.redundant, found.job, found.step, **values))
        return out + self._entries(catalog)

    def notes(self, catalog: Catalog) -> list[str]:
        """The same declarations as lines for `--lanes`, which lists lanes and reports no findings.
        Each is one line whatever a job or a step is called."""
        return [f"Lane declaration ignored: {wf_mod.one_line(f.path, 120)}, line {f.line}: "
                f"{wf_mod.one_line(f.message)} (`obaaf check` reports it as {f.rule}, {f.severity}.)"
                for f in sorted(self.findings(catalog), key=Finding.sort_key)]


def lanes(target: Path, config: Config | None = None, platform: str = "auto",
          notes: list | None = None, errors: list | None = None,
          seen: list | None = None) -> list[tuple[str, str, str, str]]:
    """(file, job or stage, lane, reason) for every workflow job and Jenkins stage, to show how the
    checker classified them. Lane declarations that did nothing, which `check` reports as findings,
    are added to `notes` as lines of text when it is given. Whatever `check` would report as an error
    for a file (it could not be read or parsed, an input is given twice, the rules could not read an
    expression) is added to `errors` as `check` words it, and a Jenkinsfile part of whose pipeline was
    not analyzed is added to `notes` (slice 3.2a); every file looked at, read or not, is added to `seen`."""
    errors = [] if errors is None else errors
    seen = [] if seen is None else seen
    notes = [] if notes is None else notes
    root, files, jenkins_paths, is_repo = _resolve(target, platform)
    firewall = egress_mod.read_firewall_policy(root) if is_repo else None
    config = config or Config.load(root)
    jenkins_sought = is_repo and platform != "github" and target.resolve() == root
    declared = _LaneDeclarations(config, root, is_repo, not is_repo, workflows_sought=platform != "jenkins",
                                 jenkins_sought=jenkins_sought)
    if jenkins_sought:
        jenkins_paths = jenkins_mod.discover(root, list(config.jenkins.get("files") or []),
                                             list(config.jenkins.get("exclude") or []))
    catalog = load()
    script_cmds = _script_commands(catalog, config)
    out = []
    for path in files:
        rel = path.relative_to(root).as_posix()
        seen.append(rel)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            errors.append(f"{rel}: cannot be read: {exc}")
            declared.unreadable(rel, path)
            continue
        workflow = wf_mod.parse(rel, text)
        if workflow.error:
            errors.append(f"{rel}: {workflow.error}")
            declared.unreadable(rel, path)
            continue
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents,
                        aliases=declared.aliases(rel, path))
        _apply_script_detection(workflow, root, script_cmds)
        declared.workflow(workflow, path)
        # What `check` reports as an error for the file (an input given twice under two spellings, an
        # expression too deep for the rules to read) means the file was not fully read, so `--lanes`
        # must not pass it either. The rules are run only to find those errors.
        try:
            rules_mod.WorkflowRules(workflow, catalog, protected=config.protected_secrets,
                                    agents=config.agents, firewall=firewall).run()
        except expr_mod.TooComplex as exc:
            errors.append(f"{rel}: {exc}")
        except (RecursionError, MemoryError):
            errors.append(f"{rel}: too deeply nested or too large to read; the checker cannot tell what this "
                          "file does")
        errors.extend(f"{rel}: {problem}" for problem in workflow.problems)
        out += [(rel, job.id, job.lane, job.lane_reason) for job in workflow.jobs.values()]
    for path in jenkins_paths:
        rel = path.relative_to(root).as_posix()
        seen.append(rel)
        try:
            data = path.read_bytes()
        except OSError as exc:
            errors.append(f"{rel}: cannot be read: {exc}")
            declared.unreadable(rel)
            continue
        result = jenkins_mod.analyze(rel, data, catalog, root, extra_agents=config.agents,
                                     lane_overrides=config.lanes)
        if result.error:
            errors.append(f"{rel}: {result.error}")
            declared.unreadable(rel)
        else:
            declared.jenkinsfile(rel, result)
            # `check` says no rule can pass such a file and still ends 0 (the Jenkins analyser is
            # advisory); the listing says the same, so a stage in the part not analyzed is not missing
            # in silence.
            general = list(dict.fromkeys(f"line {u.line}: {u.reason}" for u in result.unknowns
                                         if u.rule == jenkins_mod.ALL))
            if general:
                notes.append(f"{wf_mod.one_line(rel, 120)}: part of the pipeline was not analyzed, so a stage in "
                             f"it may be missing from this list ({wf_mod.one_line('; '.join(general))})")
        out += [(rel, f"stage {stage}", lane, reason) for stage, lane, reason in result.lanes]
    notes.extend(declared.notes(catalog))
    return out
