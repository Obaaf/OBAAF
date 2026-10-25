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
from obaaf.checker import repo as repo_checks
from obaaf.checker import rules as rules_mod
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import Finding

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}
CONFIG_LOCATIONS = (".github/obaaf.yml", ".github/obaaf.yaml", "obaaf.yml")
# Words in a job id or name that suggest it runs an AI agent, used only to warn
# when such a job was left in the trusted lane (never to classify it).
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
    """A trusted job whose run step calls a repository script that itself invokes an agent CLI is
    really an agent job (companion R1-R4). Only scripts readable under `root` are inspected, so this
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
        if job.lane == "trusted":
            reason = _agent_via_script(job, root, commands)
            if reason:
                job.lane, job.lane_reason = "agent", reason


class ConfigError(ValueError):
    pass


@dataclass
class Config:
    lanes: dict = field(default_factory=dict)
    agents: dict = field(default_factory=dict)
    ignore: list = field(default_factory=list)
    path: str | None = None

    @classmethod
    def load(cls, root: Path, explicit: str | None = None) -> "Config":
        candidates = [Path(explicit)] if explicit else [root / rel for rel in CONFIG_LOCATIONS]
        for path in candidates:
            if path.is_file():
                data = yamlutil.load_file(path) or {}
                if not isinstance(data, dict):
                    raise ConfigError(f"{path}: expected a mapping")
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
                return cls(lanes=dict(data.get("lanes") or {}), agents=dict(data.get("agents") or {}),
                           ignore=list(ignore), path=str(path))
        if explicit:
            raise ConfigError(f"config file not found: {explicit}")
        return cls()


@dataclass
class CheckResult:
    findings: list[Finding]
    files: list[str]
    errors: list[str]
    config: Config
    notes: list[str] = field(default_factory=list)

    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def at_or_above(self, severity: str) -> list[Finding]:
        threshold = SEVERITY_ORDER[severity]
        return [f for f in self.active() if SEVERITY_ORDER[f.severity] >= threshold]

    def gating(self, spec: str, catalog: Catalog) -> list[Finding]:
        """Active findings that make `--fail-on spec` fail (empty means it passes)."""
        category, severity = parse_fail_on(spec)
        if severity == "never":
            return []
        threshold = SEVERITY_ORDER[severity]
        out = []
        for f in self.active():
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


def check(target: Path, files: list[Path] | None = None, config: Config | None = None,
          catalog: Catalog | None = None, today: date | None = None) -> CheckResult:
    """Check a repository root (workflows plus repository files) or specific workflow files."""
    catalog = catalog or load()
    target = target.resolve()
    is_repo = files is None
    root = target
    if files is None:
        if target.is_file():
            files, root, is_repo = [target], target.parent, False
        else:
            files = wf_mod.discover(target)
    config = config or Config.load(root)
    script_cmds = _script_commands(catalog, config)
    findings: list[Finding] = []
    errors: list[str] = []
    rels: list[str] = []
    agent_lane_present = False
    suspect_jobs: list[tuple[str, str]] = []
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
            continue
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents)
        _apply_script_detection(workflow, root, script_cmds)
        for job in workflow.jobs.values():
            if job.lane == "agent":
                agent_lane_present = True
            elif job.lane == "trusted" and _AGENT_HINT.search(f"{job.id} {job.name}"):
                suspect_jobs.append((rel, job.id))
        findings.extend(rules_mod.WorkflowRules(workflow, catalog).run())
        errors.extend(f"{rel}: {problem}" for problem in workflow.problems)
    if is_repo:
        findings.extend(rules_mod.repo_findings(root, rels, catalog))
    _apply_ignores(findings, config, today or date.today())
    findings.sort(key=Finding.sort_key)
    notes = _lane_notes(root, catalog, is_repo, agent_lane_present, suspect_jobs)
    return CheckResult(findings=findings, files=rels, errors=errors, config=config, notes=notes)


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
                "agents.commands in .github/obaaf.yml, or set OBAAF_LANE: agent on the job. See "
                "docs/checker-configuration.md.")
    if suspect_jobs:
        shown = "; ".join(f"{w} job '{j}'" for w, j in suspect_jobs[:5])
        more = f", and {len(suspect_jobs) - 5} more" if len(suspect_jobs) > 5 else ""
        notes.append(
            f"{len(suspect_jobs)} job(s) have a name that suggests agent work but stayed in the trusted lane "
            f"({shown}{more}). If any runs an AI agent, declare it with agents.commands or OBAAF_LANE so the agent "
            "controls apply.")
    return notes


def lanes(target: Path, config: Config | None = None) -> list[tuple[str, str, str, str]]:
    """(workflow, job, lane, reason) for every job, to show how the checker classified them."""
    root = target.resolve()
    config = config or Config.load(root)
    script_root = root if root.is_dir() else root.parent
    script_cmds = _script_commands(load(), config)
    out = []
    files = [root] if root.is_file() else wf_mod.discover(root)
    for path in files:
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        workflow = wf_mod.parse(rel, path.read_text(encoding="utf-8", errors="replace"))
        if workflow.error:
            continue
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents)
        _apply_script_detection(workflow, script_root, script_cmds)
        out += [(rel, job.id, job.lane, job.lane_reason) for job in workflow.jobs.values()]
    return out
