"""The OBAAF pipeline checker (`obaaf check`, FR12).

It reads GitHub Actions workflow files and repository settings that live in
files (CODEOWNERS, agent instruction files) and reports risky settings, each
with the profile requirement it threatens and the fix. It runs locally and
sends nothing over the network (NFR5).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from obaaf import yamlutil
from obaaf.catalog import Catalog, load
from obaaf.checker import rules as rules_mod
from obaaf.checker import workflow as wf_mod
from obaaf.checker.rules import Finding

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
CONFIG_LOCATIONS = (".github/obaaf.yml", ".github/obaaf.yaml", "obaaf.yml")


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

    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    def at_or_above(self, severity: str) -> list[Finding]:
        threshold = SEVERITY_ORDER[severity]
        return [f for f in self.active() if SEVERITY_ORDER[f.severity] >= threshold]


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
    findings: list[Finding] = []
    errors: list[str] = []
    rels: list[str] = []
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
        findings.extend(rules_mod.WorkflowRules(workflow, catalog).run())
        errors.extend(f"{rel}: {problem}" for problem in workflow.problems)
    if is_repo:
        findings.extend(rules_mod.repo_findings(root, rels, catalog))
    _apply_ignores(findings, config, today or date.today())
    findings.sort(key=Finding.sort_key)
    return CheckResult(findings=findings, files=rels, errors=errors, config=config)


def lanes(target: Path, config: Config | None = None) -> list[tuple[str, str, str, str]]:
    """(workflow, job, lane, reason) for every job, to show how the checker classified them."""
    root = target.resolve()
    config = config or Config.load(root)
    out = []
    files = [root] if root.is_file() else wf_mod.discover(root)
    for path in files:
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        workflow = wf_mod.parse(rel, path.read_text(encoding="utf-8", errors="replace"))
        if workflow.error:
            continue
        wf_mod.classify(workflow, overrides=config.lanes, extra_agents=config.agents)
        out += [(rel, job.id, job.lane, job.lane_reason) for job in workflow.jobs.values()]
    return out
