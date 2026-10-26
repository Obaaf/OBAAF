"""The Jenkins adapter of `obaaf check` (advisory).

It finds Jenkinsfiles, parses them with a syntax-only parser that never compiles or runs Groovy
(parser.py), builds a model of stages, credentials, agents and conditions (model.py), and applies
the OBAAF-JEN rules (rules.py). Every file gets a coverage result per rule: pass, fail, unknown or
not applicable. Unknown means the Jenkinsfile alone cannot settle the question, usually because the
answer lives in controller configuration or in shared-library code; it is never reported as a pass.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from obaaf.catalog import Catalog
from obaaf.checker.jenkins import model as model_mod
from obaaf.checker.jenkins import parser as parser_mod
from obaaf.checker.jenkins import rules as rules_mod
from obaaf.checker.jenkins.model import CR_NO, CR_POSSIBLE, CR_YES
from obaaf.checker.jenkins.rules import ALL, RULES, Unknown, stage_label

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "Library", "Intermediate", "Saved",
             "DerivedDataCache", ".godot", "Binaries", "build", "dist", "target", ".gradle", ".idea", "vendor"}
MAX_DEPTH = 6
_NAME = re.compile(r"^(jenkinsfile([._-].+)?|.+\.jenkinsfile)$", re.I)
_AGENT_HINT = re.compile(r"agent|copilot|claude|gemini|codex|aider|opencode|cline|\bllm\b|\bai[-_ ]|autofix|auto[- ]fix",
                         re.I)


def is_jenkinsfile(path: Path) -> bool:
    return bool(_NAME.match(path.name)) and path.suffix.lower() not in (
        ".md", ".txt", ".html", ".png", ".svg", ".yml", ".yaml", ".json", ".xml", ".properties", ".orig", ".bak")


def discover(root: Path, globs: list[str] | None = None, exclude: list[str] | None = None) -> list[Path]:
    """Jenkinsfiles under root: `Jenkinsfile`, `Jenkinsfile.<x>`, `Jenkinsfile-<x>` and `<x>.jenkinsfile`
    at any depth up to MAX_DEPTH, plus files matching the configured globs (jenkins.files), minus
    those matching jenkins.exclude (for example test fixtures)."""
    root = root.resolve()
    globs = [g for g in (globs or []) if isinstance(g, str) and g.strip()]
    exclude = [g for g in (exclude or []) if isinstance(g, str) and g.strip()]
    found: set[Path] = set()
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root):
        here = Path(dirpath)
        depth = len(here.parts) - base_depth
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (depth >= MAX_DEPTH))
        for name in filenames:
            path = here / name
            rel = path.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, g) for g in exclude):
                continue
            if is_jenkinsfile(path) or any(fnmatch.fnmatch(rel, g) for g in globs):
                if path.is_file() and not path.is_symlink():
                    found.add(path)
    return sorted(found)


@dataclass
class FileResult:
    path: str
    digest: str
    kind: str | None = None
    findings: list = field(default_factory=list)
    unknowns: list = field(default_factory=list)
    applicable: set = field(default_factory=set)
    error: str | None = None
    agent_present: bool = False
    suspect_stages: list = field(default_factory=list)
    lanes: list = field(default_factory=list)       # (stage, lane, reason)


def analyze(rel: str, data: bytes, catalog: Catalog, root: Path | None, extra_agents: dict | None = None,
            lane_overrides: dict | None = None) -> FileResult:
    result = FileResult(path=rel, digest="sha256:" + hashlib.sha256(data).hexdigest())
    text = data.decode("utf-8", errors="replace")
    parsed = parser_mod.parse(text)
    if parsed.error:
        result.error = parsed.error
        return result
    pipeline = model_mod.build(parsed.tree)
    result.kind = pipeline.kind
    engine = rules_mod.JenkinsRules(rel, pipeline, catalog, root, extra_agents, lane_overrides)
    result.findings, result.unknowns, result.applicable = engine.run()
    stages: dict[tuple, list] = {}
    for info in engine.infos:
        stages.setdefault(info.ctx.stage, []).append(info)
    for stage, infos in stages.items():
        ai = next((i for i in infos if i.ai), None)
        pub = next((i for i in infos if i.publish), None)
        crs = {i.ctx.cr for i in infos if i.runs_code}
        if ai:
            lane, reason = "agent", ai.ai
        elif pub:
            lane, reason = "release", f"publishes ({pub.publish})"
        elif crs & {CR_YES, CR_POSSIBLE}:
            lane, reason = "untrusted", ("runs for change requests" if CR_YES in crs else
                                         "nothing keeps change requests out")
        elif crs and crs <= {CR_NO}:
            lane, reason = "trusted", "change requests do not reach it"
        else:
            lane, reason = "unknown", "its condition cannot be evaluated" if crs else "runs no build code"
        result.lanes.append((stage_label(stage), lane, reason))
        if ai:
            result.agent_present = True
        elif stage and _AGENT_HINT.search(" ".join(stage)):
            result.suspect_stages.append(stage_label(stage))
    return result


def coverage(result: FileResult, findings: list) -> list[dict]:
    """Per rule: fail (an active finding), ignored (findings all suppressed by configuration),
    unknown (the file cannot settle it), pass (applicable and nothing found), or not applicable."""
    out = []
    mine = [f for f in findings if f.path == result.path and f.rule.startswith("OBAAF-JEN-")]
    if result.error:
        return [{"path": result.path, "platform": "jenkins", "rule": rule, "status": "unknown",
                 "reasons": [f"the file was not analyzed: {result.error}"]} for rule in RULES]
    general = [u for u in result.unknowns if u.rule == ALL]
    for rule in RULES:
        active = [f for f in mine if f.rule == rule and not f.suppressed]
        suppressed = [f for f in mine if f.rule == rule and f.suppressed]
        reasons = [f"line {u.line}: {u.reason}" for u in result.unknowns if u.rule == rule] + \
                  [f"line {u.line}: {u.reason}" for u in general]
        if active:
            status = "fail"
        elif suppressed:
            status = "ignored"
        elif reasons:
            status = "unknown"
        elif rule in result.applicable:
            status = "pass"
        else:
            status = "not applicable"
        out.append({"path": result.path, "platform": "jenkins", "rule": rule, "status": status,
                    "reasons": list(dict.fromkeys(reasons))})
    return out


def summary(result: FileResult) -> dict:
    """File-level facts for the report: what was analyzed (by digest) and what stops any rule from passing."""
    general = list(dict.fromkeys(f"line {u.line}: {u.reason}" for u in result.unknowns if u.rule == ALL))
    return {"path": result.path, "platform": "jenkins", "kind": result.kind, "digest": result.digest,
            "error": result.error, "unknowns": general, "lanes": [
                {"stage": stage, "lane": lane, "reason": reason} for stage, lane, reason in result.lanes]}


__all__ = ["ALL", "FileResult", "RULES", "Unknown", "analyze", "coverage", "discover", "is_jenkinsfile", "summary"]
