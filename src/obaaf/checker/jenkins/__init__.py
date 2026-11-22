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
from obaaf.checker.workflow import IdleDeclaration, bounded, declared_lane, one_line

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "Library", "Intermediate", "Saved",
             "DerivedDataCache", ".godot", "Binaries", "build", "dist", "target", ".gradle", ".idea", "vendor"}
MAX_DEPTH = 6
# `Jenkinsfile`, `Jenkinsfile.<x>`, `Jenkinsfile-<x>`, `Jenkinsfile_<x>`, `Jenkinsfile<x>` (Jenkinsfile2,
# JenkinsfileRelease), and `<x>.jenkinsfile`, `<x>-jenkinsfile`, `<x>_jenkinsfile`, in any letter case.
_NAME = re.compile(r"^(jenkinsfile([._-].+|[a-z0-9]+)?|.+[._-]jenkinsfile)$", re.I)
_REFUSED_SUFFIXES = (".md", ".txt", ".html", ".png", ".svg", ".yml", ".yaml", ".json", ".xml", ".properties",
                     ".orig", ".bak")
_AGENT_HINT = re.compile(r"agent|copilot|claude|gemini|codex|aider|opencode|cline|\bllm\b|\bai[-_ ]|autofix|auto[- ]fix",
                         re.I)


def is_jenkinsfile(path: Path) -> bool:
    return bool(_NAME.match(path.name)) and path.suffix.lower() not in _REFUSED_SUFFIXES


def _glob_match(rel: str, glob: str) -> bool:
    """fnmatch, where `**/` also matches no folder at all (`ci/**/*.groovy` matches `ci/x.groovy`)."""
    if fnmatch.fnmatch(rel, glob):
        return True
    parts = glob.split("**/")
    if len(parts) == 1 or len(parts) > 8:
        return False
    for mask in range(1, 2 ** (len(parts) - 1)):
        candidate = parts[0]
        for i, part in enumerate(parts[1:]):
            candidate += ("" if mask >> i & 1 else "**/") + part
        if fnmatch.fnmatch(rel, candidate):
            return True
    return False


def _shown(names: list[str], limit: int = 5) -> str:
    out = ", ".join(one_line(n, 120) for n in names[:limit])
    return out + (f" and {len(names) - limit} more" if len(names) > limit else "")


def discover(root: Path, globs: list[str] | None = None, exclude: list[str] | None = None,
             notes: list | None = None, errors: list | None = None) -> list[Path]:
    """Jenkinsfiles under root, by name (see `_NAME`) or by the configured globs (jenkins.files), minus
    those matching jenkins.exclude (for example test fixtures).

    In a git work tree every file git lists (tracked, or not committed and not ignored) is looked at, in
    any folder and at any depth: which file a Jenkins job runs is set on the controller and can be any
    path (flagship slice 2d.2i; folders such as `build/` and `vendor/` and files below six folders were
    skipped without a word). Elsewhere the folders are walked as before, skipping SKIP_DIRS and stopping
    at MAX_DEPTH, and the folders not entered are named in a note. A
    Jenkinsfile that is a link is read when it leads to a file inside the repository, and is an error
    otherwise. What is left out (by its suffix, by jenkins.exclude, by the walk, or a glob that matches
    nothing) is said in `notes`."""
    from obaaf.checker import repo as repo_mod
    root = root.resolve()
    notes = notes if notes is not None else []
    errors = errors if errors is not None else []
    globs = [g for g in (globs or []) if isinstance(g, str) and g.strip()]
    exclude = [g for g in (exclude or []) if isinstance(g, str) and g.strip()]
    how: dict = {}
    tracked = repo_mod._git_tracked(root, how)
    listed: set[str] = set(tracked or [])
    if tracked is not None:
        # Files not committed yet and not ignored count too: a new Jenkinsfile is checked before it is
        # committed, in whatever folder it is.
        git = repo_mod.find_git(root)
        others = repo_mod._run_git(git, root, "ls-files", "-z", "--others", "--exclude-standard") if git else None
        if others is None:
            tracked = None
            how["why"] = "git did not list the files that are not committed"
        else:
            listed.update(p.decode("utf-8", "surrogateescape") for p in others.split(b"\0") if p)
    pruned: set[str] = set()
    base_depth = len(root.parts)
    for dirpath, dirnames, filenames in ([] if tracked is not None else os.walk(root)):
        here = Path(dirpath)
        depth = len(here.parts) - base_depth
        for d in dirnames:
            if d != ".git" and (d in SKIP_DIRS or depth >= MAX_DEPTH):
                pruned.add((here / d).relative_to(root).as_posix())
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not (depth >= MAX_DEPTH))
        for name in filenames:
            listed.add((here / name).relative_to(root).as_posix())
    # A configured name with no wildcard is looked at even where the walk does not go, if it is a path inside
    # the repository (the review of slice 2d.2i: `../x` and `/etc/passwd` were read).
    for g in globs:
        if any(c in g for c in "*?["):
            continue
        rel_g = Path(g)
        if rel_g.is_absolute() or ".." in rel_g.parts:
            errors.append(f"jenkins.files names '{one_line(g, 120)}', which is not a path inside the repository; "
                          "it was not read")
            continue
        if (root / rel_g).exists() or (root / rel_g).is_symlink():
            listed.add(rel_g.as_posix())
    found: set[Path] = set()
    refused_suffix: list[str] = []
    excluded: list[str] = []
    matched_globs: set[str] = set()
    for rel in sorted(listed):
        path = root / rel
        by_glob = [g for g in globs if _glob_match(rel, g)]
        matched_globs.update(by_glob)
        named = bool(_NAME.match(path.name))
        if not by_glob and not named:
            continue
        if not by_glob and path.suffix.lower() in _REFUSED_SUFFIXES:
            refused_suffix.append(rel)
            continue
        if any(_glob_match(rel, g) for g in exclude):
            excluded.append(rel)
            continue
        try:
            # The file itself, or a folder on its way, may be a link: what is read must be a file in the repository.
            target = path.resolve()
            try:
                target.relative_to(root)
                inside = True
            except ValueError:
                inside = False
            if not inside or (path.is_symlink() and not target.is_file()):
                errors.append(f"{one_line(rel, 120)}: not read: it is a link, or under one, that does not lead to a "
                              "file inside the repository, and Jenkins may run it")
                continue
            if path.is_file():
                found.add(path)
        except OSError as exc:
            errors.append(f"{one_line(rel, 120)}: cannot be read: {exc}")
    if refused_suffix:
        notes.append(f"Not read as Jenkinsfiles because of their suffix: {_shown(refused_suffix)}. If Jenkins "
                     "runs one of them, add it to jenkins.files.")
    if excluded:
        notes.append(f"Left out by jenkins.exclude: {_shown(excluded)}.")
    for g in globs:
        if g not in matched_globs:
            notes.append(f"jenkins.files pattern '{one_line(g, 120)}' matched no file.")
    if tracked is None and pruned:
        why = how.get("why", "it is not the top of a git work tree")
        notes.append(f"Jenkinsfiles were looked for by walking the folders, because git's list of tracked files "
                     f"was not used ({why}); these folders were not entered: {_shown(sorted(pruned))}. A "
                     "Jenkinsfile in them was not read.")
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
    stage_keys: set = field(default_factory=set)    # the names a `lanes:` entry may give a stage
    lane_problems: list = field(default_factory=list)   # IdleDeclaration: OBAAF_LANE values that name no lane


def analyze(rel: str, data: bytes, catalog: Catalog, root: Path | None, extra_agents: dict | None = None,
            lane_overrides: dict | None = None) -> FileResult:
    result = FileResult(path=rel, digest="sha256:" + hashlib.sha256(data).hexdigest())
    text = data.decode("utf-8", errors="replace")
    # Groovy ends a line at CR LF, LF or a lone CR. The lexer reads LF, so a file with lone-CR line ends
    # was one long line, and a `//` comment on its first line hid the whole pipeline (flagship slice 2d.2i).
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    parsed = parser_mod.parse(text)
    if parsed.error:
        result.error = parsed.error
        return result
    try:
        pipeline = model_mod.build(parsed.tree)
        pipeline.source = text
        engine = rules_mod.JenkinsRules(rel, pipeline, catalog, root, extra_agents, lane_overrides)
        findings, unknowns, applicable = engine.run()
    except RecursionError:
        result.error = "not analyzed: the pipeline is nested too deeply to model"
        return result
    except Exception as exc:     # fail closed: one file the model cannot handle must not stop the others
        result.error = f"not analyzed: internal error while modelling the pipeline ({type(exc).__name__})"
        return result
    result.kind = pipeline.kind
    result.findings, result.unknowns, result.applicable = findings, unknowns, applicable
    stages: dict[tuple, list] = {}
    for info in engine.infos:
        stages.setdefault(info.ctx.stage, []).append(info)
    # A stage with no step the model records is still a stage a `lanes:` entry may name.
    for stage in pipeline.stages:
        result.stage_keys.update(key[len(rel) + 1:] for key in engine.lane_keys(stage)[1:])
    reached: dict[tuple, list] = {}     # (value, line) of an OBAAF_LANE -> the stages whose steps it reaches
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
        # Each key is the file, a `#` and a name for the stage. The file's own name may hold a `#`.
        result.stage_keys.update(key[len(rel) + 1:] for key in engine.lane_keys(stage)[1:])
        for pair in dict.fromkeys(pair for info in infos for pair in info.ctx.lanes):
            # Not `stage_label`, which calls the steps outside any stage "pipeline": a stage may be named that.
            reached.setdefault(pair, []).append(" > ".join(stage))
        if ai:
            result.agent_present = True
        elif stage and _AGENT_HINT.search(" ".join(stage)):
            result.suspect_stages.append(stage_label(stage))
    for (value, line), labels in reached.items():
        # One finding for each declaration, not one for each stage it reaches. The stages are part of
        # what the finding is: the same value moved to another stage is another finding.
        where = {"path": rel, "line": line, "stages": tuple(sorted(dict.fromkeys(labels)))}
        if value is None:
            result.lane_problems.append(IdleDeclaration(kind="jenkins-computed", **where))
        elif declared_lane(value) is None:
            result.lane_problems.append(IdleDeclaration.of("jenkins-not-a-lane", value, **where))
    for kind, name, value, line, stage in dict.fromkeys(pipeline.unread_lanes):
        # Flagship slice 2d.2f: the variable under another spelling, and an assignment to env in a script.
        result.lane_problems.append(IdleDeclaration.of(
            kind, value if value is not None else "a value computed when the build runs", path=rel, line=line,
            stages=(stage,), name=bounded(name), name_shown=one_line(name, 60)))
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
