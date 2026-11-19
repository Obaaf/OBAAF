"""Prove declarative adoption edits on a private copy before the preview can offer them."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import date
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import stat

import yaml

from obaaf import checker, yamlutil
from obaaf.catalog import load
from obaaf.checker import baseline, workflow
from obaaf.checker.rules import ACCEPTED, FIXED, NEW, UNDECIDED
from obaaf.fix_copy import private_copy


class ProofError(ValueError):
    """The preview should withhold this candidate and display the reason."""

    def __str__(self):
        return workflow.one_line(super().__str__(), 1000)


@dataclass(frozen=True)
class CheckOptions:
    """Paths are relative to the supplied repository root, or absolute paths inside it."""

    path: Path = Path(".")
    config: Path | None = None
    baseline: Path | None = None
    platform: str = "auto"
    fail_on: str = "medium"


@dataclass(frozen=True)
class Edit:
    path: Path
    before: bytes
    after: bytes
    # Exact paths in the parsed document. A sequence index is an integer.
    keys: tuple[tuple, ...]
    # Paths present only in the original, e.g. the index of a stale entry removed from a list.
    removed: tuple[tuple, ...] = ()
    added: tuple[tuple, ...] = ()


@dataclass(frozen=True)
class Approval:
    source: str
    owner: str
    reason: str
    expires: str


@dataclass(frozen=True)
class Promise:
    """One occurrence of a checker identity, with its severity and prior state."""

    identity: str
    severity: str
    previous: str
    outcome: str  # "gone" or "accepted"
    approval: Approval | None = None


def _relative(root: Path, path: Path) -> Path:
    candidate = root / path
    if ".." in candidate.parts or not candidate.is_relative_to(root):
        raise ProofError(f"path is outside the private copy: {str(path)!r}")
    relative = candidate.relative_to(root)
    if any(part.casefold() == ".git" for part in relative.parts):
        raise ProofError("excluded Git metadata cannot be a proof input")
    return relative


def _run(root, options, today, catalog):
    target = root / options.path
    base = workflow.locate(target)[0] if target.is_dir() else target.parent
    files = [root / p for p in (options.config, options.baseline) if p is not None]
    config = checker.Config.load(base, str(root / options.config) if options.config is not None else None)
    result = checker.check(target, config=config, platform=options.platform, catalog=catalog,
                           today=today, gate_files=files)
    if result.errors:
        raise ProofError(f"checker could not read every input: {result.errors[0]}")
    if not result.files:
        raise ProofError("checker found no CI files for the requested path and platform")
    if options.baseline is not None:
        baseline.apply(result, baseline.load(root / options.baseline))
    return result


def _equivalent_notes(source, copy, git):
    if source == copy:
        return True
    # The copy has no index. Its directory walk can emit this one advisory about pruning
    # even when its Jenkins files, coverage and every other note match the source exactly.
    prefix = ("Jenkinsfiles were looked for by walking the folders, because git's list of tracked files "
              "was not used (it is not the top of a git work tree); these folders were not entered: ")
    advisory = [n for n in copy if n.startswith(prefix) and n.endswith(". A Jenkinsfile in them was not read.")]
    return git and len(advisory) == 1 and source == [n for n in copy if n != advisory[0]]


def _rows(findings):
    return Counter((baseline.key(f), f.severity, f.state) for f in findings)


def _evidence(findings):
    rows = Counter()
    for f in findings:
        acceptance = json.dumps(f.acceptance.as_dict(), sort_keys=True) if f.acceptance else None
        controls = tuple((c.id, c.name, c.verdict, c.detail) for c in f.controls)
        rows[(baseline.key(f), f.severity, f.state), acceptance, controls] += 1
    return rows


def _approvals(findings):
    rows = Counter()
    for f in findings:
        if f.state == ACCEPTED:
            a = f.acceptance
            rows[(baseline.key(f), f.severity), Approval(a.source, a.owner, a.reason, a.expires)] += 1
    return rows


def _changed_occurrences(difference):
    counts = Counter()
    for (row, _, _), count in difference.items():
        counts[row] += count
    return counts


def _stale_ignore(result):
    for entry in result.config.ignore:
        if not any(f.rule == entry["rule"] and f.rule != checker.IDLE_DECLARATION
                   and fnmatch.fnmatch(f.path, str(entry["path"]))
                   and (not entry.get("job") or entry["job"] == f.job) for f in result.findings):
            return True
    return False


def _manifest(root: Path) -> dict:
    result = {}
    for directory, folders, files in os.walk(root, onerror=_raise):
        for name in folders + files:
            path = Path(directory) / name
            mode = path.lstat().st_mode
            value = None
            if stat.S_ISREG(mode):
                with path.open("rb") as stream:
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: stream.read(131072), b""):
                        digest.update(chunk)
                value = digest.digest()
            elif stat.S_ISLNK(mode):
                value = os.readlink(path)
            elif not stat.S_ISDIR(mode):
                raise ProofError(f"unexpected special file at {str(path.relative_to(root))!r}")
            result[path.relative_to(root)] = mode, value
    return result


def _raise(exc):
    raise exc


def _structure(value, path, allowed):
    """Compare typed contents while omitting only the keys the candidate named."""
    if isinstance(value, dict):
        return ("map", frozenset(((type(k), k), _structure(v, path + ((type(k), k),), allowed))
                                 for k, v in value.items() if path + ((type(k), k),) not in allowed))
    if isinstance(value, list):
        return ("sequence", tuple(_structure(v, path + ((int, i),), allowed)
                                  for i, v in enumerate(value) if path + ((int, i),) not in allowed))
    return type(value), value


def _apply(dest, edits, expected):
    touched = set()
    for edit in edits:
        rel = Path(edit.path)
        path = dest / _relative(dest, rel)
        if rel in touched or rel not in expected or not stat.S_ISREG(expected[rel][0]):
            raise ProofError(f"edit must name one existing regular file once: {str(rel)!r}")
        if path.read_bytes() != edit.before:
            raise ProofError(f"original bytes differ at {str(rel)!r}")
        declared = edit.keys + edit.removed + edit.added
        if edit.before == edit.after or not declared or any(not p for p in declared):
            raise ProofError(f"edit needs changed bytes and named keys at {str(rel)!r}")
        allowed = {tuple((type(part), part) for part in key) for key in edit.keys}
        removed = {tuple((type(part), part) for part in key) for key in edit.removed}
        added = {tuple((type(part), part) for part in key) for key in edit.added}
        old = yamlutil.load(edit.before.decode("utf-8"))
        new = yamlutil.load(edit.after.decode("utf-8"))
        if _structure(old, (), allowed | removed) != _structure(new, (), allowed | added):
            raise ProofError(f"structure changed outside the intended keys in {str(rel)!r}")
        path.write_bytes(edit.after)
        touched.add(rel)
        expected[rel] = expected[rel][0], hashlib.sha256(edit.after).digest()


def prove(root: Path, options: CheckOptions, edits: tuple[Edit, ...], promises: tuple[Promise, ...]):
    """Return the checker result for a proven edit, or raise ProofError with the refusal reason."""
    try:
        root = Path(root).absolute()
        options = CheckOptions(_relative(root, options.path),
                               _relative(root, options.config) if options.config is not None else None,
                               _relative(root, options.baseline) if options.baseline is not None else None,
                               options.platform, options.fail_on)
        checker.parse_fail_on(options.fail_on)
        today = date.today()
        catalog = load()
        with private_copy(root) as dest:
            before = _run(dest, options, today, catalog)
            original = _run(root, options, today, catalog)
            if (original.files != before.files or original.findings != before.findings
                    or original.baseline_stale != before.baseline_stale or original.coverage != before.coverage
                    or original.jenkins != before.jenkins or original.jenkins_files != before.jenkins_files
                    or not _equivalent_notes(original.notes, before.notes, (root / ".git").exists())):
                raise ProofError("checker results on the source and unedited copy differ")
            expected_files = _manifest(dest)
            _apply(dest, edits, expected_files)
            after = _run(dest, options, today, catalog)
            if before.config.jenkins != after.config.jenkins or after.files != before.files:
                raise ProofError("the candidate changes which CI files the checker can read")
            if expected_files != _manifest(dest):
                raise ProofError("the copy differs outside the proposed file edits")
            expected = _rows(before.findings)
            previous_rows = expected.copy()
            approved = Counter()
            for promise in promises:
                old = (promise.identity, promise.severity, promise.previous)
                if promise.previous not in (NEW, UNDECIDED, ACCEPTED, FIXED) or previous_rows[old] <= 0:
                    raise ProofError("the promised finding is absent or has a different state")
                previous_rows[old] -= 1
                expected[old] -= 1
                if promise.outcome == ACCEPTED and promise.previous in (NEW, UNDECIDED):
                    if promise.approval is None:
                        raise ProofError("an acceptance must name its source, owner, reason and expiry")
                    approved[(promise.identity, promise.severity), promise.approval] += 1
                    expected[promise.identity, promise.severity, ACCEPTED] += 1
                elif promise.outcome != "gone" or promise.approval is not None:
                    raise ProofError("unknown or invalid promised finding transition")
            if _rows(after.findings) != +expected:
                raise ProofError("finding changes differ from the promised identities, severities or states")
            if _approvals(after.findings) - _approvals(before.findings) != approved:
                raise ProofError("changed acceptance differs from its promised source, owner, reason or expiry")
            before_detail = _evidence(before.findings)
            after_detail = _evidence(after.findings)
            permitted_old = _rows(before.findings) - previous_rows
            permitted_new = +expected - previous_rows
            if (_changed_occurrences(before_detail - after_detail) - permitted_old
                    or _changed_occurrences(after_detail - before_detail) - permitted_new):
                raise ProofError("an unrelated finding changed its acceptance or control evidence")
            if _rows(after.gating(options.fail_on, catalog)) - _rows(before.gating(options.fail_on, catalog)):
                raise ProofError("a finding newly counts at the selected gate")
            if after.baseline_stale or _stale_ignore(after):
                raise ProofError("a baseline or ignore entry no longer matches a finding")
            return after
    except ProofError:
        raise
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as exc:
        raise ProofError(str(exc)) from exc
