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
from obaaf.checker import jenkins as jenkins_mod
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


def check_inputs(root, options, today, catalog):
    """Run the requested check, including its baseline, on a source tree or its copy."""
    target = root / options.path
    if not target.exists():
        raise ProofError(f"check path does not exist: {options.path}")
    try:
        return _read_inputs(root, target, options, today, catalog)
    except (baseline.BaselineError, checker.ConfigError, ProofError) as exc:
        raise ProofError(_input_message(root, exc)) from exc


def _input_message(root, error):
    # Both the source and the temporary tree have the same repository-relative paths.
    # A config error may name the root itself, e.g. for two competing configs.
    message = str(error).replace(str(root) + os.sep, "./")
    if message.startswith(f"{root}:"):
        return "." + message[len(str(root)):]
    return message


def _read_inputs(root, target, options, today, catalog):
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


def check_copy_matches(root, original, before):
    """Before planning or proving, make sure the copy sees the same input and results."""
    if (original.files != before.files or original.findings != before.findings
            or original.baseline_stale != before.baseline_stale or original.coverage != before.coverage
            or original.jenkins != before.jenkins or original.jenkins_files != before.jenkins_files
            or not _equivalent_notes(original.notes, before.notes, (root / ".git").exists())):
        raise ProofError("checker results on the source and unedited copy differ")


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


# The most values one comparison of a document may visit. Aliases are expanded where they are used,
# so a small file can stand for millions of values; past this the candidate is withheld (the same
# limit as the checker's for a workflow file, D-098). Found by the review of #274.
STRUCTURE_LIMIT = 500_000

# Only these documents are compared by structure. A file of any other kind parsed as YAML loses
# everything after " #" as a comment, so a changed shell line could compare equal (review of #274).
DOCUMENT_SUFFIXES = (".yml", ".yaml", ".json")


def _structure(value, path, allowed, budget=None):
    """Compare typed contents while omitting only the keys the candidate named."""
    if budget is None:
        budget = [STRUCTURE_LIMIT]
    budget[0] -= 1
    if budget[0] < 0:
        raise ProofError(f"the document holds more than {STRUCTURE_LIMIT:,} values once its aliases are expanded")
    if isinstance(value, dict):
        return ("map", frozenset(((type(k), k), _structure(v, path + ((type(k), k),), allowed, budget))
                                 for k, v in value.items() if path + ((type(k), k),) not in allowed))
    if isinstance(value, list):
        return ("sequence", tuple(_structure(v, path + ((int, i),), allowed, budget)
                                  for i, v in enumerate(value) if path + ((int, i),) not in allowed))
    try:
        hash(value)
    except TypeError:
        raise ProofError(f"the document holds a value of a kind the proof does not compare "
                         f"({type(value).__name__})") from None
    return type(value), value


def _names_node(doc, key) -> bool:
    """Whether `key`, a path of mapping keys and sequence indexes, names a node of `doc`."""
    node = doc
    for part in key:
        if isinstance(node, dict):
            match = [k for k in node if type(k) is type(part) and k == part]
            if not match:
                return False
            node = node[match[0]]
        elif isinstance(node, list) and type(part) is int:
            if not 0 <= part < len(node):
                return False
            node = node[part]
        else:
            return False
    return True


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
        if rel.suffix.lower() not in DOCUMENT_SUFFIXES:
            raise ProofError(f"the proof compares only YAML or JSON documents, not {str(rel)!r}")
        allowed = {tuple((type(part), part) for part in key) for key in edit.keys}
        removed = {tuple((type(part), part) for part in key) for key in edit.removed}
        added = {tuple((type(part), part) for part in key) for key in edit.added}
        old = yamlutil.load(edit.before.decode("utf-8"))
        new = yamlutil.load(edit.after.decode("utf-8"))
        if not isinstance(old, (dict, list)) or not isinstance(new, (dict, list)):
            raise ProofError(f"the document is not a mapping or a list in {str(rel)!r}")
        # A declared key must name something: one that names nothing would let the comparison
        # vouch for an edit it never looked at (review of #274).
        if (any(not (_names_node(old, k) or _names_node(new, k)) for k in edit.keys)
                or any(not _names_node(old, k) for k in edit.removed)
                or any(not _names_node(new, k) for k in edit.added)):
            raise ProofError(f"a declared key names nothing in {str(rel)!r}")
        if _structure(old, (), allowed | removed) != _structure(new, (), allowed | added):
            raise ProofError(f"structure changed outside the intended keys in {str(rel)!r}")
        path.write_bytes(edit.after)
        touched.add(rel)
        expected[rel] = expected[rel][0], hashlib.sha256(edit.after).digest()


def _source_unchanged(root: Path, edits) -> None:
    """Read each edited file from the source again, last, without following a link at its name.
    The copy was compared with `before` when it was made; the source can change while the checker
    runs, and a change that moves no finding would otherwise go unseen (review of #274)."""
    for edit in edits:
        rel = _relative(root, Path(edit.path))
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            fd = os.open(root / rel, flags)
        except OSError as exc:
            raise ProofError(f"the source of {str(rel)!r} could not be read again after the proof: {exc}") from exc
        try:
            regular = stat.S_ISREG(os.fstat(fd).st_mode)
            # One byte more than expected is enough to see a change; never read a grown file whole.
            now = os.read(fd, len(edit.before) + 1) if regular else b""
            while regular and len(now) <= len(edit.before):
                more = os.read(fd, len(edit.before) + 1 - len(now))
                if not more:
                    break
                now += more
        finally:
            os.close(fd)
        if not regular or now != edit.before:
            raise ProofError(f"the source of {str(rel)!r} changed while the proof ran")


def _read_as_jenkins(root: Path, options: CheckOptions, result, edits) -> None:
    """Withhold an edit to a file that is, or that the repository says is, a Jenkinsfile.
    `jenkins.files` can name a file with any suffix, `.yml` included, and Groovy that also parses as a
    YAML mapping (statement labels) would otherwise be compared as YAML. Decided from the repository,
    not only from what this run's platform and path let the checker read, and by file identity, so
    a link or another spelling of the name is the same file (second and third reviews of #274).
    It uses the Jenkins reader's own name pattern (without its suffix exclusion) and glob match,
    which are private to that module, so that the two cannot drift apart."""
    target = root / options.path
    base = workflow.locate(target)[0] if target.is_dir() else target.parent
    read = set()
    for name in result.jenkins_files:
        try:
            info = (base / name).stat()
        except OSError:
            continue
        read.add((info.st_dev, info.st_ino))
    globs = [str(g) for g in (result.config.jenkins.get("files") or [])]
    try:
        globs += [str(g) for g in (checker.Config.load(root, None).jenkins.get("files") or [])]
    except checker.ConfigError as exc:
        raise ProofError(f"the repository's own configuration could not be read: {_input_message(root, exc)}") from exc
    for edit in edits:
        rel = _relative(root, Path(edit.path))
        path = root / rel
        info = path.stat()
        names = {rel.as_posix()}
        for start in (root, base):
            try:
                names.add(path.resolve().relative_to(start.resolve()).as_posix())
            except ValueError:
                pass
        folded = {n.casefold() for n in names}
        if ((info.st_dev, info.st_ino) in read or jenkins_mod._NAME.match(rel.name)
                or any(jenkins_mod._glob_match(n, g.casefold()) for n in folded for g in globs)):
            raise ProofError(f"{str(rel)!r} is a Jenkinsfile, or the repository names it as one, "
                             "and the proof does not compare Jenkinsfiles")


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
            before = check_inputs(dest, options, today, catalog)
            original = check_inputs(root, options, today, catalog)
            check_copy_matches(root, original, before)
            expected_files = _manifest(dest)
            _read_as_jenkins(dest, options, before, edits)
            _apply(dest, edits, expected_files)
            after = check_inputs(dest, options, today, catalog)
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
            losses = (_rows(f for f in before.findings if f.state == ACCEPTED)
                      - _rows(f for f in after.findings if f.state == ACCEPTED))
            promised_gone = Counter((p.identity, p.severity, p.previous) for p in promises
                                    if p.outcome == "gone" and p.previous == ACCEPTED)
            missing = sum((losses - promised_gone).values())
            if missing:
                raise ProofError(f"{missing} previously accepted finding(s) would lose their acceptance")
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
            _source_unchanged(root, edits)
            return after
    except ProofError:
        raise
    except (OSError, ValueError, RuntimeError, yaml.YAMLError) as exc:
        raise ProofError(str(exc)) from exc
