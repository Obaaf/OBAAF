"""`python -m obaaf.result`: a result file to send back, holding counts and nothing from the repository.

Flagship slice 3.8. Someone asked to try OBAAF runs `obaaf check` (and, if they like, `obaaf audit`)
on a repository of theirs, reads the reports, and sends back this file. The reports name files, jobs,
steps, secrets, environments, owners and lines of the workflows; this file names none of them.

What it holds, and nothing else:

- OBAAF's version, today's date, the Python version and the operating system's family;
- how long the check took;
- what the check was given (whether a configuration file and a baseline were read, the `--fail-on`
  and `--platform` values) and the exit status `obaaf check` ends with for them;
- how many files were checked, how many could not be read, and how many notes the report has;
- how many jobs (and Jenkins stages) are in each lane, with the configuration and without it;
- how many findings of each rule there are, at each severity, in each state; how the controls of each
  finding that lists them were judged; how much risk is accepted, and how many owners accept it;
- from an `obaaf audit --format json` report given with `--audit`: each settings rule's status and
  counts, and for each setting OBAAF reads, whether it was read and, if not, the reason's code; whether
  a token was used and which of the five repository roles GitHub said it has; the repository's
  visibility and the kind of account that owns it.

How that is kept: the file is built only from integers, booleans and strings of OBAAF's own vocabulary
(rule ids from its catalogue, severities, states, verdicts, lanes, setting names, reason codes), and
before it is written every key and every string in it is checked against that vocabulary. A string from
anywhere else (a path, a job's name, a message, a secret's name, an owner) fails the check, and then
nothing is written and the command ends with 2. A value read from a report that is not in the
vocabulary is counted as `other`.
"""

from __future__ import annotations

import argparse
import json
import platform as platform_mod
import re
import stat
import sys
import tempfile
import time
from collections import Counter
from datetime import date
from pathlib import Path

FORMAT = "obaaf-result/v0.1"
CHECK_FORMAT = "obaaf-check/v0.1"
AUDIT_FORMAT = "obaaf-settings-audit/v0.1"
EXIT_OK, EXIT_USAGE = 0, 2
OTHER = "other"

ABOUT = ("Counts from obaaf check, and from obaaf audit if it was given, with no file, job, step, secret, "
         "environment, owner or other text from the repository. See docs/send-us-the-result.md.")

SEVERITIES = ("high", "medium", "low", "info")
STATES = ("new", "accepted", "fixed", "cannot-tell")
VERDICTS = ("verified", "not met", "cannot tell")
CONTROL_IDS = ("secrets-protected", "environment-restricted", "no-outsider-input", "egress-enforced",
               "key-out-of-reach")
LANES = ("agent", "effect", "release", "untrusted", "trusted", "unknown")
PLATFORMS = ("auto", "github", "jenkins")
SYSTEMS = ("linux", "darwin", "windows")
CATEGORIES = ("authority", "hygiene")
ACCEPTANCE_SOURCES = ("baseline", "ignore")
AUDIT_RULE_STATUSES = ("findings", "cannot-tell", "no-finding", "not-applicable")
AUDIT_STATES = ("finding", "cannot-tell")
SETTING_STATUSES = ("read", "partial", "unread", "not_applicable")
ROLES = ("admin", "maintain", "push", "triage", "pull")
VISIBILITIES = ("public", "private", "internal")
OWNER_TYPES = ("User", "Organization")

# Strings that are not from a fixed list, each matched whole. None of them can hold a path or a name.
# ASCII digits only: `\d` would also match the digits of every other script (review of slice 3.8).
VERSION_RE = re.compile(r"\Aobaaf [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:(?:\.dev|a|b|rc)[0-9]{1,3})?\Z")
DATE_RE = re.compile(r"\A[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
PYTHON_RE = re.compile(r"\A3\.[0-9]{1,2}\Z")
BASELINE_FORMAT_RE = re.compile(r"\Aobaaf-baseline/v[0-9]{1,2}\.[0-9]{1,2}\Z")
# Every number in the file is below this. A count from a report is a count; a number this large could
# carry a token's bytes from a report someone altered (review of slice 3.8).
LARGEST = 10**6

# Every key the file can have. A key outside this set fails the check before writing.
KEYS = frozenset({
    "format", "about", "tool", "date", "python", "system", "check", "audit",
    # check
    "seconds", "exit", "failOn", "platform", "configuration", "baseline", "files", "checked", "jenkinsfiles",
    "notRead", "notes", "jobs", "withConfiguration", "withoutConfiguration", "workflowJobs", "jenkinsStages",
    "summary", "new", "accepted", "cannotTell", "fixed", "notAccepted", "acceptedRisk", "total", "bySeverity",
    "bySource", "owners", "daysToNearestExpiry", "expiringSoon", "findings", "controls", "rule", "severity",
    "state", "count", "control", "verdict", "used", "stale", "lanesNotCounted",
    *SEVERITIES, *ACCEPTANCE_SOURCES, *LANES, OTHER,
    # audit
    "rules", "status", "failed", "results", "settings", "setting", "reason", "token", "roles", "visibility",
    "ownerType", "rulesCannotTell", "rulesFailed", "drift", *ROLES,
})


class NotSendable(ValueError):
    """The file would hold something outside OBAAF's vocabulary, so it is not written."""


def _rule_ids() -> frozenset:
    from obaaf.audit.rules import RULES
    from obaaf.catalog import load
    return frozenset(load().rules) | frozenset(rule.id for rule in RULES)


def _setting_keys() -> tuple:
    from obaaf.audit.settings import SETTINGS
    return tuple(s.key for s in SETTINGS)


def _reason_codes() -> tuple:
    from obaaf.audit.settings import REASONS
    return tuple(REASONS)


def vocabulary() -> frozenset:
    """Every string the file may hold apart from those the patterns above match."""
    return frozenset({FORMAT, ABOUT, OTHER, "never", *SEVERITIES, *STATES, *VERDICTS, *CONTROL_IDS, *LANES,
                      *PLATFORMS, *SYSTEMS, *CATEGORIES, *(f"{c}:{s}" for c in CATEGORIES for s in SEVERITIES),
                      *AUDIT_RULE_STATUSES, *AUDIT_STATES, *SETTING_STATUSES, *VISIBILITIES, *OWNER_TYPES,
                      *_rule_ids(), *_setting_keys(), *_reason_codes()})


def _allowed_string(value: str, words: frozenset) -> bool:
    return value in words or any(p.match(value) for p in (VERSION_RE, DATE_RE, PYTHON_RE, BASELINE_FORMAT_RE))


def check_sendable(value, words: frozenset | None = None, where: str = "the file") -> None:
    """Raise NotSendable unless every key is in KEYS, every string is OBAAF's own and every other value
    is a number, a boolean or null. Lists and objects are walked; nothing else is allowed."""
    words = vocabulary() if words is None else words
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if not -LARGEST < value < LARGEST:
            raise NotSendable(f"{where} is a number of {LARGEST:,} or more, which no count in the file reaches")
        return
    if isinstance(value, float):
        if value != value or not -LARGEST < value < LARGEST:
            raise NotSendable(f"{where} is not a finite number below {LARGEST:,}")
        return
    if isinstance(value, str):
        if not _allowed_string(value, words):
            raise NotSendable(f"{where} holds a string that is not one of OBAAF's own")
        return
    if isinstance(value, list):
        for n, item in enumerate(value):
            check_sendable(item, words, f"{where}[{n}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or key not in KEYS:
                raise NotSendable(f"{where} has a key that is not one of the result file's")
            check_sendable(item, words, f"{where}.{key}")
        return
    raise NotSendable(f"{where} holds a value of type {type(value).__name__}")


# --- reading the reports ---------------------------------------------------------------------------

def _word(value, allowed) -> str:
    """`value` if it is one of `allowed`, else `other`."""
    return value if isinstance(value, str) and value in allowed else OTHER


def _count(value) -> int:
    """A count from a report: a non-negative integer, else 0 (a report is read, not trusted)."""
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _length(value) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _rule(value, rule_ids: frozenset) -> str:
    return value if isinstance(value, str) and value in rule_ids else OTHER


def _rows(counter: Counter, fields: tuple) -> list:
    """A counter of tuples as a sorted list of objects, one per tuple, with its count."""
    return [dict(zip(fields, key), count=n) for key, n in sorted(counter.items(), key=lambda kv: tuple(map(str, kv[0])))]


def summarize_check(doc: dict, rule_ids: frozenset) -> dict:
    """The counts in an `obaaf check --format json` report."""
    if not isinstance(doc, dict) or doc.get("format") != CHECK_FORMAT:
        raise ValueError(f"not an {CHECK_FORMAT} report")
    summary = _dict(doc.get("summary"))
    risk = _dict(doc.get("acceptedRisk"))
    findings = Counter()
    controls = Counter()
    for f in _list(doc.get("findings")):
        f = _dict(f)
        rule = _rule(f.get("rule"), rule_ids)
        findings[(rule, _word(f.get("severity"), SEVERITIES), _word(f.get("state"), STATES))] += 1
        for c in _list(f.get("controls")):
            c = _dict(c)
            controls[(rule, _word(c.get("id"), CONTROL_IDS), _word(c.get("verdict"), VERDICTS))] += 1
    fixed = Counter((_rule(_dict(f).get("rule"), rule_ids), _word(_dict(f).get("severity"), SEVERITIES))
                    for f in _list(doc.get("fixed")))
    jenkins = _dict(doc.get("jenkins"))
    out = {
        "files": {"checked": _length(doc.get("files")), "jenkinsfiles": _length(jenkins.get("files")),
                  "notRead": _length(doc.get("errors"))},
        "notes": _length(doc.get("notes")),
        "summary": {key: _count(summary.get(key)) for key in ("new", "accepted", "cannotTell", "fixed",
                                                                "notAccepted")},
        "acceptedRisk": {
            "total": _count(risk.get("total")),
            "bySeverity": {s: _count(_dict(risk.get("bySeverity")).get(s)) for s in SEVERITIES},
            "bySource": {s: _count(_dict(risk.get("bySource")).get(s)) for s in ACCEPTANCE_SOURCES},
            "owners": _length(risk.get("owners")),
            "daysToNearestExpiry": (risk.get("daysToNearestExpiry")
                                    if isinstance(risk.get("daysToNearestExpiry"), int)
                                    and not isinstance(risk.get("daysToNearestExpiry"), bool) else None),
            "expiringSoon": _count(_dict(risk.get("expiringSoon")).get("total")),
        },
        "findings": _rows(findings, ("rule", "severity", "state")),
        "controls": _rows(controls, ("rule", "control", "verdict")),
        "fixed": _rows(fixed, ("rule", "severity")),
    }
    if "baseline" in doc:
        base = _dict(doc.get("baseline"))
        fmt = base.get("format")
        out["baseline"] = {"used": True, "stale": _length(base.get("stale")),
                           "format": fmt if isinstance(fmt, str) and BASELINE_FORMAT_RE.match(fmt) else OTHER}
    return out


def summarize_audit(doc: dict, rule_ids: frozenset) -> dict:
    """The counts in an `obaaf audit --format json` report."""
    if not isinstance(doc, dict) or doc.get("format") != AUDIT_FORMAT:
        raise ValueError(f"not an {AUDIT_FORMAT} report (write one with obaaf audit --format json)")
    summary = _dict(doc.get("summary"))
    snapshot = _dict(doc.get("snapshot"))
    settings = _dict(snapshot.get("settings"))
    viewer = _dict(snapshot.get("viewer"))
    roles = _dict(viewer.get("repository_permissions"))
    repository = _dict(_dict(settings.get("repository")).get("value"))
    # One row for each rule id, so the number of rows is bounded by the vocabulary however long the
    # report's list is (second review of slice 3.8). A rule listed twice is added up, and its status is
    # `other` unless both say the same.
    by_rule: dict = {}
    for r in _list(doc.get("rules")):
        r = _dict(r)
        rule, status = _rule(r.get("id"), rule_ids), _word(r.get("status"), AUDIT_RULE_STATUSES)
        row = by_rule.setdefault(rule, {"rule": rule, "status": status, "findings": 0, "cannotTell": 0,
                                        "failed": False})
        if row["status"] != status:
            row["status"] = OTHER
        row["findings"] += _count(r.get("findings"))
        row["cannotTell"] += _count(r.get("cannot_tell"))
        row["failed"] = row["failed"] or r.get("failed") is True
    rules = list(by_rule.values())
    results = Counter((_rule(_dict(r).get("rule"), rule_ids), _word(_dict(r).get("state"), AUDIT_STATES),
                       _word(_dict(r).get("severity"), SEVERITIES) if _dict(r).get("severity") is not None else None)
                      for r in _list(doc.get("results")))
    keys, codes = _setting_keys(), _reason_codes()
    seen = []
    for key in keys:
        entry = _dict(settings.get(key))
        status = _word(entry.get("status"), SETTING_STATUSES) if entry else None
        code = entry.get("reason_code")
        seen.append({"setting": key, "status": status,
                     "reason": None if code is None else _word(code, codes)})
    unknown = [k for k in settings if k not in keys]
    if unknown:
        seen.append({"setting": OTHER, "status": OTHER, "reason": None, "count": len(unknown)})
    tool = snapshot.get("tool")
    out = {
        "tool": tool if isinstance(tool, str) and VERSION_RE.match(tool) else OTHER,
        "summary": {"findings": _count(summary.get("findings")), **{s: _count(summary.get(s)) for s in
                                                                      ("high", "medium", "low")},
                    "cannotTell": _count(summary.get("cannot_tell")),
                    "rulesCannotTell": _count(summary.get("rules_cannot_tell")),
                    "rulesFailed": _count(summary.get("rules_failed"))},
        "rules": rules,
        "results": _rows(results, ("rule", "state", "severity")),
        "settings": seen,
        "token": {"used": viewer.get("authenticated") is True,
                  "roles": {role: roles.get(role) is True for role in ROLES}},
        "visibility": _word(repository.get("visibility"), VISIBILITIES) if repository else None,
        "ownerType": _word(repository.get("owner_type"), OWNER_TYPES) if repository else None,
    }
    if "drift" in doc:
        out["drift"] = {"used": True}
    return out


def _lane_counts(target: Path, base: Path, config_path: str | None, platform: str) -> dict:
    """How many jobs and Jenkins stages are in each lane, with the configuration and without it."""
    from obaaf import checker

    def tally(config, which: str) -> Counter:
        if platform not in ("auto", which):
            return Counter()
        # Workflows and Jenkinsfiles are listed in separate runs, so a job is never taken for a stage
        # by its name (a workflow job may be called `stage deploy`; review of slice 3.8).
        rows = checker.lanes(target, config, platform=which, notes=[], errors=[], seen=[])
        return Counter(_word(lane, LANES) for _, _, lane, _ in rows)

    def counts(config) -> dict:
        jobs, stages = tally(config, "github"), tally(config, "jenkins")
        return {"workflowJobs": {lane: jobs.get(lane, 0) for lane in LANES if lane != "unknown"}
                | ({OTHER: jobs[OTHER]} if jobs.get(OTHER) else {}),
                "jenkinsStages": {lane: stages.get(lane, 0) for lane in LANES}
                | ({OTHER: stages[OTHER]} if stages.get(OTHER) else {})}

    configured = checker.Config.load(base, config_path)
    return {"withConfiguration": counts(configured), "withoutConfiguration": counts(checker.Config())}


# --- the command -----------------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m obaaf.result",
        description="Run obaaf check on a repository and write a result file to send back: counts only, with no "
                    "file, job, step, secret, environment, owner or other text from the repository. Read it before "
                    "you send it. See docs/send-us-the-result.md.")
    p.add_argument("path", nargs="?", default=".", help="the repository to check (default: .)")
    p.add_argument("--output", "-o", required=True, metavar="FILE",
                   help="where to write the result file. A file there is replaced, and removed if the command "
                        "fails, so it never holds an earlier run's result")
    p.add_argument("--audit", metavar="FILE",
                   help="also count what a report written by obaaf audit --format json found")
    p.add_argument("--config", help="the checker configuration your CI gives obaaf check, if it names one")
    p.add_argument("--baseline", metavar="FILE", help="the baseline your CI gives obaaf check, if any")
    p.add_argument("--fail-on", default="medium", help="the --fail-on your CI gives obaaf check (default: medium)")
    p.add_argument("--platform", choices=PLATFORMS, default="auto")
    return p


def _repository_root(target: Path) -> Path:
    """The directory to keep the result file out of: the top of the git work tree the check's base is in
    (`.git` there), or the base itself where there is none. The base is the one `obaaf check` uses: the
    repository root it finds above a workflows directory, or a file's own directory."""
    from obaaf.checker import workflow as wf_mod
    base = target.parent if target.is_file() else target
    if target.is_dir():
        base, _ = wf_mod.locate(target)
    base = base.resolve()
    for folder in (base, *base.parents):
        if (folder / ".git").exists():
            return folder
    return base


def _inside(output: Path, root: Path) -> bool:
    """Whether `output` would be written in `root` or under it. Compared as files, not as names, so a
    symlink or a different letter case on a case-insensitive disk does not get past it."""
    import os
    where = output.resolve().parent
    for folder in (where, *where.parents):
        if folder.exists() and os.path.samefile(folder, root):
            return True
    return False


def _fail_on_word(value: str) -> str:
    from obaaf.checker import parse_fail_on
    try:
        category, severity = parse_fail_on(value)
    except ValueError:
        return OTHER
    if severity == "never":
        return "never"
    return f"{category}:{severity}" if category else severity


def _system() -> str:
    return _word(platform_mod.system().lower(), SYSTEMS)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from obaaf import cli, checker

    audit = None
    rule_ids = _rule_ids()
    output = Path(args.output)
    if output.is_dir():
        print(f"error: --output {args.output} is a directory; name a file", file=sys.stderr)
        return EXIT_USAGE
    target = Path(args.path)
    # Mistakes in what was typed are refused before anything is removed. A file already at --output is
    # then left as it is, and the message says it is not this run's.
    left = (f" {args.output} was left as it was: it is not this run's result, so do not send it."
            if output.is_file() else "")
    if not target.exists():
        print(f"error: {args.path} not found, so no result file was written.{left}", file=sys.stderr)
        return EXIT_USAGE
    from obaaf.checker import parse_fail_on
    try:
        parse_fail_on(args.fail_on)
    except ValueError as exc:
        print(f"error: {exc}, so no result file was written.{left}", file=sys.stderr)
        return EXIT_USAGE
    # The result is written outside the repository being checked, so that writing it (or removing an
    # earlier one) can never change a workflow, the configuration or a baseline the check reads (second
    # and third reviews).
    try:
        inside = _inside(output, _repository_root(target))
    except (OSError, RuntimeError) as exc:      # a symlink loop is a RuntimeError before Python 3.13
        print(f"error: cannot tell where --output {args.output} is ({exc}), so no result file was written."
              f"{left}", file=sys.stderr)
        return EXIT_USAGE
    if inside:
        print(f"error: --output {args.output} is inside the repository being checked; write the result outside "
              f"it (the page uses ~/obaaf-try).{left}", file=sys.stderr)
        return EXIT_USAGE
    for name in ("audit", "config", "baseline"):
        given = getattr(args, name)
        if given and output.exists() and Path(given).exists() and output.samefile(given):
            print(f"error: --output names the file given with --{name}; write the result somewhere else. "
                  f"{args.output} was left as it was.", file=sys.stderr)
            return EXIT_USAGE
    if args.audit:
        try:
            audit_doc = json.loads(Path(args.audit).read_text(encoding="utf-8"))
            audit = summarize_audit(audit_doc, rule_ids)
        except (OSError, UnicodeDecodeError, ValueError, RecursionError) as exc:
            reason = "nested too deeply to read" if isinstance(exc, RecursionError) else exc
            print(f"error: --audit {args.audit}: {reason}", file=sys.stderr)
            return EXIT_USAGE
    # A regular file there is replaced on success; on failure none is left, so a file from an earlier
    # run cannot be read and sent as if it were this one's (review of slice 3.8). Anything else (a
    # device such as /dev/null, a pipe) is only written to, never removed (second review).
    try:
        if stat.S_ISREG(output.lstat().st_mode):
            output.unlink()
    except FileNotFoundError:
        pass
    except OSError as exc:
        print(f"error: cannot replace {args.output}: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # One word for each option and its value, as `obaaf` does, so a value that begins with a hyphen is
    # still read as a value.
    command = ["check", "--format=json", f"--fail-on={args.fail_on}", f"--platform={args.platform}"]
    command += ([f"--config={args.config}"] if args.config else []) \
        + ([f"--baseline={args.baseline}"] if args.baseline else [])
    with tempfile.TemporaryDirectory(prefix="obaaf-result-") as scratch:
        report_path = Path(scratch) / "check.json"
        started = time.monotonic()
        status = cli.main(command + [f"--output={report_path}", "--", args.path])
        seconds = round(time.monotonic() - started, 1)
        if status not in (0, 1) or not report_path.is_file():
            print("error: obaaf check did not write a report (see its message above), so no result file was written",
                  file=sys.stderr)
            return EXIT_USAGE
        try:
            doc = json.loads(report_path.read_text(encoding="utf-8"))
        except RecursionError:
            print("error: obaaf check's report is nested too deeply to read, so no result file was written",
                  file=sys.stderr)
            return EXIT_USAGE
    check = summarize_check(doc, rule_ids)

    base = target.parent if target.is_file() else target
    if target.is_dir():
        from obaaf.checker import workflow as wf_mod
        base, _ = wf_mod.locate(target)
    try:
        jobs = _lane_counts(target, base, args.config, args.platform)
        lanes_failed = False
    except Exception as exc:  # noqa: BLE001 - a partial result is still worth sending; the file says so
        print(f"warning: the jobs in each lane could not be counted ({type(exc).__name__}); the file says so",
              file=sys.stderr)
        jobs, lanes_failed = None, True

    config = checker.Config.load(base, args.config)
    tool = doc.get("tool")
    baseline = check.pop("baseline", {"used": False})
    result = {
        "format": FORMAT,
        "about": ABOUT,
        "tool": tool if isinstance(tool, str) and VERSION_RE.match(tool) else OTHER,
        "date": date.today().isoformat(),
        "python": f"{sys.version_info.major}.{sys.version_info.minor}",
        "system": _system(),
        "check": {
            "seconds": seconds,
            "exit": status,
            "failOn": _fail_on_word(args.fail_on),
            "platform": args.platform,
            "configuration": config.path is not None,
            "baseline": baseline,
            **check,
            "jobs": jobs,
            **({"lanesNotCounted": True} if lanes_failed else {}),
        },
        "audit": audit,
    }
    try:
        check_sendable(result)
    except NotSendable as exc:
        print(f"error: {exc}, so the result file was not written. Reports OBAAF wrote and nobody changed never "
              "cause this; if yours were not changed, it is a fault in OBAAF: please say so in your reply instead "
              "of sending a file.", file=sys.stderr)
        return EXIT_USAGE
    text = json.dumps(result, indent=2, ensure_ascii=True) + "\n"
    try:
        output.write_text(text, encoding="ascii")
    except OSError as exc:
        print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    found = sum(row["count"] for row in check["findings"])
    print(f"Wrote {args.output}: counts only ({found} finding(s) of obaaf check"
          + (f", {audit['summary']['findings']} of obaaf audit" if audit else "")
          + "). Read it before you send it.", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
