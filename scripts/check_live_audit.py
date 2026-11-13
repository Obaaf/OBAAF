#!/usr/bin/env python3
"""Decide whether a live run of `obaaf audit` passed (used by settings-audit-live.yml).

    python scripts/check_live_audit.py SNAPSHOT --report REPORT.txt --exit-code N --repo OWNER/REPO
                                       [--path DIR] [--workflows-read] [--read KEY ...] [--rate-limit-ok]
                                       [--unreadable-ok] [--notice-if-no-ruleset]

It fails when the snapshot is not valid, when it is a snapshot of another repository than the one asked for,
when the command's exit code does not fit the snapshot, when the report is not exactly the report of that
snapshot (a crash after the snapshot was written, or a report of something else), when any answer had a
shape the reader did not expect, when a rule failed while running, or when a setting named with --read was
not read. Finding an unexpected shape is what the live run is for, so nothing excuses one.

The command is expected to have been run with `--fail-on never`, so that its exit code says whether the
repository was read and not whether the rules found something. The report is rebuilt here from the
snapshot and from the same workflow files the command compared it with: those under --path (the current
directory when it is not given), by the command's own rule for whose files they are. So this checks that
the report is the snapshot's, not that the rules are right: that is what the unit tests are for.

--workflows-read fails the run unless every workflow file of that directory was read. Without it a step
in which the rules saw no workflow file at all would pass, every rule having answered "cannot tell".

--rate-limit-ok lets a run that GitHub rate limited pass with a notice, as long as every setting named
with --read was either read or was not read because of the rate limit itself. A setting that was refused
or not found before the limit was reached still fails the run.
--unreadable-ok passes a run in which the repository itself could not be read; it is for a repository
other than this one, which may be renamed or made private without this project knowing. Once the
repository has been read, everything named with --read is required as usual.
--notice-if-no-ruleset says so in a notice when the repository was read and has no ruleset: the run then
exercised no part of the reader that reads one.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from obaaf.audit import DEFAULT_API, SETTINGS, SnapshotError, load
from obaaf.audit.cli import usage_for
from obaaf.audit.report import to_text
from obaaf.audit.rules import evaluate

# Reasons that mean the run could not judge the reader, as opposed to GitHub declining to show a setting.
INCONCLUSIVE = ("network", "server_error", "unauthorized")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("snapshot")
    parser.add_argument("--report", required=True, help="the text report the command printed")
    parser.add_argument("--exit-code", required=True, type=int, help="the command's exit code")
    parser.add_argument("--repo", required=True, metavar="OWNER/REPO", help="the repository the command was asked for")
    parser.add_argument("--path", default=None, metavar="DIR",
                        help="the directory the command was given, if it was given one")
    parser.add_argument("--workflows-read", action="store_true",
                        help="fail unless the workflow files of the directory were read, all of them")
    parser.add_argument("--read", nargs="*", default=[], metavar="KEY", help="settings that must have been read")
    parser.add_argument("--rate-limit-ok", action="store_true")
    parser.add_argument("--unreadable-ok", action="store_true")
    parser.add_argument("--notice-if-no-ruleset", action="store_true")
    args = parser.parse_args(argv)
    known = {s.key for s in SETTINGS}
    unknown = [key for key in args.read if key not in known]
    if unknown:
        print(f"error: not a setting: {', '.join(unknown)}", file=sys.stderr)
        return 2
    try:
        snapshot = load(args.snapshot)
    except SnapshotError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    try:
        report = Path(args.report).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        report = None
    settings = snapshot["settings"]
    for key, entry in settings.items():
        print(f"{key:<24} {entry['status']:<15} {entry.get('reason_code', '')}")
    found = [(key, part) for key, entry in settings.items() for part in [entry] + entry.get("problems", [])
             if part.get("reason_code")]
    codes = {part["reason_code"] for _, part in found}
    repository_read = settings["repository"]["status"] == "read"
    problems = [f"{key}: an answer did not have the documented shape: {part['reason']}"
                for key, part in found if part["reason_code"] == "unexpected"]
    asked = args.repo.lower()
    if asked not in (snapshot["repository"].lower(), str(snapshot.get("requested_as", "")).lower()):
        problems.append("the snapshot is of another repository than the one the command was asked for")
    if args.exit_code != (0 if repository_read else 1):
        problems.append(f"the command exited {args.exit_code}, which does not fit a snapshot in which the "
                        f"repository was {'read' if repository_read else 'not read'}")
    usage = usage_for(args.path, snapshot["repository"], str(snapshot.get("requested_as", "")),
                      github_com=snapshot["api"] == DEFAULT_API)
    assessment = evaluate(snapshot, usage)
    summary = assessment["summary"]
    for entry in assessment["rules"]:
        print(f"{entry['id']:<24} {entry['status']:<15} {entry['findings']} finding(s), {entry['cannot_tell']} "
              "cannot tell")
    print(f"rules: {summary['findings']} finding(s), {summary['cannot_tell']} cannot tell, "
          f"{summary['rules_failed']} failed; workflow files read: {usage['read']}")
    if summary["rules_failed"]:
        problems.append(f"{summary['rules_failed']} rule(s) failed while running")
    if args.workflows_read and repository_read and not (usage["read"] and usage["files"]
                                                        and not any(f["error"] for f in usage["files"])):
        # The step was meant to run the rules on this checkout's workflow files. If none was read, every
        # rule answered "cannot tell" and the step tested nothing of them.
        problems.append("the workflow files of the checkout were not read, or not all of them, so the rules "
                        "did not run on them")
    unclear = [r for r in assessment["results"] if "not in a form this rule understands" in r["message"]]
    for result in unclear:
        print(f"::notice::{result['rule']} met a real answer it does not understand: {result['subject']}")
    if report != to_text(snapshot, assessment=assessment, usage=usage):
        # The command prints the report of the snapshot it wrote, so the two must agree to the character.
        problems.append("what the command printed is not the report of the snapshot it wrote")
    not_read = {key: [part["reason_code"] for k, part in found if k == key] or [settings[key]["status"]]
                for key in args.read if settings[key]["status"] != "read"}
    if not problems and not repository_read and args.unreadable_ok:
        print(f"::notice::The repository could not be read ({settings['repository']['reason_code']}), so this "
              "run says nothing about the reader.")
        return 0
    # A rate limit excuses only what it stopped: a setting that was not read for the limit itself, or
    # because something it depends on was not read. Anything refused before the limit still counts.
    excused = "rate_limited" in codes and args.rate_limit_ok and all(
        set(why) <= {"rate_limited", "depends"} for why in not_read.values())
    if not problems and excused:
        print("::notice::GitHub rate limited this run, so it says nothing about the reader. Run it again "
              "later, or read the run made with a token.")
        return 0
    if "rate_limited" in codes:
        problems.append("GitHub rate limited this run")
    elif not repository_read:
        problems.append(f"the repository itself was not read ({settings['repository']['reason_code']})")
    problems += [f"{key}: {part['reason_code']}: {part['reason']}" for key, part in found
                 if part["reason_code"] in INCONCLUSIVE]
    problems += [f"{key} was not read ({', '.join(dict.fromkeys(why))})" for key, why in not_read.items()]
    for problem in dict.fromkeys(problems):
        print(f"error: {problem}", file=sys.stderr)
    if not problems and args.notice_if_no_ruleset and settings["rulesets"]["status"] == "read" and not (
            settings["rulesets"]["value"]):
        print("::notice::This repository has no ruleset now, so this run met none. The part of the reader "
              "that reads rulesets was not exercised against GitHub.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
