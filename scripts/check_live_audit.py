#!/usr/bin/env python3
"""Decide whether a live run of `obaaf audit` passed (used by settings-audit-live.yml).

    python scripts/check_live_audit.py SNAPSHOT --report REPORT.txt --exit-code N [--read KEY ...]
                                       [--rate-limit-ok] [--unreadable-ok]

It fails when the snapshot is not valid, when the command's exit code or its report does not fit the
snapshot (a crash after the snapshot was written), when any answer had a shape the reader did not expect,
or when a setting named with --read was not read. Finding an unexpected shape is what the live run is for,
so nothing excuses one.

--rate-limit-ok lets a run that GitHub rate limited pass with a notice: it says nothing about the reader.
--unreadable-ok does the same when the repository itself could not be read; it is for a repository other
than this one, which may be renamed or made private without this project knowing.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from obaaf.audit import SETTINGS, SnapshotError, load

# Reasons that mean the run could not judge the reader, as opposed to GitHub declining to show a setting.
INCONCLUSIVE = ("network", "server_error", "unauthorized")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("snapshot")
    parser.add_argument("--report", required=True, help="the text report the command printed")
    parser.add_argument("--exit-code", required=True, type=int, help="the command's exit code")
    parser.add_argument("--read", nargs="*", default=[], metavar="KEY", help="settings that must have been read")
    parser.add_argument("--rate-limit-ok", action="store_true")
    parser.add_argument("--unreadable-ok", action="store_true")
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
        report = ""
    settings = snapshot["settings"]
    for key, entry in settings.items():
        print(f"{key:<24} {entry['status']:<15} {entry.get('reason_code', '')}")
    found = [(key, part) for key, entry in settings.items() for part in [entry] + entry.get("problems", [])
             if part.get("reason_code")]
    codes = {part["reason_code"] for _, part in found}
    repository_read = settings["repository"]["status"] == "read"
    problems = [f"{key}: an answer did not have the documented shape: {part['reason']}"
                for key, part in found if part["reason_code"] == "unexpected"]
    if args.exit_code != (0 if repository_read else 1):
        problems.append(f"the command exited {args.exit_code}, which does not fit a snapshot in which the "
                        f"repository was {'read' if repository_read else 'not read'}")
    if not re.search(r"^\d+ settings: \d+ read, ", report, flags=re.M) or "Traceback" in report:
        problems.append("the command did not print a whole report")
    if not problems and "rate_limited" in codes and args.rate_limit_ok:
        print("::notice::GitHub rate limited this run, so it says nothing about the reader. Run it again "
              "later, or read the run made with a token.")
        return 0
    if not problems and not repository_read and args.unreadable_ok:
        print(f"::notice::The repository could not be read ({settings['repository']['reason_code']}), so this "
              "run says nothing about the reader.")
        return 0
    if "rate_limited" in codes:
        problems.append("GitHub rate limited this run")
    elif not repository_read:
        problems.append(f"the repository itself was not read ({settings['repository']['reason_code']})")
    problems += [f"{key}: {part['reason_code']}: {part['reason']}" for key, part in found
                 if part["reason_code"] in INCONCLUSIVE]
    problems += [f"{key} was not read ({settings[key].get('reason_code', settings[key]['status'])})"
                 for key in args.read if settings[key]["status"] != "read"]
    for problem in dict.fromkeys(problems):
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
