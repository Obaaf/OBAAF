#!/usr/bin/env python3
"""Check a snapshot that `obaaf audit` took of a live repository (used by settings-audit-live.yml).

Passes when the snapshot is valid, the settings named with --read were read, and no answer had a shape the
reader did not expect. With --rate-limit-ok, a run that GitHub rate limited before it read anything passes
too, with a notice, because that says nothing about the reader.

    python scripts/check_live_audit.py SNAPSHOT --read repository rulesets [--rate-limit-ok]
"""

from __future__ import annotations

import argparse
import sys

from obaaf.audit import SETTINGS, SnapshotError, load

# Reasons that mean the run could not judge the reader, as opposed to GitHub declining to show a setting.
BROKEN = ("unexpected", "network", "server_error", "unauthorized")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("snapshot")
    parser.add_argument("--read", nargs="*", default=[], metavar="KEY", help="settings that must have been read")
    parser.add_argument("--rate-limit-ok", action="store_true")
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
    settings = snapshot["settings"]
    for key, entry in settings.items():
        print(f"{key:<24} {entry['status']:<15} {entry.get('reason_code', '')}")
    codes = {entry.get("reason_code") for entry in settings.values()}
    codes |= {problem["reason_code"] for entry in settings.values() for problem in entry.get("problems", [])}
    if "rate_limited" in codes:
        if args.rate_limit_ok:
            print("::notice::GitHub rate limited this run, so it says nothing about the reader. "
                  "Run it again later, or read the run made with a token.")
            return 0
        print("error: GitHub rate limited this run", file=sys.stderr)
        return 1
    problems = [f"{key} was not read ({settings[key].get('reason_code', settings[key]['status'])}: "
                f"{settings[key].get('reason', 'see its problems')})"
                for key in args.read if settings[key]["status"] != "read"]
    for key, entry in settings.items():
        for found in [entry] + entry.get("problems", []):
            if found.get("reason_code") in BROKEN:
                problems.append(f"{key}: {found['reason_code']}: {found['reason']}")
    for problem in dict.fromkeys(problems):
        print(f"error: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
