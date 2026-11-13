"""`obaaf audit`: the command line of the settings audit."""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

EXIT_OK, EXIT_FAIL, EXIT_USAGE = 0, 1, 2
TOKEN_ENV_DEFAULTS = ("GH_TOKEN", "GITHUB_TOKEN")
REMOTE = re.compile(r"^(?:https://github\.com/|git@github\.com:|ssh://git@github\.com/)"
                    r"([A-Za-z0-9-]+/[A-Za-z0-9._-]+?)(?:\.git)?/?\Z")


class UsageError(ValueError):
    pass


def add_parser(sub) -> None:
    x = sub.add_parser(
        "audit",
        help="read a repository's GitHub settings (read-only) and compare them with what its workflows use",
        description="Read the GitHub settings that workflows depend on (rulesets, branch protection, "
                    "environments, the names of secrets, Actions permissions and policies) and compare them "
                    "with the workflow files in a clone. Only GET requests are sent. A rule reports a finding, "
                    "or \"cannot tell\" when a setting it needs was not read; every setting that could not be "
                    "read is listed by name with the reason. With --expected it also compares the settings with "
                    "a committed snapshot and reports every difference. See docs/settings-audit.md.")
    x.add_argument("path", nargs="?", default=None,
                   help="a clone of the repository: its origin remote gives OWNER/REPO, and its workflow files "
                        "are what the settings are compared with (default: .)")
    x.add_argument("--repo", metavar="OWNER/REPO", help="the repository to audit (default: from the clone's origin "
                                                        "remote, then $GITHUB_REPOSITORY)")
    x.add_argument("--branch", action="append", default=[], metavar="NAME",
                   help="also audit this branch; the default branch is always audited (repeatable)")
    x.add_argument("--from-snapshot", metavar="FILE",
                   help="report from a saved snapshot instead of asking GitHub; no request is sent")
    x.add_argument("--snapshot-out", metavar="FILE", help="write the snapshot (JSON) to FILE")
    x.add_argument("--format", choices=("text", "json"), default="text",
                   help="text for people (default), or json: the rules' results and the snapshot in one document "
                        "(with --expected, the comparison with the committed snapshot under the key drift)")
    x.add_argument("--output", "-o", help="write the report to a file instead of standard output")
    x.add_argument("--no-token", action="store_true",
                   help="send no token even if one is set; reads what GitHub shows anyone about a public repository")
    x.add_argument("--token-env", metavar="NAME",
                   help="read the token from this environment variable (default: GH_TOKEN, then GITHUB_TOKEN, "
                        "for api.github.com only). A token is never taken from the command line")
    x.add_argument("--api-url", metavar="URL", help="API address of a GitHub Enterprise Server (https; not tested)")
    x.add_argument("--fail-on", choices=("high", "medium", "low", "never"), default="medium",
                   help="exit 1 if a rule reports a finding at or above this severity (default: medium)")
    x.add_argument("--fail-on-cannot-tell", action="store_true",
                   help="exit 1 if any rule answered \"cannot tell\"")
    x.add_argument("--fail-on-unread", action="store_true",
                   help="exit 1 if any setting that applies was not read in full")
    x.add_argument("--no-fixes", action="store_true", help="leave the fix out of each finding in the text report")
    x.add_argument("--expected", metavar="FILE",
                   help="a committed snapshot of the settings as they should be (written by --snapshot-out). "
                        "Every difference from it is a finding. The command exits 1 if there is one, if something "
                        "was read by one of the two and not by the other, or if nothing could be compared. Its "
                        "branches are audited too")
    x.add_argument("--record", metavar="DIR",
                   help="also save GitHub's answers as received (no request headers, so no token) to "
                        "DIR/responses.json, for a bug report or a test")
    x.set_defaults(func=cmd_audit)


def _git(path: str, *args: str) -> str | None:
    """One line from git about the directory, or None. Variables that point git at another repository
    (GIT_DIR and the like) are not passed on: the question is about this directory."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        done = subprocess.run(["git", "-C", path, *args], capture_output=True, text=True, timeout=10, check=False,
                              env=env)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    return done.stdout.strip() if done.returncode == 0 else None


def _origin(path: str) -> str | None:
    """OWNER/REPO from the origin remote of the clone whose top level is ``path``, if it is on github.com.
    A directory inside a clone is not the clone: its workflow files are not that repository's."""
    top = _git(path, "rev-parse", "--show-toplevel")
    try:
        if top is None or Path(top).resolve() != Path(path).resolve():
            return None
    except OSError:
        return None
    match = REMOTE.match(_git(path, "config", "--get", "remote.origin.url") or "")
    return match.group(1) if match else None


def usage_for(path: str | None, repository: str, also: str = "", github_com: bool = True) -> dict:
    """What the workflow files use, for the rules to compare settings with.

    The files are read from ``path`` when it is the top level of a clone whose origin remote names the
    repository that is audited (under either name, if GitHub has renamed it), or when the directory was
    named on the command line: whoever names a directory says whose files they are. Settings of one
    repository are never compared with the workflows of whichever clone the command happened to be
    started in. A remote on github.com says nothing about a repository on another server (``github_com``
    false), so there a directory has to be named."""
    from obaaf.audit import workflows

    where = path if path is not None else "."
    origin = _origin(where) if github_com else None
    names = {repository.lower(), also.lower()} - {""}
    matches = origin is not None and origin.lower() in names
    if not matches and path is None:
        whose = ("the settings were read from a server other than github.com, and the current directory's remote "
                 "cannot say whose files these are" if not github_com else
                 f"the clone in the current directory is of {_plain(origin)}, not of {_plain(repository)}"
                 if origin else "the current directory is not the top level of a clone whose origin remote is "
                                "on github.com")
        return workflows.not_read(f"{whose}; to compare the settings with a repository's workflow files, "
                                  "name the directory that holds them (obaaf audit DIR --repo OWNER/REPO)")
    usage = workflows.read(where)
    usage["shown"] = where
    if usage["read"] and not matches:
        usage["note"] = (f"That directory's origin remote names {_plain(origin)}, not {_plain(repository)}; its "
                         "files are compared because the directory was named." if origin else
                         "That directory is not the top level of a clone of this repository on github.com; its "
                         "files are compared because the directory was named.")
    return usage


def _detect_repository(path: str) -> tuple[str, str]:
    found = _origin(path)
    if found:
        return found, f"from the origin remote of {path}"
    env = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if env:
        return env, "from $GITHUB_REPOSITORY"
    raise UsageError("could not tell which repository to audit: pass --repo OWNER/REPO (no github.com origin "
                     f"remote was found in {_plain(path)}, and $GITHUB_REPOSITORY is not set)")


def _token(args, api: str, default_api: str) -> tuple[str | None, str]:
    """The token to send, if any, and where it came from. The value is never printed."""
    if args.no_token:
        return None, ""
    if args.token_env is not None and not args.token_env.strip():
        raise UsageError("--token-env takes the name of an environment variable")
    names = (args.token_env,) if args.token_env else (TOKEN_ENV_DEFAULTS if api == default_api else ())
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            # The characters GitHub's tokens are made of. Anything else is not a token, and could not be
            # cut out of an answer reliably if a server ever echoed it.
            if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{8,4096}", value):
                raise UsageError(f"the environment variable {_named(args, name)} does not hold a token (it is "
                                 "too short, or has characters a token cannot have)")
            return value, name
    if args.token_env:
        raise UsageError("--token-env: the environment variable it names is not set or is empty. It takes the "
                         "name of a variable, never a token")
    return None, ""


def _named(args, name: str) -> str:
    """How to refer to a token's variable in a message. What was given to --token-env is not repeated when
    it led nowhere: someone may have put the token itself there."""
    return "named by --token-env" if args.token_env else _plain(name)


def _plain(text: object, limit: int = 140) -> str:
    from obaaf.audit.github import plain

    return plain(text, limit)


def _same_file(one: str, other: str) -> bool:
    """Whether two paths name one file: the same path, or (when both exist) the same file by any name,
    a hard link or another letter case on a file system that ignores case included."""
    try:
        if Path(one).resolve() == Path(other).resolve():
            return True
        return os.path.exists(one) and os.path.exists(other) and os.path.samefile(one, other)
    except (OSError, RuntimeError, ValueError):
        return True  # cannot tell, so do not risk it


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        sys.stdout.flush()


def cmd_audit(args) -> int:
    """Run the audit. Whatever goes wrong, the result is a message and a non-zero exit, never a pass."""
    for stream in (sys.stdout, sys.stderr):
        # A terminal that cannot show a character (a name in another script on a cp1252 console) gets it
        # written as an escape. Failing to print is not a reason to fail the audit.
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass
    try:
        return _run(args)
    except UsageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        # A file that could not be written, or output that could not be printed.
        print(f"error: {_plain(exc.strerror or type(exc).__name__)}"
              + (f": {_plain(exc.filename)}" if exc.filename else ""), file=sys.stderr)
        return EXIT_FAIL
    except Exception as exc:  # noqa: BLE001 - a crash must not look like anything but a failure
        print(f"error: obaaf audit failed unexpectedly ({type(exc).__name__}). This is a bug in obaaf; nothing "
              "was established about the settings.", file=sys.stderr)
        return EXIT_FAIL


def _json(snap: dict, usage: dict, assessment: dict, drift_result: dict | None = None) -> str:
    """The JSON output: the rules' results, what was compared, the comparison with a committed snapshot
    (under `drift`, only with --expected), and the snapshot they rest on."""
    import json

    document = {"format": "obaaf-settings-audit/v0.1", "repository": snap["repository"],
                "summary": assessment["summary"], "rules": assessment["rules"], "results": assessment["results"],
                "workflows": {"read": usage["read"], "reason": usage["reason"], "from": usage.get("shown", ""),
                              "note": usage.get("note", ""), "config": usage["config"],
                              "config_error": usage["config_error"],
                              "files": [{"path": f["path"], "error": f["error"], "jobs": len(f["jobs"])}
                                        for f in usage["files"]]}}
    if drift_result is not None:
        document["drift"] = drift_result
    document["snapshot"] = snap
    return json.dumps(document, indent=2, ensure_ascii=True, allow_nan=False) + "\n"


def _run(args) -> int:
    from obaaf import audit
    from obaaf.audit import drift, report, rules, snapshot as snapshot_mod
    from obaaf.audit.settings import check_branches

    expected = None
    try:
        if args.expected is not None:
            for flag, value in (("--snapshot-out", args.snapshot_out), ("--output", args.output)):
                if value and _same_file(value, args.expected):
                    # Writing there would replace the committed record with what it is being checked against.
                    raise UsageError(f"{flag} names the same file as --expected")
            # Read before anything is asked of GitHub: a file that cannot be used stops the command here,
            # and its branches are audited along with any named on the command line.
            try:
                expected = snapshot_mod.load(args.expected)
            except snapshot_mod.SnapshotError as exc:
                raise UsageError(f"--expected {_plain(args.expected)}: {exc}") from None
            try:
                extra = drift.branches_to_read(expected)
            except drift.DriftError as exc:
                raise UsageError(f"--expected {_plain(args.expected)}: {exc}") from None
            if args.from_snapshot is None:
                args.branch = list(dict.fromkeys([*args.branch, *extra]))
                if len(args.branch) > drift.MAX_EXPECTED_BRANCHES:
                    raise UsageError(f"--expected: with the branches named on the command line, more than "
                                     f"{drift.MAX_EXPECTED_BRANCHES} branches would be audited")
        if args.from_snapshot is not None:
            for flag, value in (("--no-token", args.no_token), ("--token-env", args.token_env),
                                ("--api-url", args.api_url), ("--record", args.record), ("--branch", args.branch),
                                ("--snapshot-out", args.snapshot_out)):
                if value:
                    raise UsageError(f"{flag} has no meaning with --from-snapshot, which sends no request")
            try:
                snap = snapshot_mod.load(args.from_snapshot)
            except snapshot_mod.SnapshotError as exc:
                raise UsageError(f"--from-snapshot {_plain(args.from_snapshot)}: {exc}") from None
            if args.repo and args.repo.lower() not in (snap["repository"].lower(),
                                                       str(snap.get("requested_as", "")).lower()):
                raise UsageError(f"{_plain(args.from_snapshot)} is a snapshot of {_plain(snap['repository'])}, "
                                 f"not of {_plain(args.repo)}")
            how = "with a token" if snap["viewer"]["authenticated"] else "without a token"
            origin = (f"From the snapshot {_plain(args.from_snapshot)}, taken {report.when(snap)} {how}. Nothing "
                      "was asked of GitHub now.")
        else:
            api = audit.github.check_api_url(args.api_url) if args.api_url else audit.DEFAULT_API
            repository, found = (args.repo, "") if args.repo else _detect_repository(args.path or ".")
            if not audit.OWNER_REPO.match(repository or ""):
                raise UsageError(f"expected OWNER/REPO, got {_plain(repository)!r}")
            try:
                check_branches(args.branch)
            except ValueError as exc:
                raise UsageError(str(exc)) from None
            if expected is not None:
                # Checked again on what was read, below; this stops a wrong file before any request is sent.
                try:
                    drift.check_comparable(expected, {"api": api, "repository": repository})
                except drift.DriftError as exc:
                    raise UsageError(f"--expected {_plain(args.expected)}: {exc}") from None
            token, token_from = _token(args, api, audit.DEFAULT_API)
            client = audit.Client(api=api, token=token)
            snap = audit.take(client, repository, tuple(args.branch))
            origin = ""
            if found:
                print(f"Auditing {repository} ({_plain(found)}).", file=sys.stderr)
            if token_from:
                print(f"Using the token in the environment variable {_plain(token_from)}. Only GET requests are "
                      "sent.", file=sys.stderr)
            if args.record:
                Path(args.record).mkdir(parents=True, exist_ok=True)
                (Path(args.record) / "responses.json").write_text(client.recording_text(), encoding="utf-8")
            if args.snapshot_out:
                snapshot_mod.write(snap, args.snapshot_out)
    except (audit.ApiUrlError, snapshot_mod.SnapshotError) as exc:
        raise UsageError(str(exc)) from None
    usage = usage_for(args.path, snap["repository"], str(snap.get("requested_as", "")),
                      github_com=snap["api"] == audit.DEFAULT_API)
    assessment = rules.evaluate(snap, usage)
    result = None
    if expected is not None:
        try:
            drift.check_comparable(expected, snap)
        except drift.DriftError as exc:
            raise UsageError(f"--expected {_plain(args.expected)}: {exc}") from None
        try:
            result = drift.compare(expected, snap, expected_name=args.expected, live_name=args.from_snapshot or "")
        except drift.DriftError as exc:  # it names the file at fault
            raise UsageError(f"cannot compare: {exc}") from None
    if args.format == "json":
        text = _json(snap, usage, assessment, result)
    else:
        text = report.to_text(snap, origin=origin, assessment=assessment, usage=usage, show_fixes=not args.no_fixes)
        if result is not None:
            text = drift.to_text(result) + "\n" + text
    _emit(text, args.output)
    if args.snapshot_out and args.from_snapshot is None:
        print(f"Snapshot written to {_plain(args.snapshot_out)}.", file=sys.stderr)
    if snap["settings"]["repository"]["status"] != "read":
        # Reading nothing must not look like a pass.
        print(f"error: {report.why_unread(snap)}. Nothing was audited.", file=sys.stderr)
        return EXIT_FAIL
    code = EXIT_OK
    summary = assessment["summary"]
    if summary["rules_failed"]:
        print(f"error: {summary['rules_failed']} rule(s) failed while running. This is a bug in obaaf; those "
              "rules established nothing.", file=sys.stderr)
        code = EXIT_FAIL
    if rules.fails(assessment, args.fail_on):
        print(f"error: {summary['findings']} finding(s): {summary['high']} high, {summary['medium']} medium, "
              f"{summary['low']} low (--fail-on {args.fail_on}).", file=sys.stderr)
        code = EXIT_FAIL
    if args.fail_on_cannot_tell and summary["cannot_tell"]:
        print(f"error: the rules could not tell in {summary['cannot_tell']} case(s) (--fail-on-cannot-tell).",
              file=sys.stderr)
        code = EXIT_FAIL
    unread = report.unread_keys(snap)
    if args.fail_on_unread and unread:
        print(f"error: {len(unread)} setting(s) were not read in full (--fail-on-unread): {', '.join(unread)}",
              file=sys.stderr)
        code = EXIT_FAIL
    if result is not None and drift.failed(result):
        summary = result["summary"]
        print(f"error: the settings drifted from {_plain(args.expected)} or could not all be compared: "
              f"{summary['findings']} difference(s), {summary['parts_not_compared']} part(s) not compared, "
              f"{summary['compared']} setting(s) compared (--expected).", file=sys.stderr)
        code = EXIT_FAIL
    return code
