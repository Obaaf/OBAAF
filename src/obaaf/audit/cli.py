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
        help="read a repository's GitHub settings (read-only) and record what was and was not read",
        description="Read the GitHub settings that workflows depend on: rulesets, branch protection, "
                    "environments, the names of secrets, Actions permissions and policies. Only GET requests "
                    "are sent. Every setting that could not be read is listed by name with the reason. This "
                    "version reads and records; it applies no rule yet. See docs/settings-audit.md.")
    x.add_argument("path", nargs="?", default=".",
                   help="a clone of the repository, used to find OWNER/REPO from its origin remote (default: .)")
    x.add_argument("--repo", metavar="OWNER/REPO", help="the repository to audit (default: from the clone's origin "
                                                        "remote, then $GITHUB_REPOSITORY)")
    x.add_argument("--branch", action="append", default=[], metavar="NAME",
                   help="also audit this branch; the default branch is always audited (repeatable)")
    x.add_argument("--from-snapshot", metavar="FILE",
                   help="report from a saved snapshot instead of asking GitHub; no request is sent")
    x.add_argument("--snapshot-out", metavar="FILE", help="write the snapshot (JSON) to FILE")
    x.add_argument("--format", choices=("text", "json"), default="text",
                   help="text for people (default), or json: the snapshot itself")
    x.add_argument("--output", "-o", help="write the report to a file instead of standard output")
    x.add_argument("--no-token", action="store_true",
                   help="send no token even if one is set; reads what GitHub shows anyone about a public repository")
    x.add_argument("--token-env", metavar="NAME",
                   help="read the token from this environment variable (default: GH_TOKEN, then GITHUB_TOKEN, "
                        "for api.github.com only). A token is never taken from the command line")
    x.add_argument("--api-url", metavar="URL", help="API address of a GitHub Enterprise Server (https; not tested)")
    x.add_argument("--fail-on-unread", action="store_true",
                   help="exit 1 if any setting that applies was not read in full")
    x.add_argument("--record", metavar="DIR",
                   help="also save GitHub's answers as received (no request headers, so no token) to "
                        "DIR/responses.json, for a bug report or a test")
    x.set_defaults(func=cmd_audit)


def _detect_repository(path: str) -> tuple[str, str]:
    try:
        done = subprocess.run(["git", "-C", path, "config", "--get", "remote.origin.url"], capture_output=True,
                              text=True, timeout=10, check=False)
        match = REMOTE.match(done.stdout.strip()) if done.returncode == 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        match = None
    if match:
        return match.group(1), f"from the origin remote of {path}"
    env = os.environ.get("GITHUB_REPOSITORY", "").strip()
    if env:
        return env, "from $GITHUB_REPOSITORY"
    raise UsageError("could not tell which repository to audit: pass --repo OWNER/REPO (no github.com origin "
                     f"remote was found in {_plain(path)}, and $GITHUB_REPOSITORY is not set)")


def _token(args, api: str, default_api: str) -> tuple[str | None, str]:
    """The token to send, if any, and where it came from. The value is never printed."""
    if args.no_token:
        return None, ""
    names = (args.token_env,) if args.token_env else (TOKEN_ENV_DEFAULTS if api == default_api else ())
    for name in names:
        value = os.environ.get(name, "").strip()
        if value:
            # The characters GitHub's tokens are made of. Anything else is not a token, and could not be
            # cut out of an answer reliably if a server ever echoed it.
            if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{8,4096}", value):
                raise UsageError(f"the environment variable {_plain(name)} does not hold a token (it is too "
                                 "short, or has characters a token cannot have)")
            return value, name
    if args.token_env:
        raise UsageError(f"--token-env {_plain(args.token_env)}: that environment variable is not set or is empty")
    return None, ""


def _plain(text: object, limit: int = 140) -> str:
    from obaaf.audit.github import plain

    return plain(text, limit)


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).parent.mkdir(parents=True, exist_ok=True)
        Path(output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
        sys.stdout.flush()


def cmd_audit(args) -> int:
    """Run the audit. Whatever goes wrong, the result is a message and a non-zero exit, never a pass."""
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


def _run(args) -> int:
    from obaaf import audit
    from obaaf.audit import report, snapshot as snapshot_mod
    from obaaf.audit.settings import check_branches

    try:
        if args.from_snapshot:
            for flag, value in (("--no-token", args.no_token), ("--token-env", args.token_env),
                                ("--api-url", args.api_url), ("--record", args.record), ("--branch", args.branch),
                                ("--snapshot-out", args.snapshot_out)):
                if value:
                    raise UsageError(f"{flag} has no meaning with --from-snapshot, which sends no request")
            snap = snapshot_mod.load(args.from_snapshot)
            if args.repo and args.repo.lower() not in (snap["repository"].lower(),
                                                       str(snap.get("requested_as", "")).lower()):
                raise UsageError(f"{_plain(args.from_snapshot)} is a snapshot of {_plain(snap['repository'])}, "
                                 f"not of {_plain(args.repo)}")
            how = "with a token" if snap["viewer"]["authenticated"] else "without a token"
            origin = (f"From the snapshot {_plain(args.from_snapshot)}, taken {report.when(snap)} {how}. Nothing "
                      "was asked of GitHub now.")
        else:
            api = audit.github.check_api_url(args.api_url) if args.api_url else audit.DEFAULT_API
            repository, found = (args.repo, "") if args.repo else _detect_repository(args.path)
            if not audit.OWNER_REPO.match(repository or ""):
                raise UsageError(f"expected OWNER/REPO, got {_plain(repository)!r}")
            try:
                check_branches(args.branch)
            except ValueError as exc:
                raise UsageError(str(exc)) from None
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
    _emit(snapshot_mod.dumps(snap) if args.format == "json" else report.to_text(snap, origin=origin), args.output)
    if args.snapshot_out and not args.from_snapshot:
        print(f"Snapshot written to {_plain(args.snapshot_out)}.", file=sys.stderr)
    if snap["settings"]["repository"]["status"] != "read":
        # Reading nothing must not look like a pass.
        print(f"error: {report.why_unread(snap)}. Nothing was audited.", file=sys.stderr)
        return EXIT_FAIL
    unread = report.unread_keys(snap)
    if args.fail_on_unread and unread:
        print(f"error: {len(unread)} setting(s) were not read in full (--fail-on-unread): {', '.join(unread)}",
              file=sys.stderr)
        return EXIT_FAIL
    return EXIT_OK
