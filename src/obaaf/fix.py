"""Show offline, proven paperwork changes without modifying the source tree."""

from __future__ import annotations

import difflib
import os
from pathlib import Path
import re
import sys
from collections import defaultdict, deque
from datetime import date

from obaaf.checker.workflow import one_line


def _paths(args):
    from obaaf.checker.workflow import locate
    from obaaf.fix_proof import CheckOptions, ProofError

    target = Path(os.path.abspath(args.path))
    if not target.exists():
        raise ProofError(f"check path does not exist: {target}")
    if target.is_dir():
        root = locate(target)[0]
    else:
        root = target.parent
        for parent in target.parents:
            if (parent / ".git/HEAD").is_file() or (parent / ".git").is_file() or (parent / ".github/workflows").is_dir():
                root = parent
                break

    def relative(value):
        if value is None:
            return None
        path = Path(os.path.abspath(value))
        if not path.is_relative_to(root) or ".git" in (part.casefold() for part in path.relative_to(root).parts):
            raise ProofError(f"check input must be inside the repository: {value}")
        return path.relative_to(root)

    return root, CheckOptions(relative(target), relative(args.config), relative(args.baseline), args.platform, args.fail_on)


def _show_diff(edit):
    before = edit.before.decode("utf-8").splitlines(keepends=True)
    after = edit.after.decode("utf-8").splitlines(keepends=True)
    # The path can come from a link the repository names, so it is shown as one escaped line.
    name = one_line(Path(edit.path).as_posix())
    for line in difflib.unified_diff(before, after, fromfile=f"a/{name}", tofile=f"b/{name}"):
        sys.stdout.write(line if line.endswith("\n") else line + "\n")
        if not line.endswith("\n"):
            print(r"\ No newline at end of file")


def _owner_paths(copy, options, result, today, catalog):
    from obaaf.fix_proof import check_inputs
    # With an empty CODEOWNERS, the checker enumerates exactly which workflow,
    # policy and instruction paths still lack owners. Create it only on the copy.
    if any(f.kind == "no-codeowners" for f in result.findings):
        owner_file = copy / ".github/CODEOWNERS"
        owner_file.parent.mkdir(exist_ok=True)
        with owner_file.open("xb"):
            pass
        try:
            result = check_inputs(copy, options, today, catalog)
        finally:
            owner_file.unlink()
    return {path for f in result.findings if f.rule in ("OBAAF-REPO-001", "OBAAF-REPO-002")
            for path in (f.facts or {}).get("files", ())}


def _owner_guidance(paths):
    from obaaf.checker.rules import NEW_WORKFLOW_PROBES
    if paths:
        print("Review CODEOWNERS by hand. Replace OWNER with the team that should approve each path.")
    for path in sorted(paths):
        if path in NEW_WORKFLOW_PROBES:
            path = ".github/workflows/*." + path.rsplit(".", 1)[1]
        elif not re.fullmatch(r"[A-Za-z0-9_./-]+", path):
            print("  Review the CODEOWNERS pattern for " + one_line(repr(path)))
            continue
        print("  /" + path + " OWNER")


def _render(proposal, before, after, reasons, paths, threshold, catalog):
    from obaaf.checker import baseline

    accepted = [promise for promise in proposal.promises if promise.approval is not None]
    print(f"You are accepting risk ({len(accepted)} finding{'s' if len(accepted) != 1 else ''}).")
    by_identity = defaultdict(deque)
    for finding in before.findings:
        by_identity[baseline.key(finding), finding.severity, finding.state].append(finding)
    for promise in accepted:
        finding = by_identity[(promise.identity, promise.severity, promise.previous)].popleft()
        approval = promise.approval
        print(one_line(f"  {finding.rule} {finding.path}:{finding.line} {finding.job or ''} "
                       f"({finding.severity}) — {approval.owner} until {approval.expires}: {approval.reason}"))
    for item in proposal.items:
        print(one_line(item.description))
        for removal in item.removals:
            print("  " + one_line(removal))
    if reasons:
        print("Could not be made automatically:")
        for reason in reasons:
            print("  " + one_line(reason))
    _owner_guidance(paths)
    if after is not None:
        accepted_count = sum(f.state == "accepted" for f in after.findings)
        gated = len(after.gating(threshold, catalog))
        print(f"Checked on a copy: {accepted_count} accepted, {len(after.findings) - accepted_count} other "
              f"findings, 0 newly counting findings, 0 stale entries. At --fail-on {threshold}, {gated} count.")
        for edit in proposal.edits:
            _show_diff(edit)


def _verified_plan(source, copy, options, before, metadata):
    from obaaf.fix_paperwork import plan
    from obaaf.fix_proof import ProofError, prove

    def verify(candidate):
        for edit in candidate.edits:
            for text in (edit.before.decode("utf-8"), edit.after.decode("utf-8")):
                if any(not c.isprintable() and c not in "\t\n" for c in text.replace("\r\n", "\n")):
                    raise ProofError(f"{edit.path}: the unified diff contains nonprinting characters")
        return prove(source, options, candidate.edits, candidate.promises)

    combined = plan(copy, options, before, **metadata)
    reasons = list(combined.refused)
    if not combined.edits:
        return combined, None, reasons
    try:
        return combined, verify(combined), reasons
    except ProofError as error:
        if len(combined.items) == 1:
            reasons.append(f"{combined.items[0].description}: {error}")
            return plan(copy, options, before, selected=(), **metadata), None, reasons

    # Stale entries must be removed together to meet the proof condition. Try that
    # group first, then add each other candidate only if the cumulative diff proves.
    cleanup = [item for item in combined.items if item.removals]
    batches = ([cleanup] if cleanup else []) + [[item] for item in combined.items if not item.removals]
    selected = []
    verified = plan(copy, options, before, selected=(), **metadata)
    verdict = None
    for batch in batches:
        ids = selected + [item.id for item in batch]
        candidate = plan(copy, options, before, selected=ids, **metadata)
        try:
            result = verify(candidate)
        except ProofError as error:
            reasons.extend(f"{item.description}: {error}" for item in batch)
            continue
        verified, verdict, selected = candidate, result, ids
    return verified, verdict, reasons


def run(args):
    from obaaf import checker
    from obaaf.catalog import load
    from obaaf.fix_copy import private_copy
    from obaaf.fix_proof import check_copy_matches, check_inputs

    try:
        if (args.reason is not None or args.expires is not None) and not all((args.owner, args.reason, args.expires, args.baseline)):
            raise ValueError("baseline migration needs --baseline, --owner, --reason and --expires together")
        root, options = _paths(args)
        checker.parse_fail_on(options.fail_on)
        metadata = dict(owner=args.owner, reason=args.reason, expires=args.expires)
        with private_copy(root) as copy:
            today, catalog = date.today(), load()
            before = check_inputs(copy, options, today, catalog)
            source = check_inputs(root, options, today, catalog)
            check_copy_matches(root, source, before)
            paths = _owner_paths(copy, options, before, today, catalog)
            proposal, after, reasons = _verified_plan(root, copy, options, before, metadata)
            _render(proposal, source, after, reasons, paths, options.fail_on, catalog)
        return 0
    except (ValueError, OSError) as error:
        print("error: " + one_line(error), file=sys.stderr)
        return 2
