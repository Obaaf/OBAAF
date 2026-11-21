"""Preview offline paperwork changes and apply the proven diff on explicit request."""

from __future__ import annotations

import difflib
import os
from pathlib import Path
import re
import sys
from collections import defaultdict, deque
from contextlib import nullcontext
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

    return root, CheckOptions(relative(target), relative(args.config), relative(args.baseline), args.platform,
                              "medium" if args.fail_on is None else args.fail_on, relative(getattr(args, "settings", None)))


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


def _verified_plan(source, copy, options, before, metadata, plan, prerequisite=""):
    from obaaf.fix_proof import ProofError, prove

    def rejection(item, error):
        if item.kind != "tightening":
            return f"{item.description}: {error}"
        from obaaf.checker.todo import tightening_command
        pin = metadata.get("pin")
        request = ["--pin", "=".join(pin)] if pin else ["--tighten", "checkout-credentials"]
        command = tightening_command(before, request, candidate=item.id)
        text = (f"{item.id}: {error}. Review the reported findings and any baseline or ignore entries with "
                "their owner.")
        if command != one_line(command):
            return text + " The named retry cannot be printed on one line. Use the original paths and options."
        # A named request run again unchanged fails the same way: say so, and keep its options for after.
        if metadata.get("candidate") or prerequisite:
            return f"{text} After resolving it, preview the same request again with: {command}"
        return f"{text} Retry this step alone with {command}"

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
            reasons.append(rejection(combined.items[0], error))
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
            reasons.extend(rejection(item, error) for item in batch)
            continue
        verified, verdict, selected = candidate, result, ids
    return verified, verdict, reasons


def apply_preview_guidance():
    from obaaf.fix_apply import XATTR_FUNCTIONS

    if all(hasattr(os, name) for name in XATTR_FUNCTIONS):
        return "Run again with --apply to write these changes."
    return "Make the displayed changes by hand on this host."


def run(args):
    from obaaf import checker
    from obaaf.catalog import load
    from obaaf.checker.todo import tightening_prerequisite
    from obaaf.fix_apply import apply_edits, apply_lock
    from obaaf.fix_copy import private_copy
    from obaaf.fix_proof import ProofError, bind_settings, check_copy_matches, check_inputs, prove

    try:
        if args.gate is not None:
            if args.settings is not None:
                raise ValueError("--gate does not configure a settings snapshot in the generated workflow")
            if args.tighten is not None or args.candidate is not None or args.pin is not None:
                raise ValueError("--gate is a separate operation; omit --tighten, --candidate and --pin")
            from obaaf.fix_gate import run as run_gate
            root, options = _paths(args)
            with (apply_lock(root) if args.apply else nullcontext()) as lock:
                return run_gate(args, root, options, lock, _show_diff)
        if (args.reason is not None or args.expires is not None) and not all((args.owner, args.reason, args.expires, args.baseline)):
            raise ValueError("baseline migration needs --baseline, --owner, --reason and --expires together")
        pin = None
        if args.pin is not None:
            from obaaf.fix_tightening import parse_pin
            if len(args.pin) != 1:
                raise ValueError("select one --pin PACKAGE=VERSION per preview")
            pin = parse_pin(args.pin[0])
        if args.candidate is not None and not args.candidate.strip():
            raise ValueError("--candidate needs a nonblank name from the tightening preview")
        if args.candidate is not None and not (args.tighten or pin):
            raise ValueError("--candidate needs --tighten checkout-credentials or --pin PACKAGE=VERSION")
        if (args.tighten or pin) and any(v is not None for v in (args.owner, args.reason, args.expires)):
            raise ValueError("workflow tightening cannot change acceptance metadata; request paperwork separately")
        root, options = _paths(args)
        checker.parse_fail_on(options.fail_on)
        if args.tighten or pin:
            from obaaf.fix_tightening import plan
            metadata = dict(candidate=args.candidate, pin=pin)
        else:
            from obaaf.fix_paperwork import plan
            metadata = dict(owner=args.owner, reason=args.reason, expires=args.expires)
        with (apply_lock(root) if args.apply else nullcontext()) as lock, private_copy(root) as copy:
            options = bind_settings(root, copy, options)
            today, catalog = date.today(), load()
            before = check_inputs(copy, options, today, catalog)
            source = check_inputs(root, options, today, catalog)
            check_copy_matches(root, source, before)
            if options.evidence is not None:
                from dataclasses import replace
                from obaaf.settings_evidence import report_settings
                target = root / options.path
                report_settings(replace(options.evidence, source=root / options.settings),
                                root, target.is_dir(), source.config)
            before.checked = str(args.path)
            before.options = ([f"--config={args.config}"] if args.config else []) + [f"--platform={args.platform}"]
            before.baseline_path = args.baseline or ""
            before.fail_on = options.fail_on
            before.settings_path = args.settings or ""
            paths = _owner_paths(copy, options, before, today, catalog)
            prerequisite = tightening_prerequisite(before) if args.tighten or pin else ""
            proposal, after, reasons = _verified_plan(root, copy, options, before, metadata, plan, prerequisite)
            if args.tighten:
                print("Checkout tightening can affect later steps that use Git credentials.")
            _render(proposal, source, after, reasons, paths, options.fail_on, catalog)
            if pin and not proposal.edits:
                if proposal.already_satisfied:
                    print(one_line(proposal.already_satisfied))
                    return 0
                print(prerequisite or "No proven pin to apply. Review the reported install and its original workflow by hand.")
                return 1
            if args.candidate is not None and not proposal.edits:
                print(prerequisite or "Named checkout withheld. Review its original workflow and resolve the reported "
                      "condition before running this named request again.")
                return 1
            if args.apply:
                sys.stdout.flush()
                if proposal.edits:
                    final = prove(root, options, proposal.edits, proposal.promises)
                    try:
                        check_copy_matches(root, after, final)
                    except ProofError as exc:
                        raise ProofError("checker results changed since the displayed preview; rerun to review them") from exc
                    warnings = apply_edits(root, lock, proposal.edits)
                    print(f"Applied the displayed diff to {len(proposal.edits)} file(s).")
                    for warning in warnings:
                        print(one_line(warning), file=sys.stderr)
                else:
                    print("No proven changes to apply.")
            elif proposal.edits:
                print(apply_preview_guidance())
        return 0
    except (ValueError, OSError) as error:
        print("error: " + one_line(error), file=sys.stderr)
        return 2
