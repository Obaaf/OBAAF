"""To-do causes for matched acceptances that fail the checker's existing validation."""

from __future__ import annotations

import shlex

from obaaf.causes import Cause
from obaaf.checker import acceptance, baseline
from obaaf.checker.rules import ACCEPTED, FIXED
from obaaf.checker.workflow import one_line


def scoped_migration_command(baseline_path, checked, options) -> str:
    """Use only CLI arguments from this check. A migration requires three user decisions."""
    paths = [str(baseline_path or "FILE")]
    if checked not in ("", "."):
        paths.append(str(checked))
    # Quoting protects spaces and shell metacharacters, but argparse reads an initial dash
    # as an option even after shell quoting. A relative path with ./ denotes the same file.
    args = ["obaaf", "baseline", "migrate"]
    # A leading `=` is expanded by zsh (`=ls` is the path of ls), so it gets ./ as well.
    args.extend("./" + path if path.startswith(("-", "=")) else path for path in paths)
    args.extend(("--owner", "OWNER", "--reason", "REASON", "--expires", "YYYY-MM-DD"))
    args.extend(str(option) for option in (options or ()))
    return shlex.join(args)


def migration_command(result) -> str:
    return scoped_migration_command(result.baseline_path, result.checked, result.options)


def migration_hint(command: str, *, summary: bool = False) -> str:
    if command != one_line(command):
        # Name the command even when it cannot be printed: a reader new to OBAAF cannot guess it
        # (review-gpt #308).
        return ("Run obaaf baseline migrate yourself with the baseline's original path and the check's original "
                "paths and options, which cannot be printed faithfully as a one-line command, and supply an owner, "
                "reason and expiry.")
    return "The full report gives the command." if summary else command


def acceptance_cause(finding, result) -> Cause | None:
    """Choose one cause without counting the finding again for each problem in its entry.

    A prohibition or an increase in severity needs review even if all the paperwork is
    completed. For field errors, use the order below independently of the validator's
    message order. The detailed finding retains every problem.
    """
    made = finding.acceptance
    if made is None or made.valid or finding.state in (FIXED, ACCEPTED):
        return None

    if not acceptance.acceptable(finding) or acceptance.UNACCEPTABLE_PROBLEM in made.problems:
        return Cause("acceptance-prohibited", "An entry names a finding that cannot be accepted.",
                     "by-hand", "Restore the required code ownership and rerun the check.")
    if made.source == acceptance.BASELINE:
        if any(p.startswith("it accepts the finding at ") for p in made.problems):
            return Cause("acceptance-severity-increased", "The finding exceeds the severity accepted in the baseline.",
                         "by-hand", "Review the finding at its current severity before deciding whether to accept it.")
        if result.baseline_format == baseline.FORMAT_V1 or baseline.V1_PROBLEM in made.problems:
            return Cause("acceptance-old-baseline", "An old-format baseline entry no longer accepts its finding.",
                         "paperwork", migration_command(result))

    # The checker stores field errors as report messages. Compare only its fixed prefixes.
    # The remainder can contain user-supplied text; it must never become a to-do instruction.
    for prefix, cause in _FIELD_PROBLEMS:
        if any(problem.startswith(prefix) for problem in made.problems):
            return cause
    return Cause("acceptance-invalid", "An acceptance entry does not count.",
                 "by-hand", "Review all problems listed for the entry and rerun the check.")


_FIELD_PROBLEMS = (
    ("it expired on ", Cause("acceptance-expired", "An acceptance has expired.",
                             "by-hand", "Reassess the finding before deciding whether to renew its acceptance.")),
    ("it expires on ", Cause("acceptance-expiry-too-far", "An acceptance expires too far in the future.",
                             "by-hand", f"Choose a review date no more than {acceptance.MAX_DAYS} days ahead.")),
    ("its expiry date ", Cause("acceptance-expiry-invalid", "An acceptance has an invalid expiry date.",
                               "by-hand", "Review the entry and record a calendar date in YYYY-MM-DD format.")),
    ("it has no expiry date", Cause("acceptance-expiry-missing", "An acceptance has no expiry date.",
                                    "by-hand", "Decide when to reassess the risk and record that date in the entry.")),
    ("its reason says too little", Cause("acceptance-reason-too-short", "An acceptance gives too little reason.",
                                         "by-hand", f"Explain why the risk is accepted using at least "
                                         f"{acceptance.MIN_REASON} letters or digits.")),
    ("it gives no reason", Cause("acceptance-reason-missing", "An acceptance gives no reason.",
                                 "by-hand", "Have the risk owner record why the finding is accepted.")),
    ("its owner ", Cause("acceptance-owner-invalid", "An acceptance names an owner in an unrecognised format.",
                         "by-hand", "Record the responsible owner as @user, @org/team or an email address.")),
    ("it names no owner", Cause("acceptance-owner-missing", "An acceptance names no owner.",
                                "paperwork", "Review the risk and record the responsible owner in the entry.")),
)
