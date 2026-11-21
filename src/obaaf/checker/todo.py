"""Build the additive to-do list without changing findings or their acceptances."""

from __future__ import annotations

from collections import Counter
import shlex
from dataclasses import dataclass, field

from obaaf.catalog import Catalog
from obaaf.causes import Cause
from obaaf.checker import CheckResult, baseline
from obaaf.checker.rules import ACCEPTED, FIXED
from obaaf.checker.todo_acceptance import acceptance_cause, migration_command, migration_hint
from obaaf.checker.todo_upgrade import previous_acceptances
from obaaf.checker.workflow import one_line


_LEVELS = ("high", "medium", "low", "info")


def tightening_command(result, request, candidate=None):
    """Reproduce this check's scope without enabling apply or modifying acceptances."""
    target = str(result.checked or ".")
    if target.startswith("-") or target == "egress":
        target = "./" + target
    options = list(map(str, result.options or ()))
    args = ["obaaf", "fix", target, *request, *options]
    if not any(option == "--platform" or option.startswith("--platform=") for option in options):
        args.append("--platform=auto")
    if result.baseline_path:
        args.append("--baseline=" + str(result.baseline_path))
    args.append("--fail-on=" + str(result.fail_on))
    if candidate is not None:
        args.append("--candidate=" + candidate)
    return shlex.join(args)


def tightening_prerequisite(result: CheckResult) -> str:
    """What must be settled before a workflow edit can be proven: the proof refuses while any baseline or
    ignore entry matches no finding (fix_proof.prove), even one that matched nothing before the edit."""
    steps = []
    legacy = result.baseline_format == baseline.FORMAT_V1
    if legacy:
        steps.append("Migrate the old-format baseline.")
    # Migration drops the old entries that match no finding, so only a converted baseline's need resolving.
    stale_baseline = bool(result.baseline_stale) and not legacy
    stale_ignores = any(result.unmatched_ignores())
    removal = ""
    if (stale_baseline or stale_ignores) and not result.whole_repository:
        # A file or platform on its own cannot tell an entry for a finding elsewhere from a stale one, and
        # the paperwork preview refuses to remove it (review-gpt #294).
        steps.append("Run the check on the whole repository, on every platform: this scope cannot tell whether "
                     "a baseline or ignore entry that matches nothing here matches a finding elsewhere.")
    else:
        if stale_baseline:
            steps.append("Resolve the unmatched baseline entries.")
        if stale_ignores:
            steps.append("Resolve the unmatched ignore entries.")
        if (stale_baseline or stale_ignores) and not legacy:
            # The check's report does not list unmatched ignore entries; the paperwork preview names each
            # one and proposes its removal (review-gpt #294). The command, never the entries' own text,
            # goes into the to-do. With an old-format baseline the migration comes first, and the check
            # after it gives this command.
            command = tightening_command(result, [])
            removal = (f" To see each unmatched entry and preview its removal, run {command}"
                       if command == one_line(command) else
                       " To see each unmatched entry and preview its removal, run obaaf fix with this check's "
                       "original path, options and baseline, which cannot be printed faithfully as a one-line "
                       "command.")
    if steps:
        steps.append("Then rerun the check before previewing workflow edits.")
    return " ".join(steps) + removal


@dataclass
class _Group:
    cause: Cause
    kind: str
    severity: Counter = field(default_factory=Counter)
    previous: int = 0
    pin_packages: Counter = field(default_factory=Counter)

    def as_dict(self, result: CheckResult, prerequisites: str) -> dict:
        item = {
            "id": self.cause.id,
            "kind": self.kind,
            "sentence": self.cause.sentence,
            "count": self.severity.total(),
            "bySeverity": {level: self.severity[level] for level in _LEVELS},
            "fixKind": self.cause.fix_kind,
            "nextAction": self.cause.next_action,
            "command": self.cause.next_action if self.cause.id == "acceptance-old-baseline" else None,
        }
        if self.cause.id == "checkout-credentials":
            if result.errors:
                item["nextAction"] = "Resolve the scan errors before previewing checkout tightening."
            elif prerequisites:
                item["nextAction"] = prerequisites
            else:
                command = tightening_command(result, ["--tighten", "checkout-credentials"])
                item["command"] = command
                item["nextAction"] = f"{self.cause.next_action} Preview the change with {command}"
        if self.previous:
            item["previousMatches"] = self.previous
        if self.cause.id == "agent-tool-version":
            count = self.pin_packages.total()
            item["pinCandidates"] = count
            item["byHand"] = item["count"] - count
            if count and not result.errors and not prerequisites:
                packages = sorted(self.pin_packages)
                package = packages[0] if len(packages) == 1 else "PACKAGE"
                command = tightening_command(result, ["--pin", f"{package}=VERSION"])
                item["command"] = command
                manual = "Review other forms by hand. " if item["byHand"] else ""
                item["nextAction"] = (f"{manual}Choose an exact npm version for {', '.join(packages)} "
                                      f"and substitute your selection in {command}")
            elif count and result.errors:
                # With no candidate there is no pin to preview: keep the rule's own guidance (review-gpt #294).
                item["nextAction"] = "Resolve the scan errors before previewing a package pin."
            elif count and prerequisites:
                item["nextAction"] = prerequisites
        return item


def todo(result: CheckResult, catalog: Catalog) -> list[dict]:
    """Empty when the cause catalogue is inconsistent: the report is still written (`to_json` says
    why in its notes), and `obaaf catalog` names the problems."""
    if catalog.causes.problems:
        return []
    groups: dict[str, _Group] = {}
    previous = previous_acceptances(result.baseline_stale, result.findings)
    for finding in result.findings:
        if finding.state in (ACCEPTED, FIXED):
            continue
        cause = acceptance_cause(finding, result)
        kind = "acceptance" if cause else "rule"
        if cause is None:
            cause = catalog.causes.for_finding(finding.rule, finding.kind)
        if cause.id not in groups:
            groups[cause.id] = _Group(cause, kind)
        group = groups[cause.id]
        group.severity[finding.severity] += 1
        group.previous += previous.get(id(finding), 0)
        if cause.id == "agent-tool-version" and finding.pin_candidate:
            group.pin_packages[finding.pin_candidate] += 1

    pins = groups.get("agent-tool-version")
    has_tightening = "checkout-credentials" in groups or (pins and pins.pin_packages)
    prerequisites = tightening_prerequisite(result) if has_tightening else ""
    if has_tightening and result.baseline_format == baseline.FORMAT_V1 and "acceptance-old-baseline" not in groups:
        # With no matching old entries there is no migration row to carry the scoped command.
        prerequisites += " " + migration_hint(migration_command(result))

    def priority(group: _Group) -> tuple:
        has_preview = group.cause.id == "checkout-credentials" or bool(group.pin_packages)
        actionable = not result.errors and (group.cause.id == "acceptance-old-baseline"
                                            or (has_preview and not prerequisites))
        highest = next((i for i, level in enumerate(_LEVELS) if group.severity[level]), len(_LEVELS))
        return (not actionable, highest, -group.severity.total(), group.cause.id)

    return [group.as_dict(result, prerequisites) for group in sorted(groups.values(), key=priority)]
