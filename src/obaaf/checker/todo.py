"""Build the additive to-do list without changing findings or their acceptances."""

from __future__ import annotations

from collections import Counter
import shlex
from dataclasses import dataclass, field

from obaaf.catalog import Catalog
from obaaf.causes import Cause
from obaaf.checker import CheckResult
from obaaf.checker.rules import ACCEPTED, FIXED
from obaaf.checker.todo_acceptance import acceptance_cause
from obaaf.checker.todo_upgrade import previous_acceptances


_LEVELS = ("high", "medium", "low", "info")


def checkout_command(result, candidate=None):
    """Reproduce this check's scope without enabling apply or modifying acceptances."""
    target = str(result.checked or ".")
    if target.startswith("-"):
        target = "./" + target
    options = list(map(str, result.options or ()))
    args = ["obaaf", "fix", target, "--tighten", "checkout-credentials", *options]
    if not any(option == "--platform" or option.startswith("--platform=") for option in options):
        args.append("--platform=auto")
    if result.baseline_path:
        args.append("--baseline=" + str(result.baseline_path))
    args.append("--fail-on=" + str(result.fail_on))
    if candidate is not None:
        args.append("--candidate=" + candidate)
    return shlex.join(args)


@dataclass
class _Group:
    cause: Cause
    kind: str
    severity: Counter = field(default_factory=Counter)
    previous: int = 0
    pin_candidates: int = 0

    def as_dict(self, result: CheckResult) -> dict:
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
            else:
                command = checkout_command(result)
                item["command"] = command
                item["nextAction"] = f"{self.cause.next_action} Preview the change with {command}"
        if self.previous:
            item["previousMatches"] = self.previous
        if self.cause.id == "agent-tool-version":
            item["pinCandidates"] = self.pin_candidates
            item["byHand"] = item["count"] - self.pin_candidates
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
            group.pin_candidates += 1

    def priority(group: _Group) -> tuple:
        actionable = group.cause.id in ("acceptance-old-baseline", "checkout-credentials") and not result.errors
        highest = next((i for i, level in enumerate(_LEVELS) if group.severity[level]), len(_LEVELS))
        return (not actionable, highest, -group.severity.total(), group.cause.id)

    return [group.as_dict(result) for group in sorted(groups.values(), key=priority)]
