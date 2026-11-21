"""The actions a report can suggest for each kind of checker finding."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class Cause:
    id: str
    sentence: str
    fix_kind: str
    next_action: str


class CauseCatalog:
    """Exact selectors and a disjoint remainder cover even rules with computed kinds."""

    def __init__(self, data: object, rule_ids: Iterable[str]) -> None:
        self.problems: list[str] = []
        self._remaining: dict[str, Cause] = {}
        self._exact: dict[tuple[str, str], Cause] = {}
        known_rules = set(rule_ids)
        excluded: set[tuple[str, str]] = set()
        ids: set[str] = set()
        rows = data.get("causes") if isinstance(data, dict) else None
        if not isinstance(rows, list):
            self.problems.append("causes: expected a list of cause entries")
            return

        for number, row in enumerate(rows, 1):
            label = f"causes: entry {number}"
            if not isinstance(row, dict):
                self.problems.append(f"{label}: expected a mapping")
                continue
            unknown = set(row) - {"id", "sentence", "fix_kind", "next", "rules", "kinds", "except_kinds"}
            for key in sorted(unknown, key=repr):
                self.problems.append(f"{label}: unknown field {key!r}")
            fields = [row.get(key) for key in ("id", "sentence", "fix_kind", "next")]
            if not all(isinstance(value, str) and value.strip() for value in fields):
                self.problems.append(f"{label}: expected a nonempty id, sentence, fix_kind and next")
                continue
            cause = Cause(*fields)
            label = f"cause {cause.id}"
            if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", cause.id):
                self.problems.append(f"{label}: invalid id")
            if cause.id in ids:
                self.problems.append(f"{label}: duplicate id")
            ids.add(cause.id)
            if cause.fix_kind not in ("by-hand", "paperwork", "tightening", "confinement"):
                self.problems.append(f"{label}: invalid fix_kind")
            rules = row.get("rules", [])
            if not isinstance(rules, list) or not all(isinstance(rule, str) for rule in rules):
                self.problems.append(f"{label}: rules must be a list of rule IDs")
                rules = []
            for rule in rules:
                if rule not in known_rules:
                    self.problems.append(f"{label}: unknown rule {rule}")
                if rule in self._remaining:
                    self.problems.append(f"{rule}: multiple causes for remaining kinds")
                self._remaining[rule] = cause

            exact = self._pairs(row, "kinds", known_rules, label)
            for pair in exact:
                if pair in self._exact:
                    self.problems.append(f"{pair!r}: multiple exact causes")
                self._exact[pair] = cause
            excluded.update(self._pairs(row, "except_kinds", set(rules), label))
            if not rules and not exact:
                self.problems.append(f"{label}: no rule or kind selected")

        for rule in sorted(known_rules - self._remaining.keys()):
            self.problems.append(f"{rule}: no cause for remaining kinds")
        for pair in sorted(excluded - self._exact.keys()):
            self.problems.append(f"{pair!r}: no cause for excluded kind")
        for pair in sorted(self._exact.keys() - excluded):
            self.problems.append(f"{pair!r}: selected by both an exact and a remaining-kinds cause")

    def _pairs(self, row: dict, field: str, rules: set[str], label: str) -> list[tuple[str, str]]:
        mapping = row.get(field, {})
        if not isinstance(mapping, dict):
            self.problems.append(f"{label}: {field} must map rule IDs to lists of kinds")
            return []
        result = []
        for rule, kinds in mapping.items():
            if rule not in rules:
                self.problems.append(f"{label}: unknown rule {rule!r} in {field}")
                continue
            if not isinstance(kinds, list) or not kinds or not all(isinstance(k, str) for k in kinds):
                self.problems.append(f"{label}: expected a nonempty list of kinds in {field} for {rule}")
                continue
            if len(set(kinds)) != len(kinds):
                self.problems.append(f"{label}: repeated {field} selector for {rule}")
            result.extend((rule, kind) for kind in kinds)
        return result

    def for_finding(self, rule: str, kind: str) -> Cause:
        if self.problems:
            raise ValueError("cannot select a cause from an inconsistent catalogue")
        return self._exact.get((rule, kind), self._remaining[rule])
