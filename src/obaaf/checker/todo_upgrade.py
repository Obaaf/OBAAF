"""Display-only associations between stale baseline entries and outstanding findings."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable

from obaaf.checker import baseline
from obaaf.checker.rules import NEW, UNDECIDED, Finding


def previous_acceptances(stale_entries: Iterable[dict], findings: Iterable[Finding]) -> dict[int, int]:
    """Count one stale entry for at most one finding with the same rule, path and job.

    The shared location is a hint after an upgrade, never an acceptance or an identity match.
    Skip a location with competing finding kinds: their causes may differ. If all candidates have
    one kind, the count belongs to one cause. Use source order then finding identity to distribute
    that count consistently, independently of the order of the supplied collections.
    """
    available: Counter[tuple[str, str, str]] = Counter()
    # Retain the entries so object ids stay unique even when the input is a generator.
    seen_entries: dict[int, dict] = {}
    for entry in stale_entries:
        if not isinstance(entry, dict) or id(entry) in seen_entries:
            continue
        rule, path, job = entry.get("rule"), entry.get("path"), entry.get("job") or ""
        # The baseline's loader checks these; an entry built otherwise that does not hold three
        # strings gives no hint rather than stopping the report.
        if isinstance(rule, str) and isinstance(path, str) and isinstance(job, str):
            available[rule, path, job] += 1
            seen_entries[id(entry)] = entry

    candidates: dict[tuple[str, str, str], dict[int, Finding]] = defaultdict(dict)
    for finding in findings:
        location = finding.rule, finding.path, finding.job or ""
        if location in available and finding.state in (NEW, UNDECIDED) and finding.acceptance is None \
                and not baseline.expired_ignore(finding):
            candidates[location][id(finding)] = finding

    result = {}
    for location, group in candidates.items():
        if len({f.kind for f in group.values()}) != 1:
            continue
        count = available[location]
        if count >= len(group):
            result.update(dict.fromkeys(group, 1))
        else:
            # Only in-memory ties between otherwise indistinguishable findings use object id.
            ordered = sorted(group.values(), key=lambda f: (f.line, baseline.key(f), f.severity, id(f)))
            result.update((id(f), 1) for f in ordered[:count])
    return result
