"""Output formats for the checker: text, JSON and SARIF 2.1.0.

Each of the three leads with the risk that has been accepted: how many findings, at what severity,
by whom and until when. A gate that has accepted 38 findings and reports "0 new" has said the least
important thing first.
"""

from __future__ import annotations

import json
import shlex
import unicodedata
from datetime import date

from obaaf import __version__
from obaaf.catalog import Catalog, load
from obaaf.checker import CheckResult, SEVERITY_ORDER
from obaaf.checker import acceptance as acceptance_mod
from obaaf.checker import baseline as baseline_mod
from obaaf.checker.rules import ACCEPTED, FIXED, NEW, UNDECIDED
from obaaf.checker.workflow import one_line

SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}
SEVERITIES = ("high", "medium", "low", "info")
# An acceptance that expires within this many days is listed as expiring soon. Nothing else warns:
# on the day after its date the finding counts again and a gate that passed fails.
EXPIRY_WARNING_DAYS = 30
# How many owners, and how many acceptances about to expire, the text report lists before it says
# "and N more". The JSON and SARIF forms carry all of them.
SHOWN = 10
NO_OWNER = "(no owner recorded)"


def _requirements(rule: dict) -> str:
    refs = list(rule.get("requirements", [])) + list(rule.get("agent_controls", []))
    return ", ".join(refs) if refs else "-"


def _category(catalog: Catalog, rule_id: str) -> str:
    cat = catalog.rules[rule_id].get("category")
    return cat if cat in ("authority", "hygiene") else "authority"


def _remediation(catalog: Catalog, rule_id: str) -> str:
    return catalog.rules[rule_id].get("remediation") or "config"


def _entry_name(made) -> str:
    return "baseline entry" if made.source == acceptance_mod.BASELINE else "ignore entry"


def _controls(f) -> str:
    return "; ".join(f"{c.name}: {c.verdict}" + (f" ({c.detail})" if c.detail else "") for c in f.controls)


def _control_lines(f) -> list[str]:
    """One line for each control: the verdict first, in a column, then the control and what the
    checker found."""
    return [one_line(f"          {c.verdict:<11}  {c.name}" + (f" ({c.detail})" if c.detail else ""))
            for c in f.controls]


def _control_dict(c) -> dict:
    return {**({"id": c.id} if c.id else {}), "name": c.name, "verdict": c.verdict, "detail": c.detail}


def _lifecycle_lines(f) -> list[str]:
    """What the report says under a finding about where it stands: who accepted it and until when,
    why an entry that names it does not count, and what was established about its controls."""
    lines = []
    made = f.acceptance
    if made is not None and made.valid and f.baselined:
        lines.append(one_line(f"        Accepted by {made.owner} until {made.expires}: {made.reason}"))
    elif made is not None and not made.valid:
        lines.append(one_line(f"        Not accepted: the {_entry_name(made)} that names this finding does not "
                              f"count, because {'; '.join(made.problems)}."))
    if f.controls:
        needed = "it is cleared when this is verified" if len(f.controls) == 1 else \
            f"it is cleared when all {len(f.controls)} are verified"
        if f.state == UNDECIDED:
            lines.append("        Cannot tell: no control that would clear this finding is known to be missing, "
                         f"but not all could be verified, so it counts ({needed}):")
        else:
            lines.append(f"        Controls ({needed}):")
        lines += _control_lines(f)
    return lines


def _by_severity(findings) -> dict:
    out = {severity: 0 for severity in SEVERITIES}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def _severities(counts: dict) -> str:
    """"19 high, 19 low": the severities that have findings, the most severe first."""
    return ", ".join(f"{counts[s]} {s}" for s in (*SEVERITIES, *sorted(set(counts) - set(SEVERITIES))) if counts.get(s))


def _in_days(days: int) -> str:
    return "today is its last day" if days == 0 else f"in {_days(days)}"


def _days(days: int) -> str:
    return f"{days} day{'' if days == 1 else 's'}"


_ASCII_LOWER = {ord(upper): ord(upper) + 32 for upper in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"}


def _owner_key(name: str) -> str:
    """What two spellings of one owner have in common: the letters A to Z in either case, which is
    how GitHub compares account names, and one way of writing an accented letter. Nothing else is
    folded: `casefold` would make strasse@x.de and straße@x.de one owner, and they are two
    mailboxes. Two rows for one person is an honest answer; one row for two people is a wrong number."""
    return unicodedata.normalize("NFC", name).translate(_ASCII_LOWER)


def _path_header(path) -> str:
    """A file's path as the line that heads its findings. That line starts in the first column, where
    every line the checker writes in its own words also starts, and each of those has a space in it.
    A path is printed as it is only when every character in it is a visible ASCII character, which
    leaves nothing that can stand for a space: not a space, and not one of the characters outside
    ASCII that print as a blank (U+2800, U+3164 and others; there is no complete list to rely on).
    Any other path is put in quotes, so its line begins with a quotation mark and no line of the
    checker's does."""
    shown = one_line(path)
    return shown if shown and all("!" <= ch <= "~" for ch in shown) else f'"{shown}"'


def _source(f) -> str:
    """Whether an accepted finding was accepted by a baseline entry or by an ignore entry."""
    if f.acceptance is not None:
        return f.acceptance.source
    return acceptance_mod.IGNORE if f.suppressed else acceptance_mod.BASELINE


def accepted_risk(result: CheckResult, expiring_within: int = EXPIRY_WARNING_DAYS,
                  today: date | None = None) -> dict:
    """How much risk is accepted, by whom and until when: what every report leads with.

    It counts the findings whose state is `accepted`: a valid ignore entry or a valid baseline entry
    names them, so they do not fail the check. Each owner is listed with how many findings they
    accepted, at what severity, and the first date on which one of their acceptances runs out.
    Two spellings are one owner when they differ only in the case of A to Z (@Octocat and @octocat
    are one account to GitHub) or in how an accented letter is stored (`_owner_key`); the owner is
    shown as spelt on the first of their findings in the report's order. `expiringSoon` lists the
    acceptances that run out within `expiring_within` days of the day the check ran; 0 turns that
    list off.
    """
    today = today or result.today or date.today()
    accepted = [f for f in result.findings if f.state == ACCEPTED]
    sources = {acceptance_mod.BASELINE: 0, acceptance_mod.IGNORE: 0}
    owners: dict[str, dict] = {}
    dated = []
    for f in accepted:
        made = f.acceptance
        sources[_source(f)] = sources.get(_source(f), 0) + 1
        name = str((made.owner if made is not None else None) or "")
        day = acceptance_mod.parse_date(made.expires) if made is not None else None
        row = owners.setdefault(_owner_key(name), {"owner": name or None, "findings": [], "days": []})
        row["findings"].append(f)
        if day is not None:
            row["days"].append(day)
            dated.append((day, f))
    nearest = min((day for day, _ in dated), default=None)
    soon = sorted(((day, f) for day, f in dated if expiring_within > 0 and (day - today).days <= expiring_within),
                  key=lambda pair: (pair[0], pair[1].path, pair[1].line, pair[1].rule))
    return {
        "asOf": today.isoformat(),
        "total": len(accepted),
        "bySeverity": _by_severity(accepted),
        "bySource": sources,
        "owners": [
            {"owner": row["owner"], "total": len(row["findings"]), "bySeverity": _by_severity(row["findings"]),
             "nearestExpiry": min(row["days"]).isoformat() if row["days"] else None}
            for row in sorted(owners.values(), key=lambda r: (-len(r["findings"]), _owner_key(r["owner"] or "")))],
        "nearestExpiry": nearest.isoformat() if nearest else None,
        "daysToNearestExpiry": (nearest - today).days if nearest else None,
        "expiringSoon": {
            "withinDays": max(0, expiring_within),
            "total": len(soon),
            "findings": [
                {"rule": f.rule, "severity": f.severity, "path": f.path, "line": f.line, "job": f.job,
                 **({"scope": f.scope} if f.scope else {}),
                 "owner": f.acceptance.owner, "expires": day.isoformat(), "daysLeft": (day - today).days,
                 "source": _source(f)}
                for day, f in soon],
        },
    }


def _expiring_text(soon: dict) -> str:
    """One sentence on the acceptances that are about to run out, for the text and SARIF reports."""
    first = soon["findings"][0]
    return (f"{soon['total']} acceptance(s) expire within {_days(soon['withinDays'])}, the first on "
            f"{first['expires']} ({_in_days(first['daysLeft'])}). From the day after its date an accepted "
            "finding counts again and can fail the check: fix it, or renew the acceptance in a reviewed change.")


def _lead_lines(result: CheckResult, risk: dict) -> list[str]:
    """The first lines of the text report: the accepted risk, then everything else in one line."""
    lines = []
    if not risk["total"]:
        lines.append("Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry.")
    else:
        lines.append(f"Accepted risk: {risk['total']} finding(s) are accepted and do not fail the check "
                     f"({_severities(risk['bySeverity'])}).")
        for row in risk["owners"][:SHOWN]:
            until = f"; the first expires {row['nearestExpiry']}" if row["nearestExpiry"] else ""
            lines.append(one_line(f"  {row['owner'] or NO_OWNER}: {row['total']} ({_severities(row['bySeverity'])})"
                                  f"{until}"))
        if len(risk["owners"]) > SHOWN:
            lines.append(f"  ... and {len(risk['owners']) - SHOWN} more owner(s); --format json lists them all")
        sources = risk["bySource"]
        lines.append(f"  {sources[acceptance_mod.BASELINE]} accepted by baseline entries, "
                     f"{sources[acceptance_mod.IGNORE]} by ignore entries in the checker configuration.")
        if risk["nearestExpiry"]:
            lines.append(f"  Nearest expiry: {risk['nearestExpiry']} ({_in_days(risk['daysToNearestExpiry'])}).")
    soon = risk["expiringSoon"]
    if soon["total"]:
        lines.append(f"Expiring soon: {_expiring_text(soon)}")
        for row in soon["findings"][:SHOWN]:
            where = f" [{row.get('scope') or 'job'} {row['job']}]" if row["job"] else ""
            lines.append(one_line(f"  {row['expires']}  {row['owner'] or NO_OWNER}  {row['rule']} "
                                  f"{row['path']}:{row['line']}{where}  ({row['source']} entry)"))
        if soon["total"] > SHOWN:
            lines.append(f"  ... and {soon['total'] - SHOWN} more; --format json lists them all")
    groups = {state: [f for f in result.findings if f.state == state] for state in (NEW, UNDECIDED, FIXED)}

    def count(state: str, words: str) -> str:
        found = groups[state]
        return f"{len(found)} {words}" + (f" ({_severities(_by_severity(found))})" if found else "")

    lines.append(f"Other findings: {count(NEW, 'new')}, {count(UNDECIDED, 'cannot tell')}, "
                 f"{len(groups[FIXED])} fixed by controls the checker verified.")
    if result.baseline_stale:
        lines.append(f"Baseline entries that no longer match a finding: {len(result.baseline_stale)}. At or above "
                     "--fail-on they fail the check; they are listed below.")
    if result.errors:
        lines.append(f"Errors: {len(result.errors)}. Each names something the checker could not read, and the "
                     "check fails whatever else it found.")
    return lines


def summary(result: CheckResult) -> dict:
    """How many findings are in each state. Findings ignored by configuration are accepted ones."""
    out = {NEW: 0, ACCEPTED: 0, UNDECIDED: 0, FIXED: 0}
    for f in result.findings:
        out[f.state] += 1
    return {"new": out[NEW], "accepted": out[ACCEPTED], "cannotTell": out[UNDECIDED], "fixed": out[FIXED],
            "notAccepted": len(result.not_accepted())}


def to_text(result: CheckResult, catalog: Catalog | None = None, show_fixes: bool = True,
            expiring_within: int = EXPIRY_WARNING_DAYS) -> str:
    """The report a person reads. It leads with the accepted risk. Text that comes from the files
    checked (paths, job and step names inside messages, notes, the owner and reason of an
    acceptance) is printed with `one_line`, so a name that contains a line break cannot look like
    another line of the report. The JSON and SARIF forms carry the text as it is."""
    catalog = catalog or load()
    lines = _lead_lines(result, accepted_risk(result, expiring_within))
    if result.errors:
        lines.append("")
    for error in result.errors:
        lines.append(f"error: {one_line(error)}")
    active = result.active()
    current = None
    for f in active:
        if f.path != current:
            current = f.path
            lines.append("")
            lines.append(_path_header(current))
        rule = catalog.rules[f.rule]
        where = one_line(f"{f.scope or 'job'} {f.job}") if f.job else ""
        lines.append(f"  {f.line:>4}  {f.severity.upper():<6} {f.rule}  {rule['title']}" + (f"  [{where}]" if where else "")
                     + ("  (baseline)" if f.baselined else ""))
        lines.append(f"        {one_line(f.message)}")
        lines += _lifecycle_lines(f)
        lines.append(f"        Requirement: {_requirements(rule)}")
        if show_fixes:
            lines.append(f"        Fix: {' '.join(rule['fix'].split())}")
        if _remediation(catalog, f.rule) == "architecture" and not f.controls:
            where_to = "docs/jenkins.md" if f.rule.startswith("OBAAF-JEN-") else "templates/github-actions/"
            lines.append("        Architecture: fixing this means adopting the agent and effect lanes, not a "
                         f"one-line change. See {where_to}.")
    suppressed = [f for f in result.findings if f.suppressed]
    cats = {cat: {severity: 0 for severity in SARIF_LEVEL} for cat in ("authority", "hygiene")}
    for f in active:
        cats[_category(catalog, f.rule)][f.severity] += 1
    a, h = cats["authority"], cats["hygiene"]
    lines.append("")
    if result.jenkins_files:
        lines += _jenkins_coverage_text(result)
        lines.append("")
    if result.workflow_files or not result.jenkins_files:
        lines.append(f"{len(result.workflow_files)} workflow file(s) checked.")
    if result.jenkins_files:
        lines.append(f"{len(result.jenkins_files)} Jenkinsfile(s) checked (advisory).")
    lines.append(f"Authority findings: {a['high']} high, {a['medium']} medium, {a['low']} low.")
    lines.append(f"Hygiene findings: {h['high']} high, {h['medium']} medium, {h['low']} low."
                 + (f" {len(suppressed)} ignored by configuration." if suppressed else ""))
    if a['info'] or h['info']:
        lines.append(f"Informational findings (not gated): {a['info']} authority, {h['info']} hygiene.")
    for f in suppressed:
        made = f.acceptance
        # A finding that an entry ignores and whose controls were all verified is fixed, not accepted.
        said = f"accepted by {made.owner} until {made.expires}: {made.reason}" \
            if made is not None and made.valid and f.state == ACCEPTED else f.suppressed
        lines.append(one_line(f"  ignored: {f.rule} {f.path}:{f.line} - {said}"))
    if result.baseline_used:
        accepted = sum(1 for f in active if f.baselined)
        lines.append(f"Baseline: {accepted} finding(s) accepted by the baseline, {len(active) - accepted} new.")
        if result.baseline_format == baseline_mod.FORMAT_V1:
            lines.append(f"  The baseline is in the old format ({baseline_mod.FORMAT_V1}). Its entries name no owner, "
                         "reason or expiry date, so none of them accepts a finding. Convert it once, saying who "
                         "accepts these findings, why and until when:")
            checked = f" {shlex.quote(result.checked)}" if result.checked not in ("", ".") else ""
            given = "".join(f" {shlex.quote(str(word))}" for word in result.options)
            lines.append(one_line(f"    obaaf baseline migrate {shlex.quote(result.baseline_path or 'FILE')}{checked} "
                                  f"--owner OWNER --reason REASON --expires YYYY-MM-DD{given}"))
        if result.baseline_stale:
            lines.append(f"  {len(result.baseline_stale)} baseline entr{'y no longer matches' if len(result.baseline_stale) == 1 else 'ies no longer match'} "
                         "a finding. At or above --fail-on, that fails the check: regenerate the baseline "
                         "with --write-baseline so the improvement is locked in.")
            for entry in result.baseline_stale:
                where = f" [{entry.get('scope') or 'job'} {entry['job']}]" if entry.get("job") else ""
                lines.append(one_line(f"  no longer found: {entry.get('rule')} {entry.get('path')}{where} - "
                                      f"{_entry_text(entry)}"))
    refused = result.not_accepted()
    if refused:
        lines.append(f"Not accepted: {len(refused)} finding(s) are named by an ignore or baseline entry that does "
                     "not count. An acceptance needs an owner, a reason and an expiry date that has not passed "
                     f"and is at most {acceptance_mod.MAX_DAYS} days ahead; until it has them the finding counts.")
    undecided = [f for f in active if f.state == UNDECIDED]
    if undecided:
        lines.append(f"Cannot tell: for {len(undecided)} finding(s) a control that would clear it could not be "
                     "verified. They count as findings; the checker does not assume a control it cannot read.")
    cleared = result.cleared()
    if cleared:
        lines.append(f"Fixed: {len(cleared)} finding(s) are cleared by controls the checker verified (not counted "
                     "above):")
        for f in cleared:
            where = f" [{f.scope or 'job'} {f.job}]" if f.job else ""
            lines.append(one_line(f"  fixed: {f.rule} {f.path}:{f.line}{where} - {_controls(f)}"))
    if result.notes:
        lines.append("")
        lines.append("Notes (advisory; they do not affect the result):")
        for note in result.notes:
            lines.append(f"  - {one_line(note)}")
    return "\n".join(lines).lstrip("\n") + "\n"


def _entry_text(entry: dict) -> str:
    """What a baseline entry is about, for the line that says it no longer matches a finding."""
    if entry.get("message"):
        return str(entry["message"])
    parts = [str(entry["kind"])] if entry.get("kind") else []
    facts = entry.get("facts")
    for name, value in (facts.items() if isinstance(facts, dict) else ()):
        parts.append(f"{name}: {', '.join(str(v) for v in value) if isinstance(value, list) else value}")
    return "; ".join(parts) or "the finding it names"


def _jenkins_coverage_text(result: CheckResult) -> list[str]:
    """The coverage of each Jenkinsfile. A path, an error and a reason are text from the files checked
    and are printed with `one_line`, like every other such text in the report."""
    lines = ["Jenkins coverage (advisory). Exit status 0 is not a conformance decision: controller settings "
             "(authorization, build authorization, agents, library trust, Replay, network policy) are not in a "
             "Jenkinsfile, and what the checker cannot see is listed as unknown."]
    for summary in result.jenkins:
        path = summary["path"]
        rows = [c for c in result.coverage if c["path"] == path]
        counts = {}
        for row in rows:
            counts[row["status"]] = counts.get(row["status"], 0) + 1
        order = ("fail", "ignored", "unknown", "pass", "not applicable")
        shown = ", ".join(f"{counts[k]} {k}" for k in order if counts.get(k))
        kind = summary["kind"] or "not analyzed"
        lines.append(one_line(f"  {path} ({kind}, {summary['digest'][:19]}...): {shown}"))
        if summary["error"]:
            lines.append(one_line(f"    {summary['error']}"))
            continue
        general = summary["unknowns"]
        if general:
            lines.append("    No rule can pass, because part of the pipeline was not analyzed:")
            for reason in general[:5]:
                lines.append(one_line(f"      {reason}"))
            if len(general) > 5:
                lines.append(f"      ... and {len(general) - 5} more")
        for row in rows:
            specific = [r for r in row["reasons"] if r not in general]
            if row["status"] == "unknown" and specific:
                for reason in specific[:3]:
                    lines.append(one_line(f"    unknown {row['rule']}: {reason}"))
                if len(specific) > 3:
                    lines.append(f"    unknown {row['rule']}: ... and {len(specific) - 3} more")
    return lines


def _acceptance_dict(f, today: date) -> dict:
    """A finding's acceptance for the JSON report, with the days it has left when it is valid."""
    out = f.acceptance.as_dict()
    day = acceptance_mod.parse_date(f.acceptance.expires)
    if day is not None:
        out["expires"] = day.isoformat()
    if f.acceptance.valid and day is not None:
        out["daysLeft"] = (day - today).days
    return out


def to_json(result: CheckResult, catalog: Catalog | None = None,
            expiring_within: int = EXPIRY_WARNING_DAYS) -> str:
    """Every field of earlier versions is kept, under the name it had. `acceptedRisk` and `summary`
    come first, before the findings."""
    catalog = catalog or load()
    today = result.today or date.today()
    payload = {
        "format": "obaaf-check/v0.1",
        "tool": f"obaaf {__version__}",
        # Added in 0.4: how much risk is accepted, by whom and until when.
        "acceptedRisk": accepted_risk(result, expiring_within, today),
        "summary": summary(result),
        "files": result.files,
        "errors": result.errors,
        "findings": [
            {
                "rule": f.rule,
                "title": catalog.rules[f.rule]["title"],
                "severity": f.severity,
                "category": _category(catalog, f.rule),
                "remediation": _remediation(catalog, f.rule),
                "path": f.path,
                "line": f.line,
                "job": f.job,
                "step": f.step,
                "message": f.message,
                "requirements": catalog.rules[f.rule].get("requirements", []),
                "agentControls": catalog.rules[f.rule].get("agent_controls", []),
                "fix": " ".join(catalog.rules[f.rule]["fix"].split()),
                "suppressed": f.suppressed,
                **({"scope": f.scope} if f.scope else {}),
                **({"baselined": f.baselined} if result.baseline_used else {}),
                # Added in 0.4: where the finding stands, and what identifies it for an acceptance.
                "state": f.state,
                **({"kind": f.kind} if f.kind else {}),
                **({"facts": f.facts} if f.facts else {}),
                **({"acceptance": _acceptance_dict(f, today)} if f.acceptance is not None else {}),
                **({"controls": [_control_dict(c) for c in f.controls]} if f.controls else {}),
            }
            # A fixed finding is not a finding to act on. It is listed under "fixed", so a consumer
            # that counts "findings" does not count it.
            for f in result.findings if f.state != FIXED
        ],
        "notes": list(result.notes),
    }
    cleared = result.cleared()
    if cleared:
        payload["fixed"] = [
            {"rule": f.rule, "title": catalog.rules[f.rule]["title"], "severity": f.severity, "path": f.path,
             "line": f.line, "job": f.job, "step": f.step, "message": f.message,
             "controls": [_control_dict(c) for c in f.controls]}
            for f in cleared]
    if result.baseline_used:
        # Present only with --baseline, so existing consumers see no change.
        payload["baseline"] = {"stale": result.baseline_stale, "format": result.baseline_format}
    if result.jenkins_files:
        # Added in 0.3: present only when Jenkinsfiles were checked, so existing consumers see no change.
        payload["jenkins"] = {"advisory": True, "files": result.jenkins, "coverage": result.coverage}
    return json.dumps(payload, indent=2) + "\n"


# What a run reports besides its results, each with an id a consumer can filter on.
NOTIFICATIONS = {
    "accepted-risk": "How much risk is accepted, by whom and until when",
    "acceptance-expiring": "Acceptances that run out soon",
    "not-read": "Something the checker could not read; the check fails",
    "baseline": "Baseline entries that no longer match a finding, and a baseline in the old format",
    "note": "A note; it does not affect the result",
}


def _sentence(text: str) -> str:
    text = " ".join(str(text).split())
    return text if text.endswith((".", "!", "?")) else text + "."


def _accepted_text(f) -> str:
    """Who accepted a finding, until when and why, as one sentence. Always text: a finding marked
    accepted by hand, with no acceptance recorded, says so."""
    made = f.acceptance
    if made is None:
        return _sentence(f"Accepted; {f.suppressed}" if f.suppressed else f"Accepted; {NO_OWNER}")
    return _sentence(f"Accepted by {made.owner or NO_OWNER} until {made.expires}: {made.reason}")


def _sarif_message(f) -> str:
    """The finding's message, then where it stands. GitHub code scanning shows a result's message and
    none of its properties or suppressions, so who accepted a finding, why an acceptance does not
    count and what was established about its controls are said here in words as well."""
    parts = [str(f.message or "")]
    made = f.acceptance
    if f.state == ACCEPTED and made is not None:
        parts.append(_accepted_text(f))
    elif made is not None and not made.valid:
        parts.append(_sentence(f"Not accepted: the {_entry_name(made)} that names this finding does not count, "
                               f"because {'; '.join(made.problems)}"))
    if f.controls:
        parts.append(_sentence(f"Controls: {_controls(f)}"))
    return " ".join(part for part in parts if part)


def _notification(kind: str, level: str, text) -> dict:
    return {"descriptor": {"id": kind, "index": list(NOTIFICATIONS).index(kind)}, "level": level,
            "message": {"text": str(text)}}


def _notifications(result: CheckResult, risk: dict) -> list[dict]:
    """The accepted risk first, then what else a reader of the text report is told outside the
    findings: acceptances about to run out, what could not be read, baseline entries that no longer
    match, and the notes."""
    if risk["total"]:
        owners = "; ".join(f"{row['owner'] or NO_OWNER}: {row['total']}"
                           + (f", first expiry {row['nearestExpiry']}" if row["nearestExpiry"] else "")
                           for row in risk["owners"])
        lead = (f"Accepted risk: {risk['total']} finding(s) are accepted and do not fail the check "
                f"({_severities(risk['bySeverity'])}). By owner: {owners}.")
    else:
        lead = "Accepted risk: none. No finding is accepted by a baseline entry or an ignore entry."
    out = [_notification("accepted-risk", "note", lead)]
    if risk["expiringSoon"]["total"]:
        out.append(_notification("acceptance-expiring", "warning", _expiring_text(risk["expiringSoon"])))
    out += [_notification("not-read", "error", error) for error in result.errors]
    if result.baseline_used and result.baseline_format == baseline_mod.FORMAT_V1:
        out.append(_notification("baseline", "warning",
                                 f"The baseline is in the old format ({baseline_mod.FORMAT_V1}). Its entries name no "
                                 "owner, reason or expiry date, so none of them accepts a finding. Convert it with "
                                 "obaaf baseline migrate."))
    for entry in result.baseline_stale:
        where = f" [{entry.get('scope') or 'job'} {entry['job']}]" if entry.get("job") else ""
        out.append(_notification("baseline", "warning",
                                 f"A baseline entry no longer matches a finding: {entry.get('rule')} "
                                 f"{entry.get('path')}{where} - {_entry_text(entry)}. At or above --fail-on that "
                                 "fails the check; write the baseline again so the improvement is locked in."))
    out += [_notification("note", "note", note) for note in result.notes]
    return out


def to_sarif(result: CheckResult, catalog: Catalog | None = None,
             expiring_within: int = EXPIRY_WARNING_DAYS) -> str:
    """SARIF 2.1.0, suitable for GitHub code scanning (upload-sarif).

    The run leads with the accepted risk: in `properties` as data (`obaaf-accepted-risk`, the same
    object as `acceptedRisk` in the JSON report) and as the first notification of its invocation.
    Errors and notes are notifications too, and a run with an error has `executionSuccessful`
    false. An accepted finding is a result with a suppression whose status is `accepted`.

    A result that is not accepted has an empty list of suppressions, which is how SARIF says "not
    suppressed"; leaving the list out would say that nobody knows.

    GitHub's page on its SARIF support lists none of `suppressions`, `invocations`, `baselineState`
    or the property bags of a run or a result among the fields code scanning uses (read 2026-11-12;
    no upload was made to check it). Going by that page, an accepted finding is an open alert there
    like any other, and a refused file shows only as a failed step. The page does list each
    result's message, which is why the message carries the acceptance and the controls in words
    (`_sarif_message`).
    """
    catalog = catalog or load()
    today = result.today or date.today()
    risk = accepted_risk(result, expiring_within, today)
    reported = [f for f in result.findings if f.state != FIXED]
    used = sorted({f.rule for f in reported})
    rule_index = {rid: i for i, rid in enumerate(used)}
    rules = []
    for rid in used:
        rule = catalog.rules[rid]
        severity = max((f.severity for f in reported if f.rule == rid),
                       key=SEVERITY_ORDER.__getitem__)
        cat = _category(catalog, rid)
        tags = [f"obaaf-{cat}", "security", "supply-chain"] + list(rule.get("requirements", [])) \
            + list(rule.get("agent_controls", []))
        rules.append({
            "id": rid,
            "name": rid.replace("-", ""),
            "shortDescription": {"text": rule["title"]},
            "fullDescription": {"text": " ".join(rule["description"].split())},
            "help": {
                "text": "Fix: " + " ".join(rule["fix"].split()),
                "markdown": f"**Fix:** {' '.join(rule['fix'].split())}\n\n**Requirements:** {_requirements(rule)}",
            },
            "defaultConfiguration": {"level": SARIF_LEVEL[severity]},
            "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[severity],
                           "obaaf-category": cat, "obaaf-remediation": _remediation(catalog, rid)},
        })
    results = []
    for f in reported:
        made = f.acceptance
        entry = {
            "ruleId": f.rule,
            "ruleIndex": rule_index[f.rule],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": _sarif_message(f)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "obaaf-state": f.state},
        }
        if made is not None and not made.valid:
            entry["properties"]["obaaf-not-accepted"] = "; ".join(made.problems)
        if f.controls:
            entry["properties"]["obaaf-controls"] = [_control_dict(c) for c in f.controls]
        entry["suppressions"] = []
        if f.state == ACCEPTED:
            # Who accepted it, why and until when, as SARIF says an accepted result: a suppression.
            if made is not None:
                day = acceptance_mod.parse_date(made.expires)
                entry["properties"]["obaaf-acceptance"] = {
                    "source": made.source, "owner": made.owner, "reason": made.reason,
                    "expires": day.isoformat() if day is not None else made.expires,
                    **({"daysLeft": (day - today).days} if day is not None else {})}
            entry["suppressions"] = [{"kind": "external", "status": "accepted", "justification": _accepted_text(f)}]
        if result.baseline_used and not f.suppressed:
            entry["baselineState"] = "unchanged" if f.baselined else "new"
        results.append(entry)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "obaaf", "version": __version__, "semanticVersion": __version__.split(".dev")[0],
                                "rules": rules,
                                "notifications": [{"id": kind, "shortDescription": {"text": text}}
                                                  for kind, text in NOTIFICATIONS.items()]}},
            "properties": {"obaaf-accepted-risk": risk, "obaaf-summary": summary(result)},
            "invocations": [{"executionSuccessful": not result.errors,
                             "toolExecutionNotifications": _notifications(result, risk)}],
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2) + "\n"
