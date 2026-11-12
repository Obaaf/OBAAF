"""Output formats for the checker: text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json

from obaaf import __version__
from obaaf.catalog import Catalog, load
from obaaf.checker import CheckResult, SEVERITY_ORDER
from obaaf.checker import acceptance as acceptance_mod
from obaaf.checker import baseline as baseline_mod
from obaaf.checker.rules import ACCEPTED, FIXED, NEW, UNDECIDED
from obaaf.checker.workflow import one_line

SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.0"}


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
        if f.state == UNDECIDED:
            lines.append(one_line("        Cannot tell: no control that would clear this finding is known to be "
                                  f"missing, but not all could be verified, so it counts. {_controls(f)}."))
        else:
            lines.append(one_line(f"        Controls: {_controls(f)}."))
    return lines


def summary(result: CheckResult) -> dict:
    """How many findings are in each state. Findings ignored by configuration are accepted ones."""
    out = {NEW: 0, ACCEPTED: 0, UNDECIDED: 0, FIXED: 0}
    for f in result.findings:
        out[f.state] += 1
    return {"new": out[NEW], "accepted": out[ACCEPTED], "cannotTell": out[UNDECIDED], "fixed": out[FIXED],
            "notAccepted": len(result.not_accepted())}


def to_text(result: CheckResult, catalog: Catalog | None = None, show_fixes: bool = True) -> str:
    """The report a person reads. Text that comes from the files checked (paths, job and step names
    inside messages, notes) is printed with `one_line`, so a name that contains a line break cannot
    look like another line of the report. The JSON and SARIF forms carry the text as it is."""
    catalog = catalog or load()
    lines = []
    for error in result.errors:
        lines.append(f"error: {one_line(error)}")
    active = result.active()
    current = None
    for f in active:
        if f.path != current:
            current = f.path
            lines.append("")
            lines.append(one_line(current))
        rule = catalog.rules[f.rule]
        where = one_line(f"{f.scope or 'job'} {f.job}") if f.job else ""
        lines.append(f"  {f.line:>4}  {f.severity.upper():<6} {f.rule}  {rule['title']}" + (f"  [{where}]" if where else "")
                     + ("  (baseline)" if f.baselined else ""))
        lines.append(f"        {one_line(f.message)}")
        lines += _lifecycle_lines(f)
        lines.append(f"        Requirement: {_requirements(rule)}")
        if show_fixes:
            lines.append(f"        Fix: {' '.join(rule['fix'].split())}")
        if _remediation(catalog, f.rule) == "architecture":
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
        lines.append(one_line(f"  ignored: {f.rule} {f.path}:{f.line} - {f.suppressed}"))
    if result.baseline_used:
        accepted = sum(1 for f in active if f.baselined)
        lines.append(f"Baseline: {accepted} finding(s) accepted by the baseline, {len(active) - accepted} new.")
        if result.baseline_format == baseline_mod.FORMAT_V1:
            lines.append(f"  The baseline is in the old format ({baseline_mod.FORMAT_V1}). Its entries name no owner, "
                         "reason or expiry date, so none of them accepts a finding. Convert it once, saying who "
                         "accepts these findings, why and until when:")
            lines.append(one_line(f"    obaaf baseline migrate {result.baseline_path or 'FILE'} --owner @NAME "
                                  "--reason '...' --expires YYYY-MM-DD"))
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
    for name, value in (entry.get("facts") or {}).items():
        parts.append(f"{name}: {', '.join(value) if isinstance(value, list) else value}")
    return "; ".join(parts) or "the finding it names"


def _jenkins_coverage_text(result: CheckResult) -> list[str]:
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
        lines.append(f"  {path} ({kind}, {summary['digest'][:19]}...): {shown}")
        if summary["error"]:
            lines.append(f"    {summary['error']}")
            continue
        general = summary["unknowns"]
        if general:
            lines.append("    No rule can pass, because part of the pipeline was not analyzed:")
            for reason in general[:5]:
                lines.append(f"      {reason}")
            if len(general) > 5:
                lines.append(f"      ... and {len(general) - 5} more")
        for row in rows:
            specific = [r for r in row["reasons"] if r not in general]
            if row["status"] == "unknown" and specific:
                for reason in specific[:3]:
                    lines.append(f"    unknown {row['rule']}: {reason}")
                if len(specific) > 3:
                    lines.append(f"    unknown {row['rule']}: ... and {len(specific) - 3} more")
    return lines


def to_json(result: CheckResult, catalog: Catalog | None = None) -> str:
    catalog = catalog or load()
    payload = {
        "format": "obaaf-check/v0.1",
        "tool": f"obaaf {__version__}",
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
                **({"acceptance": f.acceptance.as_dict()} if f.acceptance is not None else {}),
                **({"controls": [{"name": c.name, "verdict": c.verdict, "detail": c.detail} for c in f.controls]}
                   if f.controls else {}),
            }
            # A fixed finding is not a finding to act on. It is listed under "fixed", so a consumer
            # that counts "findings" does not count it.
            for f in result.findings if f.state != FIXED
        ],
        "notes": list(result.notes),
        "summary": summary(result),
    }
    cleared = result.cleared()
    if cleared:
        payload["fixed"] = [
            {"rule": f.rule, "title": catalog.rules[f.rule]["title"], "severity": f.severity, "path": f.path,
             "line": f.line, "job": f.job, "step": f.step, "message": f.message,
             "controls": [{"name": c.name, "verdict": c.verdict, "detail": c.detail} for c in f.controls]}
            for f in cleared]
    if result.baseline_used:
        # Present only with --baseline, so existing consumers see no change.
        payload["baseline"] = {"stale": result.baseline_stale, "format": result.baseline_format}
    if result.jenkins_files:
        # Added in 0.3: present only when Jenkinsfiles were checked, so existing consumers see no change.
        payload["jenkins"] = {"advisory": True, "files": result.jenkins, "coverage": result.coverage}
    return json.dumps(payload, indent=2) + "\n"


def to_sarif(result: CheckResult, catalog: Catalog | None = None) -> str:
    """SARIF 2.1.0, suitable for GitHub code scanning (upload-sarif)."""
    catalog = catalog or load()
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
        entry = {
            "ruleId": f.rule,
            "ruleIndex": rule_index[f.rule],
            "level": SARIF_LEVEL[f.severity],
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity], "obaaf-state": f.state},
        }
        if f.acceptance is not None and not f.acceptance.valid:
            entry["properties"]["obaaf-not-accepted"] = "; ".join(f.acceptance.problems)
        if f.suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": f.suppressed}]
        if result.baseline_used and not f.suppressed:
            entry["baselineState"] = "unchanged" if f.baselined else "new"
        results.append(entry)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "obaaf", "version": __version__, "semanticVersion": __version__.split(".dev")[0],
                                "rules": rules}},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2) + "\n"
