"""Output formats for the checker: text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json

from obaaf import __version__
from obaaf.catalog import Catalog, load
from obaaf.checker import CheckResult, SEVERITY_ORDER

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


def to_text(result: CheckResult, catalog: Catalog | None = None, show_fixes: bool = True) -> str:
    catalog = catalog or load()
    lines = []
    for error in result.errors:
        lines.append(f"error: {error}")
    active = result.active()
    current = None
    for f in active:
        if f.path != current:
            current = f.path
            lines.append("")
            lines.append(current)
        rule = catalog.rules[f.rule]
        where = f"{f.scope or 'job'} {f.job}" if f.job else ""
        lines.append(f"  {f.line:>4}  {f.severity.upper():<6} {f.rule}  {rule['title']}" + (f"  [{where}]" if where else ""))
        lines.append(f"        {f.message}")
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
        lines.append(f"  ignored: {f.rule} {f.path}:{f.line} - {f.suppressed}")
    if result.notes:
        lines.append("")
        lines.append("Notes (advisory; they do not affect the result):")
        for note in result.notes:
            lines.append(f"  - {note}")
    return "\n".join(lines).lstrip("\n") + "\n"


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
            }
            for f in result.findings
        ],
        "notes": list(result.notes),
    }
    if result.jenkins_files:
        # Added in 0.3: present only when Jenkinsfiles were checked, so existing consumers see no change.
        payload["jenkins"] = {"advisory": True, "files": result.jenkins, "coverage": result.coverage}
    return json.dumps(payload, indent=2) + "\n"


def to_sarif(result: CheckResult, catalog: Catalog | None = None) -> str:
    """SARIF 2.1.0, suitable for GitHub code scanning (upload-sarif)."""
    catalog = catalog or load()
    used = sorted({f.rule for f in result.findings})
    rule_index = {rid: i for i, rid in enumerate(used)}
    rules = []
    for rid in used:
        rule = catalog.rules[rid]
        severity = max((f.severity for f in result.findings if f.rule == rid),
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
    for f in result.findings:
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
            "properties": {"security-severity": SECURITY_SEVERITY[f.severity]},
        }
        if f.suppressed:
            entry["suppressions"] = [{"kind": "external", "justification": f.suppressed}]
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
