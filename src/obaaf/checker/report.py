"""Output formats for the checker: text, JSON and SARIF 2.1.0."""

from __future__ import annotations

import json

from obaaf import __version__
from obaaf.catalog import Catalog, load
from obaaf.checker import CheckResult

SARIF_LEVEL = {"high": "error", "medium": "warning", "low": "note"}
SECURITY_SEVERITY = {"high": "8.0", "medium": "5.0", "low": "2.0"}


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
        where = f"job {f.job}" if f.job else ""
        lines.append(f"  {f.line:>4}  {f.severity.upper():<6} {f.rule}  {rule['title']}" + (f"  [{where}]" if where else ""))
        lines.append(f"        {f.message}")
        lines.append(f"        Requirement: {_requirements(rule)}")
        if show_fixes:
            lines.append(f"        Fix: {' '.join(rule['fix'].split())}")
        if _remediation(catalog, f.rule) == "architecture":
            lines.append("        Architecture: fixing this means adopting the agent and effect lanes, not a "
                         "one-line change. See templates/github-actions/.")
    suppressed = [f for f in result.findings if f.suppressed]
    cats = {"authority": {"high": 0, "medium": 0, "low": 0}, "hygiene": {"high": 0, "medium": 0, "low": 0}}
    for f in active:
        cats[_category(catalog, f.rule)][f.severity] += 1
    a, h = cats["authority"], cats["hygiene"]
    lines.append("")
    lines.append(f"{len(result.files)} workflow file(s) checked.")
    lines.append(f"Authority findings: {a['high']} high, {a['medium']} medium, {a['low']} low.")
    lines.append(f"Hygiene findings: {h['high']} high, {h['medium']} medium, {h['low']} low."
                 + (f" {len(suppressed)} ignored by configuration." if suppressed else ""))
    for f in suppressed:
        lines.append(f"  ignored: {f.rule} {f.path}:{f.line} - {f.suppressed}")
    if result.notes:
        lines.append("")
        lines.append("Notes (advisory; they do not affect the result):")
        for note in result.notes:
            lines.append(f"  - {note}")
    return "\n".join(lines).lstrip("\n") + "\n"


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
            }
            for f in result.findings
        ],
        "notes": list(result.notes),
    }
    return json.dumps(payload, indent=2) + "\n"


def to_sarif(result: CheckResult, catalog: Catalog | None = None) -> str:
    """SARIF 2.1.0, suitable for GitHub code scanning (upload-sarif)."""
    catalog = catalog or load()
    used = sorted({f.rule for f in result.findings})
    rule_index = {rid: i for i, rid in enumerate(used)}
    rules = []
    for rid in used:
        rule = catalog.rules[rid]
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
            "defaultConfiguration": {"level": SARIF_LEVEL[rule["severity"]]},
            "properties": {"tags": tags, "security-severity": SECURITY_SEVERITY[rule["severity"]],
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
