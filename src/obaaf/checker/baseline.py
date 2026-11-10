"""Findings baselines for `obaaf check --baseline` (adopting the checker without hiding regressions).

A baseline records the findings a project has reviewed and accepted for now. With --baseline, those
findings are still reported but no longer fail the check; any other finding does. A baseline entry that
no longer matches a finding also fails the check, so an improvement is locked in by regenerating the
baseline and a removed finding cannot come back unnoticed.

Findings are matched without their line numbers, so unrelated edits do not churn the baseline. Everything
else that describes the finding (rule, severity, file, job, step and message) has to match, so a finding
that becomes more severe, or a job that gains another secret, counts as new.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path

from obaaf import __version__

FORMAT = "obaaf-baseline/v0.1"
_EXPIRED = re.compile(r" \(An ignore entry for this finding expired on \d{4}-\d{2}-\d{2}\.\)")


class BaselineError(ValueError):
    pass


def _identity(f) -> list:
    return [f.rule, f.severity, f.path, f.job or "", f.step or "", f.scope or "", _EXPIRED.sub("", f.message)]


def _digest(identity: list) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(identity, ensure_ascii=False).encode()).hexdigest()


def fingerprint(f) -> str:
    return _digest(_identity(f))


def _entry_identity(entry: dict) -> list:
    return [str(entry.get(k) or "") for k in ("rule", "severity", "path", "job", "step", "scope", "message")]


def expired_ignore(f) -> bool:
    """Whether the finding's ignore entry has expired (it is active again, and needs a decision)."""
    return bool(_EXPIRED.search(f.message))


def build(result) -> str:
    """The baseline for a check result: every finding not already ignored by configuration."""
    entries = []
    for f in result.findings:
        # An expired ignore entry needs renewing or removing; writing the finding into the baseline
        # would turn a reviewed, expiring decision into a permanent one without a reason.
        if f.suppressed or expired_ignore(f):
            continue
        rule, severity, path, job, step, scope, message = _identity(f)
        entry = {"fingerprint": fingerprint(f), "rule": rule, "severity": severity, "path": path}
        if job:
            entry["job"] = job
        if step:
            entry["step"] = step
        if scope:
            entry["scope"] = scope
        entry["message"] = message
        entries.append(entry)
    entries.sort(key=lambda e: (e["path"], e.get("job", ""), e["rule"], e["fingerprint"]))
    return json.dumps({"format": FORMAT, "tool": f"obaaf {__version__}", "findings": entries},
                      indent=2, ensure_ascii=False) + "\n"


def load(path: Path) -> list[dict]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline not found: {path} (create it with --write-baseline)") from exc
    except (OSError, ValueError) as exc:
        raise BaselineError(f"baseline {path} cannot be read: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") != FORMAT or not isinstance(data.get("findings"), list):
        raise BaselineError(f"baseline {path} is not an {FORMAT} file")
    for entry in data["findings"]:
        if not isinstance(entry, dict) or not str(entry.get("fingerprint", "")).startswith("sha256:"):
            raise BaselineError(f"baseline {path} has an entry without a fingerprint: {entry!r}")
        # The fingerprint must describe the entry a reviewer reads; otherwise an innocent-looking line
        # could carry the fingerprint of a different, worse finding.
        if not entry.get("rule") or not entry.get("severity") or not entry.get("path") or \
                _digest(_entry_identity(entry)) != entry["fingerprint"]:
            raise BaselineError(f"baseline {path} has an entry whose fingerprint does not match its rule, "
                                f"severity, path, job, step and message: {entry.get('rule')} {entry.get('path')}; "
                                "regenerate the baseline with --write-baseline")
    return data["findings"]


def apply(result, entries: list[dict]) -> None:
    """Mark findings the baseline accepts, and record baseline entries that no longer match any finding."""
    remaining = Counter(e["fingerprint"] for e in entries)
    # Suppressed findings first: an entry for a finding that has since been given an ignore entry is
    # accounted for, not stale.
    for f in sorted(result.findings, key=lambda f: not f.suppressed):
        fp = fingerprint(f)
        if remaining[fp] > 0:
            remaining[fp] -= 1
            if not f.suppressed:
                f.baselined = True
    stale = []
    for entry in entries:
        if remaining[entry["fingerprint"]] > 0:
            remaining[entry["fingerprint"]] -= 1
            stale.append(entry)
    result.baseline_stale = stale
    result.baseline_used = True
