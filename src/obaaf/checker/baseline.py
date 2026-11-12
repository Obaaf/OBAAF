"""Baselines for `obaaf check --baseline`: the findings a project has accepted for now.

With --baseline, a finding that a valid baseline entry accepts is still reported and does not fail
the check; any other finding does. An entry is valid when it names an owner, gives a reason and
carries an expiry date that has not passed and is at most a year ahead (see `acceptance`). An entry
that is not valid accepts nothing: its finding counts as new, and the report says what the entry
lacks. An entry that no longer matches any finding also fails the check, so a fix is locked in.

Two formats are read.

`obaaf-baseline/v0.2` (written by this version). An entry holds what the finding is (rule, file, job,
step, which of the rule's cases, and the values it is about, such as the secrets a job receives),
the severity it was accepted at, and the owner, reason and expiry date. Nothing in it depends on how
a message is worded or on a line number, and there is no separate fingerprint to disagree with the
text a reviewer reads: the entry accepts exactly the finding its fields describe. A finding that is
now more severe than the entry says is not accepted by it.

`obaaf-baseline/v0.1` (written by 0.2.0 and 0.3.0). Its entries name no owner, reason or expiry
date, so none of them accepts a finding. The file is still read, so the report can say which
findings it used to cover, and `obaaf baseline migrate` turns it into a v0.2 file once someone says
who accepts those findings, why and until when.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from obaaf import __version__
from obaaf.checker import acceptance as acceptance_mod
from obaaf.checker.rules import FIXED

FORMAT_V1 = "obaaf-baseline/v0.1"
FORMAT = "obaaf-baseline/v0.2"
SEVERITIES = {"info": 0, "low": 1, "medium": 2, "high": 3}
_EXPIRED = re.compile(r" \(An ignore entry for this finding expired on \d{4}-\d{2}-\d{2}\.\)")
_LONE_SURROGATE = re.compile(r"[\ud800-\udfff]")
_IDENTITY_KEYS = ("rule", "path", "job", "step", "scope", "kind", "facts", "message")
_ENTRY_KEYS = frozenset(_IDENTITY_KEYS) | {"severity", "owner", "reason", "expires"}
V1_PROBLEM = "it is an old-format entry, which names no owner, reason or expiry date"


class BaselineError(ValueError):
    pass


@dataclass
class Baseline:
    format: str
    entries: list[dict] = field(default_factory=list)
    path: str = ""

    @property
    def legacy(self) -> bool:
        return self.format == FORMAT_V1


# ------------------------------------------------------------------ what a finding is
def identity(f) -> dict:
    """What identifies a finding for an acceptance: the rule, the file, the job and step, and either
    the rule's case and the values it is about, or, for a finding that has none, its message."""
    out: dict = {"rule": f.rule, "path": f.path}
    if f.job:
        out["job"] = f.job
    if f.step:
        out["step"] = f.step
    if f.scope:
        out["scope"] = f.scope
    if f.facts is None:
        out["message"] = _EXPIRED.sub("", f.message)
    else:
        if f.kind:
            out["kind"] = f.kind
        if f.facts:
            out["facts"] = f.facts
    return out


def _key(ident: dict) -> str:
    # ASCII only, so a name that is not valid Unicode (a lone surrogate) cannot stop the comparison.
    return json.dumps(ident, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def key(f) -> str:
    return _key(identity(f))


def _entry_key(entry: dict) -> str:
    return _key({k: entry[k] for k in _IDENTITY_KEYS if k in entry})


def dumps(data) -> str:
    """JSON a person can read (names are not escaped), which is still valid UTF-8 when a name holds
    a lone surrogate: that one character is written as its \\uXXXX escape."""
    text = json.dumps(data, indent=2, ensure_ascii=False)
    return _LONE_SURROGATE.sub(lambda m: f"\\u{ord(m.group()):04x}", text) + "\n"


# ------------------------------------------------------------------ the old format
def _identity_v1(f) -> list:
    return [f.rule, f.severity, f.path, f.job or "", f.step or "", f.scope or "", _EXPIRED.sub("", f.message)]


def _digest(ident: list) -> str:
    data = json.dumps(ident, ensure_ascii=False).encode("utf-8", "surrogatepass")
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fingerprint(f) -> str:
    """The v0.1 fingerprint of a finding: rule, severity, file, job, step and message."""
    return _digest(_identity_v1(f))


def _entry_identity_v1(entry: dict) -> list:
    return [str(entry.get(k) or "") for k in ("rule", "severity", "path", "job", "step", "scope", "message")]


def expired_ignore(f) -> bool:
    """Whether the finding's ignore entry has expired (it is active again, and needs a decision)."""
    return bool(_EXPIRED.search(f.message))


def _check_v1(path, entries: list) -> None:
    for entry in entries:
        if not isinstance(entry, dict) or not str(entry.get("fingerprint", "")).startswith("sha256:"):
            raise BaselineError(f"baseline {path} has an entry without a fingerprint: {entry!r}")
        # The fingerprint must describe the entry a reviewer reads; otherwise an innocent-looking line
        # could carry the fingerprint of a different, worse finding.
        if not entry.get("rule") or not entry.get("severity") or not entry.get("path") or \
                _digest(_entry_identity_v1(entry)) != entry["fingerprint"]:
            raise BaselineError(f"baseline {path} has an entry whose fingerprint does not match its rule, "
                                f"severity, path, job, step and message: {entry.get('rule')} {entry.get('path')}")


# ------------------------------------------------------------------ the current format
def _fact_ok(value) -> bool:
    if isinstance(value, (str, bool, int)):
        return True
    return isinstance(value, list) and all(isinstance(v, str) for v in value)


def _check_v2(path, entries: list) -> None:
    for number, entry in enumerate(entries, start=1):
        where = f"baseline {path}, entry {number}"
        if not isinstance(entry, dict):
            raise BaselineError(f"{where}: is not a mapping")
        unknown = sorted(str(k) for k in entry if k not in _ENTRY_KEYS)
        if unknown:
            # A misspelt key (expiry for expires) must not read as a missing value someone forgot.
            raise BaselineError(f"{where}: unknown field(s) {', '.join(unknown)}; an entry has "
                                f"{', '.join(sorted(_ENTRY_KEYS))}")
        for name in ("rule", "path"):
            if not isinstance(entry.get(name), str) or not entry[name]:
                raise BaselineError(f"{where}: needs a {name}")
        if entry.get("severity") not in SEVERITIES:
            raise BaselineError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
        for name in ("job", "step", "scope", "kind", "message"):
            if name in entry and (not isinstance(entry[name], str) or not entry[name]):
                raise BaselineError(f"{where}: {name} must be text that is not empty, or left out")
        if "facts" in entry:
            facts = entry["facts"]
            if not isinstance(facts, dict) or not facts or not all(isinstance(k, str) and _fact_ok(v)
                                                                 for k, v in facts.items()):
                raise BaselineError(f"{where}: facts must be a mapping of names to text, numbers, true or false, "
                                    "or lists of text, or left out")
        if "message" in entry and ("facts" in entry or "kind" in entry):
            raise BaselineError(f"{where}: has both a message and a kind or facts; a finding is identified by "
                                "one or the other")
        # owner, reason and expires are not checked here: an entry that lacks one is a readable file
        # with an acceptance that does not count, and the report says so beside the finding.


def _no_duplicates(pairs: list) -> dict:
    """A JSON object, refused when it gives a key twice: a reader of the file would see one value and
    the checker would use the other."""
    out: dict = {}
    for name, value in pairs:
        if name in out:
            raise ValueError(f"the key {name!r} appears twice in one object")
        out[name] = value
    return out


def load(path: Path) -> Baseline:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates)
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline not found: {path} (create it with --write-baseline)") from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise BaselineError(f"baseline {path} cannot be read: {exc}") from exc
    if not isinstance(data, dict) or data.get("format") not in (FORMAT, FORMAT_V1) \
            or not isinstance(data.get("findings"), list):
        raise BaselineError(f"baseline {path} is not an {FORMAT} or {FORMAT_V1} file")
    try:
        (_check_v1 if data["format"] == FORMAT_V1 else _check_v2)(path, data["findings"])
    except RecursionError as exc:
        raise BaselineError(f"baseline {path} cannot be read: it is nested too deeply") from exc
    return Baseline(format=data["format"], entries=data["findings"], path=str(path))


def _accepts(entry: dict, f) -> bool:
    return SEVERITIES.get(f.severity, 3) <= SEVERITIES[entry["severity"]]


def _match(findings: list, entries: list[dict], entry_key, finding_key, today: date, legacy: bool) -> list[dict]:
    """Give each finding the entry that names it, valid entries first, and return the entries left over.

    Entries are counted: two findings that are the same in everything but their line need two
    entries. A suppressed finding uses up its entry without being marked, so an entry for a finding
    that has since been given an ignore entry is accounted for and not stale. A fixed finding takes
    no entry, so its entry is left over and has to be removed.
    """
    by_key: dict[str, list] = {}
    for entry in entries:
        if legacy:
            made = acceptance_mod.Acceptance(acceptance_mod.BASELINE, problems=[V1_PROBLEM])
        else:
            made = acceptance_mod.make(acceptance_mod.BASELINE, entry.get("owner"), entry.get("reason"),
                                       entry.get("expires"), today)
        by_key.setdefault(entry_key(entry), []).append((entry, made))
    for candidates in by_key.values():
        candidates.sort(key=lambda pair: not pair[1].valid)       # stable: valid entries are used first
    used: set[int] = set()
    for f in sorted(findings, key=lambda f: not f.suppressed):
        if f.state == FIXED:
            continue
        candidates = [pair for pair in by_key.get(finding_key(f), ()) if id(pair[0]) not in used]
        if not candidates:
            continue
        fitting = [pair for pair in candidates if legacy or _accepts(pair[0], f)]
        entry, made = (fitting or candidates)[0]
        used.add(id(entry))
        if f.suppressed:
            continue
        if not fitting:
            made = acceptance_mod.Acceptance(
                made.source, made.owner, made.reason, made.expires,
                made.problems + [f"it accepts the finding at {entry['severity']} severity and the finding is "
                                 f"now {f.severity}"])
        f.acceptance = made
        f.baselined = made.valid
    return [entry for entry in entries if id(entry) not in used]


def apply(result, baseline: Baseline, today: date | None = None) -> None:
    """Mark the findings the baseline accepts, attach to each matched finding the acceptance it got
    (valid or not), and record the entries that no longer match any finding."""
    today = today or date.today()
    if baseline.legacy:
        stale = _match(result.findings, baseline.entries, lambda e: e["fingerprint"], fingerprint, today, True)
    else:
        stale = _match(result.findings, baseline.entries, _entry_key, key, today, False)
    result.baseline_stale = stale
    result.baseline_used = True
    result.baseline_format = baseline.format
    result.baseline_path = baseline.path


def entry_for(f, owner: str, reason: str, expires: str) -> dict:
    entry = identity(f)
    return {"rule": entry.pop("rule"), "severity": f.severity, **entry,
            "owner": owner, "reason": reason, "expires": expires}


def acceptable(result) -> list:
    """The findings a baseline can hold: everything that is not fixed, not ignored by configuration,
    and not waiting on an ignore entry that has expired or is not valid (decide those where they are)."""
    return [f for f in result.findings
            if not f.suppressed and f.state != FIXED and not expired_ignore(f)
            and not (f.acceptance is not None and f.acceptance.source == acceptance_mod.IGNORE)]


def build(findings: list, kept: dict | None = None, owner: str = "", reason: str = "", expires: str = "") -> str:
    """The baseline text for `findings`. A finding in `kept` (finding id -> its existing valid entry)
    keeps that entry's owner, reason and expiry date; every other finding gets the ones given here."""
    kept = kept or {}
    entries = []
    for f in findings:
        old = kept.get(id(f))
        entries.append(entry_for(f, old["owner"], old["reason"], old["expires"]) if old
                       else entry_for(f, owner, reason, expires))
    entries.sort(key=lambda e: (e["path"], e.get("job", ""), e["rule"], _entry_key(e)))
    return dumps({"format": FORMAT, "tool": f"obaaf {__version__}", "findings": entries})


def plan(result, previous: Baseline | None, today: date | None = None) -> tuple[list, dict, list]:
    """What writing a baseline for `result` would do, given the file already there (`previous`, in the
    current format, or None): (the findings to write, those that keep a valid entry of the old file,
    as finding id -> its owner, reason and expiry date, and those that would be newly accepted)."""
    today = today or date.today()
    findings = acceptable(result)
    kept: dict = {}
    if previous is not None and not previous.legacy:
        before = [(f.acceptance, f.baselined) for f in findings]
        _match(findings, previous.entries, _entry_key, key, today, False)
        for f, (old_acceptance, old_baselined) in zip(findings, before):
            if f.baselined:
                kept[id(f)] = {"owner": f.acceptance.owner, "reason": f.acceptance.reason,
                               "expires": f.acceptance.expires}
            f.acceptance, f.baselined = old_acceptance, old_baselined
    fresh = [f for f in findings if id(f) not in kept]
    return findings, kept, fresh
